// SPDX-License-Identifier: MIT-0
import { createHash } from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { ArnFormat, CfnOutput, CfnResource, Duration, RemovalPolicy, Stack, StackProps } from 'aws-cdk-lib';
import {
  ApiKeyCredentialLocation, ApiKeyCredentialProvider, ApiSchema, CfnGatewayTarget, Gateway, GatewayAuthorizer,
  GatewayCredentialProvider, GatewayProtocol, GatewayTarget, LambdaInterceptor, MCPProtocolVersion,
} from 'aws-cdk-lib/aws-bedrockagentcore';
import { Certificate, CertificateValidation } from 'aws-cdk-lib/aws-certificatemanager';
import { OAuthScope, ResourceServerScope, UserPool } from 'aws-cdk-lib/aws-cognito';
import { Peer, Port, SecurityGroup, SubnetType, Vpc } from 'aws-cdk-lib/aws-ec2';
import {
  Cluster, ContainerImage, ContainerInsights, CpuArchitecture, FargateService, FargateTaskDefinition,
  LogDrivers, Secret as EcsSecret,
} from 'aws-cdk-lib/aws-ecs';
import {
  ApplicationLoadBalancer, ApplicationProtocol, ListenerAction, ListenerCondition, Protocol, SslPolicy,
} from 'aws-cdk-lib/aws-elasticloadbalancingv2';
import { AccountRootPrincipal, PolicyDocument, PolicyStatement, Role, ServicePrincipal } from 'aws-cdk-lib/aws-iam';
import { Key } from 'aws-cdk-lib/aws-kms';
import { Architecture, Code, Function as LambdaFunction, Runtime } from 'aws-cdk-lib/aws-lambda';
import { CfnDelivery, CfnDeliveryDestination, CfnDeliverySource, LogGroup, RetentionDays } from 'aws-cdk-lib/aws-logs';
import { ARecord, HostedZone, RecordTarget } from 'aws-cdk-lib/aws-route53';
import { LoadBalancerTarget } from 'aws-cdk-lib/aws-route53-targets';
import { CfnSecret, Secret } from 'aws-cdk-lib/aws-secretsmanager';
import { NagSuppressions } from 'cdk-nag';
import { Construct } from 'constructs';

// Pinned by digest (multi-arch index) so a re-pushed tag can't change what runs.
const KONG_IMAGE = 'kong:3.9@sha256:c1f5fbb80cd666b4b29b4e97875ecd64d93b01b23fb3083bc3e424b3bad5fdd5';
const PYTHON_IMAGE = 'python:3.12-slim@sha256:e695ab189fa2d082b1c61c69a6b888a5adeca61ceeccad107b1ed2a125721a9e';

const P = 'kta'; // resource-name prefix
const RESOURCE_SERVER = `${P}-api`;
const TARGET = `${P}-sites`;
const PROVIDER = `${P}-kong-apikey`;
const GATEWAY = `${P}-gw`;
const KONG_SECRET = `${P}/kong-api-key`;
/** Key administration only (no Encrypt, Decrypt or GenerateDataKey), every action named: no wildcards. */
const KEY_ADMIN_ACTIONS = [
  'kms:CancelKeyDeletion', 'kms:CreateAlias', 'kms:DeleteAlias', 'kms:DescribeKey', 'kms:DisableKey', 'kms:DisableKeyRotation',
  'kms:EnableKey', 'kms:EnableKeyRotation', 'kms:GetKeyPolicy', 'kms:GetKeyRotationStatus', 'kms:ListGrants', 'kms:ListKeyPolicies',
  'kms:ListKeyRotations', 'kms:ListResourceTags', 'kms:PutKeyPolicy', 'kms:RetireGrant', 'kms:RevokeGrant', 'kms:RotateKeyOnDemand',
  'kms:ScheduleKeyDeletion', 'kms:TagResource', 'kms:UntagResource', 'kms:UpdateAlias', 'kms:UpdateKeyDescription',
];
/** Who may call which tool: OAuth scope -> Gateway tool names (`<target>___<operationId>`). */
export const TOOL_POLICY: Record<string, string[]> = {
  [`${RESOURCE_SERVER}/sites.read`]: [`${TARGET}___getSite`],
  [`${RESOURCE_SERVER}/sites.write`]: [`${TARGET}___setSiteStatus`],
};

export interface ToolAccessStackProps extends StackProps {
  /** FQDN for the internal ALB, e.g. kta-api.example.com (must be in the hosted zone). */
  readonly domainName: string;
  readonly hostedZoneId: string;
  readonly hostedZoneName: string;
}

/**
 * Agent -> AgentCore Gateway (Cognito JWT + interceptor) -> VPC Lattice -> internal HTTPS ALB
 * -> Kong OSS key-auth -> Sites API. One stack, dev removal policies.
 */
export class ToolAccessStack extends Stack {
  constructor(scope: Construct, id: string, props: ToolAccessStackProps) {
    super(scope, id, props);
    const root = path.resolve(__dirname, '..');
    const vpc = Vpc.fromLookup(this, 'Vpc', { isDefault: true });
    // ALB, Fargate task and Lattice resource gateway share two subnets in distinct AZs: ALB targets in
    // an AZ the ALB doesn't cover never get traffic (health checks fail, circuit breaker trips).
    const subnets = vpc.selectSubnets({ subnetType: SubnetType.PUBLIC, onePerAz: true }).subnets.slice(0, 2);

    // ---------- Identity: two M2M callers, scopes = "who" ----------
    const pool = new UserPool(this, 'Pool', {
      userPoolName: `${P}-pool`,
      selfSignUpEnabled: false,
      passwordPolicy: { minLength: 12, requireDigits: true, requireLowercase: true, requireUppercase: true, requireSymbols: true },
      removalPolicy: RemovalPolicy.DESTROY,
    });
    const read = new ResourceServerScope({ scopeName: 'sites.read', scopeDescription: 'Read sites' });
    const write = new ResourceServerScope({ scopeName: 'sites.write', scopeDescription: 'Change site status' });
    const api = pool.addResourceServer('Api', { identifier: RESOURCE_SERVER, scopes: [read, write] });
    const domainPrefix = `${P}-${createHash('sha256').update(`${this.account}/${this.region}`).digest('hex').slice(0, 10)}`;
    pool.addDomain('Domain', { cognitoDomain: { domainPrefix } });
    const m2m = (cid: string, scopes: ResourceServerScope[]) =>
      pool.addClient(cid, {
        userPoolClientName: `${P}-${cid.toLowerCase()}`,
        generateSecret: true,
        authFlows: {},
        // Threat model T12: a leaked token is usable for 15 minutes, not Cognito's 60-minute default.
        accessTokenValidity: Duration.minutes(15),
        oAuth: { flows: { clientCredentials: true }, scopes: scopes.map((s) => OAuthScope.resourceServer(api, s)) },
      });
    const reader = m2m('Reader', [read]);
    const operator = m2m('Operator', [read, write]);

    // ---------- Encryption at rest: one customer managed key, rotated yearly ----------
    // Encrypts the Kong secret, the three log groups and the interceptor's environment variables.
    const logGroupNames = [`/${P}/kong`, `/aws/lambda/${P}-tool-interceptor`, `/aws/vendedlogs/bedrock-agentcore/${GATEWAY}`];
    const key = new Key(this, 'DataKey', {
      alias: `alias/${P}-data`, description: `${P}: Kong secret, log groups, interceptor environment`,
      enableKeyRotation: true, pendingWindow: Duration.days(7), removalPolicy: RemovalPolicy.DESTROY,
      // Replaces CDK's default key policy (account root: kms:*). No statement on this key uses a wildcard action
      // (test/stack.test.ts enforces it). Account admins can manage and delete the key through IAM, and the root
      // principal keeps kms:PutKeyPolicy so the key can't become unmanageable, but they can't use it directly.
      policy: new PolicyDocument({
        statements: [new PolicyStatement({
          sid: 'KeyAdministrationThroughIam', principals: [new AccountRootPrincipal()], actions: KEY_ADMIN_ACTIONS,
          resources: ['*'], // in a key policy, '*' means this key
        })],
      }),
    });
    // CloudWatch Logs encrypts with the key itself, so its service principal needs it, but only for these log groups.
    // The actions are the explicit expansion of the wildcards in the CloudWatch Logs documentation's key policy.
    key.addToResourcePolicy(new PolicyStatement({
      sid: 'CloudWatchLogsForThisStacksLogGroups',
      principals: [new ServicePrincipal(`logs.${this.region}.amazonaws.com`)],
      actions: [
        'kms:Encrypt', 'kms:Decrypt', 'kms:ReEncryptFrom', 'kms:ReEncryptTo', 'kms:GenerateDataKey',
        'kms:GenerateDataKeyWithoutPlaintext', 'kms:GenerateDataKeyPair', 'kms:GenerateDataKeyPairWithoutPlaintext', 'kms:DescribeKey',
      ],
      resources: ['*'], // in a key policy, '*' means this key
      conditions: {
        ArnLike: {
          'kms:EncryptionContext:aws:logs:arn': logGroupNames.map((n) => `arn:${this.partition}:logs:${this.region}:${this.account}:log-group:${n}`),
        },
      },
    }));
    // Secrets Manager, on behalf of an IAM principal in this account that is also allowed kms:Decrypt by IAM (the ECS
    // task execution role, below), and only for the Kong secret.
    key.addToResourcePolicy(new PolicyStatement({
      sid: 'SecretsManagerForTheKongSecret', principals: [new AccountRootPrincipal()],
      actions: ['kms:Decrypt', 'kms:GenerateDataKey'], resources: ['*'],
      conditions: {
        StringEquals: { 'kms:ViaService': `secretsmanager.${this.region}.amazonaws.com`, 'kms:CallerAccount': this.account },
        ArnLike: { 'kms:EncryptionContext:SecretARN': `arn:${this.partition}:secretsmanager:${this.region}:${this.account}:secret:${KONG_SECRET}-*` }, // pragma: allowlist secret (KMS condition key on the secret's ARN, not a secret value)
      },
    }));
    // Lambda, when an IAM-authorized principal in this account creates or updates a function that uses this key.
    const viaLambda = { 'kms:ViaService': `lambda.${this.region}.amazonaws.com`, 'kms:CallerAccount': this.account };
    key.addToResourcePolicy(new PolicyStatement({
      sid: 'LambdaEncryptsFunctionEnvironments', principals: [new AccountRootPrincipal()],
      actions: ['kms:Encrypt', 'kms:Decrypt'], resources: ['*'], conditions: { StringEquals: viaLambda },
    }));
    key.addToResourcePolicy(new PolicyStatement({
      sid: 'LambdaCreatesGrantsForFunctions', principals: [new AccountRootPrincipal()],
      actions: ['kms:CreateGrant'], resources: ['*'],
      conditions: { StringEquals: viaLambda, Bool: { 'kms:GrantIsForAWSResource': 'true' } },
    }));

    // ---------- Kong OSS + Sites API on Fargate ----------
    // Random key-auth credential. ECS injects it into Kong; the Gateway's API key provider reads the
    // same secret via a CloudFormation dynamic reference. No plaintext in the repo or template.
    const apiKey = new Secret(this, 'KongApiKey', {
      secretName: KONG_SECRET,
      description: 'Kong key-auth credential used by the AgentCore Gateway',
      generateSecretString: { secretStringTemplate: '{}', generateStringKey: 'api_key', excludePunctuation: true, passwordLength: 40 },
      removalPolicy: RemovalPolicy.DESTROY,
    });
    // Set the key at the L1 level: the L2 `encryptionKey` prop also adds CDK's grantEncryptDecrypt statement to the
    // key policy, which uses wildcard actions (kms:GenerateDataKey*, kms:ReEncrypt*). The explicit
    // SecretsManagerForTheKongSecret statement above replaces it.
    (apiKey.node.defaultChild as CfnSecret).kmsKeyId = key.keyArn;
    const taskLogs = new LogGroup(this, 'TaskLogs', {
      logGroupName: logGroupNames[0], retention: RetentionDays.ONE_WEEK, encryptionKey: key, removalPolicy: RemovalPolicy.DESTROY,
    });
    const task = new FargateTaskDefinition(this, 'Task', {
      cpu: 512, memoryLimitMiB: 1024, runtimePlatform: { cpuArchitecture: CpuArchitecture.X86_64 },
    });
    const b64 = (rel: string) => Buffer.from(fs.readFileSync(path.join(root, rel))).toString('base64');
    task.addContainer('kong', {
      image: ContainerImage.fromRegistry(KONG_IMAGE),
      entryPoint: ['/bin/sh', '-c'],
      // Fail closed: no injected key => Kong does not start (never serves /sites unauthenticated).
      // The key is spliced into the config with shell parameter expansion (builtins only, so it never appears
      // in a process argument list) and written 0600. The placeholder must appear exactly once.
      command: [
        // Plain $NAME expansions only: CloudFormation's validator reads ${NAME} as an Fn::Sub parameter (E1029).
        'umask 077; ' +
          '[ -n "$KONG_API_KEY" ] || { echo "KONG_API_KEY not injected; refusing to start" >&2; exit 1; }; ' +
          'set -eu; ' +
          'cfg="$(printf %s "$KONG_DECLARATIVE_B64" | base64 -d)"; rest="${cfg#*__KONG_API_KEY__}"; ' +
          '[ "$rest" != "$cfg" ] || { echo "key placeholder missing from Kong config" >&2; exit 1; }; ' +
          'case "$rest" in *__KONG_API_KEY__*) echo "key placeholder must appear exactly once" >&2; exit 1;; esac; ' +
          'printf "%s\\n" "${cfg%%__KONG_API_KEY__*}$KONG_API_KEY$rest" > /tmp/kong.yaml; ' +
          'exec /docker-entrypoint.sh kong docker-start',
      ],
      environment: {
        KONG_DECLARATIVE_B64: b64('kong/kong.yaml'),
        KONG_DATABASE: 'off',
        KONG_DECLARATIVE_CONFIG: '/tmp/kong.yaml',
        // TLS only. No ssl_cert is set, so Kong generates a self-signed default certificate at start.
        KONG_PROXY_LISTEN: '0.0.0.0:8443 ssl',
        KONG_ADMIN_LISTEN: 'off', // no Admin API at all
        KONG_HEADERS: 'off', // don't advertise Kong/version
        KONG_PROXY_ACCESS_LOG: '/dev/stdout',
        KONG_PROXY_ERROR_LOG: '/dev/stderr',
      },
      secrets: { KONG_API_KEY: EcsSecret.fromSecretsManager(apiKey, 'api_key') },
      logging: LogDrivers.awsLogs({ streamPrefix: 'kong', logGroup: taskLogs }),
      portMappings: [{ containerPort: 8443 }],
    });
    // Sidecar on 127.0.0.1:9100 with no port mapping: reachable only by Kong over the task's localhost.
    task.addContainer('api', {
      image: ContainerImage.fromRegistry(PYTHON_IMAGE),
      user: '65534',
      entryPoint: ['/bin/sh', '-c'],
      command: ['echo "$API_B64" | base64 -d > /tmp/server.py && exec python3 -u /tmp/server.py'],
      environment: { API_B64: b64('api/server.py') },
      logging: LogDrivers.awsLogs({ streamPrefix: 'api', logGroup: taskLogs }),
    });
    const cluster = new Cluster(this, 'Cluster', { vpc, clusterName: `${P}-cluster`, containerInsightsV2: ContainerInsights.ENABLED });
    const taskSg = new SecurityGroup(this, 'TaskSg', { vpc, description: `${P} Kong task`, allowAllOutbound: false });
    // HTTPS only: image pulls (Docker Hub), Secrets Manager and CloudWatch Logs. No NAT or VPC endpoints in the
    // default VPC, so those are internet endpoints. Responses to the ALB are stateful and need no egress rule.
    taskSg.addEgressRule(Peer.anyIpv4(), Port.tcp(443), 'HTTPS to the image registry and AWS APIs');
    const service = new FargateService(this, 'Service', {
      cluster, taskDefinition: task, desiredCount: 1, serviceName: `${P}-kong`,
      // Demo trade-off: a public IP only so the task can pull images from Docker Hub in a default VPC with no NAT
      // gateway. Inbound is SG-locked to the ALB on 8443. Production: private subnets, ECR via VPC endpoints.
      assignPublicIp: true,
      vpcSubnets: { subnets }, securityGroups: [taskSg],
      minHealthyPercent: 0, circuitBreaker: { rollback: true }, healthCheckGracePeriod: Duration.seconds(120),
    });

    // ECS reads the Kong secret when the task starts. This is the IAM half (kms:Decrypt on this key only); the key
    // policy's SecretsManagerForTheKongSecret statement limits it to Secrets Manager and this secret.
    key.grantDecrypt(task.obtainExecutionRole());

    // ---------- Private front door: internal HTTPS ALB reachable only from the Lattice resource gateway ----------
    const rgSg = new SecurityGroup(this, 'ResourceGatewaySg', { vpc, description: `${P} AgentCore resource gateway ENIs`, allowAllOutbound: false });
    const albSg = new SecurityGroup(this, 'AlbSg', { vpc, description: `${P} internal ALB, ingress from resource gateway only`, allowAllOutbound: false });
    rgSg.addEgressRule(albSg, Port.tcp(443), 'resource gateway to internal ALB');
    albSg.addIngressRule(rgSg, Port.tcp(443), 'from AgentCore resource gateway');
    const zone = HostedZone.fromHostedZoneAttributes(this, 'Zone', { hostedZoneId: props.hostedZoneId, zoneName: props.hostedZoneName });
    const cert = new Certificate(this, 'Cert', { domainName: props.domainName, validation: CertificateValidation.fromDns(zone) });
    const alb = new ApplicationLoadBalancer(this, 'Alb', {
      vpc, internetFacing: false, securityGroup: albSg, vpcSubnets: { subnets }, dropInvalidHeaderFields: true,
    });
    const listener = alb.addListener('Https', {
      port: 443, protocol: ApplicationProtocol.HTTPS, certificates: [cert], sslPolicy: SslPolicy.RECOMMENDED_TLS,
      open: false, // no 0.0.0.0/0; only the rgSg rule above
      defaultAction: ListenerAction.fixedResponse(404, { contentType: 'application/json', messageBody: '{"message":"not found"}' }),
    });
    listener.addTargets('Kong', {
      priority: 10, conditions: [ListenerCondition.pathPatterns(['/sites/*'])],
      // HTTPS to Kong as well, so the apikey header is never sent in plaintext inside the VPC. Kong serves its
      // self-signed default certificate; ALB encrypts to targets but does not validate their certificates.
      port: 8443, protocol: ApplicationProtocol.HTTPS, targets: [service], deregistrationDelay: Duration.seconds(10),
      // 401 without a key = Kong is up AND key-auth is enforcing. Protocol is explicit: the API default is HTTP,
      // which Kong's TLS-only listener would reject, failing every health check.
      healthCheck: { protocol: Protocol.HTTPS, path: '/sites/health', healthyHttpCodes: '401', interval: Duration.seconds(15) },
    });
    const dns = new ARecord(this, 'Alias', { zone, recordName: props.domainName, target: RecordTarget.fromAlias(new LoadBalancerTarget(alb)) });

    // ---------- Interceptor: "which tools" ----------
    const fnLogs = new LogGroup(this, 'InterceptorLogs', {
      logGroupName: logGroupNames[1], retention: RetentionDays.ONE_WEEK, encryptionKey: key, removalPolicy: RemovalPolicy.DESTROY,
    });
    const fnRole = new Role(this, 'InterceptorRole', { assumedBy: new ServicePrincipal('lambda.amazonaws.com') });
    fnLogs.grantWrite(fnRole); // logs only; the function calls no AWS APIs
    const interceptor = new LambdaFunction(this, 'Interceptor', {
      functionName: `${P}-tool-interceptor`,
      runtime: Runtime.PYTHON_3_14, architecture: Architecture.ARM_64,
      handler: 'handler.lambda_handler',
      code: Code.fromAsset(path.join(root, 'interceptor'), { exclude: ['test_*.py', '__pycache__', '.pytest_cache'] }),
      role: fnRole, logGroup: fnLogs, timeout: Duration.seconds(5), memorySize: 128,
      environment: { TOOL_POLICY: JSON.stringify(TOOL_POLICY) },
      environmentEncryption: key,
    });
    // The interceptor's role reads its own encrypted environment variables. Named directly in the key policy.
    key.addToResourcePolicy(new PolicyStatement({
      sid: 'InterceptorReadsItsEnvironment', principals: [fnRole], actions: ['kms:Decrypt'], resources: ['*'],
    }));

    // ---------- AgentCore Gateway ----------
    const gateway = new Gateway(this, 'Gateway', {
      gatewayName: GATEWAY,
      description: 'Per-agent tool access for a Kong-protected API',
      protocolConfiguration: GatewayProtocol.mcp({ supportedVersions: [MCPProtocolVersion.MCP_2025_06_18, MCPProtocolVersion.MCP_2025_03_26] }),
      authorizerConfiguration: GatewayAuthorizer.usingCognito({ userPool: pool, allowedClients: [reader, operator] }),
      // passRequestHeaders: the interceptor needs the caller's Authorization header to read scopes.
      interceptorConfigurations: [
        LambdaInterceptor.forRequest(interceptor, { passRequestHeaders: true }),
        LambdaInterceptor.forResponse(interceptor, { passRequestHeaders: true }),
      ],
    });
    gateway.node.defaultChild!.node.addDependency(gateway.role); // role policy (lambda:InvokeFunction) first

    // Outbound auth: the Gateway injects `apikey: <key>` (Kong key-auth) on every call to the target.
    const provider = new ApiKeyCredentialProvider(this, 'ApiKeyProvider', {
      apiKeyCredentialProviderName: PROVIDER, apiKey: apiKey.secretValueFromJson('api_key'),
    });
    const spec = JSON.parse(fs.readFileSync(path.join(root, 'api', 'openapi.json'), 'utf8'));
    spec.servers = [{ url: `https://${props.domainName}` }];
    // OpenAPI targets reject spec-level security; outbound auth is configured on the target below.
    delete spec.security;
    delete spec.components.securitySchemes;
    const target = GatewayTarget.forOpenApi(this, 'SitesTarget', {
      gateway, gatewayTargetName: TARGET, description: 'Sites API behind Kong key-auth (private)',
      apiSchema: ApiSchema.fromInline(JSON.stringify(spec)),
      credentialProviderConfigurations: [
        GatewayCredentialProvider.fromApiKeyIdentityArn({
          providerArn: provider.credentialProviderArn,
          // AgentCore stores the key as a provider-managed secret; scope the gateway role's read to it.
          // (literal ARN, not formatArn: a partition token would make the L2 fall back to a wildcard)
          secretArn: `arn:aws:secretsmanager:${this.region}:${this.account}:secret:bedrock-agentcore-identity!default/apikey/${PROVIDER}-*`, // pragma: allowlist secret (ARN pattern for IAM scoping, not a secret value)
          credentialLocation: ApiKeyCredentialLocation.header({ credentialParameterName: 'apikey', credentialPrefix: '' }),
        }),
      ],
    });
    // Reach the ALB privately: AgentCore creates a VPC Lattice resource gateway in these subnets.
    const cfnTarget = target.node.defaultChild as CfnGatewayTarget;
    cfnTarget.privateEndpoint = {
      managedVpcResource: {
        vpcIdentifier: vpc.vpcId, subnetIds: subnets.map((s) => s.subnetId), securityGroupIds: [rgSg.securityGroupId],
        endpointIpAddressType: 'IPV4', tags: { Project: 'agentcore-kong-tool-access' },
      },
    };
    // Kong expects the raw key. The L2 renders prefix '' but CloudFormation requires minLength 1, so drop it.
    cfnTarget.addPropertyDeletionOverride('CredentialProviderConfigurations.0.CredentialProvider.ApiKeyCredentialProvider.CredentialPrefix');
    // Create after (and delete before) the front door, so Lattice ENIs are gone before SGs/ALB are deleted.
    target.node.addDependency(service, listener, dns, rgSg, albSg);

    // Gateway APPLICATION_LOGS: target failures reach the agent only as "An internal error occurred".
    const gwLogName = logGroupNames[2];
    const gwLogs = new LogGroup(this, 'GatewayLogs', {
      logGroupName: gwLogName, retention: RetentionDays.ONE_WEEK, encryptionKey: key, removalPolicy: RemovalPolicy.DESTROY,
    });
    const src = new CfnDeliverySource(this, 'GatewayLogSource', { name: `${GATEWAY}-applogs`, logType: 'APPLICATION_LOGS', resourceArn: gateway.gatewayArn });
    const dst = new CfnDeliveryDestination(this, 'GatewayLogDest', {
      name: `${GATEWAY}-applogs`,
      destinationResourceArn: this.formatArn({ service: 'logs', resource: 'log-group', resourceName: gwLogName, arnFormat: ArnFormat.COLON_RESOURCE_NAME }),
    });
    dst.node.addDependency(gwLogs);
    new CfnDelivery(this, 'GatewayLogDelivery', { deliverySourceName: src.name, deliveryDestinationArn: dst.attrArn }).node.addDependency(src);

    const out = (k: string, value: string) => new CfnOutput(this, k, { value });
    out('GatewayUrl', gateway.gatewayUrl!);
    out('GatewayId', gateway.gatewayId);
    out('TargetId', target.targetId);
    out('UserPoolId', pool.userPoolId);
    out('ReaderClientId', reader.userPoolClientId);
    out('OperatorClientId', operator.userPoolClientId);
    out('TokenUrl', `https://${domainPrefix}.auth.${this.region}.amazoncognito.com/oauth2/token`);
    out('InterceptorLogGroup', fnLogs.logGroupName);
    out('TaskLogGroup', taskLogs.logGroupName);
    out('GatewayLogGroup', gwLogName);

    // ---------- Checkov: resource-scoped, justified skips (read from the template's Metadata) ----------
    const checkovSkip = (c: Construct, skips: Array<[string, string]>) =>
      (c.node.defaultChild as CfnResource).addMetadata('checkov', { skip: skips.map(([id, comment]) => ({ id, comment })) });
    checkovSkip(alb, [
      ['CKV_AWS_91', 'Internal ALB reachable only from the resource-gateway SG, one route. Every request is logged by Kong (TaskLogs), the interceptor and the Gateway application logs. Same reason as the cdk-nag ELB2 suppression.'],
    ]);
    checkovSkip(interceptor, [
      ['CKV_AWS_116', 'Invoked synchronously by AgentCore Gateway only. A dead-letter queue applies only to asynchronous invocations.'],
      ['CKV_AWS_117', 'Makes no network calls and calls no AWS APIs (stdlib only, logs only). A VPC would add ENIs and attack surface without isolating anything.'],
      ['CKV_AWS_115', 'Reserved concurrency would throttle legitimate Gateway traffic and fails to deploy in accounts with a low concurrency quota. Timeout is 5 seconds and only the Gateway role may invoke it.'],
    ]);

    // ---------- cfn-nag: resource-scoped, justified suppressions (read from the template's Metadata) ----------
    const cfnNagSkip = (c: Construct, rules: Array<[string, string]>) =>
      (c.node.defaultChild as CfnResource).addMetadata('cfn_nag', { rules_to_suppress: rules.map(([id, reason]) => ({ id, reason })) });
    cfnNagSkip(alb, [
      ['W52', 'Internal ALB reachable only from the resource-gateway SG, one route. Every request is logged by Kong (TaskLogs), the interceptor and the Gateway application logs. Same as checkov CKV_AWS_91 and cdk-nag ELB2.'],
    ]);
    cfnNagSkip(interceptor, [
      ['W58', 'False positive: the role has an inline grant to write to this function\'s own log group (fnLogs.grantWrite); cfn-nag only recognizes managed policies.'],
      ['W89', 'Makes no network calls and calls no AWS APIs (stdlib only, logs only). A VPC would add ENIs and attack surface without isolating anything. Same as checkov CKV_AWS_117.'],
      ['W92', 'Reserved concurrency would throttle legitimate Gateway traffic and fails to deploy in accounts with a low concurrency quota. Same as checkov CKV_AWS_115.'],
    ]);
    cfnNagSkip(taskSg, [
      ['W5', 'Egress is TCP 443 only. In the default VPC (public IP, no NAT or VPC endpoints) the image registry, Secrets Manager and CloudWatch Logs are internet endpoints. Inbound is ALB-only.'],
    ]);

    // ---------- cdk-nag: resource-scoped, justified suppressions ----------
    NagSuppressions.addResourceSuppressions(pool, [
      { id: 'AwsSolutions-COG2', reason: 'Machine-to-machine (client_credentials) only; no human users, so MFA does not apply.' },
      { id: 'AwsSolutions-COG3', reason: 'No user sign-in (M2M only); threat protection targets user authentication.' },
      { id: 'AwsSolutions-COG8', reason: 'Plus tier adds user-sign-in threat protection, which an M2M-only pool does not use.' },
    ]);
    NagSuppressions.addResourceSuppressions(apiKey, [
      { id: 'AwsSolutions-SMG4', reason: 'Rotation = rotate the secret, redeploy (provider re-reads it, Kong task restarts). Not automated in this demo.' },
    ]);
    NagSuppressions.addResourceSuppressions(task, [
      { id: 'AwsSolutions-ECS2', reason: 'Env vars hold only non-secret config (base64 Kong config without the key, API source). The key is injected via ECS secrets.' },
    ]);
    NagSuppressions.addResourceSuppressions(alb, [
      { id: 'AwsSolutions-ELB2', reason: 'Internal ALB reachable only from the resource-gateway SG; every request is logged by Kong to CloudWatch (TaskLogs).' },
    ]);
    NagSuppressions.addResourceSuppressions(gateway.role, [
      {
        id: 'AwsSolutions-IAM5',
        reason: 'CDK L2 grants for API-key outbound auth: the gateway workload identity is <gateway-name>-<random id>, the provider-managed secret is <provider>-<random suffix>; lambda:InvokeFunction covers versions of this one interceptor.',
        appliesTo: [
          { regex: `/^Resource::arn:(aws|<AWS::Partition>):bedrock-agentcore:[^:]+:[^:]+:workload-identity-directory\\/default\\/workload-identity\\/${GATEWAY}-\\*$/g` },
          { regex: `/^Resource::arn:aws:secretsmanager:[^:]+:[^:]+:secret:bedrock-agentcore-identity!default\\/apikey\\/${PROVIDER}-\\*$/g` },
          { regex: '/^Resource::<Interceptor[A-F0-9]+\\.Arn>:\\*$/g' },
        ],
      },
    ], true);
  }
}
