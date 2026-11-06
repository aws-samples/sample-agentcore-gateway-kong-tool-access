// SPDX-License-Identifier: MIT-0
import * as fs from 'node:fs';
import * as path from 'node:path';
import { App, Aspects } from 'aws-cdk-lib';
import { Annotations, Match, Template } from 'aws-cdk-lib/assertions';
import { AwsSolutionsChecks } from 'cdk-nag';
import { TOOL_POLICY, ToolAccessStack } from '../lib/stack';

const app = new App();
const stack = new ToolAccessStack(app, 'Test', {
  env: { account: '111111111111', region: 'us-east-1' },
  domainName: 'api.example.com', hostedZoneId: 'Z0000000000000', hostedZoneName: 'example.com',
});
Aspects.of(app).add(new AwsSolutionsChecks());
const t = Template.fromStack(stack);

test('cdk-nag AwsSolutions: zero errors and warnings', () => {
  const findings = [
    ...Annotations.fromStack(stack).findError('*', Match.stringLikeRegexp('AwsSolutions-.*')),
    ...Annotations.fromStack(stack).findWarning('*', Match.stringLikeRegexp('AwsSolutions-.*')),
  ];
  expect(findings.map((f) => `${f.id}: ${f.entry.data}`)).toEqual([]);
});

test('gateway: Cognito JWT for both callers, one interceptor at REQUEST + RESPONSE with headers', () => {
  const gw = Object.values(t.findResources('AWS::BedrockAgentCore::Gateway'))[0].Properties;
  expect(gw.AuthorizerType).toBe('CUSTOM_JWT');
  expect(gw.AuthorizerConfiguration.CustomJWTAuthorizer.AllowedClients).toHaveLength(2);
  const points = gw.InterceptorConfigurations.map((c: any) => c.InterceptionPoints[0]).sort();
  expect(points).toEqual(['REQUEST', 'RESPONSE']);
  for (const c of gw.InterceptorConfigurations) expect(c.InputConfiguration.PassRequestHeaders).toBe(true);
});

test('interceptor policy maps scopes to tool-level entries', () => {
  t.hasResourceProperties('AWS::Lambda::Function', {
    FunctionName: 'kta-tool-interceptor',
    Environment: { Variables: { TOOL_POLICY: JSON.stringify(TOOL_POLICY) } },
  });
  expect(TOOL_POLICY['kta-api/sites.read']).toEqual(['kta-sites___getSite']);
  expect(TOOL_POLICY['kta-api/sites.write']).toEqual(['kta-sites___setSiteStatus']);
});

test('target: private endpoint, apikey header, https server, no securitySchemes', () => {
  const tgt = Object.values(t.findResources('AWS::BedrockAgentCore::GatewayTarget'))[0].Properties;
  expect(tgt.PrivateEndpoint.ManagedVpcResource.SubnetIds).toHaveLength(2);
  const cred = tgt.CredentialProviderConfigurations[0];
  expect(cred.CredentialProviderType).toBe('API_KEY');
  expect(cred.CredentialProvider.ApiKeyCredentialProvider).toMatchObject({ CredentialLocation: 'HEADER', CredentialParameterName: 'apikey' });
  expect(cred.CredentialProvider.ApiKeyCredentialProvider.CredentialPrefix).toBeUndefined(); // raw key, no "Bearer "
  const spec = JSON.parse(tgt.TargetConfiguration.Mcp.OpenApiSchema.InlinePayload);
  expect(spec.servers[0].url).toBe('https://api.example.com');
  expect(spec.security).toBeUndefined();
  expect(spec.components.securitySchemes).toBeUndefined();
});

test('API key never in plaintext: provider uses a Secrets Manager dynamic reference', () => {
  const p = Object.values(t.findResources('AWS::BedrockAgentCore::ApiKeyCredentialProvider'))[0].Properties;
  expect(JSON.stringify(p.ApiKey)).toContain('{{resolve:secretsmanager:');
  const kong = t.findResources('AWS::ECS::TaskDefinition');
  const containers = Object.values(kong)[0].Properties.ContainerDefinitions;
  expect(containers.find((c: any) => c.Name === 'kong').Secrets[0].Name).toBe('KONG_API_KEY');
});

test('ALB: internal, HTTPS only, ingress only from the resource-gateway SG', () => {
  t.hasResourceProperties('AWS::ElasticLoadBalancingV2::LoadBalancer', { Scheme: 'internal' });
  t.hasResourceProperties('AWS::ElasticLoadBalancingV2::Listener', { Port: 443, Protocol: 'HTTPS' });
  const sgs = t.findResources('AWS::EC2::SecurityGroup');
  for (const sg of Object.values(sgs)) for (const r of sg.Properties.SecurityGroupIngress ?? []) expect(r.CidrIp).toBeUndefined();
  t.hasResourceProperties('AWS::EC2::SecurityGroupIngress', { FromPort: 443, SourceSecurityGroupId: Match.anyValue() });
});

test('ALB to Kong is TLS: HTTPS target group and health check on 8443, Kong listens with ssl only', () => {
  t.hasResourceProperties('AWS::ElasticLoadBalancingV2::TargetGroup', {
    Port: 8443, Protocol: 'HTTPS', HealthCheckProtocol: 'HTTPS', HealthCheckPath: '/sites/health', Matcher: { HttpCode: '401' },
  });
  const containers = Object.values(t.findResources('AWS::ECS::TaskDefinition'))[0].Properties.ContainerDefinitions;
  const kong = containers.find((c: any) => c.Name === 'kong');
  expect(kong.PortMappings.map((p: any) => p.ContainerPort)).toEqual([8443]);
  expect(kong.Environment).toContainEqual({ Name: 'KONG_PROXY_LISTEN', Value: '0.0.0.0:8443 ssl' });
  expect(kong.Environment).toContainEqual({ Name: 'KONG_ADMIN_LISTEN', Value: 'off' });
  expect(containers.find((c: any) => c.Name === 'api').PortMappings ?? []).toEqual([]);
  // the key is spliced in with shell builtins, never passed as a process argument
  expect(kong.Command.join(' ')).not.toContain('sed ');
  // no ${NAME} in the shell command: CloudFormation would read it as an Fn::Sub parameter (cfn-lint E1029)
  expect(kong.Command.join(' ')).not.toMatch(/\$\{[A-Za-z0-9_:.]+\}/);
});

test('kong.yaml: key placeholder exactly once, /sites route is https-only', () => {
  const cfg = fs.readFileSync(path.join(__dirname, '..', 'kong', 'kong.yaml'), 'utf8');
  expect(cfg.split('__KONG_API_KEY__')).toHaveLength(2);
  expect(cfg).toMatch(/protocols: \[https\]/);
});

test('encryption at rest: one rotating customer managed key for the secret, all log groups and the Lambda environment', () => {
  const keys = t.findResources('AWS::KMS::Key');
  expect(Object.keys(keys)).toHaveLength(1);
  const [keyId, keyRes] = Object.entries(keys)[0];
  expect(keyRes.Properties.EnableKeyRotation).toBe(true);
  const keyArn = { 'Fn::GetAtt': [keyId, 'Arn'] };
  t.hasResourceProperties('AWS::SecretsManager::Secret', { KmsKeyId: keyArn });
  const groups = Object.values(t.findResources('AWS::Logs::LogGroup'));
  expect(groups).toHaveLength(3);
  for (const g of groups) expect(g.Properties.KmsKeyId).toEqual(keyArn);
  t.hasResourceProperties('AWS::Lambda::Function', { FunctionName: 'kta-tool-interceptor', KmsKeyArn: keyArn });
  // the logs service may use the key only for this stack's log groups
  const logsStmt = keyRes.Properties.KeyPolicy.Statement.find((s: any) => s.Sid === 'CloudWatchLogsForThisStacksLogGroups');
  expect(logsStmt.Condition.ArnLike['kms:EncryptionContext:aws:logs:arn']).toHaveLength(3);
  expect(logsStmt.Action.some((a: string) => a.includes('*'))).toBe(false);
});

test('every Checkov skip is scoped to one resource and carries a reason', () => {
  const skipped = Object.values(t.toJSON().Resources as Record<string, any>).filter((r) => r.Metadata?.checkov);
  expect(skipped.map((r) => r.Type).sort()).toEqual(['AWS::ElasticLoadBalancingV2::LoadBalancer', 'AWS::Lambda::Function']);
  for (const r of skipped) for (const s of r.Metadata.checkov.skip) expect(s.comment.length).toBeGreaterThan(40);
});

test('key policy: explicit statements only; admins manage but cannot use the key; every use is scoped', () => {
  const stmts = Object.values(t.findResources('AWS::KMS::Key'))[0].Properties.KeyPolicy.Statement;
  expect(stmts.map((s: any) => s.Sid).sort()).toEqual([
    'CloudWatchLogsForThisStacksLogGroups', 'InterceptorReadsItsEnvironment', 'KeyAdministrationThroughIam',
    'LambdaCreatesGrantsForFunctions', 'LambdaEncryptsFunctionEnvironments', 'SecretsManagerForTheKongSecret',
  ]);
  const admin = stmts.find((s: any) => s.Sid === 'KeyAdministrationThroughIam');
  expect(admin.Action).toContain('kms:PutKeyPolicy'); // the key can always be managed
  const use = ['kms:Encrypt', 'kms:Decrypt', 'kms:GenerateDataKey', 'kms:ReEncryptFrom', 'kms:ReEncryptTo', 'kms:CreateGrant'];
  expect(admin.Action.filter((a: string) => use.includes(a))).toEqual([]);
  // every statement that allows using the key either names one role or carries conditions
  for (const s of stmts.filter((x: any) => !['KeyAdministrationThroughIam', 'InterceptorReadsItsEnvironment'].includes(x.Sid))) {
    expect(s.Condition).toBeDefined();
  }
  const sm = stmts.find((s: any) => s.Sid === 'SecretsManagerForTheKongSecret');
  expect(JSON.stringify(sm.Condition.ArnLike['kms:EncryptionContext:SecretARN'])).toContain('kta/kong-api-key-*');
});

test('no IAM or key policy statement in the template uses a wildcard action', () => {
  const wild: string[] = [];
  const walk = (node: any, where: string): void => {
    if (Array.isArray(node)) { node.forEach((n) => walk(n, where)); return; }
    if (!node || typeof node !== 'object') return;
    if ('Effect' in node && ('Action' in node || 'NotAction' in node)) {
      if ('NotAction' in node) wild.push(`${where}: NotAction`);
      const actions = Array.isArray(node.Action) ? node.Action : [node.Action];
      for (const a of actions) if (typeof a === 'string' && a.includes('*')) wild.push(`${where}: ${a}`);
    }
    for (const v of Object.values(node)) walk(v, where);
  };
  for (const [id, r] of Object.entries(t.toJSON().Resources as Record<string, any>)) walk(r.Properties, id);
  expect(wild).toEqual([]);
});

test('access tokens are short-lived: 15 minutes for both clients (threat model T12)', () => {
  const clients = Object.values(t.findResources('AWS::Cognito::UserPoolClient'));
  expect(clients).toHaveLength(2);
  for (const c of clients) {
    expect(c.Properties.AccessTokenValidity).toBe(15);
    expect(c.Properties.TokenValidityUnits.AccessToken).toBe('minutes');
  }
});
