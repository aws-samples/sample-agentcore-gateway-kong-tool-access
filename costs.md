# Costs

What this stack (`lib/stack.ts`) costs to run in **us-east-1**, in two scenarios:

- **A. Demo, as delivered:** deployed for a full month, used only for a few demo runs. **≈ $51/month**, or **≈ $0.07/hour** (a deploy → demo → destroy session of about 2 hours costs **≈ $0.16**).
- **B. Illustrative volume:** the same stack serving 10 always-on agents. **≈ $117/month**, and about half of that is Cognito token requests.

Rates come from the public AWS Price List offer files for us-east-1 (`pricing.us-east-1.amazonaws.com`, published Sep–Nov 2026) and the [AgentCore pricing page](https://aws.amazon.com/bedrock/agentcore/pricing/). Prices are on-demand, with no free tier and no Savings Plans applied. A month is 30 days, or 720 hours. Check the pricing pages before relying on these numbers; this is an estimate, not a quote.

## Assumptions

| Input | A. Demo | B. Volume | Source |
|---|---|---|---|
| Hours deployed | 720 | 720 | Full month |
| Demo runs (`demo/demo.sh`) | 10 | – | Illustrative |
| Agents (Cognito M2M clients) | 2 | 10 | A: the stack. B: illustrative |
| Token requests | ~7 per demo run | 2,880 per agent (a new 15-min token, 24×7) | `accessTokenValidity: 15 min` |
| Gateway MCP requests | ~15 per demo run | 100,000 (~2.3/min) | Illustrative; includes `initialize` |
| `tools/call` reaching Kong | ~2 per run | 50,000 (half of requests) | Illustrative |
| Interceptor invocations | 2 per Gateway request (REQUEST + RESPONSE) | same | `interceptorConfigurations` |
| Lambda duration | 100 ms | 100 ms | Default (stdlib, no I/O) |
| Payload per API call | 10 KB | 10 KB | Default |
| Log volume per invocation | 1 KB | 1 KB | Default |
| ALB health checks | 2 ALB nodes × every 15 s, ~250 B Kong log line each | same | `healthCheck.interval: 15 s` |
| Container Insights metrics | ~38 series | ~38 series | Estimate (see below) |

The volume numbers are illustrative, not measured. Replace them with your own agent count and request rate.

## AWS Fargate

**How it's used:** One `kta-kong` task running all month: 0.5 vCPU, 1 GB, x86_64, running Kong and the Sites API sidecar (`FargateTaskDefinition` `Task`, `desiredCount: 1`).

**How it's priced:** Per vCPU-hour and per GB-hour.

**Calculation:**

- vCPU: 0.5 × 720 h × $0.04048 = $14.57
- Memory: 1 GB × 720 h × $0.004445 = $3.20

**Total: $17.77** (same in A and B)

**Pricing docs:** <https://aws.amazon.com/fargate/pricing/>

## Public IPv4 address

**How it's used:** `assignPublicIp: true` on the Fargate service, so the task can pull images from Docker Hub without a NAT gateway. This is a demo trade-off; see the README's security notes.

**How it's priced:** Per in-use public IPv4 address per hour.

**Calculation:**

- 1 address × 720 h × $0.005 = $3.60

**Total: $3.60**

**Pricing docs:** <https://aws.amazon.com/vpc/pricing/>

## Elastic Load Balancing (internal ALB)

**How it's used:** Internal HTTPS ALB `Alb` that sits in front of Kong. It only receives traffic from the Lattice resource gateway.

**How it's priced:** Per ALB-hour, plus per LCU-hour (or partial hour) used.

**Calculation:**

- ALB: 720 h × $0.0225 = $16.20
- LCU: health checks plus 50,000 requests a month (B) is a tiny fraction of one LCU (25 new connections/s, 1 GB/h processed) × $0.008 ≈ $0.00

**Total: $16.20**

**Pricing docs:** <https://aws.amazon.com/elasticloadbalancing/pricing/>

## Amazon CloudWatch Container Insights

**How it's used:** `containerInsightsV2: ContainerInsights.ENABLED` on `kta-cluster`. ECS publishes `ECS/ContainerInsights` metrics and writes performance log events.

**How it's priced:** Custom metrics per metric-month, plus log ingestion for the performance events.

**Calculation:**

- Metrics: about 38 series × $0.30 = $11.40. This count comes from the [documented metric table](https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/Container-Insights-metrics-ECS.html), Fargate rows only: 10 metrics × 3 dimension sets (task family, service, cluster), 5 service-only metrics and 3 cluster-only metrics.
- Performance logs: ~6 events/min × 1.5 KB ≈ 0.39 GB × $0.50 = $0.19 (estimate)

**Total: $11.59.** This is the biggest optional line. Turning Container Insights off saves it; the ECS vended metrics (CPU, memory) remain free.

**Pricing docs:** <https://aws.amazon.com/cloudwatch/pricing/>

## Amazon CloudWatch Logs

**How it's used:** Three log groups, encrypted with the KMS key and kept for 1 week: `/kta/kong` (Kong and API containers), `/aws/lambda/kta-tool-interceptor`, and the Gateway's vended `APPLICATION_LOGS` in `/aws/vendedlogs/bedrock-agentcore/kta-gw`.

**How it's priced:** Per GB ingested (standard and vended logs both cost $0.50/GB for the first tier), plus per GB-month stored.

**Calculation (A):**

- Kong health-check access logs: 2 × 4/min × 43,200 min × 250 B ≈ 0.09 GB × $0.50 = $0.04
- Interceptor and Gateway logs from 10 demo runs: ≈ $0.00
- Storage: 1-week retention keeps under 0.1 GB × $0.03 ≈ $0.00

**Calculation (B):**

- Standard (Kong + interceptor): (0.09 + 0.01 + 200,000 × 1 KB = 0.2) GB ≈ 0.30 GB × $0.50 = $0.15
- Vended (Gateway): 100,000 × 1 KB = 0.1 GB × $0.50 = $0.05
- Storage: ≈ $0.00

**Total: A $0.04 · B $0.20**

**Pricing docs:** <https://aws.amazon.com/cloudwatch/pricing/>

## AWS Secrets Manager

**How it's used:** Two secrets. One is `kta/kong-api-key`, which ECS injects into Kong. The other is the provider-managed secret AgentCore Identity creates for `ApiKeyProvider` (`bedrock-agentcore-identity!default/apikey/...`).

**How it's priced:** Per secret per month (prorated hourly), plus per 10,000 API calls.

**Calculation:**

- Secrets: 2 × $0.40 = $0.80
- API (B, upper bound of one key read per `tools/call`; the real caching behavior isn't documented): 50,000 × $0.05/10,000 = $0.25

**Total: A $0.80 · B $1.05**

**Pricing docs:** <https://aws.amazon.com/secrets-manager/pricing/>

## AWS KMS

**How it's used:** One customer managed key `DataKey`, with rotation turned on. It encrypts the Kong secret, the three log groups and the interceptor's environment variables.

**How it's priced:** Per key version per month (prorated hourly), plus per 10,000 requests. The first 20,000 requests each month are free.

**Calculation:**

- Key: 1 × $1.00 = $1.00. Each yearly rotation adds a key version and $1/month, capped after the second rotation.
- Requests: CloudWatch Logs data-key calls, plus decrypts at task start and Lambda cold start, stay well under 20,000 a month, so $0.00

**Total: $1.00**

**Pricing docs:** <https://aws.amazon.com/kms/pricing/>

## Amazon Cognito

**How it's used:** User pool `kta-pool` with two client-credentials (M2M) app clients, `reader` and `operator`. It has no users, so there are no monthly active users (MAU) to bill.

**How it's priced:** M2M app clients ($0.00 in the current price list) and M2M token requests ($0.00225 each for the first 250,000 a month).

**Calculation:**

- A: 10 runs × ~7 tokens = 70 × $0.00225 = $0.16
- B: 10 agents × 2,880 tokens = 28,800 × $0.00225 = $64.80

**Total: A $0.16 · B $64.80.** This is the dominant cost at volume. Agents must reuse each token until it expires. With 60-minute tokens, B would cost $16.20, but the 15-minute lifetime is a deliberate security choice (threat model T12).

**Pricing docs:** <https://aws.amazon.com/cognito/pricing/>

## Amazon Bedrock AgentCore Gateway (and Identity)

**How it's used:** Gateway `kta-gw` serving MCP requests, plus one OpenAPI target that reaches the ALB privately through a managed VPC resource (`privateEndpoint.managedVpcResource`). Semantic search isn't turned on (no `searchType`), so there are no tool-indexing or search charges. AgentCore Identity (the API key provider) costs nothing extra when used through Gateway.

**How it's priced:** Per API invocation, plus a data-processing charge on traffic to customer VPCs. In managed mode, the VPC Lattice resource gateway has no hourly charge, only data processing. The AgentCore price list bills this at $0.006/GB; even at VPC Lattice's $0.025/GB, the total still rounds to cents.

**Calculation:**

- Invocations A: 150 × $0.000005 = $0.00
- Invocations B: 100,000 × $0.000005 = $0.50
- Private target data B: 50,000 × 10 KB = 0.5 GB × $0.006 = $0.00

**Total: A $0.00 · B $0.50**

**Pricing docs:** <https://aws.amazon.com/bedrock/agentcore/pricing/>

## AWS Lambda

**How it's used:** The `kta-tool-interceptor` function (Python, arm64, 128 MB) runs at REQUEST and RESPONSE for every Gateway request.

**How it's priced:** Per request, plus per GB-second.

**Calculation (B):**

- Requests: 200,000 × $0.0000002 = $0.04
- Compute: 200,000 × 0.1 s × 0.125 GB = 2,500 GB-s × $0.0000133334 = $0.03

**Total: A $0.00 · B $0.07**

**Pricing docs:** <https://aws.amazon.com/lambda/pricing/>

## Not priced

- **No charge:** the ECS cluster, IAM, security groups, ACM's public certificate, Route 53 alias queries to the ALB, and Cognito user pool MAU (there are no users).
- **Excluded:** your existing Route 53 hosted zone, the CDK bootstrap bucket, data transfer (image pulls from Docker Hub are inbound and free; small cross-AZ hops between the Lattice ENIs, the ALB and the task), CloudTrail, support plans, and the agents' own model or runtime costs (the agents run outside this stack).
- **Production changes not priced here:** a second Fargate task for high availability (+$17.77 at the same size), private subnets with Amazon ECR and VPC interface endpoints instead of the public IP, and longer log retention.

## What moves the total

1. **Token requests (Cognito).** Cost grows linearly with agents × token lifetime. Cache tokens until they expire, and keep the agent count honest.
2. **Hours deployed.** In A, about 99% of the bill is hourly (Fargate, ALB, Container Insights, IPv4). Destroy the stack between demos (`npx cdk destroy`), or turn off Container Insights to cut A from ~$51 to ~$40.

## Total monthly cost

| Service | A. Demo | B. Volume |
|---|---:|---:|
| AWS Fargate | $17.77 | $17.77 |
| Public IPv4 | $3.60 | $3.60 |
| Elastic Load Balancing (ALB) | $16.20 | $16.20 |
| CloudWatch Container Insights | $11.59 | $11.59 |
| CloudWatch Logs | $0.04 | $0.20 |
| Secrets Manager | $0.80 | $1.05 |
| AWS KMS | $1.00 | $1.00 |
| Amazon Cognito (M2M tokens) | $0.16 | $64.80 |
| AgentCore Gateway | $0.00 | $0.50 |
| AWS Lambda | $0.00 | $0.07 |
| **Total** | **$51.16** | **$116.78** |
