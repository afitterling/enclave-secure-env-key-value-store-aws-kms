# Dev stage deployment result

Stack: `enclave-envoy`, stage `dev` — deployed 2026-08-20 with SST 3.19.3
(`npx sst deploy --stage dev` from `infra/`, exit code 0).

## Target

| | |
|---|---|
| AWS account | 327261196437 |
| Region | eu-central-1 |
| Git commit | `842a837` — Fix two hardening regressions found by live verification |
| Working tree | clean |
| Edition | `opensource` (teams / team grants are enterprise-only) |

## Outputs

| Output | Value |
|---|---|
| `SiteUrl` (web UI) | https://d2p0psmzi6ajta.cloudfront.net |
| `ApiUrl` (CLI + web API) | https://nhv5tdp1zk.execute-api.eu-central-1.amazonaws.com |
| `Bucket` | `enclave-envoy-dev-vaultbucketbucket-bbasfmsv` |
| `KmsKeyId` | `305f7713-2e01-44c8-83f9-c4639b9fd898` |

SST permalink: https://sst.dev/u/3f36cec9

## What changed

Nothing in AWS beyond a web bundle rebuild. The only resource churn was the
`Web → WebBuilder` local command (created, then deleted as SST does for local
commands); every other resource was already in its desired state, so the
CloudFront distribution, API Gateway endpoint, bucket, and KMS key are
unchanged from the previous deploy.

Web build: `tsc --noEmit && vite build` — 50 modules, 192.18 kB JS
(62.29 kB gzip), 9.99 kB CSS, built in 320 ms.

## State

### Live checks (2026-08-22, unauthenticated probes)

| Check | Result |
|---|---|
| `GET /` on SiteUrl | `200` |
| Bundle served by CloudFront | `assets/index-CbGl1U17.js` — matches the bundle this deploy built, so the invalidation has propagated |
| `GET /access/whoami` without a token | `401` — API is live and rejecting unauthenticated callers |
| `GET /__nope` (unknown route) | `404` |

AWS-side resource state (Lambda, DynamoDB, KMS key state, bucket versioning /
encryption) could **not** be re-verified: the `alex1-dev` SSO token has expired
since the deploy. Refresh with `aws sso login --profile alex1-dev` to query it.

### Declared state (`infra/sst.config.ts`)

Resources the stack provisions:

- **KMS** — `EnclaveMasterKey` + alias; envelope-encryption root, key material never leaves KMS.
- **S3** — `VaultBucket`, keys laid out as `<project-id>/<stage>/<file>`, with a per-stage bucket policy.
- **DynamoDB** — `OtpTable` (one-time login codes, TTL-expired) and `AccessTable` (project/member/grant access map).
- **IAM** — one `StageRole-<stage>` per stage; the bucket policy scopes each role to its own `<project>/<stage>/*` keys.
- **API Gateway v2** — `Api`, CORS open to `*` for `GET`/`POST`, stage throttle 20 req/s steady / 40 burst.
- **StaticSite** — `Web`, built from `../web`, `VITE_API_URL` / `VITE_FEATURES` / `VITE_EDITION` baked in at build time.

Routes (all Lambda-backed):

| Route | Handler |
|---|---|
| `POST /auth/request` | `functions/auth/request.handler` |
| `POST /auth/verify` | `functions/auth/verify.handler` |
| `GET /access/whoami` | `functions/access/whoami.handler` |
| `POST /crypto/datakey` | `functions/crypto/datakey.handler` |
| `POST /s3/presign` | `functions/s3/presign.handler` |
| `GET  /admin/{proxy+}` | `functions/admin/handler.handler` |
| `POST /admin/{proxy+}` | `functions/admin/handler.handler` |

Configuration:

- Valid stages: `dev`, `staging`, `prod`, `personal`.
- Bootstrap admins (`adminEmails`): `info@sp33c.tech`. Everyone else must be invited to a project first.
- SES identity: `sp33c.tech` (domain identity; the `ses:SendEmail` grant is scoped to it).
- Feature flags: `landing: true`, `fileDelete: true`.
- Removal policy: `remove` for non-prod; `prod` is `retain` + `protect`.

Secrets used by the stage — `SesSender`, `JwtSigningKey`, `StageAssumeExternalId`.
They were already set and were not touched by this deploy (their values could not
be listed here for the same expired-SSO reason).

## Notes

- Access is invite-only; the CLI never receives AWS credentials — every privileged
  action is brokered by a Lambda that re-validates the caller's JWT and the access
  map on each call.
- To re-verify the AWS-side state: `aws sso login --profile alex1-dev`, then
  `npx sst deploy --stage dev` (a no-op deploy) or direct `aws` calls.
