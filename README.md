# enclave-envoy

Securely store, sync and share the **environment files of your development stacks** —
`.env`, `.env.local`, `.env.production` and friends from React/Next/Vite, Node, Python
or any other project — across devices and teammates, using **AWS S3** for storage and
**AWS KMS** for envelope encryption, with **passwordless email (OTP) authentication**.
Comes with a **web UI** (browser-side encryption; env files render as a KEY=VALUE table
with values hidden until revealed) and a **Python CLI** that share the same
byte-compatible envelope format. Files are opaque encrypted blobs, so other secret-like
files work too — but environment files are what it is built for.

```
device A ──encrypt──► S3 (project-id/stage/file)  ◄──decrypt── device B
   │                        ▲                              │
   └── KMS data key ────────┘──────── KMS data key ────────┘
        (master key stays inside KMS)
```

## Why this shape

| Requirement                                  | How it is met                                                              |
| -------------------------------------------- | -------------------------------------------------------------------------- |
| Client-side encryption, master key in KMS    | Envelope encryption: KMS `GenerateDataKey`, AES-256-GCM locally            |
| Decrypt on another device                    | KMS-encrypted data key is embedded in the blob; any device asks KMS to unwrap it |
| Email login + one-time secret                | `/auth/request` mails a 6-digit code via SES; `/auth/verify` issues a JWT. Invite-only: admins (`adminEmails` in `sst.config.ts`) plus anyone holding a membership |
| Per-stage access via **bucket policies**     | Lambda assumes a per-stage IAM role; bucket policy scopes each role to its stage's `<project>/<stage>/<file>` keys |
| Dynamic email → project/stage mapping        | DynamoDB `AccessTable` (projects, members, teams, grants) managed from the web UI via `/admin/*` |
| `project-id/stage-name/file` layout          | Enforced by the presign Lambda and the bucket policy prefix conditions     |
| Three folders (CLI + infra + web)            | [`cli/`](./cli), [`infra/`](./infra) and [`web/`](./web)                   |

The CLI **never holds AWS credentials**. It only ever has a short-lived JWT session token; every
AWS action (KMS, S3) is brokered by a Lambda that re-checks the DynamoDB access map on every call.

## Repo layout

```
enclave-envoy-tool/
├── testdata/envelope-vector.json  # shared Python↔JS envelope compatibility fixture
├── cli/                       # Python CLI + client-side key management
│   ├── pyproject.toml
│   ├── tests/test_crypto.py   # envelope format tests (pytest)
│   └── enclave/
│       ├── cli.py             # `enclave` command (click)
│       ├── auth.py            # email-OTP login + token storage
│       ├── client.py          # thin HTTPS client for the API
│       ├── crypto.py          # AES-256-GCM envelope format
│       ├── sync.py            # bulk push/pull of dotfiles
│       └── config.py          # ~/.enclave config + session
├── web/                       # Vite + React SPA (deployed by the same `sst deploy`)
│   └── src/
│       ├── lib/               # api client, ENV1 envelope codec (WebCrypto), dotenv parser
│       ├── pages/             # login, projects, project, settings, teams
│       └── components/        # file list, upload, masked env table, viewer
└── infra/                     # SST v3 (ion) infrastructure as code
    ├── sst.config.ts          # bucket, KMS key, DynamoDB (OTP + access), API, roles, StaticSite
    ├── package.json
    └── functions/
        ├── lib/{jwt,access,assume,response}.ts   # access.ts = DynamoDB access map
        ├── auth/{request,verify}.ts
        ├── access/whoami.ts
        ├── admin/handler.ts   # projects/teams/members/grants (web UI)
        ├── crypto/datakey.ts
        └── s3/presign.ts
```

## Quick start

### 1. Deploy the infrastructure

```bash
# Set your bootstrap admin email(s) in infra/sst.config.ts (`adminEmails`) first.
cd web && npm install && cd ../infra
npm install
# A verified SES sender + your AWS profile are the only manual prerequisites.
npx sst secret set JwtSigningKey "$(openssl rand -hex 32)" --stage dev
npx sst secret set SesSender no-reply@yourdomain.example --stage dev
# Confused-deputy guard: the presign Lambda presents this ExternalId to assume a stage role.
npx sst secret set StageAssumeExternalId "$(openssl rand -hex 16)" --stage dev
npx sst deploy --stage dev
```

`sst deploy` prints `ApiUrl` (for the CLI) and `SiteUrl` (the web UI). Open `SiteUrl`,
log in with an admin email, create a project, and upload/view env files — values render
as a masked KEY=VALUE table after in-browser decryption. Invite teammates (or grant
teams) from the project's settings page; invited emails can then log in too.

### 2. Configure and use the CLI

```bash
cd ../cli
pip install -e .

enclave configure --api-url https://xxxx.execute-api.eu-central-1.amazonaws.com
enclave login alice@example.com          # → enter the 6-digit code from your inbox

# push your app's environment files for project "webapp", stage "dev"
enclave push --project webapp --stage dev .env .env.local
# or sweep every env file in the project directory:
enclave push --project webapp --stage dev --glob "./.env*"

# on another device (or a teammate's), after logging in:
enclave pull --project webapp --stage dev --dest ./
```

## Deploying a production stage

Every stage is a fully independent deployment: its own KMS master key, bucket, tables,
API, IAM roles and secrets. Nothing is shared with `dev`, and secrets do **not** carry
over — SST stores them per stage in SSM Parameter Store.

```bash
cd infra

# Fresh values — never reuse the dev signing key or external id in production.
npx sst secret set JwtSigningKey "$(openssl rand -hex 32)" --stage production
npx sst secret set StageAssumeExternalId "$(openssl rand -hex 16)" --stage production
npx sst secret set SesSender no-reply@yourdomain.example --stage production

npx sst secret list --stage production   # expect all three
npx sst deploy --stage production
```

Then open the printed `SiteUrl`, log in with an address from `adminEmails`, and create a
project — that first login is what proves SES, KMS and the presign role are all wired up
on this stage.

### What the `production` stage name changes

Naming the deployment stage exactly `production` flips two safety switches in
`infra/sst.config.ts`:

- `removal: "retain"` — tearing the stack down leaves the bucket, KMS key and DynamoDB
  tables in place, so encrypted data and the key that decrypts it survive a mistake.
- `protect: true` — `sst remove --stage production` is refused outright. To decommission
  it deliberately you must first set `protect` to `false` in the config and deploy.

Both are a literal string comparison against the stage name. Deploying to `prod`, `prd`
or anything else gets you an unprotected stack that removes cleanly, with no warning.

### Two meanings of "stage"

These are independent and it is easy to conflate them:

- The **deployment stage** (`--stage production`) selects which copy of the
  infrastructure you are talking to.
- The **vault stages** (`stages` in `infra/sst.config.ts`: `dev`, `staging`, `prod`,
  `personal`) are the per-project buckets your env files are filed under, and every
  deployment offers all four. A production deployment still holds `dev` env files, and
  `enclave push --project webapp --stage dev` against it is normal.

The vault stage is still called `prod`, and deliberately so: it is baked into existing
S3 keys (`<project>/prod/<file>`) and into the bucket policy, so renaming it would
orphan already-uploaded files.

Resource names carry the deployment stage, so the two never collide: a production
deployment creates `alias/enclave-envoy-production` and IAM roles
`enclave-envoy-production-dev`, `enclave-envoy-production-staging`,
`enclave-envoy-production-prod`, `enclave-envoy-production-personal`.

### Before you put real secrets in it

- **Lock down CORS.** The API and the bucket both allow `allowOrigins: ["*"]`. That is
  fine for a dev stack but in production it should be the CloudFront site origin. Deploy
  once to learn `SiteUrl`, then narrow both and redeploy.
- **Check the SES identity.** `sesIdentity` in the config is the domain the OTP grant is
  scoped to, and it must be verified **and out of the sandbox** in the same account and
  region, or login mail silently fails for anyone who is not a verified recipient.
- **Raise the throttle deliberately.** The API carries a stage-wide cap of 20 req/s
  (burst 40) shared across all users. Add a WAFv2 rate-based rule keyed on IP as the
  per-client layer rather than just lifting the cap.
- **Set `adminEmails` for production.** Bootstrap admins are compiled in, not per-stage.
  If production needs a different set, that is a config change and a redeploy.

## Security notes / things to harden before production

- The 6-digit OTP is rate-limited (5 attempts, 10-minute TTL, 60 s resend throttle). For higher
  assurance use a longer alphanumeric secret — see `OTP_DIGITS` in `infra/functions/auth/request.ts`.
- Access lives in the DynamoDB `AccessTable` (projects, members, teams, grants) — metadata only,
  never secrets; file contents are always client-side-encrypted before reaching AWS. Login is
  invite-only: bootstrap admins come from `adminEmails` in `infra/sst.config.ts`.
- Plaintext data keys live only in client memory (CLI process / browser tab) and are zeroized
  after use (best-effort in Python). The web UI's value masking is a display convenience, not a
  security boundary.
- The web session JWT is kept in localStorage (12 h expiry) — acceptable for a first-party SPA
  with no third-party scripts; switch to in-memory if you embed anything untrusted.
- The bucket denies non-TLS requests (`enforceHttps`). Stage IAM roles are scoped by bucket
  policy to their own `*/<stage>/*` prefix and require a secret `ExternalId` to assume, so a bare
  in-account `sts:AssumeRole` can't reach the vault.
- The API has a stage-wide request throttle; OTP verification reserves each of its five attempts
  atomically (a conditional DynamoDB update), so the code space isn't brute-forceable by
  concurrent requests. Session JWTs are HS256, carry `iss`/`aud`, and expire in 1 hour.
- `cd cli && pytest` and `cd web && npm test` assert both clients produce byte-identical
  envelopes via the shared fixture in `testdata/envelope-vector.json`.

## License

Copyright (C) 2026 Alex Fitterling.

This is the open-source edition of enclave-envoy, licensed under the **GNU General
Public License, version 3 or later**. See [LICENSE](LICENSE) for the full text.

This program is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
PARTICULAR PURPOSE. See the GNU General Public License for more details.

Team management (teams, team grants, team-based access resolution) ships in a
separately maintained enterprise edition and is not covered by this licence.
