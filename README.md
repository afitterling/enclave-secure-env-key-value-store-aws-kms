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
AWS action (KMS, S3) is brokered by a Lambda that re-checks the YAML on every call.

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
- The bucket denies non-TLS requests and unencrypted `PutObject`.
- `cd cli && pytest` and `cd web && npm test` assert both clients produce byte-identical
  envelopes via the shared fixture in `testdata/envelope-vector.json`.
