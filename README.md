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
│       ├── workload.py        # machine login: GitHub/OIDC tokens, signed AWS STS
│       ├── container.py       # `enclave run`: hardened docker/podman launcher
│       ├── dotenv.py          # in-memory env-file parsing for exec/run
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
        ├── lib/{machines,oidc,awsiam}.ts       # machine-identity bindings + verifiers
        ├── auth/{request,verify,workload}.ts
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

## Machine identities and running workloads

Humans log in with an emailed code. Workloads (CI jobs, containers, Lambdas,
Kubernetes pods) never should, and should not hold a stored key either. A project
owner instead **binds the workload's own platform identity** to stages of the
project on the project's settings page, or via `POST /api/admin/projects/<p>/machines`:

| Source            | Bound by                                                                  |
| ----------------- | ------------------------------------------------------------------------- |
| GitHub Actions    | `repository` (`owner/repo`), optionally `ref` / `environment`; or `sub`   |
| Any OIDC issuer   | issuer URL + a `sub` pattern (GitLab CI, Kubernetes service accounts, …)  |
| AWS IAM role      | account id + role name; proven with a signed `sts:GetCallerIdentity`      |

Each binding grants `read` (pull and decrypt) or `write` (also upload and
delete) on a chosen set of stages. `*` in a pattern matches anything except
`:`. The server refuses bindings that would admit strangers: a GitHub binding
must pin an owner, and other issuers need a literal `sub` prefix.
Machine tokens live 15 minutes, work only on `/crypto/datakey` and
`/s3/presign`, and are re-checked against the binding on every call. Editing
or removing a binding cuts them off immediately. Tokens must be minted for the
deployment's audience, printed by `sst deploy` as `WorkloadAudience` and served
at `GET /api/auth/workload`. The flag is `features.machineIdentities`.

### Logging in as a workload

A project owner binds a platform identity to a project (stages + read/write).
The workload then trades a token its platform already gives it for a 15-minute
enclave token, valid only for `/crypto/datakey` and `/s3/presign` in that scope.

```bash
enclave machine-login --project webapp --identity ci --github           # GitHub Actions OIDC
enclave machine-login --project webapp --identity k8s \
  --oidc-token-file /var/run/secrets/tokens/enclave                      # Kubernetes projected token
enclave machine-login --project webapp --identity gitlab --oidc-token-env ENCLAVE_ID_TOKEN
enclave machine-login --project webapp --identity ecs --aws             # IAM role, signed sts:GetCallerIdentity
```

`--aws` needs `pip install 'enclave-envoy[aws]'` (botocore). The signed STS
request includes an `x-enclave-server-id` header bound to this deployment's
audience, so it cannot be replayed against another enclave server. Add
`--print-token` to get just the token, and set `ENCLAVE_TOKEN` / `ENCLAVE_API_URL`
so nothing is written to `~/.enclave`:

```yaml
# .github/workflows/deploy.yml
jobs:
  deploy:
    runs-on: ubuntu-latest
    permissions:
      id-token: write   # lets the job mint an OIDC token
      contents: read
    env:
      ENCLAVE_API_URL: https://enclavecore.app/api
    steps:
      - uses: actions/checkout@v4
      - run: pip install enclave-envoy
      - run: echo "ENCLAVE_TOKEN=$(enclave machine-login --project webapp --identity ci --github --print-token)" >> "$GITHUB_ENV"
      - run: enclave exec -p webapp -s prod -- npm run deploy
```

### `enclave exec`: secrets into a process, never onto disk

```bash
enclave exec -p webapp -s dev -- npm run dev
enclave exec -p webapp -s dev --file .env --file .env.local --no-override -- ./manage.py migrate
```

Env files are downloaded and decrypted in memory and merged in order (later
files win). With no `--file`, every stored `.env`, `.env.*` and `*.env` file is
loaded. Secrets override the existing environment unless `--no-override`.
Signals are forwarded and the command's exit code is returned.

### `enclave run`: a hardened container with the stage's secrets

```bash
enclave run -p webapp -s prod -- ghcr.io/acme/api@sha256:<digest>
enclave run -p webapp -s prod --as-files --network none --publish 8080:8080 \
  --cosign-key cosign.pub -- ghcr.io/acme/api@sha256:<digest> serve
```

Always applied, with no flag to turn them off:

| Default                                         | Why                                                         |
| ----------------------------------------------- | ----------------------------------------------------------- |
| `--rm --init`                                   | no leftover container holding secrets; PID 1 reaps zombies  |
| `--read-only` (`--writable` to drop)            | the image cannot be modified at runtime                     |
| `--tmpfs /tmp:rw,noexec,nosuid,nodev,size=64m`  | scratch space that cannot run binaries                      |
| `--cap-drop ALL`                                | `--cap-add` only for NET_BIND_SERVICE, CHOWN, SETUID, SETGID, FOWNER |
| `--security-opt no-new-privileges`              | setuid binaries cannot escalate                             |
| `--ipc private`                                 | no shared memory with other containers                      |
| `--user 65534:65534`                            | non-root (your own uid with `--as-files`, see below)        |
| `--pids-limit 256 --memory 512m`                | fork bombs and memory exhaustion stay contained             |

Refused outright: `--network host` / `container:*`, mounting an engine socket
(`*.sock`), `/`, `/proc`, `/sys`, `/dev`, `/etc`, `/run`, `/var/run`, your home
directory or any parent of it, and anything under `~/.ssh`, `~/.aws` or
`~/.enclave` (symlinks are resolved first). Volumes are read-only unless `:rw`.

Images must be pinned by `@sha256:` digest unless you pass `--allow-unpinned`.
`--cosign-key KEY` runs `cosign verify` before anything starts.

How secrets reach the container:

- **Default (env):** argv carries only `-e KEY`. The values live in the environment
  of the docker/podman CLI process (which gets a minimal environment, not yours),
  so they never appear on disk or in `ps`. The engine still stores them in the
  container config, so they are visible to `docker inspect`, which is root-equivalent anyway.
- **`--as-files`:** one 0400 file per key plus `.env` in a 0700 directory on RAM-backed
  `/dev/shm` (disk-backed temp dir with a warning where there is none, e.g. macOS),
  mounted read-only at `/run/secrets` and deleted when the container exits.
  The container runs as your own uid (still non-root) so it can read them;
  rootless podman gets `--userns keep-id`. Rootless *docker* maps your uid to
  root in the container, where the files show up as owned by root. Pass `--user 0:0` there, or use env mode.

`--dry-run` prints the engine command, which contains secret names only.
Engine: `--engine`, else `$ENCLAVE_CONTAINER_ENGINE`, else `docker`, else `podman`.

## Deploying a production stage

Every stage is a fully independent deployment: its own KMS master key, bucket, tables,
API, IAM roles and secrets. Nothing is shared with `dev`, and secrets do **not** carry
over — SST stores them per stage in SSM Parameter Store.

Production runs on the custom domain in `siteDomains` (`infra/sst.config.ts`).
DNS has to be reachable to SST before the first deploy: a Route 53 hosted zone is
managed automatically, anything else needs the ACM validation records added by hand,
and the deploy waits on certificate validation until they resolve.

```bash
cd infra

# Fresh values — never reuse the dev signing key or external id in production.
npx sst secret set JwtSigningKey "$(openssl rand -hex 32)" --stage production
npx sst secret set StageAssumeExternalId "$(openssl rand -hex 16)" --stage production
npx sst secret set SesSender no-reply@yourdomain.example --stage production
npx sst secret set EdgeOriginToken "$(openssl rand -hex 32)" --stage production

npx sst secret list --stage production   # expect all four
npx sst deploy --stage production
```

Then open the printed `SiteUrl`, log in with an address from `adminEmails`, and create a
project — that first login is what proves SES, KMS and the presign role are all wired up
on this stage.

### The API is served from the site distribution

`sst deploy` prints two API values and they are not interchangeable:

- **`ApiUrl`** is `<SiteUrl>/api`. This is what `enclave configure --api-url` takes.
  It goes through CloudFront, so the edge Web ACL sees it.
- **`ApiOriginUrl`** is the raw API Gateway URL. It bypasses the Web ACL, and once
  `EdgeOriginToken` is set on the stage every handler rejects it with a 403.

AWS WAF cannot attach to an API Gateway HTTP API, only to CloudFront, which is why
the API is an origin on the site distribution under `/api` rather than a separate
public endpoint. The browser therefore calls the API same-origin and never makes a
cross-origin API request. The bucket still needs CORS, because the browser PUTs and
GETs presigned S3 URLs directly.

The Web ACL is production-only and carries two per-IP rate limits: a broad flood
backstop, and a tighter one scoped to `POST /api/*`, the requests that spend SES,
KMS and DynamoDB.

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

- **CORS is scoped by stage.** Origins come from `siteDomains` in the config. A stage
  with a domain allows exactly that origin; a stage without one falls back to `"*"`, and
  production refuses to deploy without one.
- **Check the SES identity.** `sesIdentity` in the config is the domain the OTP grant is
  scoped to, and it must be verified **and out of the sandbox** in the same account and
  region, or login mail silently fails for anyone who is not a verified recipient.
- **The throttle is now two-layered.** The API keeps its stage-wide cap of 20 req/s
  (burst 40) shared across all callers, and production adds per-IP limits at the edge
  Web ACL. Tune the Web ACL limits from its CloudWatch metrics rather than lifting the
  stage cap.
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
