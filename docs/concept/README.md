# Concept: identities, entitlements and safe workload runs

enclave-envoy stores a project's environment files per stage, encrypted with
KMS envelope encryption, and hands them out only to principals that are
allowed to read that stage. These documents describe how that idea extends from
people to workloads: who can be a principal, how a workload proves who it is,
how access is decided and reviewed, and how secrets reach a running container
without being exposed on the way.

The README says how to *use* each feature. These documents say *why it is
shaped this way* and what it does and does not protect against.

| Document | Edition | What it covers |
|---|---|---|
| [machine-identities.md](machine-identities.md) | open source | Bindings, OIDC and AWS IAM login, machine tokens, the single authorization gate, revocation |
| [workload-delivery.md](workload-delivery.md) | open source | `enclave exec` and `enclave run`: getting secrets into a process or a local container |
| [ciem.md](ciem.md) | enterprise | Audit trail, effective entitlements, findings, utilization, time-boxed grants |
| [cloud-runner.md](cloud-runner.md) | enterprise | Running an image on Fargate with a stage's secrets, proven by the task's own IAM role |

## The problem

Before this work, every principal was a human with an email address who logged
in with a one-time code. A CI job or a container had two bad options: reuse a
person's token, or have someone paste the decrypted env file into the CI
system's secret store. Either way the secret leaves the vault, nobody can see
who used it, and access outlives the reason it was granted.

The goals:

1. **Workloads log in as themselves**, using the identity their platform
   already gives them (GitHub Actions OIDC, any OIDC issuer, an AWS IAM role).
   There's no shared secret to store, rotate or leak.
2. **One place decides access** for humans and machines, and a revocation takes
   effect on the next request, not when a token expires.
3. **Secrets reach the workload without touching disk or argv** wherever the
   platform allows it, and the container they land in is locked down by
   default.
4. **Access is visible and reviewable**: who can reach which stage and how, what
   they actually used, and what looks excessive (enterprise).

## Principals

| Principal | Subject (`sub`) | Obtained by | Can |
|---|---|---|---|
| Human | email | OTP login (`/auth/request`, `/auth/verify`) | everything their membership allows, including administering projects they own |
| Machine | `machine:<project>/<binding id>` | workload login with an OIDC token or a signed STS request (`/auth/workload`) | read, or read and write, the stages its binding lists; never the admin API |
| Runner (enterprise) | `runner:<ECS task id>` | cloud-runner init login with the task role (`/auth/workload`, `runner: true`) | read the one stage of its own run, until the run's deadline |

Machine and runner tokens are the service's own HS256 JWTs with `typ: "machine"`
and a 15-minute lifetime. `requireAuth()` (admin endpoints) refuses them;
`requirePrincipal()` (the vault endpoints: data keys and presigned S3 URLs)
accepts all three.

## The single gate

Every vault call goes through `authorize(claims, project, stage, action)` in
`infra/functions/lib/access.ts`, where `action` is `read` or `write`:

```
human   -> canAccess(): owner, direct member with the stage, or (enterprise) a
           team grant covering the stage; members' grants may carry an expiry
machine -> the binding named in the token, re-read now: same rev, same project,
           lists the stage, not expired, grants write for writes
runner  -> the run record, re-read now: same nonce, same project and stage,
           deadline not passed; read only
```

All three paths read DynamoDB on every call. That's what makes revocation
immediate. The data-key endpoint maps `generate` to write and `decrypt` to read.
The presign endpoint maps `upload` and `delete` to write, and `download` and
`list` to read.

Plaintext never passes through the API. The server brokers KMS data keys and
presigned S3 URLs; encryption and decryption happen in the client (the CLI, or
the runner's init container).

## Edition split

| Capability | Flag | Edition |
|---|---|---|
| Machine identities, `enclave exec`, `enclave run` | `machineIdentities` | open source (`main`, published to `enclave-oss`) |
| Teams | `teams` | enterprise |
| Audit trail, access review, time-boxed grants | `ciem` | enterprise |
| Fargate cloud runner | `cloudRunner` | enterprise |

Flags are set per edition in `infra/sst.config.ts` (`editionFeatures`),
enforced in the Lambdas (`functions/lib/features.ts`) and baked into the web
build. The enterprise code is physically absent from `main`; the flag only
decides whether code that is present is switched on.

> This is the enterprise branch. `main` carries the open-source subset of these
> documents, without `ciem.md` and `cloud-runner.md`.
