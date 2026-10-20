# Cloud runner

> **Enterprise edition only** (`cloudRunner` flag). Keep this file off `main`
> and `enclave-oss`.

`enclave cloud-run` runs a container image on AWS Fargate with a stage's env
files, without the plaintext passing through the API, the caller's machine or
the task definition. The run proves *which run it is* with the IAM role ECS
gives the task, and gets a one-time, read-only token for exactly that run's
project and stage.

It's the managed counterpart of `enclave run`
([workload-delivery.md](workload-delivery.md)). Use it when the host running
the container shouldn't be trusted with the secrets, or when there's no host.

Code: `infra/functions/lib/runner.ts` (validation and task definition, pure),
`runner/launch.ts`, `runner/manage.ts`, `runner/reaper.ts`,
`auth/workload.ts` (`runnerLogin`), `cli/enclave/runner.py`, `cli/Dockerfile`.

## Shape of a run

One ECS task with two containers that share a per-task volume:

| Container | Image | Runs as | Job |
|---|---|---|---|
| `enclave-init` | the enclave CLI image (built from `cli/` at deploy) | uid 0, every default capability dropped except `CHOWN` | log in as the run, decrypt, write `/run/secrets`, hand the files to the app's uid, exit |
| `app` | the caller's image, digest-pinned | the requested non-root uid:gid | starts only if init exited 0 |

The app container has:
- `/run/secrets` mounted read-only
- a read-only root filesystem
- `capabilities: drop ALL`
- a private `/tmp` volume
- an init process

The secrets volume is Fargate ephemeral storage: per task, encrypted by Fargate,
and destroyed when the task stops.

## Flow

```mermaid
sequenceDiagram
  participant U as Caller (human or machine)
  participant L as /runner/launch
  participant A as AuditTable
  participant ECS as ECS / Fargate
  participant R as RunTable
  participant I as enclave-init (in task)
  participant W as /auth/workload
  participant V as vault (data key + presign)
  U->>L: { project, stage, image@sha256, files, mode, cpu, memory, maxMinutes, user }
  L->>L: validate; authorize(read)
  L->>A: record run.launch (fail-closed)
  L->>ECS: RegisterTaskDefinition (one-off), RunTask, Deregister
  L->>R: put { runId = task id, nonce, project, stage, files, deadline }
  L-->>U: runId
  I->>I: sign GetCallerIdentity with the task role
  I->>W: { runner: true, aws }  (retries up to 60 s)
  W->>W: STS → assumed-role/<runner role>/<task id>
  W->>R: conditional update: exists, not logged in, deadline ahead → set loggedInAt
  W-->>I: runner token (read, this project/stage, nonce)
  I->>V: data keys + downloads (authorize → run record)
  I->>I: decrypt, write files + .env + env.sh, chown to app uid, exit 0
  ECS->>ECS: start app (dependsOn init SUCCESS)
```

## Why the task role identifies the run

ECS assumes the task role with the **task id as the role session name**, so
the STS caller ARN seen at login is
`arn:aws:sts::<account>:assumed-role/<runner role>/<task id>`. The task id is
also the run id. For that to be proof, nobody else may be able to assume the
role with a session name of their choosing. Hence a dedicated role:

- **Trust policy:** `ecs-tasks.amazonaws.com` only, with `aws:SourceAccount` =
  this account and `aws:SourceArn` = this account's ECS resources.
- **No permissions.** The role exists only to be an identity.
- **Not SST's default task role.** Under `sst dev` that role also trusts the
  account root, which would let any principal in the account mint a session
  named after someone else's task.

The login handler checks:
- the account and the role name
- that the session is a 32-hex task id
- then the run record, in one conditional write

## One-time login and the run token

- **The login is single-use.** The conditional update sets `loggedInAt` only if
  the record exists, isn't yet logged in, and the deadline is in the future.
  A second login for the same task fails, so a compromised app container can't
  log in again even with the same role.
- **The token is read-only** and valid only for the run's project and stage.
  It's re-checked on every vault call against the run record's nonce and
  deadline. Its lifetime is 15 minutes, which is enough for init; the app never
  sees it.
- **A run can't launch or manage runs.** Runner tokens are refused by
  `/runner/*`.
- **Plaintext never passes through the API.** The server only brokers KMS and
  S3, as for every client.

## Delivery modes

| Mode | What the app sees | Command |
|---|---|---|
| `files` (default) | `/run/secrets/<KEY>`, `/run/secrets/.env`, `/run/secrets/env.sh`, read-only | the image's own, or the given one |
| `env` | the variables in its environment | required; the entrypoint becomes `/bin/sh -c '. /run/secrets/env.sh && exec "$@"'` |

Files are written atomically and owned by the app's uid. `env.sh` contains
POSIX `export KEY='value'` lines. In `env` mode the values never appear in the
task definition, `DescribeTasks`, or the ECS console, because they are sourced
at start from the read-only volume.

## Guard rails on a launch request

- **Image:** pinned by digest. Optionally restricted to the registries in
  `runnerRegistries`, matched as a path prefix.
- **User:** numeric `uid[:gid]`, never 0.
- **Size:** Fargate CPU/memory pairs only.
- **Runtime:** `maxMinutes` 1–240.
- **Extra environment:**
  - at most 32 entries
  - valid names
  - the `ENCLAVE_`, `AWS_` and `ECS_` prefixes are reserved
- **Command:** at most 64 arguments.
- **Access:** the caller needs **read** on the stage. Running a container with a
  stage's secrets is reading them.

## Lifecycle and cleanup

- **Deadline.** Fargate has no maximum runtime. The `RunnerReaper` cron (every
  5 minutes) stops tasks past their run's deadline.
- **Orphans.** The reaper also stops any runner task without a run record after
  120 seconds. That covers a launch that died between `RunTask` and writing the
  record. Nothing could have authorized such a task, and it would never get a
  token anyway.
- **Task definitions.** Each run registers a one-off revision and deregisters
  it right after `RunTask`. A running task keeps its revision.
- **Records.** Run records are retained for 7 days after the deadline (TTL), so
  `runs status` and the audit trail can still find them.
- **Status, stop, logs.** `/runner/status`, `/stop` and `/logs` are open to
  anyone with read on the run's stage. An unknown run and a run you can't see
  both answer 404. Stopping is audited.

## Network

- **VPC:** `RunnerVpc`, two AZs, public subnets, **no NAT gateway**, so there's
  no fixed hourly cost.
- **Public IPs:** tasks get one so they can pull images and reach STS and the
  API.
- **Security group:** `RunnerSg`, no ingress, egress only.
- **API URL:** the init container finds the API through the SSM parameter
  `/enclave-envoy/<stage>/runner/api-url`. It's written after the site is
  created, which breaks the dependency cycle between the runner and the site.

## IAM of the launch function

Everything is resource-scoped except the three task-definition actions:
- `ecs:RegisterTaskDefinition`, `ecs:DeregisterTaskDefinition` and
  `ecs:DescribeTaskDefinition` are granted on `"*"`. As far as we could
  determine, IAM doesn't support resource-level scoping for them. This departs
  from the rulebook's no-`*` rule; check the
  [ECS service authorization reference](https://docs.aws.amazon.com/service-authorization/latest/reference/list_amazonelasticcontainerservice.html)
  and narrow it if that has changed.
- `ecs:RunTask` is scoped to the run family with an `ecs:cluster` condition.
- `iam:PassRole` is scoped to the runner task role and the execution role, with
  `iam:PassedToService = ecs-tasks.amazonaws.com`.

## What this does not protect against

- **A malicious image.** It receives the secrets it was launched with. Digest
  pinning, the registry allow-list and review are the controls.
- **Egress.** The app can send its secrets anywhere on the internet. An egress
  allow-list (VPC endpoints plus a firewall) is a possible extension.
- **AWS account administrators.** They can read task memory and change the
  roles. The trust boundary is the AWS account.
