# Delivering secrets to a workload

Logging in (see [machine-identities.md](machine-identities.md)) gets a
workload a token. This document covers the last step: getting decrypted values
into the process that needs them while exposing them as little as possible.

There are two commands, both in the CLI. Both work with a human session as well
as a machine token.

| Command | Use it when | Where the secrets go |
|---|---|---|
| `enclave exec -p P -s S -- cmd …` | The workload is already running somewhere you trust (a CI runner, a VM) | The child process's environment only |
| `enclave run -p P -s S IMAGE [cmd …]` | You want the workload isolated in a container | The container's environment or a RAM-backed, read-only mount |

The enterprise [cloud runner](cloud-runner.md) does the same as `enclave run`
on Fargate.

Code: `cli/enclave/container.py`, `cli/enclave/dotenv.py`, `cli/enclave/cli.py`.

## Common path

1. Fetch each env file's ciphertext through a presigned S3 URL and ask the
   service to decrypt its data key. Both calls go through `authorize(read)`.
2. Decrypt in memory and parse the dotenv files into `KEY -> value`. Later
   files win over earlier ones.
3. Hand the values over, then let them go out of scope. Plaintext isn't
   written to a file or a log, and isn't put on a command line.

## `enclave exec`

`exec` starts the command with the current environment plus the secrets, then
waits for it, forwarding signals and returning its exit code. The values exist
only in that process's environment, which other users can't read through
`/proc` or `ps`.

The secrets are visible to the child and anything it spawns. That is the point
of the command, and also its limit: if the child is untrusted, use `run`.

## `enclave run`

`run` wraps `docker run` or `podman run` and starts the container with locked-down
defaults. The caller can loosen some of them explicitly; the dangerous ones
can't be turned off.

### Defaults

| Setting | Value | Why |
|---|---|---|
| `--read-only` | on (off with `--writable`) | the image can't be modified at runtime |
| `--cap-drop ALL` | always | no Linux capabilities unless added back from a short allow-list |
| `--security-opt no-new-privileges` | always | setuid binaries can't raise privileges |
| `--user` | `65534:65534` (nobody) unless given | not root inside the container |
| `--pids-limit` | 256 | fork bombs are contained |
| `--memory` | 512m | runaway memory is contained |
| `--ipc private`, `--init`, `--rm` | always | no shared IPC, signals reach the app, nothing left behind |
| `--tmpfs /tmp` | `noexec,nosuid,nodev,size=64m` | a writable scratch dir that can't run code |
| `--network` | `bridge` | host networking is refused |

### Refused outright

| Request | Reason |
|---|---|
| An image not pinned by digest (`@sha256:…`), unless `--allow-unpinned` | a tag can be moved to different code after review |
| `--network host` or `container:…` | shares a namespace with the host or another container |
| `--cap-add` outside `NET_BIND_SERVICE, CHOWN, SETUID, SETGID, FOWNER` | the rest are kernel-level privileges |
| Mounting `/`, `/proc`, `/sys`, `/dev`, `/etc`, `/run`, `/var/run` | host configuration or kernel interfaces |
| Mounting any engine socket | equivalent to root on the host |
| Mounting `~/.enclave`, `~/.ssh`, `~/.aws` | credentials |
| Mounting at `/run/secrets` | reserved for the secrets themselves |
| Named volumes | only explicit host paths, so the checks above can apply |

`--cosign-key KEY` runs `cosign verify` on the pinned image before anything is
decrypted.

### Two ways to hand over the secrets

**Environment (default).**
- The engine command line carries only `-e KEY`, never `KEY=value`.
- The values sit in the environment of the docker/podman client process. The CLI
  builds that environment from scratch: a short allow-list of variables the
  engine client needs (`PATH`, `HOME`, `DOCKER_HOST`, …) plus the secrets. The
  engine copies the values into the container.
- Nothing reaches disk or `ps`.
- *Residual risk:* the engine keeps the values in the container's configuration,
  so anyone who can run `docker inspect` can read them. On a normal host that's
  root or the `docker` group, who are root-equivalent anyway.

**Files (`--as-files`).**
- One file per key (mode `0400`), plus a `.env`, in a `0700` directory.
- The directory is on RAM-backed `/dev/shm` where available, so it never reaches
  a disk. Without `/dev/shm` the CLI warns and falls back to the temp dir.
- It is bind-mounted read-only at `/run/secrets`.
- The container runs as the caller's uid so it can read `0400` files the caller
  owns. On rootless podman that needs `--userns keep-id`.
- The directory is deleted when the container exits, including on Ctrl-C and
  SIGTERM, which the CLI forwards.
- This mode keeps secrets out of `docker inspect` and out of the app's
  environment, where crash reporters and child processes would otherwise see
  them.

## What this does not protect against

- **A compromised host.** Root on the machine running the engine can read
  container memory and environments. Use the cloud runner, or a host you
  trust.
- **A malicious image.** The container gets the secrets it asked for. Digest
  pinning and cosign make sure it's the image you reviewed, not that the image is
  benign.
- **Secrets the app logs itself.** Nothing downstream of the app can be
  controlled from here.
