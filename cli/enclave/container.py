"""`enclave run`: start a container with vault secrets, hardened by default.

Secrets are decrypted in memory and handed to docker/podman in one of two ways:

  env mode (default)  argv carries only `-e KEY`; the values sit in the
                      environment of the docker/podman CLI process, which the
                      engine copies into the container. Nothing on disk, nothing
                      in `ps`. The engine does keep them in the container config,
                      so anyone who can run `docker inspect` (root-equivalent
                      anyway) can read them.
  --as-files          one 0400 file per KEY plus `.env` in a 0700 directory on
                      RAM-backed /dev/shm where available, bind-mounted
                      read-only at /run/secrets and deleted when the container
                      exits.

The argv builder and validators are pure functions so they can be tested
without an engine.
"""

from __future__ import annotations

import os
import re
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, List, Optional, Sequence

from enclave.dotenv import ENV_NAME, shell_quote_line

SECRETS_MOUNT = "/run/secrets"
CAP_ALLOWLIST = {"NET_BIND_SERVICE", "CHOWN", "SETUID", "SETGID", "FOWNER"}
_DIGEST = re.compile(r"@sha256:[0-9a-f]{64}$")

# Host paths that must never be mounted into a container holding secrets:
# the engine socket is root on the host, the rest are the host's own config,
# credentials, or kernel interfaces.
_FORBIDDEN_EXACT = ["/", "/proc", "/sys", "/dev", "/etc", "/var/run", "/run", "/private/var/run"]
_FORBIDDEN_UNDER_HOME = [".enclave", ".ssh", ".aws"]

# Only what the engine CLI needs to find its daemon/socket and credentials.
_PASSTHROUGH_ENV = [
    "PATH", "HOME", "USER", "LANG", "TMPDIR", "XDG_RUNTIME_DIR",
    "DOCKER_HOST", "DOCKER_CONFIG", "DOCKER_CONTEXT", "DOCKER_CERT_PATH", "DOCKER_TLS_VERIFY",
    "CONTAINER_HOST", "CONTAINER_CONNECTION",
]


class UnsafeOption(ValueError):
    """A requested option would weaken the container's isolation."""


@dataclass
class RunOptions:
    image: str
    command: List[str] = field(default_factory=list)
    network: str = "bridge"
    publish: List[str] = field(default_factory=list)
    volumes: List[str] = field(default_factory=list)
    env: List[str] = field(default_factory=list)  # non-secret K=V
    user: str = "65534:65534"
    memory: str = "512m"
    cpus: Optional[str] = None
    pids_limit: int = 256
    writable: bool = False
    cap_add: List[str] = field(default_factory=list)
    workdir: Optional[str] = None
    entrypoint: Optional[str] = None
    userns_keep_id: bool = False  # podman rootless: map our uid 1:1 so it owns /run/secrets


# ---- validators --------------------------------------------------------------


def is_pinned(image: str) -> bool:
    return bool(_DIGEST.search(image))


def check_network(network: str) -> None:
    if network == "host" or network.startswith("container:"):
        raise UnsafeOption(f"--network {network} shares a host/other namespace; refused")


def check_caps(caps: Sequence[str]) -> List[str]:
    out = []
    for cap in caps:
        name = cap.upper()
        if name.startswith("CAP_"):
            name = name[4:]
        if name not in CAP_ALLOWLIST:
            raise UnsafeOption(
                f"--cap-add {cap} is not allowed (allowed: {', '.join(sorted(CAP_ALLOWLIST))})"
            )
        out.append(name)
    return out


def check_volume(spec: str, home: Optional[str] = None) -> str:
    """Validate SRC:DST[:ro|rw] and return it normalised, read-only by default."""
    parts = spec.split(":")
    if len(parts) not in (2, 3) or not parts[0] or not parts[1]:
        raise UnsafeOption(f"--volume {spec!r}: expected SRC:DST[:ro|rw]")
    src, dst = parts[0], parts[1]
    mode = parts[2] if len(parts) == 3 else "ro"
    if mode not in ("ro", "rw"):
        raise UnsafeOption(f"--volume {spec!r}: mode must be ro or rw")
    if not src.startswith(("/", "~", ".")):
        raise UnsafeOption(f"--volume {spec!r}: named volumes are not supported, use a host path")

    home_dir = os.path.realpath(os.path.expanduser(home or "~"))
    resolved = os.path.realpath(os.path.expanduser(src))
    if resolved.endswith(".sock"):
        raise UnsafeOption(f"--volume {spec!r}: mounting a container-engine socket gives root on the host")
    forbidden = [os.path.realpath(p) for p in _FORBIDDEN_EXACT] + _FORBIDDEN_EXACT
    # The home dir itself, or any ancestor of it, would expose ~/.ssh and friends.
    if resolved in forbidden or resolved == home_dir or home_dir.startswith(resolved.rstrip(os.sep) + os.sep):
        raise UnsafeOption(f"--volume {spec!r}: refusing to mount {resolved}")
    for sub in _FORBIDDEN_UNDER_HOME:
        guarded = os.path.join(home_dir, sub)
        if resolved == guarded or resolved.startswith(guarded + os.sep):
            raise UnsafeOption(f"--volume {spec!r}: refusing to mount credentials under {guarded}")
    if dst.rstrip("/") == SECRETS_MOUNT:
        raise UnsafeOption(f"--volume {spec!r}: {SECRETS_MOUNT} is reserved")
    return f"{resolved}:{dst}:{mode}"


def check_env_pair(pair: str) -> str:
    key = pair.split("=", 1)[0]
    if "=" not in pair or not ENV_NAME.match(key):
        raise UnsafeOption(f"--env {pair!r}: expected KEY=VALUE")
    return pair


def usable_secret_names(secrets: Dict[str, str]) -> List[str]:
    """Secret keys that are valid environment/file names, in stable order."""
    return [k for k in secrets if ENV_NAME.match(k)]


# ---- argv --------------------------------------------------------------------


def build_argv(
    engine: str,
    opts: RunOptions,
    secret_names: Sequence[str],
    secrets_dir: Optional[str] = None,
    home: Optional[str] = None,
) -> List[str]:
    """The full engine command line. Never contains a secret value.

    With `secrets_dir`, secrets are mounted as files instead of `-e KEY`.
    """
    check_network(opts.network)
    caps = check_caps(opts.cap_add)
    volumes = [check_volume(v, home) for v in opts.volumes]
    env_pairs = [check_env_pair(p) for p in opts.env]

    argv = [
        engine, "run",
        "--rm",
        "--init",
        "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges",
        "--ipc", "private",
        "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=64m",
        "--user", opts.user,
        "--pids-limit", str(opts.pids_limit),
        "--memory", opts.memory,
        "--network", opts.network,
    ]
    if opts.userns_keep_id:
        argv += ["--userns", "keep-id"]
    if not opts.writable:
        argv.append("--read-only")
    if opts.cpus:
        argv += ["--cpus", str(opts.cpus)]
    for cap in caps:
        argv += ["--cap-add", cap]
    for p in opts.publish:
        argv += ["--publish", p]
    for v in volumes:
        argv += ["--volume", v]
    for pair in env_pairs:
        argv += ["--env", pair]
    if secrets_dir:
        argv += ["--volume", f"{secrets_dir}:{SECRETS_MOUNT}:ro"]
    else:
        for name in secret_names:
            argv += ["-e", name]  # name only: the value comes from our environment
    if opts.workdir:
        argv += ["--workdir", opts.workdir]
    if opts.entrypoint is not None:
        argv += ["--entrypoint", opts.entrypoint]
    argv.append(opts.image)
    argv += list(opts.command)
    return argv


def child_env(secrets: Dict[str, str], names: Sequence[str]) -> Dict[str, str]:
    """Minimal environment for the engine CLI, plus the secret values."""
    env = {k: os.environ[k] for k in _PASSTHROUGH_ENV if k in os.environ}
    for name in names:
        env[name] = secrets[name]
    return env


def detect_engine(choice: Optional[str] = None) -> str:
    choice = choice or os.environ.get("ENCLAVE_CONTAINER_ENGINE")
    if choice:
        if shutil.which(choice) is None:
            raise RuntimeError(f"container engine {choice!r} not found on PATH")
        return choice
    for candidate in ("docker", "podman"):
        if shutil.which(candidate):
            return candidate
    raise RuntimeError("no container engine found: install docker or podman, or pass --engine")


def podman_rootless(engine: str) -> bool:
    if os.path.basename(engine) != "podman":
        return False
    out = subprocess.run(
        [engine, "info", "--format", "{{.Host.Security.Rootless}}"],
        capture_output=True, text=True,
    )
    return out.returncode == 0 and out.stdout.strip() == "true"


def files_user(engine: str, explicit_user: Optional[str]) -> tuple:
    """(user, userns_keep_id, chown_to) so the container can read /run/secrets.

    The secret files are 0400 in a 0700 directory owned by whoever runs the
    CLI, deliberately unreadable to every other host user. The container user
    therefore has to *be* that owner: our own uid (still non-root) by default,
    with podman's keep-id mapping when it runs rootless. Run as root, we keep
    the anonymous 65534 user and hand the files to it instead.
    """
    if explicit_user:
        return explicit_user, False, None
    if os.geteuid() == 0:
        return "65534:65534", False, (65534, 65534)
    return f"{os.getuid()}:{os.getgid()}", podman_rootless(engine), None


def cosign_verify(image: str, key: str) -> None:
    if shutil.which("cosign") is None:
        raise RuntimeError("--cosign-key needs cosign on PATH (https://docs.sigstore.dev)")
    result = subprocess.run(["cosign", "verify", "--key", key, image], stdout=subprocess.DEVNULL)
    if result.returncode != 0:
        raise RuntimeError(f"cosign could not verify {image} against {key}; refusing to run it")


# ---- secrets on RAM ----------------------------------------------------------


def write_secrets_dir(
    secrets: Dict[str, str],
    names: Sequence[str],
    warn: Callable[[str], None],
    chown_to: Optional[tuple] = None,
) -> str:
    """Write one 0400 file per secret plus .env into a fresh 0700 directory."""
    base = "/dev/shm" if os.path.isdir("/dev/shm") and os.access("/dev/shm", os.W_OK) else None
    if base is None:
        warn("note: /dev/shm is unavailable, so secret files go to a disk-backed temp dir "
             "(removed when the container exits)")
    path = tempfile.mkdtemp(prefix="enclave-", dir=base)
    os.chmod(path, stat.S_IRWXU)
    lines = []
    for name in names:
        _write_private(os.path.join(path, name), secrets[name])
        lines.append(shell_quote_line(name, secrets[name]))
    _write_private(os.path.join(path, ".env"), "\n".join(lines) + "\n")
    if chown_to:
        for entry in [path] + [os.path.join(path, e) for e in os.listdir(path)]:
            os.chown(entry, *chown_to)
    return path


def _write_private(file: str, content: str) -> None:
    fd = os.open(file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, stat.S_IRUSR)
    with os.fdopen(fd, "w") as f:
        f.write(content)


def remove_secrets_dir(path: Optional[str]) -> None:
    if path and os.path.isdir(path):
        for entry in os.listdir(path):
            try:
                os.chmod(os.path.join(path, entry), stat.S_IRUSR | stat.S_IWUSR)
            except OSError:
                pass
        shutil.rmtree(path, ignore_errors=True)


# ---- process -----------------------------------------------------------------


def run_forwarding_signals(
    argv: Sequence[str], env: Dict[str, str], on_exit: Optional[Callable[[], None]] = None
) -> int:
    """Run argv, forward SIGINT/SIGTERM to it, return its exit code.

    `on_exit` runs exactly once whether the child exits or we are signalled.
    """
    done = {"ran": False}

    def cleanup() -> None:
        if on_exit and not done["ran"]:
            done["ran"] = True
            on_exit()

    proc = subprocess.Popen(list(argv), env=env)

    def forward(signum, _frame):
        try:
            proc.send_signal(signum)
        except ProcessLookupError:
            pass

    previous = {s: signal.signal(s, forward) for s in (signal.SIGINT, signal.SIGTERM)}
    try:
        code = proc.wait()
    finally:
        for s, handler in previous.items():
            signal.signal(s, handler)
        cleanup()
    return exit_code(code)


def exit_code(code: int) -> int:
    """Map a Popen return code (negative = killed by signal) to a shell exit code."""
    return 128 + (-code) if code < 0 else code


def warn(msg: str) -> None:
    print(msg, file=sys.stderr)
