"""Cloud runner: run an image on Fargate with a stage's secrets, and the init
step that delivers those secrets inside the task.

    enclave cloud-run   asks the server to launch the run, then follows it
                        (status transitions, app logs, the app's exit code)
    enclave runner-init runs as the task's init container. It proves which run
                        it belongs to with the task's own IAM role (a signed
                        sts:GetCallerIdentity; ECS names the role session after
                        the task id), gets a one-time read token for exactly
                        that run's project/stage, decrypts in memory and writes
                        the secrets to the task's ephemeral volume. The app
                        container only starts if this exits 0.

Plaintext never passes through the API: the server only brokers KMS and S3,
as for every other client.
"""

from __future__ import annotations

import os
import secrets as _random
import stat
import sys
import time
from typing import Callable, Dict, List, Optional, Sequence, Tuple

from enclave import dotenv, sync, workload
from enclave.client import ApiClient, ApiError

DEFAULT_DEST = "/run/secrets"
LOGIN_DEADLINE = 60.0  # seconds; the server may not have written the run record yet
POLL_INTERVAL = 3.0
TERMINAL = "STOPPED"
CPU_CHOICES = (256, 512, 1024, 2048, 4096)


class RunnerError(RuntimeError):
    pass


# ---- runner-init (inside the task) -------------------------------------------


def runner_login(
    api: ApiClient,
    sign: Callable[[str], dict],
    sleep: Callable[[float], None] = time.sleep,
    clock: Optional[Callable[[], float]] = None,
    deadline: float = LOGIN_DEADLINE,
) -> dict:
    """Trade the task role for this run's one-time token, retrying while the
    server has not recorded the run yet (it answers 401 until then)."""
    clock = clock or time.monotonic
    audience = api.workload_info()["audience"]
    start = clock()
    delay = 1.0
    while True:
        try:
            # Re-sign every attempt: the signature carries its own timestamp.
            return api.workload_login({"runner": True, "aws": sign(audience)})
        except ApiError as e:
            if e.status != 401 or clock() - start + delay > deadline:
                raise
        sleep(delay)
        delay = min(delay * 2, 8.0)


def _write_atomic(dest: str, name: str, content: str) -> None:
    """Write a 0400 file under a temp name, then rename it into place, so the
    app never sees a half-written secret."""
    tmp = os.path.join(dest, f".tmp-{name}-{_random.token_hex(4)}")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, stat.S_IRUSR)
    try:
        with os.fdopen(fd, "w") as f:
            f.write(content)
    except BaseException:
        os.unlink(tmp)
        raise
    os.replace(tmp, os.path.join(dest, name))


def parse_owner(spec: Optional[str]) -> Optional[Tuple[int, int]]:
    """`UID:GID` -> (uid, gid); None/empty -> None (leave ownership as-is)."""
    if not spec:
        return None
    uid, sep, gid = spec.partition(":")
    if not sep or not uid.isdigit() or not gid.isdigit():
        raise RunnerError(f"--owner {spec!r}: expected numeric UID:GID")
    return int(uid), int(gid)


def materialize(
    secrets: Dict[str, str], dest: str, owner: Optional[Tuple[int, int]] = None
) -> List[str]:
    """Write one file per KEY, `.env` and `env.sh` into `dest`. Returns the
    keys written (invalid environment names are skipped).

    With `owner`, `dest` becomes 0700 and every file 0400, all owned by that
    uid:gid. Fargate bind-mount volumes start root-owned, so the init step
    runs as root (holding only CHOWN) and hands the files to the app's user.
    """
    names = [k for k in secrets if dotenv.ENV_NAME.match(k)]
    written = list(names)
    for name in names:
        _write_atomic(dest, name, secrets[name])
    _write_atomic(dest, ".env", "".join(dotenv.shell_quote_line(k, secrets[k]) + "\n" for k in names))
    _write_atomic(dest, "env.sh", "".join(dotenv.posix_export_line(k, secrets[k]) + "\n" for k in names))
    written += [".env", "env.sh"]
    if owner:
        # chmod before chown: once root no longer owns the directory, changing
        # its mode would need CAP_FOWNER, which the init container does not hold.
        os.chmod(dest, stat.S_IRWXU)
        for name in written:
            os.chown(os.path.join(dest, name), *owner)
        os.chown(dest, *owner)
    return names


def runner_init(
    api_url: str,
    dest: str,
    echo: Callable[[str], None],
    sign: Optional[Callable[[str], dict]] = None,
    sleep: Callable[[float], None] = time.sleep,
    owner: Optional[str] = None,
) -> int:
    """The whole init step. Returns a process exit code; never prints a value."""
    region = os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION")
    sign = sign or (lambda audience: workload.sign_sts_request(audience, region))
    try:
        owner_ids = parse_owner(owner)
        session = runner_login(ApiClient(api_url), sign, sleep=sleep)
        project = session["project"]
        stage = session["stages"][0]
        api = ApiClient(api_url, token=session["token"])
        secrets, used = sync.load_env(api, project, stage, session.get("files") or None)
        if not used:
            raise RunnerError(f"no env files in {project}/{stage}")
        os.makedirs(dest, exist_ok=True)
        names = materialize(secrets, dest, owner_ids)
    except (ApiError, workload.WorkloadError, RunnerError, OSError, ValueError, KeyError, IndexError) as e:
        echo(f"enclave runner-init: failed: {e}")
        return 1
    skipped = len(secrets) - len(names)
    note = f", skipped {skipped} invalid name(s)" if skipped else ""
    echo(f"enclave runner-init: wrote {len(names)} secret(s) from {len(used)} file(s) "
         f"for {project}/{stage} to {dest}{note}")
    return 0


# ---- cloud-run (on the caller's machine) -------------------------------------


def launch_body(
    project: str,
    stage: str,
    image: str,
    command: Sequence[str],
    files: Sequence[str],
    mode: str,
    cpu: Optional[int],
    memory: Optional[int],
    env_pairs: Sequence[str],
    max_minutes: int,
) -> dict:
    """Validate the request locally and build the launch body."""
    from enclave.container import is_pinned

    if not is_pinned(image):
        raise RunnerError(f"{image} is not pinned by digest; the cloud runner only runs IMAGE@sha256:<digest>")
    if mode not in ("files", "env"):
        raise RunnerError("mode must be 'files' or 'env'")
    if mode == "env" and not command:
        raise RunnerError("--mode env needs the command to run (the image entrypoint is replaced)")
    if cpu is not None and cpu not in CPU_CHOICES:
        raise RunnerError(f"--cpu must be one of {', '.join(map(str, CPU_CHOICES))}")
    if not 1 <= max_minutes <= 240:
        raise RunnerError("--max-minutes must be between 1 and 240")
    env: Dict[str, str] = {}
    for pair in env_pairs:
        key, sep, value = pair.partition("=")
        if not sep or not dotenv.ENV_NAME.match(key):
            raise RunnerError(f"--env {pair!r}: expected KEY=VALUE")
        env[key] = value
    body: dict = {"project": project, "stage": stage, "image": image, "mode": mode, "maxMinutes": max_minutes}
    if command:
        body["command"] = list(command)
    if files:
        body["files"] = list(files)
    if cpu is not None:
        body["cpu"] = cpu
    if memory is not None:
        body["memory"] = memory
    if env:
        body["env"] = env
    return body


def exit_code_from_status(status: dict) -> Optional[int]:
    """The app's exit code once the run has stopped; 1 if ECS reported none
    (e.g. the init step failed, so the app never started). None while running."""
    if status.get("status") != TERMINAL:
        return None
    code = status.get("exitCode")
    return code if isinstance(code, int) and not isinstance(code, bool) else 1


class LogTail:
    """Forward-only reader of one container's log stream."""

    def __init__(self, api: ApiClient, run_id: str, container: str = "app"):
        self.api = api
        self.run_id = run_id
        self.container = container
        self.token: Optional[str] = None

    def drain(self, out: Callable[[str], None]) -> int:
        """Print everything new. Returns the number of events printed."""
        printed = 0
        while True:
            page = self.api.runner_logs(self.run_id, self.container, self.token)
            for event in page.get("events", []):
                out(str(event.get("message", "")).rstrip("\n"))
                printed += 1
            token = page.get("nextToken")
            if not token or token == self.token:
                self.token = token or self.token
                return printed
            self.token = token


def follow(
    api: ApiClient,
    run_id: str,
    out: Callable[[str], None],
    err: Callable[[str], None],
    sleep: Callable[[float], None] = time.sleep,
    logs: bool = True,
) -> int:
    """Follow a run to completion. Ctrl-C once stops the run (and keeps
    waiting for it to stop); twice exits 130 at once."""
    tail = LogTail(api, run_id)
    last = None
    interrupts = 0
    while True:
        try:
            status = api.runner_status(run_id)
            state = status.get("status")
            if state != last:
                err(f"[{run_id}] {state}")
                last = state
            if logs and state in ("RUNNING", "DEPROVISIONING", TERMINAL):
                tail.drain(out)
            code = exit_code_from_status(status)
            if code is not None:
                reason = status.get("stoppedReason")
                if reason:
                    err(f"[{run_id}] stopped: {reason}")
                return code
            sleep(POLL_INTERVAL)
        except KeyboardInterrupt:
            interrupts += 1
            if interrupts > 1:
                return 130
            err(f"[{run_id}] stopping the run (Ctrl-C again to stop waiting)")
            try:
                api.runner_stop(run_id)
            except ApiError as e:
                err(f"[{run_id}] stop failed: {e}")


def stderr(msg: str) -> None:
    print(msg, file=sys.stderr)
