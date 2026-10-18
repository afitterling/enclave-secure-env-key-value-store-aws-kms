"""Cloud runner: the in-task init step and the cloud-run client."""

import os
import stat
import subprocess

import pytest

from enclave import dotenv, runner, sync
from enclave.client import ApiClient, ApiError

DIGEST = "ghcr.io/acme/api@sha256:" + "a" * 64
SECRETS = {"DB_URL": "postgres://u:p@h/db", "QUOTED": "it's $HOME `x`\nline2", "bad.key": "never-printed-7f3a"}
SESSION = {"token": "tok", "principal": "runner:t1", "project": "webapp", "stages": ["prod"],
           "access": "read", "files": [], "mode": "files", "expiresIn": 900}


@pytest.fixture
def server(monkeypatch):
    """Fake the API: login answers per a script; load_env returns SECRETS."""
    state = {"logins": [], "script": [SESSION], "load_env": []}

    monkeypatch.setattr(ApiClient, "workload_info", lambda self: {"audience": "aud"})

    def workload_login(self, body):
        state["logins"].append(body)
        step = state["script"].pop(0) if state["script"] else ApiError("401: no", status=401)
        if isinstance(step, Exception):
            raise step
        return step

    monkeypatch.setattr(ApiClient, "workload_login", workload_login)

    def load_env(api, project, stage, files=None):
        state["load_env"].append((api.token, project, stage, files))
        return dict(SECRETS), [".env"]

    monkeypatch.setattr(sync, "load_env", load_env)
    return state


def _sign(audience):
    return {"signed-for": audience}


def test_runner_init_writes_three_artefacts_0400(server, tmp_path, capsys):
    msgs = []
    code = runner.runner_init("https://x/api", str(tmp_path), msgs.append, sign=_sign, sleep=lambda s: None)
    assert code == 0
    assert server["logins"] == [{"runner": True, "aws": {"signed-for": "aud"}}]
    assert server["load_env"] == [("tok", "webapp", "prod", None)]

    names = sorted(os.listdir(tmp_path))
    assert names == [".env", "DB_URL", "QUOTED", "env.sh"]  # invalid name skipped, no temp files left
    for name in names:
        assert stat.S_IMODE(os.stat(tmp_path / name).st_mode) == 0o400
    assert (tmp_path / "DB_URL").read_text() == SECRETS["DB_URL"]
    assert (tmp_path / "QUOTED").read_text() == SECRETS["QUOTED"]
    parsed, _ = dotenv.parse((tmp_path / ".env").read_text())
    assert parsed == {"DB_URL": SECRETS["DB_URL"], "QUOTED": SECRETS["QUOTED"]}

    # env.sh must survive a real POSIX shell verbatim: no $ / backtick expansion.
    out = subprocess.run(
        ["sh", "-c", '. "$1"; printf %s "$QUOTED"', "sh", str(tmp_path / "env.sh")],
        capture_output=True, text=True, check=True,
    ).stdout
    assert out == SECRETS["QUOTED"]

    printed = "\n".join(msgs) + capsys.readouterr().out + capsys.readouterr().err
    assert "2 secret(s)" in printed and "skipped 1" in printed
    for value in SECRETS.values():
        assert value not in printed


def test_runner_init_passes_requested_files(server, tmp_path):
    server["script"] = [dict(SESSION, files=[".env.prod"])]
    assert runner.runner_init("https://x/api", str(tmp_path), lambda m: None, sign=_sign) == 0
    assert server["load_env"][0][3] == [".env.prod"]


def test_runner_login_retries_401_then_succeeds(server):
    server["script"] = [ApiError("401: x", status=401), ApiError("401: x", status=401), SESSION]
    slept = []
    out = runner.runner_login(ApiClient("https://x/api"), _sign, sleep=slept.append, clock=lambda: 0.0)
    assert out["token"] == "tok"
    assert slept == [1.0, 2.0]
    assert len(server["logins"]) == 3  # re-signed every attempt


def test_runner_login_does_not_retry_other_errors(server):
    server["script"] = [ApiError("403: off", status=403)]
    with pytest.raises(ApiError):
        runner.runner_login(ApiClient("https://x/api"), _sign, sleep=lambda s: None)
    assert len(server["logins"]) == 1


def test_runner_init_fails_nonzero_when_login_keeps_failing(server, tmp_path):
    server["script"] = []  # every attempt answers 401
    now = {"t": 0.0}

    def sleep(s):
        now["t"] += s

    msgs = []
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(runner.time, "monotonic", lambda: now["t"])
        code = runner.runner_init("https://x/api", str(tmp_path), msgs.append, sign=_sign, sleep=sleep)
    assert code == 1
    assert now["t"] <= runner.LOGIN_DEADLINE
    assert "failed" in msgs[-1]
    assert os.listdir(tmp_path) == []


def test_runner_init_fails_when_stage_has_no_env_files(server, tmp_path, monkeypatch):
    monkeypatch.setattr(sync, "load_env", lambda *a, **k: ({}, []))
    assert runner.runner_init("https://x/api", str(tmp_path), lambda m: None, sign=_sign) == 1


def _cli():
    """click is a CLI dependency the pure-module tests do not need."""
    testing = pytest.importorskip("click.testing")
    from enclave import cli

    return testing.CliRunner(), cli


def test_runner_init_owner_chowns_dir_and_every_file(server, tmp_path, monkeypatch):
    calls = []
    order = []
    monkeypatch.setattr(runner.os, "chown", lambda path, uid, gid: (calls.append((os.path.basename(path), uid, gid)), order.append("chown")))
    real_chmod = os.chmod
    monkeypatch.setattr(runner.os, "chmod", lambda path, mode: (order.append("chmod"), real_chmod(path, mode)))
    code = runner.runner_init("https://x/api", str(tmp_path), lambda m: None, sign=_sign, owner="65534:65534")
    assert code == 0
    assert sorted(calls) == sorted(
        [(n, 65534, 65534) for n in ("DB_URL", "QUOTED", ".env", "env.sh", tmp_path.name)]
    )
    assert stat.S_IMODE(os.stat(tmp_path).st_mode) == 0o700
    assert order[0] == "chmod"  # without CAP_FOWNER, root cannot chmod a dir it gave away


def test_runner_init_without_owner_leaves_ownership(server, tmp_path, monkeypatch):
    monkeypatch.setattr(runner.os, "chown", lambda *a: pytest.fail("chown called"))
    assert runner.runner_init("https://x/api", str(tmp_path), lambda m: None, sign=_sign) == 0


def test_runner_init_rejects_bad_owner_before_login(server, tmp_path):
    assert runner.runner_init("https://x/api", str(tmp_path), lambda m: None, sign=_sign, owner="nobody") == 1
    assert server["logins"] == []


def test_runner_init_owner_from_env(monkeypatch):
    runner_cli, cli = _cli()
    seen = {}
    monkeypatch.setenv("ENCLAVE_API_URL", "https://x/api")
    monkeypatch.setenv("ENCLAVE_RUNNER_OWNER", "1000:1000")
    monkeypatch.setattr(runner, "runner_init", lambda url, dest, echo, owner=None: seen.update(owner=owner) or 0)
    result = runner_cli.invoke(cli.main, ["runner-init", "--dest", "/tmp/x"])
    assert result.exit_code == 0 and seen["owner"] == "1000:1000"


def test_runner_init_command_requires_api_url(monkeypatch):
    runner_cli, cli = _cli()
    monkeypatch.delenv("ENCLAVE_API_URL", raising=False)
    result = runner_cli.invoke(cli.main, ["runner-init"])
    assert result.exit_code == 2


# ---- cloud-run -------------------------------------------------------------------


def test_cloud_run_refuses_unpinned_image_before_any_network_call(monkeypatch):
    def boom(*a, **k):
        raise AssertionError("network used")

    runner_cli, cli = _cli()
    monkeypatch.setattr(ApiClient, "_post", boom)
    monkeypatch.setattr(ApiClient, "_get", boom)
    monkeypatch.setenv("ENCLAVE_API_URL", "https://x/api")
    monkeypatch.setenv("ENCLAVE_TOKEN", "t")
    result = runner_cli.invoke(cli.main, ["cloud-run", "-p", "webapp", "-s", "prod", "--", "nginx:latest"])
    assert result.exit_code != 0
    assert "not pinned by digest" in result.output


@pytest.mark.parametrize(
    "kwargs, message",
    [
        (dict(mode="env", command=()), "needs the command"),
        (dict(cpu=300), "--cpu"),
        (dict(max_minutes=0), "between 1 and 240"),
        (dict(env_pairs=("NOEQUALS",)), "KEY=VALUE"),
        (dict(env_pairs=("1BAD=x",)), "KEY=VALUE"),
    ],
)
def test_launch_body_validation(kwargs, message):
    args = dict(project="p", stage="dev", image=DIGEST, command=("serve",), files=(), mode="files",
                cpu=None, memory=None, env_pairs=(), max_minutes=60)
    args.update(kwargs)
    with pytest.raises(runner.RunnerError, match=message):
        runner.launch_body(**args)


def test_launch_body_shape():
    body = runner.launch_body("p", "dev", DIGEST, ("serve", "--port", "8080"), (".env",), "env",
                              512, 1024, ("LOG_LEVEL=debug",), 30)
    assert body == {"project": "p", "stage": "dev", "image": DIGEST, "mode": "env", "maxMinutes": 30,
                    "command": ["serve", "--port", "8080"], "files": [".env"], "cpu": 512,
                    "memory": 1024, "env": {"LOG_LEVEL": "debug"}}


@pytest.mark.parametrize(
    "status, code",
    [
        ({"status": "RUNNING"}, None),
        ({"status": "STOPPED", "exitCode": 0}, 0),
        ({"status": "STOPPED", "exitCode": 3}, 3),
        ({"status": "STOPPED"}, 1),
        ({"status": "STOPPED", "exitCode": None}, 1),
        ({"status": "STOPPED", "exitCode": True}, 1),
    ],
)
def test_exit_code_from_status(status, code):
    assert runner.exit_code_from_status(status) == code


class FakeRunApi:
    def __init__(self, statuses, log_pages=None):
        self.statuses = list(statuses)
        self.log_pages = list(log_pages or [])
        self.stopped = 0

    def runner_status(self, run_id):
        item = self.statuses.pop(0) if len(self.statuses) > 1 else self.statuses[0]
        if isinstance(item, BaseException):
            raise item
        return item

    def runner_logs(self, run_id, container="app", next_token=None):
        if self.log_pages:
            return self.log_pages.pop(0)
        return {"events": [], "nextToken": next_token}

    def runner_stop(self, run_id):
        self.stopped += 1
        return {"ok": True}


def test_follow_streams_logs_and_returns_exit_code():
    api = FakeRunApi(
        [{"status": "PROVISIONING"}, {"status": "RUNNING"}, {"status": "STOPPED", "exitCode": 7}],
        [{"events": [{"timestamp": 1, "message": "hello\n"}], "nextToken": "f1"},
         {"events": [], "nextToken": "f1"}],
    )
    out, err = [], []
    assert runner.follow(api, "t1", out.append, err.append, sleep=lambda s: None) == 7
    assert out == ["hello"]
    assert err[:3] == ["[t1] PROVISIONING", "[t1] RUNNING", "[t1] STOPPED"]


def test_follow_ctrl_c_once_stops_twice_exits_130():
    api = FakeRunApi([KeyboardInterrupt(), {"status": "STOPPED", "exitCode": 143}])
    assert runner.follow(api, "t1", lambda m: None, lambda m: None, sleep=lambda s: None) == 143
    assert api.stopped == 1

    api = FakeRunApi([KeyboardInterrupt(), KeyboardInterrupt(), {"status": "RUNNING"}])
    assert runner.follow(api, "t1", lambda m: None, lambda m: None, sleep=lambda s: None) == 130
    assert api.stopped == 1


def test_api_error_carries_status():
    class R:
        status_code = 401
        text = "x"
        content = b"x"

        def json(self):
            return {"error": "nope"}

    with pytest.raises(ApiError) as e:
        ApiClient._handle(R())
    assert e.value.status == 401 and "nope" in str(e.value)
