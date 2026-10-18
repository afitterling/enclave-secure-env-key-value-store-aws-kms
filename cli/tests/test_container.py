"""`enclave run`: hardened argv, validators, and secret-value hygiene."""

import os
import stat

import pytest

from enclave import container
from enclave.container import RunOptions, UnsafeOption

PINNED = "alpine@sha256:" + "a" * 64
SECRETS = {"DB_PASSWORD": "hunter2-very-secret", "API_KEY": "sk_live_abcdef"}


def _argv(**kw):
    opts = RunOptions(image=PINNED, command=["sh", "-c", "env"], **kw)
    return container.build_argv("docker", opts, list(SECRETS), home="/home/u")


def _pairs(argv):
    return list(zip(argv, argv[1:]))


def test_hardening_defaults_present():
    argv = _argv()
    for flag in ["--rm", "--init", "--read-only"]:
        assert flag in argv
    pairs = _pairs(argv)
    for pair in [
        ("--cap-drop", "ALL"),
        ("--security-opt", "no-new-privileges"),
        ("--ipc", "private"),
        ("--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=64m"),
        ("--user", "65534:65534"),
        ("--pids-limit", "256"),
        ("--memory", "512m"),
        ("--network", "bridge"),
    ]:
        assert pair in pairs
    assert argv[:2] == ["docker", "run"]
    assert argv[-4:] == [PINNED, "sh", "-c", "env"]


def test_secret_names_only_never_values():
    argv = _argv()
    for name in SECRETS:
        assert ("-e", name) in _pairs(argv)
    joined = " ".join(argv)
    for value in SECRETS.values():
        assert value not in joined


def test_writable_drops_read_only():
    assert "--read-only" not in _argv(writable=True)


def test_as_files_mounts_dir_instead_of_env():
    opts = RunOptions(image=PINNED)
    argv = container.build_argv("podman", opts, list(SECRETS), secrets_dir="/dev/shm/enclave-x", home="/home/u")
    assert ("--volume", "/dev/shm/enclave-x:/run/secrets:ro") in _pairs(argv)
    assert "-e" not in argv


def test_child_env_is_minimal(monkeypatch):
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "leak")
    monkeypatch.setenv("PATH", "/usr/bin")
    env = container.child_env(SECRETS, list(SECRETS))
    assert "AWS_SECRET_ACCESS_KEY" not in env
    assert env["PATH"] == "/usr/bin"
    assert env["DB_PASSWORD"] == SECRETS["DB_PASSWORD"]


@pytest.mark.parametrize(
    "image,pinned",
    [(PINNED, True), ("ghcr.io/o/app:1.2@sha256:" + "0" * 64, True), ("alpine:3.20", False),
     ("alpine@sha256:abc", False), ("alpine", False)],
)
def test_digest_pin(image, pinned):
    assert container.is_pinned(image) is pinned


@pytest.mark.parametrize("network", ["host", "container:other"])
def test_refuses_shared_network(network):
    with pytest.raises(UnsafeOption):
        _argv(network=network)


def test_none_network_allowed():
    assert ("--network", "none") in _pairs(_argv(network="none"))


def test_cap_allowlist():
    assert ("--cap-add", "NET_BIND_SERVICE") in _pairs(_argv(cap_add=["cap_net_bind_service"]))
    for cap in ["SYS_ADMIN", "NET_ADMIN", "ALL", "SYS_PTRACE"]:
        with pytest.raises(UnsafeOption):
            _argv(cap_add=[cap])


@pytest.mark.parametrize(
    "spec",
    [
        "/var/run/docker.sock:/var/run/docker.sock",
        "/run/podman/podman.sock:/sock",
        "/:/host",
        "/proc:/p",
        "/sys:/s",
        "/dev:/d",
        "/etc:/e",
        "/home/u:/h",
        "/home:/h",
        "/home/u/.ssh:/k",
        "/home/u/.aws/credentials:/c",
        "/home/u/.enclave:/e",
        "/home/u/work:/run/secrets",
        "named-volume:/data",
        "/home/u/work:/data:exec",
        "justone",
    ],
)
def test_refuses_unsafe_volumes(spec):
    with pytest.raises(UnsafeOption):
        container.check_volume(spec, home="/home/u")


def test_volume_defaults_read_only(tmp_path):
    home = tmp_path / "u"
    work = home / "work"
    work.mkdir(parents=True)
    real = os.path.realpath(work)
    assert container.check_volume(f"{work}:/work", home=str(home)) == f"{real}:/work:ro"
    assert container.check_volume(f"{work}:/work:rw", home=str(home)) == f"{real}:/work:rw"


def test_refuses_symlink_to_credentials(tmp_path):
    home = tmp_path / "u"
    (home / ".ssh").mkdir(parents=True)
    link = tmp_path / "innocent"
    link.symlink_to(home / ".ssh")
    with pytest.raises(UnsafeOption):
        container.check_volume(f"{link}:/data", home=str(home))


def test_env_pair_validation():
    assert ("--env", "LOG_LEVEL=debug") in _pairs(_argv(env=["LOG_LEVEL=debug"]))
    with pytest.raises(UnsafeOption):
        _argv(env=["no-equals"])


def test_usable_secret_names_filters_invalid():
    assert container.usable_secret_names({"OK": "1", "bad.key": "2", "1NO": "3"}) == ["OK"]


def test_secrets_dir_is_private_and_removed():
    path = container.write_secrets_dir(SECRETS, list(SECRETS), lambda _m: None)
    try:
        assert stat.S_IMODE(os.stat(path).st_mode) == 0o700
        for name, value in SECRETS.items():
            f = os.path.join(path, name)
            assert stat.S_IMODE(os.stat(f).st_mode) == 0o400
            assert open(f).read() == value
        from enclave import dotenv
        assert dotenv.parse(open(os.path.join(path, ".env")).read())[0] == SECRETS
    finally:
        container.remove_secrets_dir(path)
    assert not os.path.exists(path)


def test_exit_code_mapping():
    assert container.exit_code(0) == 0
    assert container.exit_code(3) == 3
    assert container.exit_code(-15) == 143


def test_keep_id_flag():
    opts = RunOptions(image=PINNED, userns_keep_id=True)
    assert ("--userns", "keep-id") in _pairs(container.build_argv("podman", opts, [], home="/home/u"))


def test_files_user_defaults_to_owner(monkeypatch):
    monkeypatch.setattr(container, "podman_rootless", lambda engine: True)
    monkeypatch.setattr(container.os, "geteuid", lambda: 501)
    monkeypatch.setattr(container.os, "getuid", lambda: 501)
    monkeypatch.setattr(container.os, "getgid", lambda: 20)
    assert container.files_user("podman", None) == ("501:20", True, None)
    assert container.files_user("podman", "1000:1000") == ("1000:1000", False, None)
    monkeypatch.setattr(container.os, "geteuid", lambda: 0)
    assert container.files_user("docker", None) == ("65534:65534", False, (65534, 65534))
