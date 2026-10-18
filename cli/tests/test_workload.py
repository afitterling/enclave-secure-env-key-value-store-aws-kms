"""Machine login helpers and environment overrides."""

import base64

import pytest

from enclave import config, workload

botocore = pytest.importorskip("botocore")


def test_sts_request_signs_server_id_header():
    from botocore.auth import SigV4Auth
    from botocore.awsrequest import AWSRequest
    from botocore.credentials import Credentials

    creds = Credentials("AKIDEXAMPLE", "secret", "session-token").get_frozen_credentials()
    req = workload._signed(creds, "eu-central-1", "enclave-envoy:123:dev", SigV4Auth, AWSRequest)

    assert req["method"] == "POST"
    assert req["url"] == "https://sts.eu-central-1.amazonaws.com/"
    assert base64.b64decode(req["body"]).decode() == "Action=GetCallerIdentity&Version=2011-06-15"
    headers = {k.lower(): v for k, v in req["headers"].items()}
    assert headers["x-enclave-server-id"] == "enclave-envoy:123:dev"
    signed = headers["authorization"].split("SignedHeaders=")[1].split(",")[0].split(";")
    assert "x-enclave-server-id" in signed
    assert "x-amz-security-token" in signed or "x-amz-security-token" in headers


def test_us_east_1_uses_global_endpoint():
    from botocore.auth import SigV4Auth
    from botocore.awsrequest import AWSRequest
    from botocore.credentials import Credentials

    creds = Credentials("AKID", "secret").get_frozen_credentials()
    req = workload._signed(creds, "us-east-1", "aud", SigV4Auth, AWSRequest)
    assert req["url"] == "https://sts.amazonaws.com/"


def test_github_requires_oidc_env(monkeypatch):
    monkeypatch.delenv("ACTIONS_ID_TOKEN_REQUEST_URL", raising=False)
    monkeypatch.delenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", raising=False)
    with pytest.raises(workload.WorkloadError, match="id-token: write"):
        workload.github_oidc_token("aud")


def test_read_oidc_token(tmp_path, monkeypatch):
    f = tmp_path / "token"
    f.write_text("a.b.c\n")
    assert workload.read_oidc_token(file=str(f)) == "a.b.c"
    monkeypatch.setenv("CI_JOB_JWT", "x.y.z")
    assert workload.read_oidc_token(env="CI_JOB_JWT") == "x.y.z"
    with pytest.raises(workload.WorkloadError):
        workload.read_oidc_token(env="UNSET_VAR_FOR_TEST")
    f.write_text("not-a-jwt")
    with pytest.raises(workload.WorkloadError):
        workload.read_oidc_token(file=str(f))


def test_login_requires_exactly_one_source():
    with pytest.raises(workload.WorkloadError):
        workload.login(None, "p", "id", audience="a")
    with pytest.raises(workload.WorkloadError):
        workload.login(None, "p", "id", github=True, aws=True, audience="a")


def test_login_posts_oidc_body(tmp_path):
    f = tmp_path / "t"
    f.write_text("h.p.s")

    class FakeApi:
        def workload_info(self):
            return {"audience": "aud-from-server"}

        def workload_login(self, body):
            self.body = body
            return {"token": "T"}

    api = FakeApi()
    assert workload.login(api, "webapp", "ci", token_file=str(f)) == {"token": "T"}
    assert api.body == {"project": "webapp", "identity": "ci", "oidcToken": "h.p.s"}


def test_env_overrides_files(monkeypatch, tmp_path):
    monkeypatch.setattr(config, "CONFIG_FILE", tmp_path / "config.json")
    monkeypatch.setattr(config, "SESSION_FILE", tmp_path / "session.json")
    monkeypatch.setenv("ENCLAVE_API_URL", "https://env.example/api/")
    monkeypatch.setenv("ENCLAVE_TOKEN", "env-token")
    assert config.Config(api_url="https://file.example").require_api_url() == "https://env.example/api"
    assert config.Session(token="file-token").require_token() == "env-token"
    monkeypatch.delenv("ENCLAVE_API_URL")
    monkeypatch.delenv("ENCLAVE_TOKEN")
    assert config.Config(api_url="https://file.example/").require_api_url() == "https://file.example"
    assert config.Session(token="file-token").require_token() == "file-token"
