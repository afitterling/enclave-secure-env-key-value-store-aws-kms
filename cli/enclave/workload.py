"""Machine (workload) login: trade a platform identity for a short-lived token.

No OTP and no stored secret. The workload proves who it is with something its
platform already gives it, and the server matches that against a binding the
project owner created:

    --github           GitHub Actions OIDC token (needs `permissions: id-token: write`)
    --oidc-token-file  any OIDC JWT on disk, e.g. a Kubernetes projected token
    --oidc-token-env   any OIDC JWT in an environment variable (GitLab CI, ...)
    --aws              a SigV4-signed sts:GetCallerIdentity request, made with
                       the ambient AWS credentials (ECS task role, Lambda, EC2)

The signed STS request is never sent to AWS by us. The server forwards it and
learns the caller's ARN from STS's answer. The `x-enclave-server-id` header is
part of the signature, so a captured request cannot be replayed against a
different enclave deployment.
"""

from __future__ import annotations

import base64
import os
from pathlib import Path
from typing import Optional
from urllib.parse import quote

import requests

from enclave.client import ApiClient

STS_BODY = "Action=GetCallerIdentity&Version=2011-06-15"
SERVER_ID_HEADER = "x-enclave-server-id"
_TIMEOUT = 15.0


class WorkloadError(RuntimeError):
    pass


def github_oidc_token(audience: str) -> str:
    """Request an ID token from the GitHub Actions runtime for `audience`."""
    url = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_URL")
    bearer = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
    if not url or not bearer:
        raise WorkloadError(
            "Not running in GitHub Actions with OIDC enabled: ACTIONS_ID_TOKEN_REQUEST_URL / "
            "ACTIONS_ID_TOKEN_REQUEST_TOKEN are unset. Add `permissions: id-token: write` to the job."
        )
    r = requests.get(
        f"{url}&audience={quote(audience, safe='')}",
        headers={"Authorization": f"Bearer {bearer}"},
        timeout=_TIMEOUT,
    )
    if r.status_code >= 400:
        raise WorkloadError(f"GitHub OIDC token request failed: {r.status_code}")
    token = r.json().get("value")
    if not token:
        raise WorkloadError("GitHub OIDC response carried no token")
    return token


def read_oidc_token(file: Optional[str] = None, env: Optional[str] = None) -> str:
    """Read an OIDC JWT from a file (re-read each call; projected tokens rotate) or env var."""
    if file:
        token = Path(file).read_text().strip()
    elif env:
        token = os.environ.get(env, "").strip()
        if not token:
            raise WorkloadError(f"environment variable {env} is empty or unset")
    else:
        raise WorkloadError("pass a token file or an environment variable name")
    if token.count(".") != 2:
        raise WorkloadError("that does not look like a JWT")
    return token


def sign_sts_request(audience: str, region: Optional[str] = None) -> dict:
    """Build a signed sts:GetCallerIdentity request bound to `audience`.

    Uses botocore's default credential chain, so it picks up ECS/EKS/Lambda/EC2
    role credentials and AWS_PROFILE alike.
    """
    try:
        import botocore.session
        from botocore.auth import SigV4Auth
        from botocore.awsrequest import AWSRequest
    except ImportError as e:  # pragma: no cover - exercised only without the extra
        raise WorkloadError(
            "AWS login needs botocore: pip install 'enclave-envoy[aws]'"
        ) from e

    session = botocore.session.get_session()
    creds = session.get_credentials()
    if creds is None:
        raise WorkloadError("no AWS credentials found in the environment")
    region = region or session.get_config_variable("region") or "us-east-1"
    return _signed(creds.get_frozen_credentials(), region, audience, SigV4Auth, AWSRequest)


def _signed(creds, region: str, audience: str, sigv4, aws_request) -> dict:
    # us-east-1 signs against the global endpoint; every other region uses its
    # regional one so the request stays in-region.
    url = "https://sts.amazonaws.com/" if region == "us-east-1" else f"https://sts.{region}.amazonaws.com/"
    req = aws_request(
        method="POST",
        url=url,
        data=STS_BODY,
        headers={
            "Content-Type": "application/x-www-form-urlencoded; charset=utf-8",
            SERVER_ID_HEADER: audience,
        },
    )
    sigv4(creds, "sts", region).add_auth(req)
    return {
        "method": "POST",
        "url": url,
        "headers": {k: v for k, v in req.headers.items()},
        "body": base64.b64encode(STS_BODY.encode()).decode(),
    }


def login(
    api: ApiClient,
    project: str,
    identity: str,
    *,
    github: bool = False,
    token_file: Optional[str] = None,
    token_env: Optional[str] = None,
    aws: bool = False,
    audience: Optional[str] = None,
) -> dict:
    """Run the workload exchange. Returns the server's response (token + scope)."""
    chosen = sum(bool(x) for x in (github, token_file, token_env, aws))
    if chosen != 1:
        raise WorkloadError("choose exactly one of --github, --oidc-token-file, --oidc-token-env, --aws")

    if audience is None:
        audience = api.workload_info()["audience"]

    body: dict = {"project": project, "identity": identity}
    if aws:
        body["aws"] = sign_sts_request(audience)
    elif github:
        body["oidcToken"] = github_oidc_token(audience)
    else:
        body["oidcToken"] = read_oidc_token(token_file, token_env)
    return api.workload_login(body)
