"""Thin HTTPS client for the enclave-envoy API."""

from __future__ import annotations

from typing import Optional

import requests


class ApiError(RuntimeError):
    def __init__(self, message: str, status: Optional[int] = None):
        super().__init__(message)
        self.status = status


class ApiClient:
    def __init__(self, api_url: str, token: Optional[str] = None, timeout: float = 30.0):
        self.base = api_url.rstrip("/")
        self.token = token
        self.timeout = timeout

    def _post(self, path: str, body: dict, auth: bool = False) -> dict:
        headers = {"content-type": "application/json"}
        if auth:
            headers["authorization"] = f"Bearer {self.token}"
        r = requests.post(f"{self.base}{path}", json=body, headers=headers, timeout=self.timeout)
        return self._handle(r)

    def _get(self, path: str, auth: bool = False) -> dict:
        headers = {}
        if auth:
            headers["authorization"] = f"Bearer {self.token}"
        r = requests.get(f"{self.base}{path}", headers=headers, timeout=self.timeout)
        return self._handle(r)

    @staticmethod
    def _handle(r: requests.Response) -> dict:
        if r.status_code >= 400:
            try:
                msg = r.json().get("error", r.text)
            except Exception:
                msg = r.text
            raise ApiError(f"{r.status_code}: {msg}", status=r.status_code)
        return r.json() if r.content else {}

    # ---- auth -------------------------------------------------------------
    def auth_request(self, email: str) -> dict:
        return self._post("/auth/request", {"email": email})

    def auth_verify(self, email: str, code: str) -> dict:
        return self._post("/auth/verify", {"email": email, "code": code})

    def workload_info(self) -> dict:
        """Audience + signed-header name a workload must bind its proof to."""
        return self._get("/auth/workload")

    def workload_login(self, body: dict) -> dict:
        """Exchange an OIDC token or a signed STS request for a machine token."""
        return self._post("/auth/workload", body)

    def whoami(self) -> dict:
        return self._get("/access/whoami", auth=True)

    # ---- crypto -----------------------------------------------------------
    def datakey_generate(self, project: str, stage: str) -> dict:
        return self._post(
            "/crypto/datakey", {"op": "generate", "project": project, "stage": stage}, auth=True
        )

    def datakey_decrypt(self, project: str, stage: str, ciphertext_b64: str) -> dict:
        return self._post(
            "/crypto/datakey",
            {"op": "decrypt", "project": project, "stage": stage, "ciphertext": ciphertext_b64},
            auth=True,
        )

    # ---- s3 ---------------------------------------------------------------
    def presign(self, op: str, project: str, stage: str, file: Optional[str] = None) -> dict:
        body = {"op": op, "project": project, "stage": stage}
        if file is not None:
            body["file"] = file
        return self._post("/s3/presign", body, auth=True)

    # ---- cloud runner -----------------------------------------------------
    def runner_launch(self, body: dict) -> dict:
        return self._post("/runner/launch", body, auth=True)

    def runner_status(self, run_id: str) -> dict:
        return self._post("/runner/status", {"runId": run_id}, auth=True)

    def runner_stop(self, run_id: str) -> dict:
        return self._post("/runner/stop", {"runId": run_id}, auth=True)

    def runner_logs(self, run_id: str, container: str = "app", next_token: Optional[str] = None) -> dict:
        body = {"runId": run_id, "container": container}
        if next_token:
            body["nextToken"] = next_token
        return self._post("/runner/logs", body, auth=True)
