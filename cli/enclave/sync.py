"""Bulk push/pull of dotfiles: encrypt -> presign -> transfer."""

from __future__ import annotations

import base64
import os
import re
import stat
from pathlib import Path
from typing import List

import requests

from enclave import crypto
from enclave.client import ApiClient

TRANSFER_TIMEOUT = 120.0

# Server-enforced key layout uses flat basenames only (see infra safeName). We
# re-validate here so a compromised or spoofed API cannot make `pull` write
# outside --dest via a name containing "/" or "..".
_SAFE_NAME = re.compile(r"^[\w.@+-]+$")


def _safe_dest_name(file_name: str) -> str:
    if not _SAFE_NAME.fullmatch(file_name) or file_name in (".", ".."):
        raise ValueError(f"refusing unsafe file name from server: {file_name!r}")
    return file_name


def _zero(buf: bytearray) -> None:
    """Best-effort wipe of a plaintext key from memory."""
    for i in range(len(buf)):
        buf[i] = 0


def push_file(api: ApiClient, project: str, stage: str, path: Path, name: str | None = None) -> str:
    """Encrypt a single file and upload it. Returns the S3 key."""
    file_name = name or path.name
    content = path.read_bytes()

    dk = api.datakey_generate(project, stage)
    plaintext = bytearray(base64.b64decode(dk["plaintext"]))
    wrapped = base64.b64decode(dk["ciphertext"])
    try:
        envelope = crypto.seal(bytes(plaintext), wrapped, content)
    finally:
        _zero(plaintext)

    presigned = api.presign("upload", project, stage, file_name)
    r = requests.put(presigned["url"], data=envelope, timeout=TRANSFER_TIMEOUT)
    r.raise_for_status()
    return presigned["key"]


def pull_file(api: ApiClient, project: str, stage: str, file_name: str, dest_dir: Path) -> Path:
    """Download + decrypt a single file into dest_dir. Returns the local path."""
    safe_name = _safe_dest_name(file_name)
    presigned = api.presign("download", project, stage, file_name)
    r = requests.get(presigned["url"], timeout=TRANSFER_TIMEOUT)
    r.raise_for_status()
    envelope = r.content

    wrapped = crypto.parse_wrapped_key(envelope)
    unwrapped = api.datakey_decrypt(project, stage, base64.b64encode(wrapped).decode())
    plaintext = bytearray(base64.b64decode(unwrapped["plaintext"]))
    try:
        content = crypto.open_envelope(bytes(plaintext), envelope)
    finally:
        _zero(plaintext)

    dest_dir.mkdir(parents=True, exist_ok=True)
    out = dest_dir / safe_name
    out.write_bytes(content)
    os.chmod(out, stat.S_IRUSR | stat.S_IWUSR)  # 0600
    return out


def remote_list(api: ApiClient, project: str, stage: str) -> List[str]:
    return api.presign("list", project, stage).get("files", [])
