"""Local config + session persistence under ~/.enclave.

Two environment variables override the files, so CI jobs and containers never
need to write anything to disk:

    ENCLAVE_API_URL  beats config.json's api_url
    ENCLAVE_TOKEN    beats session.json's token (e.g. a machine token from
                     `enclave machine-login --print-token`)
"""

from __future__ import annotations

import json
import os
import stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

CONFIG_DIR = Path(os.environ.get("ENCLAVE_HOME", Path.home() / ".enclave"))
CONFIG_FILE = CONFIG_DIR / "config.json"
SESSION_FILE = CONFIG_DIR / "session.json"


def _ensure_dir() -> None:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    os.chmod(CONFIG_DIR, stat.S_IRWXU)  # 0700


def _write_private(path: Path, data: dict) -> None:
    _ensure_dir()
    path.write_text(json.dumps(data, indent=2))
    os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)  # 0600


@dataclass
class Config:
    api_url: Optional[str] = None

    @classmethod
    def load(cls) -> "Config":
        if CONFIG_FILE.exists():
            return cls(**json.loads(CONFIG_FILE.read_text()))
        return cls()

    def save(self) -> None:
        _write_private(CONFIG_FILE, {"api_url": self.api_url})

    def require_api_url(self) -> str:
        env_url = os.environ.get("ENCLAVE_API_URL")
        if env_url:
            return env_url.rstrip("/")
        if not self.api_url:
            raise SystemExit("No API URL configured. Run: enclave configure --api-url <url>")
        return self.api_url.rstrip("/")


@dataclass
class Session:
    email: Optional[str] = None
    token: Optional[str] = None
    access: dict = field(default_factory=dict)

    @classmethod
    def load(cls) -> "Session":
        if SESSION_FILE.exists():
            return cls(**json.loads(SESSION_FILE.read_text()))
        return cls()

    def save(self) -> None:
        _write_private(SESSION_FILE, {"email": self.email, "token": self.token, "access": self.access})

    def clear(self) -> None:
        SESSION_FILE.unlink(missing_ok=True)

    def require_token(self) -> str:
        env_token = os.environ.get("ENCLAVE_TOKEN")
        if env_token:
            return env_token
        if not self.token:
            raise SystemExit("Not logged in. Run: enclave login <email>")
        return self.token
