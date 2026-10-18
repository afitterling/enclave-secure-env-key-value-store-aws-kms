"""Dotenv parsing for `enclave exec` / `enclave run`.

Follows web/src/lib/envfile.ts for the line shape (optional `export`, KEY=VALUE,
`#` comments, trailing ` #comment` on unquoted values), and adds what the
viewer can skip but a process environment cannot: single quotes are literal,
double quotes understand \\n \\r \\t \\" \\\\ escapes.

Unlike the web viewer, which only needs a best-effort table, this parser is
strict about keys: they must be valid POSIX environment names, because they end
up as environment variables or file names. Lines that do not parse are reported
back rather than silently dropped.
"""

from __future__ import annotations

import re
from typing import Dict, Iterable, List, Tuple

_LINE = re.compile(r"^(?:export\s+)?([A-Za-z_][A-Za-z0-9_.]*)\s*=\s*(.*)$")
ENV_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

_ESCAPES = {"n": "\n", "r": "\r", "t": "\t", '"': '"', "\\": "\\"}


def _double_quoted(body: str) -> str:
    out: List[str] = []
    i = 0
    while i < len(body):
        ch = body[i]
        if ch == "\\" and i + 1 < len(body) and body[i + 1] in _ESCAPES:
            out.append(_ESCAPES[body[i + 1]])
            i += 2
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def _closing_quote(value: str, quote: str) -> int:
    """Index of the unescaped closing quote, or -1."""
    i = 1
    while i < len(value):
        if quote == '"' and value[i] == "\\":
            i += 2
            continue
        if value[i] == quote:
            return i
        i += 1
    return -1


def _value(raw: str) -> str:
    v = raw.strip()
    if v[:1] in ("'", '"'):
        end = _closing_quote(v, v[0])
        if end > 0:
            body = v[1:end]
            return body if v[0] == "'" else _double_quoted(body)
    # Strip a trailing unquoted comment: FOO=bar # note
    m = re.search(r"\s+#", v)
    return v[: m.start()].rstrip() if m else v


def parse(text: str) -> Tuple[Dict[str, str], List[int]]:
    """Parse dotenv text. Returns (entries, line numbers that did not parse)."""
    entries: Dict[str, str] = {}
    bad: List[int] = []
    for n, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        m = _LINE.match(line)
        if not m:
            bad.append(n)
            continue
        entries[m.group(1)] = _value(m.group(2))
    return entries, bad


def merge(texts: Iterable[str]) -> Dict[str, str]:
    """Parse several files in order; later files win on duplicate keys."""
    merged: Dict[str, str] = {}
    for text in texts:
        entries, _ = parse(text)
        merged.update(entries)
    return merged


def is_env_file(name: str) -> bool:
    """Which stored files `exec`/`run` load when no --file is given."""
    return name == ".env" or name.startswith(".env.") or name.endswith(".env")


def shell_quote_line(key: str, value: str) -> str:
    """Render KEY=VALUE as a dotenv line that round-trips through `parse`."""
    if re.fullmatch(r"[A-Za-z0-9_./:@%+,-]*", value):
        return f"{key}={value}"
    if "'" not in value and "\n" not in value and "\r" not in value:
        return f"{key}='{value}'"
    escaped = (
        value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n").replace("\r", "\\r")
    )
    return f'{key}="{escaped}"'
