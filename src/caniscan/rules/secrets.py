"""CS001: hardcoded credentials."""

from __future__ import annotations

import re
from typing import Any, Iterator, List, Optional, Set, Tuple
from urllib.parse import parse_qsl, urlparse

from ..models import FileKind, Finding, ScanTarget, Severity
from .base import is_reference_or_placeholder, make, redact
from .catalog import HARDCODED_SECRET as RULE

# (label, regex, group holding the secret)
PATTERNS: List[Tuple[str, "re.Pattern[str]", int]] = [
    ("Anthropic API key", re.compile(r"sk-ant-[A-Za-z0-9_\-]{20,}"), 0),
    ("OpenAI API key", re.compile(r"\bsk-(?!ant-)(?:proj-|svcacct-)?[A-Za-z0-9_\-]{20,}"), 0),
    ("GitHub token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,})"), 0),
    ("AWS access key ID", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), 0),
    ("Slack token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}"), 0),
    ("Stripe live key", re.compile(r"\b[rs]k_live_[A-Za-z0-9]{16,}"), 0),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}"), 0),
    ("Private key", re.compile(r"-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----"), 0),
    ("JSON Web Token", re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"), 0),
    ("Password in connection URL", re.compile(r"\b[a-z][a-z0-9+.\-]*://[^\s/:@\"']+:([^\s/@\"']{3,})@[^\s/\"']+", re.I), 1),
]
WEAK_URL_PASSWORDS = {"password", "pass", "pwd", "secret", "pw"}

SENSITIVE_KEY = re.compile(
    r"(api[_\-]?key|apikey|token|secret|passw(or)?d|pwd|credential|private[_\-]?key|access[_\-]?key|authorization|auth)",
    re.I,
)
SENSITIVE_FLAG = re.compile(r"^--?[\w\-]*(api[_\-]?key|token|secret|password|passwd)$", re.I)
AUTH_SCHEME = re.compile(r"^(bearer|basic|token)\s+", re.I)
LOWER_WORDS = re.compile(r"^[a-z]+([\-_.][a-z]+)*$")


def _pattern_hits(value: str) -> Iterator[Tuple[str, str]]:
    for label, rx, group in PATTERNS:
        for m in rx.finditer(value):
            secret = m.group(group)
            if is_reference_or_placeholder(secret):
                continue
            if group == 1 and secret.lower() in WEAK_URL_PASSWORDS:
                continue
            yield label, secret


def _looks_like_literal_secret(value: str) -> bool:
    v = AUTH_SCHEME.sub("", value.strip())
    if len(v) < 8 or is_reference_or_placeholder(v):
        return False
    if v.startswith(("/", "~", "./", "../")) or "\\" in v or v.lower() in ("true", "false"):
        return False  # a path or flag, e.g. TOKEN_FILE=/run/secrets/token
    if LOWER_WORDS.match(v) or v.isdigit():
        return False  # e.g. AUTH_MODE=oauth-device-flow, TIMEOUT=30000
    if v.startswith(("http://", "https://")):
        return False  # URLs handled separately
    classes = sum(bool(re.search(p, v)) for p in (r"[a-z]", r"[A-Z]", r"\d", r"[^A-Za-z0-9]"))
    return classes >= 2


def _walk(node: Any, path: Tuple[str, ...] = ()) -> Iterator[Tuple[Tuple[str, ...], str, Optional[str]]]:
    """Yield (key path, string leaf, previous sibling if inside a list)."""
    if isinstance(node, dict):
        for k, v in node.items():
            yield from _walk(v, path + (str(k),))
    elif isinstance(node, list):
        prev: Optional[str] = None
        for i, v in enumerate(node):
            if isinstance(v, (dict, list)):
                yield from _walk(v, path + (f"[{i}]",))
                prev = None
            elif isinstance(v, str):
                yield path + (f"[{i}]",), v, prev
                prev = v
    elif isinstance(node, str):
        yield path, node, None


def _loc(path: Tuple[str, ...]) -> str:
    out = ""
    for part in path:
        out += part if part.startswith("[") else (f".{part}" if out else part)
    return out or "value"


def _check_value(path: Tuple[str, ...], value: str, prev: Optional[str]) -> Iterator[Tuple[str, str, Severity]]:
    """Yield (label, secret, severity) for one string value."""
    found = False
    for label, secret in _pattern_hits(value):
        found = True
        yield label, secret, Severity.CRITICAL
    if found:
        return
    key = next((p for p in reversed(path) if not p.startswith("[")), "")
    in_list = bool(path) and path[-1].startswith("[")

    if not in_list and SENSITIVE_KEY.search(key) and _looks_like_literal_secret(value):
        yield f"Value of '{key}'", AUTH_SCHEME.sub("", value.strip()), Severity.HIGH
        return
    if in_list:
        if prev and SENSITIVE_FLAG.match(prev) and _looks_like_literal_secret(value):
            yield f"Value of {prev}", value, Severity.HIGH
            return
        if "=" in value:
            flag, _, val = value.partition("=")
            if SENSITIVE_FLAG.match(flag) and _looks_like_literal_secret(val):
                yield f"Value of {flag}", val, Severity.HIGH
                return
    if value.startswith(("http://", "https://", "ws://", "wss://")):
        for qk, qv in parse_qsl(urlparse(value).query):
            if SENSITIVE_KEY.search(qk) and _looks_like_literal_secret(qv):
                yield f"URL parameter '{qk}'", qv, Severity.HIGH


def check(target: ScanTarget) -> Iterator[Finding]:
    seen: Set[Tuple[Optional[int], str]] = set()

    if target.kind == FileKind.INSTRUCTIONS:
        for lineno, line in enumerate(target.text.splitlines(), 1):
            for label, secret in _pattern_hits(line):
                if (lineno, secret) in seen:
                    continue
                seen.add((lineno, secret))
                yield make(RULE, target, f"{label} written in an agent instruction file",
                           line=lineno, evidence=redact(secret))
        return

    roots: List[Tuple[Optional[str], Any]] = [(s.name, s.raw) for s in target.servers]
    if isinstance(target.data, dict) and isinstance(target.data.get("env"), dict):
        roots.append((None, {"env": target.data["env"]}))  # e.g. .claude/settings.json "env"

    for server_name, root in roots:
        start = target.server_line(server_name) if server_name else None
        for path, value, prev in _walk(root):
            for label, secret, severity in _check_value(path, value, prev):
                line = target.line_of(secret, start) or start
                if (line, secret) in seen:
                    continue
                seen.add((line, secret))
                where = f"server '{server_name}'" if server_name else "settings"
                yield make(
                    RULE, target, f"{label} hardcoded in {where} ({_loc(path)})",
                    severity=severity, line=line, server=server_name, evidence=redact(secret),
                )
