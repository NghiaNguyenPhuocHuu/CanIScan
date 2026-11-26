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


def _check_value(
    path: Tuple[str, ...], value: str, prev: Optional[str], heuristics: bool = True
) -> Iterator[Tuple[str, str, Severity]]:
    """Yield (label, secret, severity) for one string value.

    Known token formats are checked everywhere. The key-name/flag heuristics are
    noisier, so callers only enable them where secrets are expected (servers, env blocks).
    """
    found = False
    for label, secret in _pattern_hits(value):
        found = True
        yield label, secret, Severity.CRITICAL
    if found or not heuristics:
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

    # Fail closed: a config we could not parse still gets the raw-text pattern scan,
    # otherwise one stray byte would hide every token in the file.
    unparsed_config = target.kind == FileKind.CONFIG and target.data is None and target.parse_error
    if target.kind == FileKind.INSTRUCTIONS or unparsed_config:
        where = "a config file that could not be parsed" if unparsed_config else "an agent instruction file"
        for lineno, line in enumerate(target.text.splitlines(), 1):
            for label, secret in _pattern_hits(line):
                if (lineno, secret) in seen:
                    continue
                seen.add((lineno, secret))
                yield make(RULE, target, f"{label} written in {where}",
                           line=lineno, evidence=redact(secret))
        return

    # One pass over the whole document (#3): secrets hide in more places than server entries,
    # e.g. ~/.claude.json projects[*].env or .claude/settings.json apiKeyHelper.
    servers = {s.key_path: s for s in target.servers if s.key_path}
    for path, value, prev in _walk(target.data):
        keys = tuple(p for p in path if not p.startswith("["))
        server = next((servers[path[:i]] for i in range(len(path), 0, -1) if path[:i] in servers), None)
        # the key-name heuristics stay scoped to places that are meant to hold credentials
        in_env = "env" in keys[:-1] or "headers" in keys[:-1]
        heuristics = server is not None or in_env
        for label, secret, severity in _check_value(path, value, prev, heuristics):
            start = server.line if server else target.locate(keys)
            line = target.line_of(secret, start) or start
            if (line, secret) in seen:
                continue
            seen.add((line, secret))
            if server:
                where, loc = f"server '{server.name}'", _loc(path[len(server.key_path):])
            else:
                where, loc = "settings", _loc(path)
            yield make(
                RULE, target, f"{label} hardcoded in {where} ({loc})",
                severity=severity, line=line, server=server.name if server else None, evidence=redact(secret),
            )
