"""Helpers shared by rule implementations."""

from __future__ import annotations

import re
from typing import List, Optional, Tuple

from ..models import Finding, McpServer, Rule, ScanTarget, Severity, normalize_executable


def make(
    rule: Rule,
    target: ScanTarget,
    message: str,
    *,
    severity: Optional[Severity] = None,
    line: Optional[int] = None,
    server: Optional[str] = None,
    evidence: Optional[str] = None,
) -> Finding:
    return Finding(
        rule=rule,
        severity=severity or rule.severity,
        path=target.display_path,
        message=message,
        line=line,
        server=server,
        evidence=evidence,
    )


def redact(secret: str) -> str:
    """Never print a full secret: keep a short prefix so the user can find it."""
    s = secret.strip()
    if len(s) <= 8:
        return "*" * len(s)
    return f"{s[:4]}…**** ({len(s)} chars)"


_REFERENCE = re.compile(r"\$\{[^}]+\}|^\$[A-Za-z_]\w*$|%[A-Za-z_]\w*%|\{\{[^}]+\}\}")
_PLACEHOLDER_HINTS = (
    "your", "<", "xxxx", "changeme", "change-me", "change_me", "placeholder", "example",
    "replace", "insert", "dummy", "redacted", "...", "todo", "fixme", "sample",
)


def is_reference_or_placeholder(value: str) -> bool:
    """True for ${env:X}, $VAR, %VAR%, {{x}}, <your-key>, YOUR_TOKEN_HERE, xxxx, etc."""
    v = value.strip()
    if not v:
        return True
    if _REFERENCE.search(v):
        return True
    low = v.lower()
    if any(h in low for h in _PLACEHOLDER_HINTS):
        return True
    return len(set(v)) <= 2


def command_line(server: McpServer) -> Tuple[str, List[str]]:
    """Return (executable, args), unwrapping Windows-style `cmd /c npx ...`."""
    exe = server.executable
    args = list(server.args)
    if exe == "cmd" and args and args[0].lower() in ("/c", "/k") and len(args) > 1:
        exe = normalize_executable(args[1])
        args = args[2:]
    return exe, args
