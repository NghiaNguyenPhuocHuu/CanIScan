"""CS007 auto-approved tools, CS008 permission bypass in agent settings."""

from __future__ import annotations

import re
from typing import Iterator

from ..models import FileKind, Finding, ScanTarget, Severity
from .base import make
from .catalog import AUTO_APPROVE, PERMISSIONS_BYPASS

RISKY_TOOL = re.compile(r"(write|edit|delete|remove|rm|exec|run|shell|bash|command|push|merge|deploy|send|post|create|update|drop|kill|transfer)", re.I)
UNRESTRICTED_SHELL = {"bash", "bash(*)", "bash(:*)", "bash(**)", "*", "shell", "shell(*)"}
INTERPRETER_ALLOW = re.compile(
    r"^Bash\(\s*(sudo|sh|bash|zsh|python3?|node|deno|bun|perl|ruby|php|curl|wget|eval|env|xargs|npx|uvx)\b[^)]*\*\s*\)$", re.I
)


def check_auto_approve(target: ScanTarget) -> Iterator[Finding]:
    if target.kind != FileKind.CONFIG:
        return
    for s in target.servers:
        line = target.server_line(s.name)
        for key in ("autoApprove", "alwaysAllow"):
            value = s.raw.get(key)
            if value is True or (isinstance(value, list) and any(str(v).strip() == "*" for v in value)):
                yield make(AUTO_APPROVE, target, f"Server '{s.name}' auto-approves every tool ({key})",
                           severity=Severity.HIGH, line=target.line_of(key, line) or line, server=s.name)
            elif isinstance(value, list) and value:
                risky = [str(v) for v in value if RISKY_TOOL.search(str(v))]
                if risky:
                    yield make(AUTO_APPROVE, target,
                               f"Server '{s.name}' auto-approves tools that can change things: {', '.join(risky[:5])}",
                               line=target.line_of(key, line) or line, server=s.name)
                else:
                    yield make(AUTO_APPROVE, target,
                               f"Server '{s.name}' auto-approves {len(value)} tool(s); make sure they are read-only",
                               severity=Severity.LOW, line=target.line_of(key, line) or line, server=s.name)
        if s.raw.get("trust") is True:
            yield make(AUTO_APPROVE, target, f"Server '{s.name}' has \"trust\": true, which skips all tool confirmations",
                       severity=Severity.HIGH, line=target.line_of('"trust"', line) or line, server=s.name)


def check_permissions(target: ScanTarget) -> Iterator[Finding]:
    data = target.data
    if target.kind != FileKind.CONFIG or not isinstance(data, dict):
        return
    perms = data.get("permissions")
    if isinstance(perms, dict):
        if perms.get("defaultMode") == "bypassPermissions":
            yield make(PERMISSIONS_BYPASS, target, "defaultMode is 'bypassPermissions': the agent never asks before acting",
                       line=target.line_of("bypassPermissions"), evidence='"defaultMode": "bypassPermissions"')
        allow = perms.get("allow")
        if isinstance(allow, list):
            for entry in allow:
                e = str(entry).strip()
                if e.lower().replace(" ", "") in UNRESTRICTED_SHELL:
                    yield make(PERMISSIONS_BYPASS, target, f"Allow rule '{e}' permits any shell command without asking",
                               line=target.line_of(f'"{e}"'), evidence=e)
                elif INTERPRETER_ALLOW.match(e):
                    yield make(PERMISSIONS_BYPASS, target,
                               f"Allow rule '{e}' lets the agent run arbitrary code through an interpreter",
                               severity=Severity.MEDIUM, line=target.line_of(f'"{e}"'), evidence=e)
    if data.get("enableAllProjectMcpServers") is True:
        yield make(PERMISSIONS_BYPASS, target,
                   "enableAllProjectMcpServers is true: any repo you open can start its own MCP servers without approval",
                   severity=Severity.MEDIUM, line=target.line_of("enableAllProjectMcpServers"))
