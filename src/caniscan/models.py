"""Core data types shared by discovery, rules and reporters."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from enum import IntEnum
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple


class Severity(IntEnum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, value: str) -> "Severity":
        try:
            return cls[value.upper()]
        except KeyError:
            raise ValueError(f"unknown severity: {value!r}") from None

    @property
    def label(self) -> str:
        return self.name.lower()


@dataclass(frozen=True)
class Rule:
    id: str
    name: str
    severity: Severity  # default severity; individual findings may differ
    summary: str
    remediation: str


@dataclass
class Finding:
    rule: Rule
    severity: Severity
    path: str
    message: str
    line: Optional[int] = None
    server: Optional[str] = None
    evidence: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule.id,
            "rule": self.rule.name,
            "severity": self.severity.label,
            "path": self.path,
            "line": self.line,
            "server": self.server,
            "message": self.message,
            "evidence": self.evidence,
            "remediation": self.rule.remediation,
        }


@dataclass
class McpServer:
    """A normalised MCP server entry, whatever client format it came from."""

    name: str
    command: Optional[str] = None
    args: List[str] = field(default_factory=list)
    env: Dict[str, str] = field(default_factory=dict)
    url: Optional[str] = None
    headers: Dict[str, str] = field(default_factory=dict)
    raw: Dict[str, Any] = field(default_factory=dict)
    # Where the entry lives in the document, e.g. ("projects", "/repo", "mcpServers", "gh").
    # Names are not unique (~/.claude.json repeats them per project), so the path is the identity.
    key_path: Tuple[str, ...] = ()
    line: Optional[int] = None

    @property
    def executable(self) -> str:
        return normalize_executable(self.command or "")


def normalize_executable(cmd: str) -> str:
    """'/usr/local/bin/npx' -> 'npx', 'C:\\...\\npx.cmd' -> 'npx'."""
    name = re.split(r"[\\/]", cmd.strip())[-1].lower()
    for ext in (".cmd", ".exe", ".bat", ".ps1"):
        if name.endswith(ext):
            return name[: -len(ext)]
    return name


class FileKind:
    CONFIG = "config"  # JSON/TOML agent or MCP configuration
    INSTRUCTIONS = "instructions"  # AGENTS.md, CLAUDE.md, .cursorrules, ...


@dataclass
class ScanTarget:
    path: Path
    kind: str
    text: str = ""
    data: Any = None
    servers: List[McpServer] = field(default_factory=list)
    parse_error: Optional[str] = None
    display_path: str = ""

    def line_of(self, needle: Optional[str], start_line: Optional[int] = None) -> Optional[int]:
        """1-based line of the first occurrence of `needle` (optionally at/after start_line)."""
        if not needle:
            return None
        offset = 0
        if start_line and start_line > 1:
            pos = -1
            for _ in range(start_line - 1):
                pos = self.text.find("\n", pos + 1)
                if pos == -1:
                    break
            offset = max(pos, 0)
        candidates = [needle, json.dumps(needle)[1:-1]]
        for cand in candidates:
            idx = self.text.find(cand, offset)
            if idx == -1 and offset:
                idx = self.text.find(cand)
            if idx != -1:
                return self.text.count("\n", 0, idx) + 1
        return None

    def locate(self, key_path: Sequence[str]) -> Optional[int]:
        """1-based line of a nested key, found by searching for each key after the previous one.

        Good enough for JSON and TOML without a position-tracking parser: "projects" then "/b"
        then "mcpServers" then "gh" lands on the second project's "gh", not the first.
        """
        offset, idx = 0, -1
        for key in key_path:
            idx = -1
            for cand in (json.dumps(key), key):  # quoted JSON key first, then bare (TOML headers)
                idx = self.text.find(cand, offset)
                if idx != -1:
                    break
            if idx == -1:
                return None
            offset = idx + 1
        return self.text.count("\n", 0, idx) + 1 if idx != -1 else None
