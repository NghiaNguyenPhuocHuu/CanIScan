"""Orchestrates discovery -> parsing -> rules."""

from __future__ import annotations

import os
import stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, List, Optional, Sequence

from .discovery import discover
from .models import FileKind, Finding, ScanTarget, Severity
from .parsers import load_target
from .rules import CHECKS
from .rules.base import make
from .rules.catalog import FILE_PERMISSIONS, HARDCODED_SECRET


@dataclass
class ScanResult:
    targets: List[ScanTarget] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    @property
    def server_count(self) -> int:
        return sum(len(t.servers) for t in self.targets)

    def counts(self) -> dict:
        out = {s.label: 0 for s in sorted(Severity, reverse=True)}
        for f in self.findings:
            out[f.severity.label] += 1
        return out


def display_path(path: Path, cwd: Optional[Path] = None) -> str:
    cwd = cwd or Path.cwd()
    try:
        return path.resolve().relative_to(cwd.resolve()).as_posix()
    except ValueError:
        pass
    home = Path.home()
    try:
        return "~/" + path.resolve().relative_to(home.resolve()).as_posix()
    except ValueError:
        return str(path)


def _check_file_permissions(target: ScanTarget, has_secret: bool) -> Iterable[Finding]:
    if os.name == "nt":
        return []
    try:
        mode = target.path.stat().st_mode
    except OSError:
        return []
    if mode & stat.S_IWOTH:
        what = "add an MCP server (code execution as you)" if target.kind == FileKind.CONFIG else "inject agent instructions"
        return [make(FILE_PERMISSIONS, target, f"File is world-writable: any local user can {what}",
                     severity=Severity.HIGH, evidence=oct(mode & 0o777))]
    if has_secret and mode & stat.S_IROTH:
        return [make(FILE_PERMISSIONS, target, "File contains secrets and is readable by every local user",
                     evidence=oct(mode & 0o777))]
    return []


def scan(
    paths: Sequence[Path],
    include_global: bool = False,
    ignore: Iterable[str] = (),
    min_severity: Severity = Severity.LOW,
) -> ScanResult:
    ignored = {i.upper() for i in ignore}
    result = ScanResult()
    for path, kind in discover(paths, include_global):
        target = load_target(path, kind, display_path(path))
        result.targets.append(target)
        if target.parse_error:
            result.errors.append(f"{target.display_path}: {target.parse_error}")

        found: List[Finding] = []
        for check in CHECKS:
            try:
                found.extend(check(target))
            except Exception as exc:  # one buggy rule must not kill the scan
                result.errors.append(f"{target.display_path}: rule {check.__module__}.{check.__name__} crashed: {exc!r}")
        has_secret = any(f.rule is HARDCODED_SECRET for f in found)
        found.extend(_check_file_permissions(target, has_secret))
        result.findings.extend(found)

    result.findings = [
        f for f in result.findings if f.rule.id not in ignored and f.severity >= min_severity
    ]
    result.findings.sort(key=lambda f: (f.path, -f.severity, f.line or 0, f.rule.id))
    return result
