"""Output formats: human text, JSON, SARIF 2.1.0 (GitHub code scanning)."""

from __future__ import annotations

import json
import os
import sys
from itertools import groupby
from typing import Dict, Optional

from . import __version__
from .models import Severity
from .rules import ALL_RULES
from .scanner import ScanResult

REPO_URL = "https://github.com/NghiaNguyenPhuocHuu/CanIScan"
COLORS = {
    Severity.CRITICAL: "\033[1;97;41m",
    Severity.HIGH: "\033[1;31m",
    Severity.MEDIUM: "\033[1;33m",
    Severity.LOW: "\033[36m",
}
DIM, BOLD, RESET, GREEN = "\033[2m", "\033[1m", "\033[0m", "\033[1;32m"


def use_color(stream=None, force_off: bool = False) -> bool:
    stream = stream or sys.stdout
    if force_off or os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    return hasattr(stream, "isatty") and stream.isatty()


def render_text(result: ScanResult, color: bool = False) -> str:
    def c(code: str, text: str) -> str:
        return f"{code}{text}{RESET}" if color else text

    lines = [
        c(BOLD, f"CanIScan {__version__}")
        + c(DIM, f"  scanned {len(result.targets)} file(s), {result.server_count} MCP server(s)"),
        "",
    ]
    if not result.targets:
        lines.append("No agent or MCP configuration files found.")
    explained = set()
    for path, group in groupby(result.findings, key=lambda f: f.path):
        lines.append(c(BOLD, path))
        for f in group:
            sev = c(COLORS[f.severity], f" {f.severity.name:<8}")
            loc = c(DIM, f"  (line {f.line})") if f.line else ""
            lines.append(f"  {sev} {c(DIM, f.rule.id)}  {f.message}{loc}")
            if f.evidence:
                lines.append(c(DIM, f"             evidence: {f.evidence}"))
            if f.rule.id not in explained:  # show each fix once to keep output scannable
                explained.add(f.rule.id)
                lines.append(c(DIM, f"             fix: {f.rule.remediation}"))
        lines.append("")

    for err in result.errors:
        lines.append(c(DIM, f"warning: {err}"))
    if result.errors:
        lines.append("")

    counts = result.counts()
    if result.findings:
        summary = ", ".join(c(COLORS[Severity[k.upper()]], f"{v} {k}") for k, v in counts.items() if v)
        lines.append(f"{c(BOLD, f'{len(result.findings)} finding(s):')} {summary}")
    elif result.targets:
        lines.append(c(GREEN, "No issues found."))
    return "\n".join(lines) + "\n"


def render_json(result: ScanResult) -> str:
    payload = {
        "tool": "caniscan",
        "version": __version__,
        "summary": {"files": len(result.targets), "servers": result.server_count, **result.counts()},
        "files": [{"path": t.display_path, "kind": t.kind, "servers": [s.name for s in t.servers]} for t in result.targets],
        "findings": [f.to_dict() for f in result.findings],
        "errors": result.errors,
    }
    return json.dumps(payload, indent=2, ensure_ascii=False) + "\n"


SARIF_LEVEL = {Severity.CRITICAL: "error", Severity.HIGH: "error", Severity.MEDIUM: "warning", Severity.LOW: "note"}
# GitHub maps security-severity: >=9 critical, >=7 high, >=4 medium, else low
SECURITY_SEVERITY = {Severity.CRITICAL: "9.5", Severity.HIGH: "8.0", Severity.MEDIUM: "5.5", Severity.LOW: "3.0"}


def _uri(path: str) -> str:
    return path[2:] if path.startswith("~/") else path


def render_sarif(result: ScanResult) -> str:
    rules = [
        {
            "id": r.id,
            "name": r.name,
            "shortDescription": {"text": r.summary},
            "fullDescription": {"text": r.summary},
            "help": {"text": r.remediation, "markdown": f"**Fix:** {r.remediation}"},
            "helpUri": f"{REPO_URL}#{r.id.lower()}",
            "defaultConfiguration": {"level": SARIF_LEVEL[r.severity]},
            "properties": {"security-severity": SECURITY_SEVERITY[r.severity], "tags": ["security", "ai-agents", "mcp"]},
        }
        for r in ALL_RULES
    ]
    index: Dict[str, int] = {r.id: i for i, r in enumerate(ALL_RULES)}
    results = []
    for f in result.findings:
        text = f.message + (f" (evidence: {f.evidence})" if f.evidence else "")
        results.append({
            "ruleId": f.rule.id,
            "ruleIndex": index[f.rule.id],
            "level": SARIF_LEVEL[f.severity],
            "message": {"text": text},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": _uri(f.path)},
                "region": {"startLine": f.line or 1},
            }}],
            "properties": {"security-severity": SECURITY_SEVERITY[f.severity]},
        })
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "CanIScan", "version": __version__, "informationUri": REPO_URL, "rules": rules}},
            "results": results,
        }],
    }
    return json.dumps(sarif, indent=2, ensure_ascii=False) + "\n"


def render(result: ScanResult, fmt: str, color: Optional[bool] = False) -> str:
    if fmt == "json":
        return render_json(result)
    if fmt == "sarif":
        return render_sarif(result)
    return render_text(result, color=bool(color))
