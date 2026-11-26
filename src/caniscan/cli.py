"""Command-line entry point."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import List, Optional

from . import __version__
from .models import Severity
from .report import render, use_color
from .rules import ALL_RULES, RULES_BY_ID
from .scanner import scan

SEVERITIES = [s.label for s in Severity]


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="caniscan",
        description="Find security problems in AI agent and MCP configurations.",
        epilog="With no paths, scans the current directory plus your user-level AI client configs.",
    )
    p.add_argument("paths", nargs="*", type=Path, help="files or directories to scan (default: .)")
    g = p.add_mutually_exclusive_group()
    g.add_argument("--global", dest="include_global", action="store_true", default=None,
                   help="also scan user-level configs (Claude Desktop, Cursor, VS Code, Windsurf, ...)")
    g.add_argument("--no-global", dest="include_global", action="store_false",
                   help="do not scan user-level configs")
    p.add_argument("-f", "--format", choices=["text", "json", "sarif"], default="text")
    p.add_argument("-o", "--output", type=Path, help="write the report to a file instead of stdout")
    p.add_argument("--fail-on", choices=SEVERITIES + ["never"], default="high",
                   help="exit with code 1 if any finding is at or above this severity (default: high)")
    p.add_argument("--min-severity", choices=SEVERITIES, default="low", help="hide findings below this severity")
    p.add_argument("--ignore", action="append", default=[], metavar="RULE_ID",
                   help="skip a rule, e.g. --ignore CS002 (repeatable)")
    p.add_argument("--list-rules", action="store_true", help="print all rules and exit")
    p.add_argument("--no-color", action="store_true")
    p.add_argument("--version", action="version", version=f"CanIScan {__version__}")
    return p


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)

    if args.list_rules:
        for r in ALL_RULES:
            print(f"{r.id}  {r.severity.name:<8}  {r.name:<26} {r.summary}")
        return 0

    unknown = [i for i in args.ignore if i.upper() not in RULES_BY_ID]
    if unknown:
        print(f"caniscan: unknown rule id(s): {', '.join(unknown)}", file=sys.stderr)
        return 2

    paths = args.paths or [Path(".")]
    missing = [str(p) for p in paths if not p.exists()]
    if missing:
        print(f"caniscan: path not found: {', '.join(missing)}", file=sys.stderr)
        return 2
    include_global = args.include_global if args.include_global is not None else not args.paths

    result = scan(paths, include_global=include_global, ignore=args.ignore,
                  min_severity=Severity.parse(args.min_severity))

    if args.output:
        args.output.write_text(render(result, args.format), encoding="utf-8")
        if args.format != "text":
            # keep a human summary on the console when writing machine output to a file
            sys.stderr.write(render(result, "text", color=use_color(sys.stderr, args.no_color)))
    else:
        color = args.format == "text" and use_color(sys.stdout, args.no_color)
        sys.stdout.write(render(result, args.format, color=color))

    if args.fail_on != "never":
        threshold = Severity.parse(args.fail_on)
        if any(f.severity >= threshold for f in result.findings):
            return 1
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
