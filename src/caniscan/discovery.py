"""Find agent/MCP config and instruction files in projects and in the user's home."""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Iterable, Iterator, List, Optional, Tuple

from .models import FileKind

CONFIG_NAMES = {
    "mcp.json",  # .cursor/, .vscode/, .roo/, ...
    ".mcp.json",  # Claude Code project servers
    "claude_desktop_config.json",
    "mcp_config.json",  # Windsurf
    "cline_mcp_settings.json",
    "mcp_settings.json",  # Roo Code
}
# (parent dir, file name) pairs that are agent settings files
SETTINGS_FILES = {
    (".claude", "settings.json"),
    (".claude", "settings.local.json"),
    (".gemini", "settings.json"),
    (".codex", "config.toml"),
}
INSTRUCTION_NAMES = {
    "agents.md",
    "claude.md",
    "claude.local.md",
    "gemini.md",
    ".cursorrules",
    ".windsurfrules",
    ".clinerules",
    "copilot-instructions.md",
}
SKIP_DIRS = {
    ".git", "node_modules", ".venv", "venv", "env", "__pycache__", "dist", "build",
    ".tox", ".nox", ".mypy_cache", ".pytest_cache", ".ruff_cache", "site-packages", "target",
}

Found = Tuple[Path, str]


def classify(path: Path) -> Optional[str]:
    name = path.name
    low = name.lower()
    if name in CONFIG_NAMES or (path.parent.name, name) in SETTINGS_FILES:
        return FileKind.CONFIG
    if low in INSTRUCTION_NAMES:
        return FileKind.INSTRUCTIONS
    parts = set(path.parts[:-1])
    if low.endswith(".mdc") and ".cursor" in parts:
        return FileKind.INSTRUCTIONS
    if low.endswith((".instructions.md", ".prompt.md")):
        return FileKind.INSTRUCTIONS
    if low.endswith(".md") and (".clinerules" in parts or ".windsurf" in parts):
        return FileKind.INSTRUCTIONS
    return None


def classify_explicit(path: Path) -> str:
    """A file the user named directly is always scanned."""
    kind = classify(path)
    if kind:
        return kind
    if path.suffix.lower() in (".json", ".jsonc", ".toml"):
        return FileKind.CONFIG
    return FileKind.INSTRUCTIONS


def walk(root: Path) -> Iterator[Found]:
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        for fname in sorted(filenames):
            p = Path(dirpath) / fname
            kind = classify(p)
            if kind:
                yield p, kind


def _app_data_dir(home: Path) -> Path:
    if sys.platform == "darwin":
        return home / "Library" / "Application Support"
    if os.name == "nt":
        return Path(os.environ.get("APPDATA", home / "AppData" / "Roaming"))
    return Path(os.environ.get("XDG_CONFIG_HOME", home / ".config"))


def global_candidates(home: Optional[Path] = None) -> List[Found]:
    """User-level config locations for popular AI clients."""
    home = home or Path.home()
    app = _app_data_dir(home)
    vscode_user = app / "Code" / "User"
    cfg = FileKind.CONFIG
    ins = FileKind.INSTRUCTIONS
    return [
        (app / "Claude" / "claude_desktop_config.json", cfg),
        (home / ".claude.json", cfg),
        (home / ".claude" / "settings.json", cfg),
        (home / ".claude" / "CLAUDE.md", ins),
        (home / ".cursor" / "mcp.json", cfg),
        (home / ".codeium" / "windsurf" / "mcp_config.json", cfg),
        (home / ".gemini" / "settings.json", cfg),
        (home / ".gemini" / "GEMINI.md", ins),
        (home / ".codex" / "config.toml", cfg),
        (home / ".codex" / "AGENTS.md", ins),
        (vscode_user / "mcp.json", cfg),
        (vscode_user / "settings.json", cfg),
        (vscode_user / "globalStorage" / "saoudrizwan.claude-dev" / "settings" / "cline_mcp_settings.json", cfg),
        (vscode_user / "globalStorage" / "rooveterinaryinc.roo-cline" / "settings" / "mcp_settings.json", cfg),
        (home / ".config" / "zed" / "settings.json", cfg),
    ]


def discover(paths: Iterable[Path], include_global: bool) -> List[Found]:
    found: List[Found] = []
    seen = set()

    def add(p: Path, kind: str) -> None:
        try:
            key = p.resolve()
        except OSError:
            key = p
        if key not in seen:
            seen.add(key)
            found.append((p, kind))

    for root in paths:
        if root.is_file():
            add(root, classify_explicit(root))
        elif root.is_dir():
            for p, kind in walk(root):
                add(p, kind)
    if include_global:
        for p, kind in global_candidates():
            if p.is_file():
                add(p, kind)
    return found
