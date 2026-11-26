import json
from pathlib import Path

import pytest

from caniscan.scanner import scan


def fake(prefix: str, n: int) -> str:
    """Secret-shaped test strings, built at runtime so the repo holds none."""
    return prefix + ("aB3dE5gH7jK9mN2pQ4sT6vW8yZ" * 4)[:n]


@pytest.fixture
def project(tmp_path, monkeypatch):
    """Write files into a temp project and scan it: project({'a/b.json': {...}})."""
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    root = tmp_path / "proj"
    root.mkdir()

    def _run(files, **kwargs):
        for rel, content in files.items():
            p = root / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(content if isinstance(content, str) else json.dumps(content, indent=2), encoding="utf-8")
        return scan([root], include_global=False, **kwargs)

    _run.root = root
    _run.home = home
    return _run


def ids(result):
    return [f.rule.id for f in result.findings]


def mcp(servers):
    return {".cursor/mcp.json": {"mcpServers": servers}}
