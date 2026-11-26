"""Load config files and normalise MCP server entries across clients.

Supported shapes:
  * {"mcpServers": {...}}          Claude Desktop, Cursor, Windsurf, Cline, Roo, Gemini CLI, .mcp.json
  * {"servers": {...}}             VS Code .vscode/mcp.json
  * {"mcp": {"servers": {...}}}    VS Code settings.json
  * {"context_servers": {...}}     Zed
  * [mcp_servers.<name>]           Codex CLI config.toml
  * {"projects": {path: {"mcpServers": ...}}}   Claude Code ~/.claude.json
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple

from .models import FileKind, McpServer, ScanTarget

try:  # Python 3.11+
    import tomllib  # type: ignore[import-not-found]
except ModuleNotFoundError:  # pragma: no cover - exercised on 3.9/3.10
    try:
        import tomli as tomllib  # type: ignore[no-redef]
    except ModuleNotFoundError:
        tomllib = None  # type: ignore[assignment]

MAX_FILE_BYTES = 20 * 1024 * 1024
SERVER_CONTAINER_KEYS = ("mcpServers", "servers", "context_servers", "mcp_servers")
SERVER_HINT_KEYS = ("command", "url", "serverUrl", "httpUrl")


def strip_jsonc(text: str) -> str:
    """Remove // and /* */ comments plus trailing commas, preserving line numbers."""
    out: List[str] = []
    i, n = 0, len(text)
    in_str = False
    while i < n:
        c = text[i]
        if in_str:
            out.append(c)
            if c == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            if c == '"':
                in_str = False
            i += 1
            continue
        if c == '"':
            in_str = True
            out.append(c)
            i += 1
            continue
        if c == "/" and i + 1 < n and text[i + 1] == "/":
            j = text.find("\n", i)
            i = n if j == -1 else j
            continue
        if c == "/" and i + 1 < n and text[i + 1] == "*":
            j = text.find("*/", i + 2)
            end = n if j == -1 else j + 2
            out.append("\n" * text.count("\n", i, end))
            i = end
            continue
        out.append(c)
        i += 1
    return _strip_trailing_commas("".join(out))


def _strip_trailing_commas(text: str) -> str:
    """Drop commas directly before } or ], but never inside a string.

    A plain regex would also rewrite string values such as "a,}", so the scanner
    would see different data than the client that loads the file (a parser differential).
    """
    out: List[str] = []
    i, n = 0, len(text)
    in_str = False
    while i < n:
        c = text[i]
        if in_str:
            out.append(c)
            if c == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            if c == '"':
                in_str = False
        elif c == '"':
            in_str = True
            out.append(c)
        elif c == ",":
            j = i + 1
            while j < n and text[j] in " \t\r\n":
                j += 1
            if j >= n or text[j] not in "}]":
                out.append(c)
        else:
            out.append(c)
        i += 1
    return "".join(out)


def load_jsonc(text: str) -> Any:
    text = text.lstrip("﻿")
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return json.loads(strip_jsonc(text))


def _str_list(value: Any) -> List[str]:
    if isinstance(value, list):
        return [str(v) for v in value if v is not None]
    if isinstance(value, str):
        return [value]
    return []


def _str_dict(value: Any) -> Dict[str, str]:
    if isinstance(value, dict):
        return {str(k): "" if v is None else str(v) for k, v in value.items()}
    return {}


def build_server(name: str, cfg: Dict[str, Any]) -> McpServer:
    command = cfg.get("command")
    args = cfg.get("args")
    env = cfg.get("env")
    if isinstance(command, dict):  # older Zed format: {"command": {"path", "args", "env"}}
        args = command.get("args", args)
        env = command.get("env", env)
        command = command.get("path") or command.get("command")
    return McpServer(
        name=str(name),
        command=str(command) if command is not None else None,
        args=_str_list(args),
        env=_str_dict(env),
        url=cfg.get("url") or cfg.get("serverUrl") or cfg.get("httpUrl"),
        headers=_str_dict(cfg.get("headers")),
        raw=cfg,
    )


def _servers_in(container: Any, prefix: Tuple[str, ...]) -> Iterable[McpServer]:
    if not isinstance(container, dict):
        return
    for name, cfg in container.items():
        if isinstance(cfg, dict) and any(k in cfg for k in SERVER_HINT_KEYS):
            server = build_server(name, cfg)
            server.key_path = prefix + (str(name),)
            yield server


def extract_servers(data: Any) -> List[McpServer]:
    servers: List[McpServer] = []
    if not isinstance(data, dict):
        return servers
    for key in SERVER_CONTAINER_KEYS:
        servers.extend(_servers_in(data.get(key), (key,)))
    mcp = data.get("mcp")
    if isinstance(mcp, dict):
        servers.extend(_servers_in(mcp.get("servers"), ("mcp", "servers")))
    projects = data.get("projects")
    if isinstance(projects, dict):
        for project, project_cfg in projects.items():
            if isinstance(project_cfg, dict):
                servers.extend(_servers_in(project_cfg.get("mcpServers"), ("projects", str(project), "mcpServers")))
    return servers


def load_target(path: Path, kind: str, display_path: str = "") -> ScanTarget:
    target = ScanTarget(path=path, kind=kind, display_path=display_path or str(path))
    try:
        if path.stat().st_size > MAX_FILE_BYTES:
            target.parse_error = "file too large, skipped"
            return target
        target.text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        target.parse_error = f"cannot read: {exc.strerror or exc}"
        return target

    if kind != FileKind.CONFIG or not target.text.strip():
        return target
    try:
        if path.suffix.lower() == ".toml":
            if tomllib is None:
                target.parse_error = "TOML parsing needs Python 3.11+ or the 'tomli' package"
                return target
            target.data = tomllib.loads(target.text)
        else:
            target.data = load_jsonc(target.text)
    except Exception as exc:  # malformed user config should never crash the scan
        target.parse_error = f"could not parse: {exc}"
        return target
    target.servers = extract_servers(target.data)
    for server in target.servers:
        server.line = (
            target.locate(server.key_path)
            or target.line_of(f'"{server.name}"')
            or target.line_of(server.name)
        )
    return target
