"""CS002 unpinned packages, CS003 remote code execution, CS006 dangerous containers."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Iterator, List, Optional, Tuple

from ..models import FileKind, Finding, McpServer, ScanTarget, Severity
from .base import command_line, make
from .catalog import DANGEROUS_CONTAINER, REMOTE_CODE, UNPINNED_PACKAGE

LOCAL_SPEC = re.compile(r"^(\.|/|~|file:|git\+|git:|https?:|github:|[A-Za-z]:[\\/])")


# ---------------------------------------------------------------- npm-style runners
def _first_package(args: List[str], value_flags: Tuple[str, ...] = (), spec_flags: Tuple[str, ...] = ()) -> Optional[str]:
    i = 0
    while i < len(args):
        a = args[i]
        if a in spec_flags:
            return args[i + 1] if i + 1 < len(args) else None
        for f in spec_flags:
            if a.startswith(f + "="):
                return a.split("=", 1)[1]
        if a == "--":
            i += 1
            continue
        if a.startswith("-"):
            i += 2 if (a in value_flags and "=" not in a) else 1
            continue
        return a
    return None


def npm_package(exe: str, args: List[str]) -> Optional[str]:
    if exe in ("npx", "bunx", "pnpx"):
        rest = args
    elif exe in ("pnpm", "yarn") and args[:1] == ["dlx"]:
        rest = args[1:]
    elif exe == "bun" and args[:1] == ["x"]:
        rest = args[1:]
    elif exe == "npm" and args[:1] in (["exec"], ["x"]):
        rest = args[1:]
    else:
        return None
    return _first_package(rest, value_flags=("--registry", "--cache", "--node-options"), spec_flags=("-p", "--package"))


def npm_problem(spec: str) -> Optional[str]:
    if LOCAL_SPEC.match(spec):
        return None
    idx = spec.find("@", 1) if spec.startswith("@") else spec.find("@")
    if idx == -1:
        return "no version specified"
    version = spec[idx + 1:]
    if version in ("", "latest", "next", "*", "x", "canary", "beta"):
        return f"moving tag '@{version}'"
    if re.match(r"^[\^~><=*]", version) or "x" in version.lower().split(".") or " " in version:
        return f"version range '@{version}'"
    return None


# ---------------------------------------------------------------- python runners
PY_VALUE_FLAGS = ("--with", "--python", "-p", "--index", "--index-url", "--extra-index-url", "-i", "--pip-args")


def py_package(exe: str, args: List[str]) -> Optional[str]:
    if exe == "uvx":
        return _first_package(args, PY_VALUE_FLAGS, spec_flags=("--from",))
    if exe == "uv" and args[:2] == ["tool", "run"]:
        return _first_package(args[2:], PY_VALUE_FLAGS, spec_flags=("--from",))
    if exe == "pipx" and args[:1] == ["run"]:
        return _first_package(args[1:], PY_VALUE_FLAGS, spec_flags=("--spec",))
    return None


def py_problem(spec: str) -> Optional[str]:
    if LOCAL_SPEC.match(spec) or spec.endswith((".whl", ".tar.gz")):
        return None
    if "==" in spec or re.search(r"@\s*v?\d", spec):
        return None
    if spec.endswith("@latest"):
        return "moving tag '@latest'"
    if re.search(r"(>=|<=|~=|!=|[<>])", spec):
        return "version range"
    return "no version specified"


# ---------------------------------------------------------------- docker
DOCKER_VALUE_FLAGS = {
    "-e", "--env", "-v", "--volume", "--mount", "--name", "-p", "--publish", "--network", "--net",
    "-w", "--workdir", "-u", "--user", "--entrypoint", "--env-file", "--label", "-l", "--platform",
    "--pull", "--cap-add", "--cap-drop", "--pid", "--ipc", "--uts", "--userns", "--add-host", "--memory", "-m",
    "--cpus", "--hostname", "-h", "--restart", "--security-opt", "--device", "--gpus", "--tmpfs",
    "--ulimit", "--log-driver", "--dns", "--runtime",
}


def docker_run(exe: str, args: List[str]) -> Optional[Tuple[Optional[str], List[Tuple[str, Optional[str]]]]]:
    if exe not in ("docker", "podman", "nerdctl"):
        return None
    if args[:1] == ["run"]:
        rest = args[1:]
    elif args[:2] == ["container", "run"]:
        rest = args[2:]
    else:
        return None
    flags: List[Tuple[str, Optional[str]]] = []
    i = 0
    while i < len(rest):
        a = rest[i]
        if a.startswith("-"):
            if "=" in a:
                k, v = a.split("=", 1)
                flags.append((k, v))
            elif a in DOCKER_VALUE_FLAGS and i + 1 < len(rest):
                flags.append((a, rest[i + 1]))
                i += 1
            else:
                flags.append((a, None))
            i += 1
            continue
        return a, flags
    return None, flags


def image_problem(image: str) -> Optional[str]:
    if "@sha256:" in image or image.startswith("$"):
        return None
    last = image.rsplit("/", 1)[-1]
    if ":" not in last:
        return "no tag (defaults to :latest)"
    if last.split(":", 1)[1] == "latest":
        return "moving tag ':latest'"
    return None


def _is_root_or_home(host_path: str) -> bool:
    p = host_path.replace("\\", "/").rstrip("/")
    home = str(Path.home()).replace("\\", "/").rstrip("/")
    return p in ("", "/", "~", "$HOME", "${HOME}", "/home", "/Users") or p == home or bool(re.fullmatch(r"[A-Za-z]:", p))


# ---------------------------------------------------------------- checks
def check_unpinned(target: ScanTarget) -> Iterator[Finding]:
    if target.kind != FileKind.CONFIG:
        return
    for s in target.servers:
        exe, args = command_line(s)
        line = s.line
        spec = npm_package(exe, args)
        if spec:
            problem = npm_problem(spec)
            if problem:
                yield make(UNPINNED_PACKAGE, target, f"Server '{s.name}' runs npm package '{spec}' with {problem}",
                           line=target.line_of(spec, line) or line, server=s.name, evidence=" ".join([exe] + args))
            continue
        spec = py_package(exe, args)
        if spec:
            problem = py_problem(spec)
            if problem:
                yield make(UNPINNED_PACKAGE, target, f"Server '{s.name}' runs Python package '{spec}' with {problem}",
                           line=target.line_of(spec, line) or line, server=s.name, evidence=" ".join([exe] + args))
            continue
        run = docker_run(exe, args)
        if run and run[0]:
            problem = image_problem(run[0])
            if problem:
                yield make(UNPINNED_PACKAGE, target, f"Server '{s.name}' runs container image '{run[0]}' with {problem}",
                           line=target.line_of(run[0], line) or line, server=s.name)


DOWNLOADERS = r"(curl|wget|iwr|irm|Invoke-WebRequest|Invoke-RestMethod)"
REMOTE_EXEC_PATTERNS = [
    re.compile(DOWNLOADERS + r"\b[^|;&]*\|\s*(sudo\s+)?(ba|z|da|k)?sh\b", re.I),
    re.compile(DOWNLOADERS + r"\b[^|;&]*\|\s*(iex|Invoke-Expression|python3?|node|perl|ruby)\b", re.I),
    re.compile(r"\b(iex|Invoke-Expression)\b[\s(]*(iwr|irm|Invoke-WebRequest|Invoke-RestMethod|\(?New-Object\s+Net\.WebClient)", re.I),
    re.compile(r"\b(ba|z)?sh\s+(-c\s+)?[\"']?\s*<\(\s*(curl|wget)\b", re.I),
    re.compile(r"\beval\s+[\"']?\$\(\s*(curl|wget)\b", re.I),
]


def _full_command(s: McpServer) -> str:
    return " ".join([s.command or ""] + s.args)


def check_remote_code(target: ScanTarget) -> Iterator[Finding]:
    if target.kind != FileKind.CONFIG:
        return
    for s in target.servers:
        cmd = _full_command(s)
        for rx in REMOTE_EXEC_PATTERNS:
            m = rx.search(cmd)
            if m:
                yield make(REMOTE_CODE, target, f"Server '{s.name}' pipes a downloaded script straight into an interpreter",
                           line=s.line, server=s.name, evidence=m.group(0)[:120])
                break


def check_containers(target: ScanTarget) -> Iterator[Finding]:
    if target.kind != FileKind.CONFIG:
        return
    for s in target.servers:
        exe, args = command_line(s)
        run = docker_run(exe, args)
        if not run:
            continue
        line = s.line
        for flag, value in run[1]:
            issue: Optional[Tuple[str, Severity]] = None
            v = value or ""
            if flag == "--privileged" and v.lower() != "false":
                issue = ("runs a --privileged container (full access to the host)", Severity.CRITICAL)
            elif flag in ("-v", "--volume", "--mount"):
                src = v
                if flag == "--mount":
                    m = re.search(r"(?:source|src)=([^,]+)", v)
                    src = m.group(1) if m else ""
                else:
                    src = v.split(":")[0] if not re.match(r"^[A-Za-z]:\\", v) else v[:2]
                if "docker.sock" in v:
                    issue = ("mounts the Docker socket (equivalent to root on the host)", Severity.CRITICAL)
                elif src and _is_root_or_home(src):
                    issue = (f"mounts the host path '{src}' into the container", Severity.HIGH)
            elif flag in ("--network", "--net") and v == "host":
                issue = ("shares the host network namespace", Severity.MEDIUM)
            elif flag in ("--pid", "--ipc", "--uts", "--userns") and v == "host":
                issue = (f"shares the host {flag.lstrip('-')} namespace", Severity.HIGH)
            elif flag == "--cap-add" and v.upper() in ("ALL", "SYS_ADMIN", "SYS_PTRACE", "SYS_MODULE", "NET_ADMIN"):
                issue = (f"adds the powerful capability {v.upper()}", Severity.HIGH)
            elif flag == "--security-opt" and re.search(r"(seccomp|apparmor)[=:]unconfined", v):
                issue = (f"disables a security profile ({v})", Severity.HIGH)
            if issue:
                yield make(DANGEROUS_CONTAINER, target, f"Server '{s.name}' {issue[0]}", severity=issue[1],
                           line=target.line_of(v or flag, line) or line, server=s.name,
                           evidence=f"{flag} {v}".strip())
