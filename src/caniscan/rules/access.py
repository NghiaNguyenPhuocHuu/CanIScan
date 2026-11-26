"""CS004 broad filesystem access, CS005 insecure transport."""

from __future__ import annotations

import ipaddress
import re
from pathlib import Path
from typing import Iterator, List, Optional, Tuple
from urllib.parse import urlparse

from ..models import FileKind, Finding, ScanTarget, Severity
from .base import command_line, make
from .catalog import BROAD_FS, INSECURE_TRANSPORT
from .supply_chain import docker_run

CREDENTIAL_DIRS = (
    ".ssh", ".aws", ".gnupg", ".kube", ".docker", ".azure", ".password-store",
    ".config/gcloud", ".config/gh", "Library/Keychains",
)
PATHY = re.compile(r"^(/|~|\$HOME|\$\{HOME\}|%USERPROFILE%|%HOMEPATH%|[A-Za-z]:[\\/]?$|[A-Za-z]:[\\/])")


def _expand(arg: str, home: str) -> str:
    for token in ("${HOME}", "$HOME", "%USERPROFILE%", "%HOMEPATH%"):
        if arg.startswith(token):
            return home + arg[len(token):]
    if arg == "~" or arg.startswith(("~/", "~\\")):
        return home + arg[1:]
    return arg


def classify_path(arg: str) -> Optional[Tuple[str, Severity]]:
    if not PATHY.match(arg):
        return None
    home = str(Path.home()).replace("\\", "/").rstrip("/")
    p = _expand(arg, home).replace("\\", "/")
    norm = p.rstrip("/") or "/"
    if norm == "/" or re.fullmatch(r"[A-Za-z]:", norm):
        return "the entire filesystem", Severity.HIGH
    if norm.lower() == home.lower():
        return "your whole home directory", Severity.HIGH
    if norm in ("/home", "/Users", "C:/Users"):
        return "every user's home directory", Severity.HIGH
    for d in CREDENTIAL_DIRS:
        if norm.endswith("/" + d) or f"/{d}/" in norm + "/":
            return f"a credential directory ({d})", Severity.CRITICAL
    return None


def check_filesystem(target: ScanTarget) -> Iterator[Finding]:
    if target.kind != FileKind.CONFIG:
        return
    for s in target.servers:
        exe, args = command_line(s)
        if docker_run(exe, args):
            continue  # container mounts are handled by CS006
        line = target.server_line(s.name)
        reported = set()
        for arg in args:
            value = arg.split("=", 1)[1] if arg.startswith("-") and "=" in arg else arg
            hit = classify_path(value)
            if hit and hit[0] not in reported:
                reported.add(hit[0])
                yield make(BROAD_FS, target, f"Server '{s.name}' is given access to {hit[0]}",
                           severity=hit[1], line=target.line_of(arg, line) or line, server=s.name, evidence=arg)


LOOPBACK = {"localhost", "host.docker.internal", "0.0.0.0"}
URL_IN_ARG = re.compile(r"\b(?:http|ws)://[^\s\"']+", re.I)


def _transport_issue(url: str) -> Optional[Severity]:
    try:
        u = urlparse(url)
    except ValueError:
        return None
    if u.scheme.lower() not in ("http", "ws") or not u.hostname:
        return None
    host = u.hostname.lower()
    if host in LOOPBACK or host.endswith(".localhost"):
        return None
    try:
        ip = ipaddress.ip_address(host)
        if ip.is_loopback:
            return None
        if ip.is_private or ip.is_link_local:
            return Severity.LOW
    except ValueError:
        pass
    return INSECURE_TRANSPORT.severity


def check_transport(target: ScanTarget) -> Iterator[Finding]:
    if target.kind != FileKind.CONFIG:
        return
    for s in target.servers:
        urls: List[str] = [s.url] if s.url else []
        urls += [m.group(0) for a in s.args for m in URL_IN_ARG.finditer(a)]
        has_auth = any(k.lower() in ("authorization", "x-api-key", "api-key") for k in s.headers) or any(
            "authorization" in a.lower() for a in s.args)
        line = target.server_line(s.name)
        for url in dict.fromkeys(urls):
            sev = _transport_issue(url)
            if sev is None:
                continue
            msg = f"Server '{s.name}' connects to {url} without TLS"
            if has_auth and sev >= Severity.MEDIUM:
                sev = Severity.HIGH
                msg += " and sends credentials over it"
            yield make(INSECURE_TRANSPORT, target, msg, severity=sev,
                       line=target.line_of(url, line) or line, server=s.name)
