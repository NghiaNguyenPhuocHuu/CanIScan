"""CS009 hidden Unicode, CS010 prompt-injection phrases."""

from __future__ import annotations

import re
from typing import Iterator, List, Tuple

from ..models import FileKind, Finding, ScanTarget, Severity
from .base import make
from .catalog import HIDDEN_UNICODE, INJECTION_PHRASE

TAG_START, TAG_END = 0xE0000, 0xE007F  # "ASCII smuggling": invisible copies of ASCII
ZERO_WIDTH = {0x200B, 0x200C, 0x2060, 0x180E, 0xFEFF}  # ZWJ (200D) is left out: emoji use it
BIDI = set(range(0x202A, 0x202F)) | set(range(0x2066, 0x206A))  # Trojan Source


def _visible(line: str, limit: int = 110) -> str:
    """Render a line with invisible characters made visible."""
    out: List[str] = []
    tag_run = 0
    for ch in line:
        cp = ord(ch)
        if TAG_START <= cp <= TAG_END:
            tag_run += 1
            continue
        if tag_run:
            out.append(f"⟨{tag_run} hidden tag chars⟩")
            tag_run = 0
        out.append(f"⟨U+{cp:04X}⟩" if cp in ZERO_WIDTH or cp in BIDI else ch)
    if tag_run:
        out.append(f"⟨{tag_run} hidden tag chars⟩")
    s = "".join(out).strip()
    return s if len(s) <= limit else s[: limit - 1] + "…"


def check_hidden_unicode(target: ScanTarget) -> Iterator[Finding]:
    for lineno, line in enumerate(target.text.splitlines(), 1):
        tags, zw, bidi = [], 0, 0
        for idx, ch in enumerate(line):
            cp = ord(ch)
            if TAG_START <= cp <= TAG_END:
                tags.append(cp)
            elif cp in BIDI:
                bidi += 1
            elif cp in ZERO_WIDTH and not (cp == 0xFEFF and lineno == 1 and idx == 0):
                zw += 1
        if tags:
            decoded = "".join(chr(cp - TAG_START) for cp in tags if 0x20 <= cp - TAG_START <= 0x7E)
            msg = f"{len(tags)} invisible Unicode tag characters"
            if decoded.strip():
                shown = decoded if len(decoded) <= 160 else decoded[:159] + "…"
                msg += f" hide this text: \"{shown}\""
            yield make(HIDDEN_UNICODE, target, msg, severity=Severity.CRITICAL, line=lineno, evidence=_visible(line))
        if bidi:
            yield make(HIDDEN_UNICODE, target, f"{bidi} bidirectional control character(s) can make text display differently from what the model reads",
                       line=lineno, evidence=_visible(line))
        if zw:
            yield make(HIDDEN_UNICODE, target, f"{zw} zero-width character(s) on this line",
                       severity=Severity.MEDIUM, line=lineno, evidence=_visible(line))


PHRASES: List[Tuple["re.Pattern[str]", str, Severity]] = [
    (re.compile(r"\b(ignore|disregard|forget|override)\s+(all\s+|any\s+)?(of\s+)?(the\s+|your\s+)?(previous|prior|above|earlier|preceding|original|system)\s+(instructions|prompts?|rules|directions|guidelines)", re.I),
     "tries to override the agent's instructions", Severity.HIGH),
    (re.compile(r"\b(do\s+not|don'?t|never)\s+(tell|inform|mention|reveal|disclose|show|notify)\b[^.\n]{0,30}\b(the\s+)?user\b", re.I),
     "tells the agent to hide something from the user", Severity.HIGH),
    (re.compile(r"\b(curl|wget)\s+[^\n|]*\|\s*(sudo\s+)?(ba|z)?sh\b", re.I),
     "asks the agent to pipe a remote script into a shell", Severity.MEDIUM),
    (re.compile(r"\byou\s+are\s+now\s+(in\s+)?(developer|dan|jailbreak|unrestricted|god)\b", re.I),
     "uses a jailbreak persona", Severity.MEDIUM),
    (re.compile(r"\b(send|post|upload|exfiltrate|forward|copy)\b[^\n]{0,60}(\.env\b|id_rsa|\.ssh\b|credentials|api[_\s-]?keys?|private\s+keys?)\b[^\n]{0,60}\b(to|https?://)", re.I),
     "may instruct the agent to send secrets somewhere", Severity.MEDIUM),
]


def check_injection(target: ScanTarget) -> Iterator[Finding]:
    if target.kind != FileKind.INSTRUCTIONS:
        return
    for lineno, line in enumerate(target.text.splitlines(), 1):
        for rx, description, severity in PHRASES:
            m = rx.search(line)
            if m:
                yield make(INJECTION_PHRASE, target, f"Instruction text {description}", severity=severity,
                           line=lineno, evidence=_visible(m.group(0)))
