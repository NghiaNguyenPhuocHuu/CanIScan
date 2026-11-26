"""CS009 hidden Unicode, CS010 prompt-injection phrases."""

from __future__ import annotations

import re
import unicodedata
from typing import Iterator, List, Tuple

from ..models import FileKind, Finding, ScanTarget, Severity
from .base import make
from .catalog import HIDDEN_UNICODE, INJECTION_PHRASE

TAG_START, TAG_END = 0xE0000, 0xE007F  # "ASCII smuggling": invisible copies of ASCII
ZERO_WIDTH = {0x200B, 0x200C, 0x2060, 0x180E, 0xFEFF}  # ZWJ (200D) is left out: emoji use it
BIDI = set(range(0x202A, 0x202F)) | set(range(0x2066, 0x206A))  # Trojan Source
VARIATION_SELECTORS = set(range(0xFE00, 0xFE10)) | set(range(0xE0100, 0xE01F0))


def _is_invisible(ch: str) -> bool:
    """Characters that render as nothing but are still read by a model."""
    cp = ord(ch)
    # The tag range is listed explicitly: U+E0000 itself is unassigned (Cn), not Cf.
    return (TAG_START <= cp <= TAG_END or cp in ZERO_WIDTH or cp in BIDI or cp in VARIATION_SELECTORS
            or cp == 0x034F or unicodedata.category(ch) == "Cf")


def _decode_tags(line: str) -> str:
    """The ASCII text hidden in a line's Unicode tag characters."""
    return "".join(chr(ord(ch) - TAG_START) for ch in line
                   if TAG_START <= ord(ch) <= TAG_END and 0x20 <= ord(ch) - TAG_START <= 0x7E)


def _strip_invisible(line: str) -> Tuple[str, List[int]]:
    """The line without invisible characters, and the original index of each kept character."""
    kept: List[str] = []
    index: List[int] = []
    for i, ch in enumerate(line):
        if not _is_invisible(ch):
            kept.append(ch)
            index.append(i)
    return "".join(kept), index


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
        out.append(f"⟨U+{cp:04X}⟩" if _is_invisible(ch) else ch)
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
            decoded = _decode_tags(line)
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
        # Three views of one line, one finding per phrase, the most alarming view wins:
        # the text hidden in tag characters, the raw line, and the line without invisible characters.
        hidden = _decode_tags(line)
        shown, index = _strip_invisible(line)
        for rx, description, severity in PHRASES:
            m = rx.search(hidden) if hidden else None
            if m:
                # No innocent reason to hide these words, whatever the phrase.
                yield make(INJECTION_PHRASE, target, f"Text hidden in invisible Unicode tag characters {description}",
                           severity=Severity.CRITICAL, line=lineno, evidence=f'hidden: "{_visible(m.group(0))}"')
                continue
            m = rx.search(line)
            if m:
                yield make(INJECTION_PHRASE, target, f"Instruction text {description}", severity=severity,
                           line=lineno, evidence=_visible(m.group(0)))
                continue
            m = rx.search(shown) if len(shown) != len(line) else None
            if m:
                raw = line[index[m.start()]: index[m.end() - 1] + 1]
                yield make(INJECTION_PHRASE, target,
                           f"Instruction text {description} (split up by invisible characters)",
                           severity=severity, line=lineno, evidence=_visible(raw))
