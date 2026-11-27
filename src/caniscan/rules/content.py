"""CS009 hidden Unicode, CS010 prompt-injection phrases."""

from __future__ import annotations

import re
import unicodedata
from typing import AbstractSet, Iterator, List, Set, Tuple

from ..models import FileKind, Finding, ScanTarget, Severity
from .base import make
from .catalog import HIDDEN_UNICODE, INJECTION_PHRASE

TAG_START, TAG_END = 0xE0000, 0xE007F  # "ASCII smuggling": invisible copies of ASCII
# Zero-width and other default-ignorable characters: soft hyphen, combining grapheme joiner,
# invisible operators (function application, times, separator, plus). ZWJ is handled on its own.
ZERO_WIDTH = {0x200B, 0x200C, 0x2060, 0x180E, 0xFEFF, 0x00AD, 0x034F} | set(range(0x2061, 0x2065))
ZWJ, VS15, VS16 = 0x200D, 0xFE0E, 0xFE0F
KEYCAP_BASES = set("#*0123456789")
EMOJI_BASES_OUTSIDE_SYMBOLS = {0x203C, 0x2049, 0x2139, 0x3030, 0x303D}  # ‼ ⁉ ℹ 〰 〽
BIDI = set(range(0x202A, 0x202F)) | set(range(0x2066, 0x206A))  # Trojan Source
VARIATION_SELECTORS = set(range(0xFE00, 0xFE10)) | set(range(0xE0100, 0xE01F0))
# UTS #51 emoji tag sequence for subdivision flags (England = 🏴 + tag "gbeng" + cancel tag).
# CLDR subdivision id: region (2 letters or 3 digits) + 1-4 letters/digits, so 3-7 tag chars.
_FLAG_TAG = re.compile(
    "\U0001F3F4((?:[\U000E0061-\U000E007A]{2}|[\U000E0030-\U000E0039]{3})"
    "[\U000E0030-\U000E0039\U000E0061-\U000E007A]{1,4})\U000E007F")


def _is_invisible(ch: str) -> bool:
    """Characters that render as nothing but are still read by a model."""
    cp = ord(ch)
    # The tag range is listed explicitly: U+E0000 itself is unassigned (Cn), not Cf.
    return (TAG_START <= cp <= TAG_END or cp in ZERO_WIDTH or cp in BIDI or cp in VARIATION_SELECTORS
            or cp == 0x034F or unicodedata.category(ch) == "Cf")


def _flag_tag_indices(line: str) -> Set[int]:
    """Indices of tag characters that belong to an emoji flag (subdivision tag sequence), cancel tag included."""
    return {i for m in _FLAG_TAG.finditer(line) for i in range(m.start(1), m.end())}


def _decode_tags(line: str, skip: AbstractSet[int] = frozenset()) -> str:
    """The ASCII text hidden in a line's Unicode tag characters, leaving out the indices in `skip`."""
    return "".join(chr(ord(ch) - TAG_START) for i, ch in enumerate(line)
                   if i not in skip and TAG_START <= ord(ch) <= TAG_END and 0x20 <= ord(ch) - TAG_START <= 0x7E)


def _hidden_zwj(line: str, i: int) -> bool:
    """A ZWJ between two letters/digits, or next to another ZWJ, is not part of an emoji sequence."""
    prev = line[i - 1] if i else ""
    nxt = line[i + 1] if i + 1 < len(line) else ""
    if "\u200d" in (prev, nxt):
        return True
    return (bool(prev and nxt) and unicodedata.category(prev)[0] in "LN"
            and unicodedata.category(nxt)[0] in "LN")


def _is_cjk_ideograph(cp: int) -> bool:
    return 0x3400 <= cp <= 0x4DBF or 0x4E00 <= cp <= 0x9FFF or 0xF900 <= cp <= 0xFAFF or 0x20000 <= cp <= 0x3FFFF


def _selector_has_base(prev: str, cp: int) -> bool:
    """Whether one variation selector after `prev` can be a defined variation sequence (heuristic, no UCD file)."""
    if not prev:
        return False
    b, cat = ord(prev), unicodedata.category(prev)
    if cp in (VS15, VS16):  # text / emoji presentation
        return (cat in ("So", "Sm") or prev in KEYCAP_BASES or b in EMOJI_BASES_OUTSIDE_SYMBOLS
                or 0x1F000 <= b <= 0x1FAFF)
    if cp < VS15:  # VS1-14: math symbols, Mongolian/Phags-pa/Egyptian letters, CJK compatibility, slashed zero
        return cat in ("So", "Sm", "Lo") or prev == "0"
    return _is_cjk_ideograph(b)  # VS17-256: ideographic variation sequences


def _selector_byte(cp: int) -> int:
    """Byte carried by a selector in variation-selector smuggling (Paul Butler's scheme): VS1-16 = 0-15, VS17-256 = 16-255."""
    return cp - 0xFE00 if cp < 0xE0100 else cp - 0xE0100 + 16


def _selector_runs(line: str) -> Iterator[Tuple[int, int]]:
    """(start, end) of each run of consecutive variation selectors."""
    i = 0
    while i < len(line):
        if ord(line[i]) in VARIATION_SELECTORS:
            j = i + 1
            while j < len(line) and ord(line[j]) in VARIATION_SELECTORS:
                j += 1
            yield i, j
            i = j
        else:
            i += 1


def _decode_selectors(run: str) -> str:
    """Readable text smuggled in a run of selectors, or ""."""
    try:
        text = bytes(_selector_byte(ord(ch)) for ch in run).decode("utf-8")
    except UnicodeDecodeError:
        return ""
    if text.strip() and all(ch.isprintable() or ch.isspace() for ch in text):
        return text
    return ""


def _variation_selector_use(line: str) -> Tuple[str, int, int, int]:
    """(decoded text, selectors carrying it, selectors in long undecodable runs, stray selectors)."""
    texts: List[str] = []
    n_text = n_data = stray = 0
    for start, end in _selector_runs(line):
        n = end - start
        if n == 1:
            stray += not _selector_has_base(line[start - 1] if start else "", ord(line[start]))
            continue
        decoded = _decode_selectors(line[start:end])
        if decoded:
            texts.append(decoded)
            n_text += n
        elif n >= 4:
            n_data += n
        else:
            stray += n
    return " ".join(texts), n_text, n_data, stray


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
    flags = _flag_tag_indices(line)
    out: List[str] = []
    i = 0
    while i < len(line):
        ch, cp = line[i], ord(line[i])
        j = i + 1
        if i in flags:  # part of an emoji flag: keep it so the flag still renders
            out.append(ch)
        elif TAG_START <= cp <= TAG_END:
            while j < len(line) and TAG_START <= ord(line[j]) <= TAG_END and j not in flags:
                j += 1
            out.append(f"⟨{j - i} hidden tag chars⟩")
        elif cp in VARIATION_SELECTORS:
            while j < len(line) and ord(line[j]) in VARIATION_SELECTORS:
                j += 1
            out.append(f"⟨U+{cp:04X}⟩" if j - i == 1 else f"⟨{j - i} variation selectors⟩")
        else:
            out.append(f"⟨U+{cp:04X}⟩" if _is_invisible(ch) else ch)
        i = j
    s = "".join(out).strip()
    return s if len(s) <= limit else s[: limit - 1] + "…"


def check_hidden_unicode(target: ScanTarget) -> Iterator[Finding]:
    for lineno, line in enumerate(target.text.splitlines(), 1):
        flags = _flag_tag_indices(line)
        tags, zw, bidi = 0, 0, 0
        for idx, ch in enumerate(line):
            cp = ord(ch)
            if TAG_START <= cp <= TAG_END:
                tags += idx not in flags
            elif cp in BIDI:
                bidi += 1
            elif cp in ZERO_WIDTH and not (cp == 0xFEFF and lineno == 1 and idx == 0):
                zw += 1
            elif cp == ZWJ and _hidden_zwj(line, idx):
                zw += 1
        payload, n_text, n_data, stray = _variation_selector_use(line)
        zw += stray
        if tags:
            decoded = _decode_tags(line, skip=flags)
            msg = f"{tags} invisible Unicode tag characters"
            if decoded.strip():
                shown = decoded if len(decoded) <= 160 else decoded[:159] + "…"
                msg += f" hide this text: \"{shown}\""
            yield make(HIDDEN_UNICODE, target, msg, severity=Severity.CRITICAL, line=lineno, evidence=_visible(line))
        if n_text:
            shown = re.sub(r"\s+", " ", payload)
            shown = shown if len(shown) <= 160 else shown[:159] + "…"
            yield make(HIDDEN_UNICODE, target, f"{n_text} invisible variation selectors hide this text: \"{shown}\"",
                       severity=Severity.CRITICAL, line=lineno, evidence=_visible(line))
        if n_data:
            yield make(HIDDEN_UNICODE, target,
                       f"{n_data} variation selectors in a row can carry hidden data (variation-selector smuggling)",
                       severity=Severity.HIGH, line=lineno, evidence=_visible(line))
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
        # Emoji flags are decoded too ("gbeng"): no spaces, so no phrase matches one alone, and
        # skipping them would let a flag split a hidden phrase from the rest of the line.
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
