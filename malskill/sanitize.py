"""Display sanitization: detect on raw bytes, sanitize only what is shown.

Principle 7 of the blueprint. Every rule matches against the bytes that were on disk;
only the *copy* that reaches a terminal, a JSON report or the AI explainer goes through
this module. Doing it the other way round hides the obfuscation from the thing that is
supposed to judge it.

What this module does to a display copy:

* escapes control characters and invisible/bidi codepoints to ``\\u{200B}`` form, so a
  zero-width payload becomes visible text instead of vanishing into the terminal;
* defangs URLs (``http`` -> ``hxxp``, ``.`` -> ``[.]`` inside hosts) so the report itself
  cannot act as a lure or be pasted into a browser by reflex;
* collapses newlines and truncates to a bounded length so one finding cannot flood the
  report.

It also exposes :func:`find_invisible` which reports invisible codepoints found in *raw
bytes* — that is a detection helper, and it is here rather than in a rule module so the
byte offsets and the escaping share one table.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, List, Tuple

__all__ = [
    "INVISIBLE_CODEPOINTS",
    "InvisibleHit",
    "find_invisible",
    "strip_invisible",
    "for_display",
    "defang",
    "escape_controls",
    "decode_bytes",
]

# ---------------------------------------------------------------------------------------
# Invisible / direction-control codepoints
# ---------------------------------------------------------------------------------------

#: Codepoint -> human name. These are the characters that let a file show one thing to a
#: reviewer and say another thing to a model.
INVISIBLE_CODEPOINTS: Dict[int, str] = {
    0x200B: "ZERO WIDTH SPACE",
    0x200C: "ZERO WIDTH NON-JOINER",
    0x200D: "ZERO WIDTH JOINER",
    0x200E: "LEFT-TO-RIGHT MARK",
    0x200F: "RIGHT-TO-LEFT MARK",
    0x202A: "LEFT-TO-RIGHT EMBEDDING",
    0x202B: "RIGHT-TO-LEFT EMBEDDING",
    0x202C: "POP DIRECTIONAL FORMATTING",
    0x202D: "LEFT-TO-RIGHT OVERRIDE",
    0x202E: "RIGHT-TO-LEFT OVERRIDE",
    0x2060: "WORD JOINER",
    0x2061: "FUNCTION APPLICATION",
    0x2062: "INVISIBLE TIMES",
    0x2063: "INVISIBLE SEPARATOR",
    0x2064: "INVISIBLE PLUS",
    0xFEFF: "ZERO WIDTH NO-BREAK SPACE / BOM",
}

#: UTF-8 encodings of the above, used for raw-byte detection.
_INVISIBLE_BYTES: List[Tuple[bytes, int]] = sorted(
    ((chr(cp).encode("utf-8"), cp) for cp in INVISIBLE_CODEPOINTS),
    key=lambda item: item[0],
)

_INVISIBLE_RE = re.compile(
    "[" + "".join(chr(cp) for cp in INVISIBLE_CODEPOINTS) + "]"
)


@dataclass
class InvisibleHit:
    """One invisible codepoint found in raw bytes."""

    codepoint: int
    name: str
    byte_offset: int
    line: int

    @property
    def label(self) -> str:
        return "U+%04X (%s)" % (self.codepoint, self.name)


def find_invisible(data: bytes, *, allow_leading_bom: bool = True) -> List[InvisibleHit]:
    """Find invisible/bidi codepoints in **raw bytes**.

    A leading UTF-8 BOM is exempted by default: it is an editor artifact, not an
    attack, and flagging it would train the reader to skim past this finding.
    """
    hits: List[InvisibleHit] = []
    start = 0
    if allow_leading_bom and data.startswith(b"\xef\xbb\xbf"):
        start = 3
    newline_positions: List[int] = []
    for seq, cp in _INVISIBLE_BYTES:
        idx = data.find(seq, start)
        while idx != -1:
            if not newline_positions:
                newline_positions = _newline_index(data)
            hits.append(
                InvisibleHit(
                    codepoint=cp,
                    name=INVISIBLE_CODEPOINTS[cp],
                    byte_offset=idx,
                    line=_line_of(newline_positions, idx),
                )
            )
            idx = data.find(seq, idx + len(seq))
    hits.sort(key=lambda h: h.byte_offset)
    return hits


def _newline_index(data: bytes) -> List[int]:
    positions: List[int] = []
    idx = data.find(b"\n")
    while idx != -1:
        positions.append(idx)
        idx = data.find(b"\n", idx + 1)
    return positions


def _line_of(newline_positions: List[int], offset: int) -> int:
    lo, hi = 0, len(newline_positions)
    while lo < hi:
        mid = (lo + hi) // 2
        if newline_positions[mid] < offset:
            lo = mid + 1
        else:
            hi = mid
    return lo + 1


def strip_invisible(text: str) -> str:
    """Remove invisible/bidi codepoints. Only ever used on display or model copies."""
    return _INVISIBLE_RE.sub("", text)


def decode_bytes(data: bytes) -> str:
    """Decode raw bytes for text rules without ever raising.

    Invalid sequences become U+FFFD. Invisible codepoints are preserved because rules
    must still be able to see them: sanitization happens on the way *out*, not here.
    """
    return data.decode("utf-8", errors="replace")


# ---------------------------------------------------------------------------------------
# Display escaping
# ---------------------------------------------------------------------------------------

_CONTROL_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")


def escape_controls(text: str) -> str:
    """Escape control characters and invisible codepoints to a visible ``\\u{XXXX}``."""

    def _esc(match: "re.Match[str]") -> str:
        return "\\u{%04X}" % ord(match.group(0))

    text = _CONTROL_RE.sub(_esc, text)
    text = _INVISIBLE_RE.sub(_esc, text)
    return text


_URL_RE = re.compile(r"\b(?P<scheme>https?|ftp|ws|wss)(?P<rest>://[^\s'\"<>`)\]]+)", re.I)

#: Hostnames written without a scheme still need defanging: a finding that says
#: "executes whatever opencode.ai returns" is a live, pasteable hostname sitting in a
#: security report. The list is curated rather than "any 2+ letter suffix", because a
#: generic pattern turns ``script.py`` and ``config.ini`` into ``script[.]py``.
_DEFANG_TLDS = (
    "com|net|org|edu|gov|mil|int|io|ai|sh|dev|app|run|cloud|codes|tools|systems|"
    "link|click|site|store|shop|live|life|world|space|website|host|press|zone|team|"
    "digital|network|services|solutions|technology|software|studio|agency|ninja|wtf|"
    "info|biz|online|pro|xyz|top|icu|vip|club|fun|art|blog|page|wiki|news|today|"
    "ru|cn|su|ua|by|kz|pl|de|fr|nl|uk|eu|us|ca|au|nz|jp|kr|in|br|mx|it|es|se|no|fi|"
    "dk|ch|at|be|cz|gr|pt|tr|za|il|ir|vn|th|id|ph|sg|hk|tw|me|tv|cc|co|ws|to|gg|gl|"
    "tk|ml|ga|cf|gq|pw|mobi|name|email|expert|report|security|review|download|stream|"
    "party|science|work|rocks|cool|guru|plus|one|new|now|dad|zip|mov|foo|bar"
)
_BARE_HOST_RE = re.compile(
    r"(?<![\w.@/:-])((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"(?:" + _DEFANG_TLDS + r"))"
    r"(?![\w-])",
    re.I,
)


def _defang_url(match: "re.Match[str]") -> str:
    scheme = match.group("scheme").lower()
    scheme = scheme.replace("http", "hxxp").replace("ftp", "fxp").replace("ws", "wsx")
    rest = match.group("rest")
    # Defang only the host portion (up to the first / after ://).
    head, sep, tail = rest[3:].partition("/")
    return scheme + "://" + head.replace(".", "[.]") + sep + tail


def defang(text: str) -> str:
    """Neutralise URLs and bare hostnames so the report is not itself clickable bait."""
    text = _URL_RE.sub(_defang_url, text)
    text = _BARE_HOST_RE.sub(lambda m: m.group(1).replace(".", "[.]"), text)
    return text


def for_display(text: str, limit: int = 400, *, collapse: bool = True) -> str:
    """Render a raw-derived snippet for a terminal, a JSON report or the explainer.

    Order matters: escape first (so a hidden character becomes literal text), then
    defang (so escaping cannot be used to smuggle a live URL past the defanger), then
    truncate.
    """
    if text is None:
        return ""
    if collapse:
        text = text.replace("\r\n", "\n").replace("\r", "\n")
        text = "\\n".join(part.strip() for part in text.split("\n"))
        text = re.sub(r"[ \t]{3,}", "  ", text)
    text = escape_controls(text)
    text = defang(text)
    text = text.strip()
    if limit and len(text) > limit:
        text = text[: max(0, limit - 1)].rstrip() + "…"
    return text


def snippet_around(text: str, index: int, width: int = 200) -> str:
    """Extract a window of text centred on ``index`` (still raw; caller displays it)."""
    if index < 0:
        index = 0
    start = max(0, index - width // 2)
    end = min(len(text), index + width // 2)
    return text[start:end]
