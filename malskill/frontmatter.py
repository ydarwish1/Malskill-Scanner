"""A deliberately minimal, deliberately dumb frontmatter parser.

The extractor is the highest-value target in a scanner: it runs first, it runs trusted,
and it runs over attacker-controlled bytes. So it does the least possible work.

* No ``yaml`` module. Not ``yaml.load``, not ``yaml.safe_load``, not as an optional
  import. A YAML parser is a large attack surface (aliases, billion-laughs expansion,
  tag resolution) and this tool only needs ``key: value``.
* No rendering, no reference following, no include directives, no execution. Ever.
* Anything outside the supported subset is preserved as a **raw string** and the block
  is marked non-strict. It is never evaluated and never guessed at.

Supported subset:

* a leading ``---`` fence, closed by ``---`` or ``...``;
* ``key: value`` scalars, with ``'``/``"`` quoting and ``# comment`` stripping;
* inline lists ``[a, b]`` and inline maps ``{a: b}`` (flat, best effort);
* block lists (``- item`` on following, more-indented lines);
* block scalars (``|``, ``>`` and their chomping variants), joined as plain text;
* one level of nested mapping; deeper nesting is kept as a raw string.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Tuple

__all__ = ["FrontMatter", "parse", "parse_bytes", "iter_string_values"]

_FENCE = "---"
_KEY_RE = re.compile(r"^(?P<indent>[ \t]*)(?P<key>[^\s:#][^:]*?)\s*:\s?(?P<value>.*)$")
_LIST_ITEM_RE = re.compile(r"^(?P<indent>[ \t]*)-\s+(?P<value>.*)$")


@dataclass
class FrontMatter:
    """Result of parsing a document that may carry a frontmatter block."""

    data: Dict[str, Any] = field(default_factory=dict)
    body: str = ""
    present: bool = False
    ok: bool = True
    error: Optional[str] = None
    raw: str = ""
    #: True when every line of the block fitted the supported subset.
    strict: bool = True
    #: Lines that did not fit the subset, kept verbatim, never interpreted.
    unparsed: List[str] = field(default_factory=list)
    #: Line number (1-based) where the frontmatter body starts, for finding locations.
    start_line: int = 0

    def get(self, key: str, default: Any = None) -> Any:
        """Case-insensitive, dash/underscore-insensitive lookup."""
        norm = _norm_key(key)
        for k, v in self.data.items():
            if _norm_key(k) == norm:
                return v
        return default

    def get_str(self, key: str, default: str = "") -> str:
        value = self.get(key)
        if value is None:
            return default
        if isinstance(value, list):
            return ", ".join(str(item) for item in value)
        if isinstance(value, dict):
            return " ".join("%s: %s" % (k, v) for k, v in value.items())
        return str(value)

    def get_list(self, key: str) -> List[str]:
        value = self.get(key)
        if value is None:
            return []
        if isinstance(value, list):
            return [str(item).strip() for item in value if str(item).strip()]
        text = str(value)
        if not text.strip():
            return []
        parts = re.split(r"[,\n]", text)
        return [p.strip().strip("'\"") for p in parts if p.strip()]


def _norm_key(key: str) -> str:
    return key.strip().lower().replace("_", "-")


def parse_bytes(data: bytes) -> FrontMatter:
    """Parse raw bytes. Decoding never raises; invalid sequences become U+FFFD."""
    return parse(data.decode("utf-8", errors="replace"))


def parse(text: str) -> FrontMatter:
    """Parse a document, returning frontmatter data plus the remaining body."""
    if text.startswith("\ufeff"):
        text = text[1:]
    normalized = text.replace("\r\n", "\n").replace("\r", "\n")
    lines = normalized.split("\n")

    idx = 0
    # Allow blank lines before the fence; anything else means "no frontmatter".
    while idx < len(lines) and lines[idx].strip() == "":
        idx += 1
    if idx >= len(lines) or lines[idx].strip() != _FENCE:
        return FrontMatter(data={}, body=normalized, present=False, ok=True, raw="")

    open_at = idx
    close_at = -1
    for j in range(open_at + 1, len(lines)):
        stripped = lines[j].strip()
        if stripped == _FENCE or stripped == "...":
            close_at = j
            break

    if close_at == -1:
        raw = "\n".join(lines[open_at + 1 :])
        return FrontMatter(
            data={},
            body=normalized,
            present=True,
            ok=False,
            error="unterminated frontmatter block (opening --- has no closing ---)",
            raw=raw,
            strict=False,
            start_line=open_at + 2,
        )

    block = lines[open_at + 1 : close_at]
    body = "\n".join(lines[close_at + 1 :])
    data, unparsed, strict = _parse_block(block)
    return FrontMatter(
        data=data,
        body=body,
        present=True,
        ok=True,
        error=None,
        raw="\n".join(block),
        strict=strict,
        unparsed=unparsed,
        start_line=open_at + 2,
    )


def _indent_width(text: str) -> int:
    width = 0
    for ch in text:
        if ch == " ":
            width += 1
        elif ch == "\t":
            width += 4
        else:
            break
    return width


def _parse_block(lines: List[str]) -> Tuple[Dict[str, Any], List[str], bool]:
    data: Dict[str, Any] = {}
    unparsed: List[str] = []
    strict = True
    i = 0
    n = len(lines)

    while i < n:
        line = lines[i]
        if not line.strip() or line.lstrip().startswith("#"):
            i += 1
            continue
        if _indent_width(line) > 0:
            # Orphan indented line (continuation of something we did not consume).
            unparsed.append(line)
            strict = False
            i += 1
            continue

        match = _KEY_RE.match(line)
        if not match:
            unparsed.append(line)
            strict = False
            i += 1
            continue

        key = match.group("key").strip()
        value = match.group("value")
        block_marker = value.strip()

        if block_marker in ("|", ">", "|-", ">-", "|+", ">+", "|2", ">2"):
            collected, i = _collect_indented(lines, i + 1)
            joiner = "\n" if block_marker.startswith("|") else " "
            data[key] = joiner.join(item.strip() for item in collected).strip()
            continue

        if block_marker == "":
            collected, next_i = _collect_indented(lines, i + 1)
            if collected and all(
                _LIST_ITEM_RE.match(item) for item in collected if item.strip()
            ):
                items: List[str] = []
                for item in collected:
                    m = _LIST_ITEM_RE.match(item)
                    if m:
                        items.append(_scalar(m.group("value")))
                data[key] = items
                i = next_i
                continue
            if collected and all(
                _KEY_RE.match(item) for item in collected if item.strip()
            ):
                nested: Dict[str, Any] = {}
                nested_ok = True
                for item in collected:
                    if not item.strip():
                        continue
                    m = _KEY_RE.match(item)
                    if not m:
                        nested_ok = False
                        break
                    nested_value = m.group("value")
                    if nested_value.strip() == "":
                        nested_ok = False
                        break
                    nested[m.group("key").strip()] = _scalar(nested_value)
                if nested_ok and nested:
                    data[key] = nested
                    i = next_i
                    continue
                # Deeper / unsupported structure: keep it as a raw string, never guess.
                data[key] = "\n".join(collected).strip()
                unparsed.extend(collected)
                strict = False
                i = next_i
                continue
            if collected:
                data[key] = "\n".join(collected).strip()
                unparsed.extend(collected)
                strict = False
                i = next_i
                continue
            data[key] = ""
            i = next_i
            continue

        data[key] = _scalar(value)
        i += 1

    return data, unparsed, strict


def _collect_indented(lines: List[str], start: int) -> Tuple[List[str], int]:
    collected: List[str] = []
    i = start
    while i < len(lines):
        line = lines[i]
        if line.strip() == "":
            collected.append("")
            i += 1
            continue
        if _indent_width(line) == 0:
            break
        collected.append(line)
        i += 1
    while collected and collected[-1] == "":
        collected.pop()
    return collected, i


def _strip_comment(value: str) -> str:
    out: List[str] = []
    quote: Optional[str] = None
    prev = ""
    for idx, ch in enumerate(value):
        if quote:
            out.append(ch)
            if ch == quote:
                quote = None
        elif ch in "'\"":
            quote = ch
            out.append(ch)
        elif ch == "#" and (idx == 0 or prev in " \t"):
            break
        else:
            out.append(ch)
        prev = ch
    return "".join(out)


def _scalar(value: str) -> Any:
    """Convert one scalar token. Strings stay strings; nothing is ever evaluated."""
    text = _strip_comment(value).strip()
    if not text:
        return ""
    if text.startswith("[") and text.endswith("]"):
        inner = text[1:-1].strip()
        if not inner:
            return []
        return [_unquote(part.strip()) for part in _split_commas(inner) if part.strip()]
    if text.startswith("{") and text.endswith("}"):
        inner = text[1:-1].strip()
        result: Dict[str, Any] = {}
        for part in _split_commas(inner):
            if ":" in part:
                k, _, v = part.partition(":")
                result[k.strip().strip("'\"")] = _unquote(v.strip())
            elif part.strip():
                result[part.strip().strip("'\"")] = ""
        return result
    return _unquote(text)


def _split_commas(text: str) -> List[str]:
    parts: List[str] = []
    depth = 0
    quote: Optional[str] = None
    current: List[str] = []
    for ch in text:
        if quote:
            current.append(ch)
            if ch == quote:
                quote = None
            continue
        if ch in "'\"":
            quote = ch
            current.append(ch)
        elif ch in "[{(":
            depth += 1
            current.append(ch)
        elif ch in "]})":
            depth = max(0, depth - 1)
            current.append(ch)
        elif ch == "," and depth == 0:
            parts.append("".join(current))
            current = []
        else:
            current.append(ch)
    parts.append("".join(current))
    return parts


def _unquote(text: str) -> str:
    text = text.strip()
    if len(text) >= 2 and text[0] == text[-1] and text[0] in "'\"":
        inner = text[1:-1]
        if text[0] == "'":
            return inner.replace("''", "'")
        # Only the handful of escapes that matter; no \x / \u expansion, because
        # expanding escapes here would let a document hide bytes from the rules.
        return (
            inner.replace('\\"', '"').replace("\\n", "\n").replace("\\t", "\t")
        )
    return text


def iter_string_values(
    data: Any, prefix: str = ""
) -> Iterable[Tuple[str, str]]:
    """Yield ``(key_path, string_value)`` for every scalar in a parsed structure."""
    if isinstance(data, dict):
        for key, value in data.items():
            path = "%s.%s" % (prefix, key) if prefix else str(key)
            for item in iter_string_values(value, path):
                yield item
    elif isinstance(data, list):
        for index, value in enumerate(data):
            path = "%s[%d]" % (prefix, index)
            for item in iter_string_values(value, path):
                yield item
    elif isinstance(data, str):
        yield (prefix, data)
    elif data is not None:
        yield (prefix, str(data))
