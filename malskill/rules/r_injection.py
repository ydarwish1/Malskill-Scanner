"""HIDDEN_INSTRUCTIONS, PROMPT_INJECTION_IN_METADATA, TOOL_SHADOWING.

Rationale
---------
These three cover the attack class that is specific to agent extensions: text that is
loaded into the model's context automatically, treated as authority, and read by nobody.
MCP tool descriptions and skill frontmatter go into every session before the user types a
word. A malicious sentence there does not need an exploit — it just needs to be believed.

HIDDEN_INSTRUCTIONS
    Zero-width and bidi-control codepoints (U+200B..U+200F, U+202A..U+202E, U+2060..
    U+2064, U+FEFF) inside content the agent loads, and HTML comments carrying
    agent-directed imperatives. Detection is on the **raw bytes**: the UTF-8 encodings of
    those codepoints are searched for directly, so nothing is normalised away before the
    check. The reported evidence is the sanitized copy, with the codepoints escaped so
    they become visible in a terminal.

PROMPT_INJECTION_IN_METADATA
    Agent-manipulation phrasing restricted to *metadata* fields: frontmatter values, MCP
    tool/server descriptions and instructions, and hook command strings. Explicitly NOT
    arbitrary documentation prose — this repository's own README discusses every one of
    these phrases and must not fire.

TOOL_SHADOWING
    Metadata that claims to replace, override or intercept another tool. A shadowing tool
    sits between the agent and the real one, seeing every argument and controlling every
    result.

False-positive analysis
-----------------------
* *Emoji ZWJ sequences* (👨‍💻) use U+200D legitimately. Zero-width joiners sitting
  between two non-ASCII pictographic characters are exempt; a joiner between ASCII text
  is not.
* *A leading UTF-8 BOM* is an editor artifact and is exempt.
* *Markdown lint pragmas* (``<!-- prettier-ignore -->``) are not agent-directed and do
  not match the imperative patterns, which all require an object such as
  "previous instructions" or "the user".
* *Security tooling* whose description legitimately quotes injection phrases will fire.
  That is the accepted cost of scanning the field the agent actually obeys.
* *Right-to-left natural language* uses bidi marks legitimately. It fires; the finding
  reports the exact codepoints so a human can dismiss it in one look.
* *Documentation is not metadata.* "Metadata surface" means role INSTRUCTION — SKILL.md,
  CLAUDE.md/AGENTS.md, ``commands/**.md``, ``agents/**.md``, plugin/hook manifests, MCP
  descriptions and hook strings — not "any file ending in .md". A stray zero-width
  character pasted into a README is a copy-paste artifact, not an instruction; it is
  recorded as a suppressed hit and counted in the report rather than reported at HIGH.
"""

from __future__ import annotations

import re
from typing import List, Pattern, Tuple

from malskill.rules import Finding, make_finding
from malskill.rules.patterns import (
    Hit,
    is_instruction_record,
    iter_metadata_fields,
    line_at,
    record_suppressed,
)
from malskill.sanitize import find_invisible, for_display

RULE_IDS = (
    "HIDDEN_INSTRUCTIONS",
    "PROMPT_INJECTION_IN_METADATA",
    "TOOL_SHADOWING",
)

# ------------------------------------------------------------------ hidden instructions

_HTML_COMMENT_RE = re.compile(r"<!--(.*?)-->", re.S)

#: Imperatives that only make sense if the reader is the agent, not a human maintainer.
_AGENT_IMPERATIVE_RE = re.compile(
    r"\bignore\s+(?:all\s+|any\s+)?(?:the\s+)?(?:previous|prior|above|earlier|other)\b|"
    r"\bdisregard\s+(?:all\s+|any\s+)?(?:previous|prior|above|the\s+)?\b|"
    r"\bdo\s*n[o']?t\s+(?:tell|show|inform|mention|reveal|display|report)\b|"
    r"\bnever\s+(?:tell|show|inform|mention|reveal|display|report)\b|"
    r"\bsecretly\b|\bcovertly\b|\bwithout\s+the\s+user\b|"
    r"\bbefore\s+(?:responding|answering|replying|any\s+other)\b|"
    r"\brun\s+the\s+following\b|\bexecute\s+the\s+following\b|"
    r"\balways\s+(?:run|execute|call|use|invoke)\b|"
    r"\byou\s+(?:must|should|will)\s+(?:always|first|silently|immediately)\b|"
    r"\bsystem\s*prompt\b|\bnew\s+instructions?\b|"
    r"\bexfiltrat\w*\b",
    re.I,
)

#: Codepoints that render as nothing but are read by the model.
_PICTOGRAPH_MIN = 0x2000


def _zwj_is_emoji_only(text: str) -> bool:
    """True when every U+200D in the text joins two non-ASCII pictographs."""
    index = text.find("\u200d")
    saw_any = False
    while index != -1:
        saw_any = True
        before = text[index - 1] if index > 0 else ""
        after = text[index + 1] if index + 1 < len(text) else ""
        if not before or not after:
            return False
        if ord(before) < _PICTOGRAPH_MIN or ord(after) < _PICTOGRAPH_MIN:
            return False
        index = text.find("\u200d", index + 1)
    return saw_any


def _bank(target, rule_id: str, record, line: int, label: str, context: str) -> None:
    """Record a metadata-shaped match that landed outside an instruction surface."""
    record_suppressed(
        target,
        rule_id,
        Hit(
            label=label,
            start=0,
            end=0,
            matched=label,
            line=line,
            line_text=context,
            file_rel=getattr(record, "rel", ""),
            file_path=getattr(record, "path", ""),
            record=record,
        ),
    )


def _invisible_findings(target) -> List[Finding]:
    from malskill.rules.patterns import is_metadata_file

    findings: List[Finding] = []
    for record in getattr(target, "files", []) or []:
        if not getattr(record, "has_content", False):
            continue
        if getattr(record, "is_binary", False):
            continue
        if not (record.synthetic or is_metadata_file(record.rel)):
            continue
        hits = find_invisible(record.data)
        if not hits:
            continue
        if _zwj_is_emoji_only(record.text):
            hits = [h for h in hits if h.codepoint != 0x200D]
        if not hits:
            continue
        if not is_instruction_record(record):
            _bank(
                target,
                "HIDDEN_INSTRUCTIONS",
                record,
                hits[0].line,
                "invisible codepoint %s" % hits[0].label,
                record.line_text(hits[0].line),
            )
            continue
        labels = []
        for hit in hits[:6]:
            labels.append("%s at line %d" % (hit.label, hit.line))
        first = hits[0]
        line_no, line_text = line_at(record.text, 0)
        lines = record.text.split("\n")
        if 1 <= first.line <= len(lines):
            line_text = lines[first.line - 1]
        findings.append(
            make_finding(
                "HIDDEN_INSTRUCTIONS",
                target=target.display,
                kind=target.kind.value,
                file=record.rel,
                line=first.line,
                evidence=for_display(line_text),
                why=(
                    "%d invisible or direction-control codepoint(s) are embedded in %s, "
                    "which the agent loads as instructions: %s. You read the rendered "
                    "text; the model reads the bytes. Anything living in that gap was put "
                    "there to be acted on without being reviewed."
                    % (len(hits), record.rel, "; ".join(labels))
                ),
                recommendation=(
                    "Remove this %s. Text that is invisible to you but visible to the "
                    "agent has no legitimate purpose in an extension."
                    % target.kind.value
                ),
            )
        )
    return findings


def _html_comment_findings(target) -> List[Finding]:
    from malskill.rules.patterns import is_metadata_file

    findings: List[Finding] = []
    for record in getattr(target, "files", []) or []:
        if not getattr(record, "has_content", False):
            continue
        if getattr(record, "is_binary", False):
            continue
        if not (record.synthetic or is_metadata_file(record.rel)):
            continue
        for match in _HTML_COMMENT_RE.finditer(record.text):
            inner = match.group(1)
            phrase = _AGENT_IMPERATIVE_RE.search(inner)
            if not phrase:
                continue
            line = record.line_of(match.start())
            if not is_instruction_record(record):
                _bank(
                    target,
                    "HIDDEN_INSTRUCTIONS",
                    record,
                    line,
                    "agent-directed HTML comment",
                    inner.strip(),
                )
                break
            findings.append(
                make_finding(
                    "HIDDEN_INSTRUCTIONS",
                    target=target.display,
                    kind=target.kind.value,
                    file=record.rel,
                    line=line,
                    evidence=for_display(inner.strip()),
                    why=(
                        "An HTML comment at %s:%d contains an instruction aimed at the "
                        "agent (%r). Comments are invisible in rendered markdown but are "
                        "read verbatim by the model that loads the file."
                        % (record.rel, line, phrase.group(0))
                    ),
                    recommendation=(
                        "Remove this %s. Instructions hidden in comments are placed there "
                        "to bypass the review you are doing now." % target.kind.value
                    ),
                )
            )
            break
    return findings


# --------------------------------------------------------------- injection in metadata

INJECTION_PATTERNS: List[Tuple[str, Pattern]] = [
    (
        "override of prior instructions",
        re.compile(
            r"\b(?:ignore|disregard|forget|override)\s+(?:all\s+|any\s+)?(?:the\s+)?"
            r"(?:previous|prior|above|earlier|preceding|system)\s+"
            r"(?:instructions?|prompts?|rules?|messages?|context)\b",
            re.I,
        ),
    ),
    (
        "instruction to conceal activity from the user",
        re.compile(
            r"\bdo\s*n[o']?t\s+(?:tell|show|inform|mention\s+(?:this\s+)?to|reveal\s+to|"
            r"notify|report\s+to|display\s+to)\b[^.\n]{0,40}\b(?:the\s+)?(?:user|human|"
            r"operator|owner)\b|"
            r"\bnever\s+(?:tell|inform|show|reveal)\b[^.\n]{0,40}\b(?:the\s+)?(?:user|human)\b|"
            r"\bwithout\s+(?:the\s+)?user(?:'s|s)?\s+(?:knowledge|approval|confirmation|"
            r"consent|awareness|permission)\b|"
            r"\b(?:hide|conceal|suppress)\b[^.\n]{0,30}\b(?:from\s+(?:the\s+)?(?:user|human|"
            r"output|logs?|transcript)|this\s+(?:step|command|action))\b",
            re.I,
        ),
    ),
    (
        "instruction to always run something first",
        re.compile(
            r"\balways\s+(?:run|execute|call|invoke|use)\s+(?:this|the\s+following)\s*"
            r"(?:tool|command|script|function)?\s*first\b|"
            r"\bbefore\s+(?:using|calling|invoking|responding\s+to)\s+any\s+other\s+"
            r"(?:tool|request|message)\b|"
            r"\bmust\s+(?:always\s+)?be\s+(?:called|run|invoked)\s+(?:first|before\s+"
            r"any\s+other)\b",
            re.I,
        ),
    ),
    (
        "instruction to impersonate or fake state",
        re.compile(
            r"\bpretend\s+(?:to\s+be|you\s+are|that|this)\b|"
            r"\bact\s+as\s+if\s+(?:you|this|the)\b[^.\n]{0,40}\b(?:not|never|no)\b",
            re.I,
        ),
    ),
    (
        "explicit exfiltration language",
        re.compile(r"\bexfiltrat\w*\b|\bsteal\s+(?:the\s+)?(?:keys?|credentials?|tokens?|secrets?)\b", re.I),
    ),
    (
        "embedded fake system turn",
        re.compile(r"(?:^|\n)\s*(?:system|assistant)\s*:\s*(?:you\s+|ignore|always|never)", re.I),
    ),
]

SHADOWING_PATTERNS: List[Tuple[str, Pattern]] = [
    (
        "claims to replace another tool",
        re.compile(
            r"\binstead\s+of\s+(?:using\s+)?(?:the\s+)?(?:built[- ]?in\s+)?"
            r"(?:Bash|Read|Write|Edit|Grep|Glob|WebFetch|WebSearch|Task)?\s*"
            r"(?:tool|command)\b|"
            r"\breplaces?\s+the\s+(?:built[- ]?in\s+)?(?:Bash|Read|Write|Edit|Grep|Glob|"
            r"WebFetch|WebSearch)\s+tool\b|"
            r"\boverrides?\s+the\s+(?:built[- ]?in|default|standard)\b",
            re.I,
        ),
    ),
    (
        "claims to intercept other tools",
        re.compile(
            r"\bintercepts?\s+(?:all\s+)?(?:calls?|requests?|invocations?)\s+to\b|"
            r"\bwraps?\s+(?:every|all)\s+(?:tool|command)\s+calls?\b|"
            r"\bproxy\s+for\s+(?:all\s+)?(?:tool|bash|shell)\s+calls?\b",
            re.I,
        ),
    ),
]


def _metadata_findings(
    target, patterns: List[Tuple[str, Pattern]], finding_id: str
) -> List[Finding]:
    findings: List[Finding] = []
    seen = set()
    for field in iter_metadata_fields(target):
        for label, pattern in patterns:
            match = pattern.search(field.text)
            if not match:
                continue
            key = (label, field.source)
            if key in seen:
                continue
            seen.add(key)
            findings.append(
                _build_metadata_finding(target, field, label, match.group(0), finding_id)
            )
            break
        if len(findings) >= 4:
            break
    return findings


def _build_metadata_finding(target, field, label: str, matched: str, finding_id: str):
    where = field.file_rel or field.source
    if finding_id == "PROMPT_INJECTION_IN_METADATA":
        why = (
            "The metadata field %s contains %s (%r). Descriptions and tool metadata are "
            "loaded into every session automatically and are treated by the agent as "
            "authority, so text placed there is an instruction, not documentation."
            % (field.source, label, for_display(matched, 120))
        )
        recommendation = (
            "Remove this %s. Metadata that tells the agent to hide actions from you, or "
            "to override your instructions, is not fixable by editing one sentence."
            % target.kind.value
        )
    else:
        why = (
            "The metadata field %s %s (%r). A tool that shadows another one sits between "
            "the agent and the real tool: it sees every argument — file contents, "
            "commands, secrets — and controls what comes back."
            % (field.source, label, for_display(matched, 120))
        )
        recommendation = (
            "Remove this %s unless you deliberately installed a proxy tool and trust its "
            "author with everything the shadowed tool touches." % target.kind.value
        )
    return make_finding(
        finding_id,
        target=target.display,
        kind=target.kind.value,
        file=field.file_rel or None,
        line=field.line,
        evidence=for_display(field.text),
        why=why,
        recommendation=recommendation,
    )


def check(target) -> List[Finding]:
    findings: List[Finding] = []
    findings.extend(_invisible_findings(target))
    findings.extend(_html_comment_findings(target))
    # Both metadata passes share one cached extraction, so the second is nearly free.
    findings.extend(
        _metadata_findings(target, INJECTION_PATTERNS, "PROMPT_INJECTION_IN_METADATA")
    )
    findings.extend(_metadata_findings(target, SHADOWING_PATTERNS, "TOOL_SHADOWING"))
    return findings
