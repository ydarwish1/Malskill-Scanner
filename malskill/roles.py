"""File roles: *where* a pattern was found decides whether it is behaviour or prose.

The v1 scanner treated every byte in a bundle the same way. Measured against a real
machine that produced 47 findings of which nearly all were false: a README quoting the
official ``curl … | bash`` install line, a CHANGELOG entry, a `DESIGN.md` describing a
webpage's install button, a test file asserting that ``$(rm -rf /)`` is rejected as a
title, and — worst of all — the raw bytes of an MP3 supplying the "egress" half of a
CRITICAL exfiltration pairing.

The fix is a context model rather than more regex. Every file in a bundle is classified
into one of five roles:

``EXECUTABLE``
    Something that runs: shell/python/node/ruby/perl scripts, files carrying an execute
    bit, Makefiles/Dockerfiles, hook command strings, MCP ``command``/``args``.
``INSTRUCTION``
    Something an agent reads *as directives*: ``SKILL.md``, ``CLAUDE.md``/``AGENTS.md``,
    ``.claude/commands/**.md``, ``agents/**.md``, ``plugin.json`` / ``hooks.json`` /
    settings metadata, MCP tool and server descriptions.
``DOCS``
    Prose for humans: ``README*``, ``CHANGELOG*``, ``CONTRIBUTING*``, ``LICENSE``,
    ``DESIGN*``, and anything under ``docs/``, ``reference(s)/``, ``blueprints/``,
    ``examples/`` — markdown that is not INSTRUCTION.
``TEST``
    ``test/``, ``tests/``, ``__tests__/``, ``spec/``, ``*.test.*``, ``*_test.*``.
``DATA``
    Everything else, including every binary-sniffed file.

Behaviour rules (PIPE_TO_SHELL, DESTRUCTIVE_COMMAND, SELF_MODIFICATION,
AUTO_APPROVE_TAMPERING, OBFUSCATED_EXECUTION, NETWORK_IN_OFFLINE_CLAIM,
SENSITIVE_READ_PLUS_EGRESS, CREDENTIAL_PATH_ACCESS) fire at full severity **only** from
EXECUTABLE and INSTRUCTION. Both halves of a pairing rule must come from those roles, and
never from a binary file.

Hits in DOCS/TEST/DATA are **not** silently dropped — that would be the same lie as
printing "SAFE". They are collected as :class:`SuppressedHit` records, counted in a
report note, and listed individually as ``SUPPRESSED_PATTERN_HIT`` (LOW) findings under
``--paranoid``.

Explicit delegation closes the common reference-hop bypass without resolving anything on
the filesystem. One level of same-bundle markdown references from an original INSTRUCTION
record is looked up among the records already loaded for the target, then promoted to
INSTRUCTION. Bare links, TEST files, outside-bundle paths and unrecognised delegation prose
remain residual gaps. See docs/RULES.md, "Roles and the reference hop".

This module imports nothing from the rest of the package, so it can never take part in an
import cycle and can be reasoned about on its own.
"""

from __future__ import annotations

import enum
import os
import posixpath
import re
import stat
from dataclasses import dataclass
from typing import Any, Dict, FrozenSet, List, Optional, Tuple

__all__ = [
    "FileRole",
    "ACTIONABLE_ROLES",
    "SuppressedHit",
    "MAX_HOP_REFS_PER_FILE",
    "MAX_HOP_PROMOTIONS_PER_TARGET",
    "MAX_HOP_BYTES_PER_TARGET",
    "HOP_SUFFIXES",
    "classify",
    "assign",
    "role_of",
    "is_actionable",
]


class FileRole(str, enum.Enum):
    """Where a file sits in the chain between "an agent reads it" and "it runs"."""

    EXECUTABLE = "executable"
    INSTRUCTION = "instruction"
    DOCS = "docs"
    TEST = "test"
    DATA = "data"

    def __str__(self) -> str:
        return self.value


#: The two roles a behaviour rule may fire from at full severity.
ACTIONABLE_ROLES: FrozenSet[FileRole] = frozenset(
    {FileRole.EXECUTABLE, FileRole.INSTRUCTION}
)

#: Human wording for the report note.
ROLE_LABELS = {
    FileRole.DOCS: "documentation",
    FileRole.TEST: "test",
    FileRole.DATA: "data/binary",
    FileRole.EXECUTABLE: "executable",
    FileRole.INSTRUCTION: "instruction",
}


# ---------------------------------------------------------------------------------------
# Tables
# ---------------------------------------------------------------------------------------

#: Suffixes that make a file code. Kept in sync with patterns._SCRIPT_SUFFIXES.
SCRIPT_SUFFIXES: FrozenSet[str] = frozenset(
    {
        ".sh", ".bash", ".zsh", ".ksh", ".fish", ".command",
        ".py", ".pyw", ".js", ".mjs", ".cjs", ".jsx", ".ts", ".mts", ".cts", ".tsx",
        ".rb", ".pl", ".pm", ".php", ".ps1", ".psm1", ".bat", ".cmd",
        ".lua", ".tcl", ".applescript", ".scpt", ".mk", ".make",
    }
)

#: Files with no suffix (or an unusual one) that are still build/run scripts.
SCRIPT_BASENAMES: FrozenSet[str] = frozenset(
    {"makefile", "gnumakefile", "dockerfile", "justfile", "rakefile", "brewfile", "procfile"}
)

#: Prose containers.
PROSE_SUFFIXES: FrozenSet[str] = frozenset(
    {".md", ".markdown", ".mdx", ".txt", ".rst", ".adoc", ".asciidoc", ".org"}
)

#: Markdown filenames the agent loads as directives rather than as documentation.
INSTRUCTION_BASENAMES: FrozenSet[str] = frozenset(
    {
        "skill.md",
        "agent.md",
        "claude.md",
        "agents.md",
        "command.md",
    }
)

#: Structured metadata that configures what the agent will do.
INSTRUCTION_CONFIG_BASENAMES: FrozenSet[str] = frozenset(
    {
        "plugin.json",
        "hooks.json",
        "settings.json",
        "settings.local.json",
        ".mcp.json",
        "mcp.json",
        "marketplace.json",
        "claude_desktop_config.json",
        "installed_plugins.json",
    }
)

#: Directory names whose *.md contents are directives (``commands/x.md``, ``agents/y.md``).
INSTRUCTION_DIR_SEGMENTS: FrozenSet[str] = frozenset({"commands", "agents", "hooks"})

#: Directory names that make their contents documentation.
DOCS_DIR_SEGMENTS: FrozenSet[str] = frozenset(
    {
        "doc", "docs", "documentation",
        "reference", "references",
        "blueprint", "blueprints",
        "example", "examples", "sample", "samples",
        "guide", "guides", "tutorial", "tutorials",
        "wiki", "man", "manual", "adr", "rfc", "rfcs",
        "changelog", "changelogs", "news",
    }
)

#: Directory names that make their contents test material.
TEST_DIR_SEGMENTS: FrozenSet[str] = frozenset(
    {
        "test", "tests", "__tests__", "testing",
        "spec", "specs", "__specs__",
        "testdata", "test_data", "test-data",
        "fixture", "fixtures", "__fixtures__",
        "__mocks__", "mocks", "e2e", "integration-tests", "integration_tests",
        "benchmarks", "bench",
    }
)

#: Filename stems (before the first ``.``) that mean "documentation for a human".
DOCS_STEMS: FrozenSet[str] = frozenset(
    {
        "readme", "read_me", "readme_first",
        "changelog", "change_log", "changes", "history", "news", "releases",
        "release_notes", "releasenotes",
        "contributing", "contribution", "contributors", "authors", "credits",
        "license", "licence", "copying", "notice", "patents",
        "code_of_conduct", "conduct", "governance", "support", "security_policy",
        "design", "architecture", "roadmap", "todo", "faq", "glossary",
        "overview", "usage", "install", "installation", "setup", "getting_started",
        "migration", "upgrading", "troubleshooting", "notes", "warp", "gemini",
        "copilot-instructions", "cursorrules", "windsurfrules", "browser",
    }
)

#: Filename patterns that mean "this is a test file".
_TEST_FILE_RE = re.compile(
    r"(?:^|[._-])(?:test|tests|spec|specs)\.[A-Za-z0-9]+$|"
    r"^test_[\w.-]+\.(?:py|rb|pl|sh)$|"
    r"^conftest\.py$|"
    r"^[\w.-]+_(?:test|spec)\.[A-Za-z0-9]+$",
    re.I,
)

_EXEC_BITS = stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH

#: References followed per instruction file. Beyond this, the rest are recorded, not followed.
MAX_HOP_REFS_PER_FILE = 5
#: Records promoted per target, across all instruction files.
MAX_HOP_PROMOTIONS_PER_TARGET = 20
#: Total bytes of promoted content per target.
MAX_HOP_BYTES_PER_TARGET = 256 * 1024
#: Extensions a reference may point at. Markdown only — an instruction file delegating to a
#: script is already covered by the executable rules.
HOP_SUFFIXES = (".md", ".markdown")

#: The false-positive gate: a path is followed only when its line delegates authority.
#: Pointer-only prose such as "see the guide", ``consult`` or bare ``read`` is
#: deliberately excluded. Directly negated ``not execute`` is a disclaimer, not a cue.
_DELEGATION_RE = re.compile(
    r"(?:"
    r"\b(?:follow|following|perform|apply)\b|(?<!not )\bexecute\b|"
    r"\b(?:steps|instructions)\s+in\b|\bbefore\s+starting\b|\bbegin\s+by\b|"
    r"\bstart\s+by\b|\bfirst\s+run\b|\brun\s+the\b|\bcarry\s+out\b|"
    r"\bas\s+described\s+in\b|\bas\s+specified\s+in\b|"
    r"\bread\s+and\s+follow\b"
    r")",
    re.I,
)
_MARKDOWN_INLINE_RE = re.compile(r"\]\(([^)]+)\)")
_MARKDOWN_DEFINITION_RE = re.compile(r"^\s*\[([^\]]+)\]:\s*(\S.*)$")
_MARKDOWN_REFERENCE_RE = re.compile(r"\[([^\]]+)\]\[([^\]]+)\]")
_MARKDOWN_SHORTCUT_RE = re.compile(r"(?<!!)(?<!\])\[([^\]]+)\](?!\[)(?!\()")
_BACKTICK_PATH_RE = re.compile(r"(?<!`)`([^`]+)`(?!`)")
_AT_IMPORT_RE = re.compile(
    r"(?<![A-Za-z0-9])@([^\s<>`\[\]()]+\.(?:md|markdown))\b",
    re.I,
)
_BARE_TOKEN_RE = re.compile(r"\S+")
_URI_SCHEME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*:")
_BARE_TRAILING_PUNCTUATION = ".,;:)]\"'"
_WINDOWS_DRIVE_RE = re.compile(r"^[A-Za-z]:")
_C0_CONTROL_RE = re.compile(r"[\x00-\x1f]")


# ---------------------------------------------------------------------------------------
# Suppressed hits
# ---------------------------------------------------------------------------------------


@dataclass
class SuppressedHit:
    """A rule pattern that matched, in a place the rule is not allowed to fire from.

    Recorded rather than discarded: README principle 6 says a scanner that silently
    drops what it saw is worse than no scanner. These are aggregated into a report note
    and listed individually under ``--paranoid``.
    """

    rule_id: str
    role: str
    target: str
    kind: str
    file: str
    line: Optional[int]
    label: str
    evidence: str

    @property
    def role_label(self) -> str:
        try:
            return ROLE_LABELS[FileRole(self.role)]
        except (ValueError, KeyError):  # pragma: no cover - defensive
            return self.role

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "role": self.role,
            "target": self.target,
            "kind": self.kind,
            "file": self.file,
            "line": self.line,
            "label": self.label,
            "evidence": self.evidence,
        }


# ---------------------------------------------------------------------------------------
# Classification
# ---------------------------------------------------------------------------------------


def _segments(rel: str) -> Tuple[List[str], str]:
    normalized = (rel or "").replace("\\", "/").strip("/")
    parts = [p for p in normalized.split("/") if p not in ("", ".")]
    base = parts[-1].lower() if parts else ""
    return [p.lower() for p in parts[:-1]], base


def _stem(base: str) -> str:
    return base.split(".", 1)[0].lower()


def _suffix(base: str) -> str:
    _, dot, ext = base.rpartition(".")
    return ("." + ext.lower()) if dot else ""


def classify(
    rel: str,
    *,
    is_binary: bool = False,
    synthetic: bool = False,
    mode: int = 0,
    target_kind: str = "",
    single_file_target: bool = False,
) -> FileRole:
    """Decide the role of one file. Pure function of its path and a few flags.

    Order matters and is deliberate:

    1. binary content is DATA no matter what it is called — a ``.py`` full of NULs is a
       compiled artifact, and it must never supply evidence for a pairing rule;
    2. synthetic records (hook command strings, MCP server fragments) are EXECUTABLE:
       they *are* the command line;
    3. a command/agent target, or a single-file skill target, is the instruction itself;
    4. test material outranks everything below it, so a script under ``tests/`` is TEST;
    5. instruction surfaces, then executables, then documentation, then data.
    """
    if is_binary:
        return FileRole.DATA
    if synthetic:
        return FileRole.EXECUTABLE

    dirs, base = _segments(rel)
    if not base:
        return FileRole.DATA

    kind = (target_kind or "").lower()
    if kind in ("command", "agent"):
        return FileRole.INSTRUCTION
    if single_file_target and kind in ("skill", "plugin") and _suffix(base) in PROSE_SUFFIXES:
        return FileRole.INSTRUCTION

    dirset = set(dirs)
    suffix = _suffix(base)
    stem = _stem(base)

    # 4. tests -------------------------------------------------------------------------
    if dirset & TEST_DIR_SEGMENTS:
        return FileRole.TEST
    if _TEST_FILE_RE.search(base):
        return FileRole.TEST

    # 5a. instruction surfaces -----------------------------------------------------------
    if base in INSTRUCTION_BASENAMES or base in INSTRUCTION_CONFIG_BASENAMES:
        return FileRole.INSTRUCTION
    if suffix in (".md", ".markdown") and _instruction_dir(dirs):
        return FileRole.INSTRUCTION
    if base.endswith(".mcp.json"):
        return FileRole.INSTRUCTION

    # 5b. executables --------------------------------------------------------------------
    if suffix in SCRIPT_SUFFIXES:
        return FileRole.EXECUTABLE
    if base in SCRIPT_BASENAMES or stem == "dockerfile":
        return FileRole.EXECUTABLE
    if mode and (mode & _EXEC_BITS) and stat.S_ISREG(mode) and suffix not in PROSE_SUFFIXES:
        return FileRole.EXECUTABLE

    # 5c. documentation --------------------------------------------------------------------
    if dirset & DOCS_DIR_SEGMENTS:
        return FileRole.DOCS
    if suffix in PROSE_SUFFIXES:
        return FileRole.DOCS
    if not suffix and stem in DOCS_STEMS:
        return FileRole.DOCS

    return FileRole.DATA


def _instruction_dir(dirs: List[str]) -> bool:
    """True when a markdown file sits in a directory the agent loads directives from.

    ``commands/x.md`` and ``agents/y.md`` count wherever they appear in a bundle, because
    that is exactly the layout plugins use. ``docs/commands.md`` does not: the segment
    has to be a directory, not a filename.
    """
    for index, part in enumerate(dirs):
        if part not in INSTRUCTION_DIR_SEGMENTS:
            continue
        # ``docs/commands/x.md`` is documentation about commands, not a command.
        earlier = set(dirs[:index])
        if earlier & DOCS_DIR_SEGMENTS or earlier & TEST_DIR_SEGMENTS:
            return False
        return True
    return False


def _reference_label(raw: str) -> str:
    """Normalise a Markdown reference label for same-document lookup."""
    return " ".join(raw.split()).casefold()


def _bare_hop_token(raw: str) -> Optional[str]:
    """Return a bare relative markdown path token, without sentence punctuation."""
    candidate = raw.rstrip(_BARE_TRAILING_PUNCTUATION)
    if (
        not candidate
        or candidate.startswith("@")
        or _URI_SCHEME_RE.match(candidate)
        or any(character in candidate for character in "`<>[](")
        or posixpath.splitext(candidate)[1].lower() not in HOP_SUFFIXES
    ):
        return None
    return candidate


def _hop_candidates(text: str) -> List[Tuple[str, str]]:
    """Return reference candidates in document order as ``(path, provenance)`` pairs."""
    lines = text.splitlines()
    definitions: Dict[str, str] = {}
    definition_lines = set()
    for index, line in enumerate(lines):
        definition = _MARKDOWN_DEFINITION_RE.search(line)
        if definition is None:
            continue
        definitions[_reference_label(definition.group(1))] = definition.group(2)
        definition_lines.add(index)

    candidates: List[Tuple[str, str]] = []
    for index, line in enumerate(lines):
        line_candidates: List[Tuple[int, str, str]] = []
        for match in _AT_IMPORT_RE.finditer(line):
            line_candidates.append((match.start(), match.group(1), "@import"))

        if _DELEGATION_RE.search(line) and index not in definition_lines:
            for match in _MARKDOWN_INLINE_RE.finditer(line):
                line_candidates.append((match.start(), match.group(1), "delegation"))
            reference_spans = []
            for match in _MARKDOWN_REFERENCE_RE.finditer(line):
                reference_spans.append(match.span())
                label = _reference_label(match.group(2) or match.group(1))
                target = definitions.get(label)
                if target is not None:
                    line_candidates.append((match.start(), target, "delegation"))
            for match in _MARKDOWN_SHORTCUT_RE.finditer(line):
                if any(
                    start <= match.start() and match.end() <= end
                    for start, end in reference_spans
                ):
                    continue
                target = definitions.get(_reference_label(match.group(1)))
                if target is not None:
                    line_candidates.append((match.start(), target, "delegation"))
            for match in _BACKTICK_PATH_RE.finditer(line):
                line_candidates.append((match.start(), match.group(1), "delegation"))
            for match in _BARE_TOKEN_RE.finditer(line):
                bare = _bare_hop_token(match.group(0))
                if bare is not None:
                    line_candidates.append((match.start(), bare, "delegation"))

        line_candidates.sort(key=lambda item: item[0])
        candidates.extend((path, via) for _, path, via in line_candidates)
    return candidates


def _normalize_hop_reference(raw: str) -> Optional[str]:
    """Validate and normalise one candidate without touching the filesystem."""
    if not raw or len(raw) > 200 or _C0_CONTROL_RE.search(raw):
        return None

    candidate = raw.strip()
    if candidate.startswith("<") and candidate.endswith(">"):
        candidate = candidate[1:-1].strip()
    if not candidate or len(candidate) > 200:
        return None

    lower = candidate.lower()
    if (
        "://" in candidate
        or lower.startswith(("mailto:", "data:", "javascript:"))
        or candidate.startswith("#")
        or candidate.startswith(("/", "~", "\\"))
        or _WINDOWS_DRIVE_RE.match(candidate)
    ):
        return None

    anchor = candidate.find("#")
    query = candidate.find("?")
    cut_positions = [position for position in (anchor, query) if position >= 0]
    if cut_positions:
        candidate = candidate[: min(cut_positions)].strip()
    if not candidate:
        return None
    if ".." in candidate.split("/"):
        return None
    normalized = posixpath.normpath(candidate)
    if normalized.startswith("..") or ".." in normalized.split("/"):
        return None
    if posixpath.splitext(normalized)[1].lower() not in HOP_SUFFIXES:
        return None
    return normalized


def _promote_reference_hops(target: Any) -> None:
    """Promote one bounded level of delegated markdown already loaded in *target*."""
    records = list(getattr(target, "files", []) or [])
    meta = getattr(target, "meta", None)
    if not isinstance(meta, dict):
        meta = {}
        target.meta = meta
    meta["reference_hops"] = []
    meta.pop("reference_hops_capped", None)

    # Snapshot before promotion: a referenced document must not become a second referrer.
    referring_records = [record for record in records if role_of(record) == FileRole.INSTRUCTION]
    by_rel: Dict[str, Optional[Any]] = {}
    for record in records:
        # os.path.relpath uses native separators; hop references are normalised as POSIX.
        rel = (getattr(record, "rel", "") or "").replace("\\", "/")
        if not rel:
            continue
        if rel in by_rel:
            # Exact duplicate rel paths are ambiguous, so resolve neither one.
            by_rel[rel] = None
        else:
            by_rel[rel] = record

    references_seen = 0
    references_followed = 0
    promotions = 0
    promoted_bytes = 0
    promoted_ids = set()
    per_file_caps: List[str] = []
    promotion_cap_hit = False
    byte_cap_hit = False

    for referring in referring_records:
        if (
            getattr(referring, "is_binary", False)
            or getattr(referring, "synthetic", False)
            or not getattr(referring, "has_content", False)
        ):
            continue

        candidates = _hop_candidates(getattr(referring, "text", "") or "")
        file_seen = len(candidates)
        references_seen += file_seen
        file_followed = 0
        file_capped = False
        referring_rel = getattr(referring, "rel", "") or ""
        # Keep lookup relative paths POSIX-shaped even when records came from Windows.
        referring_lookup_rel = referring_rel.replace("\\", "/")
        referring_dir = posixpath.dirname(referring_lookup_rel)

        for raw, via in candidates:
            candidate = _normalize_hop_reference(raw)
            if candidate is None:
                continue
            if file_followed >= MAX_HOP_REFS_PER_FILE:
                file_capped = True
                continue

            file_followed += 1
            references_followed += 1
            resolved = posixpath.normpath(posixpath.join(referring_dir, candidate))
            if resolved.startswith("..") or ".." in resolved.split("/"):
                continue

            matched = by_rel.get(resolved)
            if matched is None or matched is referring:
                continue
            matched_id = id(matched)
            if matched_id in promoted_ids:
                continue
            if role_of(matched) not in (FileRole.DOCS, FileRole.DATA):
                continue
            if getattr(matched, "is_binary", False) or not getattr(
                matched, "has_content", False
            ):
                continue

            content_bytes = len(getattr(matched, "data", b"") or b"")
            if promotions >= MAX_HOP_PROMOTIONS_PER_TARGET:
                promotion_cap_hit = True
                continue
            if promoted_bytes + content_bytes > MAX_HOP_BYTES_PER_TARGET:
                byte_cap_hit = True
                continue

            matched.role = FileRole.INSTRUCTION
            promoted_ids.add(matched_id)
            promotions += 1
            promoted_bytes += content_bytes
            meta["reference_hops"].append(
                {"from": referring_rel, "to": resolved, "via": via}
            )

        if file_capped:
            per_file_caps.append(
                "%s (%d seen, %d followed)"
                % (referring_rel, file_seen, file_followed)
            )

    cap_messages: List[str] = []
    if per_file_caps:
        cap_messages.append(
            "per-file reference cap %d hit: %s"
            % (MAX_HOP_REFS_PER_FILE, ", ".join(per_file_caps))
        )
    if promotion_cap_hit:
        cap_messages.append(
            "target promotion cap %d hit"
            % MAX_HOP_PROMOTIONS_PER_TARGET
        )
    if byte_cap_hit:
        cap_messages.append(
            "target promoted-byte cap %d hit"
            % MAX_HOP_BYTES_PER_TARGET
        )
    if cap_messages:
        cap_messages.append(
            "%d references seen, %d followed, %d records promoted (%d bytes)"
            % (references_seen, references_followed, promotions, promoted_bytes)
        )
        meta["reference_hops_capped"] = "; ".join(cap_messages)


def assign(target: Any) -> None:
    """Classify every loaded record of a target, then promote one reference hop."""
    kind = getattr(getattr(target, "kind", ""), "value", str(getattr(target, "kind", "")))
    path = getattr(target, "path", "") or ""
    try:
        single_file = bool(path) and os.path.isfile(path)
    except OSError:  # pragma: no cover - defensive
        single_file = False
    for record in getattr(target, "files", []) or []:
        record.role = classify(
            getattr(record, "rel", "") or "",
            is_binary=bool(getattr(record, "is_binary", False)),
            synthetic=bool(getattr(record, "synthetic", False)),
            mode=int(getattr(record, "mode", 0) or 0),
            target_kind=kind,
            single_file_target=single_file,
        )
    _promote_reference_hops(target)


def role_of(record: Any) -> FileRole:
    """Role of a record, defaulting to DATA when it was never classified."""
    role = getattr(record, "role", None)
    if isinstance(role, FileRole):
        return role
    if isinstance(role, str) and role:
        try:
            return FileRole(role)
        except ValueError:  # pragma: no cover - defensive
            return FileRole.DATA
    return FileRole.DATA


def is_actionable(record: Any) -> bool:
    """True when a behaviour rule may fire at full severity from this record."""
    if record is None:
        return False
    if getattr(record, "is_binary", False):
        return False
    return role_of(record) in ACTIONABLE_ROLES
