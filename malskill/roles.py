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

Residual risk, stated plainly: an attacker can put the payload in ``README.md`` and have
``SKILL.md`` say "follow the steps in README.md". The scanner does not follow that
reference hop — README.md, "no following the reference hop" — so the payload lands in the
suppressed bucket rather than in FLAGGED. ``--paranoid`` exists for the reader who wants
to close that gap by hand. See docs/RULES.md, "Roles and the reference hop".

This module imports nothing from the rest of the package, so it can never take part in an
import cycle and can be reasoned about on its own.
"""

from __future__ import annotations

import enum
import os
import re
import stat
from dataclasses import dataclass
from typing import Any, FrozenSet, List, Optional, Tuple

__all__ = [
    "FileRole",
    "ACTIONABLE_ROLES",
    "SuppressedHit",
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


def assign(target: Any) -> None:
    """Classify every loaded record of a target, storing the role on the record."""
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
