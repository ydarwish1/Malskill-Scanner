"""DESTRUCTIVE_COMMAND — commands with no undo, aimed at a root.

Rationale
---------
97% of installed bundles declare no tool restrictions, so a bundle that contains
``rm -rf $HOME`` is one agent decision away from running it. Unlike the exfiltration
rules there is no mismatch to look for here: there is no description under which
formatting a disk is the expected behaviour of a skill.

The rule is written to fire on *roots*, not on deletion in general, because deletion in
general is ordinary. ``rm -rf ./build``, ``rm -rf "$TMPDIR/x"`` and ``rm -rf`` of a path
inside the bundle do not fire — only ``/``, ``~``, ``$HOME``, a bare user home, and the
handful of irreversible utilities (mkfs, diskutil erase, raw device writes, the classic
fork bomb, ``chmod -R 777 /``). Deleting an agent-critical or credential directory
(``~/.claude``, ``~/.ssh``) is included, because that is destruction with a security
consequence rather than a cleanup.

False-positive analysis
-----------------------
* *Uninstall scripts* that clear their own install root do not match, unless the root is
  literally the home directory.
* *Teaching material and warnings* (``# never run rm -rf /``) are filtered: a comment
  line, or any line in a prose file, is dropped when it or the two lines above it carry
  negation/warning language.
* *Security test fixtures* that assert a dangerous string is rejected — for example
  ``TITLE_RAW: '$(rm -rf /) `whoami`'`` in an injection-hardening test — used to fire at
  HIGH. They no longer do: files under ``test/``, ``tests/``, ``spec/`` or named
  ``*.test.*`` / ``*_test.*`` carry the TEST role, and this rule only fires from
  EXECUTABLE and INSTRUCTION files. The match is still counted in the report note and
  listed by ``--paranoid``, because a payload parked in a directory called ``tests/`` is
  a real, if unlikely, hiding place.
* *Variables* — ``rm -rf "$TARGET"`` — do not fire. That is a deliberate gap: without
  evaluation the scanner cannot know the value, and guessing would produce noise. The
  obfuscation and pipe-to-shell rules cover the cases where the value comes from outside.
"""

from __future__ import annotations

import re
from typing import List, Pattern, Tuple

from malskill.rules import Finding, make_finding
from malskill.rules.patterns import (
    actionable_hits,
    dedupe_by_label_and_file,
    is_warning_context,
    search_target,
)
from malskill.sanitize import for_display

RULE_IDS = ("DESTRUCTIVE_COMMAND",)

_ROOT_TARGET = r"[\"']?(?:/|/\*|~|~/|~/\*|\$HOME|\$\{HOME\}|\$HOME/|\$HOME/\*|" \
               r"/Users/[\w.$-]+/?|/home/[\w.$-]+/?)[\"']?"
#: A root target only counts when nothing follows it: "/home/runner/.gstack" is a
#: specific directory, "/home/runner" on its own is somebody's entire home.
_ROOT_END = r"\s*(?:$|[;&|#)])"

DESTRUCTIVE_PATTERNS: List[Tuple[str, Pattern]] = [
    (
        "rm -rf on a filesystem or home root",
        re.compile(
            r"(?<![\w-])rm\s+(?:-[a-zA-Z-]+\s+)*-{1,2}[a-zA-Z-]*[rR][a-zA-Z-]*\s+"
            + _ROOT_TARGET
            + _ROOT_END,
            re.M,
        ),
    ),
    (
        "rm -rf on a credential directory",
        re.compile(
            r"(?<![\w-])rm\s+(?:-[a-zA-Z-]+\s+)*-{1,2}[a-zA-Z-]*[rR][a-zA-Z-]*\s+"
            r"[\"']?(?:~|\$HOME|\$\{HOME\})/\.(?:ssh|aws|gnupg)\b",
            re.M,
        ),
    ),
    (
        "filesystem creation over an existing device",
        re.compile(r"(?<![\w-])mkfs(?:\.\w+)?\s+[-/\w$]"),
    ),
    (
        "diskutil erase",
        re.compile(r"(?<![\w-])diskutil\s+(?:erase\w*|partitionDisk|reformat)\b", re.I),
    ),
    (
        "fork bomb",
        re.compile(r":\s*\(\s*\)\s*\{[^}\n]*\|[^}\n]*&[^}\n]*\}\s*;?\s*:"),
    ),
    (
        "write to a raw block device",
        re.compile(
            r">\s*/dev/(?:sd[a-z]|nvme\d+n\d+|disk\d+|hd[a-z]|vd[a-z])\b|"
            r"(?<![\w-])dd\s[^\n]*\bof=/dev/(?:sd[a-z]|nvme|disk\d|hd[a-z]|vd[a-z])"
        ),
    ),
    (
        "chmod -R 777 on a root",
        re.compile(
            r"(?<![\w-])chmod\s+(?:-R\s+|-[a-zA-Z]*R[a-zA-Z]*\s+)?777\s+"
            + _ROOT_TARGET
            + _ROOT_END,
            re.M,
        ),
    ),
    (
        "recursive chown of a root",
        re.compile(
            r"(?<![\w-])chown\s+-R\s+[\w:.$]+\s+" + _ROOT_TARGET + _ROOT_END, re.M
        ),
    ),
    (
        "secure-wipe of a root",
        re.compile(
            r"(?<![\w-])(?:srm|shred)\s+(?:-[a-zA-Z]+\s+)*" + _ROOT_TARGET + _ROOT_END,
            re.M,
        ),
    ),
]

def check(target) -> List[Finding]:
    findings: List[Finding] = []
    candidates = [
        hit
        for hit in actionable_hits(
            target, "DESTRUCTIVE_COMMAND", search_target(target, DESTRUCTIVE_PATTERNS)
        )
        if not is_warning_context(hit)
    ]
    for hit in dedupe_by_label_and_file(candidates):
        where = "%s:%d" % (hit.file_rel, hit.line)
        findings.append(
            make_finding(
                "DESTRUCTIVE_COMMAND",
                target=target.display,
                kind=target.kind.value,
                file=hit.file_rel,
                line=hit.line,
                evidence=for_display(hit.context),
                why=(
                    "%s at %s. This %s carries a command that destroys data irreversibly, "
                    "and it declares nothing that would require it. An agent with Bash "
                    "access runs it verbatim; there is no step after it completes."
                    % (hit.label.capitalize(), where, target.kind.value)
                ),
                recommendation=(
                    "Remove this %s. If it is yours, scope the command to an explicit "
                    "subdirectory (never $HOME, ~ or /) and re-run the scan."
                    % target.kind.value
                ),
            )
        )
        if len(findings) >= 5:
            break
    return findings
