"""SYMLINK_ESCAPE, and the machinery behind the NOT-FULLY-ANALYZED state.

Rationale
---------
"Never print SAFE" is a data-model requirement, not a wording preference. A scanner that
silently drops the files it could not read produces a green row it cannot back up. So
every unreadable, oversized, binary, unparseable or escaping file is collected here and
reported as a third state alongside FLAGGED and CLEAN.

SYMLINK_ESCAPE is the one condition in this module that is both: it is an unscanned
record *and* a MEDIUM finding, because a link out of the bundle is a known trick. It
smuggles content past a reviewer who only reads the bundle directory, and it can turn
"read my own reference files" into a read of ``~/.ssh``. The scanner never follows the
link — it reports it and stops.

False-positive analysis
-----------------------
* *Development checkouts* symlinked into ``~/.claude/skills`` fire every time. That is
  correct behaviour: the scanner is telling you it did not analyze the real content.
* *Package-manager links* (``node_modules/.bin``) fire; they are usually in-bundle links,
  which are reported with a different detail string and do not raise the finding.
* *Oversized and binary files* never become findings on their own — they only ever
  populate the NOT-FULLY-ANALYZED section, so they cannot inflate a FLAGGED report.
"""

from __future__ import annotations

import os
from typing import List

from malskill.rules import (
    REASON_PARSE_ERROR,
    REASON_SYMLINK_OUT,
    Finding,
    Unscanned,
    make_finding,
)
from malskill.sanitize import for_display

RULE_IDS = ("SYMLINK_ESCAPE",)


def collect_unscanned(target) -> List[Unscanned]:
    """Every file in the target that could not be fully analyzed."""
    return target.unscanned() + _frontmatter_problems(target)


def _frontmatter_problems(target) -> List[Unscanned]:
    """Metadata files whose frontmatter did not parse cleanly.

    A SKILL.md whose frontmatter is broken (or uses YAML features outside the safe
    subset this scanner will parse) is a file whose claims could not be read. The
    claims-based rules therefore had less to work with, and the report says so instead
    of quietly treating the bundle as fully analyzed.

    Restricted to INSTRUCTION-role files. A README that opens with a ``---`` horizontal
    rule is not a file whose claims failed to parse, and on a real machine those
    accounted for the overwhelming majority of the parse-failure rows — noise in the very
    section that exists so real gaps stay visible.
    """
    from malskill import frontmatter as fm
    from malskill.rules.patterns import is_instruction_record, is_metadata_file

    problems: List[Unscanned] = []
    for record in getattr(target, "files", []) or []:
        if not getattr(record, "has_content", False) or record.is_binary:
            continue
        if record.synthetic or not is_metadata_file(record.rel):
            continue
        if not is_instruction_record(record):
            continue
        parsed = fm.parse(record.text)
        if not parsed.present:
            continue
        if not parsed.ok:
            problems.append(
                Unscanned(
                    target=target.display,
                    file=record.rel,
                    reason=REASON_PARSE_ERROR,
                    detail="frontmatter: %s" % (parsed.error or "unparseable"),
                )
            )
        elif not parsed.strict:
            problems.append(
                Unscanned(
                    target=target.display,
                    file=record.rel,
                    reason=REASON_PARSE_ERROR,
                    detail=(
                        "frontmatter: %d line(s) outside the supported key/value subset "
                        "were kept as raw text, not interpreted"
                        % len(parsed.unparsed)
                    ),
                )
            )
    return problems


def check(target) -> List[Finding]:
    findings: List[Finding] = []
    for record in getattr(target, "files", []) or []:
        if record.reason != REASON_SYMLINK_OUT:
            continue
        if record.detail.startswith("in-bundle"):
            continue  # inside the bundle: reported as unscanned, not as a finding
        destination = record.detail.split("-> ", 1)[-1] if "-> " in record.detail else ""
        sensitive = any(
            token in destination
            for token in (".ssh", ".aws", ".gnupg", ".claude", ".env", "Keychains")
        )
        findings.append(
            make_finding(
                "SYMLINK_ESCAPE",
                target=target.display,
                kind=target.kind.value,
                file=record.rel,
                evidence=for_display("%s -> %s" % (record.rel, destination)),
                why=(
                    "The bundle entry %s is a symlink resolving to %s, outside the bundle "
                    "root. The scanner did not follow it, so that content is unanalyzed; "
                    "an agent reading the bundle's own files would follow it.%s"
                    % (
                        record.rel,
                        for_display(destination or "an unknown location", 160),
                        " The destination is a credential or agent-configuration path."
                        if sensitive
                        else "",
                    )
                ),
                recommendation=(
                    "Delete the symlink %s, or remove the %s entirely if the link points "
                    "at credentials or at agent configuration."
                    % (os.path.basename(record.rel), target.kind.value)
                ),
            )
        )
        if len(findings) >= 5:
            break
    return findings
