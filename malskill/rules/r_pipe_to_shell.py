"""PIPE_TO_SHELL — the code that runs is whatever the server sends today.

Rationale
---------
``curl … | bash`` is the shortest path from "a bundle you reviewed" to "arbitrary code
you did not". The bytes you audited are not the bytes that execute: the remote host
decides those, at run time, every time. Whoever controls that URL — the author, a
hijacked account, anyone who can answer for that domain — controls your machine with your
agent's privileges.

Unlike the mismatch rules this one does not care what the bundle claims. There is no
description under which "fetch and execute unreviewed remote code" becomes reviewable, so
claims cannot exempt it.

Fires on ``curl|wget … | sh|bash|zsh|python|node|perl|ruby``, ``sh -c "$(curl …)"``,
``bash <(curl …)``, ``eval "$(curl …)"``, ``python -c "$(curl …)"`` and the PowerShell
``iwr … | iex`` form.

False-positive analysis
-----------------------
* *Official installer instructions* (rustup, nvm, uv, bun, Homebrew, Deno) copied into a
  README are the dominant benign source, and measured on a real machine they were the
  single largest source of noise this rule produced. They now fire only from an
  EXECUTABLE or INSTRUCTION file: a SKILL.md that tells the agent to run
  ``curl … | bash`` is a live instruction and still fires at HIGH, while the same line
  in ``README.md``, ``CHANGELOG.md``, ``docs/``, ``references/`` or a test file is banked
  as a suppressed hit, counted in the report note, and listed by ``--paranoid``.
* *Prose inside an instruction surface is still scanned*, because a SKILL.md body is an
  instruction to the agent, not documentation for a human. What is excluded there is
  warning language: a line (or its two preceding lines) that says "never", "do not run",
  "dangerous", "example of an attack" cancels the match.
* *Localhost* is not exempted here: piping even a local HTTP response into a shell is a
  code-execution path, and localhost servers are frequently proxies for remote content.
"""

from __future__ import annotations

import re
from typing import List, Pattern, Tuple

from malskill.rules import Finding, make_finding
from malskill.rules.patterns import (
    actionable_hits,
    dedupe_by_label_and_file,
    hosts_in,
    is_warning_context,
    search_target,
)
from malskill.sanitize import for_display

RULE_IDS = ("PIPE_TO_SHELL",)

_FETCH = r"(?:curl|wget|fetch|http|https)"
_SHELL = r"(?:sudo\s+)?(?:sh|bash|zsh|ksh|dash|python3?|node|nodejs|perl|ruby|php)"

PIPE_PATTERNS: List[Tuple[str, Pattern]] = [
    (
        "remote download piped into a shell",
        re.compile(r"(?<![\w-])" + _FETCH + r"\s[^\n|]{0,300}\|\s*" + _SHELL + r"\b"),
    ),
    (
        "shell executing a remote download",
        re.compile(
            r"(?<![\w-])(?:sh|bash|zsh|python3?|node|perl|ruby)\s+-c\s*[\"'][^\"'\n]{0,20}"
            r"\$\(\s*(?:curl|wget)\b|"
            r"(?<![\w-])(?:sh|bash|zsh)\s+<\(\s*(?:curl|wget)\b"
        ),
    ),
    (
        "eval of a remote download",
        re.compile(r"\beval\s+[\"']?\$\(\s*(?:curl|wget)\b|\beval\s+[\"']?`\s*(?:curl|wget)\b"),
    ),
    (
        "PowerShell download executed inline",
        re.compile(
            r"(?:Invoke-WebRequest|iwr|curl)\b[^\n|]{0,200}\|\s*(?:iex|Invoke-Expression)\b|"
            r"(?:iex|Invoke-Expression)\s*\(\s*(?:New-Object\s+Net\.WebClient|"
            r"Invoke-WebRequest|iwr)\b",
            re.I,
        ),
    ),
    (
        "remote script downloaded then immediately executed",
        re.compile(
            r"(?:curl|wget)\s[^\n]{0,200}-[oO]\s*([\w./$-]+)[^\n]{0,80}(?:;|&&)\s*"
            r"(?:chmod\s+\+x\s+[\w./$-]+\s*(?:;|&&)\s*)?(?:\./|sh\s|bash\s|python3?\s)"
        ),
    ),
]

def check(target) -> List[Finding]:
    findings: List[Finding] = []
    candidates = [
        hit
        for hit in actionable_hits(target, "PIPE_TO_SHELL", search_target(target, PIPE_PATTERNS))
        if not is_warning_context(hit)
    ]
    for hit in dedupe_by_label_and_file(candidates):
        hosts = hosts_in(hit.line_text)
        destination = hosts[0] if hosts else "an unresolved URL"
        where = "%s:%d" % (hit.file_rel, hit.line)
        findings.append(
            make_finding(
                "PIPE_TO_SHELL",
                target=target.display,
                kind=target.kind.value,
                file=hit.file_rel,
                line=hit.line,
                evidence=for_display(hit.context),
                why=(
                    "%s at %s executes whatever %s returns at run time. The bundle you are "
                    "reviewing is not the code that will run, so reviewing it proves "
                    "nothing about what happens next."
                    % (hit.label.capitalize(), where, for_display(destination, 100))
                ),
                recommendation=(
                    "Remove this %s, or replace the pipe with a pinned download whose "
                    "checksum you verify and whose contents you read before running."
                    % target.kind.value
                ),
            )
        )
        if len(findings) >= 5:
            break
    return findings
