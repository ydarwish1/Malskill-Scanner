"""HOOK_EXFIL and HOOK_REMOTE_CODE — the quietest execution path on the machine.

Rationale
---------
Hooks are configuration, not content: a string in ``settings.json`` that runs on
SessionStart, PreToolUse, PostToolUse, Stop. Nobody reviews them after the day they are
added, they never prompt, and they see everything the session sees — the prompt, the tool
input, the tool result, the transcript path, the whole environment.

That is why the bar here is lower than anywhere else. In a skill, network egress needs a
mismatch before it becomes a finding. In a hook, egress plus any reference to session
data is CRITICAL on sight: a hook that reads ``$CLAUDE_*``/the transcript/stdin and posts
it somewhere is exfiltration until proven otherwise, and "proven otherwise" is a decision
only the machine's owner can make.

Hook command strings also receive the full byte-rule pass (obfuscation, pipe-to-shell,
destructive commands, self-modification) because the engine treats the command string as
a file.

False-positive analysis
-----------------------
* *Self-hosted telemetry / transcript backup* to a host you own fires. Localhost
  destinations are exempt, so the common "post to a local logger" pattern stays quiet.
* *A hook that merely runs a local formatter* has no egress and does not fire.
* *A hook using ``jq`` on its stdin* without egress does not fire; the session-data
  reference alone is not enough.
"""

from __future__ import annotations

import re
from typing import List, Pattern, Tuple

from malskill.rules import Finding, make_finding
from malskill.rules.patterns import (
    find_egress_in_target,
    has_nonlocal_egress,
    search_target,
)
from malskill.rules.r_pipe_to_shell import PIPE_PATTERNS
from malskill.sanitize import for_display

RULE_IDS = ("HOOK_EXFIL", "HOOK_REMOTE_CODE")

#: References that mean "this command can see the session".
SESSION_DATA_PATTERNS: List[Tuple[str, Pattern]] = [
    ("$CLAUDE_* environment variable", re.compile(r"\$\{?CLAUDE_[A-Z0-9_]+\}?")),
    ("transcript", re.compile(r"\btranscript(?:_path)?\b", re.I)),
    ("tool input/output", re.compile(r"\btool_(?:input|response|output|name)\b|\bTOOL_(?:INPUT|OUTPUT)\b")),
    ("session identifiers", re.compile(r"\bsession_id\b|\bconversation\b|\bprompt\b", re.I)),
    ("piped stdin", re.compile(r"(?:-d|--data(?:-binary|-raw)?)\s*@-|\bcat\s*-\s*\||\|\s*(?:curl|wget|nc)\b|\bjq\b|\bwhile\s+read\b|\bread\s+-r\b")),
    ("environment dump", re.compile(r"(?<![\w./-])(?:env|printenv|set)\s*(?:\||>)")),
    ("agent config or history", re.compile(r"\.claude\.json\b|\.claude/(?:history|projects|todos)\b|\.(?:bash|zsh)_history\b")),
]


def check(target) -> List[Finding]:
    if getattr(target.kind, "value", str(target.kind)) != "hook":
        return []

    findings: List[Finding] = []
    egress = find_egress_in_target(target)
    external = has_nonlocal_egress(egress)
    session_hits = search_target(target, SESSION_DATA_PATTERNS)

    event = target.meta.get("event", "hook")
    source = target.meta.get("source_file", "")

    if external and session_hits:
        send = external[0]
        labels = sorted({h.label for h in session_hits})
        destination = send.destination or "an unresolved destination"
        findings.append(
            make_finding(
                "HOOK_EXFIL",
                target=target.display,
                kind=target.kind.value,
                file=source or None,
                line=target.meta.get("line"),
                evidence=for_display(target.meta.get("command", "")),
                why=(
                    "This %s hook combines network egress (%s -> %s) with access to "
                    "session data (%s). Hooks run automatically on ordinary agent "
                    "activity, see prompts, file contents and tool results, and never ask "
                    "for permission — so egress from a hook is exfiltration until you can "
                    "prove otherwise."
                    % (
                        event,
                        send.hit.label,
                        for_display(destination, 120),
                        ", ".join(labels),
                    )
                ),
                recommendation=(
                    "Delete this hook from %s now, and assume everything in recent "
                    "sessions reached %s."
                    % (source or "your settings file", for_display(destination, 120))
                ),
            )
        )

    for hit in search_target(target, PIPE_PATTERNS):
        findings.append(
            make_finding(
                "HOOK_REMOTE_CODE",
                target=target.display,
                kind=target.kind.value,
                file=source or None,
                line=target.meta.get("line"),
                evidence=for_display(hit.context),
                why=(
                    "This %s hook pipes remotely fetched content into a shell (%s). The "
                    "hook fires on ordinary agent activity, so the remote payload is "
                    "re-fetched and re-executed automatically, with no prompt and no "
                    "review." % (event, hit.label)
                ),
                recommendation=(
                    "Delete this hook from %s and inspect the URL it fetched."
                    % (source or "your settings file")
                ),
            )
        )
        break
    return findings
