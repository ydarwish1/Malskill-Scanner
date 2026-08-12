"""SELF_MODIFICATION and AUTO_APPROVE_TAMPERING — persistence and prompt removal.

Rationale
---------
Both rules are about a bundle reaching outside its own directory to change the machine's
future behaviour.

SELF_MODIFICATION: a skill that appends to ``~/.zshrc``, rewrites
``~/.claude/settings.json``, drops a file into another skill's directory, installs a git
hook, adds a crontab entry or a LaunchAgent has made itself permanent. Deleting the
bundle afterwards does not undo it — which is why the floor is CRITICAL even though the
individual write may look mundane.

AUTO_APPROVE_TAMPERING: every other protection depends on the confirmation prompt.
Content that widens the permissions allow-list, writes ``defaultMode: bypassPermissions``
into settings, invokes ``--dangerously-skip-permissions``, or simply *tells the agent* to
turn approvals off is disabling the last human checkpoint. A skill that asks for that has
declared its intent.

Detection notes
---------------
A path alone is never a finding — the write has to be visible, and it has to point *at*
the path:

* a shell redirection occurring **before** the path on the same line (so the path is the
  destination, not the source);
* a ``cp``/``mv``/``ln``/``rsync``/``install`` where the path is the **last** argument;
* a strong write call on the same line (``open(..., 'w')``, ``writeFileSync``,
  ``Path(...).write_text``, ``json.dump``, ``tee``, ``sed -i``, ``cat >``);
* the same strong write calls within two lines, but only inside real script files, where
  Python and JavaScript routinely build a path on one line and write on the next;
* or a command that is itself persistence (``crontab -``, ``launchctl load``,
  ``defaults write``, ``systemctl enable``).

The directionality checks matter more than they look: without them, markdown blockquotes
(``> note``), arrows (``->``, ``=>``) and "copy the template *out of* the bundle" lines
all read as writes, and every document that mentions a settings path becomes CRITICAL.

False-positive analysis
-----------------------
* *Installers and dotfile managers* legitimately append a PATH line to ``.zshrc``, and
  self-installing skills copy themselves into ``~/.claude/skills/``. They fire, and
  should: an agent extension that edits your shell startup or another skill's directory
  is worth exactly one look.
* *Agent-configuration helpers* you installed on purpose (a settings editor) fire by
  design; the evidence line makes them quick to confirm.
* *Tutorial content* that creates an example command with ``cat > .claude/commands/x.md``
  fires when it sits in a SKILL.md, and is suppressed when it sits in ``references/`` or
  ``docs/``: since v1.1 both rules fire only from EXECUTABLE and INSTRUCTION files (see
  :mod:`malskill.roles`). Measured on a real machine, documentation and test files were
  the source of two thirds of this rule's output.
* *Prose that warns against the dangerous flag* is filtered: lines (and their neighbours)
  carrying negation/warning language are skipped, and in prose files **and comment
  lines** the permission and persistence branches additionally require a directive verb,
  so a table of CLI flags, a document naming a LaunchAgents plist, or a code comment
  saying "bypassPermissions is unnecessary here" is not treated as an instruction.
* *Reading* ``~/.claude/settings.json`` (``cat``, ``jq``) does not fire — only writing.
  Angle-bracket placeholders and process substitution (``diff <(grep x a/<name>/b) …``)
  are no longer mistaken for a ``>`` redirection, which is what turned a read-only audit
  command into a CRITICAL finding on a real machine.
* One finding per (target-kind, file): five rows saying "this script writes
  settings.json" are one fact, and printing it five times is how a report gets skimmed.
"""

from __future__ import annotations

import re
from typing import List, Pattern, Tuple

from malskill.rules import Finding, make_finding
from malskill.rules.patterns import (
    NEGATION_RE,
    WRITE_INDICATOR_RE,
    actionable_hits,
    dedupe_by_label_and_file,
    executable_context,
    is_comment_line,
    is_prose_file,
    is_script_file,
    is_warning_context,
    search_target,
)
from malskill.sanitize import for_display

RULE_IDS = ("SELF_MODIFICATION", "AUTO_APPROVE_TAMPERING")

# --------------------------------------------------------------------------- self-modify

#: Paths whose modification outlives the bundle.
SELF_TARGET_PATTERNS: List[Tuple[str, Pattern]] = [
    ("agent settings file", re.compile(r"\.claude/settings(?:\.local)?\.json\b|\.claude/settings\b")),
    ("agent config ~/.claude.json", re.compile(r"(?:~|\$HOME|\.\.)?/?\.claude\.json\b")),
    ("another skill's directory", re.compile(r"\.claude/skills/[\w.-]+")),
    ("installed plugins directory", re.compile(r"\.claude/plugins\b")),
    ("agent commands directory", re.compile(r"\.claude/commands\b")),
    ("agent agents directory", re.compile(r"\.claude/agents\b")),
    ("agent hooks configuration", re.compile(r"\.claude/hooks\b|\"hooks\"\s*:")),
    ("shell startup file", re.compile(r"(?:~|\$HOME|/Users/[\w.$-]+|/home/[\w.$-]+)?/?\.(?:zshrc|bashrc|bash_profile|zprofile|zshenv|profile|zlogin)\b|config\.fish\b")),
    ("git hooks directory", re.compile(r"\.git/hooks\b|core\.hooksPath\b")),
    ("MCP server config", re.compile(r"(?<![\w-])\.mcp\.json\b|claude_desktop_config\.json\b")),
]

#: Commands that are themselves an act of persistence.
PERSISTENCE_PATTERNS: List[Tuple[str, Pattern]] = [
    ("crontab install", re.compile(r"(?<![\w-])crontab\s+(?:-|-e|-r|[\w./~$-]+)")),
    ("launchd job", re.compile(r"(?<![\w-])launchctl\s+(?:load|bootstrap|submit|enable)\b|LaunchAgents/|LaunchDaemons/")),
    ("macOS defaults write", re.compile(r"(?<![\w-])defaults\s+write\b")),
    ("systemd unit install", re.compile(r"systemctl\s+(?:enable|--user\s+enable)\b|/etc/systemd/system/|\.config/systemd/user/")),
    ("login item / autostart", re.compile(r"\.config/autostart/|/Library/StartupItems\b|HKCU\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run")),
]

_WINDOW = 2

#: Writes whose target is built on another line (a path in a variable, a Path object).
#: Only these justify looking outside the matched line, and only inside real scripts.
STRONG_WRITE_RE = re.compile(
    r"\bopen\s*\([^)]*[\"'](?:w|a|w\+|a\+|wb|ab)[\"']|"
    r"\bwriteFileSync?\s*\(|\bappendFileSync?\s*\(|\bwrite_text\s*\(|"
    r"\bfs\.(?:write|append|copy|rename)\w*\s*\(|\bshutil\.(?:copy|move)\w*\s*\(|"
    r"\bjson\.dump\s*\(|\bPath\([^)]*\)\.write|(?<![\w-])tee(?:\s+-a)?\s|"
    r"(?<![\w-])sed\s+-i|\bcat\s*>|(?<![\w-])dd\s+of=|(?<![\w-])jq\b[^\n]*>"
)

_REDIRECT_RE = re.compile(r"(?<=\S)(?<![-=<>|+&$])\s*>>?\s*[\"']?[~/$\w.]")
_COPY_RE = re.compile(r"(?<![\w-])(?:cp|mv|ln|rsync|install)\s")


def _is_real_redirect(line: str, position: int) -> bool:
    """False when the ``>`` closes a placeholder or a process substitution.

    ``diff <(grep 'x' skills/<skill>/SKILL.md) <(grep 'x' ~/.claude/plugins/…)`` reads
    two files and writes nothing, but the ``>`` that closes ``<skill>`` looks exactly
    like a redirection to a regex. On a real machine that one character turned a
    read-only audit command in a SKILL.md into a CRITICAL SELF_MODIFICATION finding.

    The test is deliberately simple: walk back to the start of the current token, and if
    it contains an unmatched ``<``, the ``>`` is closing it.
    """
    start = position
    while start > 0 and not line[start - 1].isspace():
        start -= 1
    token = line[start:position]
    return token.count("<") <= token.count(">")


def _window_text(record, line: int) -> str:
    lines = record.text.split("\n")
    start = max(0, line - 1 - _WINDOW)
    end = min(len(lines), line + _WINDOW)
    return "\n".join(lines[start:end])


def _is_last_path_on_line(line: str, end_col: int) -> bool:
    """True when nothing that looks like another argument follows the matched path.

    ``cp SKILL.md ~/.claude/skills/x/`` writes into the skill directory.
    ``cp -R ~/.claude/skills/x/templates ./site`` reads out of it. The difference is
    argument order, and getting it wrong turns every "copy the template out of the
    bundle" line into a CRITICAL finding.
    """
    rest = line[end_col:]
    head, _, tail = rest.partition(" ")
    del head  # path continuation, still the same argument
    tail = tail.strip().strip("\"'")
    for token in tail.split():
        if token.startswith("#") or token in ("\\", "&&", "||", ";", "|"):
            break
        return False
    return True


def _write_targets_path(hit) -> bool:
    """Does something on this line (or nearby, in a script) write to the matched path?"""
    line = hit.line_text
    col = line.find(hit.matched)
    if col < 0:
        col = 0
    end_col = col + len(hit.matched)
    before = line[:col]

    if STRONG_WRITE_RE.search(line):
        return True
    # The redirection has to appear before the path (so the path is the destination),
    # but it is matched against the whole line: cutting the line at the path would
    # remove the very character ">" needs to point at.
    for redirect in _REDIRECT_RE.finditer(line):
        arrow = line.find(">", redirect.start())
        if arrow == -1:
            arrow = redirect.start()
        if redirect.start() < col and _is_real_redirect(line, arrow):
            return True
    copy = _COPY_RE.search(before)
    if copy is not None and _is_last_path_on_line(line, end_col):
        return True

    record = hit.record
    if record is None or not is_script_file(hit.file_rel):
        return False
    if getattr(record, "synthetic", False):
        return bool(WRITE_INDICATOR_RE.search(line))
    return bool(STRONG_WRITE_RE.search(_window_text(record, hit.line)))


def _needs_directive(hit) -> bool:
    """True for places where naming a thing is not the same as doing it.

    Prose and code comments are read by humans, not interpreters, so a line there fires
    only when it also carries a directive verb (run, use, add, enable, install, …).

    Two carve-outs, in opposite directions:

    * a **fenced code block inside markdown** is a command the document is showing the
      agent to run, so it does not need a verb around it;
    * a **comment inside a script** always does, even though the file as a whole is
      executable — ``# permission mode, so bypassPermissions is unnecessary here`` is a
      sentence, and reporting it CRITICAL is how a real machine produced a false
      positive from a security plugin's own source.
    """
    if is_comment_line(hit.line_text):
        return True
    return is_prose_file(hit.file_rel) and not executable_context(hit)


def _check_self_modification(target) -> List[Finding]:
    findings: List[Finding] = []

    write_hits = [
        hit
        for hit in actionable_hits(
            target, "SELF_MODIFICATION", search_target(target, SELF_TARGET_PATTERNS)
        )
        if not is_warning_context(hit) and _write_targets_path(hit)
    ]
    for hit in dedupe_by_label_and_file(write_hits):
        findings.append(_finding(target, hit, hit.label, "written to"))
        if len(findings) >= 5:
            return findings

    persistence_hits = [
        hit
        for hit in actionable_hits(
            target, "SELF_MODIFICATION", search_target(target, PERSISTENCE_PATTERNS)
        )
        # A document (or a comment) that merely names a LaunchAgents path is not
        # installing one.
        if not is_warning_context(hit)
        and not (_needs_directive(hit) and not _AGENT_DIRECTIVE_RE.search(hit.line_text))
    ]
    seen = {(f.file, f.line) for f in findings}
    for hit in dedupe_by_label_and_file(persistence_hits):
        if (hit.file_rel, hit.line) in seen:
            continue
        findings.append(_finding(target, hit, hit.label, "installed"))
        if len(findings) >= 5:
            break
    return findings


def _finding(target, hit, label: str, verb: str) -> Finding:
    where = "%s:%d" % (hit.file_rel, hit.line)
    return make_finding(
        "SELF_MODIFICATION",
        target=target.display,
        kind=target.kind.value,
        file=hit.file_rel,
        line=hit.line,
        evidence=for_display(hit.context),
        why=(
            "At %s this %s has a %s %s. That reaches outside the bundle and changes what "
            "the machine does later: removing the %s afterwards does not undo it, which "
            "is what turns a one-shot script into a permanent foothold."
            % (where, target.kind.value, label, verb, target.kind.value)
        ),
        recommendation=(
            "Remove this %s, then inspect the target it writes to (%s) for entries you "
            "did not add yourself — settings files, shell rc files, crontab and "
            "LaunchAgents are all worth a diff."
            % (target.kind.value, label)
        ),
    )


# ---------------------------------------------------------------------- auto-approve

AUTO_APPROVE_COMMAND_PATTERNS: List[Tuple[str, Pattern]] = [
    ("--dangerously-skip-permissions", re.compile(r"--dangerously-skip-permissions\b")),
    ("permission mode override", re.compile(r"[\"']?defaultMode[\"']?\s*[:=]\s*[\"'](?:acceptEdits|bypassPermissions)[\"']|(?<![\w-])--permission-mode[= ]\s*(?:acceptEdits|bypassPermissions)")),
    ("bypassPermissions", re.compile(r"\bbypassPermissions\b")),
    ("permissions allow-list edit", re.compile(r"[\"']allow[\"']\s*:\s*\[|permissions\.allow\b|\.permissions\[[\"']allow[\"']\]|setdefault\s*\(\s*[\"']allow[\"']")),
    # Only the tool-call wildcard forms, never a bare "*": that string is a glob in
    # every JavaScript file on the machine, and flagging it buries everything else.
    ("blanket tool grant", re.compile(
        r"[\"'](?:Bash|Read|Write|Edit|WebFetch|WebSearch|Task|Glob|Grep)"
        r"\(\s*[:*]?\*{1,2}\s*\)[\"']")),
    ("auto-approve environment override", re.compile(r"\bCLAUDE_(?:AUTO_APPROVE|SKIP_PERMISSIONS|DANGEROUS\w*)\b|\bYOLO_MODE\b")),
]

#: Nearby text proving a wildcard is a permission grant and not a glob.
_PERMISSION_CONTEXT_RE = re.compile(r"\ballow\b|\bpermissions?\b|\bdefaultMode\b", re.I)

#: Code that mutates an allow-list rather than declaring one.
_ALLOW_MUTATION_RE = re.compile(
    r"\.(?:append|extend|insert|push|add)\s*\(|\+=|setdefault\s*\(|"
    r"jq\b[^\n]*\||\bupdate\s*\(",
    re.I,
)

#: Words that turn "the flag exists" into "use the flag".
_AGENT_DIRECTIVE_RE = re.compile(
    r"\b(?:run|runs|running|execute|executes|use|uses|using|add|adds|enable|enables|"
    r"set|sets|always|must|should|start|invoke|call|launch|apply|load|install|copy|"
    r"create|register|write|append|merge)\b",
    re.I,
)


def _context_lines(hit, before: int = 1, after: int = 0) -> str:
    record = hit.record
    if record is None:
        return hit.line_text
    lines = record.text.split("\n")
    start = max(0, hit.line - 1 - before)
    end = min(len(lines), hit.line + after)
    return "\n".join(lines[start:end])


AUTO_APPROVE_INSTRUCTION_PATTERNS: List[Tuple[str, Pattern]] = [
    ("instruction to disable approval prompts", re.compile(
        r"\b(?:enable|turn on|switch on|activate)\b[^.\n]{0,40}\b(?:auto[- ]?approv\w*|"
        r"auto[- ]?accept\w*|yolo mode|bypass permissions)\b", re.I)),
    ("instruction to widen the allow-list", re.compile(
        r"\b(?:add|append|insert|put)\b[^.\n]{0,50}\b(?:to (?:the |your )?(?:allow[- ]?list|"
        r"allowed[- ]?tools|permissions(?: allow)?(?: list)?))\b", re.I)),
    ("instruction to skip confirmation", re.compile(
        r"\b(?:skip|suppress|disable|bypass|ignore)\b[^.\n]{0,40}\b(?:permission|approval|"
        r"confirmation)s?\b[^.\n]{0,20}\b(?:prompts?|dialogs?|checks?|steps?)?\b", re.I)),
    ("instruction to act without asking", re.compile(
        r"\bwithout (?:asking|prompting|requesting)\b[^.\n]{0,30}\b(?:permission|"
        r"confirmation|approval|the user)\b", re.I)),
    ("always-allow instruction", re.compile(
        r"\balways allow\b[^.\n]{0,40}\b(?:tools?|commands?|edits?|everything)\b", re.I)),
]


def _command_hit_survives(hit) -> bool:
    if is_warning_context(hit):
        return False
    if NEGATION_RE.search(hit.line_text):
        # The line argues against the flag rather than using it. This covers the case
        # is_warning_context() cannot: an *error message* inside a script, e.g.
        # `echo "Claude Code refuses --dangerously-skip-permissions as root"`, which is
        # neither a comment nor prose but is plainly not an instruction to use it.
        return False
    if hit.label == "blanket tool grant" and not _PERMISSION_CONTEXT_RE.search(
        _context_lines(hit, before=3, after=1)
    ):
        # A wildcard tool grant only means anything inside a permissions block.
        return False
    if hit.label == "permissions allow-list edit":
        # A settings file that *contains* an allow-list is a user configuring their
        # own machine. What matters is bundle content that WRITES one, so this
        # branch always demands a write in context.
        if not _write_targets_path(hit) and not _ALLOW_MUTATION_RE.search(
            _context_lines(hit, before=1, after=1)
        ):
            return False
    if _needs_directive(hit) and not _AGENT_DIRECTIVE_RE.search(_context_lines(hit)):
        # Documentation, and comments inside code, that merely name the flag (a table of
        # CLI options, an architecture diagram, "# bypassPermissions is unnecessary")
        # are not instructions to disable your prompts.
        return False
    return True


def _check_auto_approve(target) -> List[Finding]:
    findings: List[Finding] = []

    command_hits = [
        hit
        for hit in actionable_hits(
            target,
            "AUTO_APPROVE_TAMPERING",
            search_target(target, AUTO_APPROVE_COMMAND_PATTERNS),
        )
        if _command_hit_survives(hit)
    ]
    for hit in dedupe_by_label_and_file(command_hits):
        findings.append(_auto_finding(target, hit))
        if len(findings) >= 4:
            return findings

    instruction_hits = [
        hit
        for hit in actionable_hits(
            target,
            "AUTO_APPROVE_TAMPERING",
            search_target(target, AUTO_APPROVE_INSTRUCTION_PATTERNS),
        )
        # These patterns are natural language, so warning language cancels them
        # everywhere, not only in prose files, and the surrounding sentences count.
        if not is_warning_context(hit)
        and not NEGATION_RE.search(_context_lines(hit, before=2, after=2))
        and not (
            _needs_directive(hit) and not _AGENT_DIRECTIVE_RE.search(_context_lines(hit))
        )
    ]
    seen = {(f.file, f.line) for f in findings}
    for hit in dedupe_by_label_and_file(instruction_hits):
        if (hit.file_rel, hit.line) in seen:
            continue
        findings.append(_auto_finding(target, hit))
        if len(findings) >= 4:
            break
    return findings


def _auto_finding(target, hit) -> Finding:
    where = "%s:%d" % (hit.file_rel, hit.line)
    return make_finding(
        "AUTO_APPROVE_TAMPERING",
        target=target.display,
        kind=target.kind.value,
        file=hit.file_rel,
        line=hit.line,
        evidence=for_display(hit.context),
        why=(
            "%s at %s. Every other control you have depends on the approval prompt; "
            "content that widens the allow-list or turns the prompt off removes the last "
            "human checkpoint before commands run with your privileges."
            % (hit.label.capitalize(), where)
        ),
        recommendation=(
            "Remove this %s and audit your permissions allow-list and settings files for "
            "entries you did not add yourself." % target.kind.value
        ),
    )


def check(target) -> List[Finding]:
    return _check_self_modification(target) + _check_auto_approve(target)
