"""Rule registry and the core data model shared by every part of the scanner.

Public contract (imported by tests and by every other module)::

    from malskill.rules import REGISTRY, Finding, Severity

* ``REGISTRY`` maps finding-ID -> :class:`Rule` metadata. Every finding ID the scanner
  can ever emit is present here, together with its **severity floor**, the trigger
  description, why it is dangerous, the recommended action and its known
  false-positive modes. ``docs/RULES.md`` documents the same set for humans.
* ``Finding`` is the single result record produced by rules.
* ``Severity`` is the four-level enum. The rule sets the FLOOR; the optional AI
  explainer may raise a finding's severity but can never lower or clear it.

This module deliberately imports nothing from the rest of the package so that it can
never participate in an import cycle and so that ``from malskill.rules import …`` is
cheap and side-effect free.
"""

from __future__ import annotations

import enum
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, Iterator, List, Optional, Tuple

__all__ = ["REGISTRY", "Finding", "Severity"]


# --------------------------------------------------------------------------------------
# Severity
# --------------------------------------------------------------------------------------


class Severity(str, enum.Enum):
    """Severity levels. The rule sets the floor; the explainer may only raise it."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"

    @property
    def rank(self) -> int:
        """Higher number == more severe. Used for sorting and escalation checks."""
        return _SEVERITY_RANK[self.value]

    def __str__(self) -> str:  # so f"{sev}" prints CRITICAL, not Severity.CRITICAL
        return self.value

    @classmethod
    def parse(cls, text: str) -> Optional["Severity"]:
        """Best-effort parse of a severity name; ``None`` when unrecognised."""
        if not text:
            return None
        try:
            return cls(text.strip().upper())
        except ValueError:
            return None

    @classmethod
    def max(cls, a: "Severity", b: "Severity") -> "Severity":
        return a if a.rank >= b.rank else b


_SEVERITY_RANK = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}

#: Canonical ordering for report output (most severe first).
SEVERITY_ORDER: Tuple[Severity, ...] = (
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
)


# --------------------------------------------------------------------------------------
# Findings and non-findings
# --------------------------------------------------------------------------------------

#: Reasons a file could not be fully analyzed. These are loud report entries, never
#: silent skips: a scanner that quietly ignores what it cannot read is lying.
REASON_BINARY = "binary"
REASON_TOO_LARGE = "too-large"
REASON_UNREADABLE = "unreadable"
REASON_PARSE_ERROR = "parse-error"
REASON_SYMLINK_OUT = "symlink-out"

UNSCANNED_REASONS: Tuple[str, ...] = (
    REASON_BINARY,
    REASON_TOO_LARGE,
    REASON_UNREADABLE,
    REASON_PARSE_ERROR,
    REASON_SYMLINK_OUT,
)


@dataclass
class Finding:
    """One deterministic rule hit.

    ``evidence`` is derived from the raw bytes but sanitized for display (zero-width
    characters escaped, URLs defanged) so that reading the report can never itself be
    the attack.
    """

    id: str
    severity: Severity
    target: str
    kind: str
    file: Optional[str] = None
    line: Optional[int] = None
    evidence: str = ""
    why: str = ""
    recommendation: str = ""
    escalated: bool = False
    escalation_note: Optional[str] = None

    def __post_init__(self) -> None:
        if isinstance(self.severity, str) and not isinstance(self.severity, Severity):
            parsed = Severity.parse(self.severity)
            if parsed is not None:
                self.severity = parsed

    # -- severity floor enforcement ----------------------------------------------------
    @property
    def floor(self) -> Severity:
        """The rule-declared severity floor for this finding ID."""
        rule = REGISTRY.get(self.id)
        return rule.severity if rule is not None else self.severity

    def escalate(self, severity: Severity, note: str) -> bool:
        """Raise severity. Returns True when applied.

        Never lowers: an AI (or anything else) asking for a lower severity than the
        rule floor is ignored by construction.
        """
        if severity.rank <= self.severity.rank:
            return False
        self.severity = severity
        self.escalated = True
        self.escalation_note = note
        return True

    def sort_key(self) -> Tuple[int, str, str, str, int]:
        return (
            -self.severity.rank,
            self.target,
            self.id,
            self.file or "",
            self.line or 0,
        )

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["severity"] = self.severity.value
        return data


@dataclass
class Unscanned:
    """A file (or config) that could not be fully analyzed. Always reported."""

    target: str
    file: str
    reason: str
    detail: str = ""
    #: Some non-analyzable conditions have a named ID in the registry (for example
    #: MCP_UNPARSEABLE_CONFIG). It is carried here so the report can name it.
    finding_id: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# --------------------------------------------------------------------------------------
# Rule metadata
# --------------------------------------------------------------------------------------


@dataclass(frozen=True)
class Rule:
    """Static metadata for one finding ID.

    Supports both attribute access (``rule.severity``) and mapping access
    (``rule["severity"]``) so downstream consumers can use whichever they expect.
    """

    id: str
    severity: Severity
    title: str
    category: str
    module: str
    trigger: str
    why: str
    recommendation: str
    false_positives: str
    #: Target kinds this rule inspects.
    applies_to: Tuple[str, ...] = ()
    #: "finding" for normal rules, "unscanned" for IDs that produce a
    #: NOT-FULLY-ANALYZED record rather than a finding.
    emits: str = "finding"

    # -- mapping-style access ----------------------------------------------------------
    def __getitem__(self, key: str) -> Any:
        try:
            return getattr(self, key)
        except AttributeError as exc:  # pragma: no cover - defensive
            raise KeyError(key) from exc

    def get(self, key: str, default: Any = None) -> Any:
        return getattr(self, key, default)

    def keys(self) -> List[str]:
        return [
            "id",
            "severity",
            "title",
            "category",
            "module",
            "trigger",
            "why",
            "recommendation",
            "false_positives",
            "applies_to",
            "emits",
        ]

    def __contains__(self, key: str) -> bool:
        return key in self.keys()

    def __iter__(self) -> Iterator[str]:
        return iter(self.keys())

    @property
    def severity_floor(self) -> Severity:
        return self.severity

    @property
    def produces_findings(self) -> bool:
        return self.emits == "finding"

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["severity"] = self.severity.value
        data["applies_to"] = list(self.applies_to)
        return data

    def rule_text(self) -> str:
        """Compact rule text handed to the zero-tool explainer."""
        return (
            "{id} (floor {sev})\n"
            "trigger: {trigger}\n"
            "why: {why}\n"
            "recommended action: {rec}\n"
            "known false-positive modes: {fp}"
        ).format(
            id=self.id,
            sev=self.severity.value,
            trigger=self.trigger,
            why=self.why,
            rec=self.recommendation,
            fp=self.false_positives,
        )


# Target kinds, kept as plain strings to match the Finding.kind contract.
KIND_SKILL = "skill"
KIND_PLUGIN = "plugin"
KIND_COMMAND = "command"
KIND_AGENT = "agent"
KIND_HOOK = "hook"
KIND_MCP_SERVER = "mcp-server"
KIND_MCP_CONFIG = "mcp-config"

_BUNDLE_KINDS: Tuple[str, ...] = (KIND_SKILL, KIND_PLUGIN, KIND_COMMAND, KIND_AGENT)
_ALL_KINDS: Tuple[str, ...] = (
    KIND_SKILL,
    KIND_PLUGIN,
    KIND_COMMAND,
    KIND_AGENT,
    KIND_HOOK,
    KIND_MCP_SERVER,
    KIND_MCP_CONFIG,
)


def _rule(**kwargs: Any) -> Rule:
    return Rule(**kwargs)


_RULES: List[Rule] = [
    # ---------------------------------------------------------------- mismatch / behavior
    _rule(
        id="NETWORK_IN_OFFLINE_CLAIM",
        severity=Severity.HIGH,
        title="Network egress inside a bundle that claims it needs no network",
        category="mismatch",
        module="malskill.rules.r_network_claims",
        trigger=(
            "A network egress primitive (curl, wget, nc, /dev/tcp, urllib, requests, "
            "fetch(, http.client, XMLHttpRequest, WebSocket, ...) appears in the bundle "
            "while the bundle's own description claims it works offline / locally / "
            "without network, or the bundle never declares any network intent, its "
            "purpose is local-only work, and it reaches a non-local URL. Targets that "
            "resolve to localhost, 127.0.0.1, 0.0.0.0 or ::1 are exempt."
        ),
        why=(
            "curl on its own is meaningless: it appears in roughly a third of installed "
            "bundles. curl inside something that told you it never touches the network "
            "is a lie about behavior, and the lie is the signal."
        ),
        recommendation=(
            "Open the flagged line, decide whether the bundle needs that host, and remove "
            "the bundle if the description does not honestly describe what it does."
        ),
        false_positives=(
            "A bundle that fetches documentation while describing itself as an 'offline "
            "formatter'; telemetry or update checks bolted onto an otherwise local tool; "
            "example URLs inside prose. Localhost/dev-server usage is exempted explicitly."
        ),
        applies_to=_BUNDLE_KINDS + (KIND_HOOK, KIND_MCP_SERVER),
    ),
    _rule(
        id="SENSITIVE_READ_PLUS_EGRESS",
        severity=Severity.CRITICAL,
        title="Bundle both reads secrets and can send data off the machine",
        category="mismatch",
        module="malskill.rules.r_exfil",
        trigger=(
            "The same bundle references a sensitive path (~/.ssh, ~/.aws, ~/.gnupg, "
            "~/.netrc, .env files, id_rsa/id_ed25519, credentials files, keychain access, "
            "~/.claude.json, browser cookie/login-data stores, or bulk environment "
            "harvesting) AND contains at least one network egress primitive that is not "
            "provably localhost-only."
        ),
        why=(
            "Read-secret plus send-somewhere is the entire shape of credential theft. "
            "Neither half is remarkable alone; together, in one bundle, they are an "
            "exfiltration pipeline that runs with your agent's privileges."
        ),
        recommendation=(
            "Remove this bundle now and treat every credential it could reach as "
            "compromised: rotate the keys and tokens on the referenced paths."
        ),
        false_positives=(
            "Legitimate deploy/credential tooling that uploads to a service you chose "
            "(an AWS profile helper, an SSH key uploader). Those are still worth a manual "
            "look, which is why the finding names the exact file and line."
        ),
        applies_to=_BUNDLE_KINDS + (KIND_HOOK, KIND_MCP_SERVER),
    ),
    _rule(
        id="CREDENTIAL_PATH_ACCESS",
        severity=Severity.MEDIUM,
        title="Bundle touches credential paths (no egress found)",
        category="mismatch",
        module="malskill.rules.r_credentials",
        trigger=(
            "A sensitive credential path is referenced but no network egress primitive "
            "exists anywhere in the bundle. Suppressed when the bundle's declared purpose "
            "is credential/ssh/gpg/keychain/dotenv management — a credential manager "
            "touching credentials is not a mismatch."
        ),
        why=(
            "Local-only credential reads still hand secrets to whatever the agent does "
            "next, including printing them into a transcript that leaves the machine by "
            "another route."
        ),
        recommendation=(
            "Review the flagged line. Keep the bundle only if reading that path is part of "
            "the job you installed it for; otherwise remove it."
        ),
        false_positives=(
            "Dotfile managers, .env loaders, SSH config helpers, documentation that shows "
            "an example path. Purpose-matched bundles are suppressed by design."
        ),
        applies_to=_BUNDLE_KINDS + (KIND_HOOK, KIND_MCP_SERVER),
    ),
    _rule(
        id="DESTRUCTIVE_COMMAND",
        severity=Severity.HIGH,
        title="Command that destroys data at a system or home root",
        category="behavior",
        module="malskill.rules.r_destructive",
        trigger=(
            "rm -rf against /, ~, $HOME or a bare user root; mkfs; diskutil erase*; the "
            "classic fork bomb; writes to raw devices (> /dev/sda, dd of=/dev/...); "
            "chmod -R 777 /. rm scoped to the bundle's own directory, ./build, mktemp "
            "output or $TMPDIR does not fire."
        ),
        why=(
            "An agent that is allowed to run Bash will run these verbatim. There is no "
            "recovery step after the command completes."
        ),
        recommendation=(
            "Remove this bundle. If you wrote it yourself, scope the deletion to an "
            "explicit subdirectory and re-run the scanner."
        ),
        false_positives=(
            "Uninstall scripts that legitimately clear their own install root; teaching "
            "material quoting the dangerous form. Both are worth reading once."
        ),
        applies_to=_BUNDLE_KINDS + (KIND_HOOK, KIND_MCP_SERVER),
    ),
    _rule(
        id="SELF_MODIFICATION",
        severity=Severity.CRITICAL,
        title="Bundle writes to the agent's own configuration or to shell startup files",
        category="behavior",
        module="malskill.rules.r_self_modify",
        trigger=(
            "A write/append/edit operation targeting ~/.claude/settings*.json, "
            "~/.claude.json, another skill's or plugin's directory, ~/.claude/plugins/, "
            "shell rc files (.zshrc, .bashrc, .profile, .bash_profile), the git hooks "
            "directory, crontab, or launchd/LaunchAgents plists."
        ),
        why=(
            "This is how a one-shot skill becomes permanent. Editing agent settings, a "
            "shell rc file or a launch agent gives the bundle a foothold that survives "
            "deleting the bundle itself."
        ),
        recommendation=(
            "Remove this bundle and then inspect the targets it writes to (settings files, "
            "shell rc files, crontab, LaunchAgents) for changes it already made."
        ),
        false_positives=(
            "Legitimate installers and dotfile managers that add a PATH line to .zshrc, "
            "and agent-configuration helpers you installed on purpose."
        ),
        applies_to=_BUNDLE_KINDS + (KIND_HOOK, KIND_MCP_SERVER),
    ),
    _rule(
        id="AUTO_APPROVE_TAMPERING",
        severity=Severity.CRITICAL,
        title="Content that widens or disables the agent's permission prompts",
        category="behavior",
        module="malskill.rules.r_self_modify",
        trigger=(
            "Content that edits a permissions allow-list, writes defaultMode "
            "acceptEdits/bypassPermissions into settings, invokes "
            "--dangerously-skip-permissions, or instructs the agent/user to enable "
            "auto-approval."
        ),
        why=(
            "Every other protection you have depends on the confirmation prompt. Anything "
            "that turns the prompt off is disabling the last human checkpoint before "
            "arbitrary commands run."
        ),
        recommendation=(
            "Remove this bundle and audit your permissions allow-list and settings files "
            "for entries you did not add yourself."
        ),
        false_positives=(
            "Security documentation quoting the flag, and CI helper scripts written for "
            "sandboxes. Prose that only warns against the flag is filtered out."
        ),
        applies_to=_ALL_KINDS,
    ),
    # ------------------------------------------------------------ obfuscation / delivery
    _rule(
        id="OBFUSCATED_EXECUTION",
        severity=Severity.HIGH,
        title="Encoded payload decoded straight into an interpreter",
        category="obfuscation",
        module="malskill.rules.r_obfuscation",
        trigger=(
            "decode-then-execute: base64/base32/xxd -r/openssl enc -d piped into "
            "sh/bash/zsh/python/node/perl/ruby/eval/exec; eval(atob(, exec(base64, "
            "Function(atob(, eval(Buffer.from(; a run of 20+ consecutive \\x or \\u "
            "escapes within reach of an exec/eval; compile()+exec() over a decoded blob."
        ),
        why=(
            "Code that hides what it runs has already told you its intent. Obfuscation "
            "exists to defeat exactly the review you are doing now."
        ),
        recommendation=(
            "Remove this bundle. Do not decode the payload on the machine you care about; "
            "if you must, decode it in a throwaway container without your credentials."
        ),
        false_positives=(
            "Minified vendored JavaScript, encoding tutorials, and test fixtures for "
            "base64 libraries. Vendored/minified assets are usually large binaries or "
            "bundles and show up as NOT-FULLY-ANALYZED as well."
        ),
        applies_to=_ALL_KINDS,
    ),
    _rule(
        id="PIPE_TO_SHELL",
        severity=Severity.HIGH,
        title="Remote content piped straight into a shell",
        category="obfuscation",
        module="malskill.rules.r_pipe_to_shell",
        trigger=(
            "curl/wget ... | sh|bash|zsh|python|node, sh -c \"$(curl ...)\", "
            "bash <(curl ...), or the PowerShell iwr|iex equivalent."
        ),
        why=(
            "Whatever the server returns at run time is executed with your privileges. "
            "The bundle you reviewed is not the code that runs; the review is worthless."
        ),
        recommendation=(
            "Remove this bundle, or replace the pipe with a pinned, checksum-verified "
            "download that you read before executing."
        ),
        false_positives=(
            "Official installer instructions copied into a README (rustup, nvm, uv). "
            "Common in real bundles, which is why the finding shows you the exact host."
        ),
        applies_to=_ALL_KINDS,
    ),
    _rule(
        id="HIDDEN_INSTRUCTIONS",
        severity=Severity.HIGH,
        title="Invisible characters or hidden HTML comments aimed at the agent",
        category="obfuscation",
        module="malskill.rules.r_injection",
        trigger=(
            "Zero-width or bidi control codepoints (U+200B..U+200F, U+202A..U+202E, "
            "U+2060..U+2064, U+FEFF outside a leading BOM) inside SKILL.md, command or "
            "agent markdown, MCP descriptions or hook strings; or an HTML comment "
            "containing agent-directed imperatives (ignore/always/never/do not tell/ "
            "secretly/before responding/run the following)."
        ),
        why=(
            "The agent reads the bytes; you read the rendered text. Anything in that gap "
            "is an instruction planted where review cannot see it."
        ),
        recommendation=(
            "Remove this bundle. Text that must be invisible to you but visible to the "
            "agent has no legitimate use."
        ),
        false_positives=(
            "A leading UTF-8 BOM (explicitly exempted), emoji ZWJ sequences in prose, and "
            "genuine right-to-left text. The finding reports the exact codepoints so you "
            "can tell these apart."
        ),
        applies_to=_ALL_KINDS,
    ),
    _rule(
        id="SYMLINK_ESCAPE",
        severity=Severity.MEDIUM,
        title="Symlink inside a bundle pointing outside the bundle",
        category="obfuscation",
        module="malskill.rules.r_unscannable",
        trigger=(
            "A symlink in the bundle resolves outside the bundle root (for example a link "
            "named 'notes' pointing at ~/.ssh)."
        ),
        why=(
            "It smuggles content past a reviewer who only reads the bundle, and it can "
            "turn an innocent-looking 'read my own docs' step into a read of your keys. "
            "The scanner never follows the link."
        ),
        recommendation=(
            "Delete the symlink, or remove the bundle if the link points at credentials or "
            "at agent configuration."
        ),
        false_positives=(
            "Development checkouts symlinked into ~/.claude/skills, and node_modules "
            "links created by package managers."
        ),
        applies_to=_ALL_KINDS,
    ),
    # ---------------------------------------------------------------- agent manipulation
    _rule(
        id="PROMPT_INJECTION_IN_METADATA",
        severity=Severity.HIGH,
        title="Agent-manipulation language in metadata the agent auto-loads",
        category="agent-manipulation",
        module="malskill.rules.r_injection",
        trigger=(
            "Skill/command/agent frontmatter descriptions, MCP tool descriptions, MCP "
            "server instructions or hook command strings containing phrases such as "
            "'ignore previous instructions', 'do not tell the user', 'without the user's "
            "approval', 'always run this tool first', 'before using any other tool', "
            "'pretend you are', or 'exfiltrate'. Restricted to metadata fields: ordinary "
            "documentation prose that merely discusses prompt injection does not fire."
        ),
        why=(
            "Descriptions and tool metadata are loaded into every session before you type "
            "anything, and nobody reads them. Text there is an instruction to the agent, "
            "not documentation for you."
        ),
        recommendation=(
            "Remove this bundle or MCP server. Metadata that tells the agent to hide "
            "things from you is not recoverable by editing one line."
        ),
        false_positives=(
            "Security tooling whose description legitimately names these phrases, and "
            "red-team fixtures. The rule ignores README/body prose for exactly this reason."
        ),
        applies_to=_ALL_KINDS,
    ),
    _rule(
        id="TOOL_SHADOWING",
        severity=Severity.MEDIUM,
        title="Metadata that redefines or intercepts other tools",
        category="agent-manipulation",
        module="malskill.rules.r_injection",
        trigger=(
            "Metadata instructing the agent to use this tool 'instead of' another named "
            "tool, claiming it 'overrides the built-in', 'replaces the Bash/Read/Write "
            "tool', or 'intercepts calls to' another tool."
        ),
        why=(
            "A shadowing tool sits between the agent and the real tool, so it sees every "
            "argument — file contents, commands, secrets — and can alter the result."
        ),
        recommendation=(
            "Remove the server or skill unless you deliberately installed a proxy tool and "
            "trust its author with everything the shadowed tool touches."
        ),
        false_positives=(
            "Genuine drop-in replacements (a faster search tool) and wrappers that "
            "advertise themselves honestly."
        ),
        applies_to=_ALL_KINDS,
    ),
    # --------------------------------------------------------------------- MCP configs
    _rule(
        id="MCP_RUNTIME_REMOTE_CODE",
        severity=Severity.HIGH,
        title="MCP server downloads and executes code at launch",
        category="mcp",
        module="malskill.rules.r_mcp_config",
        trigger=(
            "The server's command+args fetch and execute at start-up: curl/wget piped to a "
            "shell, sh -c \"$(curl ...)\", bash -c wrapping a fetch, node -e/python -c that "
            "downloads then evaluates. Plain npx/uvx/docker of a named package is NOT a "
            "finding — that is the ecosystem norm."
        ),
        why=(
            "The server starts with every session, so the remote payload is re-fetched and "
            "re-executed forever. Whoever controls that URL controls your machine."
        ),
        recommendation=(
            "Remove this server from the MCP config, or replace it with a pinned package "
            "version installed ahead of time."
        ),
        false_positives=(
            "Self-hosted bootstrap scripts on a host you control. The finding shows the "
            "URL so you can judge it."
        ),
        applies_to=(KIND_MCP_SERVER, KIND_MCP_CONFIG),
    ),
    _rule(
        id="MCP_SECRET_BROADCAST",
        severity=Severity.MEDIUM,
        title="Real secret handed to an auto-updating remote package",
        category="mcp",
        module="malskill.rules.r_mcp_config",
        trigger=(
            "The server's env block contains a credential-shaped variable (*KEY*, *TOKEN*, "
            "*SECRET*, *PASSWORD*) whose value is a real literal of 8+ characters (not "
            "${ENV_VAR}, not 'your-key-here'), while the command runs an unpinned remote "
            "package (npx -y pkg, pkg@latest, uvx pkg with no version)."
        ),
        why=(
            "The secret is handed to whatever version of that package the registry serves "
            "next. A single malicious release, from the author or from a hijacked account, "
            "reads it directly out of the environment."
        ),
        recommendation=(
            "Pin the package to an exact version and move the secret into an environment "
            "variable reference (${VAR}) instead of a literal in the config."
        ),
        false_positives=(
            "Placeholder-looking values that are actually real, and long non-secret "
            "identifiers stored in a *_KEY variable."
        ),
        applies_to=(KIND_MCP_SERVER, KIND_MCP_CONFIG),
    ),
    _rule(
        id="MCP_UNPARSEABLE_CONFIG",
        severity=Severity.MEDIUM,
        title="MCP config could not be parsed",
        category="mcp",
        module="malskill.rules.r_mcp_config",
        trigger=(
            "An MCP config file exists but does not parse as JSON (or as the supported "
            "TOML subset). Emitted as a NOT-FULLY-ANALYZED record, NOT as a finding: the "
            "scanner reports what it could not read rather than implying the file is fine."
        ),
        why=(
            "An unparsed config is an unscanned config. Silently skipping it would turn a "
            "blind spot into a green row."
        ),
        recommendation=(
            "Fix or hand-review the config file, then re-run the scan so the servers it "
            "declares are actually analyzed."
        ),
        false_positives=(
            "Configs using JSON5/comments, and TOML features outside the supported subset. "
            "Both are reported as not-analyzed rather than as findings."
        ),
        applies_to=(KIND_MCP_CONFIG,),
        emits="unscanned",
    ),
    # -------------------------------------------------------------------------- hooks
    _rule(
        id="HOOK_EXFIL",
        severity=Severity.CRITICAL,
        title="Hook that ships session data off the machine",
        category="hook",
        module="malskill.rules.r_hooks",
        trigger=(
            "A hook command containing a network egress primitive together with a "
            "reference to session data: $CLAUDE_* variables, transcript paths, tool "
            "input/output, piped stdin (curl -d @-), or an environment dump."
        ),
        why=(
            "Hooks run automatically and see everything the session sees — prompts, file "
            "contents, tool results. Egress from a hook is exfiltration until proven "
            "otherwise, and it never asks for permission."
        ),
        recommendation=(
            "Delete this hook from the settings file immediately and assume everything in "
            "recent sessions reached the remote host."
        ),
        false_positives=(
            "Deliberate self-hosted telemetry or transcript backup to a host you own. "
            "Localhost-only destinations are exempt."
        ),
        applies_to=(KIND_HOOK,),
    ),
    _rule(
        id="HOOK_REMOTE_CODE",
        severity=Severity.HIGH,
        title="Hook that executes remotely fetched code",
        category="hook",
        module="malskill.rules.r_hooks",
        trigger="A hook command that pipes remote content into a shell or interpreter.",
        why=(
            "The hook fires on ordinary agent activity, so the remote payload runs "
            "repeatedly and automatically, with no prompt and no review."
        ),
        recommendation=(
            "Delete this hook from the settings file and inspect the URL it fetched."
        ),
        false_positives=(
            "Bootstrap hooks for an internal tool on an internal host; still worth pinning."
        ),
        applies_to=(KIND_HOOK,),
    ),
    # ------------------------------------------------------------------ role context
    _rule(
        id="SUPPRESSED_PATTERN_HIT",
        severity=Severity.LOW,
        title="A behaviour pattern matched in documentation, test or data context",
        category="context",
        module="malskill.rules.engine",
        trigger=(
            "A behaviour rule's pattern (PIPE_TO_SHELL, DESTRUCTIVE_COMMAND, "
            "SELF_MODIFICATION, AUTO_APPROVE_TAMPERING, OBFUSCATED_EXECUTION, "
            "NETWORK_IN_OFFLINE_CLAIM, SENSITIVE_READ_PLUS_EGRESS, "
            "CREDENTIAL_PATH_ACCESS) matched inside a file whose role is DOCS, TEST or "
            "DATA/BINARY rather than EXECUTABLE or INSTRUCTION. Emitted only with "
            "--paranoid; by default these are counted in a report note instead."
        ),
        why=(
            "A README quoting an official 'curl | bash' installer, a CHANGELOG entry, or "
            "a test asserting that '$(rm -rf /)' is rejected are not behaviour, and "
            "reporting them at full severity trains the reader to skim past the one "
            "finding that matters. They are still counted, because a scanner that "
            "silently drops what it saw is the same lie as printing a green checkmark."
        ),
        recommendation=(
            "Read the line. If the file is genuinely documentation or test material, "
            "nothing needs doing. If a SKILL.md tells the agent to follow the steps in "
            "that document, treat the document as an instruction surface and review it "
            "by hand \u2014 v1 does not follow the reference hop."
        ),
        false_positives=(
            "By construction, most of these are false positives: that is why they are "
            "LOW and opt-in. The residual risk runs the other way \u2014 a payload hidden "
            "in a document that a SKILL.md points the agent at lands here rather than in "
            "FLAGGED."
        ),
        applies_to=_ALL_KINDS,
    ),
    # ----------------------------------------------------------------------- baseline
    _rule(
        id="BASELINE_DRIFT",
        severity=Severity.MEDIUM,
        title="A known bundle changed since the accepted baseline",
        category="baseline",
        module="malskill.baseline",
        trigger=(
            "A file's sha256 differs from the accepted baseline, or a new file appeared "
            "inside a bundle that the baseline already knows about."
        ),
        why=(
            "The realistic attack is not a new evil bundle you would scrutinise — it is a "
            "bundle you already trusted going bad in an update."
        ),
        recommendation=(
            "Diff the changed file against what you accepted before. Run "
            "'malskill baseline update' only after you have read the change."
        ),
        false_positives=(
            "Ordinary updates you performed yourself, and caches or logs written inside a "
            "bundle directory."
        ),
        applies_to=_ALL_KINDS,
    ),
    _rule(
        id="BASELINE_NEW_TARGET",
        severity=Severity.LOW,
        title="A bundle appeared that the baseline has never seen",
        category="baseline",
        module="malskill.baseline",
        trigger="A target exists that is absent from the accepted baseline.",
        why=(
            "Informational, but named on purpose: installs should never land silently. "
            "This is how you notice something you did not install."
        ),
        recommendation=(
            "Confirm you installed it. If you did, accept it with "
            "'malskill baseline update'; if not, remove it."
        ),
        false_positives=(
            "Every bundle you install intentionally fires this exactly once."
        ),
        applies_to=_ALL_KINDS,
    ),
    _rule(
        id="BASELINE_TAMPERED",
        severity=Severity.HIGH,
        title="The baseline file's self-checksum does not match its contents",
        category="baseline",
        module="malskill.baseline",
        trigger=(
            "~/.malskill/baseline.json (or --home equivalent) fails its embedded "
            "self-checksum, or is structurally invalid."
        ),
        why=(
            "Editing the baseline is how an attacker makes a modified bundle look "
            "unchanged. A broken checksum means drift detection cannot be trusted."
        ),
        recommendation=(
            "Delete the baseline, review every installed bundle by hand, then re-create "
            "the baseline with 'malskill baseline update'."
        ),
        false_positives=(
            "Hand-editing the baseline file, or a baseline written by a different version "
            "of the scanner."
        ),
        applies_to=_ALL_KINDS,
    ),
]

#: finding-ID -> :class:`Rule`. The single source of truth for severity floors.
REGISTRY: Dict[str, Rule] = {rule.id: rule for rule in _RULES}

#: IDs that produce real findings (excludes NOT-FULLY-ANALYZED-only IDs).
FINDING_IDS: Tuple[str, ...] = tuple(
    r.id for r in _RULES if r.emits == "finding"
)

#: Every registered ID, in registry order.
ALL_IDS: Tuple[str, ...] = tuple(r.id for r in _RULES)


def rule_for(finding_id: str) -> Optional[Rule]:
    """Return the registry entry for a finding ID (or ``None``)."""
    return REGISTRY.get(finding_id)


def severity_floor(finding_id: str) -> Severity:
    """Severity floor for a finding ID; MEDIUM for unknown IDs (never silently LOW)."""
    rule = REGISTRY.get(finding_id)
    return rule.severity if rule is not None else Severity.MEDIUM


#: Hard cap on the evidence carried by any finding, from the blueprint's data model.
MAX_EVIDENCE_CHARS = 400


def make_finding(
    finding_id: str,
    *,
    target: str,
    kind: str,
    file: Optional[str] = None,
    line: Optional[int] = None,
    evidence: str = "",
    why: str = "",
    recommendation: str = "",
    severity: Optional[Severity] = None,
) -> Finding:
    """Build a Finding with the registry's severity floor and default texts applied.

    Evidence is passed through the display sanitizer here rather than trusting every
    rule to remember: it is the last point before a raw-derived snippet can reach a
    terminal, and the 400-character cap is part of the published data model. The
    sanitizer is idempotent, so rules that already defanged their own evidence are
    unaffected.
    """
    from malskill.sanitize import for_display  # local: keeps this module cycle-free

    rule = REGISTRY.get(finding_id)
    sev = severity or severity_floor(finding_id)
    if rule is not None and sev.rank < rule.severity.rank:
        sev = rule.severity  # the floor is a floor
    return Finding(
        id=finding_id,
        severity=sev,
        target=target,
        kind=kind,
        file=file,
        line=line,
        evidence=for_display(evidence, MAX_EVIDENCE_CHARS),
        why=why or (rule.why if rule else ""),
        recommendation=recommendation or (rule.recommendation if rule else ""),
    )
