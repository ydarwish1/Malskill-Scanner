"""MCP config rules — the servers that load into every session.

Rationale
---------
An MCP server entry is three fields (``command``, ``args``, ``env``) that nobody looks at
after the day they paste it in, and every one of them starts a process with the user's
privileges each time the client launches.

MCP_RUNTIME_REMOTE_CODE
    The launch command fetches code and executes it. Whatever the URL serves *today* runs
    today. Crucially, plain ``npx``/``uvx``/``docker`` of a named package is **not** a
    finding: that is how essentially every real MCP server is started, and flagging it
    would produce the wall of noise the README exists to prevent.

MCP_SECRET_BROADCAST
    A real secret (not ``${VAR}``, not ``your-key-here``) written literally into the env
    block of a server that runs an unpinned remote package. The secret is handed to
    whatever version the registry serves next; one malicious or hijacked release reads it
    straight out of the environment. Reported at MEDIUM because it is a supply-chain
    exposure rather than proof of compromise. **Secret values are never printed** — the
    evidence shows the variable name and a masked value.

MCP_UNPARSEABLE_CONFIG
    Registered in the rule registry but emitted as a NOT-FULLY-ANALYZED record rather
    than a finding: the scanner says "I could not read this", which is the honest state,
    instead of leaving a silent gap.

False-positive analysis
-----------------------
* *A bootstrap script on a host you control* fires MCP_RUNTIME_REMOTE_CODE. The finding
  names the URL so the judgement is quick.
* *Long non-secret identifiers* in a ``*_KEY`` variable (a project id, a model name) can
  trip MCP_SECRET_BROADCAST. The placeholder filter removes the obvious cases and the
  masked evidence makes the rest easy to dismiss.
* *Pinned packages* (``pkg@1.2.3``) are exempt from MCP_SECRET_BROADCAST: pinning is the
  mitigation the finding asks for.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Pattern, Tuple

from malskill.rules import Finding, make_finding
from malskill.rules.patterns import hosts_in
from malskill.rules.r_pipe_to_shell import PIPE_PATTERNS
from malskill.sanitize import for_display

RULE_IDS = ("MCP_RUNTIME_REMOTE_CODE", "MCP_SECRET_BROADCAST", "MCP_UNPARSEABLE_CONFIG")

# ------------------------------------------------------------------ remote code at launch

_FETCH_RE = re.compile(r"(?<![\w-])(?:curl|wget|Invoke-WebRequest|iwr)\b")
_SHELL_WRAPPER_RE = re.compile(r"(?<![\w-])(?:sh|bash|zsh|ksh|dash)\s+-c\b")
_NODE_EVAL_RE = re.compile(r"(?<![\w-])node(?:js)?\s+(?:-e|--eval)\b")
_PY_EVAL_RE = re.compile(r"(?<![\w-])python3?\s+-c\b")
_NET_IN_CODE_RE = re.compile(
    r"fetch\s*\(|https?://|urllib|requests\.|http\.client|socket\.|net\.connect"
)

REMOTE_CODE_CHECKS: List[Tuple[str, Pattern]] = list(PIPE_PATTERNS)


def _command_line(config: Dict[str, Any]) -> str:
    command = str(config.get("command", "") or "")
    args = config.get("args", []) or []
    if isinstance(args, (list, tuple)):
        arg_text = " ".join(str(a) for a in args)
    else:
        arg_text = str(args)
    url = str(config.get("url", "") or "")
    return " ".join(part for part in (command, arg_text, url) if part).strip()


def _remote_code_reason(cmdline: str) -> str:
    for label, pattern in REMOTE_CODE_CHECKS:
        if pattern.search(cmdline):
            return label
    if _SHELL_WRAPPER_RE.search(cmdline) and _FETCH_RE.search(cmdline):
        return "shell wrapper around a network download"
    if _NODE_EVAL_RE.search(cmdline) and _NET_IN_CODE_RE.search(cmdline):
        return "inline node script that downloads and evaluates code"
    if _PY_EVAL_RE.search(cmdline) and _NET_IN_CODE_RE.search(cmdline):
        return "inline python script that downloads and executes code"
    stripped = cmdline.strip()
    if re.match(r"^(?:/\S+/)?(?:curl|wget)\b", stripped):
        return "server binary is a downloader"
    return ""


# ---------------------------------------------------------------------- secret broadcast

_SECRET_KEY_RE = re.compile(
    r"(?:^|_)(?:KEY|TOKEN|SECRET|PASSWORD|PASSWD|PWD|CREDENTIAL|CREDENTIALS|APIKEY|"
    r"ACCESS_KEY|PRIVATE_KEY|AUTH)(?:$|_)|API_?KEY|_TOKEN|_SECRET|_PASSWORD",
    re.I,
)
_PLACEHOLDER_RE = re.compile(
    r"^\s*(?:\$\{[^}]*\}|\$[A-Za-z_][\w]*|<[^>]*>|\{\{[^}]*\}\}|%[\w]+%|"
    r"(?:your|my|the)[-_ ]?\w*(?:[-_ ]?(?:key|token|secret|password|here))?|"
    r"x{3,}|\.{3,}|\*{3,}|changeme|placeholder|todo|tbd|example\w*|test|dummy|fake|"
    r"insert[-_ ]?\w*|replace[-_ ]?\w*|sk-xxx\w*|abc123|none|null|unset)\s*$",
    re.I,
)
_UNPINNED_RE = re.compile(
    r"(?<![\w-])(?:npx|bunx|pnpx|pnpm\s+dlx|yarn\s+dlx|uvx|pipx\s+run)\b|@latest\b|:latest\b"
)
_PINNED_RE = re.compile(r"@\d+\.\d+(?:\.\d+)?|==\d+\.\d+|:\d+\.\d+|--from\s+\S+==")


def _looks_like_real_secret(key: str, value: str) -> bool:
    if not isinstance(value, str):
        return False
    value = value.strip()
    if len(value) < 8:
        return False
    if "${" in value or value.startswith("$"):
        return False
    if _PLACEHOLDER_RE.match(value):
        return False
    if len(set(value)) <= 2:
        return False
    return bool(_SECRET_KEY_RE.search(key))


def _mask(value: str) -> str:
    if len(value) <= 4:
        return "*" * len(value)
    return "%s%s (%d chars)" % (value[:2], "*" * 8, len(value))


# ------------------------------------------------------------------------------- check


def check(target) -> List[Finding]:
    kind = getattr(target.kind, "value", str(target.kind))
    if kind not in ("mcp-server", "mcp-config"):
        return []

    config = target.meta.get("config") or {}
    if not isinstance(config, dict):
        return []

    findings: List[Finding] = []
    source = target.meta.get("source_file", "")
    cmdline = _command_line(config)

    reason = _remote_code_reason(cmdline) if cmdline else ""
    if reason:
        hosts = hosts_in(cmdline)
        destination = hosts[0] if hosts else "an unresolved URL"
        findings.append(
            make_finding(
                "MCP_RUNTIME_REMOTE_CODE",
                target=target.display,
                kind=kind,
                file=source or None,
                evidence=for_display(cmdline),
                why=(
                    "The launch command for this MCP server is a %s (%s). The server "
                    "starts with every session, so whatever %s serves at that moment is "
                    "fetched and executed again — the config you reviewed does not "
                    "determine the code that runs."
                    % (reason, for_display(cmdline, 160), for_display(destination, 100))
                ),
                recommendation=(
                    "Remove this server from %s, or replace it with a pinned package "
                    "version that is installed ahead of time and can be reviewed."
                    % (source or "the MCP config")
                ),
            )
        )

    env = config.get("env") or {}
    if isinstance(env, dict) and env:
        unpinned = bool(_UNPINNED_RE.search(cmdline)) and not _PINNED_RE.search(cmdline)
        if unpinned:
            leaked = [
                (key, value)
                for key, value in env.items()
                if _looks_like_real_secret(str(key), value)
            ]
            if leaked:
                names = ", ".join(key for key, _ in leaked[:4])
                findings.append(
                    make_finding(
                        "MCP_SECRET_BROADCAST",
                        target=target.display,
                        kind=kind,
                        file=source or None,
                        evidence="; ".join(
                            "%s=%s" % (key, _mask(str(value)))
                            for key, value in leaked[:4]
                        ),
                        why=(
                            "Literal secret value(s) (%s) are handed to an unpinned remote "
                            "package (%s). Every launch runs whatever version the registry "
                            "serves, and that code reads these variables directly out of "
                            "its environment."
                            % (names, for_display(cmdline, 120))
                        ),
                        recommendation=(
                            "Pin the package to an exact version and replace the literal "
                            "value(s) for %s with an environment reference (${VAR}) so the "
                            "secret is not stored in the config file." % names
                        ),
                    )
                )
    return findings
