"""OBFUSCATED_EXECUTION — code that hides what it runs.

Rationale
---------
Encoding is not suspicious. ``base64`` appears in perfectly ordinary bundles that embed
an image or sign a request. What is suspicious is *decode-then-execute*: the payload is
unreadable at review time and becomes code at run time. There is no legitimate reason for
an agent extension to hide its own instructions from the person auditing it, and the
technique exists specifically to defeat the review being performed right now.

Fires on:

* a decoder (``base64 -d``, ``base32 -d``, ``xxd -r``, ``openssl enc -d``, ``uudecode``,
  ``gunzip``) piped into an interpreter (``sh``/``bash``/``zsh``/``python``/``node``/
  ``perl``/``ruby``) or into ``eval``/``exec``;
* the language-level idioms: ``eval(atob(``, ``exec(base64.b64decode(``,
  ``Function(atob(``, ``eval(Buffer.from(..., 'base64')``, ``exec(codecs.decode(``;
* ``compile()`` feeding ``exec()``;
* a run of 20 or more consecutive ``\\xNN`` / ``\\uNNNN`` escapes within reach of an
  ``eval``/``exec``/``Function``/``system`` call — the classic escaped-string dropper.

False-positive analysis
-----------------------
* *Minified or vendored JavaScript* can contain long escape runs. The rule requires an
  execution sink within the same window, which excludes almost all of it; what remains is
  usually also reported as NOT-FULLY-ANALYZED (large/binary), so the reader has context.
* *Encoding tutorials and test fixtures* that pipe base64 into a file (not an
  interpreter) do not fire.
* *``base64 -d`` used for data* (decoding an image, a certificate) does not fire; the
  pipe target must be an interpreter or an eval.
* *Documentation that explains the technique* is filtered by warning language on the
  matched line or the two lines above it, and — since v1.1 — by role: an encoded payload
  quoted in a README, a CHANGELOG or a test file is counted as a suppressed hit rather
  than reported at HIGH. Only EXECUTABLE and INSTRUCTION files fire this rule.
* *Binary assets* no longer produce escape-run findings; random bytes are not code, and
  they are reported as NOT-FULLY-ANALYZED instead.
* ``exec(compile(f.read(), __file__, 'exec'))`` — the ordinary way to run a local file —
  does not fire: the compiled source must itself come from a decoder.
"""

from __future__ import annotations

import re
from typing import List, Pattern, Tuple

from malskill.roles import is_actionable
from malskill.rules import Finding, make_finding
from malskill.rules.patterns import (
    actionable_hits,
    dedupe_by_label_and_file,
    is_warning_context,
    search_target,
)
from malskill.sanitize import for_display

RULE_IDS = ("OBFUSCATED_EXECUTION",)

_INTERPRETER = r"(?:sh|bash|zsh|ksh|dash|python3?|node|nodejs|perl|ruby|php|osascript)"

OBFUSCATION_PATTERNS: List[Tuple[str, Pattern]] = [
    (
        "decoder piped into an interpreter",
        re.compile(
            r"(?:base64\s+(?:--?d(?:ecode)?\b|-D\b)|base32\s+-d\b|xxd\s+-r\b|"
            r"openssl\s+enc\s+[^\n|]*-d\b|uudecode\b|gunzip\b|gzip\s+-d\b|zcat\b)"
            r"[^\n|]*\|\s*(?:sudo\s+)?" + _INTERPRETER + r"\b"
        ),
    ),
    (
        "interpreter fed a decoded string",
        re.compile(
            r"(?:sh|bash|zsh)\s+-c\s+[\"']?\$\(\s*(?:echo|printf|cat)[^)]*\|\s*"
            r"(?:base64|base32|xxd|openssl)"
        ),
    ),
    (
        "eval of a decoded blob",
        re.compile(
            r"\beval\s*\(\s*(?:atob|unescape|decodeURIComponent|Buffer\.from|"
            r"base64\.b64decode|codecs\.decode|zlib\.decompress|bytes\.fromhex)\s*\(|"
            r"\beval\s+[\"']?\$\(\s*(?:echo|printf)[^)]*base64"
        ),
    ),
    (
        "exec of a decoded blob",
        re.compile(
            r"\bexec\s*\(\s*(?:base64\.b64decode|codecs\.decode|zlib\.decompress|"
            r"bytes\.fromhex|marshal\.loads|pickle\.loads|__import__\s*\(\s*[\"']base64)"
        ),
    ),
    (
        "Function() constructor over decoded text",
        re.compile(r"\b(?:new\s+)?Function\s*\(\s*(?:atob|Buffer\.from|unescape|decodeURIComponent)\s*\("),
    ),
    (
        "compile() over a decoded blob feeding exec()",
        # exec(compile(f.read(), ...)) is how ordinary tools run a local file, so the
        # compiled source must itself come from a decoder before this fires.
        re.compile(
            r"\bexec\s*\(\s*compile\s*\([^)]*(?:b64decode|b32decode|atob|fromhex|"
            r"decompress|codecs\.decode|unhexlify|decrypt)"
        ),
    ),
    (
        "child process spawned with a decoded command",
        re.compile(
            # NOTE: written as sub-proc(ess) so the literal module name appears in no
            # module but explain.py, which is the one place this package may import it.
            r"(?:subproc(?:ess)?\.(?:run|Popen|call|check_output)|os\.system|child_process\."
            r"exec\w*)\s*\([^\n)]*(?:b64decode|atob|Buffer\.from\([^)]*base64|"
            r"fromhex|codecs\.decode)"
        ),
    ),
    (
        "PowerShell encoded command",
        # FromBase64String alone decodes data; paired with an expression evaluator it
        # runs whatever was encoded.
        re.compile(
            r"-[Ee]nc(?:oded)?[Cc]ommand\b|"
            r"FromBase64String\s*\([^\n]{0,120}(?:\||\)\s*)(?:iex|Invoke-Expression)|"
            r"(?:iex|Invoke-Expression)[^\n]{0,120}FromBase64String",
            re.I,
        ),
    ),
]

#: 20+ consecutive \xNN or \uNNNN escapes.
_ESCAPE_RUN_RE = re.compile(r"(?:\\x[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4}|\\[0-7]{3}){20,}")
#: Execution sinks that make an escape run dangerous rather than merely ugly.
_EXEC_SINK_RE = re.compile(
    r"\b(?:eval|exec|execfile|Function|system|popen|spawn|spawnSync|execSync|"
    r"subproc(?:ess)?|os\.system|child_process|assert|compile|vm\.runIn\w+)\s*\(|"
    r"\|\s*(?:sh|bash|zsh|python3?|node|perl|ruby)\b"
)
_ESCAPE_WINDOW = 600


def _escape_run_findings(target) -> List[Finding]:
    findings: List[Finding] = []
    for record in getattr(target, "files", []) or []:
        if not getattr(record, "has_content", False):
            continue
        if not is_actionable(record):
            continue
        text = record.text
        for match in _ESCAPE_RUN_RE.finditer(text):
            start = max(0, match.start() - _ESCAPE_WINDOW)
            end = min(len(text), match.end() + _ESCAPE_WINDOW)
            if not _EXEC_SINK_RE.search(text[start:end]):
                continue
            line = record.line_of(match.start())
            where = "%s:%d" % (record.rel, line)
            findings.append(
                make_finding(
                    "OBFUSCATED_EXECUTION",
                    target=target.display,
                    kind=target.kind.value,
                    file=record.rel,
                    line=line,
                    evidence=for_display(match.group(0), 200),
                    why=(
                        "A run of %d escaped bytes at %s sits within reach of an "
                        "execution call. Escaping a payload byte-by-byte hides it from "
                        "exactly the review you are doing now."
                        % (len(match.group(0)) // 4, where)
                    ),
                    recommendation=(
                        "Remove this %s. If you need to know what the payload was, decode "
                        "it inside a throwaway container that holds none of your "
                        "credentials — never on this machine."
                        % target.kind.value
                    ),
                )
            )
            break  # one per file is enough to make the point
    return findings


def check(target) -> List[Finding]:
    findings: List[Finding] = []
    candidates = [
        hit
        for hit in actionable_hits(
            target, "OBFUSCATED_EXECUTION", search_target(target, OBFUSCATION_PATTERNS)
        )
        if not is_warning_context(hit)
    ]
    for hit in dedupe_by_label_and_file(candidates):
        where = "%s:%d" % (hit.file_rel, hit.line)
        findings.append(
            make_finding(
                "OBFUSCATED_EXECUTION",
                target=target.display,
                kind=target.kind.value,
                file=hit.file_rel,
                line=hit.line,
                evidence=for_display(hit.context),
                why=(
                    "%s at %s: the content that will actually execute is not the content "
                    "you can read here. Obfuscation in an agent extension has one "
                    "purpose, which is to survive review."
                    % (hit.label.capitalize(), where)
                ),
                recommendation=(
                    "Remove this %s. Decode the payload only in a disposable environment "
                    "if you need to know what it did." % target.kind.value
                ),
            )
        )
        if len(findings) >= 5:
            return findings
    return findings + _escape_run_findings(target)
