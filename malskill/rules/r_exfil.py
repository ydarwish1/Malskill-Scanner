"""SENSITIVE_READ_PLUS_EGRESS — read a secret, and be able to send it somewhere.

Rationale
---------
This is the shape of credential theft, and it is a shape rather than a keyword. Reading
``~/.ssh/id_ed25519`` is normal for an SSH helper. Running ``curl`` is normal for a
downloader. The same bundle doing both, with your agent's privileges and usually with no
tool restrictions declared, is an exfiltration pipeline — and it is the single highest
consequence finding this scanner can produce, so its floor is CRITICAL.

The rule pairs two independent matchers over the raw bytes of one bundle:

* a sensitive-path reference (SSH/AWS/GnuPG/netrc/.env/keychain/browser stores/
  ``~/.claude.json``/cloud tokens/wallets/shell history, or a bulk environment dump), and
* a network egress primitive that is not provably localhost-only.

Not all secrets are equally meaningful, so the pairing is graded:

* **Unambiguous secrets** (SSH keys, ``~/.aws/credentials``, GnuPG, ``.netrc``, keychain,
  browser stores, wallets, ``~/.claude.json``, shell history) pair with egress anywhere
  in the bundle when the read sits in executable context, and within 60 lines of each
  other in a single file regardless of context.
* **Everyday development secrets** (``.env`` files, generic credential files, npm/PyPI/
  kube/docker token stores, bulk environment dumps) are mentioned constantly in ordinary
  content, so they pair only in code, only within five lines of the egress, and never on
  a line that is simply *loading* configuration (``source .env``, ``load_dotenv``,
  ``--exclude='.env'``).

Data and asset files (``.csv``, ``.html``, ``.svg``, minified bundles) are excluded on
both sides: a CSV listing framework best practices contains ``.env`` and ``fetch(``
without doing either.

False-positive analysis
-----------------------
* *Deliberate credential tooling* (an SSH key uploader, an AWS profile sync, a secrets
  manager) genuinely does both, and will fire. It is reported with the exact file and
  line pair so a human can confirm in seconds; suppressing it by purpose here would let
  any bundle claim to be a credential manager and go quiet.
* *A skill that reads ``~/.claude.json`` for an API key and then calls that API* fires,
  because that file also holds session credentials.
* *Localhost-only destinations* are exempt: sending to 127.0.0.1 is not exfiltration.
  That exemption now covers the bare spelling too (``curl localhost:3000``), which is by
  far the commonest one and which used to slip through because it carries no URL.
* *Binary blobs never participate.* This was a real defect: on one machine a keychain
  read in ``scripts/setup-keychain.sh`` was paired with the byte sequence ``nc`` found
  inside ``assets/claude-code-rap.mp3``, producing a CRITICAL. Random bytes match short
  patterns by chance; a file the scanner cannot read as text can never be evidence of
  behaviour. Binary files are still reported as NOT-FULLY-ANALYZED.
* *Roles gate both halves.* A credential read in a script paired with an installer
  ``curl`` quoted in an unrelated README of the same 4,000-file bundle is not a pipeline,
  it is two unrelated facts. Both halves must come from an EXECUTABLE or INSTRUCTION file
  (see :mod:`malskill.roles`); everything else is banked as a suppressed hit and counted
  in the report.
* *Comments are not operations.* ``// and ``~/.claude.json``, which are somebody's actual
  projects`` is a sentence about a path, not a read of it, and ``# curl …`` is a line the
  shell never runs. Both halves must sit on a line that is not a comment.
* *Hooks* are handed to HOOK_EXFIL instead of being reported twice.
"""

from __future__ import annotations

import re
from typing import List

from malskill.rules import Finding, make_finding
from malskill.rules.patterns import (
    HARD_SENSITIVE_LABELS,
    actionable_egress,
    actionable_hits,
    executable_context,
    find_egress_in_target,
    find_sensitive_in_target,
    has_nonlocal_egress,
    is_comment_line,
    is_data_file,
    is_warning_context,
)
from malskill.sanitize import for_display

RULE_IDS = ("SENSITIVE_READ_PLUS_EGRESS",)


def _hook_rule_owns(target) -> bool:
    """True when HOOK_EXFIL already covers this target at the same severity.

    Hooks receive the full byte-rule pass, so without this a single malicious hook
    would be reported twice as CRITICAL. HOOK_EXFIL is the more specific finding and
    carries the hook-specific wording, so it wins.
    """
    if getattr(target.kind, "value", str(target.kind)) != "hook":
        return False
    from malskill.rules.patterns import search_target
    from malskill.rules.r_hooks import SESSION_DATA_PATTERNS

    return bool(search_target(target, SESSION_DATA_PATTERNS))


#: How far apart (in lines) a read and a send may sit and still be treated as one
#: operation. Beyond this, a ".env" in a changelog and a "curl" 1400 lines later are two
#: unrelated facts, not an exfiltration pipeline.
MAX_PAIR_DISTANCE = 60

#: Soft labels (.env files, token stores, environment dumps) appear constantly in
#: ordinary development content, so they must sit within a handful of lines of the
#: egress to count as one operation.
MAX_SOFT_PAIR_DISTANCE = 5

#: Lines that *load* configuration rather than read a secret out to somewhere else.
#: "source .env && curl https://api…" is how every API-backed skill starts; treating it
#: as exfiltration would flag half the ecosystem and teach the reader to skim.
_ENV_LOAD_RE = re.compile(
    r"(?:^|[;&|]|\s)(?:source|\.)\s+[^\n]*\.env|load_dotenv|dotenv|require\([\"']dotenv|"
    r"env\s+pull|--exclude=|\.env\.example|\.env\.sample|\.env\.template|"
    r"gitignore|\.env\.local[\"'`]?\s*$",
    re.I,
)


def check(target) -> List[Finding]:
    if _hook_rule_owns(target):
        return []

    all_sensitive = [
        h
        for h in actionable_hits(
            target,
            "SENSITIVE_READ_PLUS_EGRESS",
            find_sensitive_in_target(target, text_only=True),
        )
        if not is_warning_context(h)
        and not is_data_file(h.file_rel)
        and not is_comment_line(h.line_text)
    ]
    hard_hits = [h for h in all_sensitive if h.label in HARD_SENSITIVE_LABELS]
    soft_hits = [
        h
        for h in all_sensitive
        if h.label not in HARD_SENSITIVE_LABELS
        and executable_context(h)
        and not _ENV_LOAD_RE.search(h.line_text)
    ]
    all_sensitive = hard_hits + soft_hits
    if not all_sensitive:
        return []

    egress = [
        e
        for e in actionable_egress(
            target,
            "SENSITIVE_READ_PLUS_EGRESS",
            find_egress_in_target(target, text_only=True),
        )
        if not is_warning_context(e.hit)
        and not is_data_file(e.hit.file_rel)
        and not is_comment_line(e.hit.line_text)
    ]
    external = has_nonlocal_egress(egress)
    if not external:
        return []

    # Pairing rules, tightest first:
    #  * same file and within MAX_PAIR_DISTANCE lines  -> one operation, any label;
    #  * different files                               -> only unambiguous secrets
    #    (SSH/AWS/GnuPG/keychain/browser stores) read from code, because ".env"
    #    mentioned in a README and an unrelated curl in a script are not a pipeline.
    pair = None
    for hit in all_sensitive:
        limit = (
            MAX_PAIR_DISTANCE
            if hit.label in HARD_SENSITIVE_LABELS
            else MAX_SOFT_PAIR_DISTANCE
        )
        for egress_hit in external:
            if (
                egress_hit.hit.file_rel == hit.file_rel
                and abs(egress_hit.hit.line - hit.line) <= limit
            ):
                pair = (hit, egress_hit)
                break
        if pair:
            break
    if pair is None:
        hard = [
            h
            for h in all_sensitive
            if h.label in HARD_SENSITIVE_LABELS and executable_context(h)
        ]
        if not hard:
            return []
        pair = (hard[0], external[0])

    read_hit, send_hit = pair
    destination = send_hit.destination or "an unresolved destination"
    read_where = "%s:%d" % (read_hit.file_rel, read_hit.line)
    send_where = "%s:%d" % (send_hit.hit.file_rel, send_hit.hit.line)
    labels = sorted({h.label for h in all_sensitive}) or [read_hit.label]

    if read_where == send_where:
        evidence = 'reads %s and sends, @ %s: %s' % (
            read_hit.label,
            read_where,
            for_display(read_hit.context, 260),
        )
    else:
        evidence = 'reads %s @ %s: %s || sends @ %s: %s' % (
            read_hit.label,
            read_where,
            for_display(read_hit.context, 150),
            send_where,
            for_display(send_hit.hit.context, 150),
        )

    return [
        make_finding(
            "SENSITIVE_READ_PLUS_EGRESS",
            target=target.display,
            kind=target.kind.value,
            file=read_hit.file_rel,
            line=read_hit.line,
            evidence=evidence,
            why=(
                "This %s touches %s (%s) and also contains a network egress primitive "
                "(%s at %s) pointing at %s. Read-a-secret plus send-it-somewhere, inside "
                "one bundle that runs with your agent's privileges, is the exact shape of "
                "credential theft."
                % (
                    target.kind.value,
                    ", ".join(labels),
                    read_where,
                    send_hit.hit.label,
                    send_where,
                    for_display(destination, 120),
                )
            ),
            recommendation=(
                "Remove this %s: it reads %s and can post to %s. Then rotate anything it "
                "could have reached — SSH keys, cloud credentials, API tokens on those "
                "paths — because you cannot tell from here whether it already ran."
                % (
                    target.kind.value,
                    labels[0],
                    for_display(destination, 120),
                )
            ),
        )
    ]
