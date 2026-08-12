"""CREDENTIAL_PATH_ACCESS — secrets touched, no way out found (yet).

Rationale
---------
The CRITICAL case is handled by SENSITIVE_READ_PLUS_EGRESS. This rule covers the leftover:
a bundle that reads credential paths but contains no network egress at all. That is not
theft on its own, but it is still worth a human look, because the agent is the egress
path — a secret read into the transcript leaves the machine by a route this scanner
cannot see.

It is MEDIUM on purpose. Reporting it as HIGH would flood the report and destroy the
signal-to-noise ratio the README demands.

Mismatch principle, applied as a suppression
--------------------------------------------
A bundle whose declared purpose *is* credential management — SSH helpers, GPG wrappers,
keychain tools, dotenv loaders, auth utilities — is not mismatched when it reads
credentials, so it is suppressed entirely. This is the same principle as the network
rules, in the other direction: fire on contradiction, stay quiet on consistency.

False-positive analysis
-----------------------
* *Dotfile managers and .env loaders* are the main source. The purpose suppression
  removes most; the rest are one line of evidence away from being dismissed.
* *Documentation examples* (``cp ~/.ssh/id_rsa.pub …``) in prose are excluded — markdown
  fires only inside fenced code blocks.
* *A path mentioned as something the bundle refuses to touch* will still fire. That is
  accepted at MEDIUM: the scanner does not try to read intent from prose.
* Findings are capped at one per (label, file) pairing so a credential helper cannot
  produce fifty rows.
* *Documentation, tests and binary assets do not count.* A CHANGELOG entry naming
  ``~/.aws/credentials`` is not a read; the reference is banked as a suppressed hit and
  counted in the report instead (see :mod:`malskill.roles`).
"""

from __future__ import annotations

from typing import Dict, List, Tuple

from malskill.rules import Finding, make_finding
from malskill.rules.patterns import (
    actionable_egress,
    actionable_hits,
    executable_context,
    find_egress_in_target,
    find_sensitive_in_target,
    is_data_file,
    is_warning_context,
)
from malskill.sanitize import for_display

RULE_IDS = ("CREDENTIAL_PATH_ACCESS",)

#: Cap so one dotfile manager cannot dominate a report.
_MAX_FINDINGS = 3


def check(target) -> List[Finding]:
    claims = getattr(target, "claims", None)
    if claims is not None and claims.credential_purpose:
        # A credential manager touching credentials is consistent, not a mismatch.
        return []

    sensitive = [
        h
        for h in actionable_hits(
            target,
            "CREDENTIAL_PATH_ACCESS",
            find_sensitive_in_target(target, text_only=True),
        )
        if executable_context(h)
        and not is_warning_context(h)
        and not is_data_file(h.file_rel)
        and not h.file_rel.lower().endswith(".json")
    ]
    if not sensitive:
        return []

    # Any egress at all (even localhost-only) means the exfil rule owns this bundle.
    # Gated to the same roles, so a curl in a README does not silently make a real
    # credential read in a script disappear from both rules at once.
    if actionable_egress(
        target, "CREDENTIAL_PATH_ACCESS", find_egress_in_target(target, text_only=True)
    ):
        return []

    seen: Dict[Tuple[str, str], bool] = {}
    findings: List[Finding] = []
    for hit in sensitive:
        key = (hit.label, hit.file_rel)
        if key in seen:
            continue
        seen[key] = True
        where = "%s:%d" % (hit.file_rel, hit.line)
        findings.append(
            make_finding(
                "CREDENTIAL_PATH_ACCESS",
                target=target.display,
                kind=target.kind.value,
                file=hit.file_rel,
                line=hit.line,
                evidence=for_display(hit.context),
                why=(
                    "This %s references %s at %s and declares no purpose that would need "
                    "it. No network egress was found in the bundle, so this is not "
                    "exfiltration on its own — but the agent reading a secret into a "
                    "session is itself a disclosure path."
                    % (target.kind.value, hit.label, where)
                ),
                recommendation=(
                    "Read %s and decide whether reading %s is part of the job you "
                    "installed this %s for. If it is not, remove the bundle."
                    % (where, hit.label, target.kind.value)
                ),
            )
        )
        if len(findings) >= _MAX_FINDINGS:
            break
    return findings
