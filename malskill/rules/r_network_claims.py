"""NETWORK_IN_OFFLINE_CLAIM — the bundle's own description contradicts its code.

Rationale
---------
Measured on a real machine, ``curl`` appears in 284 of 867 installed bundles. A rule that
fires on ``curl`` fires 284 times and gets ignored within a week, and the one bundle that
matters scrolls past. So this rule never fires on the primitive alone. It fires on the
*contradiction*: the bundle told you it works offline, and then it reaches a host on the
internet. The lie is the signal, not the tool.

Two firing branches, both requiring egress that is not provably localhost-only:

1. ``claims_offline`` — the description explicitly says offline / local-only / no network,
   and no network intent is declared anywhere. Strongest branch.
2. ``not declares_network`` **and** the purpose is local-ish (formatting, docs, analysis)
   **and** a literal non-local URL is present. Weaker branch, so it demands an actual
   destination rather than an unresolved variable.

False-positive analysis
-----------------------
* *Version/update checks bolted onto a local tool.* These do fire. That is intended: a
  "fully offline" formatter that phones home on every run is exactly the mismatch a user
  should be told about, even when the intent is benign.
* *Documentation prose quoting a curl command.* Suppressed when the line, or the two
  lines above it, carry warning language ("never", "do not run", "example of an attack").
  Prose is otherwise scanned, because a SKILL.md body is read by the agent as an
  instruction.
* *Data files* (``.csv``, ``.html``, ``.svg``, minified bundles) are excluded: a CSV of
  framework notes containing ``fetch(`` is content, not behaviour.
* *Local dev servers.* ``curl http://localhost:8000``, ``curl localhost:3000`` and
  127.0.0.1/0.0.0.0/::1/*.local targets are exempt by construction, with or without a
  URL scheme.
* *Documentation, tests and binary assets.* Egress found in a README, a CHANGELOG, a
  test file or the raw bytes of an asset is not behaviour; it is banked as a suppressed
  hit and counted in the report (see :mod:`malskill.roles`).
* *Bundles with no description at all.* Branch 2 requires a local-ish declared purpose,
  so an undescribed bundle does not fire here; other rules cover it.
* *The word "offline" inside a description that also mentions an API.* ``claims_offline``
  is cancelled by any network declaration, because ambiguity is not deception.
"""

from __future__ import annotations

from typing import List

from malskill.rules import Finding, make_finding
from malskill.rules.patterns import (
    actionable_egress,
    find_egress_in_target,
    has_nonlocal_egress,
    is_data_file,
    is_warning_context,
)
from malskill.sanitize import for_display

RULE_IDS = ("NETWORK_IN_OFFLINE_CLAIM",)

#: Purposes weak enough that undeclared network access is a mismatch.
_LOCAL_PURPOSES = ("local",)


def check(target) -> List[Finding]:
    claims = getattr(target, "claims", None)
    if claims is None:
        return []

    egress = [
        e
        for e in actionable_egress(
            target,
            "NETWORK_IN_OFFLINE_CLAIM",
            find_egress_in_target(target, text_only=True),
        )
        if not is_warning_context(e.hit) and not is_data_file(e.hit.file_rel)
    ]
    external = has_nonlocal_egress(egress)
    if not external:
        return []

    with_destination = [e for e in external if e.nonlocal_hosts]

    reason = ""
    if claims.claims_offline:
        reason = (
            "the bundle describes itself as %r, but it reaches the network"
            % claims.offline_phrase.strip()
        )
        chosen = with_destination or external
    elif (
        not claims.declares_network
        and claims.purpose_category in _LOCAL_PURPOSES
        and with_destination
    ):
        reason = (
            "the bundle describes local-only work and never declares network use, "
            "yet it contacts an external host"
        )
        chosen = with_destination
    else:
        return []

    hit = chosen[0]
    destination = hit.destination or "an unresolved destination"
    evidence = for_display(hit.hit.context)
    where = "%s:%d" % (hit.hit.file_rel, hit.hit.line)

    return [
        make_finding(
            "NETWORK_IN_OFFLINE_CLAIM",
            target=target.display,
            kind=target.kind.value,
            file=hit.hit.file_rel,
            line=hit.hit.line,
            evidence="%s  ->  %s" % (evidence, for_display(destination, 120)),
            why=(
                "Network egress (%s) at %s contradicts what this %s says it does: %s. "
                "A description that does not match the code is the mismatch this scanner "
                "exists to catch — the tool itself is unremarkable, the contradiction is not."
                % (hit.hit.label, where, target.kind.value, reason)
            ),
            recommendation=(
                "Open %s and confirm you want this %s talking to %s. If the description "
                "is wrong, remove the bundle: you cannot review something that "
                "misdescribes itself."
                % (where, target.kind.value, for_display(destination, 120))
            ),
        )
    ]
