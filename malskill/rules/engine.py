"""The engine: run every deterministic rule over every target, collect the results.

The engine is intentionally boring. It loads one target's bytes at a time, hands the
target to each rule module, collects findings and NOT-FULLY-ANALYZED records, then drops
the bytes again. Nothing here decides anything: the rules own the decisions and the
registry owns the severity floors.

Two invariants live here:

* a rule that raises does not kill the scan — it produces a loud NOT-FULLY-ANALYZED
  record for that target instead, because a crashed rule is an unscanned target and
  pretending otherwise would be the same lie as printing SAFE;
* findings are de-duplicated and capped per (rule, target) so one pathological file
  cannot flood a report and train the reader to skim.

Since v1.1 the engine also owns the *suppressed-hit* ledger. Behaviour rules only fire
from EXECUTABLE and INSTRUCTION files (see :mod:`malskill.roles`); everything they matched
elsewhere is collected here, counted in a report note, and — with ``--paranoid`` — emitted
as LOW ``SUPPRESSED_PATTERN_HIT`` findings. Suppressed is not silent.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Sequence, Set, Tuple

from malskill import claims as claims_module
from malskill.roles import SuppressedHit
from malskill.rules import (
    REASON_PARSE_ERROR,
    REGISTRY,
    Finding,
    Severity,
    Unscanned,
    make_finding,
)
from malskill.rules import (
    r_credentials,
    r_destructive,
    r_exfil,
    r_hooks,
    r_injection,
    r_mcp_config,
    r_network_claims,
    r_obfuscation,
    r_pipe_to_shell,
    r_self_modify,
    r_unscannable,
)

__all__ = ["RULE_MODULES", "ScanResult", "run", "covered_rule_ids"]

#: Every rule module, in report-friendly order. Order does not affect results.
RULE_MODULES: Tuple[Any, ...] = (
    r_network_claims,
    r_exfil,
    r_credentials,
    r_destructive,
    r_self_modify,
    r_obfuscation,
    r_pipe_to_shell,
    r_injection,
    r_hooks,
    r_mcp_config,
    r_unscannable,
)

#: Findings kept per (rule id, target). Beyond this the report stops being read.
MAX_FINDINGS_PER_RULE_PER_TARGET = 5
#: --paranoid exists precisely to enumerate, so its own ID gets a much larger budget.
MAX_SUPPRESSED_FINDINGS_PER_TARGET = 50

STATE_FLAGGED = "FLAGGED"
STATE_CLEAN = "CLEAN"
STATE_PARTIAL = "NOT-FULLY-ANALYZED"


@dataclass
class ScanResult:
    """Everything one scan produced."""

    findings: List[Finding] = field(default_factory=list)
    unscanned: List[Unscanned] = field(default_factory=list)
    #: Pattern matches a behaviour rule saw but was not allowed to fire from.
    suppressed: List[SuppressedHit] = field(default_factory=list)
    target_states: Dict[str, str] = field(default_factory=dict)
    #: target.key -> baseline snapshot, captured before the bytes are dropped.
    target_hashes: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    stats: Dict[str, Any] = field(default_factory=dict)
    notes: List[str] = field(default_factory=list)

    @property
    def state(self) -> str:
        if self.findings:
            return STATE_FLAGGED
        if self.unscanned:
            return STATE_PARTIAL
        return STATE_CLEAN

    def by_severity(self, severity: Severity) -> List[Finding]:
        return [f for f in self.findings if f.severity == severity]


def covered_rule_ids() -> Set[str]:
    """IDs declared by the loaded rule modules (plus the IDs the engine owns)."""
    covered: Set[str] = set()
    for module in RULE_MODULES:
        covered.update(getattr(module, "RULE_IDS", ()))
    covered.update(
        {
            "BASELINE_DRIFT",
            "BASELINE_NEW_TARGET",
            "BASELINE_TAMPERED",
            "SUPPRESSED_PATTERN_HIT",
        }
    )
    return covered


def _suppressed_note(
    suppressed: Sequence[SuppressedHit], paranoid: bool, listed: int = 0
) -> str:
    """One line telling the reader what the role model held back, and how to see it."""
    if not suppressed:
        return ""
    by_role: Dict[str, int] = {}
    for entry in suppressed:
        by_role[entry.role_label] = by_role.get(entry.role_label, 0) + 1
    breakdown = ", ".join(
        "%d %s" % (count, label) for label, count in sorted(by_role.items())
    )
    rules = sorted({entry.rule_id for entry in suppressed})
    if paranoid:
        # Say exactly how many rows made it past the per-target cap. "listed below"
        # when 67 of them were not listed is the same species of small lie this whole
        # tool exists to avoid.
        shortfall = (
            ""
            if listed >= len(suppressed)
            else " (%d listed below; %d beyond the per-target cap of %d are in the JSON "
            "report's 'suppressed' array only)"
            % (listed, len(suppressed) - listed, MAX_SUPPRESSED_FINDINGS_PER_TARGET)
        )
        return (
            "%d suppressed pattern hit(s) in documentation/test context (%s) surfaced "
            "as SUPPRESSED_PATTERN_HIT [LOW]%s; rules involved: %s."
            % (len(suppressed), breakdown, shortfall, ", ".join(rules))
        )
    return (
        "%d suppressed pattern hit(s) in documentation/test context (%s) — rerun with "
        "--paranoid to list them. Rules involved: %s."
        % (len(suppressed), breakdown, ", ".join(rules))
    )


def _paranoid_findings(suppressed: Sequence[SuppressedHit]) -> List[Finding]:
    """Promote each suppressed hit to a LOW finding that names its real rule.

    Deliberately a distinct ID rather than the original rule at a lowered severity: a
    severity floor is a floor, and PIPE_TO_SHELL at LOW would be a lie about what the
    rule concluded. The original rule ID is carried in the evidence and the explanation.
    """
    out: List[Finding] = []
    for entry in suppressed:
        rule = REGISTRY.get(entry.rule_id)
        out.append(
            make_finding(
                "SUPPRESSED_PATTERN_HIT",
                target=entry.target,
                kind=entry.kind or "skill",
                file=entry.file or None,
                line=entry.line,
                evidence="%s (%s): %s" % (entry.rule_id, entry.label, entry.evidence),
                why=(
                    "The %s pattern %r matched at %s:%s, but that file's role is %s, not "
                    "executable or instruction, so %s did not fire. %s"
                    % (
                        entry.rule_id,
                        entry.label,
                        entry.file,
                        entry.line,
                        entry.role_label,
                        entry.rule_id,
                        (rule.why if rule is not None else ""),
                    )
                ),
                recommendation=(
                    "Read %s:%s. Documentation and test material quoting a dangerous "
                    "command is ordinary; treat it as real if any instruction surface in "
                    "this bundle tells the agent to follow that file."
                    % (entry.file, entry.line)
                ),
            )
        )
    return out


def _dedupe_and_cap(findings: Sequence[Finding]) -> List[Finding]:
    seen: Set[Tuple[Any, ...]] = set()
    counts: Dict[Tuple[str, str], int] = {}
    out: List[Finding] = []
    for finding in findings:
        key: Tuple[Any, ...] = (finding.id, finding.target, finding.file, finding.line)
        if finding.id == "SUPPRESSED_PATTERN_HIT":
            # One line can carry matches from several rules (a README quoting
            # ``curl … | bash`` trips both PIPE_TO_SHELL and the egress matcher). Under
            # --paranoid the reader asked for each of them, so the originating rule --
            # carried in the evidence -- is part of the identity.
            key = key + (finding.evidence,)
        if key in seen:
            continue
        seen.add(key)
        cap_key = (finding.id, finding.target)
        counts[cap_key] = counts.get(cap_key, 0) + 1
        cap = (
            MAX_SUPPRESSED_FINDINGS_PER_TARGET
            if finding.id == "SUPPRESSED_PATTERN_HIT"
            else MAX_FINDINGS_PER_RULE_PER_TARGET
        )
        if counts[cap_key] > cap:
            continue
        out.append(finding)
    return out


def run(
    inventory,
    *,
    progress: Optional[Callable[[int, int, Any], None]] = None,
    paranoid: bool = False,
) -> ScanResult:
    """Run all rules over an inventory."""
    started = time.time()
    findings: List[Finding] = []
    unscanned: List[Unscanned] = list(getattr(inventory, "unscanned", []) or [])
    suppressed: List[SuppressedHit] = []
    states: Dict[str, str] = {}

    from malskill import baseline as baseline_module

    files_seen = 0
    files_partial = 0
    reference_promotions = 0
    reference_targets = 0
    reference_caps: List[str] = []
    total = len(inventory.targets)
    hashes: Dict[str, Dict[str, Any]] = {}

    for index, target in enumerate(inventory.targets):
        target_findings: List[Finding] = []
        try:
            target.load()
        except Exception as exc:  # noqa: BLE001 - discovery must never crash a scan
            unscanned.append(
                Unscanned(
                    target=target.display,
                    file=target.path,
                    reason=REASON_PARSE_ERROR,
                    detail="could not read target: %s" % exc,
                )
            )
            states[target.display] = STATE_PARTIAL
            continue

        try:
            if target.claims is None:
                target.claims = claims_module.derive(target)

            for module in RULE_MODULES:
                try:
                    result = module.check(target) or []
                except Exception as exc:  # noqa: BLE001 - a broken rule is an unscanned target
                    unscanned.append(
                        Unscanned(
                            target=target.display,
                            file=getattr(module, "__name__", "rule"),
                            reason=REASON_PARSE_ERROR,
                            detail="rule raised %s: %s" % (type(exc).__name__, exc),
                        )
                    )
                    continue
                target_findings.extend(result)

            target_unscanned = r_unscannable.collect_unscanned(target)
            seen, partial = target.stats()
            files_seen += seen
            files_partial += partial
            unscanned.extend(target_unscanned)
            suppressed.extend(getattr(target, "suppressed", []) or [])

            meta = getattr(target, "meta", {}) or {}
            promoted = len(meta.get("reference_hops", []) or [])
            if promoted:
                reference_promotions += promoted
                reference_targets += 1
            capped = meta.get("reference_hops_capped")
            if capped:
                reference_caps.append("%s: %s" % (target.display, capped))

            if target_findings:
                states[target.display] = STATE_FLAGGED
            elif target_unscanned:
                states[target.display] = STATE_PARTIAL
            else:
                states[target.display] = STATE_CLEAN

            findings.extend(target_findings)
            try:
                hashes[target.key] = baseline_module.snapshot_for(target)
            except Exception:  # noqa: BLE001 - hashing must never break a scan
                pass
        finally:
            target.unload()

        if progress is not None:
            progress(index + 1, total, target)

    if paranoid and suppressed:
        extra = _paranoid_findings(suppressed)
        findings.extend(extra)
        for finding in extra:
            if states.get(finding.target) in (None, STATE_CLEAN):
                states[finding.target] = STATE_FLAGGED

    findings = _dedupe_and_cap(findings)
    findings.sort(key=lambda f: f.sort_key())

    unknown = sorted({f.id for f in findings if f.id not in REGISTRY})

    result = ScanResult(
        findings=findings,
        unscanned=unscanned,
        suppressed=suppressed,
        target_states=states,
        target_hashes=hashes,
        stats={
            "targets": total,
            "files_seen": files_seen,
            "files_fully_analyzed": max(0, files_seen - files_partial),
            "files_partially_analyzed": files_partial,
            "unscanned_records": len(unscanned),
            "suppressed_hits": len(suppressed),
            "duration_seconds": round(time.time() - started, 3),
            "rules_run": len(RULE_MODULES),
        },
        notes=list(getattr(inventory, "notes", []) or []),
    )
    note = _suppressed_note(
        suppressed,
        paranoid,
        listed=sum(1 for f in findings if f.id == "SUPPRESSED_PATTERN_HIT"),
    )
    if note:
        result.notes.append(note)
    if reference_promotions:
        result.notes.append(
            "%d file(s) across %d target(s) promoted to instruction context by reference."
            % (reference_promotions, reference_targets)
        )
    if reference_caps:
        result.notes.append(
            "reference-hop analysis cap hit: %s." % "; ".join(reference_caps)
        )
    if unknown:
        result.notes.append(
            "findings emitted with IDs missing from the registry: %s" % ", ".join(unknown)
        )
    return result
