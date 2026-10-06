"""Reporting: three states, defanged evidence, and no green checkmark you cannot back up.

The output contract, in order of importance:

1. **Three states, never two.** ``FLAGGED`` / ``CLEAN`` / ``NOT-FULLY-ANALYZED``. The
   partial state is always printed, even when it is the only thing to say, because a
   scanner that hides what it could not read is worse than no scanner.
2. **The word "SAFE" never appears.** The clean line says what actually happened — no
   rule fired — and states plainly that this is not a guarantee.
3. **Evidence is defanged.** URLs render as ``hxxps://evil[.]example[.]com`` and control
   characters as ``\\u{200B}``, so reading a report cannot itself be the attack, and a
   zero-width payload is visible rather than invisible.
4. **Named findings, no scores.** Every row leads with the finding ID and the severity
   floor from the registry.

Exit codes: ``0`` no findings, ``1`` at least one finding, ``2`` scanner error.
NOT-FULLY-ANALYZED on its own still exits 0 — and is still printed. With ``fail_on``
set, only findings at or above that severity exit 1; lower ones are still printed.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from malskill import __version__
from malskill.rules import REGISTRY, SEVERITY_ORDER, Finding, Severity, Unscanned
from malskill.rules.engine import STATE_CLEAN, STATE_FLAGGED, STATE_PARTIAL, ScanResult
from malskill.sanitize import for_display

__all__ = [
    "Report",
    "EXIT_OK",
    "EXIT_FINDINGS",
    "EXIT_ERROR",
    "render_rules_table",
    "render_inventory",
    "baseline_diff_state",
    "render_baseline_diff",
]

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2

SCHEMA_VERSION = 1

_REASON_LABELS = {
    "binary": "binary",
    "too-large": "oversized",
    "unreadable": "unreadable",
    "parse-error": "parse failure",
    "symlink-out": "symlink out of bundle",
}


@dataclass
class Report:
    """A finished scan, ready to be rendered as text or JSON."""

    result: ScanResult
    scope: Dict[str, Any] = field(default_factory=dict)
    notes: List[str] = field(default_factory=list)
    explainer_note: Optional[str] = None
    fail_on: Optional[Severity] = None
    generated_at: str = field(
        default_factory=lambda: time.strftime("%Y-%m-%dT%H:%M:%S%z")
    )

    # -- derived -----------------------------------------------------------------------
    @property
    def findings(self) -> List[Finding]:
        return self.result.findings

    @property
    def unscanned(self) -> List[Unscanned]:
        return self.result.unscanned

    @property
    def suppressed(self):
        return getattr(self.result, "suppressed", []) or []

    @property
    def state(self) -> str:
        return self.result.state

    def severity_counts(self) -> Dict[str, int]:
        counts = {severity.value: 0 for severity in SEVERITY_ORDER}
        for finding in self.findings:
            counts[finding.severity.value] = counts.get(finding.severity.value, 0) + 1
        return counts

    def clean_targets(self) -> List[str]:
        return sorted(
            name
            for name, state in self.result.target_states.items()
            if state == STATE_CLEAN
        )

    def partial_targets(self) -> List[str]:
        return sorted(
            name
            for name, state in self.result.target_states.items()
            if state == STATE_PARTIAL
        )

    def flagged_targets(self) -> List[str]:
        return sorted(
            name
            for name, state in self.result.target_states.items()
            if state == STATE_FLAGGED
        )

    def failing_findings(self) -> List[Finding]:
        """Findings that decide the exit code: all of them, or those at/above ``fail_on``."""
        if self.fail_on is None:
            return self.findings
        return [f for f in self.findings if f.severity.rank >= self.fail_on.rank]

    def exit_code(self) -> int:
        return EXIT_FINDINGS if self.failing_findings() else EXIT_OK

    # -- rendering ---------------------------------------------------------------------
    def to_dict(self) -> Dict[str, Any]:
        return {
            "tool": "malskill",
            "tool_version": __version__,
            "schema_version": SCHEMA_VERSION,
            "generated_at": self.generated_at,
            "state": self.state,
            "scope": self.scope,
            "stats": self.result.stats,
            "severity_counts": self.severity_counts(),
            "findings": [finding.to_dict() for finding in self.findings],
            "unscanned": [entry.to_dict() for entry in self.unscanned],
            "unscanned_summary": self.unscanned_summary(),
            # Behaviour patterns seen in documentation/test/data context. Always
            # present in the machine-readable report, whether or not --paranoid
            # promoted them to findings: suppressed must never mean invisible.
            "suppressed": [entry.to_dict() for entry in self.suppressed],
            "suppressed_summary": self.suppressed_summary(),
            "targets": [
                {"target": name, "state": state}
                for name, state in sorted(self.result.target_states.items())
            ],
            "notes": list(self.result.notes) + list(self.notes),
            "explainer": self.explainer_note,
            "fail_on": self.fail_on.value if self.fail_on is not None else None,
            "exit_code": self.exit_code(),
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)

    def unscanned_summary(self) -> Dict[str, int]:
        summary: Dict[str, int] = {}
        for entry in self.unscanned:
            label = _REASON_LABELS.get(entry.reason, entry.reason)
            summary[label] = summary.get(label, 0) + 1
        return summary

    def suppressed_summary(self) -> Dict[str, int]:
        """rule ID -> how many of its matches landed in a non-actionable role."""
        summary: Dict[str, int] = {}
        for entry in self.suppressed:
            summary[entry.rule_id] = summary.get(entry.rule_id, 0) + 1
        return summary

    def render_terminal(self, *, show_unscanned: bool = False) -> str:
        lines: List[str] = []
        stats = self.result.stats
        lines.append(
            "MalSkill Scanner v%s — scanned %s target%s, %s file%s (%s fully, %s partially)"
            % (
                __version__,
                "{:,}".format(stats.get("targets", 0)),
                "" if stats.get("targets", 0) == 1 else "s",
                "{:,}".format(stats.get("files_seen", 0)),
                "" if stats.get("files_seen", 0) == 1 else "s",
                "{:,}".format(stats.get("files_fully_analyzed", 0)),
                "{:,}".format(stats.get("files_partially_analyzed", 0)),
            )
        )
        scope_bits = []
        if self.scope.get("home"):
            scope_bits.append("home=%s" % self.scope["home"])
        if self.scope.get("paths"):
            scope_bits.append("paths=%s" % ", ".join(self.scope["paths"]))
        if scope_bits:
            lines.append("scope: %s" % "  ".join(scope_bits))
        lines.append("")

        # ---- FLAGGED -----------------------------------------------------------------
        if self.findings:
            counts = self.severity_counts()
            summary = ", ".join(
                "%d %s" % (counts[s.value], s.value)
                for s in SEVERITY_ORDER
                if counts.get(s.value)
            )
            lines.append("FLAGGED (%d)  [%s]" % (len(self.findings), summary))
            for finding in self.findings:
                lines.extend(_render_finding(finding))
            lines.append("")
        else:
            lines.append("FLAGGED (0)")
            lines.append("  No rule fired on any analyzed content.")
            lines.append("")

        # ---- NOT-FULLY-ANALYZED --------------------------------------------------------
        lines.append("NOT-FULLY-ANALYZED (%d)" % len(self.unscanned))
        if self.unscanned:
            summary = self.unscanned_summary()
            detail = ", ".join(
                "%d %s" % (count, label) for label, count in sorted(summary.items())
            )
            if not show_unscanned:
                detail += " — list every entry with --show-unscanned"
            lines.append("  %s" % detail)
            if show_unscanned:
                for entry in self.unscanned:
                    lines.append(
                        "    %-22s %s  (%s%s)"
                        % (
                            entry.target,
                            for_display(entry.file, 120),
                            entry.reason,
                            ": " + for_display(entry.detail, 120)
                            if entry.detail
                            else "",
                        )
                    )
            lines.append(
                "  These files were not (or not fully) analyzed. Nothing about them is "
                "implied by their absence from the flagged list."
            )
        else:
            lines.append("  Every discovered file was read in full.")
        lines.append("")

        # ---- CLEAN ---------------------------------------------------------------------
        clean = self.clean_targets()
        lines.append(
            "CLEAN (%d target%s): no rule fired. This is not a guarantee that they are "
            "harmless — it means the deterministic rules in this version found nothing."
            % (len(clean), "" if len(clean) == 1 else "s")
        )

        notes = list(self.result.notes) + list(self.notes)
        if self.explainer_note:
            notes.append(self.explainer_note)
        if notes:
            lines.append("")
            lines.append("notes:")
            for note in notes:
                lines.append("  - %s" % for_display(note, 400))

        lines.append("")
        footer = "state: %s   findings: %d   not-fully-analyzed: %d   exit: %d" % (
            self.state,
            len(self.findings),
            len(self.unscanned),
            self.exit_code(),
        )
        if self.fail_on is not None:
            footer += "   fail-on: %s" % self.fail_on.value
        lines.append(footer)
        return "\n".join(lines)


def _render_finding(finding: Finding) -> List[str]:
    location = finding.file or ""
    if finding.file and finding.line:
        location = "%s:%d" % (finding.file, finding.line)
    header = "  [%s] %-28s %s" % (
        finding.severity.value,
        finding.id,
        finding.target,
    )
    if location:
        header += "  %s" % for_display(location, 120)
    if finding.escalated:
        header += "  (escalated)"
    lines = [header]
    if finding.evidence:
        lines.append("    evidence: %s" % for_display(finding.evidence, 400))
    if finding.why:
        lines.append("    why: %s" % for_display(finding.why, 600))
    if finding.recommendation:
        lines.append("    recommendation: %s" % for_display(finding.recommendation, 400))
    if finding.escalation_note:
        lines.append("    explainer: %s" % for_display(finding.escalation_note, 300))
    return lines


# ---------------------------------------------------------------------------------------
# Other renderers
# ---------------------------------------------------------------------------------------


def render_rules_table(as_json: bool = False) -> str:
    """The `malskill rules` output: every registered finding ID and its floor."""
    if as_json:
        return json.dumps(
            {rule_id: rule.to_dict() for rule_id, rule in REGISTRY.items()},
            indent=2,
            ensure_ascii=False,
        )
    lines = [
        "MalSkill Scanner v%s — %d registered finding IDs" % (__version__, len(REGISTRY)),
        "Severity shown is the rule FLOOR. The optional explainer may raise it, never lower it.",
        "Full documentation: docs/RULES.md",
        "",
        "%-30s %-9s %-18s %s" % ("FINDING ID", "FLOOR", "CATEGORY", "WHAT FIRES IT"),
        "%-30s %-9s %-18s %s" % ("-" * 30, "-" * 9, "-" * 18, "-" * 40),
    ]
    for severity in SEVERITY_ORDER:
        for rule_id, rule in REGISTRY.items():
            if rule.severity != severity:
                continue
            trigger = rule.trigger.replace("\n", " ")
            if len(trigger) > 92:
                trigger = trigger[:91] + "…"
            suffix = "" if rule.produces_findings else " (reported as NOT-FULLY-ANALYZED)"
            lines.append(
                "%-30s %-9s %-18s %s%s"
                % (rule_id, severity.value, rule.category, trigger, suffix)
            )
    lines.append("")
    lines.append(
        "Mismatch-first: a scary keyword alone is never a finding. Each rule states the "
        "contradiction or combination it requires."
    )
    return "\n".join(lines)


def render_inventory(inventory, *, as_json: bool = False) -> str:
    """The `malskill list` output: what would be scanned, with no rules run."""
    if as_json:
        payload = {
            "tool": "malskill",
            "tool_version": __version__,
            "home": inventory.home,
            "cwd": inventory.cwd,
            "targets": [
                {
                    "kind": target.kind.value,
                    "name": target.name,
                    "path": target.path,
                    "source": target.source,
                }
                for target in inventory.targets
            ],
            "unscanned": [entry.to_dict() for entry in inventory.unscanned],
            "notes": inventory.notes,
        }
        return json.dumps(payload, indent=2, ensure_ascii=False)

    lines = [
        "MalSkill Scanner v%s — inventory only, no rules were run" % __version__,
        "home: %s" % inventory.home,
        "",
    ]
    by_kind: Dict[str, List[Any]] = {}
    for target in inventory.targets:
        by_kind.setdefault(target.kind.value, []).append(target)
    if not by_kind:
        lines.append("No targets discovered.")
    for kind in sorted(by_kind):
        targets = by_kind[kind]
        lines.append("%s (%d)" % (kind, len(targets)))
        for target in sorted(targets, key=lambda t: t.name):
            lines.append("  %-42s %s" % (target.name, for_display(target.path, 120)))
        lines.append("")
    if inventory.unscanned:
        lines.append("NOT-FULLY-ANALYZED (%d)" % len(inventory.unscanned))
        for entry in inventory.unscanned:
            lines.append(
                "  %-30s %s (%s)"
                % (entry.target, for_display(entry.file, 100), entry.reason)
            )
        lines.append("")
    for note in inventory.notes:
        lines.append("note: %s" % note)
    lines.append(
        "%d target(s) discovered. Run 'malskill scan' to apply the rules."
        % len(inventory.targets)
    )
    return "\n".join(lines)


def baseline_diff_state(store, changes: List[Any]) -> Tuple[str, int]:
    """(state, exit code) for ``baseline diff``: nothing to compare against is exit 2."""
    if not store.exists:
        return "NO-BASELINE", EXIT_ERROR
    if store.tampered:
        return "TAMPERED", EXIT_ERROR
    if changes:
        return "CHANGED", EXIT_FINDINGS
    return "UNCHANGED", EXIT_OK


def render_baseline_diff(
    store,
    changes: List[Any],
    unscanned: List[Unscanned],
    *,
    targets: int,
    as_json: bool = False,
) -> str:
    state, exit_code = baseline_diff_state(store, changes)
    counts = {kind: 0 for kind in ("added", "changed", "removed", "unreadable")}
    for change in changes:
        counts[change.change] += 1
    if as_json:
        payload = {
            "tool": "malskill",
            "tool_version": __version__,
            "baseline": store.path,
            "updated": store.updated,
            "state": state,
            "error": for_display(store.error) if store.error else None,
            "targets": targets,
            "counts": counts,
            "changes": [change.to_dict() for change in changes],
            "unscanned": [_unscanned_for_display(entry) for entry in unscanned],
            "exit_code": exit_code,
        }
        return json.dumps(payload, indent=2, ensure_ascii=False)

    if state == "NO-BASELINE":
        return (
            "NO-BASELINE: nothing recorded at %s. Run 'malskill baseline update' once "
            "you have reviewed what is installed." % store.path
        )
    if state == "TAMPERED":
        return "BASELINE_TAMPERED: %s (%s). Nothing was compared." % (
            store.path,
            for_display(store.error or "checksum mismatch"),
        )
    lines = [
        "MalSkill Scanner v%s — baseline diff, no rules were run" % __version__,
        "baseline: %s (written %s)" % (store.path, store.updated or "unknown date"),
        "",
    ]
    if changes:
        lines.append(
            "CHANGED (%d)  [%s]"
            % (
                len(changes),
                ", ".join("%d %s" % (n, kind) for kind, n in counts.items() if n),
            )
        )
        for change in changes:
            lines.append(
                "  %-10s %-30s %s"
                % (
                    change.change,
                    for_display(change.target, 120),
                    for_display(change.file, 200),
                )
            )
    else:
        lines.append("UNCHANGED")
        lines.append(
            "  No file added, changed or removed across %d target(s)." % targets
        )
    lines.append("")
    lines.append("NOT-FULLY-ANALYZED (%d)" % len(unscanned))
    if unscanned:
        for entry in unscanned:
            shown = _unscanned_for_display(entry)
            lines.append(
                "  %-30s %s  (%s%s)"
                % (
                    shown["target"],
                    shown["file"],
                    shown["reason"],
                    ": " + shown["detail"] if shown["detail"] else "",
                )
            )
        lines.append(
            "  These files could not be hashed, so they were not compared. Nothing "
            "about them is implied by their absence from the changed list."
        )
    else:
        lines.append("  Every discovered file was hashed and compared.")
    return "\n".join(lines)


def _unscanned_for_display(entry: Unscanned) -> Dict[str, Any]:
    shown = entry.to_dict()
    for key in ("target", "file", "detail"):
        shown[key] = for_display(shown[key] or "", 200)
    return shown
