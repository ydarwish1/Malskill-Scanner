"""``scan --summary``: one line with the state, findings per severity and the unscanned count.

The line is a view of the same report ``--json`` describes, so every count is checked
against the JSON report of the same scan. Exit codes do not change with the flag.
"""

from __future__ import annotations

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import fixture_gen  # noqa: E402
import harness  # noqa: E402

if harness.REPO_ROOT not in sys.path:
    sys.path.insert(0, harness.REPO_ROOT)

from malskill.report import Report  # noqa: E402
from malskill.rules import Finding, Severity, Unscanned  # noqa: E402
from malskill.rules.engine import ScanResult  # noqa: E402


def _report(severities=(), unscanned=0):
    findings = [
        Finding(id="TEST_%s" % severity.value, severity=severity, target="skill:t", kind="skill")
        for severity in severities
    ]
    entries = [
        Unscanned(target="skill:t", file="big-%d.txt" % index, reason="too-large")
        for index in range(unscanned)
    ]
    return Report(result=ScanResult(findings=findings, unscanned=entries))


def _expected_line(report) -> str:
    counts = report["severity_counts"]
    return (
        "state: %s   critical: %d   high: %d   medium: %d   low: %d   not-fully-analyzed: %d"
        % (
            report["state"],
            counts["CRITICAL"],
            counts["HIGH"],
            counts["MEDIUM"],
            counts["LOW"],
            len(report["unscanned"]),
        )
    )


class ReportSummaryTests(unittest.TestCase):
    def test_clean_report_has_every_field_at_zero(self) -> None:
        self.assertEqual(
            "state: CLEAN   critical: 0   high: 0   medium: 0   low: 0   not-fully-analyzed: 0",
            _report().render_summary(),
        )

    def test_counts_every_severity_in_fixed_order(self) -> None:
        report = _report(
            [Severity.LOW, Severity.HIGH, Severity.LOW, Severity.CRITICAL, Severity.LOW],
            unscanned=2,
        )
        self.assertEqual(
            "state: FLAGGED   critical: 1   high: 1   medium: 0   low: 3   not-fully-analyzed: 2",
            report.render_summary(),
        )

    def test_partial_state_without_findings(self) -> None:
        self.assertEqual(
            "state: NOT-FULLY-ANALYZED   critical: 0   high: 0   medium: 0   low: 0   "
            "not-fully-analyzed: 1",
            _report(unscanned=1).render_summary(),
        )

    def test_escalated_finding_counts_at_its_raised_severity(self) -> None:
        report = _report([Severity.MEDIUM])
        report.findings[0].escalate(Severity.CRITICAL, "explainer raised it")
        self.assertIn("critical: 1   high: 0   medium: 0", report.render_summary())

    def test_is_one_line(self) -> None:
        line = _report([Severity.HIGH], unscanned=3).render_summary()
        self.assertEqual([line], line.splitlines())


class CliSummaryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="malskill-summary-")
        self.addCleanup(self.tmp.cleanup)
        self.root = self.tmp.name
        self.home = harness.make_home(self.root, "empty-home")

    def _scan(self, target: str, *extra: str) -> harness.CliResult:
        return harness.run_malskill(["scan", "--home", self.home, "--paths", target] + list(extra))

    def _assert_matches_json(self, target: str, *extra: str) -> harness.CliResult:
        """The summary is exactly one line, agreeing with --json for the same scan."""
        result, report = harness.scan_json(
            ["scan", "--home", self.home, "--paths", target, "--json"] + list(extra)
        )
        summary = self._scan(target, "--summary", *extra)
        self.assertEqual([_expected_line(report)], summary.stdout.splitlines(), str(summary))
        self.assertEqual(result.returncode, summary.returncode, str(summary))
        self.assertEqual("", summary.stderr, str(summary))
        return summary

    def _bundle(self, kind: str, name: str) -> str:
        return harness.copy_fixture(kind, name, os.path.join(self.root, name))

    def test_flagged_bundle_exits_one(self) -> None:
        bundle = self._bundle("malicious", "sensitive_read_plus_egress")
        result = self._assert_matches_json(bundle, "--no-baseline")
        self.assertEqual(1, result.returncode, str(result))
        self.assertTrue(result.stdout.startswith("state: FLAGGED   critical: "), str(result))
        self.assertNotIn("critical: 0", result.stdout, str(result))

    def test_clean_bundle_exits_zero(self) -> None:
        bundle = self._bundle("benign", "markdown-table-formatter")
        result = self._assert_matches_json(bundle, "--no-baseline")
        self.assertEqual(0, result.returncode, str(result))
        self.assertTrue(result.stdout.startswith("state: CLEAN"), str(result))

    def test_empty_directory_is_clean(self) -> None:
        empty = os.path.join(self.root, "empty")
        os.makedirs(empty)
        result = self._assert_matches_json(empty, "--no-baseline")
        self.assertEqual(0, result.returncode, str(result))

    def test_missing_path_counts_as_not_fully_analyzed(self) -> None:
        result = self._assert_matches_json(os.path.join(self.root, "missing"), "--no-baseline")
        self.assertEqual(0, result.returncode, str(result))
        self.assertTrue(result.stdout.startswith("state: NOT-FULLY-ANALYZED"), str(result))
        self.assertIn("not-fully-analyzed: 1", result.stdout, str(result))

    def test_unreadable_binary_and_oversized_files_are_counted(self) -> None:
        bundle = fixture_gen.build_unscannable(os.path.join(self.root, "unscannable"))
        self.addCleanup(os.chmod, os.path.join(bundle, "assets", "locked.md"), 0o644)
        result = self._assert_matches_json(bundle, "--no-baseline")
        self.assertEqual(0, result.returncode, str(result))
        self.assertTrue(result.stdout.startswith("state: NOT-FULLY-ANALYZED"), str(result))
        self.assertNotIn("not-fully-analyzed: 0", result.stdout, str(result))

    def test_low_findings_and_fail_on(self) -> None:
        bundle = self._bundle("benign", "docs-install-oneliner")
        result = self._assert_matches_json(bundle, "--no-baseline", "--paranoid")
        self.assertEqual(1, result.returncode, str(result))
        self.assertNotIn("low: 0", result.stdout, str(result))

        result = self._assert_matches_json(bundle, "--no-baseline", "--paranoid", "--fail-on", "medium")
        self.assertEqual(0, result.returncode, "--fail-on still decides the exit.{}".format(result))
        self.assertTrue(result.stdout.startswith("state: FLAGGED"), str(result))

    def test_zero_width_content_never_reaches_the_line(self) -> None:
        bundle = fixture_gen.build_hidden_instructions_zero_width(os.path.join(self.root, "zw"))
        result = self._assert_matches_json(bundle, "--no-baseline")
        self.assertEqual(1, result.returncode, str(result))
        for codepoint in (fixture_gen.ZERO_WIDTH_SPACE, fixture_gen.RIGHT_TO_LEFT_OVERRIDE):
            self.assertNotIn(codepoint, result.stdout, str(result))

    def test_baseline_drift_is_counted(self) -> None:
        bundle = fixture_gen.build_clean_bundle(self.root, "drifting")
        update = harness.run_malskill(["baseline", "update", "--home", self.home, "--paths", bundle])
        self.assertEqual(0, update.returncode, str(update))
        self.assertTrue(self._scan(bundle, "--summary").stdout.startswith("state: CLEAN"))

        with open(os.path.join(bundle, "SKILL.md"), "a", encoding="utf-8") as handle:
            handle.write("\nOne more harmless line.\n")
        result = self._assert_matches_json(bundle)
        self.assertEqual(1, result.returncode, str(result))
        self.assertTrue(result.stdout.startswith("state: FLAGGED"), str(result))

    def test_json_and_summary_together_is_a_usage_error(self) -> None:
        bundle = self._bundle("benign", "markdown-table-formatter")
        result = self._scan(bundle, "--no-baseline", "--json", "--summary")
        self.assertEqual(2, result.returncode, str(result))
        self.assertEqual("", result.stdout, str(result))
        self.assertIn("not allowed with", result.stderr, str(result))
        self.assertNotIn("Traceback (most recent call last)", result.stderr, str(result))

    def test_scan_help_documents_the_flag(self) -> None:
        result = harness.run_malskill(["scan", "--help"], require_home=False)
        self.assertEqual(0, result.returncode, str(result))
        self.assertIn("--summary", result.stdout, str(result))


if __name__ == "__main__":
    unittest.main()
