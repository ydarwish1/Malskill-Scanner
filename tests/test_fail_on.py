"""``scan --fail-on LEVEL``: exit 1 only for findings at or above LEVEL.

Lower findings must still be printed and still appear in ``--json``; the flag changes the
exit code, never what the report says. Without the flag the exit codes are unchanged.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import fixture_gen  # noqa: E402
import harness  # noqa: E402

if harness.REPO_ROOT not in sys.path:
    sys.path.insert(0, harness.REPO_ROOT)

from malskill.report import EXIT_FINDINGS, EXIT_OK, Report  # noqa: E402
from malskill.rules import SEVERITY_ORDER, Finding, Severity  # noqa: E402
from malskill.rules.engine import ScanResult  # noqa: E402


def _report(severities, fail_on):
    findings = [
        Finding(id="TEST_%s" % severity.value, severity=severity, target="skill:t", kind="skill")
        for severity in severities
    ]
    return Report(result=ScanResult(findings=findings), fail_on=fail_on)


class ReportFailOnTests(unittest.TestCase):
    def test_every_threshold_against_every_single_severity(self) -> None:
        for finding_severity in SEVERITY_ORDER:
            for level in SEVERITY_ORDER:
                expected = EXIT_FINDINGS if finding_severity.rank >= level.rank else EXIT_OK
                report = _report([finding_severity], level)
                self.assertEqual(
                    expected,
                    report.exit_code(),
                    "{} finding with fail_on={}".format(finding_severity, level),
                )

    def test_no_threshold_keeps_any_finding_failing(self) -> None:
        self.assertEqual(EXIT_FINDINGS, _report([Severity.LOW], None).exit_code())
        self.assertEqual(EXIT_OK, _report([], None).exit_code())

    def test_threshold_with_no_findings_exits_zero(self) -> None:
        self.assertEqual(EXIT_OK, _report([], Severity.LOW).exit_code())

    def test_failing_findings_keeps_only_those_at_or_above(self) -> None:
        report = _report([Severity.LOW, Severity.MEDIUM, Severity.HIGH], Severity.MEDIUM)
        self.assertEqual(
            [Severity.MEDIUM, Severity.HIGH],
            [f.severity for f in report.failing_findings()],
        )
        self.assertEqual(3, len(report.findings), "the threshold must not drop findings")

    def test_escalated_finding_counts_at_its_raised_severity(self) -> None:
        report = _report([Severity.MEDIUM], Severity.HIGH)
        self.assertEqual(EXIT_OK, report.exit_code())
        report.findings[0].escalate(Severity.HIGH, "explainer raised it")
        self.assertEqual(EXIT_FINDINGS, report.exit_code())

    def test_json_carries_the_threshold(self) -> None:
        self.assertEqual("HIGH", _report([], Severity.HIGH).to_dict()["fail_on"])
        self.assertIsNone(_report([], None).to_dict()["fail_on"])


class CliFailOnTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="malskill-fail-on-")
        self.addCleanup(self.tmp.cleanup)
        self.root = self.tmp.name
        self.home = harness.make_home(self.root, "empty-home")

    def _bundle(self, kind: str, name: str) -> str:
        return harness.copy_fixture(kind, name, os.path.join(self.root, name))

    def _scan(self, target: str, *extra: str) -> harness.CliResult:
        return harness.run_malskill(
            ["scan", "--home", self.home, "--paths", target, "--no-baseline"] + list(extra)
        )

    def _scan_json(self, target: str, *extra: str):
        return harness.scan_json(
            ["scan", "--home", self.home, "--paths", target, "--no-baseline", "--json"] + list(extra)
        )

    def test_high_finding_fails_at_or_below_high(self) -> None:
        bundle = self._bundle("malicious", "pipe_to_shell")
        for level in ("low", "medium", "high"):
            result, report = self._scan_json(bundle, "--fail-on", level)
            self.assertEqual(1, result.returncode, "--fail-on {}{}".format(level, result))
            self.assertEqual(1, report["exit_code"], str(result))
            self.assertEqual(level.upper(), report["fail_on"], str(result))

    def test_high_finding_passes_above_high_but_is_still_reported(self) -> None:
        bundle = self._bundle("malicious", "pipe_to_shell")
        result, report = self._scan_json(bundle, "--fail-on", "critical")
        self.assertEqual(0, result.returncode, str(result))
        self.assertEqual(0, report["exit_code"], str(result))
        self.assertEqual("FLAGGED", report["state"], str(result))
        self.assertIn("PIPE_TO_SHELL", harness.finding_ids(report), str(result))

        terminal = self._scan(bundle, "--fail-on", "critical")
        self.assertEqual(0, terminal.returncode, str(terminal))
        self.assertIn("[HIGH] PIPE_TO_SHELL", terminal.stdout, str(terminal))
        self.assertIn("exit: 0   fail-on: CRITICAL", terminal.stdout, str(terminal))

    def test_critical_finding_fails_at_critical(self) -> None:
        bundle = self._bundle("malicious", "sensitive_read_plus_egress")
        result = self._scan(bundle, "--fail-on", "critical")
        self.assertEqual(1, result.returncode, str(result))
        self.assertIn("exit: 1   fail-on: CRITICAL", result.stdout, str(result))

    def test_low_findings_pass_at_medium_and_fail_at_low(self) -> None:
        bundle = self._bundle("benign", "docs-install-oneliner")
        result, report = self._scan_json(bundle, "--paranoid", "--fail-on", "medium")
        self.assertEqual(0, result.returncode, str(result))
        ids = harness.finding_ids(report)
        self.assertTrue(ids, "--paranoid must still list the LOW hits.{}".format(result))
        self.assertEqual({"SUPPRESSED_PATTERN_HIT"}, set(ids), str(result))

        result, _ = self._scan_json(bundle, "--paranoid", "--fail-on", "low")
        self.assertEqual(1, result.returncode, str(result))

    def test_level_is_case_insensitive(self) -> None:
        bundle = self._bundle("malicious", "pipe_to_shell")
        result, report = self._scan_json(bundle, "--fail-on", "CRITICAL")
        self.assertEqual(0, result.returncode, str(result))
        self.assertEqual("CRITICAL", report["fail_on"], str(result))

    def test_without_the_flag_exit_codes_are_unchanged(self) -> None:
        bundle = self._bundle("benign", "docs-install-oneliner")
        result, report = self._scan_json(bundle, "--paranoid")
        self.assertEqual(1, result.returncode, "a LOW finding still exits 1 by default.{}".format(result))
        self.assertIsNone(report["fail_on"], str(result))
        terminal = self._scan(bundle, "--paranoid")
        footer = terminal.stdout.strip().splitlines()[-1]
        self.assertTrue(footer.endswith("exit: 1"), "footer must not name a threshold.{}".format(terminal))

    def test_clean_scan_exits_zero_at_the_lowest_level(self) -> None:
        bundle = self._bundle("benign", "markdown-table-formatter")
        result, report = self._scan_json(bundle, "--fail-on", "low")
        self.assertEqual(0, result.returncode, str(result))
        self.assertEqual([], harness.finding_ids(report), str(result))

    def test_not_fully_analyzed_alone_still_exits_zero(self) -> None:
        bundle = fixture_gen.build_unscannable(os.path.join(self.root, "unscannable"))
        result, report = self._scan_json(bundle, "--fail-on", "low")
        self.assertEqual(0, result.returncode, str(result))
        self.assertEqual("NOT-FULLY-ANALYZED", report["state"], str(result))
        self.assertTrue(harness.unscanned(report), str(result))

    def test_unknown_or_missing_level_is_a_usage_error(self) -> None:
        bundle = self._bundle("benign", "markdown-table-formatter")
        for extra in (["--fail-on", "severe"], ["--fail-on", ""], ["--fail-on"]):
            result = self._scan(bundle, *extra)
            self.assertEqual(2, result.returncode, "{}{}".format(extra, result))
            self.assertNotIn("Traceback (most recent call last)", result.stderr, str(result))

    def test_scan_help_documents_the_flag(self) -> None:
        result = harness.run_malskill(["scan", "--help"], require_home=False)
        self.assertEqual(0, result.returncode, str(result))
        self.assertIn("--fail-on", result.stdout, str(result))
        for level in ("low", "medium", "high", "critical"):
            self.assertIn(level, result.stdout, str(result))

    def test_json_output_stays_one_valid_document(self) -> None:
        bundle = self._bundle("malicious", "pipe_to_shell")
        result = self._scan(bundle, "--json", "--fail-on", "high")
        self.assertEqual(1, result.returncode, str(result))
        self.assertIsInstance(json.loads(result.stdout), dict)


if __name__ == "__main__":
    unittest.main()
