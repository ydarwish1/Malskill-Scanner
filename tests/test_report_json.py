"""Report contract: three states, machine-readable JSON, defanged evidence, no "SAFE".

One scan produces all three states at once - a flagged bundle, an ordinary bundle and a
bundle full of material the scanner cannot fully read - so the report cannot pass by
being right about only one of them.
"""

from __future__ import annotations

import atexit
import json
import os
import re
import shutil
import sys
import tempfile
import unittest
from typing import Any, Dict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import fixture_gen  # noqa: E402
import harness  # noqa: E402

_WORKDIR = tempfile.mkdtemp(prefix="malskill-report-")
atexit.register(shutil.rmtree, _WORKDIR, True)

SAFE_TOKEN = re.compile(r"\bSAFE\b")
STATUS_KEY = re.compile(r"(^|_)(status|state)$", re.IGNORECASE)


class ReportTests(unittest.TestCase):
    """All three states in a single report."""

    mixed_home = ""
    json_result = None  # type: harness.CliResult
    report = {}  # type: Dict[str, Any]
    terminal = None  # type: harness.CliResult

    @classmethod
    def setUpClass(cls) -> None:
        root = os.path.join(_WORKDIR, "mixed")
        os.makedirs(root, exist_ok=True)
        cls.mixed_home = fixture_gen.build_report_state_home(root)
        cls.json_result, cls.report = harness.scan_json(
            ["scan", "--home", cls.mixed_home, "--json", "--no-baseline"], cwd=cls.mixed_home
        )
        cls.terminal = harness.run_malskill(
            ["scan", "--home", cls.mixed_home, "--no-baseline"], cwd=cls.mixed_home
        )

    # -- helpers ------------------------------------------------------------------

    def stats(self) -> Dict[str, Any]:
        for key in ("stats", "summary", "counts", "totals"):
            value = self.report.get(key)
            if isinstance(value, dict):
                return value
        raise AssertionError(
            "JSON report has no stats object (scanned counts, fully/partially analysed). "
            "Report keys were: {}".format(sorted(self.report.keys()))
        )

    # -- structure ----------------------------------------------------------------

    def test_json_round_trips(self) -> None:
        again = json.loads(json.dumps(self.report))
        self.assertEqual(self.report, again)
        reparsed = json.loads(self.json_result.stdout)
        self.assertEqual(self.report, reparsed, "--json stdout must be exactly one JSON document")

    def test_all_three_states_are_present_in_one_report(self) -> None:
        flagged = harness.findings(self.report)
        partial = harness.unscanned(self.report)
        where, clean = harness.clean_indicator(self.report)
        self.assertTrue(flagged, "expected FLAGGED content from the installed pipe-to-shell bundle")
        self.assertTrue(partial, "expected NOT-FULLY-ANALYZED content (oversized/binary/unreadable)")
        self.assertTrue(
            clean not in (None, 0, [], {}, ""),
            "expected a CLEAN indicator ({}) - three report states, never two".format(where),
        )

    def test_overall_status_is_flagged_when_anything_fired(self) -> None:
        self.assertEqual("FLAGGED", harness.overall_status(self.report), str(self.json_result))

    def test_status_vocabulary_is_exactly_the_three_states(self) -> None:
        for path, value in harness.iter_strings(self.report):
            key = path.rsplit(".", 1)[-1].split("[")[0]
            if STATUS_KEY.search(key):
                self.assertIn(
                    harness.normalize_status(value),
                    harness.VALID_STATES,
                    "{} = {!r} is not one of the three report states".format(path, value),
                )

    def test_report_never_says_safe(self) -> None:
        for path, value in harness.iter_strings(self.report):
            key = path.rsplit(".", 1)[-1].split("[")[0]
            if STATUS_KEY.search(key):
                self.assertNotEqual(
                    "SAFE",
                    harness.normalize_status(value),
                    "{} reports SAFE; README principle 6 forbids it".format(path),
                )
        combined = self.terminal.stdout + self.terminal.stderr
        self.assertNotRegex(
            combined,
            SAFE_TOKEN,
            "terminal report printed SAFE.{}".format(self.terminal),
        )
        self.assertNotRegex(
            self.json_result.stdout,
            SAFE_TOKEN,
            "JSON report printed SAFE.{}".format(self.json_result),
        )

    def test_findings_are_named_not_scored(self) -> None:
        for finding in harness.findings(self.report):
            finding_id = str(finding.get("id", ""))
            self.assertRegex(
                finding_id,
                r"^[A-Z][A-Z0-9_]+$",
                "findings are named IDs, never scores: {!r}".format(finding),
            )
            for key in finding:
                self.assertNotIn(
                    key.lower(),
                    ("score", "risk_score", "confidence", "rating"),
                    "numeric scoring is out of scope for v1: {!r}".format(finding),
                )

    def test_unscanned_entries_say_which_file_and_why(self) -> None:
        entries = harness.unscanned(self.report)
        reasons = set()
        for entry in entries:
            self.assertIsInstance(entry, dict)
            self.assertTrue(
                entry.get("file") or entry.get("path"),
                "unscanned entry must name the file: {!r}".format(entry),
            )
            reason = entry.get("reason") or entry.get("why")
            self.assertTrue(reason, "unscanned entry must give a reason: {!r}".format(entry))
            reasons.add(str(reason).lower())
        joined = " ".join(reasons)
        self.assertTrue(
            any(word in joined for word in ("large", "size", "binary", "unread", "permission", "parse")),
            "expected a too-large/binary/unreadable reason, got {}".format(sorted(reasons)),
        )

    def test_stats_report_what_was_and_was_not_analysed(self) -> None:
        stats = self.stats()
        numbers = [v for v in stats.values() if isinstance(v, int)]
        self.assertTrue(numbers, "stats must carry counts, got {!r}".format(stats))

    def test_report_declares_its_version(self) -> None:
        blob = json.dumps(self.report).lower()
        self.assertIn("version", blob, "the JSON report must record the scanner version")

    # -- terminal -----------------------------------------------------------------

    def test_terminal_report_shows_all_three_states(self) -> None:
        combined = self.terminal.stdout + self.terminal.stderr
        for state in ("FLAGGED", "NOT-FULLY-ANALYZED", "CLEAN"):
            self.assertIn(state, combined, "terminal report omits {}.{}".format(state, self.terminal))

    def test_terminal_defangs_urls(self) -> None:
        combined = self.terminal.stdout + self.terminal.stderr
        self.assertNotRegex(
            combined,
            r"https?://",
            "URLs in the report must be defanged so the report cannot be a lure.{}".format(self.terminal),
        )

    def test_show_unscanned_lists_the_files(self) -> None:
        result = harness.run_malskill(
            ["scan", "--home", self.mixed_home, "--no-baseline", "--show-unscanned"], cwd=self.mixed_home
        )
        self.assertEqual(1, result.returncode, str(result))
        combined = result.stdout + result.stderr
        self.assertIn("catalog.txt", combined, "--show-unscanned must list every partial file.{}".format(result))

    # -- exit codes ---------------------------------------------------------------

    def test_exit_code_is_one_when_findings_exist(self) -> None:
        self.assertEqual(1, self.json_result.returncode, str(self.json_result))

    def test_exit_code_is_zero_for_a_clean_scan(self) -> None:
        root = os.path.join(_WORKDIR, "clean")
        os.makedirs(root, exist_ok=True)
        bundle = harness.copy_fixture("benign", "markdown-table-formatter", os.path.join(root, "bundle"))
        home = harness.make_home(root, "home")
        result, report = harness.scan_fixture("paths", bundle, home)
        self.assertEqual(0, result.returncode, str(result))
        self.assertEqual([], harness.finding_ids(report))
        self.assertEqual("CLEAN", harness.overall_status(report))

    def test_exit_code_is_zero_when_only_unscanned_material_exists(self) -> None:
        """NOT-FULLY-ANALYZED alone still exits 0 - but is always shown."""
        root = os.path.join(_WORKDIR, "partial-only")
        os.makedirs(root, exist_ok=True)
        bundle = fixture_gen.build_unscannable(root)
        home = harness.make_home(root, "home")
        result, report = harness.scan_fixture("paths", bundle, home)
        self.assertEqual([], harness.finding_ids(report), str(result))
        self.assertTrue(harness.unscanned(report), "partial analysis must never be silent.{}".format(result))
        self.assertEqual(0, result.returncode, str(result))
        self.assertEqual("NOT-FULLY-ANALYZED", harness.overall_status(report), str(result))

    # -- sanitisation --------------------------------------------------------------

    def test_hidden_codepoints_are_reported_but_not_reproduced_raw(self) -> None:
        """Detect on raw bytes; sanitise only the copy that gets displayed."""
        root = os.path.join(_WORKDIR, "unicode")
        os.makedirs(root, exist_ok=True)
        bundle = fixture_gen.build_hidden_instructions_zero_width(root)
        home = harness.make_home(root, "home")
        result, report = harness.scan_fixture("paths", bundle, home)

        self.assertIn("HIDDEN_INSTRUCTIONS", harness.finding_ids(report), str(result))

        blob = json.dumps(report, ensure_ascii=False)
        for codepoint in fixture_gen.HIDDEN_CODEPOINTS:
            self.assertNotIn(
                codepoint,
                blob,
                "report reproduced U+{:04X} raw; displayed copies must be sanitised".format(ord(codepoint)),
            )
        self.assertIn(
            "200b",
            blob.lower(),
            "the finding must name the codepoints it found (e.g. U+200B).{}".format(result),
        )

        terminal = harness.run_malskill(
            ["scan", "--home", home, "--paths", bundle, "--no-baseline"]
        )
        for codepoint in fixture_gen.HIDDEN_CODEPOINTS:
            self.assertNotIn(
                codepoint,
                terminal.stdout + terminal.stderr,
                "terminal output reproduced U+{:04X} raw".format(ord(codepoint)),
            )


if __name__ == "__main__":
    unittest.main()
