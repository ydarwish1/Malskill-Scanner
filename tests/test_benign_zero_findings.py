"""The bar, from README.md: a known-benign corpus must produce zero findings.

Every bundle in ``fixtures/benign`` contains something a keyword scanner would flag -
an HTTP client, a read of the SSH directory, a recursive delete, quoted injection
phrasings, a permission allow-list. None of them is a finding, because none of them is
a *mismatch*. If any assertion in this file fails, the fix belongs in the rule, not in
the fixture.
"""

from __future__ import annotations

import os
import re
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import harness  # noqa: E402


class BenignCorpusTests(unittest.TestCase):
    """Zero findings, per bundle and over the corpus as a whole."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="malskill-benign-")
        self.addCleanup(self.tmp.cleanup)
        self.root = self.tmp.name

    # -- helpers ------------------------------------------------------------------

    @staticmethod
    def describe(report) -> str:
        lines = []
        for finding in harness.findings(report):
            lines.append(
                "  [{sev}] {id}  target={target}  file={file}:{line}\n      evidence: {evidence}".format(
                    sev=finding.get("severity"),
                    id=finding.get("id"),
                    target=finding.get("target"),
                    file=finding.get("file"),
                    line=finding.get("line"),
                    evidence=str(finding.get("evidence"))[:200],
                )
            )
        return "\n".join(lines)

    def assert_zero_findings(self, result: harness.CliResult, report, label: str) -> None:
        ids = harness.finding_ids(report)
        self.assertEqual(
            [],
            ids,
            "benign fixture {} produced {} finding(s) - the corpus bar is zero.\n{}\n{}".format(
                label, len(ids), self.describe(report), result
            ),
        )
        self.assertEqual(
            0,
            result.returncode,
            "benign fixture {} exited {}, expected 0 (no findings).{}".format(label, result.returncode, result),
        )
        self.assertNotIn(
            "Traceback (most recent call last)",
            result.stderr,
            "scanner crashed on benign fixture {}.{}".format(label, result),
        )

    # -- tests --------------------------------------------------------------------

    def test_corpus_root_scan_yields_zero_findings(self) -> None:
        """The literal command from BLUEPRINT.md's testing bar.

        Note this requires the scanner to treat each subdirectory of the given path as
        its own bundle: the corpus deliberately puts a credential-reading bundle and a
        network-using bundle in separate directories, and collapsing them into one
        logical bundle would manufacture a cross-bundle finding that does not exist.
        """
        home = harness.make_home(self.root, "empty-home")
        result, report = harness.scan_json(
            ["scan", "--home", home, "--paths", harness.BENIGN_DIR, "--json", "--no-baseline"]
        )
        ids = harness.finding_ids(report)
        self.assertEqual(
            [],
            ids,
            "`scan --paths fixtures/benign` produced {} finding(s); the blueprint's "
            "testing bar is zero.\n{}\n\nTwo causes are worth checking first:\n"
            "  1. a container target that walks the whole tree merges every bundle into "
            "one, which manufactures cross-bundle findings (a credential read in bundle A "
            "plus an HTTP client in bundle B). Loose files at a container root may be "
            "scanned as their own bundle, but that bundle must not also contain the files "
            "of its child bundles.\n"
            "  2. a per-bundle finding that would fire on every real machine (see the "
            "target names above).\n{}".format(len(ids), self.describe(report), result),
        )
        self.assert_zero_findings(result, report, "fixtures/benign (whole corpus)")

    def test_each_bundle_scanned_alone_yields_zero_findings(self) -> None:
        for entry in harness.load_manifest("benign"):
            if entry.get("mode") != "paths":
                continue
            name = entry["name"]
            with self.subTest(fixture=name, trap=entry.get("trap", "")):
                work = os.path.join(self.root, "paths-" + name)
                bundle = harness.copy_fixture("benign", name, work)
                home = harness.make_home(self.root, "home-" + name)
                result, report = harness.scan_fixture("paths", bundle, home)
                self.assert_zero_findings(result, report, "benign/" + name)

    def test_each_home_layout_yields_zero_findings(self) -> None:
        for entry in harness.load_manifest("benign"):
            if entry.get("mode") != "home":
                continue
            name = entry["name"]
            with self.subTest(fixture=name, trap=entry.get("trap", "")):
                work = os.path.join(self.root, "home-layout-" + name)
                home = harness.copy_fixture("benign", name, work)
                result, report = harness.scan_fixture("home", home, home)
                self.assert_zero_findings(result, report, "benign/" + name)

    def test_benign_scan_reports_clean_state(self) -> None:
        """A benign scan must say CLEAN, and must not invent a fourth state."""
        work = os.path.join(self.root, "clean-state")
        bundle = harness.copy_fixture("benign", "markdown-table-formatter", work)
        home = harness.make_home(self.root, "clean-state-home")
        result, report = harness.scan_fixture("paths", bundle, home)
        self.assert_zero_findings(result, report, "benign/markdown-table-formatter")
        self.assertEqual(
            "CLEAN",
            harness.overall_status(report),
            "a benign bundle with nothing unreadable in it must report CLEAN.{}".format(result),
        )

    def test_benign_terminal_output_is_not_a_green_checkmark(self) -> None:
        """CLEAN is reported with its caveat; the word SAFE is never printed."""
        work = os.path.join(self.root, "terminal")
        bundle = harness.copy_fixture("benign", "api-weather-fetch", work)
        home = harness.make_home(self.root, "terminal-home")
        result = harness.run_malskill(["scan", "--home", home, "--paths", bundle, "--no-baseline"])
        self.assertEqual(0, result.returncode, str(result))
        combined = result.stdout + result.stderr
        self.assertIn("CLEAN", combined, "terminal report must name the CLEAN state.{}".format(result))
        self.assertNotRegex(
            combined,
            r"\bSAFE\b",
            "the report must never print SAFE - README, principle 6.{}".format(result),
        )

    def test_traps_are_all_still_present_on_disk(self) -> None:
        """Guard against a fixture being 'fixed' into uselessness.

        Each of these substrings is the thing that makes its bundle a trap. If someone
        removes one to make a scan pass, the corpus stops testing anything.
        """
        required = {
            "api-weather-fetch/scripts/fetch.sh": "curl",
            "ssh-key-manager/scripts/audit_keys.sh": "/.ssh",
            "security-review-docs/README.md": "ignore all previous instructions",
            "static-site-deploy/scripts/deploy.sh": 'rm -rf "$TMPDIR/build"',
            "localhost-metrics/scripts/scrape.sh": "127.0.0.1",
            "mcp-config-standard/.claude.json": "npx",
            "hook-local-formatter/.claude/settings.json": "PostToolUse",
            "settings-with-permissions/.claude/settings.json": '"allow"',
        }
        for relpath, needle in required.items():
            with self.subTest(fixture=relpath):
                full = os.path.join(harness.BENIGN_DIR, relpath)
                self.assertTrue(os.path.isfile(full), "missing benign fixture file {}".format(full))
                with open(full, "r", encoding="utf-8") as handle:
                    text = handle.read()
                # Collapse whitespace: prose traps are line-wrapped in the fixture.
                flat = re.sub(r"\s+", " ", text).lower()
                self.assertIn(
                    re.sub(r"\s+", " ", needle).lower(),
                    flat,
                    "{} no longer contains the trap it exists for ({!r})".format(relpath, needle),
                )

    def test_manifest_matches_the_directories_on_disk(self) -> None:
        entries = harness.load_manifest("benign")
        named = sorted(entry["name"] for entry in entries)
        on_disk = sorted(
            name
            for name in os.listdir(harness.BENIGN_DIR)
            if os.path.isdir(os.path.join(harness.BENIGN_DIR, name)) and not name.startswith(".")
        )
        self.assertEqual(on_disk, named, "fixtures/benign/MANIFEST.json is out of sync with the directory")
        self.assertGreaterEqual(len(entries), 8, "the benign corpus must keep at least 8 bundles")
        for entry in entries:
            self.assertIn(entry.get("mode"), ("paths", "home"), entry)
            self.assertTrue(entry.get("trap"), "benign fixture {} must document its trap".format(entry["name"]))


if __name__ == "__main__":
    unittest.main()
