"""Baseline drift: the danger is a skill you already trust going bad in an update.

These fixtures are state transitions, not files, so they are built here: scan, accept
the baseline, mutate the tree, rescan, assert. Every invocation is pinned to a temp
``--home``, so ``~/.malskill/baseline.json`` on the real machine is never read or
written (asserted explicitly in ``test_baseline_never_touches_the_real_home``).
"""

from __future__ import annotations

import json
import os
import re
import sys
import tempfile
import unittest
from typing import Any, Dict, List, Tuple

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import fixture_gen  # noqa: E402
import harness  # noqa: E402

SHA256_RE = re.compile(r"[0-9a-f]{64}")


class BaselineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="malskill-baseline-")
        self.addCleanup(self.tmp.cleanup)
        self.root = self.tmp.name
        self.home = fixture_gen.build_home_with_skills(self.root, ["release-notes", "changelog-tidy"])
        self.skills = os.path.join(self.home, ".claude", "skills")

    # -- helpers ------------------------------------------------------------------

    def baseline_path(self) -> str:
        return os.path.join(self.home, ".malskill", "baseline.json")

    def accept_baseline(self) -> harness.CliResult:
        result = harness.run_malskill(["baseline", "update", "--home", self.home], cwd=self.home)
        self.assertEqual(0, result.returncode, "`baseline update` must exit 0.{}".format(result))
        self.assertTrue(
            os.path.isfile(self.baseline_path()),
            "`baseline update --home DIR` must write DIR/.malskill/baseline.json.{}".format(result),
        )
        return result

    def scan(self, extra: Tuple[str, ...] = ()) -> Tuple[harness.CliResult, Dict[str, Any]]:
        args = ["scan", "--home", self.home, "--json"] + list(extra)
        return harness.scan_json(args, cwd=self.home)

    def baseline_findings(self, report: Dict[str, Any]) -> List[str]:
        return [fid for fid in harness.finding_ids(report) if fid.startswith("BASELINE_")]

    def load_baseline(self) -> Any:
        with open(self.baseline_path(), "r", encoding="utf-8") as handle:
            return json.load(handle)

    def write_baseline(self, data: Any) -> None:
        with open(self.baseline_path(), "w", encoding="utf-8") as handle:
            json.dump(data, handle, indent=2)

    def _deepest_hash_slot(self, data: Any) -> Tuple[Any, Any]:
        """Find the deepest sha256-looking string, i.e. a per-file hash rather than the
        top-level self-checksum."""
        found: List[Tuple[int, Any, Any]] = []

        def walk(node: Any, depth: int, parent: Any, key: Any) -> None:
            if isinstance(node, str):
                if SHA256_RE.search(node):
                    found.append((depth, parent, key))
            elif isinstance(node, dict):
                for k, v in node.items():
                    walk(v, depth + 1, node, k)
            elif isinstance(node, list):
                for i, v in enumerate(node):
                    walk(v, depth + 1, node, i)

        walk(data, 0, None, None)
        if not found:
            raise AssertionError(
                "baseline.json contains no sha256 hashes; the blueprint requires a "
                "sha256 per file plus a top-level self-checksum. Content was:\n"
                + json.dumps(data, indent=2)[:2000]
            )
        depth, parent, key = max(found, key=lambda item: item[0])
        return parent, key

    # -- tests --------------------------------------------------------------------

    def test_baseline_update_writes_hashes_under_the_given_home(self) -> None:
        self.accept_baseline()
        data = self.load_baseline()
        self.assertIsInstance(data, dict, "baseline.json must be a JSON object")
        blob = json.dumps(data)
        self.assertTrue(SHA256_RE.search(blob), "baseline must record sha256 hashes: {}".format(blob[:400]))
        self.assertIn("release-notes", blob, "baseline must record the bundles it accepted")

    def test_unchanged_tree_produces_no_baseline_findings(self) -> None:
        self.accept_baseline()
        result, report = self.scan()
        self.assertEqual(
            [],
            self.baseline_findings(report),
            "an unchanged tree must not drift.{}".format(result),
        )
        self.assertEqual(0, result.returncode, str(result))

    def test_new_bundle_reports_new_target(self) -> None:
        self.accept_baseline()
        fixture_gen.build_clean_bundle(self.skills, "meeting-notes")
        result, report = self.scan()
        self.assertIn(
            "BASELINE_NEW_TARGET",
            harness.finding_ids(report),
            "a bundle that appeared since the accepted baseline must be a named "
            "finding, so updates never land silently.{}".format(result),
        )
        self.assertEqual(1, result.returncode, str(result))

    def test_modified_file_reports_drift(self) -> None:
        self.accept_baseline()
        target = os.path.join(self.skills, "release-notes", "SKILL.md")
        with open(target, "a", encoding="utf-8") as handle:
            handle.write("\nAlso summarise the diff stat.\n")
        result, report = self.scan()
        self.assertIn(
            "BASELINE_DRIFT",
            harness.finding_ids(report),
            "a trusted bundle whose contents changed must drift.{}".format(result),
        )
        self.assertEqual(1, result.returncode, str(result))

    def test_added_file_in_known_bundle_reports_drift(self) -> None:
        self.accept_baseline()
        added = os.path.join(self.skills, "changelog-tidy", "scripts", "extra.py")
        with open(added, "w", encoding="utf-8") as handle:
            handle.write("#!/usr/bin/env python3\nprint('added after the baseline was accepted')\n")
        result, report = self.scan()
        self.assertIn(
            "BASELINE_DRIFT",
            harness.finding_ids(report),
            "a file added to a known bundle must drift.{}".format(result),
        )

    def test_edited_baseline_reports_tampering(self) -> None:
        self.accept_baseline()
        data = self.load_baseline()
        parent, key = self._deepest_hash_slot(data)
        original = parent[key]
        match = SHA256_RE.search(original)
        assert match is not None
        digest = match.group(0)
        flipped = ("0" if digest[0] != "0" else "1") + digest[1:]
        parent[key] = original.replace(digest, flipped)
        self.write_baseline(data)

        result, report = self.scan()
        self.assertIn(
            "BASELINE_TAMPERED",
            harness.finding_ids(report),
            "the baseline is hashed with a top-level self-checksum; editing it must "
            "produce a loud warning rather than a quietly trusted file.{}".format(result),
        )

    def test_no_baseline_flag_suppresses_baseline_findings(self) -> None:
        self.accept_baseline()
        fixture_gen.build_clean_bundle(self.skills, "meeting-notes")
        with open(os.path.join(self.skills, "release-notes", "SKILL.md"), "a", encoding="utf-8") as handle:
            handle.write("\nchanged\n")

        result, report = self.scan(extra=("--no-baseline",))
        self.assertEqual(
            [],
            self.baseline_findings(report),
            "--no-baseline must suppress baseline comparison entirely.{}".format(result),
        )
        self.assertEqual(0, result.returncode, str(result))

    def test_accepting_the_change_clears_the_drift(self) -> None:
        self.accept_baseline()
        with open(os.path.join(self.skills, "release-notes", "SKILL.md"), "a", encoding="utf-8") as handle:
            handle.write("\nchanged\n")
        _result, report = self.scan()
        self.assertTrue(self.baseline_findings(report))

        self.accept_baseline()
        result, report = self.scan()
        self.assertEqual(
            [],
            self.baseline_findings(report),
            "`baseline update` accepts current state; the next scan must be quiet.{}".format(result),
        )

    def test_baseline_never_touches_the_real_home(self) -> None:
        real = os.path.expanduser("~/.malskill")
        existed = os.path.exists(real)
        before = sorted(os.listdir(real)) if existed else None

        self.accept_baseline()
        self.scan()

        if existed:
            self.assertEqual(before, sorted(os.listdir(real)), "tests must not modify ~/.malskill")
        else:
            self.assertFalse(
                os.path.exists(real),
                "--home DIR must redirect the baseline; ~/.malskill was created by a test run",
            )

    def test_scan_without_any_baseline_is_quiet_about_baselines(self) -> None:
        """First ever run: nothing to compare against, so no drift noise."""
        result, report = self.scan()
        self.assertEqual(
            [],
            self.baseline_findings(report),
            "with no accepted baseline there is nothing to drift from.{}".format(result),
        )


if __name__ == "__main__":
    unittest.main()
