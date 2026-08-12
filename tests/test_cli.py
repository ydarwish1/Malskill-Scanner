"""CLI surface: the subcommands, the flags, the exit codes, the shim.

Nothing here scans anything interesting; it checks that the front door behaves. Every
discovery invocation is pinned to an empty temp ``--home`` so an accidental default of
``~`` shows up as a test failure rather than as a scan of the developer's machine.
"""

from __future__ import annotations

import json
import os
import stat
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import harness  # noqa: E402


class CliTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="malskill-cli-")
        self.addCleanup(self.tmp.cleanup)
        self.root = self.tmp.name
        self.empty_home = harness.make_home(self.root, "empty-home")

    # -- help ---------------------------------------------------------------------

    def test_help_lists_every_subcommand(self) -> None:
        result = harness.run_malskill(["--help"], require_home=False)
        self.assertEqual(0, result.returncode, str(result))
        combined = result.stdout + result.stderr
        for subcommand in ("scan", "baseline", "list", "rules"):
            self.assertIn(subcommand, combined, "--help omits {}.{}".format(subcommand, result))

    def test_scan_help_lists_the_documented_flags(self) -> None:
        result = harness.run_malskill(["scan", "--help"], require_home=False)
        self.assertEqual(0, result.returncode, str(result))
        combined = result.stdout + result.stderr
        for flag in ("--home", "--paths", "--json", "--show-unscanned", "--explain", "--no-baseline"):
            self.assertIn(flag, combined, "`scan --help` omits {}.{}".format(flag, result))

    def test_baseline_help_documents_update(self) -> None:
        result = harness.run_malskill(["baseline", "--help"], require_home=False)
        self.assertEqual(0, result.returncode, str(result))
        self.assertIn("update", result.stdout + result.stderr, str(result))

    # -- rules --------------------------------------------------------------------

    def test_rules_prints_every_registered_finding_id(self) -> None:
        registry, _finding, _severity = harness.import_registry()
        result = harness.run_malskill(["rules"], require_home=False)
        self.assertEqual(0, result.returncode, str(result))
        combined = result.stdout + result.stderr
        missing = sorted(fid for fid in registry if fid not in combined)
        self.assertEqual(
            [],
            missing,
            "`malskill rules` must summarise every finding ID; missing {}.{}".format(missing, result),
        )

    # -- list ---------------------------------------------------------------------

    def test_list_on_an_empty_home_succeeds_and_says_nothing_alarming(self) -> None:
        result = harness.run_malskill(["list", "--home", self.empty_home])
        self.assertEqual(0, result.returncode, "`list` on an empty home must exit 0.{}".format(result))
        self.assertNotIn("Traceback (most recent call last)", result.stderr, str(result))
        self.assertNotRegex(result.stdout + result.stderr, r"\bSAFE\b", str(result))

    def test_list_names_the_targets_it_found(self) -> None:
        home = harness.copy_fixture("benign", "home-user-skills", os.path.join(self.root, "populated-home"))
        result = harness.run_malskill(["list", "--home", home], cwd=home)
        self.assertEqual(0, result.returncode, str(result))
        combined = result.stdout + result.stderr
        for name in ("note-taker", "code-reviewer"):
            self.assertIn(name, combined, "`list` did not report {}.{}".format(name, result))

    def test_list_does_not_run_rules(self) -> None:
        """Inventory only: a malicious bundle produces no findings from `list`."""
        home = harness.make_home(self.root, "mal-home")
        skills = os.path.join(home, ".claude", "skills")
        os.makedirs(skills)
        harness.copy_fixture("malicious", "pipe_to_shell", os.path.join(skills, "toolchain-installer"))
        result = harness.run_malskill(["list", "--home", home], cwd=home)
        self.assertEqual(0, result.returncode, "`list` never fires rules, so it never exits 1.{}".format(result))
        self.assertNotIn("PIPE_TO_SHELL", result.stdout + result.stderr, str(result))

    # -- scan basics ---------------------------------------------------------------

    def test_scan_of_an_empty_home_is_clean_and_exits_zero(self) -> None:
        result, report = harness.scan_json(["scan", "--home", self.empty_home, "--json", "--no-baseline"])
        self.assertEqual(0, result.returncode, str(result))
        self.assertEqual([], harness.finding_ids(report), str(result))

    def test_scan_json_is_valid_json_on_an_empty_home(self) -> None:
        result = harness.run_malskill(["scan", "--home", self.empty_home, "--json", "--no-baseline"])
        self.assertEqual(0, result.returncode, str(result))
        json.loads(result.stdout)

    def test_scan_accepts_multiple_paths(self) -> None:
        first = harness.copy_fixture("benign", "markdown-table-formatter", os.path.join(self.root, "a"))
        second = harness.copy_fixture("benign", "localhost-metrics", os.path.join(self.root, "b"))
        result, report = harness.scan_json(
            ["scan", "--home", self.empty_home, "--paths", first, second, "--json", "--no-baseline"]
        )
        self.assertEqual([], harness.finding_ids(report), str(result))
        self.assertEqual(0, result.returncode, str(result))

    # -- errors --------------------------------------------------------------------

    def test_unknown_subcommand_exits_two(self) -> None:
        result = harness.run_malskill(["definitely-not-a-subcommand"], require_home=False)
        self.assertEqual(2, result.returncode, "usage errors exit 2.{}".format(result))

    def test_unknown_flag_exits_two(self) -> None:
        result = harness.run_malskill(["scan", "--home", self.empty_home, "--not-a-flag"])
        self.assertEqual(2, result.returncode, "usage errors exit 2.{}".format(result))

    def test_no_arguments_does_not_crash(self) -> None:
        result = harness.run_malskill([], require_home=False)
        self.assertIn(result.returncode, (0, 2), "bare invocation must print usage, not a traceback.{}".format(result))
        self.assertNotIn("Traceback (most recent call last)", result.stderr, str(result))

    def test_explain_without_the_binary_changes_nothing(self) -> None:
        """No `claude` on PATH: skip silently, note it in the footer, keep the findings."""
        skills = os.path.join(self.root, "explain-home", ".claude", "skills")
        os.makedirs(skills)
        harness.copy_fixture("malicious", "pipe_to_shell", os.path.join(skills, "toolchain-installer"))
        home = os.path.join(self.root, "explain-home")

        plain = harness.run_malskill(["scan", "--home", home, "--json", "--no-baseline"], cwd=home)
        explained = harness.run_malskill(
            ["scan", "--home", home, "--json", "--no-baseline", "--explain"],
            cwd=home,
            env_overrides={"PATH": os.path.join(self.root, "no-binaries-here")},
        )
        self.assertEqual(plain.returncode, explained.returncode, str(explained))
        before = json.loads(plain.stdout)
        after = json.loads(explained.stdout)
        self.assertEqual(
            harness.finding_ids(before),
            harness.finding_ids(after),
            "an absent explainer must never change the deterministic result.{}".format(explained),
        )
        for finding in harness.findings(after):
            self.assertFalse(finding.get("escalated"), "nothing can be escalated with no explainer")

    # -- packaging -----------------------------------------------------------------

    def test_package_exposes_a_version(self) -> None:
        if harness.REPO_ROOT not in sys.path:
            sys.path.insert(0, harness.REPO_ROOT)
        import malskill

        self.assertIsInstance(malskill.__version__, str)
        self.assertTrue(malskill.__version__.strip())

    def test_bin_shim_exists_and_is_executable(self) -> None:
        self.assertTrue(os.path.isfile(harness.BIN_SHIM), "bin/malskill shim is missing")
        mode = os.stat(harness.BIN_SHIM).st_mode
        self.assertTrue(mode & stat.S_IXUSR, "bin/malskill must be executable")

    def test_bin_shim_runs_the_scanner(self) -> None:
        if not os.path.isfile(harness.BIN_SHIM):
            self.fail("bin/malskill shim is missing")
        result = harness.run_shim(["scan", "--home", self.empty_home, "--json", "--no-baseline"])
        self.assertEqual(0, result.returncode, str(result))
        json.loads(result.stdout)


if __name__ == "__main__":
    unittest.main()
