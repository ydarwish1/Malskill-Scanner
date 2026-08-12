"""Every finding ID has a fixture, and every fixture fires its finding ID.

Parameterised over ``fixtures/malicious/MANIFEST.json`` (checked-in bundles) plus
``tests/fixture_gen.py`` (bundles that cannot survive a checkout: zero-width unicode,
symlinks).

The assertion is *presence*, never exclusivity. A bundle that reads ``~/.ssh`` and posts
the result inherently trips more than one rule, and a scanner that reported only one of
them would be hiding evidence. Incidental extra findings are recorded in the manifest's
``likely_incidental`` field for the reader's benefit and are not asserted.
"""

from __future__ import annotations

import atexit
import os
import shutil
import sys
import tempfile
import unittest
from typing import Any, Dict, List, Tuple

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import fixture_gen  # noqa: E402
import harness  # noqa: E402

_WORKDIR = tempfile.mkdtemp(prefix="malskill-malicious-")
atexit.register(shutil.rmtree, _WORKDIR, True)

_CACHE: Dict[str, Tuple[harness.CliResult, Dict[str, Any]]] = {}


def all_cases() -> List[Dict[str, Any]]:
    """On-disk fixtures first, then the generated ones."""
    cases: List[Dict[str, Any]] = []
    for entry in harness.load_manifest("malicious"):
        item = dict(entry)
        item["source"] = "fixtures/malicious/" + entry["name"]
        cases.append(item)
    for entry in fixture_gen.GENERATED_FIXTURES:
        item = dict(entry)
        item["source"] = "tests/fixture_gen.py::" + entry["name"]
        cases.append(item)
    return cases


def materialise(case: Dict[str, Any], slot: str = "") -> Tuple[str, str]:
    """Return ``(scan_target, fake_home)`` for a case, built inside a temp directory."""
    name = case["name"]
    root = os.path.join(_WORKDIR, name + slot)
    os.makedirs(root, exist_ok=True)
    builder = case.get("builder")
    if builder is not None:
        target = builder(root)
    else:
        target = harness.copy_fixture("malicious", name, os.path.join(root, name))
    home = target if case["mode"] == "home" else harness.make_home(root, "fake-home")
    return target, home


def scan_case(case: Dict[str, Any]) -> Tuple[harness.CliResult, Dict[str, Any]]:
    name = case["name"]
    if name not in _CACHE:
        target, home = materialise(case)
        _CACHE[name] = harness.scan_fixture(case["mode"], target, home)
    return _CACHE[name]


class MaliciousFixtureTests(unittest.TestCase):
    def test_every_fixture_fires_its_finding(self) -> None:
        for case in all_cases():
            expected = case.get("expect_findings", [])
            if not expected:
                continue
            with self.subTest(fixture=case["name"], source=case["source"]):
                result, report = scan_case(case)
                fired = harness.finding_ids(report)
                for finding_id in expected:
                    self.assertIn(
                        finding_id,
                        fired,
                        "{} did not fire {}. Findings actually produced: {}.{}".format(
                            case["source"], finding_id, sorted(set(fired)) or "none", result
                        ),
                    )

    def test_every_fixture_uses_the_specified_exit_code(self) -> None:
        for case in all_cases():
            with self.subTest(fixture=case["name"]):
                result, _ = scan_case(case)
                self.assertEqual(
                    case.get("expect_exit", 1),
                    result.returncode,
                    "{} exit code mismatch (0 = no findings, 1 = findings, 2 = scanner error).{}".format(
                        case["source"], result
                    ),
                )

    def test_unparseable_and_unreadable_inputs_are_loud_not_silent(self) -> None:
        for case in all_cases():
            if not case.get("expect_unscanned"):
                continue
            with self.subTest(fixture=case["name"]):
                result, report = scan_case(case)
                entries = harness.unscanned(report)
                self.assertTrue(
                    entries,
                    "{} must produce at least one NOT-FULLY-ANALYZED record; a parse "
                    "failure or an unreadable file is never a silent pass.{}".format(case["source"], result),
                )
                for entry in entries:
                    self.assertTrue(
                        isinstance(entry, dict) and (entry.get("reason") or entry.get("why")),
                        "unscanned entry must carry a reason: {!r}".format(entry),
                    )

    def test_findings_conform_to_the_data_model(self) -> None:
        """Field-level contract from BLUEPRINT.md's ``Finding`` dataclass."""
        required = ("id", "severity", "target", "kind", "evidence", "why", "recommendation")
        for case in all_cases():
            if not case.get("expect_findings"):
                continue
            with self.subTest(fixture=case["name"]):
                result, report = scan_case(case)
                for finding in harness.findings(report):
                    for field in required:
                        self.assertIn(field, finding, "finding is missing {!r}: {!r}".format(field, finding))
                        self.assertTrue(
                            str(finding[field]).strip(),
                            "finding field {!r} is empty: {!r}".format(field, finding),
                        )
                    evidence = str(finding["evidence"])
                    self.assertLessEqual(
                        len(evidence),
                        400,
                        "evidence must be <= 400 chars, got {} in {}".format(len(evidence), case["source"]),
                    )
                    self.assertNotRegex(
                        evidence,
                        r"https?://",
                        "evidence URLs must be defanged so the report itself is not a "
                        "lure ({}).{}".format(case["source"], result),
                    )

    def test_severity_floors_come_from_the_registry(self) -> None:
        """Without ``--explain`` nothing can escalate, so severity == the rule's floor."""
        registry, _finding_cls, severity_enum = harness.import_registry()
        valid = {harness.normalize_status(member.value) for member in severity_enum}
        for case in all_cases():
            expected = case.get("expect_findings", [])
            if not expected:
                continue
            with self.subTest(fixture=case["name"]):
                _result, report = scan_case(case)
                for finding in harness.findings(report):
                    got = harness.normalize_status(finding.get("severity"))
                    self.assertIn(got, valid, "unknown severity {!r} in {}".format(got, case["source"]))
                    self.assertFalse(
                        finding.get("escalated"),
                        "nothing may be escalated without --explain: {!r}".format(finding),
                    )
                    floor = harness.rule_metadata_severity(registry.get(finding.get("id")))
                    if floor is not None:
                        self.assertEqual(
                            floor,
                            got,
                            "{} reported {} at {}, but the registry floor is {}".format(
                                case["source"], finding.get("id"), got, floor
                            ),
                        )

    def test_terminal_report_names_the_finding(self) -> None:
        """A human reading the default output must see the ID, not a score."""
        case = next(c for c in all_cases() if c["name"] == "pipe_to_shell")
        target, home = materialise(case, slot="-terminal")
        result = harness.run_malskill(["scan", "--home", home, "--paths", target, "--no-baseline"])
        combined = result.stdout + result.stderr
        self.assertEqual(1, result.returncode, str(result))
        self.assertIn("FLAGGED", combined, str(result))
        self.assertIn("PIPE_TO_SHELL", combined, str(result))
        self.assertNotRegex(combined, r"\bSAFE\b", str(result))
        self.assertNotRegex(
            combined,
            r"https?://",
            "URLs in the terminal report must be defanged.{}".format(result),
        )

    def test_manifest_matches_the_directories_on_disk(self) -> None:
        entries = harness.load_manifest("malicious")
        named = sorted(entry["name"] for entry in entries)
        on_disk = sorted(
            name
            for name in os.listdir(harness.MALICIOUS_DIR)
            if os.path.isdir(os.path.join(harness.MALICIOUS_DIR, name)) and not name.startswith(".")
        )
        self.assertEqual(on_disk, named, "fixtures/malicious/MANIFEST.json is out of sync with the directory")
        for entry in entries:
            with self.subTest(fixture=entry["name"]):
                self.assertIn(entry.get("mode"), ("paths", "home"), entry)
                self.assertTrue(entry.get("note"), "fixture {} must explain itself".format(entry["name"]))
                if entry.get("expect_findings"):
                    self.assertTrue(
                        entry["name"].startswith(entry["expect_findings"][0].lower()),
                        "a malicious fixture directory is named after the finding ID it "
                        "proves (optionally with a _variant suffix): {}".format(entry["name"]),
                    )

    def test_generated_fixtures_really_are_generated(self) -> None:
        """The unicode and symlink fixtures must not exist as checked-in directories."""
        for entry in fixture_gen.GENERATED_FIXTURES:
            with self.subTest(fixture=entry["name"]):
                self.assertFalse(
                    os.path.exists(os.path.join(harness.MALICIOUS_DIR, entry["name"])),
                    "{} is generated at test time; a checked-in copy would silently rot".format(entry["name"]),
                )

    def test_generated_unicode_fixture_carries_the_codepoints(self) -> None:
        root = os.path.join(_WORKDIR, "unicode-selfcheck")
        os.makedirs(root, exist_ok=True)
        bundle = fixture_gen.build_hidden_instructions_zero_width(root)
        with open(os.path.join(bundle, "SKILL.md"), "rb") as handle:
            raw = handle.read()
        text = raw.decode("utf-8")
        present = [cp for cp in fixture_gen.HIDDEN_CODEPOINTS if cp in text]
        self.assertGreaterEqual(
            len(present),
            4,
            "generated fixture should carry several hidden codepoints, found {}".format(len(present)),
        )

    def test_generated_symlink_fixture_really_escapes(self) -> None:
        root = os.path.join(_WORKDIR, "symlink-selfcheck")
        os.makedirs(root, exist_ok=True)
        bundle = fixture_gen.build_symlink_escape(root)
        link = os.path.join(bundle, "escaped-absolute.txt")
        self.assertTrue(os.path.islink(link))
        resolved = os.path.realpath(link)
        self.assertFalse(
            resolved.startswith(os.path.realpath(bundle) + os.sep),
            "fixture symlink must resolve outside the bundle root, got {}".format(resolved),
        )


if __name__ == "__main__":
    unittest.main()
