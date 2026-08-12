"""The exhaustiveness gate from BLUEPRINT.md.

> Every finding ID has >=1 firing malicious fixture (asserted by an exhaustiveness test
> that iterates the registry and fails if any rule has no covering test).

This file iterates ``malskill.rules.REGISTRY`` and fails if any registered ID lacks a
covering fixture, and iterates the blueprint's ID list and fails if any of them is not
registered. Both directions matter: an unregistered rule is a rule nobody runs, and an
uncovered rule is a rule nobody has ever seen fire.
"""

from __future__ import annotations

import dataclasses
import enum
import os
import sys
import unittest
from typing import Dict, List

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import fixture_gen  # noqa: E402
import harness  # noqa: E402

# Finding IDs and severity floors, transcribed from BLUEPRINT.md "Rules (v1 finding IDs)"
# and "Baseline". This is the contract; the registry must satisfy it.
BLUEPRINT_FLOORS: Dict[str, str] = {
    "NETWORK_IN_OFFLINE_CLAIM": "HIGH",
    "SENSITIVE_READ_PLUS_EGRESS": "CRITICAL",
    "CREDENTIAL_PATH_ACCESS": "MEDIUM",
    "DESTRUCTIVE_COMMAND": "HIGH",
    "SELF_MODIFICATION": "CRITICAL",
    "AUTO_APPROVE_TAMPERING": "CRITICAL",
    "OBFUSCATED_EXECUTION": "HIGH",
    "PIPE_TO_SHELL": "HIGH",
    "HIDDEN_INSTRUCTIONS": "HIGH",
    "SYMLINK_ESCAPE": "MEDIUM",
    "PROMPT_INJECTION_IN_METADATA": "HIGH",
    "TOOL_SHADOWING": "MEDIUM",
    "MCP_RUNTIME_REMOTE_CODE": "HIGH",
    "MCP_SECRET_BROADCAST": "MEDIUM",
    "HOOK_EXFIL": "CRITICAL",
    "HOOK_REMOTE_CODE": "HIGH",
    "BASELINE_DRIFT": "MEDIUM",
    "BASELINE_NEW_TARGET": "LOW",
    "BASELINE_TAMPERED": "HIGH",
}

FINDING_FIELDS = (
    "id",
    "severity",
    "target",
    "kind",
    "file",
    "line",
    "evidence",
    "why",
    "recommendation",
    "escalated",
    "escalation_note",
)


def coverage_map() -> Dict[str, List[str]]:
    """finding ID -> the fixtures/tests that prove it fires."""
    covered: Dict[str, List[str]] = {}
    for entry in harness.load_manifest("malicious"):
        ids = entry.get("covers", entry.get("expect_findings", []))
        for finding_id in ids:
            covered.setdefault(finding_id, []).append("fixtures/malicious/" + entry["name"])
    for finding_id, where in fixture_gen.generated_coverage().items():
        covered.setdefault(finding_id, []).append(where)
    return covered


class RegistryShapeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.registry, self.finding_cls, self.severity_cls = harness.import_registry()

    def test_registry_maps_finding_ids_to_metadata(self) -> None:
        self.assertTrue(hasattr(self.registry, "keys"), "REGISTRY must be a mapping of ID -> rule metadata")
        self.assertTrue(self.registry, "REGISTRY is empty")
        for key, value in self.registry.items():
            with self.subTest(finding_id=key):
                self.assertIsInstance(key, str)
                self.assertRegex(key, r"^[A-Z][A-Z0-9_]+$", "finding IDs are SCREAMING_SNAKE_CASE")
                self.assertIsNotNone(value, "REGISTRY[{}] has no metadata".format(key))
                self.assertIsNotNone(
                    harness.rule_metadata_severity(value),
                    "REGISTRY[{}] exposes no severity floor (looked for .severity/.floor): {!r}".format(key, value),
                )

    def test_severity_is_a_str_enum_with_four_levels(self) -> None:
        self.assertTrue(issubclass(self.severity_cls, enum.Enum), "Severity must be an Enum")
        self.assertTrue(issubclass(self.severity_cls, str), "Severity must subclass str (JSON round-trip)")
        names = {member.name for member in self.severity_cls}
        self.assertEqual({"CRITICAL", "HIGH", "MEDIUM", "LOW"}, names)

    def test_finding_is_a_dataclass_with_the_specified_fields(self) -> None:
        self.assertTrue(dataclasses.is_dataclass(self.finding_cls), "Finding must be a dataclass")
        names = {field.name for field in dataclasses.fields(self.finding_cls)}
        missing = [field for field in FINDING_FIELDS if field not in names]
        self.assertEqual([], missing, "Finding is missing fields from the data model: {}".format(missing))

    def test_every_blueprint_id_is_registered(self) -> None:
        missing = sorted(fid for fid in BLUEPRINT_FLOORS if fid not in self.registry)
        self.assertEqual(
            [],
            missing,
            "BLUEPRINT.md defines these finding IDs but the registry does not: {}".format(missing),
        )

    def test_severity_floors_match_the_blueprint(self) -> None:
        for finding_id, expected in sorted(BLUEPRINT_FLOORS.items()):
            if finding_id not in self.registry:
                continue
            with self.subTest(finding_id=finding_id):
                actual = harness.rule_metadata_severity(self.registry[finding_id])
                self.assertEqual(
                    expected,
                    actual,
                    "{} floor is {} in the registry, {} in BLUEPRINT.md".format(finding_id, actual, expected),
                )


class ExhaustivenessGateTests(unittest.TestCase):
    """The gate itself."""

    def setUp(self) -> None:
        self.registry, _finding, _severity = harness.import_registry()
        self.coverage = coverage_map()

    def test_every_registered_finding_id_has_a_covering_fixture(self) -> None:
        uncovered = sorted(fid for fid in self.registry if fid not in self.coverage)
        self.assertEqual(
            [],
            uncovered,
            "these registered finding IDs have no covering fixture or test: {}.\n"
            "Add a directory under fixtures/malicious/ named after the ID (lower case) "
            "and list it in fixtures/malicious/MANIFEST.json, or - for fixtures that "
            "cannot survive a checkout - add a builder to tests/fixture_gen.py.".format(uncovered),
        )

    def test_coverage_claims_reference_real_registry_ids(self) -> None:
        """Catches a typo in a manifest, and a rule that got renamed out from under it."""
        unknown = sorted(fid for fid in self.coverage if fid not in self.registry)
        self.assertEqual(
            [],
            unknown,
            "fixtures claim to cover finding IDs that are not in the registry: {} "
            "(claimed by {})".format(
                unknown, {fid: self.coverage[fid] for fid in unknown}
            ),
        )

    def test_blueprint_ids_are_all_covered(self) -> None:
        """Independent of the registry: the spec's own list must be exercised."""
        uncovered = sorted(fid for fid in BLUEPRINT_FLOORS if fid not in self.coverage)
        self.assertEqual([], uncovered, "no fixture covers: {}".format(uncovered))

    def test_coverage_sources_exist(self) -> None:
        for finding_id, sources in sorted(self.coverage.items()):
            for source in sources:
                with self.subTest(finding_id=finding_id, source=source):
                    if source.startswith("fixtures/"):
                        self.assertTrue(
                            os.path.isdir(os.path.join(harness.REPO_ROOT, source)),
                            "{} claims coverage from a missing directory".format(finding_id),
                        )
                    else:
                        path = source.split("::")[0]
                        self.assertTrue(
                            os.path.isfile(os.path.join(harness.REPO_ROOT, path)),
                            "{} claims coverage from a missing file {}".format(finding_id, path),
                        )


class RulesDocumentationTests(unittest.TestCase):
    """docs/RULES.md is the human half of the registry."""

    def test_rules_doc_exists(self) -> None:
        self.assertTrue(
            os.path.isfile(os.path.join(harness.REPO_ROOT, "docs", "RULES.md")),
            "docs/RULES.md is required by BLUEPRINT.md (every finding ID: trigger, why, action)",
        )

    def test_rules_doc_covers_every_registered_id(self) -> None:
        registry, _finding, _severity = harness.import_registry()
        path = os.path.join(harness.REPO_ROOT, "docs", "RULES.md")
        if not os.path.isfile(path):
            self.fail("docs/RULES.md is missing")
        with open(path, "r", encoding="utf-8") as handle:
            text = handle.read()
        missing = sorted(fid for fid in registry if fid not in text)
        self.assertEqual([], missing, "docs/RULES.md does not document: {}".format(missing))


if __name__ == "__main__":
    unittest.main()
