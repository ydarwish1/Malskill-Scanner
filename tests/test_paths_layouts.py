"""``--paths`` on a whole repository keeps every bundle in it separate.

A community skills repository, a plugin marketplace and an application repo with
project skills all put many bundles below one directory. The bundle-level mismatch rules
read claims and pair halves per target, so merging those bundles into one target both
hides findings (one skill's network declaration excuses another's offline claim) and
invents them (one skill's ``~/.ssh`` read pairs with another skill's ``curl``). Each case
below is built from checked-in fixtures and failed before nested bundles were split.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from typing import Any, Dict, List, Tuple

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import harness  # noqa: E402


def _write(path: str, text: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(text)


class RepositoryLayoutTests(unittest.TestCase):
    def setUp(self) -> None:
        self.scratch = tempfile.TemporaryDirectory(prefix="malskill-layouts-")
        self.addCleanup(self.scratch.cleanup)
        self.root = self.scratch.name
        self.home = harness.make_home(self.root, "fake-home")

    def repo(self, name: str = "repo") -> str:
        repo = os.path.join(self.root, name)
        _write(
            os.path.join(repo, ".claude-plugin", "marketplace.json"),
            json.dumps({"name": "community", "plugins": []}),
        )
        _write(os.path.join(repo, "README.md"), "# Community skills\n")
        return repo

    def place(self, kind: str, fixture: str, *parts: str) -> str:
        dest = os.path.join(*parts)
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        return harness.copy_fixture(kind, fixture, dest)

    def scan(self, path: str) -> Tuple[Dict[str, Any], List[Tuple[str, str]]]:
        _, report = harness.scan_json(
            ["scan", "--home", self.home, "--no-baseline", "--paths", path]
        )
        pairs = [(f["id"], f["target"]) for f in harness.findings(report)]
        return report, pairs

    def test_offline_claim_is_not_excused_by_a_sibling_skill(self) -> None:
        repo = self.repo()
        self.place("malicious", "network_in_offline_claim", repo, "skills", "stats")
        self.place("benign", "api-weather-fetch", repo, "skills", "weather")
        _, pairs = self.scan(repo)
        self.assertIn(("NETWORK_IN_OFFLINE_CLAIM", "skill:stats"), pairs)
        self.assertFalse([p for p in pairs if p[1] == "skill:weather"], pairs)

    def test_credential_read_is_reported_on_its_own_skill(self) -> None:
        repo = self.repo()
        self.place("malicious", "credential_path_access", repo, "skills", "fmt")
        self.place("benign", "api-weather-fetch", repo, "skills", "weather")
        _, pairs = self.scan(repo)
        self.assertIn(("CREDENTIAL_PATH_ACCESS", "skill:fmt"), pairs)
        self.assertNotIn("SENSITIVE_READ_PLUS_EGRESS", [p[0] for p in pairs])

    def test_two_benign_skills_do_not_pair_into_exfiltration(self) -> None:
        repo = self.repo()
        self.place("benign", "ssh-key-manager", repo, "skills", "ssh-keys")
        self.place("benign", "api-weather-fetch", repo, "skills", "weather")
        report, pairs = self.scan(repo)
        self.assertEqual([], pairs)
        self.assertEqual("CLEAN", harness.normalize_status(report["state"]))

    def test_project_skills_under_dot_claude_are_split(self) -> None:
        repo = os.path.join(self.root, "app")
        _write(os.path.join(repo, "src", "main.py"), "print('hello')\n")
        self.place("benign", "ssh-key-manager", repo, ".claude", "skills", "ssh-keys")
        self.place("benign", "api-weather-fetch", repo, ".claude", "skills", "weather")
        _, pairs = self.scan(repo)
        self.assertEqual([], pairs)

    def test_a_plugin_stays_one_bundle(self) -> None:
        repo = self.repo()
        plugin = os.path.join(repo, "plugins", "cost")
        _write(
            os.path.join(plugin, ".claude-plugin", "plugin.json"),
            json.dumps({"name": "cost", "version": "1.0.0"}),
        )
        self.place("malicious", "sensitive_read_plus_egress", plugin, "skills", "report")
        self.place("benign", "markdown-table-formatter", plugin, "skills", "tables")
        report, pairs = self.scan(repo)
        self.assertIn(("SENSITIVE_READ_PLUS_EGRESS", "plugin:cost"), pairs)
        names = [t.get("target") or t.get("name") for t in report["targets"]]
        self.assertNotIn("skill:report", names)

    def test_same_named_bundles_get_distinct_names(self) -> None:
        repo = self.repo()
        self.place("malicious", "pipe_to_shell", repo, "a", "skills", "helper")
        self.place("benign", "markdown-table-formatter", repo, "b", "skills", "helper")
        _, pairs = self.scan(repo)
        self.assertIn(("PIPE_TO_SHELL", "skill:a/skills/helper"), pairs)
        self.assertFalse([p for p in pairs if p[1] == "skill:b/skills/helper"], pairs)

    def test_files_between_bundles_are_still_scanned(self) -> None:
        repo = self.repo()
        self.place("benign", "api-weather-fetch", repo, "skills", "weather")
        pipe = os.path.join(harness.MALICIOUS_DIR, "pipe_to_shell", "scripts", "install.sh")
        with open(pipe, "r", encoding="utf-8") as handle:
            _write(os.path.join(repo, "skills", "bootstrap.sh"), handle.read())
        _, pairs = self.scan(repo)
        self.assertIn(("PIPE_TO_SHELL", "skill:skills"), pairs)

    def test_a_single_skill_is_still_one_bundle(self) -> None:
        skill = self.place("malicious", "sensitive_read_plus_egress", self.root, "one")
        report, pairs = self.scan(skill)
        self.assertIn(("SENSITIVE_READ_PLUS_EGRESS", "skill:one"), pairs)
        self.assertEqual(1, report["stats"]["targets"])


if __name__ == "__main__":
    unittest.main()
