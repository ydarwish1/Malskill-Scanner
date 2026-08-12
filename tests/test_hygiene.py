"""Hygiene gates on the scanner source and on this repository's own fixtures.

Source side (BLUEPRINT.md, "Testing bar" item 6 and "Language / deps"):

* stdlib only - no pip dependency may creep in;
* ``import yaml`` nowhere, ever - the extractor runs trusted and before everything else,
  so it gets a minimal safe frontmatter parser, not a YAML engine;
* ``subprocess`` only in ``explain.py`` - the zero-tool explainer is the single place
  allowed to start a process, and grep must be able to prove it in one line.

Fixture side: the malicious corpus has to stay inert, and this file is what keeps it
that way.
"""

from __future__ import annotations

import ast
import json
import os
import re
import stat
import sys
import unittest
from typing import Iterator, List, Set

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import harness  # noqa: E402

SUBPROCESS_ALLOWED_IN = {"explain.py"}

# Module files BLUEPRINT.md's "Repo layout" section requires.
REQUIRED_MODULES = (
    "__init__.py",
    "__main__.py",
    "cli.py",
    "inventory.py",
    "targets.py",
    "frontmatter.py",
    "claims.py",
    "sanitize.py",
    "baseline.py",
    "report.py",
    "explain.py",
    os.path.join("rules", "__init__.py"),
    os.path.join("rules", "engine.py"),
    os.path.join("rules", "r_network_claims.py"),
    os.path.join("rules", "r_exfil.py"),
    os.path.join("rules", "r_credentials.py"),
    os.path.join("rules", "r_obfuscation.py"),
    os.path.join("rules", "r_pipe_to_shell.py"),
    os.path.join("rules", "r_destructive.py"),
    os.path.join("rules", "r_hooks.py"),
    os.path.join("rules", "r_injection.py"),
    os.path.join("rules", "r_self_modify.py"),
    os.path.join("rules", "r_mcp_config.py"),
    os.path.join("rules", "r_unscannable.py"),
)

_FALLBACK_STDLIB = {
    "__future__", "abc", "argparse", "array", "ast", "atexit", "base64", "binascii", "bisect", "builtins",
    "bz2", "calendar", "codecs", "collections", "colorsys", "concurrent", "configparser",
    "contextlib", "copy", "csv", "ctypes", "dataclasses", "datetime", "decimal", "difflib",
    "dis", "email", "encodings", "enum", "errno", "fcntl", "filecmp", "fileinput", "fnmatch",
    "fractions", "functools", "gc", "getpass", "gettext", "glob", "grp", "gzip", "hashlib",
    "heapq", "hmac", "html", "http", "imp", "importlib", "inspect", "io", "ipaddress",
    "itertools", "json", "keyword", "linecache", "locale", "logging", "lzma", "marshal",
    "math", "mimetypes", "multiprocessing", "numbers", "operator", "os", "pathlib", "pickle",
    "pkgutil", "platform", "plistlib", "posixpath", "pprint", "pwd", "queue", "quopri",
    "random", "re", "reprlib", "resource", "secrets", "select", "shelve", "shlex", "shutil",
    "signal", "site", "socket", "sqlite3", "ssl", "stat", "statistics", "string", "stringprep",
    "struct", "subprocess", "sys", "sysconfig", "tarfile", "tempfile", "termios", "textwrap",
    "threading", "time", "timeit", "token", "tokenize", "tomllib", "traceback", "types",
    "typing", "unicodedata", "unittest", "urllib", "uuid", "warnings", "weakref", "webbrowser",
    "xml", "zipfile", "zlib", "zoneinfo",
}


def stdlib_names() -> Set[str]:
    names = getattr(sys, "stdlib_module_names", None)
    if names:
        return set(names) | _FALLBACK_STDLIB
    return set(_FALLBACK_STDLIB)


def iter_source_files() -> Iterator[str]:
    for dirpath, dirnames, filenames in os.walk(harness.MALSKILL_PKG):
        dirnames[:] = [d for d in dirnames if d not in ("__pycache__", ".git")]
        for name in sorted(filenames):
            if name.endswith(".py"):
                yield os.path.join(dirpath, name)


def read(path: str) -> str:
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        return handle.read()


class SourceHygieneTests(unittest.TestCase):
    def setUp(self) -> None:
        if not os.path.isdir(harness.MALSKILL_PKG):
            self.fail(
                "malskill/ does not exist. The suite is written against BLUEPRINT.md and "
                "fails until the package lands - that is the intended state, not a skip."
            )
        self.sources = list(iter_source_files())
        self.assertTrue(self.sources, "malskill/ contains no Python source files")

    def test_required_modules_exist(self) -> None:
        missing = [
            rel for rel in REQUIRED_MODULES if not os.path.isfile(os.path.join(harness.MALSKILL_PKG, rel))
        ]
        self.assertEqual([], missing, "BLUEPRINT.md repo layout is missing: {}".format(missing))

    def test_no_yaml_anywhere(self) -> None:
        """Not imported, not lazily imported, not optional.

        Checked on the AST rather than with grep, so that ``frontmatter.py`` stays free
        to say in its own docstring *why* it does not use yaml - which is the point.
        """
        offenders: List[str] = []
        for path in self.sources:
            rel = os.path.relpath(path, harness.REPO_ROOT)
            text = read(path)
            for node in ast.walk(ast.parse(text, filename=path)):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        if alias.name.split(".")[0] == "yaml":
                            offenders.append("{}:{}: import yaml".format(rel, node.lineno))
                elif isinstance(node, ast.ImportFrom):
                    if (node.module or "").split(".")[0] == "yaml":
                        offenders.append("{}:{}: from yaml import ...".format(rel, node.lineno))
            for match in re.finditer(r"""(?:__import__|import_module)\(\s*['"]yaml""", text):
                offenders.append("{}: dynamic yaml import at offset {}".format(rel, match.start()))
        self.assertEqual(
            [],
            offenders,
            "the extractor runs trusted and must never hand bytes to a YAML engine:\n"
            + "\n".join(offenders),
        )

    def test_subprocess_only_in_explain(self) -> None:
        """Only the zero-tool explainer may start a process.

        Checked on the AST: importing ``subprocess``, or referencing the name at all,
        outside ``explain.py`` is a failure. A rule module is still allowed to carry the
        *string* "subprocess" inside a detection pattern - matching that word in someone
        else's script is the job, and a string literal cannot start a process.
        """
        offenders: List[str] = []
        for path in self.sources:
            rel = os.path.relpath(path, harness.REPO_ROOT)
            if os.path.basename(path) in SUBPROCESS_ALLOWED_IN:
                continue
            for node in ast.walk(ast.parse(read(path), filename=path)):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        if alias.name.split(".")[0] == "subprocess":
                            offenders.append("{}:{}: import subprocess".format(rel, node.lineno))
                elif isinstance(node, ast.ImportFrom):
                    if (node.module or "").split(".")[0] == "subprocess":
                        offenders.append("{}:{}: from subprocess import ...".format(rel, node.lineno))
                elif isinstance(node, ast.Name) and node.id == "subprocess":
                    offenders.append("{}:{}: reference to subprocess".format(rel, node.lineno))
        self.assertEqual(
            [],
            offenders,
            "subprocess is allowed only in explain.py (the zero-tool explainer):\n" + "\n".join(offenders),
        )

    def test_explainer_is_the_only_process_starter(self) -> None:
        forbidden = re.compile(r"\b(os\.system|os\.popen|os\.exec[lv]|pty\.spawn|commands\.getoutput)\b")
        offenders = []
        for path in self.sources:
            for lineno, line in enumerate(read(path).splitlines(), start=1):
                if forbidden.search(line):
                    offenders.append("{}:{}: {}".format(os.path.relpath(path, harness.REPO_ROOT), lineno, line.strip()))
        self.assertEqual([], offenders, "nothing may exec content from a scanned bundle:\n" + "\n".join(offenders))

    def test_every_source_file_parses(self) -> None:
        for path in self.sources:
            with self.subTest(source=os.path.relpath(path, harness.REPO_ROOT)):
                ast.parse(read(path), filename=path)

    def test_imports_are_stdlib_only(self) -> None:
        allowed = stdlib_names()
        offenders: List[str] = []
        for path in self.sources:
            tree = ast.parse(read(path), filename=path)
            rel = os.path.relpath(path, harness.REPO_ROOT)
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    names = [alias.name for alias in node.names]
                elif isinstance(node, ast.ImportFrom):
                    if node.level:  # relative import inside the package
                        continue
                    names = [node.module or ""]
                else:
                    continue
                for name in names:
                    root = name.split(".")[0]
                    if not root or root == "malskill" or root in allowed:
                        continue
                    offenders.append("{}:{}: {}".format(rel, getattr(node, "lineno", 0), name))
        self.assertEqual(
            [],
            offenders,
            "the scanner is stdlib-only; no pip dependency may be imported:\n" + "\n".join(offenders),
        )

    def test_no_dependency_manifest_declares_dependencies(self) -> None:
        for name in ("requirements.txt", "requirements-dev.txt", "Pipfile", "poetry.lock"):
            path = os.path.join(harness.REPO_ROOT, name)
            if not os.path.isfile(path):
                continue
            lines = [
                line.strip()
                for line in read(path).splitlines()
                if line.strip() and not line.strip().startswith("#")
            ]
            self.assertEqual([], lines, "{} declares dependencies; v1 is stdlib only".format(name))


class CorpusHygieneTests(unittest.TestCase):
    """The fixtures must stay inert. This is the guard on our own deliverable."""

    ALLOWED_HOSTS = {
        "localhost",
        "127.0.0.1",
        "0.0.0.0",
        "::1",
        "[::1]",
        "api.open-meteo.com",
        "github.com",
        "ghcr.io",
    }

    def iter_fixture_files(self) -> Iterator[str]:
        for dirpath, dirnames, filenames in os.walk(harness.FIXTURES_DIR):
            dirnames[:] = [d for d in dirnames if d != ".git"]
            for name in filenames:
                yield os.path.join(dirpath, name)

    def test_no_fixture_file_is_executable(self) -> None:
        offenders = []
        for path in self.iter_fixture_files():
            mode = os.lstat(path).st_mode
            if stat.S_ISLNK(mode):
                continue
            if mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH):
                offenders.append(os.path.relpath(path, harness.REPO_ROOT))
        self.assertEqual([], offenders, "fixture scripts must carry no execute bit: {}".format(offenders))

    def test_every_host_referenced_is_reserved_or_local(self) -> None:
        url_re = re.compile(r"https?://([A-Za-z0-9_.:\[\]-]+)")
        offenders = []
        for path in self.iter_fixture_files():
            text = read(path)
            for host in url_re.findall(text):
                if host.startswith("["):
                    bare = host[1:host.index("]")] if "]" in host else host.strip("[]")
                else:
                    bare = host.split(":")[0]
                if host in self.ALLOWED_HOSTS or bare in self.ALLOWED_HOSTS:
                    continue
                if re.search(r"(^|\.)example\.(com|net|org)$", bare):
                    continue
                offenders.append("{}: {}".format(os.path.relpath(path, harness.REPO_ROOT), host))
        self.assertEqual(
            [],
            offenders,
            "fixtures may only reference reserved example hosts or the loopback: {}".format(offenders),
        )

    def test_credential_values_are_obviously_fake(self) -> None:
        path = os.path.join(harness.MALICIOUS_DIR, "mcp_secret_broadcast", ".claude.json")
        with open(path, "r", encoding="utf-8") as handle:
            config = json.load(handle)
        values = []
        for server in config.get("mcpServers", {}).values():
            values.extend(server.get("env", {}).values())
        self.assertTrue(values, "the secret-broadcast fixture must carry env values")
        for value in values:
            self.assertIn(
                "FAKE-KEY-FOR-TESTING",
                value,
                "every credential-shaped fixture value must be branded fake: {!r}".format(value),
            )

    def test_dangerous_fixtures_have_an_inert_shebang(self) -> None:
        required = {
            "destructive_command": "scripts/clean.sh",
            "self_modification": "scripts/install.sh",
            "auto_approve_tampering": "scripts/enable.sh",
            "pipe_to_shell": "scripts/install.sh",
            "obfuscated_execution": "scripts/bootstrap.sh",
        }
        for fixture, relpath in sorted(required.items()):
            with self.subTest(fixture=fixture):
                path = os.path.join(harness.MALICIOUS_DIR, fixture, relpath)
                self.assertTrue(os.path.isfile(path), "missing {}".format(path))
                first_line = read(path).splitlines()[0]
                self.assertEqual(
                    "#!/bin/echo INERT-TEST-FIXTURE-DO-NOT-EXECUTE",
                    first_line,
                    "a fixture that would damage a machine if run must not have a working shebang",
                )

    def test_no_fixture_uses_the_word_safe(self) -> None:
        """Keeps the 'never print SAFE' assertions honest: nothing can echo it back."""
        offenders = []
        for path in self.iter_fixture_files():
            if re.search(r"\bSAFE\b", read(path)):
                offenders.append(os.path.relpath(path, harness.REPO_ROOT))
        self.assertEqual([], offenders, "fixture content would pollute the no-SAFE report check: {}".format(offenders))

    def test_manifests_are_valid_json(self) -> None:
        for kind in ("benign", "malicious"):
            with self.subTest(kind=kind):
                self.assertTrue(harness.load_manifest(kind))


if __name__ == "__main__":
    unittest.main()
