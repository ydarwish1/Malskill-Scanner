"""Shared helpers for the MalSkill Scanner test suite.

Everything in here exists to keep the tests hermetic and the failure messages useful:

* every scanner invocation runs as a subprocess (`python3 -m malskill ...`) with
  ``PYTHONPATH`` pointed at the repo, ``cwd`` pointed at an empty scratch directory, and
  ``--home`` pointed at a per-test temp directory, so no test can read or write the real
  machine's ``~/.claude`` state;
* the JSON report is read through small tolerant accessors, so a naming difference in
  the implementation produces one legible failure instead of forty ``KeyError``s.

The accessors document, in code, the JSON contract the suite assumes. See
``tests/README.md`` for the prose version.
"""

from __future__ import annotations

import atexit
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from typing import Any, Dict, Iterator, List, Optional, Sequence, Tuple

# --------------------------------------------------------------------------------------
# Paths
# --------------------------------------------------------------------------------------

TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(TESTS_DIR)
FIXTURES_DIR = os.path.join(REPO_ROOT, "fixtures")
BENIGN_DIR = os.path.join(FIXTURES_DIR, "benign")
MALICIOUS_DIR = os.path.join(FIXTURES_DIR, "malicious")
MALSKILL_PKG = os.path.join(REPO_ROOT, "malskill")
BIN_SHIM = os.path.join(REPO_ROOT, "bin", "malskill")

DEFAULT_TIMEOUT = 180

VALID_STATES = ("FLAGGED", "CLEAN", "NOT-FULLY-ANALYZED")

# A neutral working directory: empty, so no `.claude/` project discovery can ever pick
# up the repository (or the developer's) files during a test run.
_NEUTRAL_CWD = tempfile.mkdtemp(prefix="malskill-neutral-cwd-")
atexit.register(shutil.rmtree, _NEUTRAL_CWD, True)


# --------------------------------------------------------------------------------------
# Running the CLI
# --------------------------------------------------------------------------------------


class CliResult:
    """A finished CLI invocation, with a readable repr for assertion messages."""

    def __init__(self, argv: Sequence[str], proc: "subprocess.CompletedProcess[str]"):
        self.argv = list(argv)
        self.returncode = proc.returncode
        self.stdout = proc.stdout or ""
        self.stderr = proc.stderr or ""

    def __str__(self) -> str:  # pragma: no cover - only used in failure output
        return (
            "\n--- command ---\n{cmd}\n--- exit ---\n{code}\n"
            "--- stdout ({olen} bytes) ---\n{out}\n--- stderr ({elen} bytes) ---\n{err}\n"
        ).format(
            cmd=" ".join(self.argv),
            code=self.returncode,
            olen=len(self.stdout),
            out=_clip(self.stdout),
            elen=len(self.stderr),
            err=_clip(self.stderr),
        )

    __repr__ = __str__


def _clip(text: str, limit: int = 6000) -> str:
    if len(text) <= limit:
        return text
    return text[:limit] + "\n... [{} more chars]".format(len(text) - limit)


def run_malskill(
    args: Sequence[str],
    cwd: Optional[str] = None,
    timeout: int = DEFAULT_TIMEOUT,
    require_home: bool = True,
    env_overrides: Optional[Dict[str, str]] = None,
) -> CliResult:
    """Run ``python3 -m malskill <args>`` in a subprocess and capture everything.

    ``require_home`` guards the suite against itself: any subcommand that performs
    discovery must be given an explicit ``--home``, otherwise the test would read the
    real machine.
    """
    argv = [sys.executable, "-m", "malskill"] + list(args)
    if require_home and args and args[0] in ("scan", "baseline", "list"):
        if "--home" not in args:
            raise AssertionError(
                "test bug: {!r} must be given --home so it cannot touch the real "
                "machine".format(list(args))
            )

    env = dict(os.environ)
    existing = env.get("PYTHONPATH")
    env["PYTHONPATH"] = REPO_ROOT + (os.pathsep + existing if existing else "")
    env["PYTHONIOENCODING"] = "utf-8"
    env["NO_COLOR"] = "1"
    env["TERM"] = "dumb"
    env["COLUMNS"] = "120"
    # Never let ambient agent state leak into a test run.
    for key in [k for k in env if k.startswith("CLAUDE")]:
        env.pop(key, None)
    if env_overrides:
        env.update(env_overrides)

    proc = subprocess.run(
        argv,
        cwd=cwd or _NEUTRAL_CWD,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        universal_newlines=True,
        timeout=timeout,
    )
    return CliResult(argv, proc)


def run_shim(args: Sequence[str], cwd: Optional[str] = None) -> CliResult:
    """Run the ``bin/malskill`` shim instead of the module entry point."""
    argv = [BIN_SHIM] + list(args)
    env = dict(os.environ)
    existing = env.get("PYTHONPATH")
    env["PYTHONPATH"] = REPO_ROOT + (os.pathsep + existing if existing else "")
    env["NO_COLOR"] = "1"
    proc = subprocess.run(
        argv,
        cwd=cwd or _NEUTRAL_CWD,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        universal_newlines=True,
        timeout=DEFAULT_TIMEOUT,
    )
    return CliResult(argv, proc)


def scan_json(args: Sequence[str], cwd: Optional[str] = None) -> Tuple[CliResult, Dict[str, Any]]:
    """Run ``scan --json`` and parse stdout. Raises AssertionError with full context."""
    argv = list(args)
    if "--json" not in argv:
        argv.append("--json")
    result = run_malskill(argv, cwd=cwd)
    if result.returncode not in (0, 1):
        raise AssertionError("scanner did not complete (exit {}):{}".format(result.returncode, result))
    try:
        report = json.loads(result.stdout)
    except ValueError as exc:
        raise AssertionError("--json stdout is not a single JSON document ({}):{}".format(exc, result))
    if not isinstance(report, dict):
        raise AssertionError("--json report must be a JSON object, got {}:{}".format(type(report).__name__, result))
    return result, report


# --------------------------------------------------------------------------------------
# Report accessors (the assumed JSON contract)
# --------------------------------------------------------------------------------------


def _candidate_containers(report: Dict[str, Any]) -> Iterator[Dict[str, Any]]:
    yield report
    for key in ("report", "result", "data", "summary", "stats", "counts", "totals"):
        value = report.get(key)
        if isinstance(value, dict):
            yield value


def _find_list(report: Dict[str, Any], names: Sequence[str]) -> Optional[List[Any]]:
    for container in _candidate_containers(report):
        for name in names:
            value = container.get(name)
            if isinstance(value, list):
                return value
    return None


def _find_scalar(report: Dict[str, Any], names: Sequence[str]) -> Optional[Any]:
    for container in _candidate_containers(report):
        for name in names:
            if name in container and not isinstance(container[name], (list, dict)):
                return container[name]
    return None


def findings(report: Dict[str, Any]) -> List[Dict[str, Any]]:
    """The FLAGGED list. Contract: ``report["findings"]`` is a list of finding objects."""
    value = _find_list(report, ("findings", "flagged"))
    if value is None:
        raise AssertionError(
            "JSON report has no findings list. Expected a top-level \"findings\" array. "
            "Report keys were: {}".format(sorted(report.keys()))
        )
    for item in value:
        if not isinstance(item, dict):
            raise AssertionError("findings[] entries must be objects, got {!r}".format(item))
    return value


def finding_ids(report: Dict[str, Any]) -> List[str]:
    ids = []
    for finding in findings(report):
        value = finding.get("id") or finding.get("finding_id") or finding.get("rule_id")
        if value is None:
            raise AssertionError("finding object has no \"id\" field: {!r}".format(finding))
        ids.append(str(value))
    return ids


def finding_field(finding: Dict[str, Any], *names: str) -> Any:
    for name in names:
        if name in finding:
            return finding[name]
    return None


def unscanned(report: Dict[str, Any]) -> List[Dict[str, Any]]:
    """The NOT-FULLY-ANALYZED list. Contract: ``report["unscanned"]``."""
    value = _find_list(
        report,
        ("unscanned", "not_fully_analyzed", "notFullyAnalyzed", "not-fully-analyzed", "partial"),
    )
    if value is None:
        raise AssertionError(
            "JSON report has no unscanned list. Expected a top-level \"unscanned\" array "
            "(NOT-FULLY-ANALYZED is a first-class report state, never silent). "
            "Report keys were: {}".format(sorted(report.keys()))
        )
    return value


def normalize_status(value: Any) -> str:
    return re.sub(r"[\s_]+", "-", str(value).strip().upper())


def overall_status(report: Dict[str, Any]) -> str:
    value = _find_scalar(report, ("status", "state", "overall_status", "overallStatus", "result"))
    if value is None:
        raise AssertionError(
            "JSON report has no overall status field. Expected \"status\" with one of "
            "{}. Report keys were: {}".format(VALID_STATES, sorted(report.keys()))
        )
    return normalize_status(value)


def clean_indicator(report: Dict[str, Any]) -> Tuple[str, Any]:
    """Locate the CLEAN part of the three-state report.

    Returns ``(where, value)``. Raises if the report gives no way at all to see which
    targets were scanned and produced nothing - a two-state report is a spec violation.
    """
    for container in _candidate_containers(report):
        for name in sorted(container.keys()):
            if "clean" in name.lower():
                return ("key:" + name, container[name])
    targets = _find_list(report, ("targets", "bundles", "scanned", "inventory"))
    if targets:
        statuses = [
            normalize_status(t.get("status") or t.get("state"))
            for t in targets
            if isinstance(t, dict) and (t.get("status") or t.get("state"))
        ]
        if "CLEAN" in statuses:
            return ("targets[].status", statuses)
    raise AssertionError(
        "JSON report exposes no CLEAN state: no *clean* key anywhere and no "
        "targets[].status == CLEAN. Three report states are mandatory. "
        "Report keys were: {}".format(sorted(report.keys()))
    )


def iter_strings(node: Any, path: str = "$") -> Iterator[Tuple[str, str]]:
    """Yield ``(json-path, value)`` for every string in a decoded JSON document."""
    if isinstance(node, str):
        yield (path, node)
    elif isinstance(node, dict):
        for key, value in node.items():
            for item in iter_strings(value, "{}.{}".format(path, key)):
                yield item
    elif isinstance(node, list):
        for index, value in enumerate(node):
            for item in iter_strings(value, "{}[{}]".format(path, index)):
                yield item


# --------------------------------------------------------------------------------------
# Fixtures
# --------------------------------------------------------------------------------------


def load_manifest(kind: str) -> List[Dict[str, Any]]:
    """Load ``fixtures/<kind>/MANIFEST.json`` and return its fixture entries."""
    path = os.path.join(FIXTURES_DIR, kind, "MANIFEST.json")
    with open(path, "r", encoding="utf-8") as handle:
        data = json.load(handle)
    entries = data.get("fixtures")
    if not isinstance(entries, list) or not entries:
        raise AssertionError("{} has no fixtures[]".format(path))
    return entries


def fixture_path(kind: str, name: str) -> str:
    return os.path.join(FIXTURES_DIR, kind, name)


def copy_fixture(kind: str, name: str, dest: str) -> str:
    """Copy a checked-in fixture into ``dest`` (which must not exist yet)."""
    src = fixture_path(kind, name)
    if not os.path.isdir(src):
        raise AssertionError("fixture {}/{} does not exist at {}".format(kind, name, src))
    shutil.copytree(src, dest, symlinks=True)
    return dest


def make_home(root: str, name: str = "home") -> str:
    """Create an empty fake ``~`` inside ``root``."""
    home = os.path.join(root, name)
    os.makedirs(home, exist_ok=True)
    return home


def scan_args_for(mode: str, target: str, home: str, extra: Sequence[str] = ()) -> Tuple[List[str], str]:
    """Build the scan argv for a fixture, plus the cwd it should run in.

    ``paths`` mode: an empty fake home + ``--paths <bundle>``, run from a neutral cwd.
    ``home`` mode:  the fixture *is* the fake home; run from it so project-level
    ``.mcp.json`` / ``.claude/settings.json`` discovery is exercised too.
    """
    if mode == "paths":
        args = ["scan", "--home", home, "--paths", target, "--json"] + list(extra)
        return args, _NEUTRAL_CWD
    if mode == "home":
        args = ["scan", "--home", target, "--json"] + list(extra)
        return args, target
    raise AssertionError("unknown fixture mode {!r}".format(mode))


def scan_fixture(
    mode: str,
    target: str,
    home: str,
    extra: Sequence[str] = ("--no-baseline",),
) -> Tuple[CliResult, Dict[str, Any]]:
    args, cwd = scan_args_for(mode, target, home, extra)
    return scan_json(args, cwd=cwd)


# --------------------------------------------------------------------------------------
# Importing the package under test (deliberately no try/except: absence is a failure)
# --------------------------------------------------------------------------------------


def import_registry():
    """Return ``(REGISTRY, Finding, Severity)`` from ``malskill.rules``.

    No skip-on-ImportError: if the package is missing or the names are not exported,
    that is a red test, which is exactly what the blueprint asks for.
    """
    if REPO_ROOT not in sys.path:
        sys.path.insert(0, REPO_ROOT)
    from malskill.rules import REGISTRY, Finding, Severity  # noqa: F401

    return REGISTRY, Finding, Severity


def rule_metadata_severity(entry: Any) -> Optional[str]:
    """Pull a severity out of a registry entry without assuming its shape."""
    if entry is None:
        return None
    for attr in ("severity", "floor", "severity_floor", "default_severity"):
        value = None
        if isinstance(entry, dict):
            value = entry.get(attr)
        elif hasattr(entry, attr):
            value = getattr(entry, attr)
        if value is not None:
            return normalize_status(getattr(value, "value", value))
    return None
