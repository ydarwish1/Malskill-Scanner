#!/usr/bin/env python3
"""Run MalSkill Scanner against pinned real-world corpora and write Markdown results."""

from __future__ import annotations

import argparse
import html
import json
import os
import platform
import shlex
import sys
import tempfile
import time
import unicodedata
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence


REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from malskill import __version__
from malskill.inventory import DiscoveryOptions, discover
from malskill.rules import REGISTRY
from malskill.rules.engine import run as run_rules


MANIFEST_PATH = Path(__file__).with_name("corpora.json")
DEFAULT_CORPUS_ROOT = os.path.join("eval", "corpora")
DEFAULT_OUT = os.path.join("eval", "RESULTS.md")
PRIVATE_ALLOWED_KEYS = frozenset(
    {
        "id",
        "kind",
        "status",
        "bundles",
        "files",
        "elapsed_seconds",
        "findings_by_rule",
        "unscanned_count",
    }
)
PRIVATE_FORBIDDEN_KEYS = frozenset(
    {"name", "path", "target", "display", "file", "evidence", "detail", "details"}
)


def build_parser() -> argparse.ArgumentParser:
    """Build the evaluation harness argument parser."""
    parser = argparse.ArgumentParser(
        description="Scan pinned real-world corpora and generate eval/RESULTS.md."
    )
    parser.add_argument(
        "--corpus-root",
        action="append",
        nargs="+",
        default=[],
        metavar="DIR",
        help=(
            "directory containing clones named by corpus id; repeat or pass multiple "
            "roots (default: eval/corpora)"
        ),
    )
    parser.add_argument(
        "--include-local",
        action="store_true",
        help="also scan installed extensions through ordinary home discovery",
    )
    parser.add_argument(
        "--out",
        default=DEFAULT_OUT,
        metavar="PATH",
        help="generated Markdown path (default: eval/RESULTS.md)",
    )
    return parser


def _load_manifest() -> List[Dict[str, Any]]:
    with MANIFEST_PATH.open("r", encoding="utf-8") as handle:
        manifest = json.load(handle)
    if manifest.get("version") != 1 or not isinstance(manifest.get("corpora"), list):
        raise ValueError("eval/corpora.json must contain version 1 and a corpora list")
    return list(manifest["corpora"])


def _command_used(argv: Sequence[str]) -> str:
    return " ".join(["python3"] + [shlex.quote(part) for part in argv])


def _display_script_path() -> str:
    try:
        return os.path.relpath(__file__, os.getcwd())
    except ValueError:
        return __file__


def _resolve_corpus_dir(corpus_id: str, roots: Sequence[str]) -> Optional[str]:
    for root in roots:
        candidate = os.path.abspath(
            os.path.expanduser(os.path.join(root, corpus_id))
        )
        if os.path.isdir(candidate):
            return candidate
    return None


def _clone_dir(corpus_id: str, roots: Sequence[str]) -> str:
    for root in roots:
        candidate = os.path.normpath(
            os.path.join(os.path.expanduser(root), corpus_id)
        )
        if os.path.isdir(candidate):
            return candidate
    return os.path.normpath(os.path.join(os.path.expanduser(roots[0]), corpus_id))


def _rule_counts(result: Any) -> Dict[str, int]:
    counts = Counter(finding.id for finding in result.findings)
    counts.update(
        entry.finding_id
        for entry in result.unscanned
        if getattr(entry, "finding_id", None)
    )
    return dict(counts)


def _public_file(file_value: Optional[str], corpus_dir: str) -> str:
    if not file_value:
        return ""
    if os.path.isabs(file_value):
        try:
            if os.path.commonpath([corpus_dir, file_value]) == corpus_dir:
                return os.path.relpath(file_value, corpus_dir)
        except ValueError:
            pass
    return file_value


def _scan_public(corpus: Dict[str, Any], corpus_dir: str) -> Dict[str, Any]:
    started = time.perf_counter()
    try:
        with tempfile.TemporaryDirectory(prefix="malskill-eval-") as empty_home:
            options = DiscoveryOptions(
                home=empty_home,
                cwd=empty_home,
                paths=[corpus_dir],
            )
            inventory = discover(options)
            result = run_rules(inventory)
        elapsed = time.perf_counter() - started
        return {
            "id": corpus["id"],
            "kind": corpus["kind"],
            "status": "ok",
            "error": "",
            "bundles": int(result.stats.get("targets", 0)),
            "files": int(result.stats.get("files_seen", 0)),
            "elapsed_seconds": elapsed,
            "findings_by_rule": _rule_counts(result),
            "unscanned_count": len(result.unscanned),
            "details": [
                {
                    "rule_id": finding.id,
                    "target": finding.target,
                    "file": _public_file(finding.file, corpus_dir),
                    "line": finding.line,
                    "label": "",
                }
                for finding in result.findings
            ],
        }
    except OSError as exc:  # a corpus I/O failure must not abort the remaining scans
        return {
            "id": corpus["id"],
            "kind": corpus["kind"],
            "status": "error",
            "error": "%s: %s" % (type(exc).__name__, exc),
            "bundles": None,
            "files": None,
            "elapsed_seconds": time.perf_counter() - started,
            "findings_by_rule": {},
            "unscanned_count": None,
            "details": [],
        }


def _assert_private_row(row: Dict[str, Any]) -> None:
    """Reject any private row shape capable of carrying scan-identifying detail."""
    extra = set(row) - PRIVATE_ALLOWED_KEYS
    if extra:
        raise AssertionError(
            "private-aggregate row has forbidden field(s): %s" % ", ".join(sorted(extra))
        )

    def walk(value: Any) -> None:
        if isinstance(value, dict):
            for key, child in value.items():
                if str(key).lower() in PRIVATE_FORBIDDEN_KEYS:
                    raise AssertionError(
                        "private-aggregate row carries forbidden name/path field %r" % key
                    )
                walk(child)
        elif isinstance(value, (list, tuple)):
            for child in value:
                walk(child)

    walk(row)
    if row.get("status") not in {"ok", "not-requested", "error"}:
        raise AssertionError("private-aggregate status must be a fixed non-sensitive value")
    counts = row.get("findings_by_rule")
    if not isinstance(counts, dict) or any(
        not isinstance(rule_id, str)
        or rule_id not in REGISTRY
        or not isinstance(count, int)
        or isinstance(count, bool)
        or count < 0
        for rule_id, count in counts.items()
    ):
        raise AssertionError("private-aggregate findings must be registered rule-id counts only")
    for key in ("bundles", "files", "unscanned_count"):
        value = row.get(key)
        if value is not None and (
            not isinstance(value, int) or isinstance(value, bool) or value < 0
        ):
            raise AssertionError("private-aggregate %s must be a non-negative count" % key)
    elapsed = row.get("elapsed_seconds")
    if elapsed is not None and (
        not isinstance(elapsed, (int, float)) or isinstance(elapsed, bool) or elapsed < 0
    ):
        raise AssertionError("private-aggregate elapsed_seconds must be non-negative")


def _private_placeholder(corpus: Dict[str, Any]) -> Dict[str, Any]:
    row = {
        "id": corpus["id"],
        "kind": corpus["kind"],
        "status": "not-requested",
        "bundles": None,
        "files": None,
        "elapsed_seconds": None,
        "findings_by_rule": {},
        "unscanned_count": None,
    }
    _assert_private_row(row)
    return row


def _scan_private(corpus: Dict[str, Any]) -> Dict[str, Any]:
    started = time.perf_counter()
    try:
        inventory = discover(DiscoveryOptions())
        result = run_rules(inventory)
        row = {
            "id": corpus["id"],
            "kind": corpus["kind"],
            "status": "ok",
            "bundles": int(result.stats.get("targets", 0)),
            "files": int(result.stats.get("files_seen", 0)),
            "elapsed_seconds": time.perf_counter() - started,
            "findings_by_rule": _rule_counts(result),
            "unscanned_count": len(result.unscanned),
        }
    except OSError:  # exception text can contain a private path, so do not retain it
        row = {
            "id": corpus["id"],
            "kind": corpus["kind"],
            "status": "error",
            "bundles": None,
            "files": None,
            "elapsed_seconds": time.perf_counter() - started,
            "findings_by_rule": {},
            "unscanned_count": None,
        }
    _assert_private_row(row)
    return row


def _print_summary(row: Dict[str, Any]) -> None:
    corpus_id = row["id"]
    status = row["status"]
    if status == "ok":
        findings = sum(row["findings_by_rule"].values())
        print(
            "%s: %d bundle(s), %d file(s), %d finding(s), %d unscanned, %.3fs"
            % (
                corpus_id,
                row["bundles"],
                row["files"],
                findings,
                row["unscanned_count"],
                row["elapsed_seconds"],
            ),
            flush=True,
        )
    elif status == "not-requested":
        print("%s: skipped (pass --include-local to scan it)" % corpus_id, flush=True)
    elif row.get("kind") == "private-aggregate":
        print(
            "%s: error (details withheld by private-aggregate policy)" % corpus_id,
            flush=True,
        )
    elif status == "skipped":
        print("%s: skipped (corpus directory is absent)" % corpus_id, flush=True)
    else:
        print("%s: error: %s" % (corpus_id, row.get("error", "unknown error")), flush=True)


def _cell(value: Any) -> str:
    if value is None:
        return "—"
    text = str(value).replace("\r", " ").replace("\n", " ")
    text = "".join(
        "\\u%04x" % ord(char)
        if unicodedata.category(char) in {"Cc", "Cf", "Zl", "Zp"}
        or ord(char) == 0x00A0
        else char
        for char in text
    )
    escaped = html.escape(text, quote=False).replace("\\", "\\\\")
    for marker in ("|", "[", "]", "`"):
        escaped = escaped.replace(marker, "\\" + marker)
    return escaped


def _count_cell(value: Any) -> str:
    return "—" if value is None else "{:,}".format(value)


def _elapsed_cell(value: Any) -> str:
    return "—" if value is None else "%.3f" % value


def _status_cell(row: Dict[str, Any]) -> str:
    status = row["status"]
    if status == "ok":
        return "complete"
    if status == "not-requested":
        return "not requested; pass `--include-local`"
    if status == "skipped":
        return "skipped; corpus directory absent"
    if row.get("kind") == "private-aggregate":
        return "error; details withheld by private-aggregate policy"
    return "error: %s" % row.get("error", "unknown error")


def _all_rule_ids(rows: Sequence[Dict[str, Any]]) -> List[str]:
    rule_ids = list(REGISTRY)
    known = set(rule_ids)
    unknown = sorted(
        {
            rule_id
            for row in rows
            for rule_id in row.get("findings_by_rule", {})
            if rule_id not in known
        }
    )
    return rule_ids + unknown


def _severity_floor(rule_id: str) -> str:
    rule = REGISTRY.get(rule_id)
    if rule is not None:
        return rule.severity.value
    return "UNKNOWN"


def _clone_commands(
    corpora: Sequence[Dict[str, Any]], clone_dirs: Dict[str, str]
) -> List[str]:
    commands: List[str] = []
    parents = []
    for corpus in corpora:
        if corpus.get("kind") != "public":
            continue
        target = clone_dirs[corpus["id"]]
        parent = os.path.dirname(target) or "."
        if parent not in parents:
            parents.append(parent)
            commands.append("mkdir -p %s" % shlex.quote(parent))
        commands.append(
            "git clone %s %s" % (shlex.quote(corpus["repo"]), shlex.quote(target))
        )
        commands.append(
            "git -C %s checkout %s"
            % (shlex.quote(target), shlex.quote(corpus["commit"]))
        )
    return commands


def _render_results(
    corpora: Sequence[Dict[str, Any]],
    rows: Sequence[Dict[str, Any]],
    clone_dirs: Dict[str, str],
    command: str,
    generated_at: str,
) -> str:
    rows_by_id = {row["id"]: row for row in rows}
    for corpus in corpora:
        if corpus.get("kind") == "private-aggregate":
            _assert_private_row(rows_by_id[corpus["id"]])

    lines = [
        "# MalSkill Scanner Evaluation Results",
        "",
        "> **Generated file.** `eval/run_eval.py` wrote this document. Do not edit it by hand.",
        "",
        "Exact command used:",
        "",
        "    %s" % command,
        "",
        "## Environment",
        "",
        "| Field | Value |",
        "| --- | --- |",
        "| Platform | %s |" % _cell(platform.platform()),
        "| Machine | %s |" % _cell(platform.machine()),
        "| Python version | %s |" % _cell(platform.python_version()),
        "| MalSkill Scanner | %s |" % _cell(__version__),
        "| Run time (UTC) | %s |" % _cell(generated_at),
        "",
        "## Corpora",
        "",
        "| ID | Repository | Pinned commit | Bundles | Files | Unscanned | Elapsed seconds | Status |",
        "| --- | --- | --- | ---: | ---: | ---: | ---: | --- |",
    ]

    for corpus in corpora:
        row = rows_by_id[corpus["id"]]
        repo = corpus.get("repo") if corpus.get("kind") == "public" else None
        commit = corpus.get("commit") if corpus.get("kind") == "public" else None
        lines.append(
            "| %s | %s | %s | %s | %s | %s | %s | %s |"
            % (
                _cell(corpus["id"]),
                _cell(repo),
                _cell(commit),
                _count_cell(row["bundles"]),
                _count_cell(row["files"]),
                _count_cell(row["unscanned_count"]),
                _elapsed_cell(row["elapsed_seconds"]),
                _cell(_status_cell(row)),
            )
        )

    lines.extend(
        [
            "",
            "## Findings by rule",
            "",
            "Counts are deterministic findings emitted by each rule. A named unscanned condition, such as `MCP_UNPARSEABLE_CONFIG`, also contributes to its rule-ID count; all unscanned records are counted separately in the corpus table above.",
            "",
            "| Rule ID | Severity floor | %s |"
            % " | ".join(_cell(corpus["id"]) for corpus in corpora),
            "| --- | --- | %s |" % " | ".join("---:" for _ in corpora),
        ]
    )
    for rule_id in _all_rule_ids(rows):
        count_cells = []
        for corpus in corpora:
            row = rows_by_id[corpus["id"]]
            if row["status"] != "ok":
                count_cells.append("—")
            else:
                count_cells.append(
                    "{:,}".format(row["findings_by_rule"].get(rule_id, 0))
                )
        lines.append(
            "| %s | %s | %s |"
            % (
                _cell(rule_id),
                _cell(_severity_floor(rule_id)),
                " | ".join(count_cells),
            )
        )

    lines.extend(["", "## Per-finding detail — public corpora only", ""])
    for corpus in corpora:
        if corpus.get("kind") != "public":
            continue
        row = rows_by_id[corpus["id"]]
        lines.extend(["### %s" % _cell(corpus["id"]), ""])
        if row["status"] != "ok":
            lines.extend(["Detail unavailable: %s." % _cell(_status_cell(row)), ""])
            continue
        if not row["details"]:
            lines.extend(["_No findings._", ""])
            continue
        lines.extend(
            [
                "| Rule ID | Target | File | Line | Human label |",
                "| --- | --- | --- | ---: | --- |",
            ]
        )
        for detail in row["details"]:
            lines.append(
                "| %s | %s | %s | %s |  |"
                % (
                    _cell(detail["rule_id"]),
                    _cell(detail["target"]),
                    _cell(detail["file"]),
                    _cell(detail["line"] if detail["line"] is not None else ""),
                )
            )
        lines.append("")

    lines.extend(
        [
            "## Manual labels",
            "",
            "A human reviews each public-corpus finding using `confirmed`, `false-positive`, or `unclear`. The blank label column above is a worksheet, not durable storage: re-running this script regenerates it. Record completed labels in the subsection below.",
            "",
            "### Labeled findings",
            "",
            "<!-- Intentionally empty. Add reviewed finding references and labels here. -->",
            "",
            "## Reproduction",
            "",
            "Fetch each public corpus and check out its pinned commit:",
            "",
        ]
    )
    lines.extend("    %s" % item for item in _clone_commands(corpora, clone_dirs))
    lines.extend(
        [
            "",
            "Run the exact evaluation invocation recorded at the top of this file:",
            "",
            "    %s" % command,
            "",
        ]
    )
    return "\n".join(lines)


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Run all requested corpora and write the generated results document."""
    args = build_parser().parse_args(argv)
    roots = [root for group in args.corpus_root for root in group] or [DEFAULT_CORPUS_ROOT]
    command_argv = list(
        [_display_script_path()] + list(sys.argv[1:])
        if argv is None
        else ["eval/run_eval.py"] + list(argv)
    )
    command = _command_used(command_argv)
    generated_at = datetime.now(timezone.utc).isoformat(timespec="seconds")

    try:
        corpora = _load_manifest()
    except Exception as exc:
        sys.stderr.write("eval: could not read corpus manifest: %s\n" % exc)
        return 2

    rows: List[Dict[str, Any]] = []
    clone_dirs = {
        corpus["id"]: _clone_dir(corpus["id"], roots)
        for corpus in corpora
        if corpus.get("kind") == "public"
    }
    for corpus in corpora:
        if corpus.get("kind") == "private-aggregate":
            row = _scan_private(corpus) if args.include_local else _private_placeholder(corpus)
        else:
            corpus_dir = _resolve_corpus_dir(corpus["id"], roots)
            if corpus_dir is None:
                row = {
                    "id": corpus["id"],
                    "kind": corpus["kind"],
                    "status": "skipped",
                    "error": "corpus directory is absent",
                    "bundles": None,
                    "files": None,
                    "elapsed_seconds": None,
                    "findings_by_rule": {},
                    "unscanned_count": None,
                    "details": [],
                }
            else:
                row = _scan_public(corpus, corpus_dir)
        rows.append(row)
        _print_summary(row)

    try:
        output = _render_results(corpora, rows, clone_dirs, command, generated_at)
        out_path = Path(args.out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(output, encoding="utf-8")
    except Exception as exc:
        sys.stderr.write("eval: could not write %s: %s\n" % (args.out, exc))
        return 2

    print("wrote %s" % args.out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
