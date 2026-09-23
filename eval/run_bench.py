#!/usr/bin/env python3
"""Labeled detection benchmark: recall and false positives across real repo layouts.

The unit tests scan every fixture on its own, which is not how people meet skills. A
community skills repository or a plugin marketplace ships dozens of bundles side by side,
and ``malskill scan --paths <repo>`` has to keep them apart: one skill's network
declaration must not excuse another skill's offline lie, and one skill's ``~/.ssh`` read
must not pair with a different skill's ``curl``.

This harness takes the labeled corpora in ``fixtures/`` (every ``paths``-mode fixture,
malicious and benign), lays them out in several repository shapes, scans each layout
once through the public API, and scores every sample by where its findings landed:

* a malicious sample is **detected** when its expected rule fires on a file inside that
  sample's own directory;
* a benign sample is a **false positive** when any finding lands inside its directory.

Every number in the generated file comes from this script; re-run it to regenerate.

    python3 eval/run_bench.py --out eval/BENCHMARK.md
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from malskill import __version__  # noqa: E402
from malskill.inventory import DiscoveryOptions, discover  # noqa: E402
from malskill.rules.engine import run as run_rules  # noqa: E402

FIXTURES = REPO_ROOT / "fixtures"
DEFAULT_OUT = os.path.join("eval", "BENCHMARK.md")

#: Findings that describe scanner state rather than a sample's content.
_IGNORED_IDS = frozenset(
    {"BASELINE_DRIFT", "BASELINE_NEW_TARGET", "BASELINE_TAMPERED", "SUPPRESSED_PATTERN_HIT"}
)


# ------------------------------------------------------------------------------ samples


def load_samples() -> List[Dict[str, Any]]:
    """Every labeled single-bundle sample in the fixture manifests."""
    samples: List[Dict[str, Any]] = []
    for kind in ("malicious", "benign"):
        manifest = json.loads((FIXTURES / kind / "MANIFEST.json").read_text("utf-8"))
        for entry in manifest["fixtures"]:
            if entry.get("mode") != "paths":
                continue
            samples.append(
                {
                    "name": entry["name"],
                    "label": kind,
                    "expect": list(entry.get("expect_findings") or []),
                    "source": FIXTURES / kind / entry["name"],
                    "origin": "fixtures/%s" % kind,
                }
            )
    return samples


# ------------------------------------------------------------------------------ layouts
#
# Each layout returns (scan_root, {sample name: absolute sample directory}).


def _copy(sample: Dict[str, Any], dest: Path) -> Path:
    shutil.copytree(str(sample["source"]), str(dest), symlinks=True)
    return dest


def layout_standalone(samples, root: Path) -> List[Tuple[Path, Dict[str, Path]]]:
    """Each sample scanned on its own, the way the unit tests do it."""
    scans = []
    for sample in samples:
        dest = _copy(sample, root / sample["name"])
        scans.append((dest, {sample["name"]: dest}))
    return scans


def layout_skills_repo(samples, root: Path) -> List[Tuple[Path, Dict[str, Path]]]:
    """A community skills repository: skills/<name>/ plus a marketplace manifest."""
    repo = root / "skills-repo"
    (repo / ".claude-plugin").mkdir(parents=True)
    (repo / ".claude-plugin" / "marketplace.json").write_text(
        json.dumps({"name": "community-skills", "plugins": []}, indent=2), "utf-8"
    )
    (repo / "README.md").write_text("# Community skills\n\nA collection of skills.\n", "utf-8")
    placed = {s["name"]: _copy(s, repo / "skills" / s["name"]) for s in samples}
    return [(repo, placed)]


def layout_benign_skills_repo(samples, root: Path) -> List[Tuple[Path, Dict[str, Path]]]:
    """A clean skills repository: only the benign samples, under skills/<name>/.

    Malicious samples are left out so every finding here is a false positive the
    reader would see on a repository with nothing wrong in it.
    """
    benign = [s for s in samples if s["label"] == "benign"]
    return layout_skills_repo(benign, root)


def layout_plugin_marketplace(samples, root: Path) -> List[Tuple[Path, Dict[str, Path]]]:
    """A plugin marketplace: plugins/<plugin>/skills/<name>/, one plugin per sample."""
    repo = root / "marketplace"
    (repo / ".claude-plugin").mkdir(parents=True)
    (repo / ".claude-plugin" / "marketplace.json").write_text(
        json.dumps({"name": "market", "plugins": []}, indent=2), "utf-8"
    )
    placed = {}
    for sample in samples:
        plugin = repo / "plugins" / (sample["name"] + "-plugin")
        (plugin / ".claude-plugin").mkdir(parents=True)
        (plugin / ".claude-plugin" / "plugin.json").write_text(
            json.dumps({"name": sample["name"] + "-plugin", "version": "1.0.0"}), "utf-8"
        )
        placed[sample["name"]] = _copy(sample, plugin / "skills" / sample["name"])
    return [(repo, placed)]


def layout_project_skills(samples, root: Path) -> List[Tuple[Path, Dict[str, Path]]]:
    """An application repository carrying project-level skills in .claude/skills/."""
    repo = root / "app-repo"
    (repo / "src").mkdir(parents=True)
    (repo / "src" / "main.py").write_text("print('hello')\n", "utf-8")
    (repo / "README.md").write_text("# App\n", "utf-8")
    placed = {s["name"]: _copy(s, repo / ".claude" / "skills" / s["name"]) for s in samples}
    return [(repo, placed)]


LAYOUTS = [
    ("standalone", "each sample scanned alone (`--paths <sample>`)", layout_standalone),
    ("skills-repo", "all samples in one repo under `skills/<name>/`", layout_skills_repo),
    (
        "clean-skills-repo",
        "only the benign samples, one repo under `skills/<name>/`",
        layout_benign_skills_repo,
    ),
    (
        "plugin-marketplace",
        "one plugin per sample under `plugins/<p>/skills/<name>/`",
        layout_plugin_marketplace,
    ),
    (
        "project-skills",
        "all samples in an app repo under `.claude/skills/<name>/`",
        layout_project_skills,
    ),
]


# ------------------------------------------------------------------------------ scoring


def _scan(scan_root: Path, home: Path):
    inventory = discover(DiscoveryOptions(home=str(home), cwd=str(home), paths=[str(scan_root)]))
    result = run_rules(inventory)
    roots = {t.display: t.root for t in inventory.targets}
    located: List[Tuple[str, str]] = []  # (rule id, absolute file path)
    for finding in result.findings:
        if finding.id in _IGNORED_IDS:
            continue
        base = roots.get(finding.target, "")
        path = os.path.normpath(os.path.join(base, finding.file or ""))
        located.append((finding.id, path))
    return located, len(inventory.targets)


def _inside(path: str, directory: Path) -> bool:
    directory_s = os.path.normpath(str(directory))
    return path == directory_s or path.startswith(directory_s + os.sep)


def score_layout(samples, builder) -> Dict[str, Any]:
    by_name = {s["name"]: s for s in samples}
    work = Path(tempfile.mkdtemp(prefix="malskill-bench-"))
    try:
        home = work / "empty-home"
        home.mkdir()
        rows: Dict[str, Dict[str, Any]] = {}
        bundles = 0
        started = time.perf_counter()
        for scan_root, placed in builder(samples, work / "layout"):
            located, count = _scan(scan_root, home)
            bundles += count
            for name, directory in placed.items():
                fired = sorted({rid for rid, path in located if _inside(path, directory)})
                sample = by_name[name]
                if sample["label"] == "malicious":
                    ok = all(rid in fired for rid in sample["expect"]) and bool(fired)
                else:
                    ok = not fired
                rows[name] = {"fired": fired, "ok": ok}
        elapsed = time.perf_counter() - started
    finally:
        shutil.rmtree(str(work), ignore_errors=True)

    malicious = [s for s in samples if s["label"] == "malicious" and s["name"] in rows]
    benign = [s for s in samples if s["label"] == "benign" and s["name"] in rows]
    detected = sum(1 for s in malicious if rows[s["name"]]["ok"])
    false_pos = sum(1 for s in benign if not rows[s["name"]]["ok"])
    return {
        "rows": rows,
        "bundles": bundles,
        "detected": detected,
        "malicious": len(malicious),
        "false_positives": false_pos,
        "benign": len(benign),
        "elapsed": elapsed,
    }


# ------------------------------------------------------------------------------ report


def _pct(num: int, den: int) -> str:
    return "%.1f%%" % (100.0 * num / den) if den else "n/a"


def render(samples, results: List[Tuple[str, str, Dict[str, Any]]], argv: List[str]) -> str:
    out: List[str] = []
    add = out.append
    add("# MalSkill Scanner Benchmark")
    add("")
    add("> **Generated file.** `eval/run_bench.py` wrote this document. Do not edit it by hand.")
    add("")
    add("Command: `%s`  " % " ".join(["python3", "eval/run_bench.py"] + argv))
    add("Scanner version: %s" % __version__)
    add("")
    add("A malicious sample counts as detected only when its expected rule fires on a file")
    add("inside that sample's own directory. A benign sample is a false positive when any")
    add("finding lands inside its directory. `%d` malicious and `%d` benign samples." % (
        sum(1 for s in samples if s["label"] == "malicious"),
        sum(1 for s in samples if s["label"] == "benign"),
    ))
    add("")
    add("## Summary")
    add("")
    add("| Layout | What it models | Bundles seen | Detected | Detection rate | False positives | FP rate |")
    add("| --- | --- | ---: | ---: | ---: | ---: | ---: |")
    for key, desc, res in results:
        add(
            "| %s | %s | %d | %d/%d | %s | %d/%d | %s |"
            % (
                key,
                desc,
                res["bundles"],
                res["detected"],
                res["malicious"],
                _pct(res["detected"], res["malicious"]),
                res["false_positives"],
                res["benign"],
                _pct(res["false_positives"], res["benign"]),
            )
        )
    add("")
    add("## Per sample")
    add("")
    header = "| Sample | Label | Expected | " + " | ".join(k for k, _, _ in results) + " |"
    add(header)
    add("| --- | --- | --- |" + " --- |" * len(results))
    for sample in samples:
        cells = []
        for _, _, res in results:
            row = res["rows"].get(sample["name"])
            if row is None:
                cells.append("not placed")
                continue
            mark = "ok" if row["ok"] else ("**MISS**" if sample["label"] == "malicious" else "**FP**")
            fired = ", ".join(row["fired"]) or "-"
            cells.append("%s (%s)" % (mark, fired))
        add(
            "| %s | %s | %s | %s |"
            % (
                sample["name"],
                sample["label"],
                ", ".join(sample["expect"]) or "-",
                " | ".join(cells),
            )
        )
    add("")
    return "\n".join(out)


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--out", default=DEFAULT_OUT, help="Markdown output path")
    parser.add_argument("--json", dest="json_out", help="also write raw results as JSON")
    args = parser.parse_args(argv)

    samples = load_samples()
    results = []
    for key, desc, builder in LAYOUTS:
        res = score_layout(samples, builder)
        results.append((key, desc, res))
        print(
            "%-20s bundles=%-4d detected=%d/%d false_positives=%d/%d  %.1fs"
            % (
                key,
                res["bundles"],
                res["detected"],
                res["malicious"],
                res["false_positives"],
                res["benign"],
                res["elapsed"],
            )
        )
    shown = [a for a in (argv if argv is not None else sys.argv[1:])]
    Path(args.out).write_text(render(samples, results, shown), "utf-8")
    if args.json_out:
        Path(args.json_out).write_text(
            json.dumps(
                {k: {kk: vv for kk, vv in r.items()} for k, _, r in results}, indent=2
            ),
            "utf-8",
        )
    print("wrote %s" % args.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
