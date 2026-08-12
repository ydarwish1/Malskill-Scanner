"""Command line interface.

    malskill scan [--home DIR] [--paths DIR ...] [--project] [--all-clients]
                  [--json] [--show-unscanned] [--paranoid] [--explain] [--no-baseline]
    malskill baseline update [--home DIR] [--paths DIR ...]
    malskill list [--home DIR]
    malskill rules

``--home DIR`` redirects **all** home-based discovery *and* the baseline store
(``<home>/.malskill/baseline.json``), which is what makes hermetic runs possible: point
it at an empty directory and the scanner behaves as if the machine were empty.

``--paths`` scans arbitrary directories as bundles. When ``--paths`` is given, home and
client discovery is off unless ``--discover`` is added, so ``malskill scan --paths
fixtures/benign`` means exactly what it says and cannot be polluted by whatever is
installed on the machine running it.

Exit codes: 0 = no findings, 1 = at least one finding, 2 = scanner error.
"""

from __future__ import annotations

import argparse
import os
import sys
from typing import List, Optional, Sequence

from malskill import __version__, baseline as baseline_module
from malskill.inventory import DiscoveryOptions, discover
from malskill.report import (
    EXIT_ERROR,
    EXIT_OK,
    Report,
    render_inventory,
    render_rules_table,
)
from malskill.rules.engine import run as run_rules

__all__ = ["main", "build_parser"]

_DESCRIPTION = (
    "MalSkill Scanner — audit installed Claude Code skills, plugins, commands, agents, "
    "hooks and MCP servers for content that would push an agent to act against you. "
    "Deterministic rules decide; the optional AI explainer may only escalate."
)

_EPILOG = (
    "Report states: FLAGGED / CLEAN / NOT-FULLY-ANALYZED. The scanner never reports that "
    "anything is guaranteed harmless.\n"
    "Exit codes: 0 = no findings, 1 = findings, 2 = scanner error."
)


def _add_scope_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--home",
        metavar="DIR",
        default="",
        help="replace ~ for all home-based discovery and for the baseline store",
    )
    parser.add_argument(
        "--cwd",
        metavar="DIR",
        default="",
        help="treat DIR as the current project directory (default: actual cwd)",
    )
    parser.add_argument(
        "--paths",
        metavar="DIR",
        nargs="+",
        default=[],
        help="scan these directories as bundles (a directory of directories is treated "
        "as a container: each subdirectory is one bundle)",
    )
    parser.add_argument(
        "--project",
        action="store_true",
        help="also scan the project scope (<cwd>/.claude/…, <cwd>/.mcp.json)",
    )
    parser.add_argument(
        "--all-clients",
        action="store_true",
        help="also scan other MCP clients (~/.cursor/mcp.json, ~/.codex/config.toml)",
    )
    parser.add_argument(
        "--discover",
        action="store_true",
        help="run home/client discovery even when --paths is given",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="malskill",
        description=_DESCRIPTION,
        epilog=_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version="malskill %s" % __version__)
    subparsers = parser.add_subparsers(dest="command")

    scan = subparsers.add_parser(
        "scan",
        help="run every rule over discovered targets",
        description="Run every deterministic rule over the discovered inventory.",
    )
    _add_scope_args(scan)
    scan.add_argument("--json", action="store_true", help="emit the full report as JSON")
    scan.add_argument(
        "--show-unscanned",
        action="store_true",
        help="list every file that was not fully analyzed",
    )
    scan.add_argument(
        "--paranoid",
        action="store_true",
        help="list every behaviour pattern that matched in documentation, test or data "
        "context as a LOW SUPPRESSED_PATTERN_HIT finding (by default these are only "
        "counted in a report note)",
    )
    scan.add_argument(
        "--explain",
        action="store_true",
        help="ask the zero-tool explainer for context (it may only ESCALATE findings)",
    )
    scan.add_argument(
        "--no-baseline",
        action="store_true",
        help="skip baseline drift comparison for this run",
    )
    scan.add_argument(
        "--explainer-binary",
        default="claude",
        help="binary used by --explain (default: claude)",
    )

    baseline = subparsers.add_parser(
        "baseline",
        help="manage the accepted-state baseline",
        description="Record the current state as accepted, so future scans report drift.",
    )
    baseline_sub = baseline.add_subparsers(dest="baseline_command")
    baseline_update = baseline_sub.add_parser(
        "update", help="accept the current state and write the baseline"
    )
    _add_scope_args(baseline_update)
    baseline_update.add_argument(
        "--json", action="store_true", help="emit the result as JSON"
    )
    baseline_show = baseline_sub.add_parser(
        "show", help="print what the baseline currently records"
    )
    baseline_show.add_argument("--home", metavar="DIR", default="")
    baseline_show.add_argument("--json", action="store_true")

    listing = subparsers.add_parser(
        "list",
        help="show what would be scanned; runs no rules",
        description="Inventory only: discover targets and print them. No rules are run.",
    )
    _add_scope_args(listing)
    listing.add_argument("--json", action="store_true")

    rules = subparsers.add_parser(
        "rules",
        help="print the rule registry summary table",
        description="Every registered finding ID with its severity floor and trigger.",
    )
    rules.add_argument("--json", action="store_true")

    return parser


def _options(args: argparse.Namespace) -> DiscoveryOptions:
    return DiscoveryOptions(
        home=getattr(args, "home", "") or "",
        cwd=getattr(args, "cwd", "") or "",
        paths=list(getattr(args, "paths", []) or []),
        project=bool(getattr(args, "project", False)),
        all_clients=bool(getattr(args, "all_clients", False)),
        discover_home=True if getattr(args, "discover", False) else None,
    )


def _scope(options: DiscoveryOptions, args: argparse.Namespace) -> dict:
    return {
        "home": options.resolved_home(),
        "cwd": options.resolved_cwd(),
        "paths": [os.path.abspath(os.path.expanduser(p)) for p in options.paths],
        "project": options.project,
        "all_clients": options.all_clients,
        "home_discovery": options.wants_home_discovery(),
        "baseline": not bool(getattr(args, "no_baseline", False)),
        "paranoid": bool(getattr(args, "paranoid", False)),
    }


def cmd_scan(args: argparse.Namespace, stdout) -> int:
    options = _options(args)
    inventory = discover(options)
    result = run_rules(inventory, paranoid=bool(getattr(args, "paranoid", False)))

    notes: List[str] = []
    if not args.no_baseline:
        store = baseline_module.load(options.resolved_home())
        drift, baseline_notes = baseline_module.check(result.target_hashes, store)
        result.findings.extend(drift)
        result.findings.sort(key=lambda f: f.sort_key())
        notes.extend(baseline_notes)
        for finding in drift:
            state = result.target_states.get(finding.target)
            if state is None or state == "CLEAN":
                result.target_states[finding.target] = "FLAGGED"
    else:
        notes.append("baseline comparison skipped (--no-baseline).")

    explainer_note: Optional[str] = None
    if args.explain:
        from malskill.explain import ExplainerConfig, explain_findings

        explainer_note = explain_findings(
            result.findings,
            ExplainerConfig(binary=getattr(args, "explainer_binary", "claude")),
        )
        result.findings.sort(key=lambda f: f.sort_key())

    report = Report(
        result=result,
        scope=_scope(options, args),
        notes=notes,
        explainer_note=explainer_note,
    )
    if args.json:
        stdout.write(report.to_json() + "\n")
    else:
        stdout.write(report.render_terminal(show_unscanned=args.show_unscanned) + "\n")
    return report.exit_code()


def cmd_baseline_update(args: argparse.Namespace, stdout) -> int:
    options = _options(args)
    inventory = discover(options)
    snapshot = baseline_module.collect(inventory)
    path = baseline_module.save(options.resolved_home(), snapshot)
    files = sum(len(entry.get("files", {})) for entry in snapshot.values())
    if getattr(args, "json", False):
        import json

        stdout.write(
            json.dumps(
                {
                    "baseline": path,
                    "targets": len(snapshot),
                    "files": files,
                    "tool_version": __version__,
                },
                indent=2,
            )
            + "\n"
        )
    else:
        stdout.write(
            "Baseline accepted: %d target(s), %d file hash(es) written to %s\n"
            % (len(snapshot), files, path)
        )
        stdout.write(
            "Future scans report BASELINE_DRIFT when any of those files change.\n"
        )
    return EXIT_OK


def cmd_baseline_show(args: argparse.Namespace, stdout) -> int:
    store = baseline_module.load(getattr(args, "home", "") or "")
    if getattr(args, "json", False):
        import json

        stdout.write(
            json.dumps(
                {
                    "path": store.path,
                    "exists": store.exists,
                    "tampered": store.tampered,
                    "error": store.error,
                    "updated": store.updated,
                    "tool_version": store.tool_version,
                    "targets": sorted(store.targets),
                },
                indent=2,
            )
            + "\n"
        )
        return EXIT_OK
    if not store.exists:
        stdout.write("No baseline recorded at %s\n" % store.path)
        return EXIT_OK
    if store.tampered:
        stdout.write("BASELINE_TAMPERED: %s (%s)\n" % (store.path, store.error))
        return EXIT_OK
    stdout.write("Baseline %s (written %s)\n" % (store.path, store.updated))
    for key in sorted(store.targets):
        entry = store.targets[key]
        stdout.write("  %-50s %d file(s)\n" % (key, len(entry.get("files", {}))))
    return EXIT_OK


def cmd_list(args: argparse.Namespace, stdout) -> int:
    options = _options(args)
    if not options.paths:
        options.discover_home = True
    inventory = discover(options)
    stdout.write(render_inventory(inventory, as_json=args.json) + "\n")
    return EXIT_OK


def cmd_rules(args: argparse.Namespace, stdout) -> int:
    stdout.write(render_rules_table(as_json=args.json) + "\n")
    return EXIT_OK


def main(argv: Optional[Sequence[str]] = None, stdout=None, stderr=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    stdout = stdout or sys.stdout
    stderr = stderr or sys.stderr
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.command:
        parser.print_help(stdout)
        return EXIT_OK

    try:
        if args.command == "scan":
            return cmd_scan(args, stdout)
        if args.command == "baseline":
            command = getattr(args, "baseline_command", None)
            if command == "update":
                return cmd_baseline_update(args, stdout)
            if command == "show":
                return cmd_baseline_show(args, stdout)
            stderr.write("usage: malskill baseline update [--home DIR] [--paths DIR ...]\n")
            return EXIT_ERROR
        if args.command == "list":
            return cmd_list(args, stdout)
        if args.command == "rules":
            return cmd_rules(args, stdout)
    except KeyboardInterrupt:
        stderr.write("interrupted\n")
        return EXIT_ERROR
    except Exception as exc:  # noqa: BLE001 - a scanner error is exit 2, never a traceback
        stderr.write("malskill: scanner error: %s: %s\n" % (type(exc).__name__, exc))
        if os.environ.get("MALSKILL_DEBUG"):
            import traceback

            traceback.print_exc(file=stderr)
        return EXIT_ERROR

    parser.print_help(stdout)
    return EXIT_OK
