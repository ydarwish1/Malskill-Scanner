"""Discovery: find everything the agent will load, before any rule runs.

This is the trusted extractor layer. It runs first, over attacker-controlled bytes, so it
does as little as possible: ``os.listdir``/``os.walk``, byte reads, ``json.loads``, and
the minimal frontmatter parser. No YAML library, no TOML library beyond a tiny
hand-written subset, no rendering, no symlink following out of a root, and nothing from
the scanned content is ever executed.

``--home DIR`` replaces ``~`` for *all* home-based discovery (and for the baseline path),
which is what makes hermetic testing possible: point it at an empty directory and the
scanner sees an empty machine.

Discovery covers:

* user skills          ``<home>/.claude/skills/*/``
* project skills       ``<cwd>/.claude/skills/*/``          (--project, or cwd has .claude/)
* commands             ``<home>/.claude/commands/**/*.md``, project equivalent
* agents               ``<home>/.claude/agents/**/*.md``
* plugins              ``<home>/.claude/plugins/`` incl. ``installed_plugins.json`` and
                       marketplace repositories, each installed plugin as one bundle
* hooks                ``settings.json`` / ``settings.local.json`` (home and project)
* MCP (Claude Code)    ``<home>/.claude.json`` top-level and per-project ``mcpServers``,
                       ``<cwd>/.mcp.json``
* MCP (Claude Desktop) ``<home>/Library/Application Support/Claude/claude_desktop_config.json``
* MCP (other clients)  ``<home>/.cursor/mcp.json``, ``<home>/.codex/config.toml`` with
                       ``--all-clients`` (best effort; parse failure is reported, never fatal)
* arbitrary dirs       ``--paths DIR ...``

Anything that exists but cannot be parsed becomes a NOT-FULLY-ANALYZED record. Nothing is
ever skipped silently.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from malskill.rules import REASON_PARSE_ERROR, REASON_UNREADABLE, Unscanned
from malskill.targets import (
    MAX_FILE_BYTES,
    SKIP_DIRNAMES,
    Inventory,
    Target,
    TargetKind,
    synthetic_record,
)

__all__ = ["DiscoveryOptions", "discover", "expand_paths"]

_BUNDLE_MANIFESTS = (
    "SKILL.md",
    "skill.md",
    "plugin.json",
    ".claude-plugin",
    "AGENT.md",
    "agent.md",
)

_CONFIG_FILENAMES = (
    ".mcp.json",
    "mcp.json",
    "settings.json",
    "settings.local.json",
    "claude_desktop_config.json",
)

_EMBEDDED_SCAN_DEPTH = 3


@dataclass
class DiscoveryOptions:
    """Everything the CLI can change about where the scanner looks."""

    home: str = ""
    cwd: str = ""
    paths: List[str] = field(default_factory=list)
    project: bool = False
    all_clients: bool = False
    #: Run home/client discovery. Defaults to "only when no --paths were given".
    discover_home: Optional[bool] = None

    def resolved_home(self) -> str:
        return os.path.abspath(os.path.expanduser(self.home or "~"))

    def resolved_cwd(self) -> str:
        return os.path.abspath(self.cwd or os.getcwd())

    def wants_home_discovery(self) -> bool:
        if self.discover_home is not None:
            return self.discover_home
        return not self.paths


# ---------------------------------------------------------------------------------------
# Small, careful readers
# ---------------------------------------------------------------------------------------


def _read_text(path: str) -> Tuple[Optional[str], Optional[str]]:
    """Read a file as text. Returns (text, error)."""
    try:
        with open(path, "rb") as handle:
            data = handle.read(MAX_FILE_BYTES)
    except OSError as exc:
        return None, str(exc)
    return data.decode("utf-8", errors="replace"), None


def _read_json(path: str) -> Tuple[Optional[Any], Optional[str]]:
    text, error = _read_text(path)
    if error is not None:
        return None, error
    if text is None:
        return None, "unreadable"
    stripped = text.lstrip("\ufeff \t\r\n")
    if not stripped:
        return None, "file is empty"
    try:
        return json.loads(text), None
    except ValueError as exc:
        return None, "invalid JSON: %s" % exc


def _unscanned(target: str, path: str, reason: str, detail: str, finding_id=None):
    return Unscanned(
        target=target, file=path, reason=reason, detail=detail, finding_id=finding_id
    )


def _line_of_snippet(path: str, snippet: str) -> Optional[int]:
    text, error = _read_text(path)
    if error or not text or not snippet:
        return None
    probe = snippet.strip().split("\n")[0][:60]
    index = text.find(probe)
    if index == -1:
        return None
    return text.count("\n", 0, index) + 1


# ---------------------------------------------------------------------------------------
# Minimal TOML subset (for ~/.codex/config.toml only)
# ---------------------------------------------------------------------------------------

_TOML_TABLE_RE = re.compile(r"^\s*\[\[?([^\]]+)\]\]?\s*$")
_TOML_KV_RE = re.compile(r"^\s*([A-Za-z0-9_.\"'-]+)\s*=\s*(.+?)\s*$")


def parse_toml_subset(text: str) -> Dict[str, Any]:
    """Parse the tiny slice of TOML that MCP client configs actually use.

    Tables, string/array/inline-table/bool/number values. Anything else raises
    ValueError, and the caller reports the file as NOT-FULLY-ANALYZED rather than
    guessing. Deliberately not a TOML implementation.
    """
    root: Dict[str, Any] = {}
    current = root
    for raw_line in text.split("\n"):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        table = _TOML_TABLE_RE.match(line)
        if table:
            current = root
            for part in _split_toml_key(table.group(1)):
                node = current.get(part)
                if not isinstance(node, dict):
                    node = {}
                    current[part] = node
                current = node
            continue
        kv = _TOML_KV_RE.match(line)
        if not kv:
            raise ValueError("unsupported line: %s" % line[:60])
        key = kv.group(1).strip().strip("\"'")
        current[key] = _toml_value(kv.group(2))
    return root


def _split_toml_key(key: str) -> List[str]:
    parts: List[str] = []
    current: List[str] = []
    quote = ""
    for ch in key:
        if quote:
            if ch == quote:
                quote = ""
            else:
                current.append(ch)
        elif ch in "\"'":
            quote = ch
        elif ch == ".":
            parts.append("".join(current).strip())
            current = []
        else:
            current.append(ch)
    parts.append("".join(current).strip())
    return [p for p in parts if p]


def _toml_value(token: str) -> Any:
    token = token.strip()
    if token.startswith("#"):
        return ""
    if token.startswith('"') or token.startswith("'"):
        quote = token[0]
        end = token.find(quote, 1)
        while end > 0 and token[end - 1] == "\\":
            end = token.find(quote, end + 1)
        if end == -1:
            raise ValueError("unterminated string")
        return token[1:end]
    if token.startswith("["):
        if not token.rstrip().endswith("]"):
            raise ValueError("multi-line arrays are not supported")
        inner = token.strip()[1:-1]
        return [_toml_value(part) for part in _split_top_level(inner) if part.strip()]
    if token.startswith("{"):
        if not token.rstrip().endswith("}"):
            raise ValueError("multi-line inline tables are not supported")
        inner = token.strip()[1:-1]
        table: Dict[str, Any] = {}
        for part in _split_top_level(inner):
            if not part.strip():
                continue
            key, _, value = part.partition("=")
            table[key.strip().strip("\"'")] = _toml_value(value)
        return table
    lowered = token.lower()
    if lowered in ("true", "false"):
        return lowered == "true"
    try:
        return int(token)
    except ValueError:
        pass
    try:
        return float(token)
    except ValueError:
        pass
    return token


def _split_top_level(text: str) -> List[str]:
    parts: List[str] = []
    depth = 0
    quote = ""
    current: List[str] = []
    for ch in text:
        if quote:
            current.append(ch)
            if ch == quote:
                quote = ""
            continue
        if ch in "\"'":
            quote = ch
            current.append(ch)
        elif ch in "[{":
            depth += 1
            current.append(ch)
        elif ch in "]}":
            depth -= 1
            current.append(ch)
        elif ch == "," and depth == 0:
            parts.append("".join(current))
            current = []
        else:
            current.append(ch)
    parts.append("".join(current))
    return parts


# ---------------------------------------------------------------------------------------
# Target builders
# ---------------------------------------------------------------------------------------


def _skill_target(path: str, source: str, kind: TargetKind = TargetKind.SKILL) -> Target:
    return Target(
        kind=kind,
        name=os.path.basename(os.path.normpath(path)) or path,
        path=os.path.abspath(path),
        source=source,
    )


def _markdown_targets(root: str, kind: TargetKind, source: str) -> List[Target]:
    """Every .md under a directory becomes its own command/agent target."""
    targets: List[Target] = []
    if not os.path.isdir(root):
        return targets
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = sorted(d for d in dirnames if d != ".git")
        for filename in sorted(filenames):
            if not filename.lower().endswith((".md", ".markdown")):
                continue
            full = os.path.join(dirpath, filename)
            rel = os.path.relpath(full, root)
            targets.append(
                Target(
                    kind=kind,
                    name=os.path.splitext(rel)[0].replace(os.sep, "/"),
                    path=os.path.abspath(full),
                    source=source,
                )
            )
    return targets


def _hook_targets(
    config: Any, config_path: str, inventory: Inventory
) -> List[Target]:
    """Extract every hook command string from a settings structure."""
    targets: List[Target] = []
    if not isinstance(config, dict):
        return targets
    hooks = config.get("hooks")
    if not isinstance(hooks, dict):
        return targets

    for event, entries in hooks.items():
        for command, matcher in _iter_hook_commands(entries):
            name = "%s %s" % (event, matcher or "*")
            target = Target(
                kind=TargetKind.HOOK,
                name=name.strip(),
                path=os.path.abspath(config_path),
                source=config_path,
                synthetic_only=True,
                meta={
                    "event": event,
                    "matcher": matcher,
                    "command": command,
                    "source_file": config_path,
                    "line": _line_of_snippet(config_path, command),
                    "description": command,
                },
            )
            target.synthetic_files = [
                synthetic_record(
                    "hook:%s" % (name.strip() or event),
                    command,
                    detail="hook command string from %s" % config_path,
                    path=config_path,
                )
            ]
            targets.append(target)
    return targets


def _iter_hook_commands(entries: Any, matcher: str = "") -> List[Tuple[str, str]]:
    out: List[Tuple[str, str]] = []
    if isinstance(entries, str):
        if entries.strip():
            out.append((entries, matcher))
    elif isinstance(entries, list):
        for item in entries:
            out.extend(_iter_hook_commands(item, matcher))
    elif isinstance(entries, dict):
        local_matcher = str(entries.get("matcher", matcher) or matcher)
        command = entries.get("command")
        if isinstance(command, str) and command.strip():
            out.append((command, local_matcher))
        for key in ("hooks", "commands", "steps"):
            if key in entries:
                out.extend(_iter_hook_commands(entries[key], local_matcher))
    return out


def _server_targets(
    servers: Any, config_path: str, client: str, scope: str = ""
) -> List[Target]:
    targets: List[Target] = []
    if not isinstance(servers, dict):
        return targets
    for name, config in servers.items():
        if not isinstance(config, dict):
            config = {"command": str(config)}
        display = "%s/%s" % (client, name) if client else str(name)
        if scope:
            display = "%s (%s)" % (display, scope)
        meta: Dict[str, Any] = {
            "config": config,
            "source_file": config_path,
            "client": client,
            "server": name,
        }
        for key in ("description", "instructions", "tools", "prompts"):
            if key in config:
                meta[key] = config[key]
        try:
            blob = json.dumps({name: config}, indent=2, ensure_ascii=False)
        except (TypeError, ValueError):
            blob = str(config)
        target = Target(
            kind=TargetKind.MCP_SERVER,
            name=display,
            path=os.path.abspath(config_path),
            source=config_path,
            synthetic_only=True,
            meta=meta,
        )
        target.synthetic_files = [
            synthetic_record(
                "mcp:%s" % name,
                blob,
                detail="MCP server entry from %s" % config_path,
                path=config_path,
            )
        ]
        targets.append(target)
    return targets


# ---------------------------------------------------------------------------------------
# Config file handling
# ---------------------------------------------------------------------------------------


def _load_mcp_config(
    path: str, client: str, inventory: Inventory, *, scope_label: str = ""
) -> None:
    if not os.path.isfile(path) or not inventory.claim_config(path):
        return
    config, error = _read_json(path)
    if error is not None:
        inventory.unscanned.append(
            _unscanned(
                "mcp-config:%s" % os.path.basename(path),
                path,
                REASON_PARSE_ERROR,
                error,
                finding_id="MCP_UNPARSEABLE_CONFIG",
            )
        )
        return
    if not isinstance(config, dict):
        inventory.unscanned.append(
            _unscanned(
                "mcp-config:%s" % os.path.basename(path),
                path,
                REASON_PARSE_ERROR,
                "top-level JSON value is not an object",
                finding_id="MCP_UNPARSEABLE_CONFIG",
            )
        )
        return

    inventory.extend(
        _server_targets(config.get("mcpServers"), path, client, scope_label)
    )
    inventory.extend(
        _server_targets(config.get("mcp_servers"), path, client, scope_label)
    )
    inventory.extend(
        _server_targets(config.get("servers"), path, client, scope_label)
    )

    projects = config.get("projects")
    if isinstance(projects, dict):
        for project_path, project_config in projects.items():
            if not isinstance(project_config, dict):
                continue
            inventory.extend(
                _server_targets(
                    project_config.get("mcpServers"),
                    path,
                    client,
                    "project %s" % project_path,
                )
            )
            inventory.extend(_hook_targets(project_config, path, inventory))

    inventory.extend(_hook_targets(config, path, inventory))


def _load_settings(path: str, inventory: Inventory) -> None:
    if not os.path.isfile(path) or not inventory.claim_config(path):
        return
    config, error = _read_json(path)
    if error is not None:
        inventory.unscanned.append(
            _unscanned(
                "settings:%s" % os.path.basename(path),
                path,
                REASON_PARSE_ERROR,
                error,
            )
        )
        return
    inventory.extend(_hook_targets(config, path, inventory))
    if isinstance(config, dict) and isinstance(config.get("mcpServers"), dict):
        inventory.extend(_server_targets(config["mcpServers"], path, "settings"))


def _load_codex_toml(path: str, inventory: Inventory) -> None:
    if not os.path.isfile(path) or not inventory.claim_config(path):
        return
    text, error = _read_text(path)
    if error is not None or text is None:
        inventory.unscanned.append(
            _unscanned(
                "mcp-config:%s" % os.path.basename(path),
                path,
                REASON_UNREADABLE,
                error or "unreadable",
                finding_id="MCP_UNPARSEABLE_CONFIG",
            )
        )
        return
    try:
        data = parse_toml_subset(text)
    except ValueError as exc:
        inventory.unscanned.append(
            _unscanned(
                "mcp-config:%s" % os.path.basename(path),
                path,
                REASON_PARSE_ERROR,
                "TOML outside the supported subset (%s)" % exc,
                finding_id="MCP_UNPARSEABLE_CONFIG",
            )
        )
        return
    for key in ("mcp_servers", "mcpServers", "servers"):
        inventory.extend(_server_targets(data.get(key), path, "codex"))


def _scan_embedded_configs(root: str, inventory: Inventory) -> None:
    """Find MCP/hook configs *inside* a bundle (plugins and --paths fixtures)."""
    if not os.path.isdir(root):
        return
    root_depth = root.rstrip(os.sep).count(os.sep)
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        if dirpath.rstrip(os.sep).count(os.sep) - root_depth >= _EMBEDDED_SCAN_DEPTH:
            dirnames[:] = []
        dirnames[:] = sorted(d for d in dirnames if d not in (".git", "node_modules"))
        for filename in sorted(filenames):
            if filename not in _CONFIG_FILENAMES and not filename.endswith(".mcp.json"):
                continue
            path = os.path.join(dirpath, filename)
            if not inventory.claim_config(path):
                continue
            config, error = _read_json(path)
            if error is not None:
                inventory.unscanned.append(
                    _unscanned(
                        "mcp-config:%s" % os.path.basename(path),
                        path,
                        REASON_PARSE_ERROR,
                        error,
                        finding_id="MCP_UNPARSEABLE_CONFIG",
                    )
                )
                continue
            if not isinstance(config, dict):
                continue
            for key in ("mcpServers", "mcp_servers", "servers"):
                inventory.extend(_server_targets(config.get(key), path, "bundle"))
            inventory.extend(_hook_targets(config, path, inventory))


# ---------------------------------------------------------------------------------------
# Plugins
# ---------------------------------------------------------------------------------------


def _looks_like_plugin_root(path: str) -> bool:
    for marker in (
        ".claude-plugin",
        "plugin.json",
        "skills",
        "commands",
        "agents",
        "hooks",
        ".mcp.json",
    ):
        if os.path.exists(os.path.join(path, marker)):
            return True
    return False


def _discover_plugins(plugins_root: str, inventory: Inventory) -> None:
    if not os.path.isdir(plugins_root):
        return

    manifest = os.path.join(plugins_root, "installed_plugins.json")
    if os.path.isfile(manifest):
        data, error = _read_json(manifest)
        if error is not None:
            inventory.unscanned.append(
                _unscanned(
                    "plugin:installed_plugins.json",
                    manifest,
                    REASON_PARSE_ERROR,
                    error,
                )
            )
        else:
            inventory.notes.append(
                "installed_plugins.json lists %d entr%s"
                % (
                    _count_plugin_entries(data),
                    "y" if _count_plugin_entries(data) == 1 else "ies",
                )
            )

    seen: List[str] = []

    def _walk(path: str, depth: int) -> None:
        if depth > 3 or not os.path.isdir(path):
            return
        try:
            entries = sorted(os.listdir(path))
        except OSError as exc:
            inventory.unscanned.append(
                _unscanned("plugin:%s" % os.path.basename(path), path, REASON_UNREADABLE, str(exc))
            )
            return
        for entry in entries:
            if entry.startswith(".") and entry != ".claude-plugin":
                continue
            full = os.path.join(path, entry)
            if not os.path.isdir(full) or os.path.islink(full):
                continue
            if _looks_like_plugin_root(full):
                if full not in seen:
                    seen.append(full)
                    target = _skill_target(full, plugins_root, TargetKind.PLUGIN)
                    inventory.add(target)
                    _scan_embedded_configs(full, inventory)
                continue
            _walk(full, depth + 1)

    _walk(plugins_root, 0)


def _count_plugin_entries(data: Any) -> int:
    if isinstance(data, dict):
        return sum(
            len(v) if isinstance(v, (list, dict)) else 1 for v in data.values()
        )
    if isinstance(data, list):
        return len(data)
    return 0


# ---------------------------------------------------------------------------------------
# --paths expansion
# ---------------------------------------------------------------------------------------


def _has_manifest(path: str) -> bool:
    for name in _BUNDLE_MANIFESTS:
        full = os.path.join(path, name)
        if name == ".claude-plugin":
            # A marketplace ships .claude-plugin/marketplace.json at the root of a
            # repository full of independent plugins and skills. Only a plugin.json makes
            # the directory one installable plugin.
            if os.path.isfile(os.path.join(full, "plugin.json")):
                return True
            continue
        if os.path.exists(full):
            return True
    return False


def _is_plugin_root(path: str) -> bool:
    return os.path.isfile(os.path.join(path, "plugin.json")) or os.path.isfile(
        os.path.join(path, ".claude-plugin", "plugin.json")
    )


#: How deep below a --paths argument to look for nested bundles. Real layouts sit at
#: depth 2 (skills/<name>/) to 4 (plugins/<p>/skills/<name>/); the bound keeps a scan of
#: a huge checkout from walking every directory in it twice.
_NESTED_BUNDLE_DEPTH = 6


def _nested_bundle_roots(path: str) -> List[str]:
    """Directories below ``path`` that are bundles in their own right.

    A walk stops descending at the first bundle root it meets, so a skill that carries a
    nested example skill stays one bundle, exactly as it installs.
    """
    roots: List[str] = []
    base_depth = path.rstrip(os.sep).count(os.sep)
    for dirpath, dirnames, _ in os.walk(path, topdown=True, followlinks=False):
        if dirpath != path and _has_manifest(dirpath):
            roots.append(dirpath)
            dirnames[:] = []
            continue
        if dirpath.rstrip(os.sep).count(os.sep) - base_depth >= _NESTED_BUNDLE_DEPTH:
            dirnames[:] = []
            continue
        dirnames[:] = sorted(
            d
            for d in dirnames
            if d not in SKIP_DIRNAMES and not os.path.islink(os.path.join(dirpath, d))
        )
    return roots


def _list_dir(path: str) -> Tuple[List[str], List[str]]:
    subdirs: List[str] = []
    loose_files: List[str] = []
    for entry in sorted(os.listdir(path)):
        full = os.path.join(path, entry)
        if os.path.isdir(full) and not os.path.islink(full):
            if entry not in (".git",):
                subdirs.append(full)
        elif os.path.isfile(full):
            loose_files.append(full)
    return subdirs, loose_files


def _split_container(path: str, roots: List[str], top: str) -> List[Target]:
    """One target per nested bundle, and per sibling directory that holds none.

    Every directory between ``top`` and a bundle is a container: its immediate
    subdirectories are split further, and its own loose files become one
    non-recursive target, so no file is dropped and no two bundles are merged.
    """
    targets: List[Target] = []
    subdirs, loose_files = _list_dir(path)
    for subdir in subdirs:
        if subdir in roots:
            kind = TargetKind.PLUGIN if _is_plugin_root(subdir) else TargetKind.SKILL
            targets.append(_skill_target(subdir, "--paths", kind))
        elif any(root.startswith(subdir + os.sep) for root in roots):
            targets.extend(_split_container(subdir, roots, top))
        else:
            targets.append(_skill_target(subdir, "--paths"))
    if loose_files and path != top:
        loose = _skill_target(path, "--paths")
        loose.recursive = False
        targets.append(loose)
    return targets


def _disambiguate(targets: List[Target], top: str) -> None:
    """Two bundles named ``helper`` in one repository must not share a report row."""
    seen: Dict[str, int] = {}
    for target in targets:
        seen[target.display] = seen.get(target.display, 0) + 1
    for target in targets:
        if seen[target.display] > 1:
            rel = os.path.relpath(target.path, top).replace(os.sep, "/")
            target.name = rel if rel != "." else target.name


def expand_paths(paths: List[str], inventory: Inventory) -> List[Target]:
    """Turn --paths arguments into bundle targets.

    A directory containing a manifest (SKILL.md, plugin.json, .claude-plugin/plugin.json)
    is one bundle. Anything else is a *container*, and bundle-level mismatch rules must
    never see two bundles as one: one skill's credential read must not pair with a
    different skill's curl, and one skill's declared network use must not excuse
    another skill's offline claim.

    Containers are split at every bundle found below them, at any depth up to
    ``_NESTED_BUNDLE_DEPTH`` (``skills/<name>/``, ``plugins/<p>/skills/<name>/``,
    ``.claude/skills/<name>/``). A container with no nested bundle keeps the flat rule:
    each immediate subdirectory is its own bundle.
    """
    targets: List[Target] = []
    for raw in paths:
        path = os.path.abspath(os.path.expanduser(raw))
        if not os.path.exists(path):
            inventory.unscanned.append(
                _unscanned("path:%s" % raw, path, REASON_UNREADABLE, "path does not exist")
            )
            continue
        if os.path.isfile(path):
            targets.append(
                Target(
                    kind=TargetKind.SKILL,
                    name=os.path.basename(path),
                    path=path,
                    source="--paths",
                )
            )
            continue

        try:
            subdirs, loose_files = _list_dir(path)
        except OSError as exc:
            inventory.unscanned.append(
                _unscanned("path:%s" % raw, path, REASON_UNREADABLE, str(exc))
            )
            continue

        if _has_manifest(path) or not subdirs:
            targets.append(_skill_target(path, "--paths"))
            continue

        try:
            roots = _nested_bundle_roots(path)
            found = _split_container(path, roots, path)
        except OSError as exc:
            inventory.unscanned.append(
                _unscanned("path:%s" % raw, path, REASON_UNREADABLE, str(exc))
            )
            continue
        _disambiguate(found, path)
        targets.extend(found)
        if loose_files:
            inventory.notes.append(
                "%s: %d loose file(s) at the container root scanned separately from the "
                "%d bundle(s) below it" % (path, len(loose_files), len(found))
            )
            root_target = _skill_target(path, "--paths")
            root_target.recursive = False
            targets.append(root_target)
    return targets


# ---------------------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------------------


def discover(options: DiscoveryOptions) -> Inventory:
    """Build the full inventory for one scan."""
    home = options.resolved_home()
    cwd = options.resolved_cwd()
    inventory = Inventory(home=home, cwd=cwd)

    if options.paths:
        for target in expand_paths(options.paths, inventory):
            inventory.add(target)
            _scan_embedded_configs(target.path, inventory)

    if not options.wants_home_discovery():
        return inventory

    claude_home = os.path.join(home, ".claude")

    # Skills ---------------------------------------------------------------------------
    skills_root = os.path.join(claude_home, "skills")
    for path in _immediate_dirs(skills_root, inventory):
        target = _skill_target(path, skills_root)
        inventory.add(target)
        _scan_embedded_configs(path, inventory)

    # Commands and agents ---------------------------------------------------------------
    inventory.extend(
        _markdown_targets(
            os.path.join(claude_home, "commands"),
            TargetKind.COMMAND,
            os.path.join(claude_home, "commands"),
        )
    )
    inventory.extend(
        _markdown_targets(
            os.path.join(claude_home, "agents"),
            TargetKind.AGENT,
            os.path.join(claude_home, "agents"),
        )
    )

    # Plugins ---------------------------------------------------------------------------
    _discover_plugins(os.path.join(claude_home, "plugins"), inventory)

    # Hooks / settings -------------------------------------------------------------------
    _load_settings(os.path.join(claude_home, "settings.json"), inventory)
    _load_settings(os.path.join(claude_home, "settings.local.json"), inventory)

    # MCP: Claude Code -------------------------------------------------------------------
    _load_mcp_config(os.path.join(home, ".claude.json"), "claude-code", inventory)

    # Project scope ----------------------------------------------------------------------
    project_claude = os.path.join(cwd, ".claude")
    if options.project or os.path.isdir(project_claude):
        project_skills = os.path.join(project_claude, "skills")
        for path in _immediate_dirs(project_skills, inventory):
            target = _skill_target(path, project_skills)
            inventory.add(target)
            _scan_embedded_configs(path, inventory)
        inventory.extend(
            _markdown_targets(
                os.path.join(project_claude, "commands"),
                TargetKind.COMMAND,
                os.path.join(project_claude, "commands"),
            )
        )
        inventory.extend(
            _markdown_targets(
                os.path.join(project_claude, "agents"),
                TargetKind.AGENT,
                os.path.join(project_claude, "agents"),
            )
        )
        _load_settings(os.path.join(project_claude, "settings.json"), inventory)
        _load_settings(os.path.join(project_claude, "settings.local.json"), inventory)
        _load_mcp_config(os.path.join(cwd, ".mcp.json"), "project", inventory)

    # MCP: Claude Desktop (macOS) ---------------------------------------------------------
    _load_mcp_config(
        os.path.join(
            home, "Library", "Application Support", "Claude", "claude_desktop_config.json"
        ),
        "claude-desktop",
        inventory,
    )
    # Linux/Windows-style locations, same file name.
    _load_mcp_config(
        os.path.join(home, ".config", "Claude", "claude_desktop_config.json"),
        "claude-desktop",
        inventory,
    )

    # Other clients ------------------------------------------------------------------------
    if options.all_clients:
        _load_mcp_config(os.path.join(home, ".cursor", "mcp.json"), "cursor", inventory)
        _load_mcp_config(
            os.path.join(home, ".vscode", "mcp.json"), "vscode", inventory
        )
        _load_codex_toml(os.path.join(home, ".codex", "config.toml"), inventory)

    return inventory


def _immediate_dirs(root: str, inventory: Inventory) -> List[str]:
    if not os.path.isdir(root):
        return []
    try:
        entries = sorted(os.listdir(root))
    except OSError as exc:
        inventory.unscanned.append(
            _unscanned("dir:%s" % root, root, REASON_UNREADABLE, str(exc))
        )
        return []
    out: List[str] = []
    for entry in entries:
        if entry.startswith("."):
            continue
        full = os.path.join(root, entry)
        if os.path.isdir(full):
            out.append(full)
    return out
