"""Baseline store: remember what every bundle looked like, alert on what changed.

The realistic attack is not a new obviously-evil skill — you would read that one. It is a
skill you already trust going bad in an update, or a file quietly appearing inside a
bundle you accepted months ago. So the scanner records a sha256 per file per target and
compares on every run.

Storage: ``<home>/.malskill/baseline.json`` (``--home`` redirects it, which is what makes
the tests hermetic). The file carries a ``self_checksum`` over its own canonical
contents; if that does not match, drift detection cannot be trusted and the scanner says
so loudly (``BASELINE_TAMPERED``, HIGH) rather than reporting "no drift".

Findings:

* ``BASELINE_DRIFT`` [MEDIUM] — a known file's hash changed, or a file appeared in a
  known bundle.
* ``BASELINE_NEW_TARGET`` [LOW] — a bundle the baseline has never seen. Informational,
  but named, so an install can never land silently.
* ``BASELINE_TAMPERED`` [HIGH] — the store's self-checksum does not match.

Nothing here ever runs on the *first* scan: with no accepted baseline there is nothing to
compare against, and flagging every installed bundle as "new" on day one would be noise,
not signal. The report says so explicitly instead.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from malskill import __version__
from malskill.rules import Finding, make_finding
from malskill.sanitize import for_display

__all__ = [
    "BASELINE_VERSION",
    "baseline_path",
    "BaselineStore",
    "load",
    "save",
    "collect",
    "check",
]

BASELINE_VERSION = 1
#: Files per target recorded in the baseline. Beyond this, the count itself is recorded.
MAX_FILES_PER_TARGET = 5000
#: Drift findings emitted per target before the rest are summarised.
MAX_DRIFT_PER_TARGET = 3


def baseline_path(home: str) -> str:
    """``<home>/.malskill/baseline.json`` — honours --home for hermetic runs."""
    root = os.path.abspath(os.path.expanduser(home or "~"))
    return os.path.join(root, ".malskill", "baseline.json")


@dataclass
class BaselineStore:
    path: str
    targets: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    exists: bool = False
    tampered: bool = False
    error: Optional[str] = None
    updated: str = ""
    tool_version: str = ""

    def get(self, key: str) -> Optional[Dict[str, Any]]:
        return self.targets.get(key)


def _canonical(payload: Dict[str, Any]) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _checksum(payload: Dict[str, Any]) -> str:
    return hashlib.sha256(_canonical(payload).encode("utf-8")).hexdigest()


def load(home: str) -> BaselineStore:
    """Load and verify the baseline store. Never raises."""
    path = baseline_path(home)
    store = BaselineStore(path=path)
    if not os.path.isfile(path):
        return store
    store.exists = True
    try:
        with open(path, "rb") as handle:
            raw = handle.read(64 * 1024 * 1024)
        data = json.loads(raw.decode("utf-8", errors="replace"))
    except (OSError, ValueError) as exc:
        store.tampered = True
        store.error = "baseline unreadable or not valid JSON: %s" % exc
        return store

    if not isinstance(data, dict) or "targets" not in data:
        store.tampered = True
        store.error = "baseline is structurally invalid (no 'targets' object)"
        return store

    recorded = data.pop("self_checksum", None)
    computed = _checksum(data)
    if recorded != computed:
        store.tampered = True
        store.error = (
            "self-checksum mismatch (recorded %s, computed %s)"
            % (str(recorded)[:16], computed[:16])
        )
        return store

    targets = data.get("targets")
    if not isinstance(targets, dict):
        store.tampered = True
        store.error = "baseline 'targets' is not an object"
        return store

    store.targets = targets
    store.updated = str(data.get("updated", ""))
    store.tool_version = str(data.get("tool_version", ""))
    return store


def save(home: str, targets: Dict[str, Dict[str, Any]]) -> str:
    """Write a new accepted baseline; returns the path written."""
    path = baseline_path(home)
    directory = os.path.dirname(path)
    if directory and not os.path.isdir(directory):
        os.makedirs(directory, exist_ok=True)
    payload: Dict[str, Any] = {
        "version": BASELINE_VERSION,
        "tool_version": __version__,
        "updated": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "targets": targets,
    }
    payload["self_checksum"] = _checksum(payload)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True, ensure_ascii=True)
        handle.write("\n")
    os.replace(tmp, path)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return path


def collect(inventory) -> Dict[str, Dict[str, Any]]:
    """Load every target just far enough to hash its files."""
    snapshot: Dict[str, Dict[str, Any]] = {}
    for target in inventory.targets:
        try:
            target.load()
            snapshot[target.key] = snapshot_for(target)
        except Exception:  # noqa: BLE001 - a target we cannot read is simply not recorded
            continue
        finally:
            try:
                target.unload()
            except Exception:  # noqa: BLE001
                pass
    return snapshot


def snapshot_for(target) -> Dict[str, Any]:
    files = target.file_hashes()
    truncated = False
    if len(files) > MAX_FILES_PER_TARGET:
        truncated = True
        files = dict(sorted(files.items())[:MAX_FILES_PER_TARGET])
    return {
        "kind": target.kind.value,
        "name": target.name,
        "path": target.path,
        "files": files,
        "truncated": truncated,
    }


def check(
    snapshot: Dict[str, Dict[str, Any]],
    store: BaselineStore,
    *,
    target_lookup: Optional[Dict[str, Any]] = None,
) -> Tuple[List[Finding], List[str]]:
    """Compare a fresh snapshot with the accepted baseline.

    Returns ``(findings, notes)``. Notes explain *why* no drift was reported when that is
    the case, because "no drift" and "no baseline yet" must never look identical.
    """
    findings: List[Finding] = []
    notes: List[str] = []

    if store.tampered:
        findings.append(
            make_finding(
                "BASELINE_TAMPERED",
                target="baseline:%s" % store.path,
                kind="baseline",
                file=store.path,
                evidence=for_display(store.error or "checksum mismatch"),
                why=(
                    "The baseline store at %s failed its own self-checksum (%s). Editing "
                    "the baseline is how a modified bundle is made to look unchanged, so "
                    "drift detection cannot be trusted until this is resolved."
                    % (store.path, store.error or "checksum mismatch")
                ),
                recommendation=(
                    "Delete %s, review every installed bundle by hand, then re-create the "
                    "baseline with 'malskill baseline update'." % store.path
                ),
            )
        )
        return findings, notes

    if not store.exists:
        notes.append(
            "no baseline recorded yet (%s): drift and new-target checks were skipped. "
            "Run 'malskill baseline update' once you have reviewed what is installed."
            % store.path
        )
        return findings, notes

    for key, current in sorted(snapshot.items()):
        previous = store.get(key)
        display = "%s:%s" % (current.get("kind", "target"), current.get("name", key))
        kind = current.get("kind", "target")
        if previous is None:
            findings.append(
                make_finding(
                    "BASELINE_NEW_TARGET",
                    target=display,
                    kind=kind,
                    file=current.get("path"),
                    evidence=for_display(
                        "%s (%d file(s)) not present in the baseline recorded %s"
                        % (
                            current.get("path", key),
                            len(current.get("files", {})),
                            store.updated or "previously",
                        )
                    ),
                    why=(
                        "This %s is not in the accepted baseline, so it was installed or "
                        "renamed since %s. Named on purpose: an install that lands "
                        "silently is an install nobody reviewed."
                        % (kind, store.updated or "the last baseline")
                    ),
                    recommendation=(
                        "Confirm you installed %s. If you did, accept it with 'malskill "
                        "baseline update'; if you did not, remove it." % display
                    ),
                )
            )
            continue

        old_files = previous.get("files") or {}
        new_files = current.get("files") or {}
        changed = [
            rel
            for rel, digest in sorted(new_files.items())
            if rel in old_files and old_files[rel] != digest
        ]
        added = [rel for rel in sorted(new_files) if rel not in old_files]
        removed = [rel for rel in sorted(old_files) if rel not in new_files]

        emitted = 0
        for rel in changed:
            findings.append(
                _drift_finding(display, kind, current, rel, "changed", store)
            )
            emitted += 1
            if emitted >= MAX_DRIFT_PER_TARGET:
                break
        if emitted < MAX_DRIFT_PER_TARGET:
            for rel in added:
                findings.append(
                    _drift_finding(display, kind, current, rel, "appeared", store)
                )
                emitted += 1
                if emitted >= MAX_DRIFT_PER_TARGET:
                    break
        if emitted == 0 and removed:
            findings.append(
                _drift_finding(display, kind, current, removed[0], "disappeared", store)
            )
            emitted += 1

        extra = len(changed) + len(added) + len(removed) - emitted
        if emitted and extra > 0:
            notes.append(
                "%s: %d further file change(s) not listed individually" % (display, extra)
            )

    return findings, notes


def _drift_finding(
    display: str,
    kind: str,
    current: Dict[str, Any],
    rel: str,
    verb: str,
    store: BaselineStore,
) -> Finding:
    return make_finding(
        "BASELINE_DRIFT",
        target=display,
        kind=kind,
        file=rel,
        evidence=for_display("%s %s since the baseline of %s" % (rel, verb, store.updated or "unknown date")),
        why=(
            "%s in %s has %s since the baseline you accepted%s. The dangerous case is not "
            "a new bundle you would scrutinise — it is one you already trust changing "
            "underneath you."
            % (rel, current.get("path", display), verb, " on " + store.updated if store.updated else "")
        ),
        recommendation=(
            "Diff %s against what you accepted before. Run 'malskill baseline update' "
            "only after you have read the change." % rel
        ),
    )
