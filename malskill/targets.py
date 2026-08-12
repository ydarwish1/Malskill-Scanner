"""Core containers: what a scan target is and how its bytes are (carefully) read.

Everything in this module is part of the trusted extractor layer, so it obeys the
extractor rules from the blueprint:

* byte-level reads only, never ``exec``/``eval``, never a shell, never a renderer;
* symlinks that resolve outside the scanned root are refused and reported, never
  followed — that escape is itself a known trojan/exfil trick;
* files above 2 MiB are truncated for analysis and reported as NOT-FULLY-ANALYZED,
  but the first 2 MiB are still scanned rather than skipped;
* a NUL byte in the first 8 KiB marks a file binary: byte-pattern rules still run over
  it, and it is still reported as not fully analyzed. A scanner that silently drops
  what it cannot read is worse than no scanner.

File contents are loaded per target and dropped again after the rules run, so scanning
several thousand bundles does not require holding them all in memory.
"""

from __future__ import annotations

import enum
import hashlib
import os
import stat
from dataclasses import dataclass, field
from typing import Any, Dict, Iterator, List, Optional, Set, Tuple

from malskill import roles as roles_module
from malskill.roles import FileRole, SuppressedHit
from malskill.rules import (
    REASON_BINARY,
    REASON_PARSE_ERROR,
    REASON_SYMLINK_OUT,
    REASON_TOO_LARGE,
    REASON_UNREADABLE,
    Unscanned,
)
from malskill.sanitize import decode_bytes

__all__ = [
    "MAX_FILE_BYTES",
    "TargetKind",
    "FileRecord",
    "Target",
    "Inventory",
]

#: Analysis cap per file. Larger files are still scanned up to this point.
MAX_FILE_BYTES = 2 * 1024 * 1024
#: Bytes inspected for the NUL-byte binary sniff.
BINARY_SNIFF_BYTES = 8 * 1024
#: Defensive cap so one pathological directory cannot stall a whole scan.
MAX_FILES_PER_TARGET = 20000
#: Hard ceiling on bytes streamed for the content hash. Without it, a symlink or a
#: device node pointing at /dev/zero would hash forever; the read loop below is the one
#: place in the scanner that consumes unbounded input.
MAX_HASH_BYTES = 64 * 1024 * 1024
#: Directories never descended into, and reported as NOT-FULLY-ANALYZED when present.
#: VCS internals, dependency trees and caches: enormous, third-party, and not the
#: bundle's own content. Scanning them buries the one finding that matters under a
#: thousand rows from vendored libraries, which is the exact failure mode the README
#: names. Their absence is announced, never silent.
SKIP_DIRNAMES = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        "node_modules",
        ".venv",
        "venv",
        "__pycache__",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".tox",
        ".gradle",
        ".next",
        ".turbo",
        "site-packages",
    }
)

_TEXT_HINT_SUFFIXES = frozenset(
    {
        ".md",
        ".markdown",
        ".txt",
        ".json",
        ".jsonc",
        ".yaml",
        ".yml",
        ".toml",
        ".sh",
        ".bash",
        ".zsh",
        ".fish",
        ".py",
        ".js",
        ".mjs",
        ".cjs",
        ".ts",
        ".rb",
        ".pl",
        ".php",
        ".ps1",
        ".rs",
        ".go",
        ".env",
        ".cfg",
        ".ini",
        ".conf",
        ".plist",
        ".html",
        ".xml",
        ".csv",
    }
)


class TargetKind(str, enum.Enum):
    """The kinds of things a scan can cover. Values match ``Finding.kind``."""

    SKILL = "skill"
    PLUGIN = "plugin"
    COMMAND = "command"
    AGENT = "agent"
    HOOK = "hook"
    MCP_SERVER = "mcp-server"
    MCP_CONFIG = "mcp-config"

    def __str__(self) -> str:
        return self.value


@dataclass
class FileRecord:
    """One file (or one synthetic string, e.g. a hook command) inside a target."""

    path: str
    rel: str
    size: int = 0
    data: bytes = b""
    sha256: str = ""
    truncated: bool = False
    is_binary: bool = False
    #: Set when the file could not be fully analyzed (see REASON_* constants).
    reason: Optional[str] = None
    detail: str = ""
    #: True for content that is not a real file on disk (hook commands, MCP server
    #: config fragments) but must still receive the full byte-rule pass.
    synthetic: bool = False
    loaded: bool = False
    #: st_mode as seen at read time; the execute bit feeds role classification.
    mode: int = 0
    #: Assigned by malskill.roles.assign() when the target is loaded.
    role: FileRole = FileRole.DATA
    _text: Optional[str] = field(default=None, repr=False, compare=False)
    _fenced: Optional[Set[int]] = field(default=None, repr=False, compare=False)

    # -- content -----------------------------------------------------------------------
    @property
    def text(self) -> str:
        """Decoded content for text rules. Invisible codepoints are preserved."""
        if self._text is None:
            self._text = decode_bytes(self.data)
        return self._text

    @property
    def has_content(self) -> bool:
        return bool(self.data)

    @property
    def is_text_like(self) -> bool:
        return not self.is_binary

    @property
    def suffix(self) -> str:
        return os.path.splitext(self.rel)[1].lower()

    @property
    def looks_textual(self) -> bool:
        return self.suffix in _TEXT_HINT_SUFFIXES

    def line_of(self, index: int) -> int:
        """1-based line number for a character index into :attr:`text`."""
        if index <= 0:
            return 1
        return self.text.count("\n", 0, index) + 1

    def line_text(self, line: int) -> str:
        lines = self.text.split("\n")
        if 1 <= line <= len(lines):
            return lines[line - 1]
        return ""

    def fenced_lines(self) -> Set[int]:
        """1-based line numbers inside fenced markdown code blocks, computed once.

        Cached per record: ``executable_context()`` is called for every hit, and a big
        SKILL.md with fifty hits would otherwise be re-scanned fifty times.
        """
        if self._fenced is None:
            from malskill.rules.patterns import compute_fenced_code_lines

            self._fenced = compute_fenced_code_lines(self.text)
        return self._fenced

    def unload(self) -> None:
        self.data = b""
        self._text = None
        self._fenced = None
        self.loaded = False

    def as_unscanned(self, target_name: str) -> Optional[Unscanned]:
        if self.reason is None:
            return None
        finding_id = "SYMLINK_ESCAPE" if self.reason == REASON_SYMLINK_OUT else None
        return Unscanned(
            target=target_name,
            file=self.rel or self.path,
            reason=self.reason,
            detail=self.detail,
            finding_id=finding_id,
        )


@dataclass
class Target:
    """A scanned unit: a skill bundle, a plugin, a command file, a hook, an MCP server."""

    kind: TargetKind
    name: str
    path: str
    source: str = ""
    files: List[FileRecord] = field(default_factory=list)
    #: Extra structured context: parsed frontmatter, MCP server config, hook event, ...
    meta: Dict[str, Any] = field(default_factory=dict)
    #: Synthetic records injected at discovery time (hook command strings, server JSON).
    synthetic_files: List[FileRecord] = field(default_factory=list)
    #: True for targets whose content is entirely synthetic (hooks, MCP servers). Their
    #: `path` points at the config file they came from, which must NOT be read again as
    #: bundle content or every finding would be reported twice.
    synthetic_only: bool = False
    #: False for the "loose files at a container root" target created by --paths: it
    #: must read only its own top-level files. Recursing there would merge every bundle
    #: under the container into one target, and bundle-level mismatch rules would then
    #: pair one skill's credential read with a different skill's curl.
    recursive: bool = True
    #: Populated by claims.derive() during load().
    claims: Any = None
    #: Pattern matches that landed in a non-actionable role (docs/test/data). Collected
    #: rather than discarded, so the report can count them and --paranoid can list them.
    suppressed: List[SuppressedHit] = field(default_factory=list)
    #: Set by the engine from --paranoid. Rules never read it; the engine does.
    paranoid: bool = False
    loaded: bool = False
    #: Set when discovery itself failed (unparseable config, unreadable directory).
    load_errors: List[Unscanned] = field(default_factory=list)

    # -- identity ----------------------------------------------------------------------
    @property
    def display(self) -> str:
        return "%s:%s" % (self.kind.value, self.name)

    @property
    def key(self) -> str:
        """Stable identity for the baseline store."""
        return "%s:%s@%s" % (self.kind.value, self.name, self.path)

    @property
    def root(self) -> str:
        return self.path if os.path.isdir(self.path) else os.path.dirname(self.path)

    # -- content -----------------------------------------------------------------------
    def load(self) -> None:
        """Read the target's bytes. Idempotent; pair with :meth:`unload`."""
        if self.loaded:
            return
        self.files = list(self.synthetic_files)
        self.suppressed = []
        self._suppressed_keys = set()
        for record in self.files:
            record.loaded = True
        if not self.synthetic_only:
            if os.path.isdir(self.path):
                self.files.extend(
                    _walk_bundle(
                        self.path, recursive=self.recursive, errors=self.load_errors,
                        target_name=self.display,
                    )
                )
            elif os.path.exists(self.path) or os.path.islink(self.path):
                root = os.path.dirname(self.path)
                self.files.append(
                    _read_file(self.path, root, os.path.basename(self.path))
                )
        roles_module.assign(self)
        self.loaded = True

    def unload(self) -> None:
        for record in self.files:
            if not record.synthetic:
                record.unload()
            else:
                record._fenced = None
        self.files = [r for r in self.files if r.synthetic]
        self.loaded = False
        # Drop the per-target matcher caches with the bytes they describe.
        for attr in ("_egress_cache", "_sensitive_cache"):
            if hasattr(self, attr):
                delattr(self, attr)

    # -- iteration helpers -------------------------------------------------------------
    def iter_files(self) -> Iterator[FileRecord]:
        return iter(self.files)

    def iter_content_files(self) -> Iterator[FileRecord]:
        """Files with bytes available for rules (includes truncated and binary ones)."""
        for record in self.files:
            if record.has_content:
                yield record

    def iter_text_files(self) -> Iterator[FileRecord]:
        """Files whose decoded text is meaningful for text rules."""
        for record in self.files:
            if record.has_content and not record.is_binary:
                yield record

    def unscanned(self) -> List[Unscanned]:
        out = list(self.load_errors)
        for record in self.files:
            entry = record.as_unscanned(self.display)
            if entry is not None:
                out.append(entry)
        return out

    def file_hashes(self) -> Dict[str, str]:
        """rel -> sha256, including synthetic content so hook/MCP edits show as drift."""
        return {r.rel: r.sha256 for r in self.files if r.sha256}

    def stats(self) -> Tuple[int, int]:
        """(files seen, files not fully analyzed)."""
        total = len([r for r in self.files if not r.synthetic])
        partial = len([r for r in self.files if not r.synthetic and r.reason])
        return total, partial


@dataclass
class Inventory:
    """Everything discovery found, plus what it could not read."""

    targets: List[Target] = field(default_factory=list)
    unscanned: List[Unscanned] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)
    home: str = ""
    cwd: str = ""
    #: Absolute paths of config files already ingested (settings/MCP). Discovery walks
    #: overlapping roots (a container directory and its bundles), and a config read
    #: twice would register the same hook or server twice.
    processed_configs: Set[str] = field(default_factory=set)

    def claim_config(self, path: str) -> bool:
        """Return True the first time a config path is seen; False afterwards."""
        key = os.path.abspath(path)
        if key in self.processed_configs:
            return False
        self.processed_configs.add(key)
        return True

    def add(self, target: Target) -> None:
        self.targets.append(target)

    def extend(self, targets: List[Target]) -> None:
        self.targets.extend(targets)

    def by_kind(self, kind: TargetKind) -> List[Target]:
        return [t for t in self.targets if t.kind == kind]

    def __len__(self) -> int:
        return len(self.targets)


# ---------------------------------------------------------------------------------------
# Reading
# ---------------------------------------------------------------------------------------


def _is_within(root_real: str, candidate_real: str) -> bool:
    if candidate_real == root_real:
        return True
    return candidate_real.startswith(root_real.rstrip(os.sep) + os.sep)


def _walk_bundle(
    root: str,
    *,
    recursive: bool = True,
    errors: Optional[List[Unscanned]] = None,
    target_name: str = "",
) -> List[FileRecord]:
    """Walk a bundle directory, never following symlinks out of it.

    ``os.walk`` swallows directory-listing errors by default, which would turn an
    unreadable subdirectory into a silent gap. The ``onerror`` hook below turns it into
    a NOT-FULLY-ANALYZED record instead.
    """
    records: List[FileRecord] = []
    try:
        root_real = os.path.realpath(root)
    except OSError:
        root_real = root

    def _on_error(exc: OSError) -> None:
        if errors is None:
            return
        errors.append(
            Unscanned(
                target=target_name or root,
                file=str(getattr(exc, "filename", "") or root),
                reason=REASON_UNREADABLE,
                detail="directory could not be listed: %s" % exc,
            )
        )

    count = 0
    truncated = False
    for dirpath, dirnames, filenames in os.walk(
        root, topdown=True, followlinks=False, onerror=_on_error
    ):
        if not recursive:
            dirnames[:] = []
        for skipped in sorted(d for d in dirnames if d in SKIP_DIRNAMES):
            full = os.path.join(dirpath, skipped)
            records.append(
                FileRecord(
                    path=full,
                    rel=os.path.relpath(full, root),
                    reason=REASON_TOO_LARGE,
                    detail="vendored/VCS directory not analyzed (%s/)" % skipped,
                )
            )
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRNAMES)
        # Refuse symlinked directories that escape the bundle; report, do not follow.
        kept: List[str] = []
        for dirname in dirnames:
            full = os.path.join(dirpath, dirname)
            if os.path.islink(full):
                rel = os.path.relpath(full, root)
                try:
                    resolved = os.path.realpath(full)
                except OSError:
                    resolved = full
                if not _is_within(root_real, resolved):
                    records.append(
                        FileRecord(
                            path=full,
                            rel=rel,
                            reason=REASON_SYMLINK_OUT,
                            detail="directory symlink -> %s" % resolved,
                        )
                    )
                    continue
                # In-bundle symlinked dir: skip to avoid cycles, but say so.
                records.append(
                    FileRecord(
                        path=full,
                        rel=rel,
                        reason=REASON_SYMLINK_OUT,
                        detail="in-bundle directory symlink -> %s (not descended)"
                        % resolved,
                    )
                )
                continue
            kept.append(dirname)
        dirnames[:] = kept

        for filename in sorted(filenames):
            full = os.path.join(dirpath, filename)
            rel = os.path.relpath(full, root)
            if count >= MAX_FILES_PER_TARGET:
                # One summary record, not one per file: a 100k-file bundle would
                # otherwise bury the report under 80k identical rows.
                if not truncated:
                    truncated = True
                    records.append(
                        FileRecord(
                            path=root,
                            rel=".",
                            reason=REASON_TOO_LARGE,
                            detail="bundle exceeds %d files; the remainder (from %s "
                            "onwards) was not analyzed" % (MAX_FILES_PER_TARGET, rel),
                        )
                    )
                continue
            count += 1
            records.append(_read_file(full, root, rel, root_real=root_real))
    return records


def _read_file(
    path: str, root: str, rel: str, root_real: Optional[str] = None
) -> FileRecord:
    if root_real is None:
        try:
            root_real = os.path.realpath(root)
        except OSError:
            root_real = root

    if os.path.islink(path):
        try:
            resolved = os.path.realpath(path)
        except OSError:
            resolved = path
        if not _is_within(root_real, resolved):
            return FileRecord(
                path=path,
                rel=rel,
                reason=REASON_SYMLINK_OUT,
                detail="symlink -> %s" % resolved,
            )

    try:
        info = os.stat(path)
    except OSError as exc:
        return FileRecord(
            path=path, rel=rel, reason=REASON_UNREADABLE, detail=str(exc)
        )

    # Only regular files are opened. A FIFO would block the scan forever, a socket
    # would raise, and a character device (/dev/zero, /dev/urandom) would stream
    # without end. All three exist inside real bundles by accident often enough.
    if not stat.S_ISREG(info.st_mode):
        return FileRecord(
            path=path,
            rel=rel,
            mode=info.st_mode,
            reason=REASON_UNREADABLE,
            detail="not a regular file (%s); not opened" % _file_type_name(info.st_mode),
        )

    size = info.st_size
    record = FileRecord(path=path, rel=rel, size=size, mode=info.st_mode)
    digest = hashlib.sha256()
    hashed = 0
    hash_truncated = False
    try:
        with open(path, "rb") as handle:
            data = handle.read(MAX_FILE_BYTES)
            digest.update(data)
            hashed += len(data)
            extra = handle.read(1024 * 1024)
            while extra:
                digest.update(extra)
                hashed += len(extra)
                if hashed >= MAX_HASH_BYTES:
                    hash_truncated = True
                    break
                extra = handle.read(1024 * 1024)
    except OSError as exc:
        record.reason = REASON_UNREADABLE
        record.detail = str(exc)
        return record

    record.data = data
    record.sha256 = digest.hexdigest()
    record.loaded = True
    if hash_truncated:
        record.truncated = True
        record.reason = REASON_TOO_LARGE
        record.detail = "only the first %d bytes were hashed" % MAX_HASH_BYTES

    if size > MAX_FILE_BYTES:
        record.truncated = True
        record.reason = REASON_TOO_LARGE
        record.detail = "%d bytes; only the first %d were analyzed" % (
            size,
            MAX_FILE_BYTES,
        )

    if b"\x00" in data[:BINARY_SNIFF_BYTES]:
        record.is_binary = True
        if record.reason is None:
            record.reason = REASON_BINARY
            record.detail = "NUL byte in first %d bytes; byte-pattern rules only" % (
                BINARY_SNIFF_BYTES
            )
    return record


def _file_type_name(mode: int) -> str:
    for predicate, name in (
        (stat.S_ISDIR, "directory"),
        (stat.S_ISFIFO, "named pipe"),
        (stat.S_ISSOCK, "socket"),
        (stat.S_ISCHR, "character device"),
        (stat.S_ISBLK, "block device"),
    ):
        if predicate(mode):
            return name
    return "special file"


def synthetic_record(
    name: str, content: str, *, detail: str = "", path: str = ""
) -> FileRecord:
    """Wrap a string (hook command, MCP config fragment) as a scannable record."""
    data = content.encode("utf-8", errors="replace")
    return FileRecord(
        path=path or name,
        rel=name,
        size=len(data),
        data=data,
        sha256=hashlib.sha256(data).hexdigest(),
        synthetic=True,
        detail=detail,
        loaded=True,
    )


def parse_error_record(path: str, rel: str, detail: str) -> FileRecord:
    """A file that exists but could not be parsed: loud, never silent."""
    return FileRecord(path=path, rel=rel, reason=REASON_PARSE_ERROR, detail=detail)
