"""Shared detection primitives.

Every rule module needs the same handful of building blocks — "is there network egress
here", "is there a credential path here", "is this line inside a fenced code block" — and
they must agree with each other, because the mismatch rules combine them. Defining them
once, in one table, is what keeps NETWORK_IN_OFFLINE_CLAIM and SENSITIVE_READ_PLUS_EGRESS
from disagreeing about what "egress" means.

Nothing here is a rule. Nothing here emits a finding. These are matchers over the raw
decoded bytes of a file, plus the small amount of context (line number, enclosing line,
destination host) that the rules need in order to fire on *mismatches* instead of on
scary words.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Pattern, Sequence, Set, Tuple

from malskill.roles import ACTIONABLE_ROLES, FileRole, SuppressedHit, role_of
from malskill.rules import REASON_TOO_LARGE

__all__ = [
    "Hit",
    "EgressHit",
    "MetaField",
    "iter_metadata_fields",
    "is_metadata_file",
    "is_instruction_record",
    "search_text",
    "search_target",
    "actionable_hits",
    "actionable_egress",
    "record_suppressed",
    "find_egress",
    "find_egress_in_target",
    "find_sensitive",
    "find_sensitive_in_target",
    "has_nonlocal_egress",
    "is_local_host",
    "hosts_in",
    "line_at",
    "fenced_code_lines",
    "compute_fenced_code_lines",
    "is_data_file",
    "is_comment_line",
    "dedupe_by_label_and_file",
    "HARD_SENSITIVE_LABELS",
    "SOFT_SENSITIVE_LABELS",
    "is_warning_context",
    "executable_context",
    "is_script_file",
    "is_prose_file",
    "EGRESS_PATTERNS",
    "SENSITIVE_PATTERNS",
    "ENV_HARVEST_PATTERNS",
    "WRITE_INDICATOR_RE",
    "NEGATION_RE",
]


# ---------------------------------------------------------------------------------------
# Generic matching
# ---------------------------------------------------------------------------------------


@dataclass
class Hit:
    """One pattern match inside one file, with enough context to explain itself."""

    label: str
    start: int
    end: int
    matched: str
    line: int
    line_text: str
    file_rel: str
    file_path: str
    record: Any = None

    @property
    def context(self) -> str:
        return self.line_text.strip() or self.matched


def line_at(text: str, index: int) -> Tuple[int, str]:
    """Return the 1-based line number and full line text containing ``index``."""
    if index < 0:
        index = 0
    line_no = text.count("\n", 0, index) + 1
    start = text.rfind("\n", 0, index) + 1
    end = text.find("\n", index)
    if end == -1:
        end = len(text)
    return line_no, text[start:end]


#: Bound on hits collected from a single file per table, so one pathological file cannot
#: turn a scan into an hour of list building. Set well above ``limit_per_pattern`` times
#: the largest table (25 x 20 = 500): the old value of 200 was reachable, and reaching it
#: aborted the whole loop, so the *later* patterns in a table silently stopped running on
#: exactly the busiest files.
_MAX_HITS_PER_FILE = 2000
#: Most frontmatter fields inspected per file. Above this the file is reported as not fully
#: analyzed rather than partially and silently scanned.
MAX_METADATA_FIELDS_PER_FILE = 2000
#: Most metadata bytes inspected per file, same rule.
MAX_METADATA_BYTES_PER_FILE = 1_000_000


def search_text(
    text: str,
    patterns: Sequence[Tuple[str, Pattern]],
    *,
    file_rel: str = "",
    file_path: str = "",
    record: Any = None,
    limit_per_pattern: int = 25,
) -> List[Hit]:
    """Run a labelled pattern table over decoded text.

    Deliberately one compiled pattern at a time rather than one combined alternation:
    measured on a real 100 MB corpus the per-pattern loop is ~35% faster, because each
    small pattern keeps its literal-prefix optimisation while a giant alternation loses
    it. Slower scanners get skipped, and a skipped scanner finds nothing.
    """
    hits: List[Hit] = []
    for label, pattern in patterns:
        count = 0
        for match in pattern.finditer(text):
            line_no, line_text = line_at(text, match.start())
            hits.append(
                Hit(
                    label=label,
                    start=match.start(),
                    end=match.end(),
                    matched=match.group(0),
                    line=line_no,
                    line_text=line_text,
                    file_rel=file_rel,
                    file_path=file_path,
                    record=record,
                )
            )
            count += 1
            if count >= limit_per_pattern:
                break
        if len(hits) >= _MAX_HITS_PER_FILE:
            break
    hits.sort(key=lambda h: (h.file_rel, h.start))
    return hits


def search_target(
    target: Any,
    patterns: Sequence[Tuple[str, Pattern]],
    *,
    text_only: bool = False,
    limit_per_pattern: int = 25,
) -> List[Hit]:
    """Run a pattern table over every readable file in a target.

    Binary and truncated files are included on purpose: byte-pattern rules still apply
    to them, and they are reported separately as NOT-FULLY-ANALYZED. Role filtering is
    a separate step (:func:`actionable_hits`) so that what was dropped can be counted
    rather than silently vanish.
    """
    hits: List[Hit] = []
    for record in getattr(target, "files", []) or []:
        if not getattr(record, "has_content", False):
            continue
        if text_only and getattr(record, "is_binary", False):
            continue
        hits.extend(
            search_text(
                record.text,
                patterns,
                file_rel=record.rel,
                file_path=record.path,
                record=record,
                limit_per_pattern=limit_per_pattern,
            )
        )
    return hits


# ---------------------------------------------------------------------------------------
# Role gating
# ---------------------------------------------------------------------------------------

#: Suppressed records kept per (rule, target). Past this the note's count still grows,
#: but the list stops, so --paranoid cannot itself become the wall of noise.
MAX_SUPPRESSED_PER_RULE_PER_TARGET = 25


def record_suppressed(target: Any, rule_id: str, hit: "Hit") -> None:
    """Remember a pattern match that fell outside the roles a rule may fire from.

    Never silent (README principle 6): the engine counts these into a report note and
    ``--paranoid`` promotes each one to a LOW ``SUPPRESSED_PATTERN_HIT`` finding.
    """
    from malskill.sanitize import for_display

    bucket = getattr(target, "suppressed", None)
    if bucket is None:
        return
    role = role_of(hit.record)
    key = (rule_id, hit.file_rel, hit.line, hit.label)
    seen = getattr(target, "_suppressed_keys", None)
    if seen is None:
        seen = set()
        try:
            target._suppressed_keys = seen
        except AttributeError:  # pragma: no cover - non-Target objects
            return
    if key in seen:
        return
    seen.add(key)
    count = sum(1 for entry in bucket if entry.rule_id == rule_id)
    if count >= MAX_SUPPRESSED_PER_RULE_PER_TARGET:
        return
    bucket.append(
        SuppressedHit(
            rule_id=rule_id,
            role=role.value,
            target=getattr(target, "display", ""),
            kind=getattr(getattr(target, "kind", ""), "value", ""),
            file=hit.file_rel,
            line=hit.line,
            label=hit.label,
            evidence=for_display(hit.context, 240),
        )
    )


def actionable_hits(target: Any, rule_id: str, hits: Iterable["Hit"]) -> List["Hit"]:
    """Keep only hits from EXECUTABLE/INSTRUCTION files; bank the rest as suppressed."""
    kept: List[Hit] = []
    for hit in hits:
        record = hit.record
        if record is not None and role_of(record) in ACTIONABLE_ROLES and not getattr(
            record, "is_binary", False
        ):
            kept.append(hit)
        else:
            record_suppressed(target, rule_id, hit)
    return kept


def actionable_egress(
    target: Any, rule_id: str, egress: Iterable["EgressHit"]
) -> List["EgressHit"]:
    """The same gate for egress hits, which wrap a :class:`Hit`."""
    kept: List[EgressHit] = []
    for item in egress:
        record = item.hit.record
        if record is not None and role_of(record) in ACTIONABLE_ROLES and not getattr(
            record, "is_binary", False
        ):
            kept.append(item)
        else:
            record_suppressed(target, rule_id, item.hit)
    return kept


def dedupe_by_label_and_file(hits: Iterable["Hit"]) -> List["Hit"]:
    """One hit per (label, file). Five rows saying the same thing train the eye to skim."""
    seen: Set[Tuple[str, str]] = set()
    out: List[Hit] = []
    for hit in hits:
        key = (hit.label, hit.file_rel)
        if key in seen:
            continue
        seen.add(key)
        out.append(hit)
    return out


# ---------------------------------------------------------------------------------------
# Network egress
# ---------------------------------------------------------------------------------------

EGRESS_PATTERNS: List[Tuple[str, Pattern]] = [
    ("curl", re.compile(r"(?<![\w./-])curl(?:\.exe)?(?=\s|$)")),
    ("wget", re.compile(r"(?<![\w./-])wget(?:\.exe)?(?=\s|$)")),
    ("netcat", re.compile(r"(?<![\w./-])(?:nc|ncat|netcat|socat)(?=\s+[-\w.])")),
    ("bash /dev/tcp", re.compile(r"/dev/(?:tcp|udp)/")),
    # NOT a bare "urllib": ``from urllib.parse import quote`` is pure string handling and
    # ``from urllib.error import HTTPError`` is exception handling. Neither sends
    # anything, and treating them as egress supplied the "send" half of a CRITICAL
    # exfiltration pairing on a real machine.
    ("python urllib", re.compile(r"\burllib\.request\b|\burllib3\b|\burlopen\s*\(|\burlretrieve\s*\(|\bimport\s+urllib\s*$|\bimport\s+urllib\s*,", re.M)),
    ("python requests", re.compile(r"\brequests\.(?:get|post|put|patch|delete|request|Session)\b")),
    ("python httpx/aiohttp", re.compile(r"\b(?:httpx|aiohttp)\.(?:get|post|put|request|AsyncClient|ClientSession)\b")),
    ("python http.client", re.compile(r"\bhttp\.client\b|\bHTTPSConnection\s*\(|\bHTTPConnection\s*\(")),
    ("raw socket", re.compile(r"\bsocket\.socket\s*\(|\bsocket\.create_connection\s*\(")),
    ("js fetch", re.compile(r"(?<![\w.])fetch\s*\(\s*[`'\"]?\w")),
    ("js XMLHttpRequest", re.compile(r"\bXMLHttpRequest\b")),
    ("websocket", re.compile(r"\bWebSocket\s*\(|\bwebsockets?\.connect\s*\(")),
    ("js axios/got/node-fetch", re.compile(r"\b(?:axios|got|superagent)\.(?:get|post|put|request)\b|\brequire\(['\"](?:node-fetch|axios|got)['\"]\)")),
    ("node http", re.compile(r"\bhttps?\.request\s*\(|\bhttps?\.get\s*\(")),
    ("powershell web", re.compile(r"\bInvoke-(?:WebRequest|RestMethod)\b|\bStart-BitsTransfer\b|\bDownloadString\s*\(")),
    ("scp/sftp/ftp", re.compile(r"(?<![\w./-])(?:scp|sftp|ftp|tftp)(?=\s+[-\w.~/$])")),
    ("rsync to remote", re.compile(r"(?<![\w./-])rsync\s[^\n]*(?:@[\w.-]+:|::)")),
    ("mail pipe", re.compile(r"(?<![\w./-])(?:sendmail|mailx?)(?=\s+[-\w.@])")),
    ("dns exfil", re.compile(r"(?<![\w./-])(?:dig|nslookup|host)\s+[^\s]*\$")),
]

_URL_RE = re.compile(r"\b(?:https?|ftp|ws|wss)://([^\s'\"`<>)\]}\\,;|]+)", re.I)
_HOST_ARG_RE = re.compile(
    r"(?:(?:nc|ncat|netcat|socat|scp|rsync|ssh)\s+(?:-\w+\s+)*)"
    r"([A-Za-z0-9_.-]+\.[A-Za-z]{2,}|\d{1,3}(?:\.\d{1,3}){3}|localhost)\b"
)
_DEV_TCP_RE = re.compile(r"/dev/(?:tcp|udp)/([^/\s'\"]+)")

#: A loopback destination written without a scheme. ``curl localhost:3000`` carries no
#: URL and no nc-style argument, so before this pattern existed the blueprint's localhost
#: exemption simply did not apply to the commonest spelling of it — and a diagram line in
#: a SKILL.md reading "curl localhost:3000  (port status)" supplied the egress half of a
#: CRITICAL exfiltration pairing on a real machine.
_BARE_LOCAL_RE = re.compile(
    r"(?<![\w.:-])(localhost|127(?:\.\d{1,3}){3}|0\.0\.0\.0|\[::1\]|::1|"
    r"host\.docker\.internal|[\w-]+\.local(?:host)?)(?::\d{1,5})?(?![\w.-])",
    re.I,
)

_LOCAL_HOSTS = {
    "localhost",
    "127.0.0.1",
    "0.0.0.0",
    "::1",
    "[::1]",
    "[::]",
    "::",
    "127.0.0.53",
    "host.docker.internal",
    "0",
}


def is_local_host(host: str) -> bool:
    """True when a destination is unambiguously on this machine."""
    if not host:
        return False
    host = host.strip().strip("'\"`").lower()
    host = host.split("@")[-1]
    host = host.rstrip("/")
    # Check the whole token first: splitting "::1" on ":" yields an empty string, which
    # is how the bare IPv6 loopback used to escape the exemption entirely.
    if host in _LOCAL_HOSTS:
        return True
    if host.startswith("[") and "]" in host:
        host = host[: host.index("]") + 1]
    elif host.count(":") == 1:
        host = host.split(":")[0]
    host = host.rstrip("/")
    if host in _LOCAL_HOSTS:
        return True
    if host.startswith("127."):
        return True
    if host.endswith(".local") or host.endswith(".localhost"):
        return True
    return False


def hosts_in(text: str) -> List[str]:
    """Destinations mentioned on a line: URL hosts, nc/scp targets, /dev/tcp targets.

    Bare loopback spellings (``curl localhost:3000``) are included too. That can only
    ever *add* a local destination: a line naming both localhost and a remote host still
    reports the remote one, and :meth:`EgressHit.local_only` requires every destination
    found to be local.
    """
    found: List[str] = []
    for match in _URL_RE.finditer(text):
        rest = match.group(1)
        host = rest.split("/")[0]
        found.append(host)
    for match in _HOST_ARG_RE.finditer(text):
        found.append(match.group(1))
    for match in _DEV_TCP_RE.finditer(text):
        found.append(match.group(1))
    for match in _BARE_LOCAL_RE.finditer(text):
        found.append(match.group(1))
    return found


def urls_in(text: str) -> List[str]:
    return [match.group(0) for match in _URL_RE.finditer(text)]


@dataclass
class EgressHit:
    """A network egress primitive plus what it appears to talk to."""

    hit: Hit
    hosts: List[str]
    urls: List[str]

    @property
    def has_destination(self) -> bool:
        return bool(self.hosts)

    @property
    def local_only(self) -> bool:
        return bool(self.hosts) and all(is_local_host(h) for h in self.hosts)

    @property
    def nonlocal_hosts(self) -> List[str]:
        return [h for h in self.hosts if not is_local_host(h)]

    @property
    def destination(self) -> str:
        if self.urls:
            return self.urls[0]
        if self.hosts:
            return self.hosts[0]
        return ""


def _context_window(text: str, hit: Hit, before: int = 1, after: int = 2) -> str:
    """A few lines around a hit: shell commands and JS calls often wrap lines."""
    lines = text.split("\n")
    idx = hit.line - 1
    start = max(0, idx - before)
    end = min(len(lines), idx + after + 1)
    return "\n".join(lines[start:end])


def find_egress(
    text: str, *, file_rel: str = "", file_path: str = "", record: Any = None
) -> List[EgressHit]:
    """Locate network egress primitives and their apparent destinations."""
    out: List[EgressHit] = []
    for hit in search_text(
        text, EGRESS_PATTERNS, file_rel=file_rel, file_path=file_path, record=record
    ):
        window = _context_window(text, hit)
        out.append(EgressHit(hit=hit, hosts=hosts_in(window), urls=urls_in(window)))
    return out


def find_egress_in_target(target: Any, *, text_only: bool = False) -> List[EgressHit]:
    cache = getattr(target, "_egress_cache", None)
    if cache is not None and cache[0] == text_only:
        return cache[1]
    out: List[EgressHit] = []
    for record in getattr(target, "files", []) or []:
        if not getattr(record, "has_content", False):
            continue
        if text_only and getattr(record, "is_binary", False):
            continue
        out.extend(
            find_egress(
                record.text,
                file_rel=record.rel,
                file_path=record.path,
                record=record,
            )
        )
    try:
        target._egress_cache = (text_only, out)
    except AttributeError:  # pragma: no cover - non-Target objects
        pass
    return out


def has_nonlocal_egress(egress: Iterable[EgressHit]) -> List[EgressHit]:
    """Egress hits that are not provably localhost-only.

    A hit with no visible destination counts: ``curl "$URL"`` is not evidence of a local
    destination, and treating unknown as local would let one variable defeat the rule.
    """
    return [e for e in egress if not e.local_only]


# ---------------------------------------------------------------------------------------
# Sensitive paths
# ---------------------------------------------------------------------------------------

SENSITIVE_PATTERNS: List[Tuple[str, Pattern]] = [
    ("~/.ssh", re.compile(r"(?:~|\$HOME|/home/[\w.$-]+|/Users/[\w.$-]+)?/?\.ssh/[\w.*-]*|(?<![\w-])\.ssh(?=\b)(?!\w)")),
    ("private key file", re.compile(r"\bid_(?:rsa|dsa|ecdsa|ed25519)\b|-----BEGIN (?:RSA |OPENSSH |EC |DSA |PGP )?PRIVATE KEY-----")),
    ("~/.aws credentials", re.compile(r"\.aws/(?:credentials|config)\b|\baws_secret_access_key\b", re.I)),
    ("~/.gnupg", re.compile(r"\.gnupg\b|\bsecring\.(?:gpg|kbx)\b|\bgpg\s+--export-secret-keys\b")),
    ("~/.netrc", re.compile(r"(?<![\w-])\.netrc\b|\b_netrc\b")),
    (".env file", re.compile(r"(?:^|[\s'\"`=(/:])\.env(?:\.[A-Za-z0-9_-]+)?(?![\w/-])", re.M)),
    ("credentials file", re.compile(r"\bcredentials\.(?:json|txt|csv|ini|yml|yaml|db)\b|[/~]\.?credentials\b|\.git-credentials\b", re.I)),
    ("keychain", re.compile(r"\bsecurity\s+find-(?:generic|internet)-password\b|Library/Keychains|\blogin\.keychain(?:-db)?\b|\bsecurity\s+dump-keychain\b")),
    ("~/.claude.json", re.compile(r"\.claude\.json\b|\.claude/\.credentials\.json\b")),
    ("browser secrets", re.compile(r"(?:Chrome|Chromium|Brave|Edge|Firefox)[^\n'\"]{0,60}(?:Cookies|Login Data|Local State|logins\.json|key4\.db)|\bcookies\.sqlite\b|\bLogin Data\b")),
    ("cloud/CI tokens", re.compile(r"\.kube/config\b|\.docker/config\.json\b|\.npmrc\b|\.pypirc\b|\.config/gh/hosts\.yml\b|\.config/gcloud\b|\.azure/(?:accessTokens|msal)\w*\.json\b")),
    ("crypto wallet", re.compile(r"\bwallet\.dat\b|Ethereum/keystore|\.electrum/wallets\b|Exodus/exodus\.wallet\b")),
    ("shell history", re.compile(r"(?<![\w-])\.(?:bash|zsh)_history\b|\.python_history\b")),
]

#: Bulk environment harvesting: the whole environment, not one named variable.
ENV_HARVEST_PATTERNS: List[Tuple[str, Pattern]] = [
    ("printenv dump", re.compile(r"(?<![\w./-])printenv(?:\s*(?:\||>|$))")),
    ("env dump", re.compile(r"(?<![\w./-])env\s*(?:\||>|>>)")),
    ("set dump", re.compile(r"(?<![\w./-])set\s*\|\s*(?:curl|nc|base64|gzip)")),
    ("python environ dump", re.compile(r"(?:json\.dumps|dict|str|repr)\s*\(\s*os\.environ|os\.environ\.copy\s*\(\)|list\(os\.environ")),
    ("node env dump", re.compile(r"JSON\.stringify\s*\(\s*process\.env|Object\.(?:keys|entries|assign)\s*\(\s*process\.env")),
]


#: Labels that are unambiguous secrets: seeing one paired with egress anywhere in a
#: bundle is enough for CRITICAL.
HARD_SENSITIVE_LABELS = frozenset(
    {
        "~/.ssh",
        "private key file",
        "~/.aws credentials",
        "~/.gnupg",
        "~/.netrc",
        "keychain",
        "~/.claude.json",
        "browser secrets",
        "crypto wallet",
        "shell history",
    }
)

#: Labels that are frequently mentioned in ordinary development content (.env files,
#: token stores, environment dumps). They still pair with egress, but only inside code
#: and only when the two halves are close enough to plausibly be one operation.
SOFT_SENSITIVE_LABELS = frozenset(
    {
        ".env file",
        "credentials file",
        "cloud/CI tokens",
        "printenv dump",
        "env dump",
        "set dump",
        "python environ dump",
        "node env dump",
    }
)

_DATA_SUFFIXES = frozenset(
    {".csv", ".tsv", ".html", ".htm", ".xml", ".svg", ".lock", ".map", ".snap",
     ".log", ".sql", ".po", ".pot", ".rst"}
)


def is_data_file(rel: str) -> bool:
    """Data/asset files: matches inside them are content, not behaviour.

    A CSV of framework best practices contains the word ``fetch(`` and the string
    ``.env`` without doing either. The mismatch rules skip these; the execution rules
    still cover them.
    """
    rel = (rel or "").lower()
    if rel.endswith(".min.js") or rel.endswith(".bundle.js"):
        return True
    return os.path.splitext(rel)[1] in _DATA_SUFFIXES


def find_sensitive(
    text: str,
    *,
    file_rel: str = "",
    file_path: str = "",
    record: Any = None,
    include_env_harvest: bool = True,
) -> List[Hit]:
    table = list(SENSITIVE_PATTERNS)
    if include_env_harvest:
        table = table + ENV_HARVEST_PATTERNS
    return search_text(
        text, table, file_rel=file_rel, file_path=file_path, record=record
    )


def find_sensitive_in_target(
    target: Any, *, include_env_harvest: bool = True, text_only: bool = False
) -> List[Hit]:
    key = (include_env_harvest, text_only)
    cache = getattr(target, "_sensitive_cache", None)
    if cache is not None and cache[0] == key:
        return cache[1]
    table = list(SENSITIVE_PATTERNS)
    if include_env_harvest:
        table = table + ENV_HARVEST_PATTERNS
    hits = search_target(target, table, text_only=text_only)
    try:
        target._sensitive_cache = (key, hits)
    except AttributeError:  # pragma: no cover - non-Target objects
        pass
    return hits


# ---------------------------------------------------------------------------------------
# Shared modifiers
# ---------------------------------------------------------------------------------------

#: Something on this line writes: shell redirection, tee, in-place sed, copy, file open.
#: The redirection branch deliberately requires a non-space character before the ``>``
#: and forbids ``->``/``=>``/``>>``-style arrows, because markdown blockquotes and code
#: arrows would otherwise read as "writes to a file" and turn every document mentioning
#: a settings path into a CRITICAL finding.
WRITE_INDICATOR_RE = re.compile(
    r"(?<=\S)(?<![-=<>|+&$])\s*>>?\s*[\"']?[~/$\w.]|"
    r"(?<![\w-])tee(?:\s+-a)?\s|(?<![\w-])sed\s+-i|"
    r"(?<![\w-])(?:cp|mv|install|ln|rsync)\s+[-\w~./$\"']|"
    r"\bopen\s*\([^)]*[\"'](?:w|a|w\+|a\+|wb|ab)[\"']|"
    r"\bwriteFileSync?\s*\(|\bappendFileSync?\s*\(|\bwrite_text\s*\(|"
    r"\bfs\.(?:write|append|copy|rename)\w*\s*\(|\bshutil\.(?:copy|move)\w*\s*\(|"
    r"\bjson\.dump\s*\(|\bPath\([^)]*\)\.write|"
    r"\bcat\s*>|(?<![\w-])patch\s+-|(?<![\w-])dd\s+of="
)


#: Prose that warns *against* something rather than doing it.
NEGATION_RE = re.compile(
    r"\b(?:never|don'?t|do not|avoid|warning|danger(?:ous)?|caution|beware|"
    r"should not|must not|refuse[sd]?|blocked|forbidden|not recommended|instead of running|"
    r"malicious|attack(?:er|ers)?|exploit|red[- ]team|example of|for example|e\.g\.|"
    r"such as|sample|demo|illustrat\w*|detects?|detection|flags?|flagged|scanner|"
    r"destroys?|destroying|wipes?|irreversible|catastroph\w*|disaster|harmful|"
    r"anti[- ]pattern|bad practice|vulnerab\w*|threat|suspicious|do not run|"
    r"would (?:delete|destroy|wipe|remove))\b",
    re.I,
)

_FENCE_RE = re.compile(r"^\s{0,3}(```+|~~~+)")


def compute_fenced_code_lines(text: str) -> Set[int]:
    """1-based line numbers that sit inside a fenced markdown code block."""
    inside = False
    fence = ""
    result: Set[int] = set()
    for index, line in enumerate(text.split("\n"), start=1):
        match = _FENCE_RE.match(line)
        if match:
            token = match.group(1)
            if not inside:
                inside = True
                fence = token[0] * 3
                continue
            if token.startswith(fence):
                inside = False
                continue
        if inside:
            result.add(index)
    return result


#: Backwards-compatible alias. Prefer ``record.fenced_lines()``, which caches.
fenced_code_lines = compute_fenced_code_lines


_COMMENT_PREFIXES = ("#", "//", "*", "--", ">", "<!--", ";", "%")


def is_comment_line(line: str) -> bool:
    """True when a line is a comment in one of the languages the scanner reads.

    A comment inside a script is prose, not behaviour: it is read by a maintainer, never
    by an interpreter. Treating it as executable is how ``# bypassPermissions is
    unnecessary here`` became a CRITICAL finding on a real machine.
    """
    stripped = line.strip()
    if not stripped:
        return False
    return any(stripped.startswith(prefix) for prefix in _COMMENT_PREFIXES)


def is_warning_context(hit: Hit, *, lookback: int = 2) -> bool:
    """True when a match is prose or a comment that argues *against* the thing matched.

    Security documentation is the single largest source of false positives in a scanner
    like this one: a README that says "never run `curl … | bash`" contains the exact
    bytes of the attack. So for prose files, and for comment lines inside scripts, the
    match plus the two lines above it are checked for negation/warning language, and the
    hit is dropped if any is found. Real payloads do not come with a warning label.
    """
    line = hit.line_text.strip()
    commented = is_comment_line(line)
    if not commented and not is_prose_file(hit.file_rel):
        return False
    if NEGATION_RE.search(hit.line_text):
        return True
    record = hit.record
    if record is None:
        return False
    lines = record.text.split("\n")
    start = max(0, hit.line - 1 - lookback)
    context = "\n".join(lines[start : hit.line])
    return bool(NEGATION_RE.search(context))


_SCRIPT_SUFFIXES = frozenset(
    {".sh", ".bash", ".zsh", ".fish", ".py", ".js", ".mjs", ".cjs", ".ts", ".rb",
     ".pl", ".php", ".ps1", ".bat", ".cmd", ".command", ".make", ".mk"}
)


def is_script_file(rel: str) -> bool:
    suffix = os.path.splitext(rel)[1].lower()
    if suffix in _SCRIPT_SUFFIXES:
        return True
    return os.path.basename(rel).lower() in ("makefile", "dockerfile", "justfile")


def is_prose_file(rel: str) -> bool:
    return os.path.splitext(rel)[1].lower() in (
        ".md",
        ".markdown",
        ".mdx",
        ".txt",
        ".rst",
        ".adoc",
    )


#: Metadata keys carried on a Target (MCP servers, hooks, plugin manifests).
_META_TEXT_KEYS = (
    "description",
    "instructions",
    "systemPrompt",
    "system_prompt",
    "name",
    "title",
    "summary",
    "command",
    "prompt",
    "argument-hint",
)


@dataclass
class MetaField:
    """One piece of metadata the agent loads automatically, without being asked."""

    source: str
    text: str
    file_rel: str = ""
    file_path: str = ""
    line: Optional[int] = None
    record: Any = None


def is_metadata_file(rel: str) -> bool:
    """Files whose contents are loaded into the agent's context as instructions."""
    rel = (rel or "").replace("\\", "/")
    base = os.path.basename(rel).lower()
    return base.endswith(".md") or base.endswith(".markdown")


def is_instruction_record(record: Any) -> bool:
    """True for records the agent loads as directives (role INSTRUCTION, or synthetic).

    This is the surface the metadata rules (HIDDEN_INSTRUCTIONS,
    PROMPT_INJECTION_IN_METADATA, TOOL_SHADOWING) are restricted to. It is narrower than
    "any markdown file": a README that happens to carry a stray zero-width character from
    a copy-paste is documentation, and flagging it HIGH is exactly the noise the README's
    bar forbids. Such hits are recorded as suppressed rather than dropped.
    """
    if record is None:
        return False
    if getattr(record, "synthetic", False):
        return True
    if getattr(record, "is_binary", False):
        return False
    return role_of(record) is FileRole.INSTRUCTION


def _top_level_key(key_path: str) -> str:
    return key_path.split(".", 1)[0].split("[", 1)[0]


def _line_of_field(parsed: Any, key_path: str) -> Optional[int]:
    prefix = key_path
    while prefix:
        line = parsed.key_lines.get(prefix)
        if line is not None:
            return line
        if prefix.endswith("]") and "[" in prefix:
            prefix = prefix.rsplit("[", 1)[0]
        elif "." in prefix:
            prefix = prefix.rsplit(".", 1)[0]
        else:
            break

    top_level = _top_level_key(key_path)
    line = parsed.key_lines.get(top_level)
    if line is not None:
        return line
    if parsed.start_line:
        return parsed.start_line
    return None


def iter_metadata_fields(target: Any) -> List[MetaField]:
    """Collect agent-visible metadata: frontmatter values, MCP descriptions, hook strings.

    Deliberately excludes ordinary documentation prose. A README that *discusses* prompt
    injection (this repository, for instance) must not fire the injection rules; only
    fields loaded into the model's context as authority are inspected.
    """
    try:
        cached = getattr(target, "_malskill_metadata_fields", None)
    except (AttributeError, TypeError):
        cached = None
    if cached is not None:
        return cached

    from malskill import frontmatter as fm

    fields: List[MetaField] = []
    meta = getattr(target, "meta", {}) or {}
    label = getattr(target, "display", str(getattr(target, "name", "")))

    for key in _META_TEXT_KEYS:
        value = meta.get(key)
        if isinstance(value, str) and value.strip():
            fields.append(MetaField(source="meta.%s" % key, text=value))

    for collection_key in ("tools", "toolDescriptions", "prompts", "resources"):
        collection = meta.get(collection_key)
        if not isinstance(collection, list):
            continue
        for index, item in enumerate(collection):
            if isinstance(item, dict):
                for key in ("name", "description", "instructions"):
                    value = item.get(key)
                    if isinstance(value, str) and value.strip():
                        fields.append(
                            MetaField(
                                source="%s[%d].%s" % (collection_key, index, key),
                                text=value,
                            )
                        )
            elif isinstance(item, str) and item.strip():
                fields.append(
                    MetaField(
                        source="%s[%d]" % (collection_key, index), text=item
                    )
                )

    for record in getattr(target, "files", []) or []:
        if not getattr(record, "has_content", False):
            continue
        if getattr(record, "is_binary", False):
            continue
        if getattr(record, "synthetic", False):
            fields.append(
                MetaField(
                    source=record.rel,
                    text=record.text,
                    file_rel=record.rel,
                    file_path=record.path,
                    line=1,
                    record=record,
                )
            )
            continue
        if not is_metadata_file(record.rel) or not is_instruction_record(record):
            continue
        parsed = fm.parse(record.text)
        if not parsed.present or not parsed.ok:
            continue
        observed_fields = 0
        observed_bytes = 0
        capped = False
        for key_path, value in fm.iter_string_values(parsed.data):
            observed_fields += 1
            observed_bytes += len(value.encode("utf-8"))
            if (
                observed_fields > MAX_METADATA_FIELDS_PER_FILE
                or observed_bytes > MAX_METADATA_BYTES_PER_FILE
            ):
                capped = True
            if capped or not value.strip():
                continue
            fields.append(
                MetaField(
                    source="%s frontmatter %s" % (record.rel, key_path),
                    text=value,
                    file_rel=record.rel,
                    file_path=record.path,
                    line=_line_of_field(parsed, key_path),
                    record=record,
                )
            )
        field_cap_hit = observed_fields > MAX_METADATA_FIELDS_PER_FILE
        byte_cap_hit = observed_bytes > MAX_METADATA_BYTES_PER_FILE
        if (field_cap_hit or byte_cap_hit) and getattr(record, "reason", None) is None:
            record.reason = REASON_TOO_LARGE
            if field_cap_hit and byte_cap_hit:
                record.detail = (
                    "frontmatter metadata capped at %d fields and %d bytes "
                    "(file has %d fields and %d metadata bytes); not fully analyzed"
                    % (
                        MAX_METADATA_FIELDS_PER_FILE,
                        MAX_METADATA_BYTES_PER_FILE,
                        observed_fields,
                        observed_bytes,
                    )
                )
            elif field_cap_hit:
                record.detail = (
                    "frontmatter metadata capped at %d fields (file has %d); "
                    "not fully analyzed"
                    % (MAX_METADATA_FIELDS_PER_FILE, observed_fields)
                )
            else:
                record.detail = (
                    "frontmatter metadata capped at %d bytes "
                    "(file has %d metadata bytes); not fully analyzed"
                    % (MAX_METADATA_BYTES_PER_FILE, observed_bytes)
                )

    # Callers only iterate this shared list and must not mutate it.
    try:
        setattr(target, "_malskill_metadata_fields", fields)
    except (AttributeError, TypeError):
        pass
    return fields


def executable_context(hit: Hit) -> bool:
    """True when a hit is in a place that actually runs.

    Scripts, config fragments and hook strings always count. In markdown, only fenced
    code blocks count — otherwise every security note that quotes a command would fire.
    """
    record = hit.record
    rel = hit.file_rel or ""
    if record is not None and getattr(record, "synthetic", False):
        return True
    if is_script_file(rel):
        return True
    if not is_prose_file(rel):
        return True
    if record is None:
        return True
    fenced = getattr(record, "fenced_lines", None)
    if callable(fenced):
        return hit.line in fenced()
    return hit.line in compute_fenced_code_lines(record.text)
