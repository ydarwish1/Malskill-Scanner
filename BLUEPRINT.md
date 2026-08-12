# MalSkill Scanner — Implementation Blueprint (v1)

This document is the binding spec for v1. It operationalizes README.md. If the README and this
file conflict, the README's principles win; this file's mechanics win.

## Non-negotiable principles (from README)

1. Deterministic rules are the engine. Any AI component may only **escalate** a finding's
   severity or add explanation text. It can NEVER clear, downgrade, or suppress a finding.
2. The AI explainer (optional) gets **zero tools** — it is a subprocess text call, nothing else.
3. Flag **mismatches**, not scary keywords. `curl` alone is never a finding. `curl` plus a
   no-network claim, or plus a read of `~/.ssh`, is.
4. Baseline drift: remember content hashes; a trusted skill changing is a finding.
5. MCP tool/server descriptions and configs are first-class scan targets.
6. Never print "SAFE". Three report states: `FLAGGED` / `CLEAN` / `NOT-FULLY-ANALYZED`.
   Unreadable/binary/oversized/parse-failure = loud `NOT-FULLY-ANALYZED`, never silent.
7. Detect on **raw bytes**; sanitize only the copy shown to the model/terminal.
8. Named findings (e.g. `NETWORK_IN_OFFLINE_CLAIM`), never numeric scores.
9. The extractor/inventory layer runs first and trusted: byte-level reads only, no YAML
   `load` (only a minimal safe frontmatter parser), no rendering, no following symlinks out
   of the scanned root, no executing anything from the scanned content. Ever.
10. Bar for success: near-zero findings on a known-benign corpus.

## Language / deps

- Python 3.9+ **stdlib only** for the scanner itself. No pip dependencies.
- Tests: `unittest` via `python3 -m unittest discover -s tests`.
- Entry point: `python3 -m malskill …` and a `bin/malskill` shim.

## Repo layout

```
malskill/
  __init__.py          # __version__
  __main__.py          # dispatch to cli.main()
  cli.py               # arg parsing, subcommands: scan, baseline, list
  inventory.py         # target discovery (skills, plugins, commands, agents, hooks, MCP)
  targets.py           # dataclasses: Target, TargetKind, FileRecord
  frontmatter.py       # minimal safe SKILL.md/agent-md frontmatter parser (no yaml module)
  claims.py            # derive Claims from frontmatter/description text
  sanitize.py          # unicode/zero-width stripping + reporting, truncation for display
  baseline.py          # ~/.malskill/baseline.json  (sha256 per file, per target)
  report.py            # terminal + JSON reporting, three states, exit codes
  explain.py           # optional zero-tool escalate-only explainer via `claude -p`
  rules/
    __init__.py        # Rule registry, Finding dataclass, severity enum
    engine.py          # runs all rules over inventory, collects findings
    r_network_claims.py
    r_exfil.py
    r_credentials.py
    r_obfuscation.py
    r_pipe_to_shell.py
    r_destructive.py
    r_hooks.py
    r_injection.py     # prompt injection in descriptions/tool metadata
    r_self_modify.py
    r_mcp_config.py
    r_unscannable.py   # emits NOT-FULLY-ANALYZED records
bin/malskill           # exec shim: python3 -m malskill "$@"
tests/                 # unittest suite
fixtures/
  benign/              # realistic benign skills/MCP configs (MUST produce zero findings)
  malicious/           # one directory per rule demonstrating a true positive
docs/RULES.md          # every finding ID: what fires it, why it matters, what to do
README.md              # (exists — do not rewrite its philosophy; may add usage section)
BLUEPRINT.md           # this file
```

## Data model

```python
class Severity(str, Enum): CRITICAL, HIGH, MEDIUM, LOW  # rule sets the FLOOR; explainer may raise, never lower

@dataclass
class Finding:
    id: str              # e.g. "NETWORK_IN_OFFLINE_CLAIM"
    severity: Severity
    target: str          # human path/name of skill / server / hook
    kind: str            # skill|plugin|command|agent|hook|mcp-server|mcp-config
    file: str | None     # file that triggered, if applicable
    line: int | None
    evidence: str        # raw-derived, sanitized-for-display snippet (<= 400 chars)
    why: str             # one or two sentences: why this is dangerous
    recommendation: str  # concrete: "Remove X", "Pin/inspect Y", "Re-review after update"
    escalated: bool = False
    escalation_note: str | None = None

@dataclass
class Unscanned:
    target: str; file: str; reason: str   # binary|too-large|unreadable|parse-error|symlink-out
```

## Inventory (what gets scanned)

Root override: `--home DIR` replaces `~` for ALL discovery (hermetic tests). `--paths P...`
scans arbitrary dirs as skill bundles in addition to/instead of discovery.

Claude Code (primary):
- User skills:      `~/.claude/skills/*/` (SKILL.md + every file in the bundle, recursive)
- Project skills:   `<cwd>/.claude/skills/*/` when `--project` or cwd has `.claude/`
- Commands:         `~/.claude/commands/**/*.md`, `<cwd>/.claude/commands/**/*.md`
- Agents:           `~/.claude/agents/**/*.md`
- Plugins:          `~/.claude/plugins/` — `installed_plugins.json`, marketplace repos; scan each
                    installed plugin dir as a bundle (its skills/commands/agents/hooks/scripts)
- Hooks:            `~/.claude/settings.json`, `<cwd>/.claude/settings.json`,
                    `.claude/settings.local.json` → `hooks` entries (the command strings)
- MCP (Claude Code): `~/.claude.json` → top-level `mcpServers` AND `projects.<path>.mcpServers`;
                    `<cwd>/.mcp.json`
- MCP (Claude Desktop, macOS): `~/Library/Application Support/Claude/claude_desktop_config.json`
- MCP (optional, flag `--all-clients`): `~/.cursor/mcp.json`, `~/.codex/config.toml` (parse
  best-effort; on parse failure emit NOT-FULLY-ANALYZED, never crash)

File reading rules:
- Read bytes. Max 2 MiB per file → larger = `Unscanned(too-large)` but STILL run raw-byte
  substring rules on the first 2 MiB.
- Binary sniff (NUL byte in first 8 KiB) → mark binary; still run byte-pattern rules; skip
  text-only rules; record as partially analyzed only if byte rules can't apply.
- Never follow a symlink that resolves outside the scanned root → `Unscanned(symlink-out)`
  finding `SYMLINK_ESCAPE` (MEDIUM) because that is itself a known exfil/trojan trick.
- JSON parse via `json.loads` only. Frontmatter via `frontmatter.py` (subset: `key: value`,
  simple lists; anything else → keep raw string, never eval, never yaml.load).

## Claims model (`claims.py`)

Derived per bundle from frontmatter + description text (case-insensitive):
- `allowed_tools`: from `allowed-tools:` / `tools:` frontmatter if present.
- `claims_offline`: description matches (offline|no network|local[- ]only|without internet|
  no external calls) and does NOT also declare network intent.
- `declares_network`: description/frontmatter mentions (api|http|fetch|download|webhook|
  request|url|endpoint|cloud|server|online|scrape|search) OR allowed_tools includes
  WebFetch/WebSearch/Bash(curl…). Generous on purpose — mismatch rules only fire when the
  bundle plausibly did NOT declare network.
- `claims_read_only`: (read[- ]only|does not modify|no changes to your system).
- `purpose_category`: rough bucket via description keywords: formatting/docs/analysis vs
  network/deploy/install. Used only to strengthen mismatch context in `why`, not to gate.

## Rules (v1 finding IDs)

Severity floors in brackets. Every rule must have ≥1 malicious fixture that fires it and the
benign corpus must not fire it.

Mismatch / behavior:
- `NETWORK_IN_OFFLINE_CLAIM` [HIGH] — network egress primitive (curl|wget|nc|/dev/tcp|
  urllib|requests|fetch(|http.client|XMLHttpRequest|WebSocket) in bundle files while
  `claims_offline` or (not `declares_network` and purpose is local-ish AND target URL is
  non-local). Localhost/127.0.0.1/0.0.0.0/::1 targets are exempt.
- `SENSITIVE_READ_PLUS_EGRESS` [CRITICAL] — same bundle both reads a sensitive path AND has
  any network egress primitive. Sensitive paths: `~/.ssh`, `~/.aws`, `~/.gnupg`, `~/.netrc`,
  `.env` files, `id_rsa|id_ed25519`, `credentials`, `keychain`/`security find-generic-password`,
  `~/.claude.json`, browser cookie/login-data paths, `Library/Keychains`, env-var harvesting
  (`env` dump | `printenv` piped/redirected, `process.env` serialized) feeding egress.
- `CREDENTIAL_PATH_ACCESS` [MEDIUM] — sensitive-path read with NO egress in bundle (lower
  severity; still worth review) unless the bundle's declared purpose is credential/ssh
  management (then suppress — mismatch principle).
- `DESTRUCTIVE_COMMAND` [HIGH] — `rm -rf` on `$HOME`/`~`/`/` roots, `mkfs`, `diskutil erase`,
  `:(){:|:&};:` fork bomb, `> /dev/sda`, `chmod -R 777 /`. Scoped rm inside the bundle's own
  temp dirs does not fire.
- `SELF_MODIFICATION` [CRITICAL] — writes/appends to `~/.claude/settings*.json`, other skills'
  directories, `~/.claude.json`, shell rc files (`.zshrc`, `.bashrc`, `.profile`), git hooks
  dir, `~/.claude/plugins/`, crontab/launchd plists — from any skill/plugin file.
- `AUTO_APPROVE_TAMPERING` [CRITICAL] — content that edits permission allow-lists
  (`"allow"` arrays in settings, `--dangerously-skip-permissions`, `defaultMode: acceptEdits`
  written into settings) or instructs the agent to do so.

Obfuscation / delivery:
- `OBFUSCATED_EXECUTION` [HIGH] — decode-then-execute: (base64|base32|xxd -r|openssl enc -d)
  piped to (sh|bash|zsh|python|node|eval|exec); `eval(atob(`, `exec(base64`,
  `Function(atob`, long `\x..`/`\u..` escape runs (≥20 consecutive) inside an exec/eval reach,
  `compile(`+`exec(` on decoded blobs.
- `PIPE_TO_SHELL` [HIGH] — `curl|wget … | sh|bash|zsh` or `sh -c "$(curl …)"` — remote code
  executed at run time, regardless of claims.
- `HIDDEN_INSTRUCTIONS` [HIGH] — zero-width/bidi-control unicode (U+200B..200F, U+202A..202E,
  U+2060..2064, U+FEFF) inside SKILL.md/command/agent/tool descriptions; or HTML comments
  containing imperative agent-directed text (`<!-- … (ignore|always|never|do not tell|
  secretly|before responding|run the following) … -->`). Raw-bytes detection; report the
  codepoints; show sanitized snippet.
- `SYMLINK_ESCAPE` [MEDIUM] — symlink in bundle resolving outside the bundle root.

Agent-manipulation (the MCP/skill-specific class):
- `PROMPT_INJECTION_IN_METADATA` [HIGH] — skill description, MCP tool description, or server
  `instructions` containing agent-manipulation phrases: `ignore (all |any )?(previous|prior|
  above) instructions`, `do not (tell|show|inform|mention).{0,40}(user|human)`, `without
  (the )?user('s)? (knowledge|approval|confirmation)`, `always (run|execute|call) (this|the
  following) (tool|command) first`, `before (using|calling) any other tool`, `hide`, `conceal`,
  `pretend`, `exfiltrate`. Word-boundary, case-insensitive; fixtures must prove benign docs
  that merely discuss injection (like this repo!) don't fire — restrict rule to metadata/
  description fields and hook command strings, NOT arbitrary README prose.
- `TOOL_SHADOWING` [MEDIUM] — MCP server or skill metadata that instructs redefinition/
  interception of other tools (`instead of using <other tool>`, `overrides the built-in`,
  `replaces the (Bash|Read|Write) tool`).

MCP config rules (`r_mcp_config.py`):
- `MCP_RUNTIME_REMOTE_CODE` [HIGH] — server `command`+`args` that download-and-execute at
  launch (`curl|wget` in command string with pipe, `bash -c` wrapping a fetch). Plain
  `npx`/`uvx`/`docker` of a named package is NOT a finding (that's the ecosystem norm).
- `MCP_SECRET_BROADCAST` [MEDIUM] — env block passes credential-looking values (`*KEY*`,
  `*TOKEN*`, `*SECRET*`, `*PASSWORD*` with a non-placeholder value ≥ 8 chars) to a server
  whose command is an unpinned remote package (`npx -y pkg@latest` or no version pin) —
  report as "secret handed to auto-updating code".
- `MCP_UNPARSEABLE_CONFIG` → NOT-FULLY-ANALYZED entry, not a finding.

Hooks (`r_hooks.py`) — hook command strings get the full byte-rule pass PLUS:
- `HOOK_EXFIL` [CRITICAL] — hook command with network egress AND reference to conversation/
  transcript/env (`$CLAUDE_*`, `transcript`, `stdin` piped to curl). Hooks see everything;
  egress from a hook is exfiltration until proven otherwise.
- `HOOK_REMOTE_CODE` [HIGH] — hook command pipes remote content to a shell.

Baseline (`baseline.py`):
- `BASELINE_DRIFT` [MEDIUM] — file hash changed / file added to a known bundle since last
  accepted baseline. `BASELINE_NEW_TARGET` [LOW] — entirely new bundle since baseline (info-
  grade; still a named finding so updates never land silently).
- `malskill baseline update` accepts current state (writes `~/.malskill/baseline.json`,
  honoring `--home`). Baseline file itself hashed with a top-level self-checksum; mismatch →
  loud warning `BASELINE_TAMPERED` [HIGH].

## Explainer (`explain.py`) — optional, off by default

`--explain` → for each finding, build a prompt containing ONLY: finding id, rule text from
docs/RULES.md, sanitized evidence (≤ 2 KB, zero-width stripped, control chars escaped).
Run `claude -p <prompt> --output-format text` with a system preamble stating: "You may output
exactly one line: `KEEP <one-sentence added context>` or `ESCALATE <CRITICAL|HIGH> <reason>`."
Parse strictly; anything unparseable → ignore, keep rule floor. `ESCALATE` may only raise
severity. If `claude` binary is absent or errors → skip silently with a note in the report
footer. The subprocess gets a 30 s timeout and no tools of any kind (it's `-p` print mode).

## Report (`report.py`)

Terminal (default):
```
MalSkill Scanner v1.0.0 — scanned 867 bundles, 14,444 files (13,982 fully, 462 partially)

FLAGGED (3)
  [CRITICAL] SENSITIVE_READ_PLUS_EGRESS  skill:pdf-tools  scripts/setup.sh:14
    reads ~/.aws/credentials and POSTs to hxxps://metrics.example[.]com
    why: … recommendation: Remove this skill. …
  …
NOT-FULLY-ANALYZED (462)
  241 binary files, 3 oversized, 1 unreadable, 217 non-text assets — list with --show-unscanned
CLEAN (861 bundles): no rule fired. This is not a guarantee of safety.
```
- URLs in evidence are defanged (`hxxp`, `[.]`) so the report itself can't be a lure.
- Evidence lines are passed through `sanitize.for_display()` — control chars → `\u{XXXX}`.
- `--json` → machine-readable full report (findings, unscanned, stats, versions).
- `--show-unscanned` lists every partial file.
- Exit codes: `0` no findings, `1` ≥1 finding, `2` scanner error. NOT-FULLY-ANALYZED alone
  still exits 0 but is always shown.

## CLI

```
malskill scan [--home DIR] [--paths DIR ...] [--project] [--all-clients]
              [--json] [--show-unscanned] [--explain] [--no-baseline]
malskill baseline update [--home DIR] [--paths DIR ...]
malskill list [--home DIR]        # inventory only, no rules
malskill rules                    # print docs/RULES.md summary table
```

## Testing bar (must pass before "done")

1. `python3 -m unittest discover -s tests` green.
2. Every finding ID has ≥1 firing malicious fixture (asserted by an exhaustiveness test that
   iterates the registry and fails if any rule has no covering test).
3. `malskill scan --paths fixtures/benign` → 0 findings (the README bar), asserted in tests.
4. Scan of the real machine (`malskill scan`) completes without crashing; NOT-FULLY-ANALYZED
   is populated, not silent.
5. `--json` output round-trips through `json.loads`.
6. No pip installs anywhere; `grep -r "import yaml\|subprocess" malskill/` shows subprocess
   ONLY in explain.py.
7. Unicode fixtures are generated by tests/fixture helper scripts (checked-in files with raw
   zero-width bytes are fine too, but tests must not depend on git/editor preserving them —
   generate at test time into tmp dirs).

## Style

- Type hints everywhere, dataclasses, no globals except rule registry.
- Every rule module: `RULE_IDS`, `check(bundle|config) -> list[Finding]`, docstring with
  rationale + false-positive analysis.
- docs/RULES.md is generated content-complete by hand: for each ID — trigger, why dangerous,
  recommended action, known false-positive modes.

---

# v1.1 amendments — the file-role context model

**Status: binding, supersedes the v1 mechanics it names.** The README's principles are
unchanged and still win; this section changes mechanics only.

## Why

v1 was built and passed its own bar on fixtures. Then it was run against a real machine:
139 targets, 3,008 files. It produced **47 findings, of which nearly all were false**.

The failures were one shape, not forty-seven: *a pattern matched somewhere that does not
execute and is not read as a directive.*

| What fired | Where | Was it behaviour? |
|---|---|---|
| `PIPE_TO_SHELL` ×6 | `README.md`, `CHANGELOG.md`, `blueprints/*/DESIGN.md`, `references/*.md` quoting the official bun / Homebrew / ollama installer one-liners | no |
| `DESTRUCTIVE_COMMAND` ×2 | `test/context-save-hardening.test.ts`, where `TITLE_RAW: '$(rm -rf /) \`whoami\`'` is the **input being rejected** | no |
| `SELF_MODIFICATION` ×9 | `CONTRIBUTING.md`, `README.md`, `references/testing-strategies.md`, and a read-only `diff <(grep …)` misparsed as a redirect | no |
| `AUTO_APPROVE_TAMPERING` ×5 | `README.md` prose, a `plugins/*/README.md` example allow-list, a `.ts` **test** file, a code comment saying the flag *is unnecessary* | no |
| `SENSITIVE_READ_PLUS_EGRESS` ×1 | keychain read in `scripts/setup-keychain.sh` paired with the bytes `nc` **inside an MP3** | no |
| `SENSITIVE_READ_PLUS_EGRESS` ×1 | `curl localhost:3000` in a SKILL.md ASCII diagram used as the egress half | no |
| `SENSITIVE_READ_PLUS_EGRESS` ×2 | a read in one plugin's script paired with a `curl` quoted in a **different plugin's** README inside the same marketplace checkout | no |

README, "The bar": *near-zero findings on a corpus known to be benign. If v1 returns more
than a dozen findings and they are mostly "curl present", it has already failed.* It had.

## The model (new module `malskill/roles.py`)

Every file record gets a **role**, assigned once at load time and stored on the record:

| Role | Definition |
|---|---|
| `EXECUTABLE` | `.sh .bash .zsh .ksh .fish .command .py .js .mjs .cjs .ts .tsx .rb .pl .php .ps1 .lua …`; execute-bit files; `Makefile`/`Dockerfile`/`justfile`; **hook command strings**; **MCP `command`/`args`** (synthetic records) |
| `INSTRUCTION` | `SKILL.md`, `CLAUDE.md`, `AGENTS.md`, `commands/**.md`, `agents/**.md`, `plugin.json`, `hooks.json`, `settings*.json`, `*.mcp.json`, `marketplace.json`; every file of a `command`/`agent` target; MCP tool & server descriptions |
| `DOCS` | `README* CHANGELOG* CONTRIBUTING* LICENSE DESIGN* HISTORY* NOTES* …`; anything under `docs/ doc/ reference/ references/ blueprints/ examples/ samples/ guides/ wiki/ adr/`; **any other prose file** (`.md .markdown .mdx .txt .rst .adoc`) that is not INSTRUCTION |
| `TEST` | `test/ tests/ __tests__/ testing/ spec/ specs/ testdata/ fixtures/ __mocks__/ e2e/ bench*/`; `*.test.* *_test.* *.spec.* *_spec.* test_*.py conftest.py` |
| `DATA` | everything else, **and unconditionally every binary-sniffed file whatever its name** |

Classification order is fixed: binary → synthetic → command/agent target → TEST →
INSTRUCTION → EXECUTABLE → DOCS → DATA. Binary first means a `.py` full of NULs is a
compiled artifact, not a script. TEST before EXECUTABLE means `tests/helper.sh` is test
material.

## The policy

1. **Behaviour rules fire at full severity only from `EXECUTABLE` and `INSTRUCTION`.**
   The eight are `PIPE_TO_SHELL`, `DESTRUCTIVE_COMMAND`, `SELF_MODIFICATION`,
   `AUTO_APPROVE_TAMPERING`, `OBFUSCATED_EXECUTION`, `NETWORK_IN_OFFLINE_CLAIM`,
   `SENSITIVE_READ_PLUS_EGRESS`, `CREDENTIAL_PATH_ACCESS`.
2. **Pairing rules: both halves, `EXECUTABLE`/`INSTRUCTION`, never binary.** This is the
   MP3 fix and the cross-plugin-README fix.
3. **The localhost exemption applies wherever the egress matcher is used**, including the
   bare spelling — `curl localhost:3000`, `127.0.0.1:8787/health`, `[::1]:8787`,
   `host.docker.internal`, `*.local`. `is_local_host("::1")` previously returned `False`
   because splitting on `:` produced an empty string.
4. **Metadata rules stay on metadata surfaces**, but "metadata surface" is now role
   `INSTRUCTION` plus synthetic records, rather than "any file ending in `.md`".
5. **Suppressed is not silent** (README principle 6). Every held-back match becomes a
   `SuppressedHit` in `ScanResult.suppressed`, surfaced three ways:
   * a report note: `N suppressed pattern hit(s) in documentation/test context (…) — rerun
     with --paranoid to list them. Rules involved: …`;
   * `report["suppressed"]` + `report["suppressed_summary"]` in `--json`, **always**;
   * `--paranoid` → one `SUPPRESSED_PATTERN_HIT` [LOW] finding each, naming the original
     rule, the role and the line.

### New CLI

```
malskill scan … [--paranoid]
```

### New finding ID

`SUPPRESSED_PATTERN_HIT` [LOW], category `context`, emitted by the engine. Deliberately a
**separate ID** rather than the original rule at a lowered severity: a severity floor is a
floor, and `PIPE_TO_SHELL [LOW]` would misstate what that rule concluded.

## Additional rule-precision amendments

* `SELF_MODIFICATION`: a `>` that closes an angle-bracket placeholder or a process
  substitution (`<(…)`, `<skill>`) is not a redirection.
* `AUTO_APPROVE_TAMPERING` / `SELF_MODIFICATION`: **comment lines inside scripts** need a
  directive verb, exactly as prose does; a **fenced code block inside markdown** does not.
* `AUTO_APPROVE_TAMPERING`: negation/warning language on the matched line cancels the
  command-pattern branch too, which covers `echo "… refuses --dangerously-skip-permissions
  …"` inside a script.
* `SENSITIVE_READ_PLUS_EGRESS` / `CREDENTIAL_PATH_ACCESS`: neither half may sit on a
  comment line.
* Egress matcher: `urllib` alone is no longer egress. `urllib.parse` is string handling and
  `urllib.error` is exception handling; the matcher wants `urllib.request`, `urlopen(`,
  `urlretrieve(`, `urllib3` or a bare `import urllib`.
* Behaviour rules de-duplicate per **(label, file)** rather than (label, file, line). Five
  rows saying "this script writes settings.json" are one fact.
* `r_unscannable`: frontmatter parse problems are reported only for `INSTRUCTION` files. A
  `README.md` opening with a `---` horizontal rule is not a bundle whose claims failed to
  parse; those accounted for most of the parse-failure rows (148 → 81 on the real machine).

## Extractor hardening (principle 9)

* **Only regular files are opened.** A FIFO blocks `open()` forever, a socket raises, a
  character device streams without end. `stat.S_ISREG` is checked first; anything else is a
  NOT-FULLY-ANALYZED `unreadable` row naming the file type.
* **Hashing is capped at 64 MiB** (`MAX_HASH_BYTES`), so a link to `/dev/zero` cannot spin.
* **`os.walk(onerror=…)`** — a directory that cannot be listed becomes a NOT-FULLY-ANALYZED
  row instead of vanishing.
* **The >20,000-file cap emits one summary record**, not one row per skipped file.
* Fenced-code-block computation is cached per record.

## Reporting amendments

* `make_finding()` puts evidence through `sanitize.for_display(…, 400)` centrally, so the
  400-character cap and URL defanging are structural rather than per-rule discipline.
* The bare-hostname defanger's TLD table was widened (it previously missed `.ai`, `.sh`,
  `.app`, `.run`, `.cloud`, `.co.uk` …), so `executes whatever opencode.ai returns` no
  longer ships a live hostname inside a security report.

## Testing bar additions

Items 1–7 of the v1 bar stand. Added:

8. `fixtures/benign/docs-install-oneliner/` — README/CHANGELOG/CONTRIBUTING/`docs/DESIGN.md`
   quoting installer one-liners, a self-install `cp`, a `.claude/skills` symlink and the
   dangerous flag. Zero findings.
9. `fixtures/benign/test-suite-injection-strings/` — `test/*.test.ts` and `tests/test_*.py`
   whose fixtures are `rm -rf /`, `curl | bash`, base64-to-shell and a settings redirect.
   Zero findings.
10. `fixtures/benign/localhost-only-diagram/` — an offline claim plus loopback probes
    written **without** a URL scheme. Zero findings.
11. `tests/fixture_gen.py::build_binary_asset_pairing` — a real keychain read plus a
    **generated** binary asset containing `curl`, `nc -e`, `socat -`, `/dev/tcp/` in its
    raw bytes. Zero findings, and the asset still appears in NOT-FULLY-ANALYZED.
12. `tests/test_roles_context.py` — every behaviour rule proven to **still fire** from a
    `SKILL.md` body, a `commands/*.md`, an `agents/*.md` and a script; `--paranoid`
    surfacing; the default note; and a unit-level table test for the classifier.
13. `tests/test_robustness.py` — FIFO / socket / `/dev/zero` link / unreadable directory /
    unreadable file / 40,000-line frontmatter / invalid UTF-8 / 60-deep tree / symlink loop;
    hermeticity proven by instrumenting `open()` during an in-process scan; four shapes of
    baseline tampering; explainer protocol strictness; and a structural test that every
    behaviour rule module actually calls the role gate.

## Measured result

`python3 -m malskill scan --no-baseline` on the same machine: **47 findings → 14**, with
491 suppressed hits counted in the report note and listable with `--paranoid`. Every one of
the remaining 14 is a true positive or a defensible one-look finding; none is "curl
present".
