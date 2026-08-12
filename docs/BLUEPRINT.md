# Design

How the scanner is built and why. The README covers what it does; docs/RULES.md covers
each finding. This file is the spec the tests are written against.

## Principles

1. Deterministic rules decide. The optional AI explainer can only raise a severity or add
   context, never clear a finding. Otherwise a malicious bundle argues its way out.
2. The explainer gets no tools. If it gets tricked, it cannot act on it.
3. Flag contradictions, not keywords. `curl` alone is never a finding.
4. Hash every file so a trusted skill going bad in an update gets caught.
5. MCP tool and server descriptions load into every session and nobody reads them, so scan
   them too.
6. Never claim something is safe. Three states: FLAGGED, CLEAN, NOT-FULLY-ANALYZED. A file
   that could not be read is listed, not dropped.
7. Detect on raw bytes. Sanitize only the copy shown to a human or the model, or the
   obfuscation gets hidden from the thing judging it.
8. Name findings, do not score them. `NETWORK_IN_OFFLINE_CLAIM` is actionable, "47" is not.
9. The inventory layer runs first and trusted, so it stays small: byte reads, a minimal
   frontmatter parser, `json.loads`, no yaml module, no rendering, no symlinks out of the
   scanned root, nothing from a scanned bundle ever executed.
10. Near-zero findings on known-benign content, or the human learns to skim and the one
    real finding scrolls past.

## Constraints

Python 3.9+, standard library only. `subprocess` appears in `explain.py` and nowhere else,
which a test enforces. Tests are `unittest`. Entry points are `python3 -m malskill` and the
`bin/malskill` shim.

## Layout

```
malskill/
  cli.py          scan / baseline / list / rules
  inventory.py    discovery and byte-level file loading
  targets.py      Target, FileRecord dataclasses
  roles.py        file role classification (no package imports, so it cannot cycle)
  frontmatter.py  minimal safe parser, no yaml
  claims.py       what a bundle says about itself
  sanitize.py     invisible codepoints, URL defanging, display truncation
  baseline.py     ~/.malskill/baseline.json, self-checksummed
  report.py       three states, terminal and JSON
  explain.py      zero-tool escalate-only explainer
  rules/
    engine.py     runs rules, applies role policy, collects findings
    patterns.py   shared matchers, so rules agree on what egress means
    r_*.py        one module per rule family
```

## What gets scanned

User and project skills, commands and agents. Installed plugins and their bundles. Hook
command strings in `settings.json`. MCP servers from `~/.claude.json`, project `.mcp.json`
and Claude Desktop, plus Cursor and others behind `--all-clients`.

`--home DIR` redirects all home-based discovery and the baseline path, which is how tests
stay hermetic. `--paths DIR` scans specific bundles instead of discovery, and a directory
of directories becomes one bundle per subdirectory so one skill's secret read cannot pair
with another skill's `curl`.

Reading rules: 2 MiB cap per file, then the first 2 MiB still gets byte rules. A NUL in the
first 8 KiB means binary. Symlinks resolving outside the bundle are a finding, not a
traversal. Vendor directories (`node_modules`, `.venv`, `.git`, caches) are skipped and
announced as unscanned rather than skipped silently.

## File roles

Where a pattern lives decides whether it is behavior. Each file gets one role at load time.

| Role | What it is |
| --- | --- |
| EXECUTABLE | scripts by extension, execute-bit files, Makefile and Dockerfile, hook command strings, MCP command and args |
| INSTRUCTION | SKILL.md, CLAUDE.md, AGENTS.md, commands and agents, plugin.json, hooks.json, settings files, MCP tool and server descriptions |
| DOCS | README, CHANGELOG, CONTRIBUTING, DESIGN, anything under docs/ or reference/, other prose |
| TEST | test and spec directories, `*.test.*`, `test_*.py` and similar |
| DATA | everything else, and every binary file whatever its name |

Order is fixed: binary, then synthetic records, then command and agent targets, then TEST,
INSTRUCTION, EXECUTABLE, DOCS, DATA. Binary first means a `.py` full of NULs is a compiled
artifact. TEST before EXECUTABLE means `tests/helper.sh` is test material.

Policy:

- Behavior rules fire at full severity only from EXECUTABLE and INSTRUCTION.
- Pairing rules need both halves from EXECUTABLE or INSTRUCTION, never from a binary, never
  from a comment line.
- The localhost exemption applies wherever egress is matched, including bare forms like
  `curl localhost:3000` and `[::1]:8787`.
- Metadata rules stay on INSTRUCTION files and synthetic records, not on every `.md`.
- Suppressed is not silent. Every held-back match becomes a `SuppressedHit`, counted in the
  report note, always present in `--json`, and listed as `SUPPRESSED_PATTERN_HIT` (LOW)
  under `--paranoid`. It is a separate ID rather than the original rule at a lower
  severity, because a floor is a floor and `PIPE_TO_SHELL [LOW]` would misstate what that
  rule concluded.

## Data model

```python
class Severity(str, Enum):   # rule sets the floor; the explainer may raise, never lower
    CRITICAL, HIGH, MEDIUM, LOW

@dataclass
class Finding:
    id: str            # NETWORK_IN_OFFLINE_CLAIM
    severity: Severity
    target: str        # skill:pdf-tools
    kind: str          # skill | plugin | command | agent | hook | mcp-server | mcp-config
    file: str | None
    line: int | None
    evidence: str      # derived from raw bytes, sanitized for display, <= 400 chars
    why: str
    recommendation: str
    escalated: bool = False

@dataclass
class Unscanned:
    target: str; file: str; reason: str   # binary | too-large | unreadable | parse-error | symlink-out
```

## Claims

Derived per bundle from frontmatter and description text: declared tools, whether it claims
to be offline, whether it declares network use, whether it claims to be read-only, and a
rough purpose category. The network claim is read generously, so mismatch rules only fire
when a bundle plausibly did not declare the behavior it contains.

## Explainer

Off by default. With `--explain`, each finding becomes a prompt containing only the finding
ID, the rule text, and sanitized evidence under 2 KB. It runs as `claude -p` with a 30
second timeout and may reply with one line: `KEEP <context>` or `ESCALATE <level> <reason>`.
Anything unparseable is ignored and the rule floor stands. A missing `claude` binary is a
footer note, not an error.

## Report

Terminal output groups findings by severity, then lists NOT-FULLY-ANALYZED counts, then the
CLEAN count with the explicit caveat that no rule fired is not a guarantee. URLs are
defanged (`hxxps://`, `[.]`) so the report cannot itself be a lure. `--json` carries
findings, unscanned records, suppressed hits and stats. Exit codes: 0 none, 1 findings,
2 scanner error. Unscanned records alone still exit 0 and are still shown.

## Testing bar

- The full suite passes.
- Every registry ID has a fixture that fires it, enforced by an exhaustiveness test.
- `scan --paths fixtures/benign` returns zero findings.
- A scan of a real machine completes without crashing and reports what it could not read.
- `--json` round-trips through `json.loads`.
- No pip installs; `subprocess` only in `explain.py`; no yaml import anywhere.
- Fixtures that depend on zero-width unicode, symlinks or state transitions are generated
  at test time rather than checked in.

## Known limit

A payload can sit in a README while a SKILL.md tells the agent to go read it. Version 1
does not follow that reference hop, so the payload keeps the DOCS role and stays a
suppressed hit. This is stated in docs/RULES.md rather than papered over.
