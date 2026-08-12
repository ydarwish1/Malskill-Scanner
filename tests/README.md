# MalSkill Scanner — test suite

```bash
python3 -m unittest discover -s tests            # everything
python3 -m unittest discover -s tests -v         # with test names
python3 -m unittest discover -s tests -k benign  # one slice
python3 -m unittest tests.test_baseline          # (also works: python3 tests/test_baseline.py)
```

Stdlib only, no pip installs, no plugins, Python 3.9+. `tests/` deliberately has no
`__init__.py`, so `discover -s tests` puts this directory on `sys.path` and the modules
import each other by bare name (`import harness`); each test module also inserts its own
directory into `sys.path` so a single-file run works too.

---

## What each file is for

| file | responsibility |
| --- | --- |
| `harness.py` | subprocess runner, JSON report accessors, fixture copying. No tests. |
| `fixture_gen.py` | fixtures that cannot survive a git checkout, built at test time. No tests. |
| `test_benign_zero_findings.py` | the README bar: a known-benign corpus produces **zero** findings. |
| `test_malicious_each_rule.py` | parameterised over every fixture: the named rule must fire. |
| `test_baseline.py` | drift / new-target / tampering, driven as state transitions. |
| `test_report_json.py` | three report states, `--json` round-trip, defanging, exit codes, never "SAFE". |
| `test_cli.py` | `--help`, `rules`, `list`, exit codes, `bin/malskill` shim. |
| `test_registry_coverage.py` | the exhaustiveness gate: every ID in `REGISTRY` has a covering fixture. |
| `test_explainer_escalate_only.py` | the AI may only escalate — never clear, downgrade or drop a finding (in-process, no `claude` binary needed). |
| `test_hygiene.py` | no yaml, `subprocess` only in `explain.py`, stdlib-only imports; plus corpus inertness. |

---

## Hermeticity: nothing touches the real machine

Every invocation goes through `harness.run_malskill()`, which:

* runs `python3 -m malskill …` as a **subprocess** with `PYTHONPATH` set to the repo root;
* runs it with `cwd` set to an **empty scratch directory**, so no `.claude/` project
  discovery can ever pick up this repository or the developer's files (fixtures that
  need project-level discovery get `cwd` set to their own copied temp tree instead);
* **refuses to run** `scan`, `baseline` or `list` unless `--home` is present — a test-suite
  bug that would otherwise scan the developer's real `~/.claude` fails loudly instead;
* strips `CLAUDE*` variables from the environment.

`test_baseline.py::test_baseline_never_touches_the_real_home` asserts after the fact that
`~/.malskill` was neither created nor modified.

Fixtures are always **copied into a temp directory** before being scanned (the one
exception is the whole-corpus read-only scan of `fixtures/benign`), so a scan that writes
cannot corrupt the checked-in corpus.

---

## Fixture conventions

```
fixtures/
  benign/     MANIFEST.json + one directory per bundle   → must produce ZERO findings
  malicious/  MANIFEST.json + one directory per finding ID → must produce that finding
```

* **Directory name = finding ID, lower-cased.** `fixtures/malicious/pipe_to_shell/` proves
  `PIPE_TO_SHELL`. Asserted by `test_manifest_matches_the_directories_on_disk`.
* **`MANIFEST.json` is the contract.** Both manifests are validated against the directory
  listing, so a fixture cannot be added without being declared, or declared without
  existing. A `_variant` suffix on the directory name is allowed when one rule needs two
  spellings (`network_in_offline_claim_negated_phrasing`).
* **No fixture commentary inside a bundle.** Per-fixture prose lives in
  `fixtures/{benign,malicious}/NOTES.md`, outside every bundle. The claims model reads a
  bundle's top-level Markdown, so a `README.md` explaining that "this fixture is about
  credential management" declares a credential-management purpose and suppresses the rule
  the fixture exists to prove. That happened; the notes were moved out.

Malicious manifest entry:

```json
{
  "name": "hook_exfil",
  "mode": "home",                       // "paths" | "home"
  "expect_findings": ["HOOK_EXFIL"],    // asserted PRESENT, never exclusive
  "expect_exit": 1,                     // 0 none, 1 findings, 2 scanner error
  "expect_unscanned": false,            // require >=1 NOT-FULLY-ANALYZED record
  "covers": ["..."],                    // registry-coverage claim; defaults to expect_findings
  "likely_incidental": ["..."],         // documentation only, never asserted
  "note": "one sentence for the human"
}
```

Two fixture shapes:

* `mode: "paths"` — a skill bundle. Scanned as `scan --home <empty temp home> --paths <bundle>`.
* `mode: "home"` — a home-shaped tree (`.claude/settings.json`, `.claude.json`, `.mcp.json`,
  `.claude/plugins/…`). Copied to a temp dir and scanned as `scan --home <copy>` with `cwd`
  set to the copy, which also exercises project-level `.mcp.json` discovery.

Every non-baseline scan passes `--no-baseline`, so a first-run baseline can never
contaminate a rule assertion. `test_baseline.py` is the only file that lets the baseline
run.

### Presence, not exclusivity

Malicious fixtures assert that the named ID is **among** the findings. A bundle that reads
`~/.aws/credentials` and POSTs the result inherently trips more than one rule, and a
scanner that reported only the "primary" one would be hiding evidence. Expected
side-findings are recorded in `likely_incidental` for the reader and are never asserted.

### Inertness

Enforced by `test_hygiene.py::CorpusHygieneTests`:

* hosts are RFC 2606 reserved (`evil.example.com`, `attacker.example.net`) or loopback —
  a URL pointing anywhere else fails the suite;
* credential-shaped values all contain the literal `FAKE-KEY-FOR-TESTING`;
* **no fixture file carries an execute bit**;
* fixtures whose content would damage a machine or rewrite user configuration carry the
  shebang `#!/bin/echo INERT-TEST-FIXTURE-DO-NOT-EXECUTE`, so running one prints its own
  path and exits 0;
* no fixture contains the token `SAFE`, so the "never print SAFE" assertions cannot be
  satisfied or defeated by echoed fixture content.

The scanner only ever reads bytes. Nothing in `fixtures/` is executed by the suite.

---

## Why some fixtures are generated at runtime

`tests/fixture_gen.py` builds three groups into temp directories instead of checking them
in. Each has a reason it *cannot* be trusted on disk:

1. **`hidden_instructions_zero_width` → `HIDDEN_INSTRUCTIONS`.** The payload is
   U+200B/U+200C/U+200D/U+2060/U+2063/U+FEFF and bidi overrides. Editors strip them,
   linters strip them, review tools render them invisible, and copy-paste loses them. A
   checked-in file that "contains" U+200B is a file that *might*; a fixture that might not
   fire is worse than no fixture. The builder writes the bytes and asserts they are still
   there before any scan. (The HTML-comment half of the same rule *is* checked in, at
   `fixtures/malicious/hidden_instructions/`, because it is plain ASCII.)
2. **`symlink_escape` → `SYMLINK_ESCAPE`.** Symlinks survive only with `core.symlinks=true`
   on a filesystem that supports them; a Windows checkout or a zip export silently turns
   the link into a text file containing its target path, and the fixture stops testing
   anything. Both link targets are generated inside the temp tree, so even following one
   by accident reads nothing that matters.
3. **`BASELINE_DRIFT` / `BASELINE_NEW_TARGET` / `BASELINE_TAMPERED`.** These are not files,
   they are state transitions: scan → `baseline update` → mutate the tree (or edit
   `baseline.json`) → rescan → assert. There is nothing to check in.

`fixture_gen.generated_coverage()` reports what those cover, and
`test_registry_coverage.py` treats it as first-class coverage, so the exhaustiveness gate
passes only when *every* registry ID is proven by something — on disk or generated.

---

## The JSON contract these tests assume

`BLUEPRINT.md` specifies the fields but not the exact envelope, so `harness.py` reads the
report through tolerant accessors. The shape below is what the suite expects; anything
else produces one legible failure naming the keys it looked for, instead of forty
`KeyError`s.

```jsonc
{
  "version": "1.0.0",
  "status": "FLAGGED",          // or "CLEAN" | "NOT-FULLY-ANALYZED"; also accepted: "state"
  "findings": [                 // also accepted: "flagged"
    {
      "id": "PIPE_TO_SHELL",    // SCREAMING_SNAKE_CASE, never a score
      "severity": "HIGH",       // == the registry floor unless --explain escalated it
      "target": "skill:toolchain-installer",
      "kind": "skill",
      "file": "scripts/install.sh",
      "line": 6,
      "evidence": "...",        // <= 400 chars, defanged (no live http:// or https://)
      "why": "...",
      "recommendation": "...",
      "escalated": false
    }
  ],
  "unscanned": [                // also accepted: "not_fully_analyzed"
    {"target": "...", "file": "assets/catalog.txt", "reason": "too-large"}
  ],
  "stats": {"bundles": 3, "files": 12, "clean_bundles": 1}   // must expose a CLEAN count
}
```

Accepted aliases are listed in `harness.py` next to each accessor. Three requirements are
hard, not tolerant:

* the three states must all be observable (`findings`, `unscanned`, and *some* CLEAN
  indicator — a `*clean*` key anywhere, or `targets[].status == "CLEAN"`);
* every `*status*`/`*state*` string in the document must be one of the three states —
  `SAFE` fails the suite, and so does a fourth invented state;
* evidence and terminal output must not contain a live URL (`hxxps`/`[.]` defanging), and
  must not reproduce raw zero-width codepoints.

---

## Deliberate false-positive traps in `fixtures/benign/`

These exist to break a keyword scanner. If one of them starts failing, the fix belongs in
the rule, not in the fixture.

| bundle | trap |
| --- | --- |
| `api-weather-fetch` | uses `curl`, and declares network use in the description **and** `allowed-tools` |
| `ssh-key-manager` | reads `~/.ssh`, and credential management is its declared purpose |
| `security-review-docs` | README prose quotes injection phrasings verbatim while teaching a reviewer to spot them |
| `static-site-deploy` | `rm -rf "$TMPDIR/build"` — recursive delete scoped to a scratch dir it created |
| `localhost-metrics` | claims "no external calls" **and** uses `curl` — every target is loopback |
| `mcp-config-standard` | `npx -y @scope/server@1.2.3`, `uvx pkg==0.4.1`, pinned container: the ecosystem norm |
| `hook-local-formatter` | a hook that shells out to a local formatter, with no egress primitive |
| `settings-with-permissions` | a user's own settings file legitimately *contains* `permissions.allow` |
| `plugin-home` | an installed marketplace plugin with a skill, a command and a local hook |
| `home-user-skills` | ordinary user skills, commands and agents |
| `markdown-table-formatter` | the control: nothing interesting at all |

Two of these are worth calling out to whoever integrates the rules:

* **`security-review-docs`** proves `PROMPT_INJECTION_IN_METADATA` is scoped to metadata
  fields (frontmatter `description`, MCP tool descriptions, server `instructions`, hook
  command strings) and not to arbitrary prose. This repository's own docs would fail a
  broader rule.
* **`settings-with-permissions`** proves `AUTO_APPROVE_TAMPERING` fires on *bundle content
  that writes* an allow-list, not on a settings file that has one. The broader reading
  flags every real machine on day one.

The whole-corpus scan (`scan --paths fixtures/benign`, the literal command from the
blueprint's testing bar) additionally requires the scanner to treat each subdirectory as
its own bundle: the corpus deliberately puts the credential-reading bundle and the
network-using bundle in *separate* directories, and merging them into one logical bundle
would manufacture a cross-bundle `SENSITIVE_READ_PLUS_EGRESS` that does not exist.

---

## Failure policy

There is no skip-on-ImportError anywhere. If `malskill/` is absent or incomplete, the
suite is **red**, and that is the intended signal — the tests are written against
`BLUEPRINT.md`, not against whatever happens to be implemented. Likewise `docs/RULES.md`
and `bin/malskill` are asserted to exist, because the blueprint requires them.
