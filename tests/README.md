# Test suite

```bash
python3 -m unittest discover -s tests            # everything (add -v for test names)
python3 -m unittest discover -s tests -k benign  # one slice
python3 -m unittest tests.test_baseline          # one module
```

Stdlib only, no pip installs, Python 3.9+. `tests/` deliberately has no `__init__.py`, so `discover -s
tests` puts this directory on `sys.path` and the modules import each other by bare name (`import
harness`). Each module also adds its own directory, so single-file runs work.

## What each file covers

| file | responsibility |
| --- | --- |
| `harness.py` | subprocess runner, JSON report accessors, fixture copying. No tests. |
| `fixture_gen.py` | fixtures that cannot survive a git checkout, built at test time. No tests. |
| `test_benign_zero_findings.py` | the bar: a known-benign corpus produces zero findings. |
| `test_malicious_each_rule.py` | parameterised over every fixture, the named rule must fire. |
| `test_baseline.py` | drift, new target and tampering, driven as state transitions. |
| `test_report_json.py` | three report states, `--json` round-trip, defanging, exit codes, never "SAFE". |
| `test_cli.py` | `--help`, `rules`, `list`, exit codes, the `bin/malskill` shim. |
| `test_registry_coverage.py` | exhaustiveness gate: every ID in `REGISTRY` has a covering fixture. |
| `test_explainer_escalate_only.py` | the AI may only escalate, never clear, downgrade or drop a finding. |
| `test_hygiene.py` | no yaml, `subprocess` only in `explain.py`, stdlib-only imports, corpus inertness. |

## Hermeticity

Everything runs through `harness.run_malskill()`: `python3 -m malskill` in a subprocess, `PYTHONPATH`
at the repo root, `cwd` an empty scratch dir so no `.claude/` project discovery reaches this
repository, `CLAUDE*` stripped. It refuses `scan`, `baseline` and `list` without `--home`, so a
suite bug cannot scan the real `~/.claude`. Fixtures are copied to a temp dir first (the exception
is the read-only whole-corpus scan of `fixtures/benign`), and `test_baseline.py` checks afterwards
that `~/.malskill` was never created or modified.

## Fixture conventions

`fixtures/benign/` holds one directory per bundle and must produce zero findings. `fixtures/malicious/`
holds one directory per finding ID and must produce that finding, the directory named after the ID
lower-cased (`pipe_to_shell/` proves `PIPE_TO_SHELL`, and a `_variant` suffix is allowed when one rule
needs two spellings). `MANIFEST.json` is the contract, validated against the directory listing, so a
fixture cannot be added without being declared or declared without existing. Each entry has a name, a
mode, `expect_findings`, `expect_exit` and a note, all documented in the two manifests.

Findings are asserted present, not exclusive: a bundle that reads `~/.aws/credentials` and posts the
result trips more than one rule, and expected side-findings go in `likely_incidental`. `mode: "paths"`
is a skill bundle; `mode: "home"` is a home-shaped tree, scanned with `cwd` set to the copy so
project-level `.mcp.json` discovery runs too. Every non-baseline scan passes `--no-baseline`.

Per-fixture commentary never lives inside a bundle. The claims model reads a bundle's top-level
Markdown, so a note saying "this fixture is about credential management" declares a purpose and
suppresses the rule the fixture proves. That prose lives one level up, in the two corpus READMEs.

Inertness is enforced by `test_hygiene.py::CorpusHygieneTests`: hosts are RFC 2606 reserved
(`evil.example.com`, `attacker.example.net`) or loopback and anything else fails the suite,
credential-shaped values contain the literal `FAKE-KEY-FOR-TESTING`, no fixture file has an execute
bit, anything that would damage a machine carries the shebang `#!/bin/echo
INERT-TEST-FIXTURE-DO-NOT-EXECUTE`, and no fixture contains the token `SAFE`, so echoed fixture
content cannot defeat the "never print SAFE" assertions.

## The JSON contract

`docs/BLUEPRINT.md` specifies the fields but not the exact envelope, so `harness.py` reads
the report through tolerant accessors, each listing the aliases it accepts.

```json
{"status": "FLAGGED",
 "findings": [{"id": "PIPE_TO_SHELL", "severity": "HIGH", "target": "skill:installer",
               "file": "scripts/install.sh", "line": 6, "evidence": "..."}],
 "unscanned": [{"file": "assets/catalog.txt", "reason": "too-large"}],
 "stats": {"bundles": 3, "clean_bundles": 1}}
```

Three requirements are hard rather than tolerant: all three states observable (`findings`, `unscanned`,
and a `*clean*` key or `targets[].status == "CLEAN"`); every status string one of the three, so `SAFE`
or a fourth invented state fails; no live URL and no raw zero-width codepoint in output.

## Why three fixture groups are generated at runtime

`tests/fixture_gen.py` builds them into temp directories because none can be trusted on disk.
`hidden_instructions_zero_width` carries zero-width and bidi-control codepoints that editors, linters
and copy-paste all strip, so the builder writes the bytes and asserts they survived (the HTML-comment
half of the rule is checked in, being ASCII). `symlink_escape` needs a real symlink, which survives
only with `core.symlinks=true` on a filesystem that supports it. `BASELINE_DRIFT`,
`BASELINE_NEW_TARGET` and `BASELINE_TAMPERED` are state transitions, not files: scan, `baseline
update`, mutate, rescan, assert. `test_registry_coverage.py` counts `fixture_gen.generated_coverage()`
as first-class coverage, so the gate passes only when every registry ID is proven by something.

## Deliberate false-positive traps in fixtures/benign

Each bundle breaks a keyword scanner a different way; longer notes in `fixtures/benign/README.md`. If
a row starts failing, the fix belongs in the rule, not the fixture.

| bundle | trap |
| --- | --- |
| `api-weather-fetch` | uses `curl`, and declares network use in the description and `allowed-tools` |
| `ssh-key-manager` | reads `~/.ssh`, and credential management is its declared purpose |
| `security-review-docs` | prose quotes injection phrasings while teaching a reviewer to spot them |
| `static-site-deploy` | recursive delete scoped to a scratch dir the script created |
| `localhost-metrics` | claims "no external calls" and uses `curl`, every target loopback |
| `localhost-only-diagram` | loopback endpoints written with no URL scheme, `[::1]:8787` and friends |
| `docs-install-oneliner` | docs quote the official installer one-liners; `--paranoid` shows them as LOW |
| `test-suite-injection-strings` | injection tests whose input fixtures are the dangerous commands |
| `mcp-config-standard` | version-pinned `npx`/`uvx`/container servers, the ecosystem norm |
| `hook-local-formatter` | a hook shelling out to a local formatter, no egress primitive |
| `settings-with-permissions` | a user's own settings file that legitimately has `permissions.allow` |
| `plugin-home`, `home-user-skills` | an installed marketplace plugin, and ordinary user skills, commands and agents |
| `markdown-table-formatter` | the control: nothing interesting at all |

## Failure policy

No skip-on-ImportError anywhere. If `malskill/` is absent or incomplete the suite is red, which is the
intended signal: the tests are written against `docs/BLUEPRINT.md`, not against what happens to be
implemented. `docs/RULES.md` and `bin/malskill` are asserted to exist for the same reason.
