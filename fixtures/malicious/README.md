# Malicious corpus

One directory per finding ID, named after the ID in lower case (a `_variant` suffix is
allowed when one rule needs two spellings). `MANIFEST.json` is the machine-readable
contract: for each fixture, the scan mode and the finding IDs that scan must produce.
`NOTES.md` is the human half - why each fixture exists and which benign bundle it
contrasts with.

**No fixture commentary lives inside a bundle.** The claims model reads a bundle's
top-level Markdown, so a `README.md` explaining that "this fixture is about credential
management" turns the bundle into a declared credential manager and suppresses the very
rule the fixture exists to prove. That is not hypothetical: it silently disarmed
`credential_path_access` until the prose was moved out to `NOTES.md`.

## Inertness

Everything here is test data that is only ever *read*:

- Hosts are `evil.example.com` / `attacker.example.net` (RFC 2606 reserved; they do not
  resolve).
- Credential values are the literal string `FAKE-KEY-FOR-TESTING` plus filler.
- No file carries an execute bit.
- Scripts whose contents would damage a machine or rewrite user configuration
  (`destructive_command`, `self_modification`, `auto_approve_tampering`,
  `pipe_to_shell`, `obfuscated_execution`) carry the shebang
  `#!/bin/echo INERT-TEST-FIXTURE-DO-NOT-EXECUTE`, so running one prints its own path
  and exits 0.
- The scanner reads bytes. It never executes anything from a scanned bundle.

## Scan modes

- `mode: paths` - a skill bundle; scanned with `--paths <bundle>`.
- `mode: home` - a home-shaped tree (`.claude/settings.json`, `.claude.json`,
  `.mcp.json`); copied to a temp directory and scanned with `--home <copy>`.

Tests always copy the fixture into a temp directory first and always pass `--home`, so
no scan ever reads or writes the real machine's configuration.

## Fixtures that are NOT on disk

Three groups are generated at test time by `tests/fixture_gen.py`:

| generated fixture | covers | why not on disk |
| --- | --- | --- |
| `hidden_instructions_zero_width` | `HIDDEN_INSTRUCTIONS` | git, editors and review tools normalise or strip zero-width and bidi-control codepoints; a checked-in file cannot be trusted to still contain them |
| `symlink_escape` | `SYMLINK_ESCAPE` | git only preserves symlinks under `core.symlinks=true`, and a checkout on a filesystem without symlink support silently turns the link into a text file |
| baseline drift trees | `BASELINE_DRIFT`, `BASELINE_NEW_TARGET`, `BASELINE_TAMPERED` | these are state transitions, not files: scan, `baseline update`, mutate, rescan |

`tests/test_registry_coverage.py` treats the generated fixtures as first-class coverage,
so every ID in the registry is accounted for whether its fixture lives on disk or not.
