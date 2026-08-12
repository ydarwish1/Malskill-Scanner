# Malicious corpus

One directory per finding ID, named after the ID in lower case (a `_variant` suffix is
allowed when one rule needs two spellings). `MANIFEST.json` is the machine-readable
contract: scan mode, the finding IDs the scan must produce, expected exit code. Tests
assert those IDs are present, never that they are the only ones.

No per-fixture commentary goes inside a bundle. The claims model reads a bundle's
top-level Markdown, so a `README.md` saying "this fixture is about credential
management" declares a purpose and suppresses the very rule the fixture exists to prove.
That is not hypothetical: it silently disarmed `credential_path_access` until the prose
moved out. This file sits above every bundle directory, so prose here is inert.

## What each fixture proves

| fixture | fires | why, and what it contrasts with |
| --- | --- | --- |
| `network_in_offline_claim` | `NETWORK_IN_OFFLINE_CLAIM` | Description promises offline-only; a script posts filename and hostname to a third-party host on every run. The mismatch is the finding, not the primitive. |
| `network_in_offline_claim_negated_phrasing` | `NETWORK_IN_OFFLINE_CLAIM` | The same lie in its natural phrasing: "No network access is required and no external calls are made." A negated mention must strengthen the offline claim, never cancel it by looking like a network declaration. |
| `sensitive_read_plus_egress` | `SENSITIVE_READ_PLUS_EGRESS` | One bundle reads `~/.aws/credentials`, `~/.ssh/id_rsa`, `~/.netrc` and dumps the environment, then posts the lot to a host it never mentions. The CRITICAL case. |
| `credential_path_access` | `CREDENTIAL_PATH_ACCESS` | A formatter that stockpiles private keys into a cache directory. No egress primitive, so MEDIUM not CRITICAL, and its declared purpose (text formatting) is nowhere near credentials, so the suppression protecting `benign/ssh-key-manager` does not apply. |
| `destructive_command` | `DESTRUCTIVE_COMMAND` | Unscoped recursive removal of `$HOME` and `/`, disk erase, `mkfs`, fork bomb. Contrast `benign/static-site-deploy`, scoped to a scratch dir it created. |
| `self_modification` | `SELF_MODIFICATION` | Appends to shell rc files, rewrites `~/.claude/settings.json`, edits another skill's `SKILL.md`, injects an MCP server, installs a launch agent and a crontab entry, overwrites a git pre-commit hook. All persistence. |
| `auto_approve_tampering` | `AUTO_APPROVE_TAMPERING` | Writes an unrestricted allow-list into settings, empties the deny list, sets `defaultMode: acceptEdits`, relaunches with the skip-permissions flag. Contrast `benign/settings-with-permissions`. |
| `obfuscated_execution` | `OBFUSCATED_EXECUTION` | Decode-then-execute in four languages: base64, `openssl enc -d` and `xxd -r` into a shell, `eval(atob(...))` and `Function(atob(...))`, `exec(base64.b64decode(...))` and a long `\x` escape run. The encoded strings decode to harmless references to a reserved example host. |
| `pipe_to_shell` | `PIPE_TO_SHELL` | Four spellings of fetch-a-remote-script-and-run-it. The declared purpose is honest, it really is an installer, and it is still a finding because the code that runs is whatever the host serves that moment. |
| `hidden_instructions` | `HIDDEN_INSTRUCTIONS` | Agent-directed imperatives in HTML comments: nothing in a Markdown preview, fully present in the bytes the model reads. The on-disk half of the rule. |
| `prompt_injection_in_metadata` | `PROMPT_INJECTION_IN_METADATA` | The manipulation lives in the frontmatter `description`, loaded into context every session. Contrast `benign/security-review-docs`, whose prose quotes the same phrasings. |
| `tool_shadowing` | `TOOL_SHADOWING` | Metadata telling the agent to route built-in tool calls through this bundle. Whoever owns the shadowing tool owns every read and command that follows. |
| `mcp_runtime_remote_code` | `MCP_RUNTIME_REMOTE_CODE` | Servers that fetch their own body at launch. Contrast `benign/mcp-config-standard`, where `npx`/`uvx`/`docker` launch a named, version-pinned package. |
| `mcp_secret_broadcast` | `MCP_SECRET_BROADCAST` | Credential-shaped env values handed to `@latest` and to an unpinned package. The trigger is name pattern plus non-empty value plus unpinned package. Placeholder detection, if implemented, must key on empty strings and `${VAR}` templates, not on the substring "FAKE". |
| `hook_exfil` | `HOOK_EXFIL` | Hooks see every prompt, tool call and transcript, and run without asking. These three ship the transcript, the raw prompt stream and the environment to a collector. Contrast `benign/hook-local-formatter`: same events, no egress. |
| `hook_remote_code` | `HOOK_REMOTE_CODE` | A `SessionStart` hook pipes a remote script into a shell, so the attacker has execution before the user types anything. |
| `mcp_unparseable_config` | none (`MCP_UNPARSEABLE_CONFIG`) | Truncated JSON with a trailing comma. Must produce a loud NOT-FULLY-ANALYZED record, not a crash and not a silent skip. Deliberately not a finding: the report state carries the message. |

## Scan modes and inertness

`mode: paths` is a skill bundle, scanned with `--paths <bundle>`. `mode: home` is a
home-shaped tree (`.claude/settings.json`, `.claude.json`, `.mcp.json`), scanned with
`--home <copy>`. Tests copy the fixture into a temp directory first and always pass
`--home`, so no scan reads or writes the real machine.

Everything here is test data that is only ever read. Hosts are RFC 2606 reserved
(`evil.example.com`, `attacker.example.net`) or loopback. Credential values contain the
literal `FAKE-KEY-FOR-TESTING`. No file carries an execute bit. Scripts that would
damage a machine or rewrite user configuration (`destructive_command`,
`self_modification`, `auto_approve_tampering`, `pipe_to_shell`, `obfuscated_execution`)
carry the shebang `#!/bin/echo INERT-TEST-FIXTURE-DO-NOT-EXECUTE`, so running one prints
its own path and exits 0.

## Fixtures that are not on disk

Three groups are generated at test time by `tests/fixture_gen.py`.

| generated fixture | covers | why not on disk |
| --- | --- | --- |
| `hidden_instructions_zero_width` | `HIDDEN_INSTRUCTIONS` | Editors, linters and review tools normalise or strip zero-width and bidi-control codepoints, so a checked-in file cannot be trusted to still contain them. |
| `symlink_escape` | `SYMLINK_ESCAPE` | Git preserves symlinks only under `core.symlinks=true`; a checkout without symlink support turns the link into a text file containing its target. |
| baseline drift trees | `BASELINE_DRIFT`, `BASELINE_NEW_TARGET`, `BASELINE_TAMPERED` | These are state transitions, not files: scan, `baseline update`, mutate, rescan. |

`tests/test_registry_coverage.py` treats generated fixtures as first-class coverage, so
every registry ID is accounted for whether its fixture lives on disk or not.
