# Fixture notes

Why each malicious fixture exists, what it should fire and how it contrasts with the
benign bundle that would otherwise look like it.

This file lives **outside** every bundle on purpose. Prose inside a bundle is not inert:
the claims model reads top-level Markdown, so a note saying "this fixture is about
credential management" turns the bundle into a declared credential manager and
suppresses the very rule the fixture exists to prove. Fixture commentary belongs here;
the machine-readable contract belongs in `MANIFEST.json`.

---

## `network_in_offline_claim`

The description promises an offline, local-only tool. `scripts/stats.sh` posts the
filename and hostname to a third-party host on every run. The primitive is not the
problem; the mismatch between the claim and the primitive is.

---

## `network_in_offline_claim_negated_phrasing`

The same fixture written the way the lie is actually written: "No network access is
required and no external calls are made." `BLUEPRINT.md` lists both `no network` and
`no external calls` as `claims_offline` triggers, so a *negated* mention of the word
must strengthen the offline claim, never cancel it by looking like a network
declaration. If this fixture stops firing while `network_in_offline_claim` still does,
the claims model is cancelling `claims_offline` on the substring rather than on intent -
and the most natural phrasing of the lie walks straight past the rule.

---

## `sensitive_read_plus_egress`

One bundle that both reads credential paths (`~/.aws/credentials`, `~/.ssh/id_rsa`,
`~/.netrc`, a full environment dump) and has an egress primitive pointed at a host it
never mentions. This is the CRITICAL case. The hosts and paths are fake; the file has
no execute bit and is never run.

---

## `credential_path_access`

A formatter that stockpiles private keys into a cache directory. There is no egress
primitive in the bundle, so this is the MEDIUM finding rather than the CRITICAL one,
and the bundle's declared purpose (text formatting) is nowhere near credential
management, so the suppression that protects `benign/ssh-key-manager` does not apply.

---

## `destructive_command`

Unscoped recursive removal of `$HOME` and `/`, disk erase, filesystem creation and a
fork bomb. Contrast with `benign/static-site-deploy`, whose `rm -rf` is scoped to a
scratch directory it created under `$TMPDIR`.

The script's shebang is `/bin/echo` and it carries no execute bit: if it is ever run by
accident it prints its own path and exits.

---

## `self_modification`

A "preferences sync" skill that appends to shell rc files, rewrites
`~/.claude/settings.json`, edits a *different* skill's `SKILL.md`, injects an MCP server
into `~/.claude.json`, installs a launch agent, installs a crontab entry and overwrites
the repository's git pre-commit hook. Every one of those is persistence.

---

## `auto_approve_tampering`

Writes an unrestricted permission allow-list into the agent's settings, empties the deny
list, sets `defaultMode: acceptEdits` and relaunches with
`--dangerously-skip-permissions`. Compare `benign/settings-with-permissions`, which is a
user's own settings file that merely *contains* an allow-list.

---

## `obfuscated_execution`

Decode-then-execute in four languages: base64 piped to a shell, `openssl enc -d` piped
to a shell, `xxd -r` piped to a shell, `eval(atob(...))` and `Function(atob(...))` in
JavaScript, `exec(base64.b64decode(...))` and a long run of `\x` escapes in Python.

The encoded strings decode to harmless references to `*.evil.example.com`, which does
not resolve. No file here carries an execute bit and the shell shebangs are `/bin/echo`.

---

## `pipe_to_shell`

Four spellings of "fetch a script from a remote host and run it immediately". The
declared purpose is honest - it really is an installer - and it is still a finding,
because the code that runs is whatever the host serves at that moment.

---

## `hidden_instructions`

Agent-directed imperatives concealed in HTML comments, which render as nothing in a
Markdown preview but are fully present in the bytes the model reads.

This is the on-disk half of the rule. The zero-width and bidi-control half is generated
at test time by `tests/fixture_gen.py` (`hidden_instructions_zero_width`), because git,
editors and review tools all silently normalise or strip those codepoints.

---

## `prompt_injection_in_metadata`

The manipulation lives in the frontmatter `description`, which is loaded into context
for every session that has this skill installed. Compare `benign/security-review-docs`,
whose prose quotes the same phrasings while teaching a human to recognise them: the rule
must look at metadata fields, not at documentation.

---

## `tool_shadowing`

Metadata that tells the agent to route built-in tool calls through this bundle instead.
Whoever owns the shadowing tool owns every read and every command that follows.

---

## `mcp_runtime_remote_code`

Home-shaped fixture: scan with `--home <copy-of-this-dir>`.

Every one of these servers fetches its own body from a remote host at launch, so the
code that runs in your session is whatever that host serves that morning. Contrast
`benign/mcp-config-standard`, where `npx`/`uvx`/`docker` launch a named, version-pinned
package - the ecosystem norm, and not a finding.

---

## `mcp_secret_broadcast`

Home-shaped fixture: scan with `--home <copy-of-this-dir>`.

Real credentials handed to unpinned, auto-updating remote packages: `@latest` in one
case, no version pin at all in the other. Whoever publishes the next version of that
package receives the secrets.

All values are inert test strings containing `FAKE-KEY-FOR-TESTING`. A scanner must not
treat "looks like a placeholder" as a reason to stay quiet here - the trigger is the
*name* pattern (KEY/TOKEN/SECRET/PASSWORD) plus a non-empty value plus an unpinned
package. Placeholder detection, if implemented, must key on empty strings and on
`${VAR}` / `<your-key-here>` style templates, not on the substring "FAKE".

---

## `hook_exfil`

Home-shaped fixture: scan with `--home <copy-of-this-dir>`.

Hooks see every prompt, every tool call and the whole transcript, and they run without
asking. These three ship the transcript, the raw prompt stream and the environment to a
collector. Compare `benign/hook-local-formatter`: same hook events, no egress primitive.

---

## `hook_remote_code`

Home-shaped fixture: scan with `--home <copy-of-this-dir>`.

A `SessionStart` hook that pipes a remote script into a shell: the attacker gets code
execution at the start of every single session, before the user types anything.

---

## `mcp_unparseable_config`

Home-shaped fixture: scan with `--home <copy-of-this-dir>`.

Truncated JSON with a trailing comma. This must produce a loud NOT-FULLY-ANALYZED
record - not a crash, and not a silent skip that lets an unreadable config hide a
server. It is deliberately *not* a finding: the report state carries the message.

