# Fixture notes

What each benign bundle is a trap for. Kept **outside** the bundles: the claims model
reads top-level Markdown, so commentary inside a bundle would do the scanner's work for
it (a note saying "this is a credential manager" is itself a declaration of purpose).
The bundles carry only the kind of README a real skill would ship.

---

## `api-weather-fetch`

Uses `curl` and declares that use twice over: in the frontmatter `description` and in `allowed-tools`. `curl` appears in 284 of 867 bundles on a real machine; the primitive alone is never a finding.

---

## `ssh-key-manager`

Reads the SSH configuration directory, and credential management is its declared purpose, so `CREDENTIAL_PATH_ACCESS` is suppressed by the mismatch principle. There is no egress primitive anywhere in the bundle, so the CRITICAL rule cannot apply either. A scanner that flags this has learned "scary path" instead of "mismatch".

---

## `security-review-docs`

Its prose quotes attacker phrasings verbatim while teaching a reviewer to recognise them. `PROMPT_INJECTION_IN_METADATA` must be scoped to metadata fields - frontmatter `description`, MCP tool descriptions, server `instructions`, hook command strings - and not to README prose. A broader rule flags every security document ever written, including this repository's own.

---

## `static-site-deploy`

Contains `rm -rf` twice, both scoped to a scratch directory the script itself created under `$TMPDIR`. Scoped cleanup is ordinary build hygiene, not a destructive command.

---

## `localhost-metrics`

Claims to run locally *and* uses `curl`. Both are true: every target is the loopback interface, which the network-mismatch rule exempts by construction.

---

## `markdown-table-formatter`

The control. No network, no credentials, no shell. If this ever produces a finding, the engine is broken.

---

## `mcp-config-standard`

Home-shaped. `npx -y @scope/pkg@1.2.3`, `uvx pkg==0.4.1`, a pinned container image and a project-scoped server. Package managers launching a named, version-pinned package are the ecosystem norm and must not fire `MCP_RUNTIME_REMOTE_CODE`. No credential-shaped value appears in any env block.

---

## `hook-local-formatter`

Home-shaped. A `PostToolUse` hook that shells out to a local formatter. Hook command strings get the full byte-rule pass, and this one contains no egress primitive, so it stays clean even though it references `$CLAUDE_PROJECT_DIR`.

---

## `settings-with-permissions`

Home-shaped. A user's own settings file legitimately contains a `permissions.allow` array. `AUTO_APPROVE_TAMPERING` fires on bundle content that *writes* an allow-list into settings, never on a settings file that merely has one - the broader reading flags every real machine on day one.

---

## `plugin-home`

Home-shaped. An installed marketplace plugin with a skill, a slash command and a local hook. Plugin discovery must not itself manufacture findings; the marketplace URL is a repository reference, not an egress primitive.

---

## `home-user-skills`

Home-shaped. Exercises user-level discovery of `~/.claude/skills`, `~/.claude/commands` and `~/.claude/agents` with entirely ordinary content.

---

## `docs-install-oneliner`

The v1.1 regression for the largest single source of false positives measured on a real
machine. `README.md` and `CHANGELOG.md` quote the official `curl -fsSL … | bash` installer
and the Homebrew `/bin/bash -c "$(curl …)"` form; `docs/DESIGN.md` describes somebody
else's download page including its literal install command; `CONTRIBUTING.md` shows both
`ln -sfn … .claude/skills/…` and `cp SKILL.md ~/.claude/skills/…`, and mentions
`--dangerously-skip-permissions` in passing.

None of it is behaviour. Documentation is role `DOCS`, and behaviour rules fire only from
`EXECUTABLE` and `INSTRUCTION`. The matches are still counted: run with `--paranoid` and
every one of them appears as a `SUPPRESSED_PATTERN_HIT` [LOW].

---

## `test-suite-injection-strings`

Injection-hardening tests whose *input fixtures* are the dangerous commands - the whole
point of such a test being that the command is rejected, never run. Covers both directory
spellings (`test/`, `tests/`) and both filename spellings (`*.test.ts`, `test_*.py`), and
carries `$(rm -rf /)`, `rm -rf $HOME`, `curl … | bash`, `echo … | base64 -d | sh`,
`launchctl load …`, `cp … ~/.claude/skills/…` and `--dangerously-skip-permissions`.

A scanner that flags these flags every security test suite on the machine.

---

## `localhost-only-diagram`

Claims to work offline and genuinely does contact HTTP endpoints - all of them loopback,
and most written **without** a URL scheme: `curl localhost:3000`, `curl 127.0.0.1:8787/health`,
`curl '[::1]:8787/health'`. That spelling is the trap. The blueprint exempts loopback
destinations, but a host matcher that only understands `scheme://host` sees no destination
at all and treats "unknown" as external - which is how a diagram line in a SKILL.md became
the egress half of a CRITICAL exfiltration pairing on a real machine.
