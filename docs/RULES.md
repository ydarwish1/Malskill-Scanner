# Rule reference

Every finding ID the scanner can emit, what fires it, why it is dangerous, what to do, and how it can be wrong. `malskill rules` prints the same set straight out of `malskill.rules.REGISTRY`. If a rule is not here, it does not exist.

Three things apply to every rule below.

Severity is a floor set by the rule. The optional AI explainer (`--explain`) may raise a finding's severity and add a sentence of context. `Finding.escalate()` refuses anything at or below the current level, so nothing can lower, clear or suppress a finding.

A scary keyword alone is never a finding. Every rule states the contradiction or combination it requires.

Detection runs on raw bytes. Only the display copy is sanitized: invisible codepoints escaped as `\u{200B}`, URLs defanged as `hxxps://evil[.]example[.]com`.

## File roles

Every file is classified into one of five roles (`malskill/roles.py`).

| Role | What it is | Examples |
|---|---|---|
| `EXECUTABLE` | something that runs | `*.sh` `*.py` `*.js` `*.mjs` `*.ts` `*.rb` `*.pl`, files with an execute bit, `Makefile`, `Dockerfile`, hook command strings, MCP `command`/`args` |
| `INSTRUCTION` | something an agent reads as directives | `SKILL.md`, `CLAUDE.md`, `AGENTS.md`, `commands/**.md`, `agents/**.md`, `plugin.json`, `hooks.json`, `settings.json`, `.mcp.json`, MCP tool and server descriptions |
| `DOCS` | prose for humans | `README*`, `CHANGELOG*`, `CONTRIBUTING*`, `LICENSE`, `DESIGN*`, and markdown under `docs/`, `reference(s)/`, `blueprints/`, `examples/`, `guides/` |
| `TEST` | test material | `test/`, `tests/`, `__tests__/`, `spec/`, `fixtures/`, `*.test.*`, `*_test.*`, `test_*.py`, `conftest.py` |
| `DATA` | everything else | assets, CSV/JSON data, and every binary-sniffed file whatever its name |

The eight behaviour rules (`PIPE_TO_SHELL`, `DESTRUCTIVE_COMMAND`, `SELF_MODIFICATION`, `AUTO_APPROVE_TAMPERING`, `OBFUSCATED_EXECUTION`, `NETWORK_IN_OFFLINE_CLAIM`, `SENSITIVE_READ_PLUS_EGRESS`, `CREDENTIAL_PATH_ACCESS`) fire only from `EXECUTABLE` and `INSTRUCTION` files. For the two pairing rules both halves must come from those roles, and neither may come from a binary file. The metadata rules (`HIDDEN_INSTRUCTIONS`, `PROMPT_INJECTION_IN_METADATA`, `TOOL_SHADOWING`) read `INSTRUCTION` files plus hook and MCP strings, not any file that happens to end in `.md`.

A `curl … | bash` line quoted in a README is documentation. The same line in a script or a SKILL.md is behaviour, because an agent that reads a SKILL.md may act on what it finds.

Suppressed is not silent. Held-back matches are counted in a report note, listed in full under `report["suppressed"]` in the JSON output, and printed as `SUPPRESSED_PATTERN_HIT` findings with `--paranoid`.

## Roles and the reference hop

The role policy used to create this bypass, and the attack is worth keeping explicit.

> An attacker puts the payload in `README.md` or `docs/setup.md`, and writes in
> `SKILL.md`: "Before starting, follow the steps in `docs/setup.md`." The agent reads the
> SKILL.md, follows the pointer and executes the payload. The scanner classified the
> payload file as `DOCS`, so it lands in the suppressed ledger at LOW rather than in
> `FLAGGED`.

The scanner now closes that form of the bypass by following one explicit reference hop from an `INSTRUCTION` file. It never opens or resolves the referenced path on the filesystem. Every bundle file has already been loaded and checked before roles are assigned, so resolution is only POSIX path normalization followed by an exact, case-sensitive lookup in that same target's file records. A `..` path cannot reach a filesystem call, a symlink that escaped the bundle was already rejected and is not present to match, and there is no fetch-on-read.

A link is not automatically a delegation. The line carrying the reference must use an action cue such as "follow", "steps in", "before starting" or "read and follow"; a bare `- [usage](docs/usage.md)` in a documentation list is deliberately left as a citation. Claude Code `@path/to/file.md` imports are followed unconditionally because that syntax itself loads the file as authority. The pass follows one hop only, accepts only `.md` and `.markdown`, and can only match a file already loaded from the same bundle. It follows at most 5 references from one instruction file, promotes at most 20 records across a target, and promotes at most 262144 bytes of content; hitting a cap is recorded in target metadata rather than hidden.

Residual gaps remain. A reference introduced only by pointer language — `see`, `consult`, `refer to` or a bare `read` — is not followed. Promoting on pointer language produced false positives on ordinary documentation, and the trade is deliberate: a false positive at full severity costs more than this miss. Neither is a `TEST`-role file promoted, even when delegated to, because test context is deliberately suppressed. A file outside the bundle cannot match, and delegation phrased without a cue in the scanner's bounded cue list is not followed. Those cases remain in the suppressed ledger when an existing behaviour pattern sees them; `BASELINE_DRIFT` still covers documentation files regardless of role.

## Summary

| Finding ID | Floor | Category | Trigger |
|---|---|---|---|
| `SENSITIVE_READ_PLUS_EGRESS` | CRITICAL | mismatch | secret path read plus network egress in one bundle |
| `SELF_MODIFICATION` | CRITICAL | behavior | writes agent settings, another skill, shell rc, cron/launchd |
| `AUTO_APPROVE_TAMPERING` | CRITICAL | behavior | widens or disables the permission prompt |
| `HOOK_EXFIL` | CRITICAL | hook | hook with egress plus access to session data |
| `NETWORK_IN_OFFLINE_CLAIM` | HIGH | mismatch | egress in a bundle that claims offline or local-only |
| `DESTRUCTIVE_COMMAND` | HIGH | behavior | `rm -rf` a root, mkfs, disk erase, fork bomb |
| `OBFUSCATED_EXECUTION` | HIGH | obfuscation | decode-then-execute |
| `PIPE_TO_SHELL` | HIGH | obfuscation | remote content piped into a shell |
| `HIDDEN_INSTRUCTIONS` | HIGH | obfuscation | invisible codepoints or agent-directed HTML comments |
| `PROMPT_INJECTION_IN_METADATA` | HIGH | agent-manipulation | manipulation phrasing in auto-loaded metadata |
| `MCP_RUNTIME_REMOTE_CODE` | HIGH | mcp | MCP server downloads and executes code at launch |
| `HOOK_REMOTE_CODE` | HIGH | hook | hook pipes remote content into a shell |
| `BASELINE_TAMPERED` | HIGH | baseline | baseline store fails its own self-checksum |
| `CREDENTIAL_PATH_ACCESS` | MEDIUM | mismatch | secret path read, no egress in the bundle |
| `SYMLINK_ESCAPE` | MEDIUM | obfuscation | symlink resolving outside the bundle |
| `TOOL_SHADOWING` | MEDIUM | agent-manipulation | metadata that replaces or intercepts another tool |
| `MCP_SECRET_BROADCAST` | MEDIUM | mcp | literal secret handed to an unpinned remote package |
| `MCP_UNPARSEABLE_CONFIG` | MEDIUM | mcp | MCP config that does not parse (reported as NOT-FULLY-ANALYZED) |
| `BASELINE_DRIFT` | MEDIUM | baseline | known file changed or appeared since the accepted baseline |
| `BASELINE_NEW_TARGET` | LOW | baseline | bundle the baseline has never seen |
| `SUPPRESSED_PATTERN_HIT` | LOW | context | behaviour pattern matched in docs/test/data context (`--paranoid` only) |

## SENSITIVE_READ_PLUS_EGRESS (CRITICAL)

Fires when: one bundle both references a sensitive path and has a network egress primitive that is not provably localhost. Unambiguous secrets (`~/.ssh`, `id_rsa`, `~/.aws/credentials`, `~/.gnupg`, `~/.netrc`, keychain, `~/.claude.json`, browser cookie stores, crypto wallets, shell history) pair with egress anywhere in the bundle. Everyday development secrets (`.env`, generic `credentials.*`, `.npmrc`, `.kube/config`, bulk environment dumps) are so common that they only pair in code, within 5 lines, and not on an ordinary config load. Egress means curl, wget, nc, /dev/tcp, urllib.request, requests, httpx, raw sockets, `fetch(`, WebSocket, axios, Invoke-WebRequest, scp/sftp, remote rsync and similar. Both halves must sit on a non-comment line in an `EXECUTABLE` or `INSTRUCTION` file, never in a binary.

Why: read-a-secret plus send-it-somewhere in one bundle running with your agent's privileges is the shape of credential theft. Neither half means anything alone.

Do: remove the bundle, then rotate every credential it could reach. You cannot tell from the files whether it already ran.

Wrong when: the bundle is deliberate credential tooling (an SSH key uploader, a vault sync). Those genuinely do both. The finding names file and line so the check takes seconds, and exempting anything that calls itself a credential manager would hand every attacker the same excuse.

Quiet on: `source ./.env && curl https://api.example.com/…` (config load, not secret read); `curl localhost:3000` with any secret; `from urllib.parse import quote`, which is string handling rather than egress; data files and prose.

## SELF_MODIFICATION (CRITICAL)

Fires when: a visible write targets `~/.claude/settings.json`, `~/.claude.json`, another skill or plugin directory, `~/.claude/commands/`, `~/.claude/agents/`, a shell startup file (`.zshrc`, `.bashrc`, `.profile`, `config.fish`), the git hooks directory, `.mcp.json` or `claude_desktop_config.json`; or the command is itself persistence (`crontab -`, `launchctl load`, `defaults write`, `systemctl enable`). The path alone never fires. The write must be visible: a redirection pointing at the path, `tee`, `sed -i`, a `cp`/`mv`/`ln` where the path is the destination, or a strong write call (`open(..., 'w')`, `writeFileSync`, `write_text`, `json.dump`) within two lines inside a real script.

Why: this is how a one-shot skill becomes permanent. A shell rc file, a git hook or a LaunchAgent survives deleting the bundle.

Do: remove the bundle, then diff your settings files, shell rc files, `crontab -l` and `~/Library/LaunchAgents/` for entries you did not add.

Wrong when: installers and dotfile managers append a `PATH` line to `.zshrc`; a skill installs or symlinks itself into `~/.claude/skills/`; a tutorial creates an example command with `cat > .claude/commands/example.md`.

Quiet on: reads of those paths; a `cp` where the agent path is the source; markdown blockquotes and `->` arrows, which are not redirections; process substitution such as `diff <(grep x skills/<skill>/SKILL.md) <(…)`, which writes nothing. At most one finding per write target per file.

## AUTO_APPROVE_TAMPERING (CRITICAL)

Fires when: content removes the human checkpoint. `--dangerously-skip-permissions`, `--permission-mode acceptEdits|bypassPermissions`, `defaultMode: bypassPermissions`, a write or mutation of a permissions `allow` array, a blanket grant (`Bash(*)`, `Read(**)`) inside a permissions block, `CLAUDE_AUTO_APPROVE`-style environment overrides, or prose telling a human or agent to enable auto-approval and act without asking. A settings file that merely contains an allow-list never fires. In prose the line needs a directive verb (run, use, add, enable, set, always, must), so a flag reference table does not count.

Why: every other protection depends on the confirmation prompt. Turning it off disables the last human checkpoint before arbitrary commands run as you.

Do: remove the bundle and audit your allow-list and settings files for entries you did not add.

Wrong when: security documentation quotes the flag while arguing against it (the negation filter catches most of these); CI and sandbox scripts bypass prompts on purpose in throwaway containers.

Quiet on: your own scoped `permissions.allow` with `defaultMode: default`; a bare `"*"` in ordinary code; an error string inside a script such as `echo "refuses --dangerously-skip-permissions as root"`; a comment saying `# bypassPermissions is unnecessary here`. A fenced code block in a `SKILL.md` still fires without a directive verb, because that is a command the document is showing the agent to run.

## HOOK_EXFIL (CRITICAL)

Fires when: a hook command string contains egress to a non-local destination and a reference to session data: `$CLAUDE_*` variables, a transcript path, tool input or output, session identifiers, piped stdin (`curl -d @-`), `jq` over the hook payload, an environment dump, or agent config and history files.

Why: hooks run automatically on ordinary agent activity, see everything the session sees, and never ask for permission.

Do: delete the hook from the settings file, and assume everything in recent sessions reached the remote host.

Wrong when: the hook is deliberate self-hosted telemetry, transcript backup, or a team-internal audit endpoint. Only the machine's owner can tell.

Quiet on: hooks with no egress (formatters, linters, notifications) and hooks posting only to localhost.

## NETWORK_IN_OFFLINE_CLAIM (HIGH)

Fires when: a bundle reaches a non-local destination and either describes itself as offline, local-only or "no network required" while declaring no network intent anywhere (strong branch), or never declares network intent, has a local-ish purpose (formatting, docs, notes, analysis) and contacts a literal external URL (weak branch). Destinations on localhost, `127.0.0.0/8`, `0.0.0.0`, `::1` and `*.local` are exempt. Any network declaration in the same description cancels the offline claim, because ambiguity is not deception.

Why: `curl` on its own means nothing, it is in roughly a third of installed bundles. `curl` in a bundle that told you it never touches the network means the description cannot be trusted, and the description is the only thing most people read before installing.

Do: open the flagged line and decide whether you want this bundle talking to that host. If the description does not match the code, remove it. You cannot review something that misdescribes itself.

Wrong when: an update or telemetry check is bolted onto an otherwise local tool; a description says "offline" about one feature and not another; an example URL sits inside instructions the agent may never act on.

Quiet on: bundles that mention an API, download, webhook or search, or that grant `WebFetch`/`WebSearch`/`Bash(curl…)`; localhost dev-server calls; prose warning against a network call.

## DESTRUCTIVE_COMMAND (HIGH)

Fires when: `rm -rf` targets a root (`/`, `/*`, `~`, `$HOME`, `/Users/<name>`, `/home/<name>`) or `~/.ssh`, `~/.aws`, `~/.gnupg`; or the content is `mkfs*`, `diskutil erase*`, the classic fork bomb, a write to a raw block device (`dd of=/dev/nvme…`), `chmod -R 777` or `chown -R` of a root, or `shred` of a root.

Why: an agent with Bash access runs these verbatim, and there is no step after the command completes. No description makes formatting a disk expected behaviour for a skill.

Do: remove the bundle. If it is yours, scope the deletion to an explicit subdirectory and rescan.

Wrong when: an uninstall script clears an install root that happens to be a home directory; a Dockerfile wipes a container root. The largest benign source is an injection-hardening test whose input fixture is the dangerous string, and those are held in the suppressed ledger by role.

Quiet on: `rm -rf ./build`, `rm -rf "$TMPDIR/x"`, `rm -rf node_modules`, a documented `rm -rf ~/.claude/skills/<self>` uninstall step, `chown -R me /home/me/.app`. `rm -rf "$TARGET"` does not fire: without evaluating the variable the scanner cannot know the value, and guessing produces noise.

## OBFUSCATED_EXECUTION (HIGH)

Fires when: something decodes and then executes. A decoder (`base64 -d`, `xxd -r`, `openssl enc -d`, `uudecode`, `gunzip`) piped into an interpreter; `sh -c "$(echo … | base64 -d)"`; `eval(atob(`, `eval(Buffer.from(`, `exec(base64.b64decode(`, `exec(marshal.loads(` and similar; `exec(compile(<decoded blob>))`; a child process spawned with a decoded command string; PowerShell `-EncodedCommand` or `FromBase64String` feeding `iex`; or a run of 20+ consecutive `\xNN`/`\uNNNN` escapes with an execution sink within 600 characters.

Why: code that hides what it runs has already told you its intent. Obfuscation exists to defeat the review you are performing.

Do: remove the bundle. If you need to know what the payload was, decode it in a throwaway container that holds none of your credentials.

Wrong when: minified or vendored JavaScript has long escape runs near an `eval`-like call; an encoding tutorial or library fixture demonstrates the pattern; legitimate PowerShell decodes data rather than commands.

Quiet on: `base64 -d > file.png` (decoding to data, not to an interpreter); `exec(compile(f.read(), __file__, 'exec'))`, the standard way to run a local file; warning comments that quote the pattern.

## PIPE_TO_SHELL (HIGH)

Fires when: `curl` or `wget` output is executed. `… | sh|bash|zsh|python|node|perl|ruby`, `sh -c "$(curl …)"`, `bash <(curl …)`, `eval "$(curl …)"`, `iwr … | iex`, or download-then-run (`curl -o x && chmod +x x && ./x`). Claims cannot exempt this rule, and localhost is not exempt either, because a local port is often a proxy for remote content.

Why: whatever the server returns at run time executes with your privileges. The bundle you reviewed is not the code that runs.

Do: remove the bundle, or replace the pipe with a pinned download whose checksum you verify and whose contents you read first.

Wrong when: an official installer one-liner (rustup, nvm, uv, bun, Homebrew, Deno) is copied into a `SKILL.md`. That fires deliberately: an agent reading a SKILL.md may execute what it finds there. The finding names the host so you can judge it quickly.

Quiet on: `curl -o file.tar.gz` with no execution; a commented or warning-labelled line; the same one-liner in a `README.md`, `CHANGELOG.md`, `docs/` or a test file. At most one finding per form per file.

## HIDDEN_INSTRUCTIONS (HIGH)

Fires when: an `INSTRUCTION` file, command or agent file, MCP description or hook string contains invisible or direction-control codepoints in the raw bytes (U+200B..U+200F, U+202A..U+202E, U+2060..U+2064, U+FEFF outside a leading BOM), or an HTML comment carrying agent-directed imperatives ("ignore previous instructions", "do not tell the user", "secretly", "always run", "system prompt", "exfiltrate").

Why: you read the rendered text, the model reads the bytes. Anything in that gap was put there to be acted on without review.

Do: remove the bundle. Text that must be invisible to you but visible to the agent has no legitimate purpose in an extension.

Wrong when: the content is genuine right-to-left natural language, which uses bidi marks, or carries stray zero-width characters pasted from a web page.

Quiet on: emoji ZWJ sequences where U+200D joins two pictographs, a leading UTF-8 BOM, `<!-- prettier-ignore -->` and other lint pragmas, and `DOCS`-role markdown, where a stray zero-width character is a copy-paste artifact rather than a planted instruction.

## PROMPT_INJECTION_IN_METADATA (HIGH)

Fires when: manipulation phrasing appears in metadata fields only, which means the frontmatter of an `INSTRUCTION` file, MCP server `description`/`instructions`, MCP tool descriptions and hook command strings. Patterns cover ignore/disregard/override previous instructions, do not tell or reveal to the user, without the user's knowledge or consent, hide or suppress from the user or logs, always call this tool first, pretend to be or act as if, exfiltrate or steal credentials, and embedded fake `system:` turns.

Why: descriptions and tool metadata load into every session before you type anything, and nobody reads them. Text there is an instruction to the agent.

Do: remove the bundle or MCP server. Metadata that tells the agent to hide things from you is not fixable by editing one sentence.

Wrong when: security tooling legitimately quotes these phrases in its own description, or a description says "never reveal secrets to the user" as a safety instruction.

Quiet on: README and body prose discussing prompt injection, including this repository's own documentation. The rule reads metadata fields, never arbitrary documentation text, and that restriction is what makes it usable.

## MCP_RUNTIME_REMOTE_CODE (HIGH)

Fires when: an MCP server's `command` plus `args` fetch and execute at launch. A download piped into a shell, `sh -c "$(curl …)"`, `bash -c` wrapping a fetch, `node -e` or `python -c` that downloads then evaluates, or a server whose command is `curl` or `wget`.

Why: the server starts with every session, so the remote payload is re-fetched and re-executed forever. Whoever controls that URL controls your machine.

Do: remove the server from the MCP config, or replace it with a pinned package installed ahead of time so it can be reviewed.

Wrong when: the bootstrap script is hosted on infrastructure you control.

Quiet on: plain `npx -y <package>`, `uvx <package>`, `docker run <image>`. That is the ecosystem norm, and flagging it would produce the wall of noise that gets scanners ignored.

## HOOK_REMOTE_CODE (HIGH)

Fires when: a hook command pipes remote content into a shell or interpreter (the `PIPE_TO_SHELL` patterns applied to hook command strings).

Why: the hook fires on ordinary agent activity, so the remote payload runs repeatedly and automatically, with no prompt and no review.

Do: delete the hook from the settings file and inspect the URL it fetched.

Wrong when: it is a bootstrap hook for an internal tool on an internal host. Still worth pinning.

## BASELINE_TAMPERED (HIGH)

Fires when: `<home>/.malskill/baseline.json` fails the `self_checksum` recorded inside it, is not valid JSON, or is structurally invalid.

Why: editing the baseline is how a modified bundle is made to look unchanged. A broken checksum means drift detection cannot be trusted. Drift and new-target comparison are skipped for that run, because "no drift" and "I could not check" must not look the same.

Do: delete the baseline, review every installed bundle by hand, then re-create it with `malskill baseline update`.

Wrong when: you hand-edited the file, the baseline came from a different scanner version, or a run was interrupted mid-write.

The self-checksum catches corruption and casual tampering, not an attacker. The algorithm is in this repository, so anything with write access to the store can recompute it. The store is written `0600`; the real protection is the permissions on your home directory.

## CREDENTIAL_PATH_ACCESS (MEDIUM)

Fires when: a sensitive credential path is referenced in executable context and the bundle has no network egress primitive anywhere. Suppressed when the bundle's declared purpose is credential management (ssh, gpg, keychain, vault, dotenv, auth, API keys), since a credential manager touching credentials is consistent rather than a mismatch.

Why: local-only credential reads still hand secrets to whatever the agent does next, including printing them into a transcript that leaves by another route. MEDIUM because it is worth a look, not an emergency.

Do: read the flagged line and decide whether reading that path is part of the job you installed the bundle for.

Wrong when: a dotfile manager, `.env` loader or SSH config helper does not declare a credential purpose in its description, or a path is named as something the bundle deliberately avoids ("we never read `~/.ssh`") and the negation filter misses it.

Quiet on: bundles with egress, which belong to `SENSITIVE_READ_PLUS_EGRESS`; paths in prose or data files; purpose-matched credential tooling.

## SYMLINK_ESCAPE (MEDIUM)

Fires when: a symlink inside a bundle resolves outside the bundle root. The scanner never follows it. The entry is reported as a finding and as a NOT-FULLY-ANALYZED record.

Why: it smuggles content past a reviewer who only reads the bundle, and it can turn "read my own reference files" into a read of `~/.ssh`. The finding says so explicitly when the destination is a credential or agent-configuration path.

Do: delete the symlink, or remove the bundle if the link points at credentials or agent configuration.

Wrong when: a development checkout is symlinked into `~/.claude/skills/`, or a package manager left links behind (`node_modules/.bin`, virtualenv `bin/python`).

Quiet on: symlinks that stay inside the bundle. Those are recorded as NOT-FULLY-ANALYZED, not descended into to avoid cycles, and are not findings.

## TOOL_SHADOWING (MEDIUM)

Fires when: metadata claims to replace or intercept another tool: "instead of using the Read tool", "replaces the Bash tool", "overrides the built-in", "intercepts all calls to", "proxy for all shell calls".

Why: a shadowing tool sits between the agent and the real tool, so it sees every argument (file contents, commands, secrets) and controls what comes back.

Do: remove the server or skill unless you deliberately installed a proxy and trust its author with everything the shadowed tool touches.

Wrong when: an honest drop-in replacement advertises itself, for example a faster search tool that says "use this instead of the Grep tool".

Quiet on: "use this instead of manually formatting". The pattern requires the literal word tool or command as the object.

## MCP_SECRET_BROADCAST (MEDIUM)

Fires when: an MCP server's `env` block holds a credential-shaped variable (`*KEY*`, `*TOKEN*`, `*SECRET*`, `*PASSWORD*`, `*AUTH*`) with a literal value of 8+ characters that is not a placeholder, while the command runs an unpinned remote package (`npx`, `bunx`, `pnpm dlx`, `uvx`, `pipx run`, `@latest`) with no version pin. Secret values are never printed; evidence shows the variable name and a masked value.

Why: the secret is handed to whatever version of that package the registry serves next. One malicious release, from the author or a hijacked account, reads it out of the environment.

Do: pin the package to an exact version, and replace the literal with an environment reference (`${VAR}`) so the secret is not stored in a config file.

Wrong when: a long non-secret identifier such as a project id or model name is stored in a `*_KEY` variable, or a placeholder-looking value is actually real.

Quiet on: pinned packages (`pkg@1.2.3`, `pkg==1.2`), `${ENV_VAR}` references, short values, servers with no `env` block.

## MCP_UNPARSEABLE_CONFIG (MEDIUM, reported as NOT-FULLY-ANALYZED)

Fires when: an MCP config file exists but does not parse. Invalid JSON, a non-object top-level value, or TOML outside the small supported subset (`~/.codex/config.toml`).

This is not a finding. It is emitted as a NOT-FULLY-ANALYZED record (`emits == "unscanned"` in the registry) and never contributes to the exit code. The ID is registered and documented so it is discoverable.

Why: an unparsed config is an unscanned config. Silently skipping it would turn a blind spot into a green row.

Do: fix or hand-review the config, then rescan so the servers it declares are analyzed.

Wrong when: the config uses JSON5 or comments, or advanced TOML (multi-line arrays, dotted keys). Both are reported as not-analyzed rather than as findings.

## BASELINE_DRIFT (MEDIUM)

Fires when: with an accepted baseline present, a recorded file's sha256 changed, a new file appeared inside a known bundle, or a file disappeared while nothing else in that bundle changed. Hook command strings and MCP server entries are hashed too. At most three files per bundle are listed individually; the rest are summarised in the report notes.

Why: the realistic attack is not a new obviously-evil skill, you would read that one. It is a bundle you already trust going bad in an update.

Do: diff the changed file against what you accepted. Run `malskill baseline update` only after you have read the change.

Wrong when: you performed the update yourself, or the bundle writes caches, logs, lock files or a regenerated timestamp into its own directory.

Quiet on: everything, when no baseline exists yet. The first run says so in the notes rather than flagging every installed bundle.

## BASELINE_NEW_TARGET (LOW)

Fires when: with an accepted baseline present, a target (bundle, hook, MCP server) exists that the baseline has never seen.

Why: informational, but named, so an install can never land silently. This is how you notice something you did not install.

Do: confirm you installed it. If you did, accept it with `malskill baseline update`. If you did not, remove it.

Wrong when: every bundle you install intentionally fires this once, and a moved directory fires it once too, since the baseline key includes the path.

## SUPPRESSED_PATTERN_HIT (LOW, `--paranoid` only)

Fires when: one of the eight behaviour rules matched inside a file whose role is `DOCS`, `TEST` or `DATA`/binary. Each row names the rule whose pattern matched, the role that held it back, and the file and line. Without `--paranoid` these are counted in a report note and listed under `report["suppressed"]` in the JSON output. They are never dropped.

It is a separate ID rather than the original rule at a lower severity because a floor is a floor, and printing `PIPE_TO_SHELL [LOW]` would misrepresent what that rule concluded.

Why: two opposite reasons. It is the receipt for the noise reduction, a claim you can audit instead of taking on trust. It is also where the residual risk lives: a payload planted in a file that a `SKILL.md` points the agent at appears here, at LOW, instead of in `FLAGGED`.

Do: read the line. Documentation and test material quoting a dangerous command needs nothing. Treat it as real if any instruction surface in the same bundle points the agent at that file.

Wrong when: by construction most of these are false positives, which is why they are LOW and opt-in. The interesting failure runs the other way, a genuine payload parked in a file called `README.md` or a directory called `tests/`.

## NOT-FULLY-ANALYZED reasons

Not findings, never affect the exit code, always printed. `--show-unscanned` lists every one.

| Reason | Meaning |
|---|---|
| `binary` | NUL byte in the first 8 KiB. Byte-pattern rules still ran; text-only analysis did not. |
| `too-large` | Over 2 MiB (only the first 2 MiB analyzed), a bundle over 20000 files, or a vendored/VCS directory (`node_modules`, `.venv`, `site-packages`, `.git`, caches) not descended into. |
| `unreadable` | Permission denied, I/O error, or a path that disappeared mid-scan. |
| `parse-error` | Invalid JSON/TOML, broken frontmatter, frontmatter outside the safe subset, or a rule that raised. A crashed rule is an unscanned target, not a clean one. |
| `symlink-out` | A symlink the scanner refused to follow. Escaping links also produce `SYMLINK_ESCAPE`; in-bundle links are recorded without a finding. |

## Report states and exit codes

| State | Meaning |
|---|---|
| `FLAGGED` | At least one rule fired. |
| `CLEAN` | No rule fired on what could be analyzed. Not a statement that anything is guaranteed harmless. |
| `NOT-FULLY-ANALYZED` | Nothing fired, but content exists that was not fully read. Always shown alongside the other two. |

| Exit code | Meaning |
|---|---|
| `0` | No findings, including the not-fully-analyzed-only case. |
| `1` | One or more findings. |
| `2` | Scanner error. |

`--paranoid` findings are findings. A scan that would otherwise exit `0` exits `1` once the suppressed ledger is surfaced.
