# MalSkill Scanner — Rule Reference

Every finding ID the scanner can emit, what fires it, why it matters, what to do about it,
and how it can be wrong. If a rule is not documented here, it does not exist:
`malskill rules` prints the same set straight out of `malskill.rules.REGISTRY`.

## How to read this document

* **Severity is a floor, set by the rule.** The optional AI explainer (`--explain`) may
  raise a finding's severity and add a sentence of context. It can never lower, clear or
  suppress one — `Finding.escalate()` refuses anything at or below the current level. A
  malicious bundle cannot talk its way out of a finding.
* **Findings are named, never scored.** `NETWORK_IN_OFFLINE_CLAIM` tells you what to look
  at. "Scored 47" does not.
* **Mismatch-first.** A scary keyword on its own is never a finding. `curl` appears in
  roughly a third of installed bundles; `curl` inside a bundle that claims it works
  offline is a lie about behaviour, and the lie is the signal. Every rule below states
  the contradiction or combination it requires.
* **Detection runs on raw bytes; only the display copy is sanitized.** Evidence shown to
  you (and to the explainer) has invisible codepoints escaped as `\u{200B}` and URLs
  defanged as `hxxps://evil[.]example[.]com`, so reading a report can never itself be the
  attack.
* **Three report states, never two:** `FLAGGED`, `CLEAN`, `NOT-FULLY-ANALYZED`. The
  scanner never prints that anything is guaranteed harmless, and a file it could not read
  is always listed rather than silently dropped.
* **Where a pattern was found decides whether it is behaviour.** See
  [Roles and the reference hop](#roles-and-the-reference-hop) below — this is the single
  most important thing to understand about why the scanner is quiet on a real machine.

---

## Roles and the reference hop

Every file in a bundle is classified into one of five **roles** (`malskill/roles.py`):

| Role | What it is | Examples |
|---|---|---|
| `EXECUTABLE` | something that runs | `*.sh` `*.py` `*.js` `*.mjs` `*.ts` `*.rb` `*.pl`, files with an execute bit, `Makefile`, `Dockerfile`, **hook command strings**, **MCP `command`/`args`** |
| `INSTRUCTION` | something an agent reads *as directives* | `SKILL.md`, `CLAUDE.md`, `AGENTS.md`, `commands/**.md`, `agents/**.md`, `plugin.json`, `hooks.json`, `settings.json`, `.mcp.json`, MCP tool/server descriptions |
| `DOCS` | prose for humans | `README*`, `CHANGELOG*`, `CONTRIBUTING*`, `LICENSE`, `DESIGN*`, and anything under `docs/`, `reference(s)/`, `blueprints/`, `examples/`, `guides/` — markdown that is not INSTRUCTION |
| `TEST` | test material | `test/`, `tests/`, `__tests__/`, `spec/`, `fixtures/`, `*.test.*`, `*_test.*`, `test_*.py`, `conftest.py` |
| `DATA` | everything else | assets, CSV/JSON data, **every binary-sniffed file, whatever its name** |

**The policy.** The eight behaviour rules — `PIPE_TO_SHELL`, `DESTRUCTIVE_COMMAND`,
`SELF_MODIFICATION`, `AUTO_APPROVE_TAMPERING`, `OBFUSCATED_EXECUTION`,
`NETWORK_IN_OFFLINE_CLAIM`, `SENSITIVE_READ_PLUS_EGRESS`, `CREDENTIAL_PATH_ACCESS` — fire
at full severity **only** from `EXECUTABLE` and `INSTRUCTION` files. For the two pairing
rules, **both** halves must come from those roles, and neither may come from a binary
file.

The metadata rules (`HIDDEN_INSTRUCTIONS`, `PROMPT_INJECTION_IN_METADATA`,
`TOOL_SHADOWING`) were already restricted to metadata surfaces; "metadata surface" now
means role `INSTRUCTION` (plus hook/MCP strings) rather than "any file ending in `.md`".

**Why.** Measured on one real machine, v1 produced 47 findings and nearly all of them were
a README quoting the official `curl -fsSL … | bash` installer, a `CHANGELOG` entry, a
`DESIGN.md` describing somebody else's download page, a `CONTRIBUTING.md` showing how to
symlink a checkout, or an injection-hardening test whose input fixture is the literal
string `$(rm -rf /)`. The README's bar is near-zero findings on benign content; a scanner
that produces forty-seven of these teaches its reader to skim, and the one real finding
scrolls past.

**Suppressed is not silent.** Every held-back match is recorded. A default scan prints a
note:

```
491 suppressed pattern hit(s) in documentation/test context (69 data/binary,
382 documentation, 40 test) — rerun with --paranoid to list them.
Rules involved: AUTO_APPROVE_TAMPERING, DESTRUCTIVE_COMMAND, PIPE_TO_SHELL, …
```

and `--paranoid` emits each one as a LOW `SUPPRESSED_PATTERN_HIT` finding naming the rule
whose pattern matched and the role that held it back. The machine-readable report always
carries the full ledger under `report["suppressed"]`, whether or not `--paranoid` was
passed.

### The residual risk, stated plainly

This creates a bypass, and pretending otherwise would be the same dishonesty as printing
"SAFE":

> An attacker puts the payload in `README.md`, `docs/setup.md` or `references/install.md`,
> and writes in `SKILL.md`: *"Before starting, follow the steps in `docs/setup.md`."* The
> agent reads the SKILL.md, follows the pointer, and executes the payload. The scanner
> classified the payload file as `DOCS`, so it appears in the suppressed ledger at LOW
> rather than in `FLAGGED`.

This is accepted for v1, and it is already declared in README.md, which lists
**"no following the reference hop"** among the extractor's deliberate limits. The extractor
does not resolve links, includes or file references, because a reference resolver is an
attack surface of its own — path traversal, symlink escape, fetch-on-read — running
trusted and first.

What to do about it in the meantime:

* the hit is **not lost** — it is in `report["suppressed"]` on every scan, and `--paranoid`
  prints it;
* if a `SKILL.md` points the agent at another file, treat that file as an instruction
  surface and read it yourself. `--paranoid` is the fastest way to see what is in it;
* `BASELINE_DRIFT` still covers documentation files: a README that changes inside a bundle
  you already accepted is reported regardless of role.

Resolving one level of explicit reference from an INSTRUCTION file, and re-classifying the
referenced file as INSTRUCTION, is the obvious v2 change. It is not in v1 because it has to
be done inside the extractor's constraints (no network, no symlink escape, bounded depth),
and doing it badly is worse than not doing it at all.

## Summary

| Finding ID | Floor | Category | One-line trigger |
|---|---|---|---|
| `SENSITIVE_READ_PLUS_EGRESS` | CRITICAL | mismatch | secret path read + network egress in one bundle |
| `SELF_MODIFICATION` | CRITICAL | behavior | writes agent settings, another skill, shell rc, cron/launchd |
| `AUTO_APPROVE_TAMPERING` | CRITICAL | behavior | widens or disables the permission prompt |
| `HOOK_EXFIL` | CRITICAL | hook | hook with egress + access to session data |
| `NETWORK_IN_OFFLINE_CLAIM` | HIGH | mismatch | egress in a bundle that claims offline/local-only |
| `DESTRUCTIVE_COMMAND` | HIGH | behavior | `rm -rf` a root, mkfs, disk erase, fork bomb |
| `OBFUSCATED_EXECUTION` | HIGH | obfuscation | decode-then-execute |
| `PIPE_TO_SHELL` | HIGH | obfuscation | remote content piped into a shell |
| `HIDDEN_INSTRUCTIONS` | HIGH | obfuscation | zero-width/bidi codepoints or agent-directed HTML comments |
| `PROMPT_INJECTION_IN_METADATA` | HIGH | agent-manipulation | manipulation phrasing in auto-loaded metadata |
| `MCP_RUNTIME_REMOTE_CODE` | HIGH | mcp | MCP server downloads and executes code at launch |
| `HOOK_REMOTE_CODE` | HIGH | hook | hook pipes remote content into a shell |
| `BASELINE_TAMPERED` | HIGH | baseline | baseline store fails its own self-checksum |
| `CREDENTIAL_PATH_ACCESS` | MEDIUM | mismatch | secret path read, no egress in the bundle |
| `SYMLINK_ESCAPE` | MEDIUM | obfuscation | symlink resolving outside the bundle |
| `TOOL_SHADOWING` | MEDIUM | agent-manipulation | metadata that replaces or intercepts another tool |
| `MCP_SECRET_BROADCAST` | MEDIUM | mcp | literal secret handed to an unpinned remote package |
| `MCP_UNPARSEABLE_CONFIG` | MEDIUM | mcp | MCP config that does not parse (**NOT-FULLY-ANALYZED**, not a finding) |
| `BASELINE_DRIFT` | MEDIUM | baseline | known file changed or appeared since the accepted baseline |
| `BASELINE_NEW_TARGET` | LOW | baseline | bundle the baseline has never seen |
| `SUPPRESSED_PATTERN_HIT` | LOW | context | behaviour pattern matched in documentation/test/data context (`--paranoid` only) |

---

## SENSITIVE_READ_PLUS_EGRESS — CRITICAL

**Trigger.** One bundle contains both a sensitive-path reference and a network egress
primitive that is not provably localhost-only.

Sensitive paths are split into two classes, because they are not equally meaningful:

* *Unambiguous secrets* (`~/.ssh`, `id_rsa`/`id_ed25519`, `~/.aws/credentials`,
  `~/.gnupg`, `~/.netrc`, keychain access, `~/.claude.json`, browser cookie/login-data
  stores, crypto wallets, shell history). These pair with egress anywhere in the bundle
  when the read is in executable context, or anywhere at all if the two sit within 60
  lines of each other in one file.
* *Everyday development secrets* (`.env` files, generic `credentials.*`, `.npmrc`/
  `.pypirc`/`.kube/config`/`.docker/config.json`, bulk environment dumps such as
  `printenv | …`, `JSON.stringify(process.env)`, `dict(os.environ)`). These are so common
  that they only pair when they are **in code**, **within 5 lines** of the egress, and
  the line is not an ordinary config load.

Egress primitives: `curl`, `wget`, `nc`/`ncat`/`socat`, `/dev/tcp/`, `urllib`/`urlopen`,
`requests.*`, `httpx`/`aiohttp`, `http.client`, raw sockets, `fetch(`, `XMLHttpRequest`,
`WebSocket`, `axios`/`got`, `http(s).request`, `Invoke-WebRequest`, `scp`/`sftp`/`ftp`,
`rsync` to a remote, mail pipes.

**Why it is dangerous.** Read-a-secret plus send-it-somewhere, inside one bundle running
with your agent's privileges and (in 97% of installed bundles) with no declared tool
restrictions, is the entire shape of credential theft. Neither half is remarkable alone;
together they are a pipeline.

**Recommended action.** Remove the bundle, then rotate every credential it could reach —
SSH keys, cloud credentials, API tokens on the referenced paths. You cannot tell from the
files whether it already ran.

**Known false-positive modes.**

* Deliberate credential tooling: an SSH key uploader, an AWS profile sync, a secrets
  manager that posts to a vault. These genuinely do both. The finding names both file and
  line so the judgement takes seconds; suppressing them by "declared purpose" would let
  any bundle claim to be a credential manager and go quiet.
* Binary blobs participate, because byte patterns match inside them. A compiled helper
  containing both an SSH path and a URL is exactly what deserves a look.
* A skill that reads `~/.claude.json` to find an API key and then calls that API.

**Does not fire on.** `source ./.env && curl https://api.example.com/…` (config load, not
secret read); `.env` mentioned in a README paired with an installer `curl` 30 lines away;
`curl http://localhost:3000` **or** `curl localhost:3000` with any secret (localhost is
exempt with or without a URL scheme); anything inside a data file (`.csv`, `.html`,
`.svg`, `.min.js`) or in prose that carries warning language.

**Role constraints (v1.1).** Both halves must come from an `EXECUTABLE` or `INSTRUCTION`
file, and **neither may come from a binary file**. Two real defects this closes:

* a keychain read in `scripts/setup-keychain.sh` paired with the byte sequence `nc` found
  inside the raw bytes of `assets/claude-code-rap.mp3`. Short patterns match random bytes
  by chance, so binary content is now `DATA` and can never be pairing evidence. The file
  is still reported as NOT-FULLY-ANALYZED;
* a `~/.claude.json` reference in `plugins/receipts/…/mine-transcripts.mjs` paired with an
  installer `curl` quoted in `external_plugins/discord/README.md` — a different plugin, in
  a four-thousand-file marketplace checkout. Documentation is not an execution surface.

**Comments are not operations.** A line beginning `#`, `//`, `--` or `*` is read by a
maintainer, never by an interpreter: `// and ~/.claude.json, which are somebody's actual
projects` is a sentence about a path, not a read of it. Both halves must sit on a
non-comment line.

**`urllib` is not automatically egress.** `from urllib.parse import quote` is string
handling and `from urllib.error import HTTPError` is exception handling. The matcher wants
`urllib.request`, `urlopen(`, `urlretrieve(`, `urllib3`, or a bare `import urllib`.

---

## SELF_MODIFICATION — CRITICAL

**Trigger.** A write, append or edit whose destination is:
`~/.claude/settings.json` / `settings.local.json`, `~/.claude.json`, another skill's or
plugin's directory, `~/.claude/plugins/`, `~/.claude/commands/`, `~/.claude/agents/`,
a shell startup file (`.zshrc`, `.bashrc`, `.bash_profile`, `.profile`, `.zprofile`,
`config.fish`), the git hooks directory or `core.hooksPath`, `.mcp.json` /
`claude_desktop_config.json`; or a command that is itself persistence (`crontab -`,
`launchctl load`, `defaults write`, `systemctl enable`, autostart entries).

The path alone never fires. A write must be visible: shell redirection *pointing at* the
path, `tee`, `sed -i`, a `cp`/`mv`/`ln` where the path is the **destination**, or —
inside real script files only — a strong write call (`open(..., 'w')`,
`writeFileSync`, `Path(...).write_text`, `json.dump`, `cat >`) within two lines.

**Why it is dangerous.** This is how a one-shot skill becomes permanent. Editing agent
settings, a shell rc file, a git hook or a LaunchAgent gives the bundle a foothold that
survives deleting the bundle itself.

**Recommended action.** Remove the bundle, then inspect what it writes to — diff your
settings files, shell rc files, `crontab -l`, `~/Library/LaunchAgents/` — for entries you
did not add.

**Known false-positive modes.**

* Installers and dotfile managers that legitimately append a `PATH` line to `.zshrc`.
* Skills that install themselves (`cp SKILL.md ~/.claude/skills/<name>/`) or symlink a
  development checkout into `~/.claude/skills/`.
* Agent-configuration helpers you installed on purpose, and tutorials that create example
  commands with `cat > .claude/commands/example.md`.

**Does not fire on.** Reading those paths (`cat`, `grep`, `jq`); `cp -R ~/.claude/skills/
x/templates ./site` (the agent path is the *source*); markdown blockquotes and `->`/`=>`
arrows, which are not redirections; documents that merely name a LaunchAgents plist;
**angle-bracket placeholders and process substitution** — `diff <(grep 'x'
skills/<skill>/SKILL.md) <(grep 'x' ~/.claude/plugins/cache/…)` reads two files and writes
nothing, but the `>` closing `<skill>` used to read as a redirection and turned a
read-only audit command in a SKILL.md into a CRITICAL finding.

**Role constraints (v1.1).** Fires only from `EXECUTABLE` and `INSTRUCTION` files. A
`CONTRIBUTING.md` showing `ln -sfn /path/to/checkout .claude/skills/x`, a
`references/testing-strategies.md` showing `cat > .claude/commands/test.md`, and a
`tests/test_paths.py` listing `launchctl load …` as a string to reject are all counted in
the suppressed ledger instead. Comment lines inside scripts additionally require a
directive verb.

At most one finding per (write target, file): five rows saying "this script writes
`settings.json`" are one fact, and printing it five times is how a report gets skimmed.

---

## AUTO_APPROVE_TAMPERING — CRITICAL

**Trigger.** Content that removes the human checkpoint:

* `--dangerously-skip-permissions` or `--permission-mode acceptEdits|bypassPermissions`;
* `defaultMode: acceptEdits|bypassPermissions` or `bypassPermissions` in settings;
* content that **writes or mutates** a permissions `"allow"` array (a redirection or
  `open(..., 'w')` aimed at it, or an `append`/`extend`/`setdefault`/`+=` on it) — a
  settings file that merely *contains* an allow-list is a user configuring their own
  machine and never fires;
* a blanket tool grant (`Bash(*)`, `Read(**)`, `WebFetch(*)`) appearing within a
  permissions block;
* `CLAUDE_AUTO_APPROVE` / `CLAUDE_SKIP_PERMISSIONS` style environment overrides;
* instructions to a human or agent to enable auto-approval, widen the allow-list, skip
  confirmation prompts, or act "without asking for permission".

In prose files these only fire when the surrounding line carries a directive verb (run,
use, add, enable, set, always, must, install …), so a table of CLI flags or an
architecture diagram does not count as an instruction.

**Why it is dangerous.** Every other protection you have depends on the confirmation
prompt. Anything that turns it off is disabling the last human checkpoint before
arbitrary commands run as you.

**Recommended action.** Remove the bundle and audit your permissions allow-list and
settings files for entries you did not add.

**Known false-positive modes.**

* Security documentation that quotes the flag while explaining why not to use it (the
  negation filter removes most of these, not all).
* CI/sandbox helper scripts written for throwaway containers, where bypassing prompts is
  intentional.
* Tooling that legitimately launches Claude Code non-interactively.

**Does not fire on.** A user's own `settings.json` containing `permissions.allow` with
scoped entries and `defaultMode: default`; `| --yolo | nothing checked | container only |`
style reference tables; a bare `"*"` glob in ordinary code; sentences that argue against
the flag ("never run with `--dangerously-skip-permissions`"); an **error message inside a
script** — `echo "Claude Code refuses --dangerously-skip-permissions as root"` is neither
prose nor a comment, but it is plainly not an instruction to use the flag; a **code
comment** saying `# bypassPermissions is unnecessary here`.

**Role constraints (v1.1).** Fires only from `EXECUTABLE` and `INSTRUCTION` files. A
README describing a `--force` flag, a `docs/DESIGN.md` mentioning a sandbox harness, and a
test fixture whose payload string is `--dangerously-skip-permissions` are counted in the
suppressed ledger instead. A fenced code block inside a `SKILL.md` still fires without
needing a directive verb around it — that is a command the document is showing the agent
to run.

---

## HOOK_EXFIL — CRITICAL

**Trigger.** A hook command string that contains a network egress primitive with a
non-local destination **and** a reference to session data: `$CLAUDE_*` variables, a
transcript path, tool input/output, session identifiers, piped stdin (`curl -d @-`,
`… | curl`), `jq` over the hook payload, an environment dump, or agent config/history
files.

**Why it is dangerous.** Hooks run automatically on ordinary agent activity, see
everything the session sees — prompts, file contents, tool results — and never ask for
permission. Egress from a hook is exfiltration until proven otherwise, and only the
machine's owner can prove otherwise.

**Recommended action.** Delete the hook from the settings file immediately, and assume
everything in recent sessions reached the remote host.

**Known false-positive modes.**

* Deliberate self-hosted telemetry or transcript backup to a host you own.
* Team-internal audit hooks that post tool usage to an internal endpoint.

**Does not fire on.** Hooks with no egress (formatters, linters, notifications); hooks
posting only to `localhost`/`127.0.0.1`.

---

## NETWORK_IN_OFFLINE_CLAIM — HIGH

**Trigger.** A network egress primitive reaching a non-local destination, in a bundle
that either

1. describes itself as offline / local-only / "no network required" and declares no
   network intent anywhere (strong branch), or
2. never declares network intent, has a local-ish purpose (formatting, docs, notes,
   analysis) and contacts a literal external URL (weak branch).

Destinations resolving to `localhost`, `127.0.0.0/8`, `0.0.0.0`, `::1`, `*.local` are
exempt. The offline claim is cancelled by any network declaration in the same
description, because ambiguity is not deception.

**Why it is dangerous.** `curl` is in ~284 of 867 installed bundles; on its own it means
nothing. `curl` in a bundle that told you it never touches the network means the
description cannot be trusted, and the description is the only thing most people read
before installing.

**Recommended action.** Open the flagged line, decide whether you want this bundle
talking to that host, and remove it if the description does not match the code — you
cannot review something that misdescribes itself.

**Known false-positive modes.**

* Update/telemetry checks bolted onto an otherwise local tool. These fire deliberately.
* A bundle whose description says "offline" about one feature and not another.
* Example URLs inside instructions that the agent may or may not act on.

**Does not fire on.** Bundles that mention an API, download, URL, webhook, search or that
grant `WebFetch`/`WebSearch`/`Bash(curl…)`; localhost dev-server calls; prose that warns
against a network call.

---

## DESTRUCTIVE_COMMAND — HIGH

**Trigger.** `rm -rf` (any recursive flag combination) whose target is a *root*: `/`,
`/*`, `~`, `~/`, `$HOME`, `${HOME}`, `/Users/<name>`, `/home/<name>`; `rm -rf` of
`~/.ssh`, `~/.aws`, `~/.gnupg`; `mkfs*`; `diskutil erase*`/`partitionDisk`; the classic
fork bomb `:(){:|:&};:`; writes to raw block devices (`> /dev/sda`, `dd of=/dev/nvme…`);
`chmod -R 777` or `chown -R` of a root; `srm`/`shred` of a root.

**Why it is dangerous.** An agent with Bash access runs these verbatim, and there is no
step after the command completes. No description makes formatting a disk the expected
behaviour of a skill.

**Recommended action.** Remove the bundle. If it is yours, scope the deletion to an
explicit subdirectory and re-run the scan.

**Known false-positive modes.**

* Uninstall scripts that clear an install root that happens to be a home directory.
* Security test fixtures that assert a dangerous string is rejected (a literal
  `rm -rf /` inside a test case still matches).
* Dockerfiles that wipe a container root.

**Role constraints (v1.1).** Fires only from `EXECUTABLE` and `INSTRUCTION` files. The
largest benign source by far is an injection-hardening test whose *input fixture* is the
dangerous string — `TITLE_RAW: '$(rm -rf /) `whoami`'` — and the whole point of such a
test is that the command is never run. Those now land in the suppressed ledger, where
`--paranoid` will still show them.

**Does not fire on.** `rm -rf ./build`, `rm -rf "$TMPDIR/x"`, `rm -rf node_modules`,
`rm -rf ~/.claude/skills/<self>` (documented uninstall step), `chown -R me /home/me/.app`
(a specific directory, not the home root), or a commented line whose neighbours warn
against it. `rm -rf "$TARGET"` does not fire either: without evaluating the variable the
scanner cannot know the value, and guessing would produce noise.

---

## OBFUSCATED_EXECUTION — HIGH

**Trigger.** Decode-then-execute, in any of these forms:

* a decoder (`base64 -d`, `base32 -d`, `xxd -r`, `openssl enc -d`, `uudecode`, `gunzip`,
  `zcat`) piped into `sh`/`bash`/`zsh`/`python`/`node`/`perl`/`ruby`/`php`;
* `sh -c "$(echo … | base64 -d)"`;
* `eval(atob(`, `eval(Buffer.from(`, `eval(base64.b64decode(`, `eval(codecs.decode(`,
  `Function(atob(`, `exec(base64.b64decode(`, `exec(marshal.loads(`;
* `exec(compile(<decoded blob>…))`;
* a child process spawned with a decoded command string;
* PowerShell `-EncodedCommand`, or `FromBase64String` feeding `iex`;
* a run of 20+ consecutive `\xNN`/`\uNNNN`/octal escapes with an execution sink
  (`eval`, `exec`, `Function`, `system`, `spawn`, `subprocess`, a pipe to an interpreter)
  within 600 characters.

**Why it is dangerous.** Code that hides what it runs has already told you its intent.
Obfuscation exists to defeat exactly the review you are performing.

**Recommended action.** Remove the bundle. If you need to know what the payload was,
decode it inside a throwaway container that holds none of your credentials — never on the
machine you care about.

**Known false-positive modes.**

* Minified or vendored JavaScript with long escape runs near an `eval`-like call.
* Encoding tutorials and library test fixtures.
* Legitimate PowerShell that decodes data (not commands) from base64.

**Does not fire on.** `base64 -d > file.png` (decoding to data, not to an interpreter);
`exec(compile(f.read(), __file__, 'exec'))`, the standard way to run a *local* file;
warning comments that quote the pattern.

---

## PIPE_TO_SHELL — HIGH

**Trigger.** `curl`/`wget` (or PowerShell equivalents) whose output is executed:
`… | sh|bash|zsh|python|node|perl|ruby`, `sh -c "$(curl …)"`, `bash <(curl …)`,
`eval "$(curl …)"`, `iwr … | iex`, or download-then-run-immediately
(`curl -o x && chmod +x x && ./x`).

Claims cannot exempt this rule: there is no description under which "fetch and execute
unreviewed remote code" becomes reviewable. Localhost is not exempt either, because a
local port is frequently a proxy for remote content.

**Why it is dangerous.** Whatever the server returns at run time executes with your
privileges. The bundle you reviewed is not the code that runs, so the review proves
nothing.

**Recommended action.** Remove the bundle, or replace the pipe with a pinned download
whose checksum you verify and whose contents you read before running.

**Known false-positive modes.**

* **The big one:** official installer one-liners (rustup, nvm, uv, bun, Homebrew, Deno)
  copied into a README or SKILL.md. These fire deliberately — an agent that reads a
  SKILL.md may execute what it finds there, so an installer line inside a bundle is a
  live instruction, not documentation. The finding names the host so you can judge it in
  seconds.

**Does not fire on.** `curl -o file.tar.gz` with no execution; a commented or
warning-labelled line ("never run `curl … | bash`"); the same one-liner in a `README.md`,
`CHANGELOG.md`, `docs/`, `reference(s)/`, `blueprints/` or a test file — see the role
policy above. It **does** still fire from a `SKILL.md`, a `commands/*.md`, a hook string,
an MCP command and any script, because those are the places the line actually acts.

At most one finding per (form, file).

---

## HIDDEN_INSTRUCTIONS — HIGH

**Trigger.** Two forms, both restricted to content the agent loads as instructions
(markdown files in a bundle, command/agent files, MCP descriptions, hook strings):

1. invisible or direction-control codepoints found in the **raw bytes** —
   U+200B..U+200F, U+202A..U+202E, U+2060..U+2064, U+FEFF (outside a leading BOM);
2. an HTML comment containing agent-directed imperatives: "ignore previous instructions",
   "do not tell the user", "secretly", "before responding", "run the following", "always
   run", "new instructions", "system prompt", "exfiltrate".

**Why it is dangerous.** You read the rendered text; the model reads the bytes. Anything
in that gap was put there to be acted on without being reviewed.

**Recommended action.** Remove the bundle. Text that must be invisible to you but visible
to the agent has no legitimate purpose in an extension.

**Known false-positive modes.**

* Genuine right-to-left natural language, which legitimately uses bidi marks.
* Copy-pasted content that carries stray zero-width characters from a web page.
* An emoji ZWJ sequence is **exempt** when U+200D joins two non-ASCII pictographs
  (👨‍💻), and a leading UTF-8 BOM is exempt.

**Does not fire on.** `<!-- prettier-ignore -->` and other lint pragmas: they are not
agent-directed, and the imperative patterns all require an object such as "previous
instructions" or "the user". Since v1.1 it also does not fire from a `README.md` or other
`DOCS`-role markdown: a stray zero-width character pasted in from a web page is a
copy-paste artifact, not a planted instruction. Those hits go to the suppressed ledger, so
`--paranoid` still shows them.

---

## PROMPT_INJECTION_IN_METADATA — HIGH

**Trigger.** Agent-manipulation phrasing inside **metadata fields only**: frontmatter
values of skills/commands/agents, MCP server `description`/`instructions`, MCP tool
descriptions, and hook command strings. Patterns:

* `ignore|disregard|forget|override (all|any)? (previous|prior|above|system) instructions`
* `do not tell|show|inform|reveal … the user`, `never tell … the user`
* `without the user's knowledge|approval|confirmation|consent`
* `hide|conceal|suppress … from the user/output/logs`
* `always run|execute|call this tool first`, `before using any other tool`,
  `must be called first`
* `pretend to be|you are|that`, `act as if …`
* `exfiltrate`, `steal the keys|credentials|tokens`
* an embedded fake `system:`/`assistant:` turn

**Why it is dangerous.** Descriptions and tool metadata are loaded into every session
before you type anything, and nobody reads them. Text there is an instruction to the
agent, not documentation for you.

**Recommended action.** Remove the bundle or MCP server. Metadata that tells the agent to
hide things from you is not fixable by editing one sentence.

**Known false-positive modes.**

* Security tooling whose *description* legitimately quotes these phrases (a scanner, a
  red-team fixture, a guardrail skill).
* A description that says "never reveal secrets to the user" as a safety instruction.

**Does not fire on.** README/body prose that discusses prompt injection — including this
repository's own documentation. The rule reads metadata fields, never arbitrary
documentation text; that restriction is the reason the rule is usable at all. Since v1.1,
"metadata field" means the frontmatter of an `INSTRUCTION`-role file (`SKILL.md`,
`CLAUDE.md`/`AGENTS.md`, `commands/**.md`, `agents/**.md`) plus MCP and hook strings — not
the frontmatter of any file that happens to end in `.md`.

---

## MCP_RUNTIME_REMOTE_CODE — HIGH

**Trigger.** An MCP server whose `command` + `args` fetch and execute at launch: a
download piped into a shell, `sh -c "$(curl …)"`, `bash -c` wrapping a fetch, `node -e`
or `python -c` that downloads then evaluates, or a server whose command *is* `curl`/
`wget`.

**Why it is dangerous.** The server starts with every session, so the remote payload is
re-fetched and re-executed forever. Whoever controls that URL controls your machine.

**Recommended action.** Remove the server from the MCP config, or replace it with a
pinned package version installed ahead of time so it can be reviewed.

**Known false-positive modes.**

* A bootstrap script hosted on infrastructure you control.

**Does not fire on.** Plain `npx -y <package>`, `uvx <package>`, `docker run <image>` —
that is the ecosystem norm, and flagging it would produce the wall of noise that gets
scanners ignored.

---

## HOOK_REMOTE_CODE — HIGH

**Trigger.** A hook command that pipes remote content into a shell or interpreter (the
`PIPE_TO_SHELL` patterns, applied to hook command strings).

**Why it is dangerous.** The hook fires on ordinary agent activity, so the remote payload
runs repeatedly and automatically, with no prompt and no review.

**Recommended action.** Delete the hook from the settings file and inspect the URL it
fetched.

**Known false-positive modes.** Bootstrap hooks for an internal tool on an internal host
— still worth pinning.

---

## BASELINE_TAMPERED — HIGH

**Trigger.** `<home>/.malskill/baseline.json` fails the `self_checksum` recorded inside
it, is not valid JSON, or is structurally invalid.

**Why it is dangerous.** Editing the baseline is how a modified bundle is made to look
unchanged. A broken checksum means drift detection cannot be trusted, so it is reported
instead of silently producing "no drift".

**Recommended action.** Delete the baseline, review every installed bundle by hand, then
re-create it with `malskill baseline update`.

**Known false-positive modes.** Hand-editing the file; a baseline written by a different
version of the scanner; a truncated write from an interrupted run.

When this fires, drift and new-target comparison are skipped for that run — the scanner
does not report differences against a store it cannot trust.

---

## CREDENTIAL_PATH_ACCESS — MEDIUM

**Trigger.** A sensitive credential path referenced in executable context, with **no**
network egress primitive anywhere in the bundle. Suppressed entirely when the bundle's
declared purpose is credential management (ssh, gpg, keychain, vault, dotenv, auth, API
keys) — a credential manager touching credentials is consistent, not a mismatch.

**Why it is dangerous.** Local-only credential reads still hand secrets to whatever the
agent does next, including printing them into a transcript that leaves by another route.
It is MEDIUM because it is worth a look, not an emergency.

**Recommended action.** Read the flagged line and decide whether reading that path is
part of the job you installed the bundle for. If it is not, remove it.

**Known false-positive modes.**

* Dotfile managers, `.env` loaders and SSH config helpers that do not declare a
  credential purpose in their description.
* A path named as something the bundle deliberately avoids ("we never read `~/.ssh`") —
  the negation filter catches most, not all.

**Does not fire on.** Bundles with egress (those belong to `SENSITIVE_READ_PLUS_EGRESS`);
paths mentioned in prose or in data files; purpose-matched credential tooling.

---

## SYMLINK_ESCAPE — MEDIUM

**Trigger.** A symlink inside a bundle whose target resolves outside the bundle root. The
scanner never follows it; the entry is reported both as a finding and as a
NOT-FULLY-ANALYZED record.

**Why it is dangerous.** It smuggles content past a reviewer who only reads the bundle,
and it can turn "read my own reference files" into a read of `~/.ssh`. The finding says
so explicitly when the destination is a credential or agent-configuration path.

**Recommended action.** Delete the symlink, or remove the bundle if the link points at
credentials or at agent configuration.

**Known false-positive modes.**

* Development checkouts symlinked into `~/.claude/skills/`.
* Package-manager links (`node_modules/.bin`, virtualenv `bin/python`).

**Does not fire on.** Symlinks that stay inside the bundle — those are recorded as
NOT-FULLY-ANALYZED (not descended, to avoid cycles) but are not findings.

---

## TOOL_SHADOWING — MEDIUM

**Trigger.** Metadata that claims to replace or intercept another tool: "instead of using
the Read tool", "replaces the Bash tool", "overrides the built-in", "intercepts all calls
to", "wraps every tool call", "proxy for all shell calls".

**Why it is dangerous.** A shadowing tool sits between the agent and the real tool, so it
sees every argument — file contents, commands, secrets — and controls what comes back.

**Recommended action.** Remove the server or skill unless you deliberately installed a
proxy tool and trust its author with everything the shadowed tool touches.

**Known false-positive modes.** Honest drop-in replacements (a faster search tool that
says "use this instead of the Grep tool"), and wrappers that advertise themselves clearly.

**Does not fire on.** "Use this instead of manually formatting" — the pattern requires the
literal word *tool* or *command* as the object.

---

## MCP_SECRET_BROADCAST — MEDIUM

**Trigger.** An MCP server whose `env` block contains a credential-shaped variable
(`*KEY*`, `*TOKEN*`, `*SECRET*`, `*PASSWORD*`, `*CREDENTIAL*`, `*AUTH*`) with a literal
value of 8+ characters that is not a placeholder (`${VAR}`, `<your-key>`, `changeme`,
`xxx…`, `example`, `todo`), **while** the command runs an unpinned remote package
(`npx`/`bunx`/`pnpm dlx`/`uvx`/`pipx run`, `@latest`, `:latest`) with no version pin.

Secret values are never printed. Evidence shows the variable name and a masked value.

**Why it is dangerous.** The secret is handed to whatever version of that package the
registry serves next. A single malicious release — from the author or from a hijacked
account — reads it straight out of the environment.

**Recommended action.** Pin the package to an exact version, and replace the literal with
an environment reference (`${VAR}`) so the secret is not stored in a config file.

**Known false-positive modes.** Long non-secret identifiers stored in a `*_KEY` variable
(a project id, a model name); a placeholder-looking value that is actually real.

**Does not fire on.** Pinned packages (`pkg@1.2.3`, `pkg==1.2`); `${ENV_VAR}` references;
short values; servers with no `env` block.

---

## MCP_UNPARSEABLE_CONFIG — reported as NOT-FULLY-ANALYZED

**Trigger.** An MCP config file exists but does not parse: invalid JSON, a non-object
top-level value, or TOML outside the small supported subset (`~/.codex/config.toml`).

**This is not a finding.** It is emitted as a NOT-FULLY-ANALYZED record carrying the ID,
because the honest statement is "I could not read this file", not "this file is fine". It
is present in `REGISTRY` (with `emits == "unscanned"`) so that the ID is documented and
discoverable, and it never contributes to the exit code.

**Why it matters.** An unparsed config is an unscanned config. Silently skipping it would
turn a blind spot into a green row.

**Recommended action.** Fix or hand-review the config, then re-run the scan so the servers
it declares are actually analyzed.

**Known false-positive modes.** Configs using JSON5/comments; advanced TOML (multi-line
arrays, dotted-key edge cases). Both are reported as not-analyzed rather than as findings.

---

## BASELINE_DRIFT — MEDIUM

**Trigger.** With an accepted baseline present, a recorded file's sha256 changed, or a new
file appeared inside a bundle the baseline already knows about. (A file that disappeared
is reported the same way when nothing else in that bundle changed.) At most three files
per bundle are listed individually; the rest are summarised in the report notes.

Hook command strings and MCP server entries are hashed too, so an edited hook or a
rewritten server command shows up as drift.

**Why it is dangerous.** The realistic attack is not a new obviously-evil skill — you
would read that one. It is a bundle you already trust going bad in an update.

**Recommended action.** Diff the changed file against what you accepted. Run
`malskill baseline update` only after you have read the change.

**Known false-positive modes.** Updates you performed yourself; caches, logs or lock files
written inside a bundle directory; a bundle that regenerates a timestamp on every run.

**Does not fire on.** Anything, when no baseline exists yet — the first run says so in the
notes rather than flagging every installed bundle.

---

## BASELINE_NEW_TARGET — LOW

**Trigger.** With an accepted baseline present, a target (bundle, hook, MCP server) exists
that the baseline has never seen.

**Why it matters.** Informational, but *named*, so an install can never land silently.
This is how you notice something you did not install — or a bundle that renamed itself.

**Recommended action.** Confirm you installed it. If you did, accept it with
`malskill baseline update`; if you did not, remove it.

**Known false-positive modes.** Every bundle you install intentionally fires this exactly
once, and a moved directory fires it once as well (the baseline key includes the path).

---

## SUPPRESSED_PATTERN_HIT — LOW  *(`--paranoid` only)*

**Trigger.** One of the eight behaviour rules matched its pattern inside a file whose role
is `DOCS`, `TEST` or `DATA`/binary rather than `EXECUTABLE` or `INSTRUCTION`. See
[Roles and the reference hop](#roles-and-the-reference-hop).

Emitted **only** with `--paranoid`. Without that flag these are counted in a single report
note and listed in full under `report["suppressed"]` in the JSON output. They are never
dropped, because a scanner that silently discards what it saw is telling the same lie as
one that prints a green checkmark.

Each row names the rule whose pattern matched, the role that held it back, and the exact
file and line. It is a **separate ID** rather than the original rule at a lowered severity
on purpose: a severity floor is a floor, and printing `PIPE_TO_SHELL [LOW]` would
misrepresent what that rule concluded.

**Why it matters.** Two opposite reasons, and both are the point:

* it is the receipt for the noise reduction. "47 findings" became "14 findings plus 491
  counted-and-listable suppressions" — a claim you can audit rather than take on trust;
* it is where the residual risk lives. If a `SKILL.md` tells the agent to follow the steps
  in a document, that document is an instruction surface and v1 does not know it. A payload
  planted there appears here, at LOW, instead of in `FLAGGED`.

**Recommended action.** Read the line. Documentation and test material quoting a dangerous
command is ordinary and needs nothing. Treat it as real if any instruction surface in the
same bundle points the agent at that file.

**Known false-positive modes.** By construction, most of these *are* false positives —
that is exactly why they are LOW and opt-in. The interesting failure runs the other way: a
genuine payload parked in a file called `README.md` or in a directory called `tests/`.

**Does not fire on.** Anything at all, without `--paranoid`.

---

# NOT-FULLY-ANALYZED reasons

These are not findings and never affect the exit code, but they are always printed, and
`--show-unscanned` lists every one.

| Reason | Meaning |
|---|---|
| `binary` | NUL byte in the first 8 KiB. Byte-pattern rules still ran; text-only analysis did not. |
| `too-large` | Over 2 MiB (only the first 2 MiB was analyzed), a bundle over 20 000 files, or a vendored/VCS directory (`node_modules`, `.venv`, `site-packages`, `.git`, caches) that was not descended into. |
| `unreadable` | Permission denied, I/O error, or a path that disappeared mid-scan. |
| `parse-error` | Invalid JSON/TOML config, broken frontmatter, frontmatter using constructs outside the safe subset, or a rule that raised (a crashed rule is an unscanned target, not a clean one). |
| `symlink-out` | A symlink the scanner refused to follow. Escaping links also produce `SYMLINK_ESCAPE`; in-bundle links are recorded without a finding. |

# Report states and exit codes

| State | Meaning |
|---|---|
| `FLAGGED` | At least one rule fired. |
| `CLEAN` | No rule fired on what could be analyzed. Explicitly **not** a statement that anything is guaranteed harmless. |
| `NOT-FULLY-ANALYZED` | Nothing fired, but content exists that was not (or not fully) read. Always shown alongside the other two. |

Exit codes: `0` no findings (including the not-fully-analyzed-only case), `1` one or more
findings, `2` scanner error. `--paranoid` findings are findings: a scan that would
otherwise exit `0` exits `1` once the suppressed ledger is surfaced.

# What the baseline self-checksum does and does not prove

`BASELINE_TAMPERED` catches a *hand edit*: a changed hash, a removed `self_checksum`, an
added or altered key, a truncated write. It does not, and cannot, defeat an attacker who
can already write the file: the algorithm is in this repository, so anything with write
access to `~/.malskill/baseline.json` can recompute it. It is an integrity check against
corruption and casual tampering, not an authentication scheme. The store is written `0600`;
the real protection is the permissions on your home directory.

When the store is untrusted, drift and new-target comparison are **skipped** for that run
rather than computed against a file the scanner cannot rely on — "no drift" and "I could
not check" must never look the same.
