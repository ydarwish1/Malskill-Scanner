# MalSkill Scanner

Audits the AI agent extensions already installed on your machine (Claude Code skills, plugins, commands, agents, hooks, MCP servers) and flags the ones whose contents would push an agent to act against you. Python 3.9+, stdlib only, nothing to install.

```bash
./bin/malskill scan               # audit everything installed on this machine
./bin/malskill baseline update    # accept what's there now; future scans flag what changed
```

A finding looks like this:

```
[CRITICAL] SENSITIVE_READ_PLUS_EGRESS   skill:pdf-tools  scripts/collect.sh:5
  evidence: reads ~/.aws/credentials ... sends to hxxps://collector[.]attacker[.]example[.]net
  why: Read-a-secret plus send-it-somewhere, inside one bundle that runs with your
       agent's privileges, is the exact shape of credential theft.
  recommendation: Remove this skill, then rotate anything it could have reached.
```

Every report ends in one of three states: `FLAGGED`, `CLEAN`, or `NOT-FULLY-ANALYZED`. It never says "safe", because it can't prove that. A file it couldn't read is listed loudly, not dropped.

## How it decides

Keyword scanning doesn't work at real scale. Measured on one machine: 867 installed bundles, 14,444 files. `curl` appears in 284 of those bundles. Flag that and the report becomes a wall the human learns to skim, and the one real finding scrolls past.

So the scanner flags contradictions instead of keywords:

- `curl` in a skill that declares network use: nothing.
- `curl` in a skill that claims it works offline: `NETWORK_IN_OFFLINE_CLAIM`.
- Reading `~/.ssh` in a declared credential manager: nothing.
- Reading `~/.ssh` in the same bundle that posts to an external host: `SENSITIVE_READ_PLUS_EGRESS`.

Where a pattern lives matters too. A `curl | bash` one-liner quoted in a README is documentation; the same line in a script or a SKILL.md an agent obeys is behavior. Documentation hits are counted and disclosed, not flagged (rerun with `--paranoid` to see them).

The rules are deterministic. The optional AI explainer (`--explain`) runs with zero tools and can only raise a finding's severity or add context. It can never clear one, so a malicious bundle can't talk its way out.

Detection runs on raw bytes. Only the copy shown to you is sanitized: invisible unicode escaped, URLs defanged. Reading a report can't itself be the attack.

## What it scans

- Claude Code skills, plugins, commands, agents (user and project level)
- Hook commands in `settings.json`
- MCP server configs: `~/.claude.json`, `.mcp.json`, Claude Desktop, and `--all-clients` for Cursor and others
- A baseline of every file's hash, so a skill you trusted last week gets flagged when an update changes it

## Commands

```bash
./bin/malskill scan                # full audit
./bin/malskill scan --json         # machine-readable report
./bin/malskill scan --paths DIR    # audit a specific bundle instead of discovery
./bin/malskill scan --paranoid     # include hits suppressed in docs/test context
./bin/malskill scan --explain      # add the zero-tool AI explainer
./bin/malskill list                # show what would be scanned, run no rules
./bin/malskill rules               # print every rule and what fires it
./bin/malskill baseline update     # accept current state
```

Exit codes: 0 no findings, 1 findings, 2 scanner error.

## Docs

- [docs/RULES.md](docs/RULES.md): every finding ID, what fires it, why it matters, and how it can be wrong
- [docs/BLUEPRINT.md](docs/BLUEPRINT.md): the spec this was built against
- [tests/README.md](tests/README.md): the test suite and fixture corpus

Tests: `python3 -m unittest discover -s tests`. The bar, asserted in the suite: a known-benign corpus full of curl-using, ssh-reading, injection-quoting bundles must produce zero findings.
