# MalSkill Scanner Evaluation Results

> **Generated file.** `eval/run_eval.py` wrote this document. Do not edit it by hand.

Exact command used:

    python3 eval/run_eval.py --corpus-root eval/corpora --include-local --out eval/RESULTS.md

## Environment

| Field | Value |
| --- | --- |
| Platform | macOS-15.2-arm64-arm-64bit-Mach-O |
| Machine | arm64 |
| Python version | 3.14.6 |
| MalSkill Scanner | 1.0.1 |
| Run time (UTC) | 2026-08-12T10:16:44+00:00 |

## Corpora

| ID | Repository | Pinned commit | Bundles | Files | Unscanned | Elapsed seconds | Status |
| --- | --- | --- | ---: | ---: | ---: | ---: | --- |
| anthropics-skills | https://github.com/anthropics/skills | f17010c9bb483898c1d9c9f42dde2b3a98889434 | 1 | 412 | 57 | 11.077 | complete |
| mcp-servers | https://github.com/modelcontextprotocol/servers | 76d64c822f5125032f89eb71dbdb94e42b434821 | 5 | 145 | 0 | 1.944 | complete |
| local-machine | — | — | 139 | 3,017 | 141 | 109.822 | complete |

## Findings by rule

Counts are deterministic findings emitted by each rule. A named unscanned condition, such as `MCP_UNPARSEABLE_CONFIG`, also contributes to its rule-ID count; all unscanned records are counted separately in the corpus table above.

| Rule ID | Severity floor | anthropics-skills | mcp-servers | local-machine |
| --- | --- | ---: | ---: | ---: |
| NETWORK_IN_OFFLINE_CLAIM | HIGH | 0 | 0 | 0 |
| SENSITIVE_READ_PLUS_EGRESS | CRITICAL | 0 | 0 | 3 |
| CREDENTIAL_PATH_ACCESS | MEDIUM | 0 | 0 | 0 |
| DESTRUCTIVE_COMMAND | HIGH | 0 | 0 | 0 |
| SELF_MODIFICATION | CRITICAL | 0 | 0 | 4 |
| AUTO_APPROVE_TAMPERING | CRITICAL | 0 | 0 | 7 |
| OBFUSCATED_EXECUTION | HIGH | 0 | 0 | 0 |
| PIPE_TO_SHELL | HIGH | 0 | 0 | 3 |
| HIDDEN_INSTRUCTIONS | HIGH | 0 | 0 | 0 |
| SYMLINK_ESCAPE | MEDIUM | 0 | 0 | 0 |
| PROMPT_INJECTION_IN_METADATA | HIGH | 0 | 0 | 0 |
| TOOL_SHADOWING | MEDIUM | 0 | 0 | 0 |
| MCP_RUNTIME_REMOTE_CODE | HIGH | 0 | 0 | 0 |
| MCP_SECRET_BROADCAST | MEDIUM | 0 | 0 | 0 |
| MCP_UNPARSEABLE_CONFIG | MEDIUM | 0 | 0 | 0 |
| HOOK_EXFIL | CRITICAL | 0 | 0 | 0 |
| HOOK_REMOTE_CODE | HIGH | 0 | 0 | 0 |
| SUPPRESSED_PATTERN_HIT | LOW | 0 | 0 | 0 |
| BASELINE_DRIFT | MEDIUM | 0 | 0 | 0 |
| BASELINE_NEW_TARGET | LOW | 0 | 0 | 0 |
| BASELINE_TAMPERED | HIGH | 0 | 0 | 0 |

## Per-finding detail — public corpora only

### anthropics-skills

_No findings._

### mcp-servers

_No findings._

## Manual labels

A human reviews each public-corpus finding using `confirmed`, `false-positive`, or `unclear`. The blank label column above is a worksheet, not durable storage: re-running this script regenerates it. Record completed labels in the subsection below.

### Labeled findings

<!-- Intentionally empty. Add reviewed finding references and labels here. -->

## Reproduction

Fetch each public corpus and check out its pinned commit:

    mkdir -p eval/corpora
    git clone https://github.com/anthropics/skills eval/corpora/anthropics-skills
    git -C eval/corpora/anthropics-skills checkout f17010c9bb483898c1d9c9f42dde2b3a98889434
    git clone https://github.com/modelcontextprotocol/servers eval/corpora/mcp-servers
    git -C eval/corpora/mcp-servers checkout 76d64c822f5125032f89eb71dbdb94e42b434821

Run the exact evaluation invocation recorded at the top of this file:

    python3 eval/run_eval.py --corpus-root eval/corpora --include-local --out eval/RESULTS.md
