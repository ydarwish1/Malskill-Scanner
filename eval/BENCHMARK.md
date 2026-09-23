# MalSkill Scanner Benchmark

> **Generated file.** `eval/run_bench.py` wrote this document. Do not edit it by hand.

Command: `python3 eval/run_bench.py --out eval/BENCHMARK.md`  
Scanner version: 1.0.1

A malicious sample counts as detected only when its expected rule fires on a file
inside that sample's own directory. A benign sample is a false positive when any
finding lands inside its directory. `13` malicious and `10` benign samples.

## Summary

| Layout | What it models | Bundles seen | Detected | Detection rate | False positives | FP rate |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| standalone | each sample scanned alone (`--paths <sample>`) | 23 | 13/13 | 100.0% | 0/10 | 0.0% |
| skills-repo | all samples in one repo under `skills/<name>/` | 1 | 10/13 | 76.9% | 0/10 | 0.0% |
| clean-skills-repo | only the benign samples, one repo under `skills/<name>/` | 1 | 0/0 | n/a | 1/10 | 10.0% |
| plugin-marketplace | one plugin per sample under `plugins/<p>/skills/<name>/` | 1 | 10/13 | 76.9% | 0/10 | 0.0% |
| project-skills | all samples in an app repo under `.claude/skills/<name>/` | 3 | 10/13 | 76.9% | 0/10 | 0.0% |

## Per sample

| Sample | Label | Expected | standalone | skills-repo | clean-skills-repo | plugin-marketplace | project-skills |
| --- | --- | --- | --- | --- | --- | --- | --- |
| network_in_offline_claim | malicious | NETWORK_IN_OFFLINE_CLAIM | ok (NETWORK_IN_OFFLINE_CLAIM) | **MISS** (-) | not placed | **MISS** (-) | **MISS** (-) |
| network_in_offline_claim_negated_phrasing | malicious | NETWORK_IN_OFFLINE_CLAIM | ok (NETWORK_IN_OFFLINE_CLAIM) | **MISS** (-) | not placed | **MISS** (-) | **MISS** (-) |
| sensitive_read_plus_egress | malicious | SENSITIVE_READ_PLUS_EGRESS | ok (SENSITIVE_READ_PLUS_EGRESS) | ok (SENSITIVE_READ_PLUS_EGRESS) | not placed | ok (SENSITIVE_READ_PLUS_EGRESS) | ok (SENSITIVE_READ_PLUS_EGRESS) |
| credential_path_access | malicious | CREDENTIAL_PATH_ACCESS | ok (CREDENTIAL_PATH_ACCESS) | **MISS** (-) | not placed | **MISS** (-) | **MISS** (-) |
| destructive_command | malicious | DESTRUCTIVE_COMMAND | ok (DESTRUCTIVE_COMMAND) | ok (DESTRUCTIVE_COMMAND) | not placed | ok (DESTRUCTIVE_COMMAND) | ok (DESTRUCTIVE_COMMAND) |
| self_modification | malicious | SELF_MODIFICATION | ok (CREDENTIAL_PATH_ACCESS, SELF_MODIFICATION) | ok (SELF_MODIFICATION) | not placed | ok (SELF_MODIFICATION) | ok (SELF_MODIFICATION) |
| auto_approve_tampering | malicious | AUTO_APPROVE_TAMPERING | ok (AUTO_APPROVE_TAMPERING) | ok (AUTO_APPROVE_TAMPERING) | not placed | ok (AUTO_APPROVE_TAMPERING) | ok (AUTO_APPROVE_TAMPERING) |
| obfuscated_execution | malicious | OBFUSCATED_EXECUTION | ok (OBFUSCATED_EXECUTION) | ok (OBFUSCATED_EXECUTION) | not placed | ok (OBFUSCATED_EXECUTION) | ok (OBFUSCATED_EXECUTION) |
| pipe_to_shell | malicious | PIPE_TO_SHELL | ok (PIPE_TO_SHELL) | ok (PIPE_TO_SHELL) | not placed | ok (PIPE_TO_SHELL) | ok (PIPE_TO_SHELL) |
| hidden_instructions | malicious | HIDDEN_INSTRUCTIONS | ok (HIDDEN_INSTRUCTIONS) | ok (HIDDEN_INSTRUCTIONS) | not placed | ok (HIDDEN_INSTRUCTIONS) | ok (HIDDEN_INSTRUCTIONS) |
| prompt_injection_in_metadata | malicious | PROMPT_INJECTION_IN_METADATA | ok (PROMPT_INJECTION_IN_METADATA) | ok (PROMPT_INJECTION_IN_METADATA) | not placed | ok (PROMPT_INJECTION_IN_METADATA) | ok (PROMPT_INJECTION_IN_METADATA) |
| tool_shadowing | malicious | TOOL_SHADOWING | ok (TOOL_SHADOWING) | ok (TOOL_SHADOWING) | not placed | ok (TOOL_SHADOWING) | ok (TOOL_SHADOWING) |
| auto_approve_tampering_reference_hop | malicious | AUTO_APPROVE_TAMPERING | ok (AUTO_APPROVE_TAMPERING) | ok (AUTO_APPROVE_TAMPERING) | not placed | ok (AUTO_APPROVE_TAMPERING) | ok (AUTO_APPROVE_TAMPERING) |
| api-weather-fetch | benign | - | ok (-) | ok (-) | ok (-) | ok (-) | ok (-) |
| ssh-key-manager | benign | - | ok (-) | ok (-) | **FP** (SENSITIVE_READ_PLUS_EGRESS) | ok (-) | ok (-) |
| security-review-docs | benign | - | ok (-) | ok (-) | ok (-) | ok (-) | ok (-) |
| static-site-deploy | benign | - | ok (-) | ok (-) | ok (-) | ok (-) | ok (-) |
| localhost-metrics | benign | - | ok (-) | ok (-) | ok (-) | ok (-) | ok (-) |
| markdown-table-formatter | benign | - | ok (-) | ok (-) | ok (-) | ok (-) | ok (-) |
| docs-install-oneliner | benign | - | ok (-) | ok (-) | ok (-) | ok (-) | ok (-) |
| test-suite-injection-strings | benign | - | ok (-) | ok (-) | ok (-) | ok (-) | ok (-) |
| localhost-only-diagram | benign | - | ok (-) | ok (-) | ok (-) | ok (-) | ok (-) |
| docs-reference-link | benign | - | ok (-) | ok (-) | ok (-) | ok (-) | ok (-) |
