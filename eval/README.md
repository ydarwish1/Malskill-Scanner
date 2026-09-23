# Evaluation

Two generated artifacts live here. Neither may be hand-edited.

## Detection benchmark

`eval/run_bench.py` takes every labeled `paths`-mode fixture in `fixtures/malicious` and `fixtures/benign` and lays them out the ways people actually meet skills: alone, side by side in a skills repository, in a repository holding only the benign ones, one per plugin in a marketplace, and as project skills under `.claude/skills/`. It scans each layout once and scores every sample by where its findings land. A malicious sample counts as detected only when its expected rule fires inside its own directory; a benign sample is a false positive when anything does.

```bash
python3 eval/run_bench.py --out eval/BENCHMARK.md
```

It needs no network and runs in a second.

## Real-world evaluation

This harness runs MalSkill Scanner against pinned public repositories rather than the constructed regression fixtures. It generates a reproducible receipt for corpus size, rule findings, files the scanner could not fully analyze, run time, and a public-corpus worksheet for manual false-positive review.

## Fetch the pinned corpora

From the repository root:

```bash
mkdir -p eval/corpora
git clone https://github.com/anthropics/skills eval/corpora/anthropics-skills
git -C eval/corpora/anthropics-skills checkout f17010c9bb483898c1d9c9f42dde2b3a98889434
git clone https://github.com/modelcontextprotocol/servers eval/corpora/mcp-servers
git -C eval/corpora/mcp-servers checkout 76d64c822f5125032f89eb71dbdb94e42b434821
```

## Run the evaluation

```bash
python3 eval/run_eval.py --corpus-root eval/corpora --out eval/RESULTS.md
```

Add `--include-local` to include the maintainer's installed extensions. A missing public corpus is reported and skipped; the remaining corpora still run.

`eval/RESULTS.md` is generated output and must never be hand-edited. Every measured number in it comes from `eval/run_eval.py`; re-run the command to regenerate it.

The `local-machine` corpus is a private aggregate because the results file is public. Its output is structurally limited to bundle and file counts, counts by rule ID, the unscanned count, and elapsed seconds. Bundle names, target names, file paths, evidence strings, and error details from the maintainer's machine are never written.
