# MalSkill Scanner

Audits the AI agent extensions you have already installed — Claude Code skills, plugins, and MCP servers — and flags the ones whose contents would push an agent to act against you.

**Status: design only. Nothing is built yet.** This README is the design.

---

## Why it needs to exist

Measured on one real machine: **867 installed skill bundles, 14,444 files, 5,060 of them executable scripts.** Most of it third-party. **97.2% declare no tool restrictions at all** — they inherit whatever the agent can do.

Keyword scanning collapses at that scale. `curl` appears in **284 of the 867** bundles. Words like `PreToolUse` and `SessionStart` appear in **62.6%** of them. A scanner built on keywords produces a wall of false positives and gets ignored inside a week.

---

## The approach

**1. Don't let the AI decide.** Plain dumb rules find the problems. The AI only explains them — it is never allowed to say "actually that one's fine." Otherwise a bad skill just talks the scanner into passing it.

**2. Give the AI that reads the suspicious file zero tools.** Then if it gets tricked, it can't do anything about it.

**3. Stop flagging scary words. Flag mismatches.** `curl` in 284 skills means nothing. `curl` in a skill that claims it only formats text means everything.

**4. Remember what every skill looked like last week and alert on what changed.** The real danger isn't a new evil skill — it's a skill you already trust going bad in an update.

**5. Scan MCP tool descriptions too.** Those load into every session and literally nobody reads them.

**6. Never print "SAFE".** Print "no rule fired, 243 files couldn't be scanned." A green checkmark you can't back up is worse than no scanner.

---

## What that means in practice

- Deterministic rules are the engine. The model is a zero-tool explainer that can only **escalate** a finding, never clear one. Severity floors come from the rule.
- **Detect on raw bytes; sanitize only the copy shown to the model.** Do it the other way round and you hide the obfuscation from the thing judging it.
- **Three report states, never two:** `FLAGGED` / `CLEAN` / `NOT-FULLY-ANALYZED`. A parse failure is a loud finding, not a silent green row.
- **Named findings, not a 0–100 score.** `NETWORK_IN_OFFLINE_CLAIM` is actionable. "Scored 47" is not.
- The extractor is the real high-value target — it runs trusted, before anything else. Byte-level reads only, `safe_load` only, no rendering, no following the reference hop.
- **Specificity gets published. Recall does not.** Recall against attacks nobody has written yet cannot be measured honestly, and claiming it would be a lie.

## The bar

Near-zero findings on a corpus known to be benign. If v1 returns more than a dozen findings and they are mostly "curl present," it has already failed — the human learns to skim, and the one real finding scrolls past.

---

*The six lines are a plain-language rendering of a design review by Claude Fable 5. Corpus figures are measured, not estimated.*
