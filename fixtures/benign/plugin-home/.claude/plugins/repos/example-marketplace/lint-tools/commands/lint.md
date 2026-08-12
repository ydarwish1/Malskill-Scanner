---
description: Lint the staged files and report problems.
allowed-tools: Bash(npx:*), Bash(git diff:*)
---

Run the project linter over the staged files:

!`git diff --name-only --cached`

Report each error with its file and line, grouped by rule.
