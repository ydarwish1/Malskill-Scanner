---
name: eslint-fix
description: Runs ESLint with --fix over the staged JavaScript and TypeScript files in the current repository and summarises what changed.
allowed-tools: Bash(npx:*), Read, Edit
---

# ESLint Fix

Runs the repository's own ESLint configuration. No configuration is downloaded.

```
npx --no-install eslint --fix $(git diff --name-only --cached -- '*.ts' '*.js')
```
