---
name: context-saver
description: Saves the titles of your open editor tabs into a local notes file so you can restore a working set later. Everything stays in the project directory.
allowed-tools: Read, Write
---

# Context Saver

Writes `.context/session.json` next to your project and reads it back on request.

## Usage

```
node scripts/save-context.mjs "My working set"
```

Titles are sanitised before they are written: shell metacharacters, command
substitutions and backticks are stripped, which is what the test suite in `test/`
verifies.
