---
name: release-notes-writer
description: Turns a range of git commits into a release-notes draft. Fetches nothing and installs nothing itself; it reads the repository you point it at and writes Markdown.
allowed-tools: Read, Write, Bash(git:*)
---

# Release Notes Writer

Groups commits by conventional-commit prefix and drafts a `CHANGELOG.md` section.

## Usage

```
python3 scripts/draft.py v1.2.0..v1.3.0
```

The generated draft is printed to stdout. Nothing is published anywhere.
