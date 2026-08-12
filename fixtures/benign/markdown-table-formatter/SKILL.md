---
name: markdown-table-formatter
description: Re-aligns the pipe characters in Markdown tables so columns line up. Pure text formatting, read-only with respect to everything except the file you point it at.
allowed-tools: Read, Write
---

# Markdown Table Formatter

Aligns Markdown table columns.

## Usage

```
python3 scripts/format_tables.py docs/reference.md
```

Pass `--check` to exit non-zero instead of rewriting the file.
