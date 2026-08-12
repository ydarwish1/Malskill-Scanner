# Design notes

## Landing page (for reference)

The upstream download page is a single column. Below the hero headline sits a copy box
containing the literal `curl -fsSL https://example.com/install.sh | sh` command with a
small copy icon at its right edge; it is the page's most prominent call to action.

This document describes somebody else's webpage. It executes nothing.

## Draft pipeline

1. `git log --format=%H%x00%s` over the requested range.
2. Group by conventional-commit prefix.
3. Emit Markdown.

## Permissions

The skill declares `Read`, `Write` and `Bash(git:*)`. It deliberately does not ask for
`--dangerously-skip-permissions`, and the sandboxed evaluation harness that the upstream
project uses for benchmarking is out of scope here.
