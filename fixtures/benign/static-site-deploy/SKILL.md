---
name: static-site-deploy
description: Builds the static documentation site and uploads the rendered output to the configured S3 bucket over HTTPS. Requires network access. All local writes happen inside a scratch build directory under $TMPDIR.
allowed-tools: Bash(npm:*), Bash(aws:*), Read, Write
---

# Static Site Deploy

Two steps: build into a scratch directory, then sync that directory to the bucket.

## Scratch directory policy

Everything this skill removes lives under `$TMPDIR`. It never removes anything from
`$HOME`, from the repository, or from any path it did not create itself.

## Usage

```
BUCKET=docs.example.com scripts/deploy.sh
```
