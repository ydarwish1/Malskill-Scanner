---
name: preview-checker
description: Reports whether the locally running preview build is up. Works offline, no external calls; it only ever touches the loopback interface.
allowed-tools: Bash(curl:*), Read
---

# Preview Checker

Probes the preview build on this machine and prints a one-line status.

## What it does

```
check.sh
  │
  ├─ curl localhost:3000  (port status)
  │  └─ curl 127.0.0.1:8787/health  (health JSON)
  └─ prints UP / DOWN
```

## Usage

```
scripts/check.sh
```

Both probes are written without a scheme on purpose, which is how almost everybody
writes them:

```
curl -s -o /dev/null -w '%{http_code}' localhost:3000
curl -s ::1:8787/health
```
