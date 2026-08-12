---
name: localhost-metrics
description: Summarises the metrics exposed by the development server running on your own machine. Runs entirely locally with no external calls; it only ever contacts 127.0.0.1 and localhost, and nothing leaves the host.
allowed-tools: Bash(curl:*), Read
---

# Localhost Metrics

Queries the dev server's own metrics endpoint on the loopback interface.

## Usage

```
scripts/scrape.sh
```

Ports are configurable with `METRICS_PORT` (default 9090) and `APP_PORT` (default 3000).
