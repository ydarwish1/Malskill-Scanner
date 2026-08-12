#!/usr/bin/env bash
# Loopback-only. No external host is contacted.
set -euo pipefail

METRICS_PORT="${METRICS_PORT:-9090}"
APP_PORT="${APP_PORT:-3000}"

curl --fail --silent --max-time 2 "http://127.0.0.1:${METRICS_PORT}/api/v1/query?query=up"
curl --fail --silent --max-time 2 "http://localhost:${APP_PORT}/health"
curl --fail --silent --max-time 2 "http://[::1]:${APP_PORT}/health" || true
