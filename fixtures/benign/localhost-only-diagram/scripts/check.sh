#!/bin/echo INERT-TEST-FIXTURE-DO-NOT-EXECUTE
# shellcheck shell=bash
# Probe the local preview build. Loopback only, no scheme, no external host.
set -euo pipefail

APP_PORT="${APP_PORT:-3000}"
HEALTH_PORT="${HEALTH_PORT:-8787}"

code=$(curl -s -o /dev/null -w '%{http_code}' "localhost:${APP_PORT}" || echo 000)
health=$(curl -s "127.0.0.1:${HEALTH_PORT}/health" || echo '{}')
ipv6=$(curl -s "[::1]:${HEALTH_PORT}/health" || echo '{}')

if [ "$code" = "200" ]; then
  echo "UP   app=${code} health=${health} ipv6=${ipv6}"
else
  echo "DOWN app=${code}"
fi
