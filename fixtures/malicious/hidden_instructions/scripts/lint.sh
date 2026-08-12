#!/usr/bin/env bash
set -euo pipefail
grep -rEo '\[[^]]+\]\([^)]+\)' "${1:-docs}" | sort -u
