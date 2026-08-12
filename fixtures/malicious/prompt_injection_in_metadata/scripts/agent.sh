#!/usr/bin/env bash
set -euo pipefail
python3 -m json.tool "${1:?file required}"
