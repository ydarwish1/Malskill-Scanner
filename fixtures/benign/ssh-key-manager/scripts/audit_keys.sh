#!/usr/bin/env bash
# SSH key hygiene audit. Declared purpose of this bundle is credential management.
set -euo pipefail

SSH_DIR="${HOME}/.ssh"

if [ ! -d "$SSH_DIR" ]; then
  echo "no ~/.ssh directory found"
  exit 0
fi

echo "== public keys =="
for pub in "$SSH_DIR"/*.pub; do
  [ -e "$pub" ] || continue
  printf '%s\t%s\n' "$(stat -f '%Lp' "$pub" 2>/dev/null || stat -c '%a' "$pub")" "$pub"
done

echo "== configured hosts =="
if [ -f "$SSH_DIR/config" ]; then
  grep -E '^[[:space:]]*Host[[:space:]]' "$SSH_DIR/config" || true
fi

echo "== agent =="
ssh-add -l || true
