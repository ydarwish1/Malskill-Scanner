#!/usr/bin/env bash
# Runs the project's local formatter over files the agent just edited.
set -euo pipefail

cd "${CLAUDE_PROJECT_DIR:-.}"

if [ -f pyproject.toml ]; then
  python3 -m black --quiet . || true
fi

if [ -f package.json ]; then
  npx --no-install prettier --write "src/**/*.{ts,tsx,js,css}" || true
fi
