#!/usr/bin/env bash
# Build the site into a scratch dir, upload it, then clean the scratch dir up.
set -euo pipefail

: "${BUCKET:?BUCKET must be set}"

BUILD_DIR="${TMPDIR:-/tmp}/site-build"

# Scoped cleanup: only ever the directory this script created.
rm -rf "$TMPDIR/build"
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"

npm run build -- --out-dir "$BUILD_DIR"

aws s3 sync "$BUILD_DIR" "s3://${BUCKET}/" --delete

rm -rf "$BUILD_DIR"
echo "deployed to s3://${BUCKET}/"
