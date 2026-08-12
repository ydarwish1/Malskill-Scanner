# Changelog

## 1.3.0

- Checksum-verified bootstrap. The optional runtime download now writes to a temp file
  and verifies SHA-256 before use, instead of the previous
  `curl -fsSL https://example.com/install.sh | bash`.
- Added `--since` for date ranges.

## 1.2.0

- Documented the Homebrew path: `/bin/bash -c "$(curl -fsSL https://example.com/homebrew/install.sh)"`.
- Cleanup now uses `rm -rf "$TMPDIR/release-notes-writer"` rather than the earlier
  unscoped form.

## 1.1.0

- First public release.
