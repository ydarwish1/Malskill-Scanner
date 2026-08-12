# Benign corpus

Eleven realistic bundles. Every one of them contains something a keyword scanner would
flag, and none of them is a finding. `MANIFEST.json` records, for each bundle, the trap
it exists to catch; `NOTES.md` explains each trap in prose.

The bundles themselves carry only the documentation a real skill would ship. Commentary
about *why* a bundle is in the corpus is kept in `NOTES.md`, outside every bundle,
because the claims model reads top-level Markdown - a note saying "this is a credential
manager" would do the scanner's work for it.

Two shapes of fixture live here:

- `mode: paths` - a skill bundle. Scanned with `--paths <bundle>`.
- `mode: home` - a home-shaped tree (`.claude/`, `.claude.json`, `.mcp.json`). Copied to
  a temp directory and scanned with `--home <copy>`.

The suite scans this directory as a whole (`--paths fixtures/benign`) *and* each bundle
individually. The whole-directory scan requires the scanner to treat each subdirectory
as its own bundle: the corpus deliberately spreads a credential-reading bundle and a
network-using bundle across two directories, and merging them into one logical bundle
would manufacture a cross-bundle finding that does not exist.

Nothing here should ever produce a finding. If it does, fix the rule, not the fixture.
