# Benign corpus

Fourteen realistic bundles. Every one contains something a keyword scanner would flag,
and none of them is a finding. `MANIFEST.json` records the trap each bundle exists to
catch; the table below is the same thing in prose.

The bundles themselves carry only the documentation a real skill would ship. Commentary
about why a bundle is in the corpus stays in this file, which sits above every bundle
directory, because the claims model reads a bundle's top-level Markdown and a note
saying "this is a credential manager" would do the scanner's work for it.

## The bar

Nothing here produces a finding. If something does, fix the rule, not the fixture.

## What each bundle is a trap for

| bundle | mode | trap |
| --- | --- | --- |
| `api-weather-fetch` | paths | Uses an HTTP client and declares it twice, in the frontmatter description and in `allowed-tools`. The primitive alone is never a finding. |
| `ssh-key-manager` | paths | Reads the SSH config directory, and key management is its declared purpose, so the credential-path rule is suppressed by the mismatch principle. No egress primitive anywhere. |
| `security-review-docs` | paths | Its prose quotes attacker phrasings while teaching a reviewer to spot them. The injection rule is scoped to metadata fields, not README prose. A broader rule flags every security document, including this repository's own. |
| `static-site-deploy` | paths | Recursive removal scoped to a scratch directory the script created under `$TMPDIR`. Scoped cleanup is build hygiene. |
| `localhost-metrics` | paths | Claims to run locally and contacts an HTTP endpoint. Every target is loopback, which the mismatch rule exempts. |
| `markdown-table-formatter` | paths | The control. No network, no credentials, no shell. A finding here means the engine is broken. |
| `docs-install-oneliner` | paths | README, CHANGELOG, CONTRIBUTING and `docs/DESIGN.md` quote the official pipe-to-shell installer, the Homebrew form, a self-install copy into `~/.claude/skills`, a symlink into `.claude/skills` and the skip-permissions flag. Documentation is role `DOCS`; behaviour rules fire only from `EXECUTABLE` and `INSTRUCTION`. Run with `--paranoid` and every match shows up as `SUPPRESSED_PATTERN_HIT` [LOW]. |
| `test-suite-injection-strings` | paths | Injection-hardening tests whose input fixtures are the dangerous commands, the whole point being that the command is rejected. Covers `test/` and `tests/`, `*.test.ts` and `test_*.py`. A scanner that flags these flags every security test suite on the machine. |
| `localhost-only-diagram` | paths | Claims offline and does contact endpoints, all loopback and most written without a URL scheme (`localhost:3000`, `127.0.0.1:8787/health`, `[::1]:8787/health`). A host matcher that only understands `scheme://host` sees no destination and treats unknown as external. That is how a diagram line in a SKILL.md became half of a CRITICAL pairing on a real machine. |
| `mcp-config-standard` | home | `npx -y @scope/pkg@1.2.3`, `uvx pkg==0.4.1`, a pinned container image, a project-scoped server. Version-pinned package managers are the ecosystem norm. No credential-shaped value in any env block. |
| `hook-local-formatter` | home | A `PostToolUse` hook that shells out to a local formatter. Hook command strings get the full byte-rule pass and this one has no egress primitive. |
| `settings-with-permissions` | home | A user's own settings file legitimately contains a `permissions.allow` array. The auto-approve rule fires on bundle content that writes an allow-list, never on a settings file that has one. The broader reading flags every real machine on day one. |
| `plugin-home` | home | An installed marketplace plugin with a skill, a slash command and a local hook. Plugin discovery must not manufacture findings; the marketplace URL is a repository reference, not egress. |
| `home-user-skills` | home | User-level discovery of `~/.claude/skills`, `~/.claude/commands` and `~/.claude/agents` with entirely ordinary content. |

## Fixture shapes

`mode: paths` is a skill bundle, scanned with `--paths <bundle>`. `mode: home` is a
home-shaped tree (`.claude/`, `.claude.json`, `.mcp.json`), copied to a temp directory
and scanned with `--home <copy>`.

The suite scans this directory as a whole (`--paths fixtures/benign`) and each bundle on
its own. The whole-directory scan requires the scanner to treat each subdirectory as its
own bundle: the corpus deliberately spreads the credential-reading bundle and the
network-using bundle across two directories, and merging them into one logical bundle
would manufacture a cross-bundle finding that does not exist.
