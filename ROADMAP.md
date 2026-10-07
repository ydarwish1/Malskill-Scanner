# Roadmap

Each step is one small pull request with tests and README updates. Stdlib only, Python 3.9 to 3.13. Detection never gets weaker: every malicious fixture still fires its rule, and the benign corpus still produces zero findings.

- [x] 1. Add `--fail-on LEVEL` to `scan` (`low`, `medium`, `high` or `critical`): exit 1 only when a finding at or above LEVEL exists. Lower findings are still printed. Without the flag, exit codes stay as they are.
- [x] 2. Parse MCP config files written as JSONC (`//` and `/* */` comments, trailing commas) instead of reporting them as NOT-FULLY-ANALYZED. A file that is still invalid after that stays NOT-FULLY-ANALYZED.
- [x] 3. Read `~/.codex/config.toml` with `tomllib` when the running Python has it (3.11+), and keep the current subset parser for Python 3.9 and 3.10.
- [x] 4. Add `baseline diff`: list the files added, changed or removed since the accepted baseline, without running any rule. Exit 0 when nothing changed, 1 when something did.
- [x] 5. Add `scan --summary`: print one line with the report state, the number of findings per severity, and the number of files not fully analyzed.
- [x] 6. Add `scan --markdown`: print the report as Markdown fit for a pull request comment, sanitised exactly like the terminal report (invisible unicode escaped, URLs defanged).
- [x] 7. Fix a detection regression from steps 2 and 3: a config file over 2 MiB (`~/.claude.json`, `.mcp.json`, a client config, `~/.codex/config.toml`) is now only NOT-FULLY-ANALYZED and exits 0, so a malicious server followed by whitespace or comment padding is no longer flagged. Run the rules on the first 2 MiB again, as before step 2, and also list the file as NOT-FULLY-ANALYZED. A test pads a malicious server past 2 MiB, in JSON and in TOML, and expects its finding and exit 1.
- [x] 8. Fix a detection regression from step 3: on Python 3.9 and 3.10, one dotted key (such as `telemetry.enabled = true`) anywhere in `~/.codex/config.toml` makes the whole file NOT-FULLY-ANALYZED, so its servers are no longer scanned. Parse dotted keys into nested tables, as TOML does, on their own lines and inside inline tables. A test, with the subset parser forced, expects a malicious server next to a dotted key to be flagged.
- [ ] 9. Fix two odd-input gaps: a JSON or JSONC config nested too deep for Python's parser stops the whole scan with exit 2 (RecursionError) instead of being listed as NOT-FULLY-ANALYZED; and `baseline diff` says "Every discovered file was hashed and compared" when a file over 64 MiB was hashed only in part. List both under NOT-FULLY-ANALYZED.
- [ ] 10. Add `scan --sarif`: print the findings as SARIF 2.1.0 for GitHub code scanning, with one rule per finding ID, its level, and each finding's file and line.
- [ ] 11. Add a "Use in CI" section to the README with a GitHub Actions example that runs `scan --paths` on a skills repository with `--fail-on high` and uploads the SARIF.
