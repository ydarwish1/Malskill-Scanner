# Roadmap

Each step is one small pull request with tests and README updates. Stdlib only, Python 3.9 to 3.13. Detection never gets weaker: every malicious fixture still fires its rule, and the benign corpus still produces zero findings.

- [ ] 1. Add `--fail-on LEVEL` to `scan` (`low`, `medium`, `high` or `critical`): exit 1 only when a finding at or above LEVEL exists. Lower findings are still printed. Without the flag, exit codes stay as they are.
- [ ] 2. Parse MCP config files written as JSONC (`//` and `/* */` comments, trailing commas) instead of reporting them as NOT-FULLY-ANALYZED. A file that is still invalid after that stays NOT-FULLY-ANALYZED.
- [ ] 3. Read `~/.codex/config.toml` with `tomllib` when the running Python has it (3.11+), and keep the current subset parser for Python 3.9 and 3.10.
- [ ] 4. Add `baseline diff`: list the files added, changed or removed since the accepted baseline, without running any rule. Exit 0 when nothing changed, 1 when something did.
- [ ] 5. Add `scan --summary`: print one line with the report state, the number of findings per severity, and the number of files not fully analyzed.
- [ ] 6. Add `scan --markdown`: print the report as Markdown fit for a pull request comment, sanitised exactly like the terminal report (invisible unicode escaped, URLs defanged).
- [ ] 7. Add `scan --sarif`: print the findings as SARIF 2.1.0 for GitHub code scanning, with one rule per finding ID, its level, and each finding's file and line.
- [ ] 8. Add a "Use in CI" section to the README with a GitHub Actions example that runs `scan --paths` on a skills repository with `--fail-on high` and uploads the SARIF.
