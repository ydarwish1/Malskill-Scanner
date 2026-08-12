#!/usr/bin/env python3
"""Draft release notes from a git range. Reads git output on stdin; writes Markdown."""
import re
import sys

PREFIX_RE = re.compile(r"^(feat|fix|docs|perf|refactor|test|chore)(\([^)]*\))?:\s*(.+)$")

SECTIONS = [
    ("feat", "Added"),
    ("fix", "Fixed"),
    ("perf", "Performance"),
    ("docs", "Documentation"),
]


def group(lines):
    buckets = {}
    for line in lines:
        match = PREFIX_RE.match(line.strip())
        if not match:
            continue
        buckets.setdefault(match.group(1), []).append(match.group(3))
    return buckets


def render(buckets):
    out = []
    for key, title in SECTIONS:
        entries = buckets.get(key)
        if not entries:
            continue
        out.append("### %s" % title)
        out.extend("- %s" % entry for entry in entries)
        out.append("")
    return "\n".join(out)


def main():
    sys.stdout.write(render(group(sys.stdin.readlines())))
    return 0


if __name__ == "__main__":
    sys.exit(main())
