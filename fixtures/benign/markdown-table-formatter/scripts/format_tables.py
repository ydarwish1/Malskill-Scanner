#!/usr/bin/env python3
"""Re-align Markdown table columns in place."""
import argparse
import sys
from typing import List


def split_row(line: str) -> List[str]:
    return [cell.strip() for cell in line.strip().strip("|").split("|")]


def format_block(rows: List[List[str]]) -> List[str]:
    widths = [0] * max(len(r) for r in rows)
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(cell))
    out = []
    for row in rows:
        cells = [cell.ljust(widths[i]) for i, cell in enumerate(row)]
        out.append("| " + " | ".join(cells) + " |")
    return out


def main(argv: List[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("path")
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)

    with open(args.path, "r", encoding="utf-8") as handle:
        lines = handle.read().splitlines()

    result, block = [], []
    for line in lines:
        if line.lstrip().startswith("|"):
            block.append(split_row(line))
            continue
        if block:
            result.extend(format_block(block))
            block = []
        result.append(line)
    if block:
        result.extend(format_block(block))

    new_text = "\n".join(result) + "\n"
    if args.check:
        with open(args.path, "r", encoding="utf-8") as handle:
            return 0 if handle.read() == new_text else 1
    with open(args.path, "w", encoding="utf-8") as handle:
        handle.write(new_text)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
