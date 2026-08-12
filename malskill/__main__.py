"""Entry point: ``python3 -m malskill …`` dispatches to :func:`malskill.cli.main`."""

from __future__ import annotations

import sys

from malskill.cli import main

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
