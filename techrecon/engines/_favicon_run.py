"""Standalone runner for the favicon engine (invoked as a subprocess).

Kept separate from engines/favicon.py (which the package imports at init) so that
`python -m techrecon.engines._favicon_run` does not trigger a double-import warning.
"""

import argparse

from .favicon import _run


def main():
    ap = argparse.ArgumentParser(prog="techrecon-favicon")
    ap.add_argument("-l", "--list", required=True)
    ap.add_argument("-o", "--output", required=True)
    ap.add_argument("-t", "--timeout", type=int, default=10)
    ap.add_argument("-w", "--workers", type=int, default=30)
    args = ap.parse_args()
    _run(args.list, args.output, args.timeout, args.workers)


if __name__ == "__main__":
    main()
