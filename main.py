#!/usr/bin/env python3
"""Entry point for the privesc script"""

import argparse
import sys
from pathlib import Path

# Allow running from the project root
sys.path.insert(0, str(Path(__file__).parent))

from core.context import build_context
from core.reporter import Reporter
from core.runner import Runner


def parse_args():
    parser = argparse.ArgumentParser(
        description="Just Another Privesc Script",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument(
        "--quick", action="store_true",
        help="Skip slow modules (large filesystem searches)",
    )
    parser.add_argument(
        "--module", metavar="NAME",
        help="Run a single module by name",
    )
    parser.add_argument(
        "--tags", metavar="TAG[,TAG]",
        help="Only run modules with these tags (comma-separated)",
    )
    parser.add_argument(
        "--skip-tags", metavar="TAG[,TAG]",
        help="Skip modules with these tags",
    )
    parser.add_argument(
        "--output", metavar="DIR",
        help="Directory to write JSON and text reports (created if needed)",
    )
    parser.add_argument(
        "--no-color", action="store_true",
        help="Disable colored output",
    )
    parser.add_argument(
        "--list", action="store_true",
        help="List available modules and exit",
    )
    return parser.parse_args()


def main():
    args = parse_args()

    reporter = Reporter(
        output_dir=args.output,
        no_color=args.no_color,
    )
    runner = Runner(
        reporter=reporter,
        quick=args.quick,
        only_module=args.module,
        only_tags=args.tags.split(",") if args.tags else [],
        skip_tags=args.skip_tags.split(",") if args.skip_tags else [],
    )

    if args.list:
        runner.list_modules()
        return

    ctx = build_context()
    runner.run(ctx)


if __name__ == "__main__":
    main()
