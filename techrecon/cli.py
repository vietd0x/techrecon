"""CLI entry point for techrecon."""

import argparse
import sys

from . import __version__
from .config import Config
from .normalizer import get_coverage_stats, normalize_rows
from .reporter import check_outdated, generate_risk_report, generate_summary, load_csv
from .scanner import run_scan
from .tracker import print_comparison, print_history


def main():
    parser = argparse.ArgumentParser(
        prog="techrecon",
        description="Technology stack detection framework for asset inventories",
    )
    parser.add_argument("-V", "--version", action="version", version=f"techrecon {__version__}")
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # --- scan ---
    p_scan = subparsers.add_parser("scan", help="Scan targets and generate technology CSV")
    p_scan.add_argument("-i", "--input", required=True, help="Input targets.csv (asset inventory)")
    p_scan.add_argument("-o", "--output", default="technology_ver.csv", help="Output CSV path")
    p_scan.add_argument("-c", "--config", help="Config YAML file")
    p_scan.add_argument("-e", "--engines", nargs="+", default=None,
                        help="Engines to use (httpx, nuclei, whatweb, webanalyze)")
    p_scan.add_argument("--deep", action="store_true",
                        help="Deep pass: re-scan gap targets with additional engines")
    p_scan.add_argument("--threads", type=int, default=50, help="Concurrent threads (default: 50)")
    p_scan.add_argument("--timeout", type=int, default=10, help="Request timeout in seconds (default: 10)")
    p_scan.add_argument("--retries", type=int, default=1, help="Retries per request (default: 1)")
    p_scan.add_argument("--rate-limit", type=int, default=0, help="Rate limit (requests/sec, 0=unlimited)")
    p_scan.add_argument("--include-internal", action="store_true", help="Include internal/private IPs")
    p_scan.add_argument("--output-dir", default="output", help="Working directory for intermediate files")
    p_scan.add_argument("-v", "--verbose", action="store_true", help="Verbose output")

    # --- report ---
    p_report = subparsers.add_parser("report", help="Generate report from existing technology_ver.csv")
    p_report.add_argument("-i", "--input", required=True, help="Input technology_ver.csv")
    p_report.add_argument("--outdated", action="store_true", help="Check for outdated/EOL technologies")
    p_report.add_argument("--risk", action="store_true", help="Risk-prioritized report")
    p_report.add_argument("--all", action="store_true", help="Generate all report types")

    # --- normalize ---
    p_norm = subparsers.add_parser("normalize", help="Normalize tech names in existing CSV (in-place)")
    p_norm.add_argument("-i", "--input", required=True, help="Input technology_ver.csv")
    p_norm.add_argument("-o", "--output", help="Output path (default: overwrite input)")

    # --- history ---
    p_hist = subparsers.add_parser("history", help="Show run history and improvement tracking")
    p_hist.add_argument("--output-dir", default="output", help="Directory with run_history.csv")

    # --- compare ---
    p_cmp = subparsers.add_parser("compare", help="Compare last two runs")
    p_cmp.add_argument("--output-dir", default="output", help="Directory with run_history.csv")

    # --- coverage ---
    p_cov = subparsers.add_parser("coverage", help="Show coverage stats for a CSV")
    p_cov.add_argument("-i", "--input", required=True, help="Input technology_ver.csv")

    # --- engines ---
    p_engines = subparsers.add_parser("engines", help="List available scan engines")

    args = parser.parse_args()

    if args.command == "scan":
        cmd_scan(args)
    elif args.command == "report":
        cmd_report(args)
    elif args.command == "normalize":
        cmd_normalize(args)
    elif args.command == "history":
        cmd_history(args)
    elif args.command == "compare":
        cmd_compare(args)
    elif args.command == "coverage":
        cmd_coverage(args)
    elif args.command == "engines":
        cmd_engines()
    else:
        parser.print_help()
        sys.exit(1)


def cmd_scan(args):
    cfg = Config.load(args.config)
    cfg.engine.httpx.threads = args.threads
    cfg.engine.httpx.timeout = args.timeout
    cfg.engine.httpx.retries = args.retries
    cfg.engine.httpx.rate_limit = args.rate_limit
    cfg.output_dir = args.output_dir

    if args.include_internal:
        cfg.filter.skip_internal = False
        cfg.filter.external_only = False

    run_scan(
        targets_csv=args.input,
        output_csv=args.output,
        config=cfg,
        engines=args.engines,
        deep=args.deep,
        verbose=args.verbose,
    )


def cmd_report(args):
    rows = load_csv(args.input)
    if not rows:
        print("ERROR: No data in input CSV.", file=sys.stderr)
        sys.exit(1)

    rows = normalize_rows(rows)
    generate_summary(rows)

    if args.outdated or args.all:
        check_outdated(rows)

    if args.risk or args.all:
        generate_risk_report(rows)


def cmd_normalize(args):
    from .enricher import CSV_FIELDS, write_csv

    rows = load_csv(args.input)
    if not rows:
        print("ERROR: No data in input CSV.", file=sys.stderr)
        sys.exit(1)

    before = get_coverage_stats(rows)
    rows = normalize_rows(rows)
    after = get_coverage_stats(rows)

    output = args.output or args.input
    write_csv(rows, output)

    unique_before = len({r.get("technology", "") for r in load_csv(args.input) if r.get("technology")})
    unique_after = len({r["technology"] for r in rows if r["technology"]})

    print(f"\n  Normalized: {output}")
    print(f"  Rows: {before['tech_entries']} -> {after['tech_entries']} (deduped {before['tech_entries'] - after['tech_entries']})")
    print(f"  Unique technologies: {unique_before} -> {unique_after} (merged {unique_before - unique_after})")


def cmd_history(args):
    print_history(args.output_dir)


def cmd_compare(args):
    print_comparison(args.output_dir)


def cmd_coverage(args):
    rows = load_csv(args.input)
    if not rows:
        print("ERROR: No data in input CSV.", file=sys.stderr)
        sys.exit(1)

    rows = normalize_rows(rows)
    stats = get_coverage_stats(rows)

    print(f"\n  {'='*50}")
    print(f"  COVERAGE METRICS")
    print(f"  {'='*50}")
    print(f"  Total targets:           {stats['total_targets']}")
    print(f"  Tech detected:           {stats['targets_with_tech']:>5d}  ({stats['tech_coverage_pct']}%)")
    print(f"  NO tech:                 {stats['targets_no_tech']:>5d}  ({100 - stats['tech_coverage_pct']:.1f}%)")
    print(f"  With version:            {stats['targets_with_version']:>5d}  ({stats['ver_coverage_pct']}%)")
    print(f"  Tech but NO version:     {stats['targets_tech_no_version']:>5d}")
    print(f"  Entry-level version %:   {stats['entry_ver_pct']}%")
    print(f"  {'='*50}")


def cmd_engines():
    from .engines import ENGINES

    print("\nAvailable scan engines:\n")
    for name, cls in ENGINES.items():
        engine = cls()
        status = "installed" if engine.is_available() else "NOT FOUND"
        path = engine.get_binary_path() or "-"
        print(f"  {name:<15s}  [{status}]  {path}")
    print()


if __name__ == "__main__":
    main()
