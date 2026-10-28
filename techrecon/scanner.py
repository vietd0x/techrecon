"""Scanner orchestrator — run engines, collect results, produce CSV."""

import os
import subprocess
import sys
import time
from pathlib import Path
from typing import List, Optional, Set

from .config import Config
from .engines import get_engine
from .enricher import flatten_results, load_target_metadata, write_csv
from .filter import load_and_filter, write_target_list
from .normalizer import get_coverage_stats, normalize_rows
from .reporter import check_outdated, generate_summary
from .tracker import print_comparison, record_run


def _run_engine(engine_name, target_file, output_dir, config, verbose):
    """Run a single engine and return parsed results."""
    engine = get_engine(engine_name)
    if not engine.is_available():
        print(f"WARNING: {engine_name} not found in PATH, skipping.", file=sys.stderr)
        return []

    raw_output = os.path.join(output_dir, f"{engine_name}_results.jsonl")
    cmd = engine.build_command(target_file, raw_output, config.engine.httpx)
    _log(verbose, f"       $ {' '.join(cmd)}")

    try:
        subprocess.run(
            cmd,
            capture_output=not verbose,
            text=True,
            timeout=3600,
        )
    except subprocess.TimeoutExpired:
        print(f"WARNING: {engine_name} timed out after 3600s", file=sys.stderr)
        return []
    except FileNotFoundError:
        print(f"WARNING: {engine_name} binary not found", file=sys.stderr)
        return []

    if os.path.exists(raw_output) and os.path.getsize(raw_output) > 0:
        results = engine.parse_output(raw_output)
        _log(verbose, f"       {len(results)} results from {engine_name}")
        return results

    _log(verbose, f"       No results from {engine_name}")
    return []


def _find_gap_targets(rows: List[dict]) -> tuple:
    """Find targets missing tech detection or version info."""
    all_targets = set()
    has_tech: Set[str] = set()
    has_ver: Set[str] = set()

    for r in rows:
        t = r.get("target", "")
        all_targets.add(t)
        if r.get("technology"):
            has_tech.add(t)
            if r.get("version"):
                has_ver.add(t)

    no_tech = all_targets - has_tech
    tech_no_ver = has_tech - has_ver
    return sorted(no_tech), sorted(tech_no_ver)


def run_scan(
    targets_csv: str,
    output_csv: str,
    config: Optional[Config] = None,
    engines: Optional[List[str]] = None,
    deep: bool = False,
    verbose: bool = False,
) -> str:
    """Full scan pipeline: filter -> scan -> [deep pass] -> normalize -> enrich -> CSV -> track."""
    if config is None:
        config = Config()

    t_start = time.monotonic()
    engine_names = engines or config.engine.enabled
    output_dir = config.output_dir
    Path(output_dir).mkdir(parents=True, exist_ok=True)

    # Step 1: Filter targets
    _log(verbose, "[1/5] Filtering targets...")
    targets = load_and_filter(targets_csv, config.filter)
    if not targets:
        print("ERROR: No targets after filtering.", file=sys.stderr)
        return ""

    target_file = os.path.join(output_dir, "scan_targets.txt")
    write_target_list(targets, target_file)
    _log(verbose, f"       {len(targets)} targets after filtering -> {target_file}")

    # Step 2: Run primary engines
    all_results = []
    for engine_name in engine_names:
        _log(verbose, f"[2/5] Running engine: {engine_name}...")
        results = _run_engine(engine_name, target_file, output_dir, config, verbose)
        all_results.extend(results)

    if not all_results:
        print("WARNING: No results from any engine.", file=sys.stderr)

    # Step 3: Deep pass — re-scan gaps with additional engines
    deep_engines_used = []
    if deep:
        _log(verbose, "[3/5] Deep pass — analyzing gaps...")
        meta_map_tmp = load_target_metadata(targets_csv)
        rows_tmp = flatten_results(all_results, meta_map_tmp)
        rows_tmp = normalize_rows(rows_tmp)
        no_tech, tech_no_ver = _find_gap_targets(rows_tmp)

        _log(verbose, f"       Gaps: {len(no_tech)} no-tech, {len(tech_no_ver)} tech-no-ver")

        deep_candidates = list(set(no_tech) | set(tech_no_ver))
        if deep_candidates:
            deep_target_file = os.path.join(output_dir, "deep_targets.txt")
            write_target_list(deep_candidates, deep_target_file)

            deep_pool = ["nuclei", "whatweb", "webanalyze", "favicon", "tlsx", "katana"]
            deep_to_run = [e for e in deep_pool if e not in engine_names]
            if not deep_to_run:
                deep_to_run = [e for e in deep_pool if e != engine_names[0]]

            for engine_name in deep_to_run:
                eng = get_engine(engine_name)
                if not eng.is_available():
                    continue
                _log(verbose, f"       Deep scan with {engine_name} on {len(deep_candidates)} targets...")
                results = _run_engine(
                    engine_name, deep_target_file, output_dir, config, verbose
                )
                if results:
                    all_results.extend(results)
                    deep_engines_used.append(engine_name)
        else:
            _log(verbose, "       No gap targets — skip deep pass")
    else:
        _log(verbose, "[3/5] Deep pass — skipped (use --deep to enable)")

    # Step 4: Normalize + Enrich
    _log(verbose, "[4/5] Normalizing tech names and enriching with metadata...")
    meta_map = load_target_metadata(targets_csv)
    rows = flatten_results(all_results, meta_map)
    rows = normalize_rows(rows)
    _log(verbose, f"       {len(rows)} rows after normalization")

    # Step 5: Write CSV, report, track
    _log(verbose, f"[5/5] Writing output -> {output_csv}")
    write_csv(rows, output_csv)

    summary = generate_summary(rows)
    alerts = check_outdated(rows)

    duration = time.monotonic() - t_start
    coverage = get_coverage_stats(rows)
    coverage["unique_technologies"] = summary.get("unique_technologies", 0)

    all_engines = list(engine_names) + deep_engines_used
    notes = ""
    if deep and deep_engines_used:
        notes = f"deep pass: {'+'.join(deep_engines_used)}"

    record_run(
        output_dir=output_dir,
        stats=coverage,
        engines=all_engines,
        duration_sec=duration,
        outdated_count=len(alerts),
        notes=notes,
    )

    # Print coverage summary
    _print_coverage(coverage)

    if alerts:
        print(f"\n  {len(alerts)} outdated technology alerts found!")

    # Auto-compare with previous run
    print_comparison(output_dir)

    print(f"\n  Output: {output_csv}")
    print(f"  Duration: {duration:.1f}s")
    return output_csv


def _print_coverage(stats: dict):
    """Print coverage metrics."""
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


def _log(verbose: bool, msg: str):
    if verbose:
        print(msg, file=sys.stderr)
