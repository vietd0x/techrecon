"""Run history tracker — record stats per scan run and compare improvements."""

import csv
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, TextIO
import sys


HISTORY_FIELDS = [
    "run_id",
    "timestamp",
    "engines",
    "total_targets",
    "targets_with_tech",
    "targets_no_tech",
    "targets_with_version",
    "targets_tech_no_version",
    "tech_entries",
    "ver_entries",
    "unique_technologies",
    "tech_coverage_pct",
    "ver_coverage_pct",
    "entry_ver_pct",
    "outdated_alerts",
    "duration_sec",
    "notes",
]


def get_history_path(output_dir: str) -> str:
    return os.path.join(output_dir, "run_history.csv")


def record_run(
    output_dir: str,
    stats: Dict,
    engines: List[str],
    duration_sec: float = 0,
    outdated_count: int = 0,
    notes: str = "",
) -> Dict:
    """Append a run record to run_history.csv. Return the record."""
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    history_path = get_history_path(output_dir)
    exists = os.path.exists(history_path)

    now = datetime.now(timezone.utc)
    run_id = now.strftime("%Y%m%d_%H%M%S")

    record = {
        "run_id": run_id,
        "timestamp": now.isoformat(timespec="seconds"),
        "engines": "+".join(engines),
        "total_targets": stats.get("total_targets", 0),
        "targets_with_tech": stats.get("targets_with_tech", 0),
        "targets_no_tech": stats.get("targets_no_tech", 0),
        "targets_with_version": stats.get("targets_with_version", 0),
        "targets_tech_no_version": stats.get("targets_tech_no_version", 0),
        "tech_entries": stats.get("tech_entries", 0),
        "ver_entries": stats.get("ver_entries", 0),
        "unique_technologies": stats.get("unique_technologies", 0),
        "tech_coverage_pct": stats.get("tech_coverage_pct", 0),
        "ver_coverage_pct": stats.get("ver_coverage_pct", 0),
        "entry_ver_pct": stats.get("entry_ver_pct", 0),
        "outdated_alerts": outdated_count,
        "duration_sec": round(duration_sec, 1),
        "notes": notes,
    }

    with open(history_path, "a", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=HISTORY_FIELDS)
        if not exists:
            writer.writeheader()
        writer.writerow(record)

    return record


def load_history(output_dir: str) -> List[Dict]:
    """Load all run records."""
    history_path = get_history_path(output_dir)
    if not os.path.exists(history_path):
        return []
    with open(history_path, "r", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def print_history(output_dir: str, out: Optional[TextIO] = None):
    """Print run history table."""
    if out is None:
        out = sys.stdout

    runs = load_history(output_dir)
    if not runs:
        out.write("\n  No run history found.\n")
        return

    out.write(f"\n{'='*90}\n")
    out.write(f"  TECHRECON RUN HISTORY\n")
    out.write(f"{'='*90}\n\n")
    out.write(f"  {'Run ID':<17s}  {'Engines':<20s}  {'Targets':>7s}  "
              f"{'Tech%':>6s}  {'Ver%':>6s}  {'EntryVer%':>9s}  {'Alerts':>6s}  {'Time':>6s}\n")
    out.write(f"  {'-'*17}  {'-'*20}  {'-'*7}  "
              f"{'-'*6}  {'-'*6}  {'-'*9}  {'-'*6}  {'-'*6}\n")

    for r in runs:
        out.write(
            f"  {r['run_id']:<17s}  {r['engines']:<20s}  {r['total_targets']:>7s}  "
            f"{r['tech_coverage_pct']:>5s}%  {r['ver_coverage_pct']:>5s}%  "
            f"{r['entry_ver_pct']:>8s}%  {r['outdated_alerts']:>6s}  "
            f"{r['duration_sec']:>5s}s\n"
        )

    out.write(f"\n")


def print_comparison(output_dir: str, out: Optional[TextIO] = None):
    """Compare the last two runs and show deltas."""
    if out is None:
        out = sys.stdout

    runs = load_history(output_dir)
    if len(runs) < 2:
        out.write("\n  Need at least 2 runs to compare.\n")
        return

    prev = runs[-2]
    curr = runs[-1]

    out.write(f"\n{'='*70}\n")
    out.write(f"  IMPROVEMENT COMPARISON\n")
    out.write(f"  {prev['run_id']} ({prev['engines']})  ->  {curr['run_id']} ({curr['engines']})\n")
    out.write(f"{'='*70}\n\n")

    metrics = [
        ("Total targets", "total_targets", False),
        ("Targets with tech", "targets_with_tech", False),
        ("Targets NO tech", "targets_no_tech", True),
        ("Targets with version", "targets_with_version", False),
        ("Tech coverage %", "tech_coverage_pct", False),
        ("Version coverage %", "ver_coverage_pct", False),
        ("Entry version %", "entry_ver_pct", False),
        ("Tech entries", "tech_entries", False),
        ("Version entries", "ver_entries", False),
        ("Outdated alerts", "outdated_alerts", False),
    ]

    for label, key, invert in metrics:
        p = float(prev.get(key, 0))
        c = float(curr.get(key, 0))
        delta = c - p

        if delta == 0:
            indicator = "  "
        elif invert:
            indicator = "v " if delta < 0 else "^ "
        else:
            indicator = "^ " if delta > 0 else "v "

        sign = "+" if delta > 0 else ""
        is_pct = "%" in label

        if is_pct:
            out.write(
                f"  {indicator}{label:<25s}  {p:>8.1f}%  ->  {c:>8.1f}%  "
                f"({sign}{delta:+.1f}pp)\n"
            )
        else:
            out.write(
                f"  {indicator}{label:<25s}  {int(p):>8d}   ->  {int(c):>8d}   "
                f"({sign}{int(delta):+d})\n"
            )

    # Overall verdict
    tech_delta = float(curr.get("tech_coverage_pct", 0)) - float(prev.get("tech_coverage_pct", 0))
    ver_delta = float(curr.get("ver_coverage_pct", 0)) - float(prev.get("ver_coverage_pct", 0))

    out.write(f"\n  Verdict: ")
    if tech_delta > 0 and ver_delta > 0:
        out.write(f"IMPROVED (tech +{tech_delta:.1f}pp, version +{ver_delta:.1f}pp)\n")
    elif tech_delta > 0:
        out.write(f"PARTIAL (tech +{tech_delta:.1f}pp, version {ver_delta:+.1f}pp)\n")
    elif ver_delta > 0:
        out.write(f"PARTIAL (tech {tech_delta:+.1f}pp, version +{ver_delta:.1f}pp)\n")
    elif tech_delta == 0 and ver_delta == 0:
        out.write(f"NO CHANGE\n")
    else:
        out.write(f"REGRESSION (tech {tech_delta:+.1f}pp, version {ver_delta:+.1f}pp)\n")

    out.write(f"\n{'='*70}\n")
