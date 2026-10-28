"""Report generation — summary stats, outdated tech alerts, risk prioritization."""

import csv
from collections import defaultdict
from typing import Dict, List, Optional, TextIO
import sys


KNOWN_OUTDATED = {
    "OpenSSL": [
        ("1.0.", "EOL since 2019-12-31 — critical vulnerabilities"),
        ("1.1.0", "EOL since 2019-09-11"),
    ],
    "PHP": [
        ("5.", "EOL — multiple critical CVEs"),
        ("7.0", "EOL since 2019-01-10"),
        ("7.1", "EOL since 2019-12-01"),
        ("7.2", "EOL since 2020-11-30"),
        ("7.3", "EOL since 2021-12-06"),
        ("7.4", "EOL since 2022-11-28"),
        ("8.0", "EOL since 2023-11-26"),
    ],
    "Apache": [
        ("2.2.", "EOL since 2018-01 — upgrade to 2.4.x"),
        ("2.4.0", "Very old — upgrade to latest 2.4.x"),
    ],
    "nginx": [
        ("1.14.", "EOL"),
        ("1.16.", "EOL"),
    ],
    "jQuery": [
        ("1.", "EOL — known XSS vulnerabilities (CVE-2020-11022, CVE-2020-11023)"),
        ("2.", "EOL — known XSS vulnerabilities"),
    ],
    "Perl": [
        ("5.16.", "Very old — released 2012"),
        ("5.18.", "Very old — released 2013"),
        ("5.20.", "Old — released 2014"),
    ],
}


def load_csv(path: str) -> List[dict]:
    with open(path, "r", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def generate_summary(rows: List[dict], out: Optional[TextIO] = None) -> Dict:
    """Print summary stats and return them as a dict."""
    if out is None:
        out = sys.stdout

    all_targets = {r["target"] for r in rows}
    targets_with_tech = {r["target"] for r in rows if r.get("technology")}

    tech_counts: Dict[str, int] = defaultdict(int)
    versioned = 0
    version_map: Dict[str, set] = defaultdict(set)

    for r in rows:
        tech = r.get("technology", "")
        ver = r.get("version", "")
        if tech:
            tech_counts[tech] += 1
            if ver:
                versioned += 1
                version_map[tech].add(ver)

    out.write(f"\n{'='*60}\n")
    out.write(f"  TECHRECON SCAN SUMMARY\n")
    out.write(f"{'='*60}\n\n")
    out.write(f"  Targets scanned:        {len(all_targets)}\n")
    out.write(f"  With tech detected:     {len(targets_with_tech)}\n")
    out.write(f"  Total tech entries:     {sum(tech_counts.values())}\n")
    out.write(f"  With version info:      {versioned}\n")
    out.write(f"  Unique technologies:    {len(tech_counts)}\n")

    out.write(f"\n  Top 20 technologies:\n")
    out.write(f"  {'Count':>6s}  {'Technology'}\n")
    out.write(f"  {'-'*6}  {'-'*30}\n")
    for tech, count in sorted(tech_counts.items(), key=lambda x: -x[1])[:20]:
        out.write(f"  {count:6d}  {tech}\n")

    if version_map:
        out.write(f"\n  Versioned technologies:\n")
        out.write(f"  {'Technology':<25s}  {'Versions'}\n")
        out.write(f"  {'-'*25}  {'-'*40}\n")
        for tech in sorted(version_map):
            versions = ", ".join(sorted(version_map[tech]))
            out.write(f"  {tech:<25s}  {versions}\n")

    out.write(f"\n{'='*60}\n")

    return {
        "total_targets": len(all_targets),
        "targets_with_tech": len(targets_with_tech),
        "total_entries": sum(tech_counts.values()),
        "versioned": versioned,
        "unique_technologies": len(tech_counts),
        "tech_counts": dict(tech_counts),
        "version_map": {k: sorted(v) for k, v in version_map.items()},
    }


def check_outdated(rows: List[dict], out: Optional[TextIO] = None) -> List[dict]:
    """Check for known outdated/EOL technologies. Return list of alerts."""
    if out is None:
        out = sys.stdout

    alerts = []
    seen = set()

    for r in rows:
        tech = r.get("technology", "")
        ver = r.get("version", "")
        if not tech or not ver:
            continue

        for known_tech, patterns in KNOWN_OUTDATED.items():
            if tech.lower() != known_tech.lower():
                continue
            for prefix, reason in patterns:
                if ver.startswith(prefix):
                    key = (r["target"], tech, ver)
                    if key in seen:
                        continue
                    seen.add(key)
                    alerts.append({
                        "target": r["target"],
                        "url": r.get("url", ""),
                        "technology": tech,
                        "version": ver,
                        "risk_score": r.get("risk_score", ""),
                        "reason": reason,
                    })

    if alerts:
        alerts.sort(key=lambda a: (-float(a.get("risk_score") or 0), a["technology"]))
        out.write(f"\n{'!'*60}\n")
        out.write(f"  OUTDATED / EOL TECHNOLOGY ALERTS ({len(alerts)})\n")
        out.write(f"{'!'*60}\n\n")
        for a in alerts:
            risk = f" [risk={a['risk_score']}]" if a["risk_score"] else ""
            out.write(f"  [{a['technology']} {a['version']}] {a['target']}{risk}\n")
            out.write(f"    -> {a['reason']}\n\n")

    return alerts


def generate_risk_report(rows: List[dict], out: Optional[TextIO] = None) -> List[dict]:
    """Generate risk-prioritized report of targets with versions."""
    if out is None:
        out = sys.stdout

    versioned = [r for r in rows if r.get("version") and r.get("risk_score")]
    versioned.sort(key=lambda r: -float(r.get("risk_score", 0)))

    if not versioned:
        return []

    out.write(f"\n  HIGH-RISK TARGETS WITH VERSIONED SOFTWARE\n")
    out.write(f"  {'Risk':>6s}  {'Target':<40s}  {'Technology':<20s}  {'Version'}\n")
    out.write(f"  {'-'*6}  {'-'*40}  {'-'*20}  {'-'*15}\n")

    seen = set()
    report = []
    for r in versioned:
        key = (r["target"], r["technology"], r["version"])
        if key in seen:
            continue
        seen.add(key)
        out.write(
            f"  {r['risk_score']:>6s}  {r['target']:<40s}  "
            f"{r['technology']:<20s}  {r['version']}\n"
        )
        report.append(r)

    return report
