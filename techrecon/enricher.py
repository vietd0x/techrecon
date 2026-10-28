"""Enrich scan results with metadata from the original asset inventory."""

import csv
from typing import Dict, List, Optional


def load_target_metadata(targets_csv: str) -> Dict[str, dict]:
    """Load target metadata from asset inventory CSV."""
    meta = {}
    with open(targets_csv, "r", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        for row in reader:
            target = row.get("target", "").strip()
            if target:
                meta[target] = row
    return meta


def find_meta(
    meta_map: Dict[str, dict], input_target: str, host: str
) -> dict:
    """Find matching metadata for a scan result."""
    result = meta_map.get(input_target)
    if result:
        return result
    for t, m in meta_map.items():
        if m.get("host") == host or t == host:
            return m
    return {}


def flatten_results(
    scan_results: List[dict],
    meta_map: Optional[Dict[str, dict]] = None,
) -> List[dict]:
    """Flatten scan results into one row per (target, technology) pair."""
    rows = []
    seen = set()

    for r in scan_results:
        input_target = r.get("input", "")
        host = r.get("host", "")
        url = r.get("url", "")

        meta = {}
        if meta_map:
            meta = find_meta(meta_map, input_target, host)

        original_target = meta.get("target", input_target)
        target_type = meta.get("target_type", "")
        scope_status = meta.get("scope_status", "")
        risk_score = meta.get("risk_score", "")

        techs = r.get("technologies", [])
        if not techs:
            techs = [{"name": "", "version": "", "source": ""}]

        for tech in techs:
            tech_name = tech.get("name", "")
            tech_version = tech.get("version", "")
            source = tech.get("source", "")

            key = (original_target, url, tech_name, tech_version)
            if key in seen:
                continue
            seen.add(key)

            rows.append({
                "target": original_target,
                "url": url,
                "host": host,
                "status_code": r.get("status_code", ""),
                "title": r.get("title", ""),
                "technology": tech_name,
                "version": tech_version,
                "detection_source": source,
                "webserver": r.get("webserver", ""),
                "cdn": r.get("cdn", ""),
                "target_type": target_type,
                "scope_status": scope_status,
                "risk_score": risk_score,
            })

    rows.sort(key=lambda r: (r["target"], r["technology"]))
    return rows


CSV_FIELDS = [
    "target", "url", "host", "status_code", "title",
    "technology", "version", "detection_source",
    "webserver", "cdn", "target_type", "scope_status", "risk_score",
]


def write_csv(rows: List[dict], output_path: str) -> str:
    """Write enriched results to CSV."""
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_FIELDS)
        writer.writeheader()
        writer.writerows(rows)
    return output_path
