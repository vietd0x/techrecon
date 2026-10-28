"""Target filtering — skip internal IPs, deduplicate, scope check."""

import csv
import ipaddress
import re
from pathlib import Path
from typing import List, Set

from .config import FilterConfig

_PRIVATE_RE = re.compile(r"^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|127\.)")


def is_internal_ip(addr: str) -> bool:
    if _PRIVATE_RE.match(addr):
        return True
    try:
        return ipaddress.ip_address(addr).is_private
    except ValueError:
        return False


def load_and_filter(targets_csv: str, cfg: FilterConfig) -> List[str]:
    """Read targets.csv, apply filters, return deduplicated target list."""
    seen: Set[str] = set()
    targets: List[str] = []

    with open(targets_csv, "r", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        for row in reader:
            target = row.get("target", "").strip()
            if not target:
                continue

            target_type = row.get("target_type", "")
            if cfg.target_types and target_type not in cfg.target_types:
                continue

            scope = row.get("scope_status", "")
            if cfg.scope_status and scope not in cfg.scope_status:
                continue

            if cfg.external_only and row.get("scan_zone") == "internal":
                continue

            host = row.get("host", "")
            if cfg.skip_internal:
                check_addr = host or target.split(":")[0]
                if is_internal_ip(check_addr):
                    continue

            if target_type == "host_port":
                effective = host or target.split(":")[0]
            else:
                effective = target

            if effective and effective not in seen:
                seen.add(effective)
                targets.append(effective)

    return sorted(targets)


def write_target_list(targets: List[str], output_path: str) -> str:
    """Write filtered targets to a text file, one per line."""
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w") as f:
        for t in targets:
            f.write(t + "\n")
    return output_path
