"""Configuration management."""

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

import yaml


@dataclass
class ScanConfig:
    threads: int = 50
    timeout: int = 10
    retries: int = 1
    rate_limit: int = 0
    follow_redirects: bool = True
    user_agent: str = ""


@dataclass
class FilterConfig:
    external_only: bool = True
    skip_internal: bool = True
    internal_ranges: List[str] = field(default_factory=lambda: [
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "127.0.0.0/8",
    ])
    target_types: List[str] = field(default_factory=lambda: [
        "hostname", "ip", "url", "host_port",
    ])
    scope_status: List[str] = field(default_factory=lambda: ["in_scope"])


@dataclass
class EngineConfig:
    enabled: List[str] = field(default_factory=lambda: ["httpx"])
    httpx: ScanConfig = field(default_factory=ScanConfig)


@dataclass
class Config:
    engine: EngineConfig = field(default_factory=EngineConfig)
    filter: FilterConfig = field(default_factory=FilterConfig)
    output_dir: str = "output"

    @classmethod
    def load(cls, path: Optional[str] = None) -> "Config":
        if path and os.path.exists(path):
            with open(path) as f:
                data = yaml.safe_load(f) or {}
            return cls._from_dict(data)
        default_path = Path(__file__).parent.parent / "config" / "default.yaml"
        if default_path.exists():
            with open(default_path) as f:
                data = yaml.safe_load(f) or {}
            return cls._from_dict(data)
        return cls()

    @classmethod
    def _from_dict(cls, data: Dict) -> "Config":
        cfg = cls()
        if "engine" in data:
            eng = data["engine"]
            if "enabled" in eng:
                cfg.engine.enabled = eng["enabled"]
            if "httpx" in eng:
                for k, v in eng["httpx"].items():
                    if hasattr(cfg.engine.httpx, k):
                        setattr(cfg.engine.httpx, k, v)
        if "filter" in data:
            flt = data["filter"]
            for k, v in flt.items():
                if hasattr(cfg.filter, k):
                    setattr(cfg.filter, k, v)
        if "output_dir" in data:
            cfg.output_dir = data["output_dir"]
        return cfg
