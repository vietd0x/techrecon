"""webanalyze engine — Wappalyzer CLI for technology detection."""

import json
from typing import List

from ..config import ScanConfig
from .base import BaseEngine


class WebanalyzeEngine(BaseEngine):
    name = "webanalyze"
    binary = "webanalyze"

    def build_command(
        self, target_file: str, output_file: str, config: ScanConfig
    ) -> List[str]:
        cmd = [
            self.get_binary_path() or "webanalyze",
            "-hosts", target_file,
            "-output", "json",
            "-silent",
            "-worker", str(config.threads),
        ]
        return cmd

    def parse_output(self, output_file: str) -> List[dict]:
        results = []
        with open(output_file, "r") as f:
            raw = f.read().strip()
        if not raw:
            return results

        try:
            entries = json.loads(raw)
            if isinstance(entries, dict):
                entries = [entries]
        except json.JSONDecodeError:
            for line in raw.splitlines():
                try:
                    entries = [json.loads(line)]
                except json.JSONDecodeError:
                    continue
                results.append(self._normalize(entries[0]))
            return results

        for entry in entries:
            results.append(self._normalize(entry))
        return results

    def _normalize(self, d: dict) -> dict:
        hostname = d.get("hostname", d.get("url", ""))
        matches = d.get("matches", []) or []
        techs = []

        for match in matches:
            app = match.get("app", {}) if isinstance(match, dict) else {}
            name = app.get("name", "") if isinstance(app, dict) else str(match.get("app_name", ""))
            version = match.get("version", "")
            if name:
                techs.append({"name": name, "version": version, "source": "webanalyze"})

        return {
            "url": hostname,
            "host": "",
            "input": hostname,
            "status_code": "",
            "title": "",
            "webserver": "",
            "cdn": "",
            "technologies": techs,
        }
