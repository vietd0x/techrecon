"""nuclei engine — template-based technology fingerprinting."""

import json
import re
from typing import List

from ..config import ScanConfig
from .base import BaseEngine

NUCLEI_TAGS = "tech,detect,exposure,token,waf"


class NucleiEngine(BaseEngine):
    name = "nuclei"
    binary = "nuclei"

    def build_command(
        self, target_file: str, output_file: str, config: ScanConfig
    ) -> List[str]:
        cmd = [
            self.get_binary_path() or "nuclei",
            "-l", target_file,
            "-tags", NUCLEI_TAGS,
            "-jsonl",
            "-o", output_file,
            "-c", str(config.threads),
            "-timeout", str(config.timeout),
            "-retries", str(max(config.retries, 2)),
            "-no-color",
            "-silent",
        ]
        if config.rate_limit > 0:
            cmd.extend(["-rl", str(config.rate_limit)])
        return cmd

    def parse_output(self, output_file: str) -> List[dict]:
        results = []
        with open(output_file, "r") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    d = json.loads(line)
                except json.JSONDecodeError:
                    continue
                results.append(self._normalize(d))
        return results

    def _normalize(self, d: dict) -> dict:
        info = d.get("info", {})
        matched = d.get("matched-at", d.get("host", ""))
        template_id = d.get("template-id", "")

        tech_name = info.get("name", template_id)
        version = ""
        extracted = d.get("extracted-results", [])
        if extracted:
            version = extracted[0] if isinstance(extracted, list) else str(extracted)

        matcher_name = d.get("matcher-name", "")
        if not version and matcher_name and re.match(r"[\d]", matcher_name):
            version = matcher_name

        return {
            "url": matched,
            "host": d.get("host", ""),
            "input": d.get("host", ""),
            "status_code": "",
            "title": "",
            "webserver": "",
            "cdn": "",
            "technologies": [
                {"name": tech_name, "version": version, "source": "nuclei"}
            ],
        }
