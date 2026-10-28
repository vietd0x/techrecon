"""whatweb engine — 1800+ plugin web technology identification."""

import json
import re
from typing import List

from ..config import ScanConfig
from .base import BaseEngine

_SKIP_PLUGINS = {"Title", "IP", "Country", "Strict-Transport-Security", "X-Frame-Options",
                 "X-XSS-Protection", "X-UA-Compatible", "Meta-Refresh-Redirect"}

_SERVER_COMP_RE = re.compile(
    r"([a-zA-Z][a-zA-Z0-9._-]*)(?:/([0-9][0-9a-zA-Z._-]*))?",
)


class WhatwebEngine(BaseEngine):
    name = "whatweb"
    binary = "whatweb"

    def build_command(
        self, target_file: str, output_file: str, config: ScanConfig
    ) -> List[str]:
        cmd = [
            self.get_binary_path() or "whatweb",
            "-i", target_file,
            f"--log-json={output_file}",
            "--no-errors",
            "--colour=never",
            "-a", "3",
            "--max-threads", str(min(config.threads, 25)),
            "--open-timeout", str(config.timeout),
            "--read-timeout", str(config.timeout * 2),
        ]
        return cmd

    def parse_output(self, output_file: str) -> List[dict]:
        results = []
        with open(output_file, "r") as f:
            raw = f.read().strip()
        if not raw:
            return results

        entries = []
        try:
            parsed = json.loads(raw)
            if isinstance(parsed, dict):
                entries = [parsed]
            else:
                entries = parsed
        except json.JSONDecodeError:
            decoder = json.JSONDecoder()
            pos = 0
            while pos < len(raw):
                chunk = raw[pos:].lstrip()
                if not chunk:
                    break
                try:
                    obj, end = decoder.raw_decode(chunk)
                    if isinstance(obj, list):
                        entries.extend(obj)
                    else:
                        entries.append(obj)
                    pos += len(raw) - len(chunk) - pos + end
                except json.JSONDecodeError:
                    pos += 1

        for entry in entries:
            results.append(self._normalize(entry))
        return results

    def _normalize(self, d: dict) -> dict:
        target = d.get("target", "")
        bare_host = self._bare_host(target)
        plugins = d.get("plugins", {})
        techs = []

        for plugin_name, plugin_data in plugins.items():
            if plugin_name in _SKIP_PLUGINS:
                continue

            version = ""
            if isinstance(plugin_data, dict):
                ver_list = plugin_data.get("version", [])
                if ver_list:
                    version = ver_list[0] if isinstance(ver_list, list) else str(ver_list)
                if not version:
                    string_list = plugin_data.get("string", [])
                    if string_list:
                        s = string_list[0] if isinstance(string_list, list) else str(string_list)
                        m = re.search(r"(\d+\.\d+[\d.]*)", s)
                        if m:
                            version = m.group(1)

            techs.append({"name": plugin_name, "version": version, "source": "whatweb"})

        http_server = ""
        if "HTTPServer" in plugins:
            srv = plugins["HTTPServer"]
            if isinstance(srv, dict):
                string_list = srv.get("string", [])
                if string_list:
                    raw = string_list if isinstance(string_list, list) else [str(string_list)]
                    http_server = raw[0]
                    for s in raw:
                        for m in _SERVER_COMP_RE.finditer(s):
                            name = m.group(1)
                            ver = m.group(2) or ""
                            if name.startswith("(") or name.lower() in ("dev",):
                                continue
                            existing = {t["name"].lower() for t in techs}
                            if name.lower() not in existing:
                                techs.append({"name": name, "version": ver, "source": "whatweb"})

        status = d.get("http_status", "")
        return {
            "url": target,
            "host": bare_host,
            "input": bare_host,
            "status_code": status,
            "title": "",
            "webserver": http_server,
            "cdn": "",
            "technologies": techs,
        }

    @staticmethod
    def _bare_host(target: str) -> str:
        """Strip scheme, path, and port so the target maps to the canonical asset."""
        t = target.strip()
        if "://" in t:
            t = t.split("://", 1)[1]
        t = t.split("/", 1)[0]
        # keep IPv6 brackets intact; strip :port only for host:port forms
        if t.count(":") == 1:
            t = t.split(":", 1)[0]
        return t
