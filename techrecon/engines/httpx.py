"""httpx engine — Wappalyzer-based tech detection via ProjectDiscovery httpx."""

import json
import re
from typing import List

from ..config import ScanConfig
from .base import BaseEngine

_TITLE_VERSION_RE = re.compile(
    r"(?:Apache Tomcat|Nginx|Jetty|WildFly|JBoss|Caddy|LiteSpeed|lighttpd)"
    r"[/\s]+([\d]+\.[\d]+[\d.]*)",
    re.IGNORECASE,
)

_SERVER_MULTI_RE = re.compile(
    r"([a-zA-Z][a-zA-Z0-9._-]*)(?:/([0-9][0-9a-zA-Z._-]*))?",
)


class HttpxEngine(BaseEngine):
    name = "httpx"
    binary = "httpx"

    def build_command(
        self, target_file: str, output_file: str, config: ScanConfig
    ) -> List[str]:
        cmd = [
            self.get_binary_path() or "httpx",
            "-l", target_file,
            "-td",
            "-server",
            "-title",
            "-status-code",
            "-cdn",
            "-json",
            "-no-color",
            "-threads", str(config.threads),
            "-timeout", str(config.timeout),
            "-retries", str(max(config.retries, 2)),
            "-o", output_file,
            "-follow-redirects",
        ]
        if config.rate_limit > 0:
            cmd.extend(["-rl", str(config.rate_limit)])
        if config.user_agent:
            cmd.extend(["-H", f"User-Agent: {config.user_agent}"])
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
        techs = []
        for tech in d.get("tech", []) or []:
            name, version = self._parse_tech_version(tech)
            if name:
                techs.append({"name": name, "version": version, "source": "wappalyzer"})

        server = d.get("webserver", "")
        if server:
            for srv_name, srv_ver in self._extract_all_server_components(server):
                techs.append({"name": srv_name, "version": srv_ver, "source": "http_header"})

        cdn_name = d.get("cdn_name", "")
        if d.get("cdn") and cdn_name:
            techs.append({"name": cdn_name, "version": "", "source": "cdn"})

        # Extract CPE data (httpx already detects these)
        for cpe_entry in d.get("cpe", []) or []:
            cpe_str = cpe_entry.get("cpe", "")
            product = cpe_entry.get("product", "")
            if product and not any(t["name"].lower() == product.lower() for t in techs):
                techs.append({"name": product, "version": "", "source": "cpe"})

        # Recognise the real backend from the DNS CNAME chain (e.g. an opaque
        # host whose CNAME ends in .edgekey.net -> Akamai, or an ALB -> AWS ELB).
        from ..normalizer import recognize_hostname
        for cname in d.get("cname", []) or []:
            tech = recognize_hostname(cname)
            if tech and not any(t["name"].lower() == tech.lower() for t in techs):
                techs.append({"name": tech, "version": "", "source": "cname"})

        # Extract version from page title (e.g. "Apache Tomcat/9.0.95")
        title = d.get("title", "")
        if title:
            m = _TITLE_VERSION_RE.search(title)
            if m:
                title_tech = m.group(0).split("/")[0].split()[0].strip()
                title_ver = m.group(1)
                existing = [t for t in techs if t["name"].lower().startswith(title_tech.lower())]
                if existing:
                    for t in existing:
                        if not t["version"]:
                            t["version"] = title_ver
                else:
                    techs.append({"name": title_tech, "version": title_ver, "source": "title"})

        return {
            "url": d.get("url", ""),
            "host": d.get("host", ""),
            "input": d.get("input", ""),
            "status_code": d.get("status_code", ""),
            "title": title,
            "webserver": server,
            "cdn": cdn_name if d.get("cdn") else "",
            "technologies": techs,
        }

    @staticmethod
    def _parse_tech_version(tech_string: str):
        if ":" in tech_string:
            parts = tech_string.split(":", 1)
            return parts[0].strip(), parts[1].strip()
        return tech_string.strip(), ""

    @staticmethod
    def _extract_all_server_components(server_string: str):
        """Extract ALL components from compound Server headers like
        'Apache/2.4.25 (Unix) OpenSSL/1.0.2j PHP/5.6.30'."""
        if not server_string:
            return []
        results = []
        for m in _SERVER_MULTI_RE.finditer(server_string):
            name = m.group(1)
            ver = m.group(2) or ""
            if name.startswith("(") or name.lower() in ("dev",):
                continue
            results.append((name, ver))
        return results if results else [(server_string, "")]
