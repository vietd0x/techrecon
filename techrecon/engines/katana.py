"""katana engine — crawl targets and infer technology (incl. versions) from discovered URLs/JS."""

import json
import re
import sys
from typing import List

from ..config import ScanConfig
from .base import BaseEngine

# URL/path patterns → technology. First match wins per hint; many can apply per host.
_PATH_HINTS = [
    (re.compile(r"/_next/"), "Next.js"),
    (re.compile(r"/_nuxt/"), "Nuxt.js"),
    (re.compile(r"/wp-(content|includes|json|admin)"), "WordPress"),
    (re.compile(r"/sites/(default|all)/|/misc/drupal"), "Drupal"),
    (re.compile(r"/media/(jui|system)/|/administrator/"), "Joomla"),
    (re.compile(r"/polyfills[.-]|/runtime[.-].*\.js|/main[.-].*\.js"), "Angular"),
    (re.compile(r"/static/js/.*\.chunk\.js"), "React"),
    (re.compile(r"\.vue(\?|$)|/js/app\.[a-f0-9]+\.js"), "Vue.js"),
    (re.compile(r"/cdn-cgi/"), "Cloudflare"),
    (re.compile(r"\.php(\?|$)"), "PHP"),
    (re.compile(r"\.aspx?(\?|$)|/__VIEWSTATE"), "ASP.NET"),
    (re.compile(r"\.jsp(\?|$)|/j_spring_security"), "Java"),
    (re.compile(r"\.cfm(\?|$)"), "ColdFusion"),
    (re.compile(r"/graphql(\?|$)"), "GraphQL"),
]

# Versioned library bundles, e.g. jquery-3.6.0.min.js, bootstrap.5.2.1.css, vue@2.6.14
_LIB_VERSION_RE = re.compile(
    r"(jquery|bootstrap|angular|react|vue|lodash|moment|axios|d3|chart\.?js|swiper|slick|popper)"
    r"[/@._-]*v?(\d+\.\d+(?:\.\d+)?)",
    re.IGNORECASE,
)

_LIB_CANON = {
    "jquery": "jQuery", "bootstrap": "Bootstrap", "angular": "Angular",
    "react": "React", "vue": "Vue.js", "lodash": "Lodash", "moment": "Moment.js",
    "axios": "Axios", "d3": "D3.js", "chartjs": "Chart.js", "chart.js": "Chart.js",
    "swiper": "Swiper", "slick": "Slick", "popper": "Popper",
}


class KatanaEngine(BaseEngine):
    name = "katana"
    binary = "katana"

    def build_command(
        self, target_file: str, output_file: str, config: ScanConfig
    ) -> List[str]:
        # katana emits JSONL only to stdout; a thin Python runner captures it to
        # output_file so the engine stays cross-platform (no shell redirection).
        cmd = [
            sys.executable, "-m", "techrecon.engines._katana_run",
            "-l", target_file,
            "-o", output_file,
            "-t", str(config.timeout),
            "-c", str(min(config.threads, 15)),
            "-d", "2",
        ]
        if config.rate_limit > 0:
            cmd.extend(["--rate-limit", str(config.rate_limit)])
        return cmd

    def parse_output(self, output_file: str) -> List[dict]:
        # Aggregate all discovered URLs per host, then infer tech once per host.
        per_host = {}
        with open(output_file, "r") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    d = json.loads(line)
                except json.JSONDecodeError:
                    continue
                url = self._extract_url(d)
                if not url:
                    continue
                host = self._host_of(url)
                per_host.setdefault(host, {"urls": [], "any": url})
                per_host[host]["urls"].append(url)

        results = []
        for host, data in per_host.items():
            techs = self._infer(data["urls"])
            results.append({
                "url": data["any"],
                "host": host,
                "input": host,
                "status_code": "",
                "title": "",
                "webserver": "",
                "cdn": "",
                "technologies": techs,
            })
        return results

    @staticmethod
    def _extract_url(d: dict) -> str:
        if isinstance(d.get("request"), dict):
            u = d["request"].get("endpoint") or d["request"].get("url")
            if u:
                return u
        return d.get("endpoint") or d.get("url") or ""

    @staticmethod
    def _host_of(url: str) -> str:
        t = url
        if "://" in t:
            t = t.split("://", 1)[1]
        t = t.split("/", 1)[0]
        if t.count(":") == 1:
            t = t.split(":", 1)[0]
        return t

    def _infer(self, urls) -> List[dict]:
        found = {}  # name -> version
        for url in urls:
            for pat, tech in _PATH_HINTS:
                if pat.search(url):
                    found.setdefault(tech, "")
            m = _LIB_VERSION_RE.search(url)
            if m:
                raw = m.group(1).lower().replace(".", "") if m.group(1).lower() == "chartjs" else m.group(1).lower()
                name = _LIB_CANON.get(m.group(1).lower(), _LIB_CANON.get(raw, m.group(1)))
                ver = m.group(2)
                # keep the longest/most specific version seen
                if not found.get(name) or len(ver) > len(found.get(name, "")):
                    found[name] = ver
        return [{"name": n, "version": v, "source": "katana"} for n, v in found.items()]
