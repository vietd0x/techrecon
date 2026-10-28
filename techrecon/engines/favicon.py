"""favicon engine — fetch /favicon.ico and compute the Shodan-compatible mmh3 hash.

Favicons are usually served straight through CDNs/WAFs, so the hash fingerprints
the origin application even when headers are hidden. The raw hash is pivotable on
Shodan via `http.favicon.hash:<hash>`; known hashes can be mapped to a product via
FAVICON_DB (seed it with your own standard-portal hashes for high-value matching).

This engine needs no external binary — it runs itself as a subprocess:
    python -m techrecon.engines.favicon --run -l <targets> -o <out.jsonl> -t <timeout>
"""

import argparse
import base64
import concurrent.futures
import json
import ssl
import sys
import urllib.request
from typing import List

from ..config import ScanConfig
from .base import BaseEngine

# mmh3 (Shodan) favicon hash -> product. Extend with your own asset hashes.
FAVICON_DB = {
    # "116323821": "GitLab",
    # "81586312": "Jenkins",
}


def murmur3_32(data: bytes, seed: int = 0) -> int:
    """MurmurHash3 x86 32-bit, returning a signed int (matches Shodan/mmh3)."""
    c1, c2 = 0xCC9E2D51, 0x1B873593
    length = len(data)
    h1 = seed & 0xFFFFFFFF
    rounded_end = length & 0xFFFFFFFC
    for i in range(0, rounded_end, 4):
        k1 = (data[i] | (data[i + 1] << 8) | (data[i + 2] << 16) | (data[i + 3] << 24)) & 0xFFFFFFFF
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1
        h1 = ((h1 << 13) | (h1 >> 19)) & 0xFFFFFFFF
        h1 = (h1 * 5 + 0xE6546B64) & 0xFFFFFFFF
    k1 = 0
    tail = length & 0x03
    if tail == 3:
        k1 = (data[rounded_end + 2] << 16) & 0xFFFFFFFF
    if tail >= 2:
        k1 |= (data[rounded_end + 1] << 8)
    if tail >= 1:
        k1 |= data[rounded_end]
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1
    h1 ^= length
    h1 ^= h1 >> 16
    h1 = (h1 * 0x85EBCA6B) & 0xFFFFFFFF
    h1 ^= h1 >> 13
    h1 = (h1 * 0xC2B2AE35) & 0xFFFFFFFF
    h1 ^= h1 >> 16
    return h1 - 0x100000000 if h1 & 0x80000000 else h1


def shodan_favicon_hash(content: bytes) -> int:
    """Shodan's definition: mmh3.hash(base64.encodebytes(favicon_bytes))."""
    return murmur3_32(base64.encodebytes(content))


def _fetch_favicon(host: str, timeout: int):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/125.0 Safari/537.36"
    for scheme in ("https", "http"):
        base = host if "://" in host else f"{scheme}://{host}"
        url = base.rstrip("/") + "/favicon.ico"
        try:
            req = urllib.request.Request(url, headers={"User-Agent": ua})
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                content = resp.read(1024 * 256)  # cap at 256 KB
            if content:
                return {"host": host, "url": url, "favicon_hash": shodan_favicon_hash(content)}
        except Exception:
            continue
    return None


def _run(target_file: str, output_file: str, timeout: int, workers: int):
    hosts = [l.strip() for l in open(target_file) if l.strip()]
    with open(output_file, "w") as out:
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
            for res in ex.map(lambda h: _fetch_favicon(h, timeout), hosts):
                if res:
                    out.write(json.dumps(res) + "\n")


class FaviconEngine(BaseEngine):
    name = "favicon"
    binary = sys.executable  # pure-Python; always available

    def is_available(self) -> bool:
        return True

    def get_binary_path(self):
        return sys.executable

    def build_command(
        self, target_file: str, output_file: str, config: ScanConfig
    ) -> List[str]:
        return [
            sys.executable, "-m", "techrecon.engines._favicon_run",
            "-l", target_file,
            "-o", output_file,
            "-t", str(config.timeout),
            "-w", str(min(config.threads, 30)),
        ]

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
                h = d.get("favicon_hash")
                host = d.get("host", "")
                if h is None or not host:
                    continue
                techs = [{"name": "Favicon", "version": str(h), "source": "favicon"}]
                known = FAVICON_DB.get(str(h))
                if known:
                    techs.append({"name": known, "version": "", "source": "favicon"})
                results.append({
                    "url": d.get("url", host),
                    "host": host,
                    "input": host,
                    "status_code": "",
                    "title": "",
                    "webserver": "",
                    "cdn": "",
                    "technologies": techs,
                })
        return results


def main():
    ap = argparse.ArgumentParser(prog="techrecon-favicon")
    ap.add_argument("--run", action="store_true", help="run the favicon fetcher")
    ap.add_argument("-l", "--list", required=True)
    ap.add_argument("-o", "--output", required=True)
    ap.add_argument("-t", "--timeout", type=int, default=10)
    ap.add_argument("-w", "--workers", type=int, default=30)
    args = ap.parse_args()
    _run(args.list, args.output, args.timeout, args.workers)


if __name__ == "__main__":
    main()
