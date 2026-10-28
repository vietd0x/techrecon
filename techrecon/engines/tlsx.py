"""tlsx engine — TLS/certificate scanning (TLS version, cipher, cert org, JARM)."""

import json
from typing import List

from ..config import ScanConfig
from .base import BaseEngine


class TlsxEngine(BaseEngine):
    name = "tlsx"
    binary = "tlsx"

    def build_command(
        self, target_file: str, output_file: str, config: ScanConfig
    ) -> List[str]:
        cmd = [
            self.get_binary_path() or "tlsx",
            "-list", target_file,
            "-json",
            "-o", output_file,
            "-silent",
            "-no-color",
            "-c", str(config.threads),
            "-timeout", str(config.timeout),
            "-tls-version",   # negotiated TLS version
            "-cipher",        # negotiated cipher
            "-cn", "-san",    # subject CN + SANs
            "-so",            # subject org / issuer org
            "-jarm",          # JARM fingerprint
        ]
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
        host = d.get("host", "")
        techs = []

        tls_version = d.get("tls_version", "")
        if tls_version:
            # normalise e.g. "tls12" / "TLS 1.2" into a clean "TLS 1.2"
            v = tls_version.lower().replace("tls", "").replace("v", "").strip()
            v = v.replace("13", "1.3").replace("12", "1.2").replace("11", "1.1").replace("10", "1.0")
            techs.append({"name": "TLS", "version": v, "source": "tlsx"})

        cipher = d.get("cipher", "")
        if cipher:
            techs.append({"name": "TLS Cipher", "version": cipher, "source": "tlsx"})

        # Certificate issuer organisation (CA) — useful inventory context.
        issuer = d.get("issuer_org") or d.get("issuer_organization") or []
        if isinstance(issuer, list):
            issuer = issuer[0] if issuer else ""
        if issuer:
            techs.append({"name": f"Cert CA: {issuer}", "version": "", "source": "tlsx_cert"})

        jarm = d.get("jarm_hash") or d.get("jarm", "")
        if jarm:
            techs.append({"name": "JARM", "version": str(jarm), "source": "tlsx"})

        return {
            "url": host,
            "host": host,
            "input": host,
            "status_code": "",
            "title": "",
            "webserver": "",
            "cdn": "",
            "technologies": techs,
        }
