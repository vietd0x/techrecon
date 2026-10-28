"""Technology name normalization — merge duplicates, filter noise, promote versions."""

import re
from typing import Dict, List, Set, Tuple

CANONICAL_NAMES: Dict[str, str] = {
    "nginx": "Nginx",
    "NGINX": "Nginx",
    "apache": "Apache",
    "apache http server": "Apache",
    "Apache HTTP Server": "Apache",
    "microsoft-iis": "IIS",
    "Microsoft-IIS": "IIS",
    "iis": "IIS",
    "openresty": "OpenResty",
    "gws": "Google Web Server",
    "google": "Google Web Server",
    "cloudflare": "Cloudflare",
    "cloudfront": "Amazon CloudFront",
    "Amazon CloudFront": "Amazon CloudFront",
    "akamai": "Akamai",
    "AkamaiGHost": "Akamai",
    "Akamai-Global-Host": "Akamai",
    "Akamai Global Host": "Akamai",
    "jquery": "jQuery",
    "jQuery": "jQuery",
    "microsoft httpapi": "Microsoft HTTPAPI",
    "Microsoft HTTPAPI": "Microsoft HTTPAPI",
    "Microsoft-HTTPAPI": "Microsoft HTTPAPI",
    "microsoft asp.net": "ASP.NET",
    "Microsoft ASP.NET": "ASP.NET",
    "asp.net": "ASP.NET",
    "ASP.NET": "ASP.NET",
    "awselb": "AWS ELB",
    "Amazon ELB": "AWS ELB",
    "Amazon Web Services": "AWS",
    "AmazonS3": "Amazon S3",
    "bootstrapcdn": "Bootstrap",
    "BootstrapCDN": "Bootstrap",
    "all in one seo pack": "All in One SEO",
    "All in One SEO Pack": "All in One SEO",
    "php": "PHP",
    "openssl": "OpenSSL",
    "perl": "Perl",
    "mod_perl": "mod_perl",
    "istio-envoy": "Envoy",
    "Microsoft-Azure-Application-Gateway/v2": "Azure Application Gateway",
    "Microsoft-Azure-Application-Gateway": "Azure Application Gateway",
    "Cloudrity": "Cloudrity",
    "webp_server_go": "WebP Server Go",
    "Amazon-CloudFront": "Amazon CloudFront",
    "cloudfront": "Amazon CloudFront",
}

NOISE_TECHS: Set[str] = {
    "HSTS", "Strict-Transport-Security",
    "UncommonHeaders", "Uncommon-Headers",
    "RedirectLocation", "Redirect-Location",
    "Cookies",
    "HTTP/3",
    "Via-Proxy",
    "X-Frame-Options", "X-XSS-Protection", "X-UA-Compatible",
    "Meta-Refresh-Redirect",
    "Title", "IP", "Country",
    "v2", "v1", "dev", "Unix",
    "HTTPServer",
    "Basic Auth Detection",
}

_NOT_A_VERSION_RE = re.compile(
    r"^[a-f0-9]{8}-[a-f0-9]{4}-|^Basic$|^[a-zA-Z]+$"
)

# Hostname-pattern recognition for targets that return no usable banner.
# Ordered (regex, technology). The pattern matches anywhere in the hostname.
# detection_source = "hostname_pattern" makes clear these are name-based inferences.
HOSTNAME_PATTERNS = [
    # --- DNS-suffix giveaways (CDN / cloud / PaaS) ---
    (re.compile(r"\.edgekey\.net$|\.akamaiedge\.net$|\.akamai(zed)?\.net$"), "Akamai"),
    (re.compile(r"\.cloudfront\.net$"), "Amazon CloudFront"),
    (re.compile(r"\.msappproxy\.net$"), "Azure AD Application Proxy"),
    (re.compile(r"\.azurewebsites\.net$"), "Azure App Service"),
    (re.compile(r"\.trafficmanager\.net$"), "Azure Traffic Manager"),
    (re.compile(r"\.blob\.core\.windows\.net$"), "Azure Blob Storage"),
    (re.compile(r"\.elb\.amazonaws\.com$|\.elb\.[a-z0-9-]+\.amazonaws\.com$"), "AWS ELB"),
    (re.compile(r"\.s3[.-][a-z0-9-]*\.amazonaws\.com$|\.s3\.amazonaws\.com$"), "Amazon S3"),
    (re.compile(r"\.github\.io$"), "GitHub Pages"),
    (re.compile(r"\.herokuapp\.com$"), "Heroku"),
    (re.compile(r"\.substack\.com$"), "Substack"),
    # --- product names embedded in the hostname ---
    (re.compile(r"(^|[.-])appgate|appgategw|awsappgate|appgatedmz"), "Appgate SDP"),
    (re.compile(r"(^|[.-])autodiscover([.-]|$)"), "Microsoft Exchange"),
    (re.compile(r"(^|[.-])(owa|outlook|exchange|mail)([.-]|$)"), "Microsoft Exchange"),
    (re.compile(r"(^|[.-])confluence"), "Atlassian Confluence"),
    (re.compile(r"(^|[.-])jira"), "Atlassian Jira"),
    (re.compile(r"(^|[.-])gitlab"), "GitLab"),
    (re.compile(r"(^|[.-])jenkins"), "Jenkins"),
    (re.compile(r"(^|[.-])grafana"), "Grafana"),
    (re.compile(r"(^|[.-])kibana"), "Kibana"),
    (re.compile(r"(^|[.-])sonar(qube)?([.-]|$)"), "SonarQube"),
    (re.compile(r"(^|[.-])nexus([.-]|$)"), "Sonatype Nexus"),
    (re.compile(r"(^|[.-])vcenter|vsphere"), "VMware vCenter"),
    (re.compile(r"(^|[.-])citrix|netscaler"), "Citrix"),
    # --- role hints (not a product, but better than nothing) ---
    (re.compile(r"(^|[.-])(api-?gw|apigateway|api-gateway)([.-]|$)"), "API Gateway"),
    (re.compile(r"(^|[.-])(vpn|sslvpn)([.-]|$)"), "VPN Gateway"),
    (re.compile(r"(^|[.-])(sso|adfs|idp|login|auth)([.-]|$)"), "SSO / Identity"),
    (re.compile(r"(^|[.-])(smtp|imap|pop3?)([.-]|$)"), "Mail Server"),
]


def recognize_hostname(host: str) -> str:
    """Return an inferred technology for a hostname, or '' if no pattern matches."""
    if not host:
        return ""
    h = host.lower()
    for pat, tech in HOSTNAME_PATTERNS:
        if pat.search(h):
            return tech
    return ""

_SERVER_VER_RE = re.compile(
    r"([a-zA-Z][a-zA-Z0-9._-]*)/([\d]+\.[\d]+[\d.]*)"
)

_LOWER_MAP: Dict[str, str] = {}


def _build_lower_map():
    if _LOWER_MAP:
        return
    for variant, canonical in CANONICAL_NAMES.items():
        _LOWER_MAP[variant.lower()] = canonical


def normalize_tech_name(name: str) -> str:
    _build_lower_map()
    if not name:
        return name
    canonical = _LOWER_MAP.get(name.lower())
    if canonical:
        return canonical
    return CANONICAL_NAMES.get(name, name)


def normalize_rows(rows: List[dict]) -> List[dict]:
    """Normalize names, filter noise, promote versions cross-engine, infer from headers."""
    # Phase 1: normalize names, filter noise, clean bad versions
    cleaned = []
    for r in rows:
        tech = r.get("technology", "")
        if tech:
            r = dict(r)
            r["technology"] = normalize_tech_name(tech)
        if r.get("technology", "") in NOISE_TECHS:
            continue
        ver = r.get("version", "")
        if ver and _NOT_A_VERSION_RE.match(ver):
            r = dict(r)
            r["version"] = ""
        cleaned.append(r)

    # Phase 2: infer tech from webserver header for targets with no tech
    targets_with_tech = {r["target"] for r in cleaned if r.get("technology")}
    header_inferred = []
    seen_inferred = set()
    for r in cleaned:
        t = r.get("target", "")
        if t in targets_with_tech or t in seen_inferred:
            continue
        ws = r.get("webserver", "")
        if ws:
            for m in _SERVER_VER_RE.finditer(ws):
                name = normalize_tech_name(m.group(1))
                ver = m.group(2)
                new_row = dict(r)
                new_row["technology"] = name
                new_row["version"] = ver
                new_row["detection_source"] = "http_header_inferred"
                header_inferred.append(new_row)
                seen_inferred.add(t)
    cleaned.extend(header_inferred)

    # Phase 3: cross-engine version promotion
    best_version: Dict[Tuple[str, str], str] = {}
    for r in cleaned:
        key = (r.get("target", ""), r.get("technology", ""))
        ver = r.get("version", "")
        if ver and (key not in best_version or len(ver) > len(best_version[key])):
            best_version[key] = ver

    promoted = []
    for r in cleaned:
        key = (r.get("target", ""), r.get("technology", ""))
        if not r.get("version") and key in best_version:
            r = dict(r)
            r["version"] = best_version[key]
        promoted.append(r)

    # Phase 4: hostname-pattern recognition for targets with no detected tech.
    targets_with_tech_now = {r["target"] for r in promoted if r.get("technology")}
    inferred_host = []
    host_seen = set()
    for r in promoted:
        t = r.get("target", "")
        if t in targets_with_tech_now or t in host_seen:
            continue
        tech = recognize_hostname(t)
        if tech:
            new_row = dict(r)
            new_row["technology"] = tech
            new_row["version"] = ""
            new_row["detection_source"] = "hostname_pattern"
            inferred_host.append(new_row)
            host_seen.add(t)
    promoted.extend(inferred_host)

    # Phase 5: dedup
    seen = set()
    normalized = []
    for r in promoted:
        key = (r.get("target", ""), r.get("url", ""), r.get("technology", ""), r.get("version", ""))
        if key in seen:
            continue
        seen.add(key)
        normalized.append(r)

    normalized.sort(key=lambda r: (r.get("target", ""), r.get("technology", "")))
    return normalized


def get_coverage_stats(rows: List[dict]) -> Dict:
    """Compute coverage metrics after normalization."""
    all_targets = set()
    targets_with_tech = set()
    targets_with_ver = set()
    tech_entries = 0
    ver_entries = 0

    for r in rows:
        t = r.get("target", "")
        all_targets.add(t)
        tech = r.get("technology", "")
        ver = r.get("version", "")
        if tech:
            targets_with_tech.add(t)
            tech_entries += 1
            if ver:
                targets_with_ver.add(t)
                ver_entries += 1

    total = len(all_targets) or 1
    return {
        "total_targets": len(all_targets),
        "targets_with_tech": len(targets_with_tech),
        "targets_no_tech": len(all_targets - targets_with_tech),
        "targets_with_version": len(targets_with_ver),
        "targets_tech_no_version": len(targets_with_tech - targets_with_ver),
        "tech_entries": tech_entries,
        "ver_entries": ver_entries,
        "tech_coverage_pct": round(len(targets_with_tech) / total * 100, 1),
        "ver_coverage_pct": round(len(targets_with_ver) / total * 100, 1),
        "entry_ver_pct": round(ver_entries / max(tech_entries, 1) * 100, 1),
    }
