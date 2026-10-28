# techrecon

Technology stack detection framework for asset inventories. Scans a CSV of targets and produces a consolidated `technology_ver.csv` with identified technologies, versions, and risk metadata — then normalizes, deduplicates, and tracks coverage improvement across runs.

## Features

- **Multi-engine scanning** — httpx (Wappalyzer), nuclei (templates), whatweb (1800+ plugins), webanalyze, katana (crawler), tlsx (TLS/cert), favicon (hash fingerprint)
- **Multi-pass deep scanning** (`--deep`) — runs primary engines first, finds targets with no tech / no version, then re-scans only those gaps with additional engines
- **Technology normalization** — merges duplicate names (`nginx`/`NGINX`/`Nginx` → `Nginx`), filters non-technology noise (HSTS, Cookies, UncommonHeaders), and re-deduplicates
- **Cross-engine version promotion** — if one engine finds `Nginx 1.22.1` and another finds bare `Nginx` on the same target, the version is propagated
- **Deep data extraction** — compound `Server` headers (`Apache/2.4.25 OpenSSL/1.0.2j PHP/5.6.30` → 3 components), CPE data, page-title versions, and header-inferred versions
- **Full coverage accounting** — every scanned target appears in the output, including unreachable ones flagged with a `detection_source` reason (no silent drops)
- **Run history & improvement tracking** — each scan is recorded to `run_history.csv`; `history` and `compare` show deltas and a verdict (IMPROVED / PARTIAL / REGRESSION)
- **Smart filtering** — auto-skip internal/private IPs, scope-aware, deduplication
- **Metadata enrichment** — joins scan results with asset inventory (risk scores, target types, scope status)
- **Outdated tech detection** — built-in checks for EOL software (OpenSSL 1.0.x, PHP 5.x/7.x, Apache 2.2.x, jQuery 1.x/2.x)

## Extended detection engines

Three engines target the gaps that header/template scanning can't reach:

- **katana** (crawler) — crawls each site (incl. JavaScript) and infers technology from discovered paths and bundle names: `/_next/` → Next.js, `wp-content` → WordPress, `jquery-3.6.0.min.js` → jQuery 3.6.0, etc. Strong for **SPA frameworks and JS-library versions** that never appear in HTTP headers.
- **tlsx** (TLS/certificate) — reads the TLS handshake: negotiated **TLS version** (flags legacy 1.0/1.1), cipher, certificate issuer CA, and JARM fingerprint. Works on hosts that **reject HTTP fingerprinting** but still complete a TLS handshake.
- **favicon** (hash fingerprint, built-in) — fetches `/favicon.ico` and computes the **Shodan-compatible mmh3 hash**. Favicons pass straight through CDNs/WAFs, so the hash fingerprints the **origin application behind Akamai/Cloudflare**. The raw hash is written to `favicon_results.jsonl` and emitted as the `version` of a `Favicon` entry — pivot it on Shodan with `http.favicon.hash:<hash>`. Seed `FAVICON_DB` in `engines/favicon.py` with your own standard-portal hashes to auto-identify internal assets.

```bash
# Use them explicitly
techrecon scan -i targets.csv -o out.csv -e httpx tlsx favicon katana -v

# Or let --deep add them automatically on gap targets (no tech / no version)
techrecon scan -i targets.csv -o out.csv -e httpx nuclei whatweb --deep -v
```

## Installation

### Docker (recommended — all tools included)

```bash
git clone https://github.com/vietd0x/techrecon.git
cd techrecon

# Build image (bundles httpx + nuclei + whatweb + webanalyze)
docker build -t techrecon .

# Or with make
make build
```

### From source with uv (recommended)

[uv](https://github.com/astral-sh/uv) is a fast Python package/venv manager.

```bash
git clone https://github.com/vietd0x/techrecon.git
cd techrecon

# Create an isolated environment and install techrecon (editable)
uv venv --python 3.12
uv pip install -e .

# Run via the venv (either activate it, or prefix with `uv run`)
uv run techrecon --version
uv run techrecon engines
```

> On filesystems that don't support symlinks (e.g. VMware HGFS shares), create the
> venv on a local path and use copy mode:
> ```bash
> export UV_LINK_MODE=copy
> uv venv /home/<user>/.venv-techrecon --python 3.12
> uv pip install --python /home/<user>/.venv-techrecon/bin/python -e ".[dev]"
> /home/<user>/.venv-techrecon/bin/techrecon engines
> ```

### From source with pip

```bash
git clone https://github.com/vietd0x/techrecon.git
cd techrecon
pip install -e .
```

### External tools (only needed for source install, Docker includes all)

| Engine | Install | Purpose |
|--------|---------|---------|
| [httpx](https://github.com/projectdiscovery/httpx) | `go install github.com/projectdiscovery/httpx/cmd/httpx@latest` | Wappalyzer tech detection, Server/CPE/title parsing |
| [nuclei](https://github.com/projectdiscovery/nuclei) | `go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` | Template-based fingerprinting |
| [whatweb](https://github.com/urbanadventurer/WhatWeb) | `git clone` + `gem install addressable` | 1800+ plugin deep scan |
| [webanalyze](https://github.com/rverton/webanalyze) | `go install github.com/rverton/webanalyze/cmd/webanalyze@latest` | Wappalyzer CLI |
| [katana](https://github.com/projectdiscovery/katana) | `go install github.com/projectdiscovery/katana/cmd/katana@latest` | Crawler — infers SPA frameworks + JS-library versions from discovered URLs |
| [tlsx](https://github.com/projectdiscovery/tlsx) | `go install github.com/projectdiscovery/tlsx/cmd/tlsx@latest` | TLS version, cipher, cert CA, JARM — works even on hosts that block HTTP |
| favicon | *(built-in, pure Python)* | Shodan-compatible favicon mmh3 hash — fingerprints origin through CDN/WAF |

> Note: WhatWeb is not published on RubyGems — the Docker image installs it from GitHub. For source installs, clone the repo and put `whatweb` on your `PATH`.

## Windows Setup (Python, no Docker)

The framework is pure Python (only dependency: PyYAML) and runs on Windows unmodified — binary lookup uses `shutil.which`, which resolves `.exe` automatically. Three of the four engines ship native Windows binaries; WhatWeb needs Ruby (optional).

> Engine coverage on native Windows: **httpx + nuclei + webanalyze** install cleanly as `.exe`. **WhatWeb** requires Ruby — install it only if you want its (strong) version detection. If you want all four engines with zero tool-wrangling, use Docker Desktop (WSL2) with the Linux image instead — see [Windows via Docker](#windows-via-docker-full-engine-parity).

### Step 1 — Install uv

uv bundles Python management and virtualenvs — the simplest path on Windows. In PowerShell:

```powershell
winget install astral-sh.uv
# or: powershell -c "irm https://astral.sh/uv/install.ps1 | iex"
uv --version
```

(No separate Python install needed — uv fetches the interpreter in the next step.)

### Step 2 — Install techrecon

```powershell
# Clone (or copy) the project, then from its folder:
cd C:\tools\techrecon

uv venv --python 3.12
uv pip install -e .

# Verify (activate the venv, or prefix commands with `uv run`)
uv run techrecon --version
```

> Prefer plain pip? `python -m venv .venv ; .\.venv\Scripts\Activate.ps1 ; pip install -e .`

### Step 3 — Install the scan engines (`.exe`)

Create a folder for the binaries and add it to PATH, e.g. `C:\tools\bin`:

```powershell
mkdir C:\tools\bin
```

Download the Windows builds and extract the `.exe` files into `C:\tools\bin`:

| Engine | Download (Windows amd64) |
|--------|--------------------------|
| httpx | https://github.com/projectdiscovery/httpx/releases → `httpx_*_windows_amd64.zip` |
| nuclei | https://github.com/projectdiscovery/nuclei/releases → `nuclei_*_windows_amd64.zip` |
| webanalyze | https://github.com/rverton/webanalyze/releases → `webanalyze_*_Windows_x86_64.zip` |

Add the folder to PATH for the current session (persist it in System Environment Variables for permanence):

```powershell
$env:Path += ";C:\tools\bin"
```

Initialize the engine databases:

```powershell
nuclei -update-templates
webanalyze -update        # downloads technologies.json into the current folder
```

### Step 4 (optional) — WhatWeb for best version detection

WhatWeb is a Ruby program. Install Ruby via [RubyInstaller](https://rubyinstaller.org/) (or `winget install RubyInstallerTeam.Ruby.3.3`), then:

```powershell
git clone --depth 1 https://github.com/urbanadventurer/WhatWeb.git C:\tools\WhatWeb
gem install addressable --no-document

# Create a wrapper so `whatweb` is callable (Ruby scripts aren't .exe)
Set-Content C:\tools\bin\whatweb.bat "@ruby C:\tools\WhatWeb\whatweb %*"
```

### Step 5 — Verify engines are detected

```powershell
uv run techrecon engines
```

Expected (WhatWeb only if Step 4 was done):

```
Available scan engines:
  httpx            [installed]  C:\tools\bin\httpx.exe
  nuclei           [installed]  C:\tools\bin\nuclei.exe
  whatweb          [installed]  C:\tools\bin\whatweb.bat
  webanalyze       [installed]  C:\tools\bin\webanalyze.exe
```

### Step 6 — Run a scan

```powershell
# Quick scan (httpx only)
uv run techrecon scan -i C:\data\targets.csv -o C:\data\technology_ver.csv -v

# Best detection (all installed engines + deep pass)
uv run techrecon scan -i C:\data\targets.csv -o C:\data\technology_ver.csv `
  -e httpx nuclei whatweb webanalyze favicon tlsx katana --deep `
  --threads 50 --timeout 15 --retries 2 -v

# Reports and coverage
uv run techrecon report -i C:\data\technology_ver.csv --all
uv run techrecon coverage -i C:\data\technology_ver.csv
```

> PowerShell line continuation is the backtick `` ` ``. In `cmd.exe`, put the whole command on one line or use `^` for continuation.

### Windows via Docker (full engine parity)

If Docker Desktop (WSL2 backend) is available, the Linux image runs all four engines with no per-tool setup. Drop `--network host` (not supported on Docker Desktop; the container has normal outbound access):

```powershell
docker run --rm `
  -v C:\data\targets.csv:/data/input/targets.csv:ro `
  -v C:\data\output:/data/output `
  techrecon:minimal scan -i /data/input/targets.csv -o /data/output/technology_ver.csv `
    -e httpx nuclei whatweb webanalyze --deep -v
```

### Windows troubleshooting

| Symptom | Fix |
|---------|-----|
| `techrecon` not recognized | Reopen terminal, or use `python -m techrecon.cli ...`; ensure Python Scripts dir is on PATH |
| `engines` shows `NOT FOUND` | The `.exe` isn't on PATH — confirm `C:\tools\bin` is in `$env:Path` and the binary is there |
| `nuclei`: no templates | Run `nuclei -update-templates` once (needs internet) |
| WhatWeb does nothing | Ruby not installed or `whatweb.bat` wrapper path wrong |
| TLS/handshake errors on some hosts | Lower `--threads` (e.g. `10`) and raise `--timeout` (e.g. `30`) |

## Quick Start

### With Docker

```bash
# Copy targets.csv into data/input/
mkdir -p data/input data/output
cp /path/to/targets.csv data/input/

# Scan (all engines + deep pass)
docker run --rm --network host \
  -v $(pwd)/data/input:/data/input \
  -v $(pwd)/data/output:/data/output \
  techrecon scan -i /data/input/targets.csv -o /data/output/technology_ver.csv \
    -e httpx nuclei whatweb webanalyze --deep -v

# Report
make report

# Check engines
make engines
```

### Without Docker

```bash
# Quick scan with httpx (default engine)
techrecon scan -i targets.csv -o technology_ver.csv

# Full multi-engine scan with deep pass
techrecon scan -i targets.csv -o technology_ver.csv \
  -e httpx nuclei whatweb webanalyze --deep --threads 50 --timeout 15 --retries 2 -v

# Coverage snapshot of an existing CSV
techrecon coverage -i technology_ver.csv

# Show run history and compare the last two runs
techrecon history
techrecon compare

# Normalize/dedup an existing CSV in place
techrecon normalize -i technology_ver.csv

# Generate reports
techrecon report -i technology_ver.csv --all
```

## Recommended Scan Profiles

| Goal | Command |
|------|---------|
| Fast triage | `techrecon scan -i t.csv -o out.csv` |
| Balanced | `techrecon scan -i t.csv -o out.csv -e httpx whatweb --deep` |
| Maximum coverage | `techrecon scan -i t.csv -o out.csv -e httpx nuclei whatweb webanalyze --deep --timeout 15 --retries 2` |
| Reach slow/TLS-sensitive hosts | lower `--threads` (e.g. `10`), raise `--timeout` (e.g. `30`), `--retries 3` |

High thread counts can starve slow-TLS hosts into timing out. If targets that respond to `curl` are missing from the output, re-scan them with low concurrency and a longer timeout.

## Input Format

`targets.csv` — asset inventory with these columns:

| Column | Required | Description |
|--------|----------|-------------|
| `target` | Yes | Hostname, IP, URL, or host:port |
| `target_type` | No | `hostname`, `ip`, `url`, `host_port` |
| `host` | No | Resolved hostname |
| `scan_zone` | No | `external` or `internal` |
| `scope_status` | No | `in_scope` or `out_of_scope` |
| `risk_score` | No | Numeric risk score for prioritization |

Example:
```csv
target,target_type,host,scan_zone,scope_status,risk_score
example.com,hostname,example.com,external,in_scope,50.0
192.168.1.1,ip,192.168.1.1,internal,in_scope,10.0
```

## Output Format

`technology_ver.csv` — one row per (target, technology) pair:

| Column | Description |
|--------|-------------|
| `target` | Original target from inventory (canonical, scheme-stripped) |
| `url` | Scanned URL |
| `host` | Hostname/IP |
| `status_code` | HTTP response code |
| `title` | Page title |
| `technology` | Technology name (e.g. Nginx, PHP, jQuery) |
| `version` | Version if detected |
| `detection_source` | See table below |
| `webserver` | Raw Server header |
| `cdn` | CDN name if detected |
| `target_type` | From asset inventory |
| `scope_status` | From asset inventory |
| `risk_score` | From asset inventory |

### `detection_source` values

| Source | Meaning |
|--------|---------|
| `wappalyzer` | httpx Wappalyzer engine |
| `http_header` | parsed from the `Server` header |
| `http_header_inferred` | version inferred from the header on an otherwise tech-less target |
| `http_header_recovery` | recovered in a low-concurrency re-probe of a previously-missed host |
| `cpe` | CPE product data from httpx |
| `title` | version parsed from the page title |
| `cdn` | CDN detection |
| `nuclei` | nuclei template match |
| `whatweb` | whatweb plugin |
| `webanalyze` | webanalyze Wappalyzer CLI |
| `katana` | framework/library inferred from crawled URLs & JS bundles |
| `tlsx` | TLS version / cipher / JARM from the TLS handshake |
| `tlsx_cert` | certificate issuer (CA) organisation |
| `favicon` | Shodan-compatible favicon mmh3 hash (and DB match if known) |
| `hostname_pattern` | inferred from the hostname (e.g. `appgate*` → Appgate SDP, `autodiscover` → Exchange) |
| `cname` | real backend inferred from the DNS CNAME chain (e.g. CNAME → `*.edgekey.net` = Akamai, `*.elb.amazonaws.com` = AWS ELB) |
| `responsive_no_banner` | target responded but exposed no identifiable banner |
| `no_response` | target did not respond (dead IP, TLS reset, or connection filtered) |

## Configuration

```yaml
# config.yaml
engine:
  enabled:
    - httpx
  httpx:
    threads: 50
    timeout: 10
    retries: 1
    rate_limit: 0          # 0 = unlimited
    follow_redirects: true

filter:
  external_only: true
  skip_internal: true
  target_types:
    - hostname
    - ip
    - url
    - host_port
  scope_status:
    - in_scope

output_dir: output
```

## CLI Reference

```
techrecon scan -i <targets.csv> -o <output.csv> [options]

Options:
  -i, --input          Input targets CSV (required)
  -o, --output         Output technology CSV (default: technology_ver.csv)
  -c, --config         Config YAML file
  -e, --engines        Engines: httpx nuclei whatweb webanalyze
  --deep               Deep pass: re-scan gap targets with additional engines
  --threads            Concurrent threads (default: 50)
  --timeout            Request timeout seconds (default: 10)
  --retries            Retries per request (default: 1)
  --rate-limit         Rate limit requests/sec (0=unlimited)
  --include-internal   Include internal/private IPs
  --output-dir         Working directory (default: output)
  -v, --verbose        Verbose output

techrecon report -i <technology_ver.csv> [options]
  --outdated           Check for EOL/outdated technologies
  --risk               Risk-prioritized target list
  --all                All report types

techrecon coverage  -i <technology_ver.csv>   Coverage metrics for a CSV
techrecon normalize -i <csv> [-o <csv>]       Normalize + dedup tech names
techrecon history   [--output-dir <dir>]      Show all recorded runs
techrecon compare   [--output-dir <dir>]      Delta between the last two runs
techrecon engines                             List engines and install status
```

## How the Pipeline Works

```
1. Filter      targets.csv → in-scope, external, deduped → scan_targets.txt
2. Scan        run each primary engine → raw per-engine JSONL
3. Deep pass   (--deep) find no-tech / no-version targets → re-scan with extra engines
4. Normalize   merge duplicate names, drop noise, promote versions, infer from headers
5. Enrich      join asset metadata (risk, type, scope) → technology_ver.csv
6. Track       record coverage stats to run_history.csv, print comparison vs previous run
```

### Coverage metrics (`coverage` / end of every scan)

- **Tech coverage %** — targets with ≥1 technology ÷ total targets
- **Version coverage %** — targets with ≥1 versioned technology ÷ total targets
- **Entry-level version %** — versioned tech entries ÷ all tech entries

## Project Structure

```
techrecon/
├── techrecon/
│   ├── __init__.py
│   ├── cli.py           # CLI entry point (scan/report/coverage/normalize/history/compare/engines)
│   ├── scanner.py       # Scan orchestrator (filter → scan → deep → normalize → enrich → track)
│   ├── filter.py        # Target filtering
│   ├── normalizer.py    # Name canonicalization, noise filter, version promotion, coverage stats
│   ├── enricher.py      # Metadata enrichment + CSV output
│   ├── reporter.py      # Summary, outdated checks, risk reports
│   ├── tracker.py       # run_history.csv recording + run comparison
│   ├── config.py        # YAML configuration
│   └── engines/
│       ├── __init__.py   # Engine registry
│       ├── base.py       # Base engine class
│       ├── httpx.py      # httpx (Wappalyzer, Server/CPE/title parsing)
│       ├── nuclei.py     # nuclei (templates, expanded tags)
│       ├── whatweb.py    # whatweb (1800+ plugins, bare-host normalization)
│       ├── webanalyze.py # webanalyze (Wappalyzer CLI)
│       ├── katana.py     # katana crawler + JS/URL tech inference
│       ├── tlsx.py       # tlsx TLS/certificate scanning
│       └── favicon.py    # favicon mmh3 hash (pure Python, self-runs)
├── config/
│   └── default.yaml
├── Dockerfile           # Multi-stage build (Go 1.27 builder + Python 3.12 runtime)
├── docker-compose.yml
├── Makefile             # make build / scan / report / engines
├── pyproject.toml
├── requirements.txt
├── LICENSE
└── README.md
```

## Docker Image Contents

| Tool | Version | Source |
|------|---------|--------|
| httpx | latest | `go install github.com/projectdiscovery/httpx/cmd/httpx@latest` |
| nuclei | latest | `go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` |
| whatweb | latest | `git clone https://github.com/urbanadventurer/WhatWeb` + `gem install addressable` |
| webanalyze | latest | `go install github.com/rverton/webanalyze/cmd/webanalyze@latest` |
| katana | latest | `go install github.com/projectdiscovery/katana/cmd/katana@latest` |
| tlsx | latest | `go install github.com/projectdiscovery/tlsx/cmd/tlsx@latest` |
| favicon | built-in | pure-Python engine (no external binary) |
| Python | 3.12 | Base image `python:3.12-slim-bookworm` |
| nuclei-templates | latest | Auto-updated at build time |

## License

MIT
