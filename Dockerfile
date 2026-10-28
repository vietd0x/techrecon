# ============================================================
# Stage 1: Build Go tools + fetch WhatWeb (git lives only here)
# ============================================================
FROM golang:1.27-bookworm AS builder

ENV CGO_ENABLED=0

RUN go install github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && \
    go install github.com/rverton/webanalyze/cmd/webanalyze@latest && \
    go install github.com/projectdiscovery/katana/cmd/katana@latest && \
    go install github.com/projectdiscovery/tlsx/cmd/tlsx@latest

# Clone WhatWeb here so neither git nor the .git history reach the runtime
RUN git clone --depth 1 https://github.com/urbanadventurer/WhatWeb.git /opt/whatweb && \
    rm -rf /opt/whatweb/.git

# Clone nuclei-templates in the builder (reliable) instead of relying on
# `nuclei -update-templates` at runtime, which silently fetched nothing.
RUN git clone --depth 1 https://github.com/projectdiscovery/nuclei-templates.git /opt/nuclei-templates && \
    rm -rf /opt/nuclei-templates/.git

# ============================================================
# Stage 2: Runtime image (no build toolchain, no git)
# ============================================================
FROM python:3.12-slim-bookworm

LABEL maintainer="MBBank Security Team"
LABEL description="techrecon - Technology stack detection framework"
LABEL version="1.1.0"

# Runtime-only deps. WhatWeb needs the Ruby runtime + the pure-Ruby
# 'addressable' gem (no native extensions -> no build-essential/ruby-dev).
# Install, add gem, and clean apt lists in ONE layer so nothing lingers.
RUN apt-get update && apt-get install -y --no-install-recommends \
        ruby \
        ca-certificates \
        curl \
        dnsutils \
    && gem install addressable --no-document \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* /var/cache/apt/*

# Copy engine binaries + WhatWeb from the builder stage
COPY --from=builder /go/bin/httpx /usr/local/bin/httpx
COPY --from=builder /go/bin/nuclei /usr/local/bin/nuclei
COPY --from=builder /go/bin/webanalyze /usr/local/bin/webanalyze
COPY --from=builder /go/bin/katana /usr/local/bin/katana
COPY --from=builder /go/bin/tlsx /usr/local/bin/tlsx
COPY --from=builder /opt/whatweb /opt/whatweb
RUN ln -s /opt/whatweb/whatweb /usr/local/bin/whatweb

# nuclei templates: place at the default location nuclei auto-discovers ($HOME/nuclei-templates)
COPY --from=builder /opt/nuclei-templates /root/nuclei-templates

# Register templates with nuclei + refresh webanalyze tech DB.
# Fail the build loudly if templates are missing (no silent masking this time).
RUN nuclei -update-template-dir /root/nuclei-templates -ut 2>/dev/null; \
    tcount=$(find /root/nuclei-templates -name '*.yaml' | wc -l); \
    echo "nuclei templates installed: $tcount"; \
    [ "$tcount" -gt 100 ] || (echo "ERROR: nuclei templates missing" && exit 1); \
    webanalyze -update 2>/dev/null || true; \
    rm -rf /root/.cache

# Install techrecon (PyYAML is the only dependency)
WORKDIR /app
COPY pyproject.toml requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY techrecon ./techrecon
COPY README.md LICENSE ./
RUN pip install --no-cache-dir -e . && rm -rf /root/.cache

RUN mkdir -p /data/input /data/output
WORKDIR /data

ENTRYPOINT ["techrecon"]
CMD ["--help"]
