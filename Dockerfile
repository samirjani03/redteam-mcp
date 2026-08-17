# =============================================================================
# RedTeam MCP v2 — Kali Linux Bug-Bounty Container (stable build)
# =============================================================================
# Build:
#   docker build -t redteam-mcp-v2:latest -f Dockerfile .
# Run:
#   docker run -d --name redteam-mcp-v2 \
#     -v redteam-data:/app/data -v redteam-reports:/app/reports \
#     --add-host host.docker.internal:host-gateway \
#     redteam-mcp-v2:latest tail -f /dev/null
# =============================================================================

FROM kalilinux/kali-rolling:latest

ENV DEBIAN_FRONTEND=noninteractive

# ── 1. Kali apt packages ─────────────────────────────────────────────────────
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        # Core system utilities
        curl wget git ca-certificates tini unzip tar build-essential \
        # JSON parsing
        jq \
        # DNS utilities: dig, nslookup
        bind9-dnsutils \
        # Port scanning
        nmap naabu \
        # Web vulnerability scanners & fingerprinting
        nikto wafw00f sslscan whatweb \
        # Template-based vuln scanner
        nuclei \
        # Subdomain & DNS enumeration
        subfinder amass dnsx \
        # HTTP probing
        httpx-toolkit \
        # Web fuzzers & content discovery
        gobuster ffuf wpscan \
        # Bulk DNS resolution
        massdns \
        # Brute-force & exploitation
        hydra sqlmap commix metasploit-framework \
        # Python environment
        python3 python3-pip python3-venv \
        # Wordlists (dirb, rockyou + SecLists ~519MB)
        wordlists seclists \
    && \
    (gunzip /usr/share/wordlists/rockyou.txt.gz 2>/dev/null || true) && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# ── 2. Pre-built release binaries (curl + unzip — proven approach) ───────────

# feroxbuster — recursive web fuzzer
RUN curl -sSL --retry 3 --retry-delay 5 \
    "https://github.com/epi052/feroxbuster/releases/download/v2.10.4/x86_64-linux-feroxbuster.zip" \
    -o /tmp/ferox.zip && \
    unzip -o /tmp/ferox.zip feroxbuster -d /usr/local/bin/ && \
    chmod +x /usr/local/bin/feroxbuster && \
    rm -f /tmp/ferox.zip

# kerbrute — Kerberos AD enumeration
RUN curl -sSL --retry 3 --retry-delay 5 \
    "https://github.com/ropnop/kerbrute/releases/download/v1.0.3/kerbrute_linux_amd64" \
    -o /usr/local/bin/kerbrute && \
    chmod +x /usr/local/bin/kerbrute

# rustscan — ultra-fast port scanner
RUN curl -sSL --retry 3 --retry-delay 5 \
    "https://github.com/RustScan/RustScan/releases/download/2.3.0/rustscan_2.3.0_amd64.deb" \
    -o /tmp/rustscan.deb && \
    dpkg -i /tmp/rustscan.deb 2>/dev/null || apt-get install -f -y && \
    rm -f /tmp/rustscan.deb

# gitleaks — git secret scanner
RUN curl -sSL --retry 3 --retry-delay 5 \
    "https://github.com/gitleaks/gitleaks/releases/download/v8.21.2/gitleaks_8.21.2_linux_x64.tar.gz" \
    | tar -xzf - -C /usr/local/bin/ gitleaks && \
    chmod +x /usr/local/bin/gitleaks

# trufflehog — credential scanner
RUN curl -sSL --retry 3 --retry-delay 5 \
    "https://github.com/trufflesecurity/trufflehog/releases/download/v3.82.6/trufflehog_3.82.6_linux_amd64.tar.gz" \
    | tar -xzf - -C /usr/local/bin/ trufflehog && \
    chmod +x /usr/local/bin/trufflehog

# ── 3. Python-based tools (git clone + wrapper scripts) ──────────────────────

# jwt_tool — JWT testing (not on PyPI)
RUN git clone --depth=1 https://github.com/ticarpi/jwt_tool /opt/jwt_tool && \
    pip3 install --no-cache-dir --break-system-packages -r /opt/jwt_tool/requirements.txt && \
    printf '#!/bin/sh\nexec python3 /opt/jwt_tool/jwt_tool.py "$@"\n' > /usr/local/bin/jwt_tool && \
    chmod +x /usr/local/bin/jwt_tool

# corsy — CORS misconfiguration scanner (not on PyPI)
RUN git clone --depth=1 https://github.com/s0md3v/Corsy /opt/corsy && \
    pip3 install --no-cache-dir --break-system-packages requests && \
    printf '#!/bin/sh\nexec python3 /opt/corsy/corsy.py "$@"\n' > /usr/local/bin/corsy && \
    chmod +x /usr/local/bin/corsy

# smuggler — HTTP request smuggling
RUN git clone --depth=1 https://github.com/defparam/smuggler.git /opt/smuggler && \
    printf '#!/bin/sh\nexec python3 /opt/smuggler/smuggler.py "$@"\n' > /usr/local/bin/smuggler && \
    chmod +x /usr/local/bin/smuggler

# ── 4. httpx symlink (Kali ships it as httpx-toolkit) ───────────────────────
RUN if [ -f /usr/bin/httpx-toolkit ] && [ ! -f /usr/local/bin/httpx ]; then \
        ln -s /usr/bin/httpx-toolkit /usr/local/bin/httpx; \
    fi

# ── 5. Python virtual environment + MCP server ──────────────────────────────
WORKDIR /app

RUN python3 -m venv /app/.venv
ENV PATH="/app/.venv/bin:$PATH"

COPY requirements.txt .
# --only-binary :all: pydantic-core → use pre-built wheel, never compile Rust
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir --only-binary :all: pydantic-core && \
    pip install --no-cache-dir -r requirements.txt arjun

COPY src/ ./src/

# Create persistent data directories (mounted as volumes at runtime)
RUN mkdir -p /app/data /app/reports /app/screenshots

# Pre-fetch Nuclei templates (fail silently — also works at runtime)
RUN nuclei -update-templates -silent || true

# ── 6. Runtime configuration ─────────────────────────────────────────────────
ENV PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app/src

# Ollama LLM (override with -e at runtime)
ENV OLLAMA_HOST=http://host.docker.internal:11434 \
    OLLAMA_MODEL=llama3.2 \
    MAX_AGENT_STEPS=50

# Security controls
ENV REDTEAM_ALLOWED_TARGETS="" \
    REDTEAM_AUDIT_LOG=/app/data/audit.log \
    REDTEAM_RATE_LIMIT=0

# tini as PID 1 — reaps zombie processes from tool timeouts
ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["/app/.venv/bin/python", "/app/src/server.py"]
