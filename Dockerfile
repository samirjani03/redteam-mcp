# ── Stage 1: Kali apt tools ──────────────────────────────────────────────────
FROM kalilinux/kali-rolling:latest AS tools

ENV DEBIAN_FRONTEND=noninteractive

# Single RUN layer — apt cache cleaned at the end to keep image lean.
# python3 / python3-pip / python3-venv are the correct Kali package names
# (Kali 2024.4+ ships Python 3.12 as 'python3'; no versioned suffix in apt).
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        curl wget git ca-certificates \
        nmap \
        nikto \
        sslscan \
        dnsrecon \
        gobuster \
        ffuf \
        hydra \
        wpscan \
        wafw00f \
        sqlmap \
        commix \
        theharvester \
        python3 python3-pip python3-venv \
        wordlists \
    && \
    (gunzip /usr/share/wordlists/rockyou.txt.gz 2>/dev/null || true) && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Metasploit in its own layer — it's ~1 GB and changes rarely.
# Separating it means the layer above stays cached on rebuilds.
RUN apt-get update && \
    apt-get install -y --no-install-recommends metasploit-framework && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# ── Stage 2: Go-based tools ───────────────────────────────────────────────────
FROM tools AS gotools

RUN apt-get update && \
    apt-get install -y --no-install-recommends golang-go && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Disable interactive git prompts inside Docker
ENV GONOSUMCHECK=* \
    GOFLAGS=-mod=mod \
    GIT_TERMINAL_PROMPT=0 \
    GOPATH=/root/go

# Install each tool in its own layer for better cache granularity
RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
RUN go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
RUN go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
# amass moved to owasp-amass org (projectdiscovery/amass is archived)
RUN go install -v github.com/owasp-amass/amass/v4/cmd/amass@latest

# ── Stage 3: Final image ──────────────────────────────────────────────────────
FROM tools AS final

# Copy only the compiled Go binaries — no Go toolchain in final image
COPY --from=gotools /root/go/bin/subfinder /usr/local/bin/subfinder
COPY --from=gotools /root/go/bin/httpx     /usr/local/bin/httpx
COPY --from=gotools /root/go/bin/nuclei    /usr/local/bin/nuclei
COPY --from=gotools /root/go/bin/amass     /usr/local/bin/amass

# WhatWeb — available directly in Kali apt (not a RubyGem)
RUN apt-get update && \
    apt-get install -y --no-install-recommends whatweb && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Arjun — install into the venv (created below) to avoid apt package conflicts
# We create the venv first, then install arjun into it along with mcp

# ── MCP server ────────────────────────────────────────────────────────────────
WORKDIR /app

# Venv isolates pip completely from apt-managed system packages
RUN python3 -m venv /app/.venv
ENV PATH="/app/.venv/bin:$PATH"

COPY requirements.txt .
# Install mcp + arjun both into the venv — no system package conflicts
RUN pip install --no-cache-dir -r requirements.txt arjun

COPY src/ ./src/

# Pre-fetch Nuclei templates so first scan isn't slow
RUN nuclei -update-templates -silent || true

ENV PYTHONUNBUFFERED=1

CMD ["/app/.venv/bin/python", "src/server.py"]
