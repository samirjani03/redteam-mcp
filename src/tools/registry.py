"""
Tool registry — single source of truth for all 20 MCP tool definitions.

Each entry describes the tool name, what it does, and its parameter schema.
Used by:
  - src/agent/planner.py  — to build the LLM system prompt
  - src/agent/planner.py  — to validate tool names before execution
  - src/server.py         — documentation reference
"""

from __future__ import annotations

TOOL_REGISTRY: dict[str, dict] = {
    "nmap_scan": {
        "description": "Port and service scanner. Use to discover open ports and running services.",
        "category": "recon",
        "args": {
            "target": "str — IP, hostname, or CIDR (e.g. 192.168.1.1)",
            "ports":  "str — port range (default '1-1000')",
            "flags":  "str — extra nmap flags (default '-sV -sC')",
        },
    },
    "gobuster_dir": {
        "description": "Directory brute-force. Use after finding a web server to discover hidden paths.",
        "category": "web",
        "args": {
            "url":        "str — target URL",
            "wordlist":   "str — wordlist path (optional)",
            "extensions": "str — file extensions, comma-separated (optional)",
            "threads":    "int — concurrent threads (optional)",
        },
    },
    "sqlmap_scan": {
        "description": "SQL injection scanner. Use on URLs with query parameters.",
        "category": "exploit",
        "args": {
            "url":   "str — target URL",
            "data":  "str — POST body (optional)",
            "level": "int — test level 1-5",
            "risk":  "int — risk level 1-3",
        },
    },
    "nikto_scan": {
        "description": "Web server vulnerability scanner. Use on discovered web servers.",
        "category": "web",
        "args": {
            "host": "str — hostname or IP",
            "port": "int — port (default 80)",
            "ssl":  "bool — use HTTPS (default false)",
        },
    },
    "whatweb_scan": {
        "description": "Fingerprint web technologies (CMS, frameworks, server versions).",
        "category": "recon",
        "args": {
            "url":        "str — target URL",
            "aggression": "int — 1 (passive) to 4 (aggressive, default 1)",
        },
    },
    "subfinder_enum": {
        "description": "Enumerate subdomains of a domain using passive sources.",
        "category": "recon",
        "args": {
            "domain": "str — target domain (e.g. example.com)",
            "silent": "bool — suppress banner (default true)",
        },
    },
    "httpx_probe": {
        "description": "Probe a list of hosts for live HTTP services. Use after subfinder.",
        "category": "recon",
        "args": {
            "targets": "str — newline-separated hosts or URLs",
            "threads": "int — concurrent threads (default 50)",
        },
    },
    "nuclei_scan": {
        "description": "Template-based vuln scanner. Use after discovering web services.",
        "category": "vuln",
        "args": {
            "target":    "str — target URL or IP",
            "templates": "str — template tags/categories (default 'cves,vulnerabilities')",
            "severity":  "str — severity filter (default 'medium,high,critical')",
        },
    },
    "ffuf_fuzz": {
        "description": "Fast web fuzzer for directories, parameters, and vhosts.",
        "category": "web",
        "args": {
            "url":          "str — URL with FUZZ keyword (e.g. http://example.com/FUZZ)",
            "wordlist":     "str — wordlist path (optional)",
            "filter_codes": "str — HTTP codes to hide (default '404')",
        },
    },
    "wpscan_scan": {
        "description": "WordPress vulnerability scanner. Use only if WordPress is detected.",
        "category": "web",
        "args": {
            "url":       "str — target WordPress URL",
            "enumerate": "str — options: vp=vulnerable plugins, vt=themes, u=users",
        },
    },
    "amass_enum": {
        "description": "Deep DNS enumeration and attack surface mapping.",
        "category": "recon",
        "args": {
            "domain":  "str — target domain",
            "passive": "bool — passive only (default true)",
        },
    },
    "hydra_brute": {
        "description": "Brute-force login credentials. Use on discovered login services.",
        "category": "exploit",
        "args": {
            "target":        "str — target IP or hostname",
            "service":       "str — service (e.g. ssh, ftp, http-post-form)",
            "username":      "str — single username or 'L:/path/to/list'",
            "password_list": "str — wordlist path (optional)",
        },
    },
    "curl_request": {
        "description": "Send a raw HTTP request. Use for manual PoC verification.",
        "category": "web",
        "args": {
            "url":     "str — target URL",
            "method":  "str — HTTP method (default GET)",
            "headers": "str — newline-separated headers (optional)",
            "data":    "str — request body (optional)",
        },
    },
    "dnsrecon_enum": {
        "description": "DNS reconnaissance. Use to find DNS records, zone transfers.",
        "category": "recon",
        "args": {
            "domain":    "str — target domain",
            "scan_type": "str — std|axfr|brt|goo (default 'std')",
        },
    },
    "theharvester_osint": {
        "description": "OSINT email and subdomain harvesting from public sources.",
        "category": "osint",
        "args": {
            "domain":  "str — target domain",
            "sources": "str — data sources (default 'google,bing,crtsh')",
        },
    },
    "wafw00f_detect": {
        "description": "Detect Web Application Firewalls before running injection attacks.",
        "category": "recon",
        "args": {
            "url":      "str — target URL",
            "find_all": "bool — detect all WAFs (default false)",
        },
    },
    "sslscan_audit": {
        "description": "Audit SSL/TLS configuration for weak ciphers and expired certs.",
        "category": "recon",
        "args": {
            "host": "str — hostname or IP",
            "port": "int — port (default 443)",
        },
    },
    "commix_scan": {
        "description": "Detect and exploit OS command injection vulnerabilities.",
        "category": "exploit",
        "args": {
            "url":   "str — target URL",
            "data":  "str — POST data (optional)",
            "level": "int — test level 1-3",
        },
    },
    "arjun_params": {
        "description": "Discover hidden HTTP parameters on web endpoints.",
        "category": "web",
        "args": {
            "url":    "str — target URL",
            "method": "str — GET or POST (default GET)",
        },
    },
    "msf_auxiliary": {
        "description": "Run a Metasploit auxiliary module non-interactively.",
        "category": "exploit",
        "args": {
            "module":  "str — module path (e.g. auxiliary/scanner/http/http_version)",
            "options": "str — KEY=VALUE pairs space-separated",
        },
    },
    # ── New tools (Phase 3) ─────────────────────────────────────────────
    "rustscan": {
        "description": "Ultra-fast port discovery (finds open ports in seconds, feeds to nmap). Use first for large IP ranges.",
        "category": "recon",
        "args": {
            "target":  "str — IP or CIDR range",
            "ports":   "str — port range (default '1-65535')",
            "timeout": "int — per-port timeout ms (default 1500)",
        },
    },
    "feroxbuster": {
        "description": "Recursive web content discovery. Better than gobuster for deep directory trees and modern apps.",
        "category": "web",
        "args": {
            "url":      "str — target URL",
            "wordlist": "str — wordlist path (optional)",
            "depth":    "int — recursion depth (default 3)",
            "threads":  "int — concurrent threads (default 50)",
        },
    },
    "kerbrute": {
        "description": "Kerberos user enumeration and password spraying for Active Directory environments.",
        "category": "exploit",
        "args": {
            "action":  "str — userenum | passwordspray | bruteuser",
            "domain":  "str — AD domain (e.g. corp.local)",
            "dc":      "str — domain controller IP",
            "wordlist": "str — usernames or passwords wordlist",
        },
    },
    # ── Bug-Bounty Recon Stack (Phase 4) ────────────────────────────────────
    "naabu_scan": {
        "description": "Fast parallel port scanner. Use BEFORE nmap on large IP ranges to quickly find open ports.",
        "category": "recon",
        "args": {
            "target": "str — IP, hostname, or CIDR range",
            "ports":  "str — port spec (default '-top-ports 1000'). Use '-p 1-65535' for full.",
            "rate":   "int — packets per second (default 1000)",
        },
    },
    "dnsx_resolve": {
        "description": "Bulk DNS resolver for subdomain lists. Filters wildcards. Pipe subfinder output here.",
        "category": "recon",
        "args": {
            "domains":      "str — newline-separated domains to resolve",
            "record_types": "str — comma-separated record types (default 'A,CNAME,MX,TXT')",
            "threads":      "int — concurrent threads (default 100)",
        },
    },
    "katana_crawl": {
        "description": "JS-aware web crawler. Finds endpoints, params, JS files. Run after httpx_probe.",
        "category": "web",
        "args": {
            "url":      "str — target URL",
            "depth":    "int — crawl depth (default 3)",
            "js_crawl": "bool — parse JS files for embedded endpoints (default true)",
            "headless": "bool — use headless browser for SPA sites (default false)",
        },
    },
    "gau_urls": {
        "description": "Harvest historical URLs from Wayback/OTX/CommonCrawl. #1 source for old params and leaked files.",
        "category": "recon",
        "args": {
            "domain":    "str — target domain (e.g. example.com)",
            "threads":   "int — concurrent threads (default 5)",
            "providers": "str — data sources (default 'wayback,otx,commoncrawl')",
        },
    },
    "waybackurls_fetch": {
        "description": "Pull all archived URLs from Wayback Machine. Complements gau_urls for maximum coverage.",
        "category": "recon",
        "args": {
            "domain": "str — target domain (e.g. example.com)",
        },
    },
    "dalfox_xss": {
        "description": "Verified XSS scanner. Use after nuclei flags XSS candidates to eliminate false positives.",
        "category": "exploit",
        "args": {
            "url":        "str — target URL with parameters",
            "data":       "str — POST body (optional)",
            "blind_host": "str — blind XSS callback host (optional, use interactsh URL)",
        },
    },
    "subzy_takeover": {
        "description": "Subdomain takeover detection. Run after subfinder_enum + dnsx_resolve on CNAME records.",
        "category": "recon",
        "args": {
            "targets":     "str — newline-separated subdomains to check",
            "concurrency": "int — concurrent checks (default 10)",
        },
    },
    "gowitness_screenshot": {
        "description": "Visual screenshot of web targets. Use for triage and report evidence. Saves to /app/screenshots/.",
        "category": "recon",
        "args": {
            "targets": "str — newline-separated URLs to screenshot",
            "threads": "int — concurrent browser threads (default 4)",
        },
    },
    "gitleaks_scan": {
        "description": "Scan for leaked API keys, secrets, and credentials in git repos or local directories.",
        "category": "osint",
        "args": {
            "target":    "str — path or git repo URL to scan",
            "scan_type": "str — 'dir' for local directory, 'git' for repo (default 'dir')",
        },
    },
    "asnmap_lookup": {
        "description": "Map ASN, org name, IP, or domain to full CIDR ranges. Use to expand target scope.",
        "category": "recon",
        "args": {
            "target": "str — ASN (e.g. AS13335), domain, IP, or org name",
        },
    },
    "alterx_permute": {
        "description": "Generate subdomain permutations from known subdomains. Pair with dnsx_resolve to validate.",
        "category": "recon",
        "args": {
            "subdomains": "str — newline-separated list of known subdomains",
            "patterns":   "str — custom permutation patterns (optional)",
        },
    },
    "interactsh_oob": {
        "description": "Out-of-band callback testing for blind SSRF/XXE/SQLi/RCE. Start listener, inject payload, check callbacks.",
        "category": "exploit",
        "args": {
            "action":      "str — 'start' to launch listener or 'check' to read captured callbacks",
            "output_file": "str — file to write OOB interactions (default /tmp/oob.txt)",
        },
    },
    "uncover_search": {
        "description": "Search for exposed assets on Shodan, Censys, FOFA. Requires API keys as env vars.",
        "category": "recon",
        "args": {
            "query":  "str — search query (e.g. 'apache country:IN', 'ssl:example.com')",
            "engine": "str — shodan|censys|fofa|quake|hunter|zoomeye (default 'shodan')",
            "limit":  "int — max results (default 100)",
        },
    },
    # ── Gap Analysis Tools ───────────────────────────────────────────────
    "jwt_attack": {
        "description": "Analyze, tamper, crack HMAC, and attack JWT tokens using jwt_tool.",
        "category": "exploit",
        "args": {
            "token":  "str — JWT token string (eyJ...)",
            "mode":   "str — decode | crack | alg_confusion | none_alg | tamper (default decode)",
            "secret": "str — wordlist path for crack mode, or secret key",
        },
    },
    "cors_check": {
        "description": "Test for CORS misconfiguration vulnerabilities using corsy.",
        "category": "web",
        "args": {
            "url":     "str — target URL",
            "threads": "int — concurrent threads (default 10)",
            "headers": "str — extra request headers",
        },
    },
    "smuggling_test": {
        "description": "Test for HTTP Request Smuggling vulnerabilities (CL.TE, TE.CL, TE.TE) using smuggler.",
        "category": "web",
        "args": {
            "url":      "str — target URL (http/https)",
            "timeout":  "int — per-request timeout in seconds (default 10)",
            "log_file": "str — output log path (default /tmp/smuggler_out.txt)",
        },
    },
    "trufflehog_scan": {
        "description": "Deep secret and credential scanner across filesystems and git history.",
        "category": "osint",
        "args": {
            "target":        "str — path or git repo URL to scan",
            "scan_type":     "str — filesystem | git | github | gitlab (default filesystem)",
            "only_verified": "bool — only report verified live secrets (default false)",
        },
    },
    "header_audit": {
        "description": "Audit HTTP security headers (HSTS, CSP, X-Frame, MIME, Referrer, CORS).",
        "category": "web",
        "args": {
            "url": "str — target URL",
        },
    },
    "whois_lookup": {
        "description": "WHOIS lookup for domain or IP registration info and nameservers.",
        "category": "recon",
        "args": {
            "target": "str — domain or IP address",
        },
    },
    "crt_sh_enum": {
        "description": "Certificate Transparency log search (crt.sh) for passive subdomain discovery.",
        "category": "recon",
        "args": {
            "domain": "str — target domain (e.g. example.com)",
        },
    },
    "lfi_scan": {
        "description": "Fuzz for Local File Inclusion (LFI) and Path Traversal vulnerabilities using ffuf and SecLists.",
        "category": "web",
        "args": {
            "url":     "str — URL with FUZZ keyword",
            "param":   "str — fuzz keyword (default FUZZ)",
            "threads": "int — concurrent threads (default 40)",
        },
    },
    "smb_enum": {
        "description": "Windows/Samba SMB enumeration (shares, users, password policies) using enum4linux.",
        "category": "recon",
        "args": {
            "target":   "str — target IP address",
            "username": "str — optional SMB username",
            "password": "str — optional SMB password",
        },
    },
    "ssh_audit_tool": {
        "description": "Audit SSH server algorithms and configuration for weak ciphers and vulnerabilities.",
        "category": "recon",
        "args": {
            "host": "str — target hostname or IP",
            "port": "int — SSH port (default 22)",
        },
    },
    "open_redirect_check": {
        "description": "Fuzz URL/redirect parameters for open redirect vulnerabilities using ffuf.",
        "category": "web",
        "args": {
            "url":     "str — URL with FUZZ keyword",
            "param":   "str — fuzz keyword (default FUZZ)",
            "threads": "int — concurrent threads (default 30)",
        },
    },
    "bypass_403": {
        "description": "Attempt to bypass 403 Forbidden responses using header manipulation & path tricks.",
        "category": "web",
        "args": {
            "url": "str — URL returning 403",
        },
    },
    "js_extract": {
        "description": "Extract endpoints, routes, and potential secrets/API keys from JavaScript files.",
        "category": "web",
        "args": {
            "url_or_file": "str — URL to JS file or local path",
        },
    },
}

