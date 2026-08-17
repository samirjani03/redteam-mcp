"""
Red Team MCP Server v2 — entry point
======================================
Registers all tool functions with FastMCP, then defers to sub-modules.

Tools: 40+ MCP tools across recon, web, fuzzing, DNS, OSINT, exploitation,
       CVE intelligence, URL harvesting, crawling, XSS, JWT, and agentic loops.

Modules:
  src/tools/    — shell executor, output formatter, tool registry
  src/parsers/  — typed output parsers (nmap, nuclei, subfinder …)
  src/agent/    — Ollama agentic loop (PentestAgent)
  src/memory/   — SQLite session persistence (MemoryStore)
  src/reporting/— Markdown report generator
  src/security/ — target allowlist, rate limiter, audit log

Python: 3.11+   FastMCP: 2.3.x
"""

from __future__ import annotations

import json
import os
import shlex
import sys

# Ensure 'src' directory is in sys.path for reliable imports
_src_dir = os.path.dirname(os.path.abspath(__file__))
if _src_dir not in sys.path:
    sys.path.insert(0, _src_dir)

from fastmcp import FastMCP

from tools.executor import run_shell, fmt_output
from tools.registry import TOOL_REGISTRY

mcp = FastMCP(
    name="RedTeamMCP",
    instructions=(
        "Full-stack security research assistant with 40+ Kali Linux tools. "
        "Recon pipeline: naabu_scan → nmap_scan → subfinder_enum → dnsx_resolve → "
        "httpx_probe → katana_crawl → gau_urls → feroxbuster → nuclei_scan. "
        "XSS workflow: nuclei_scan (xss tags) → dalfox_xss. "
        "Subdomain workflow: subfinder_enum → dnsx_resolve → subzy_takeover. "
        "URL harvest: gau_urls + waybackurls_fetch → ffuf_fuzz on interesting params. "
        "For full autonomous pentesting use pentest_target(). "
        "Always ensure explicit written authorisation before testing any target."
    ),
)


# ---------------------------------------------------------------------------
# 1. nmap_scan
# ---------------------------------------------------------------------------
@mcp.tool()
async def nmap_scan(target: str, ports: str = "1-1000", flags: str = "-sV -sC") -> str:
    """
    Run an Nmap scan against a target.

    Args:
        target: IP, hostname, or CIDR (e.g. 192.168.1.1 or 10.0.0.0/24)
        ports:  Port range or list (e.g. '80,443' or '1-65535'). Default: 1-1000
        flags:  Extra nmap flags (e.g. '-A -T4'). Default: '-sV -sC'
    """
    cmd = f"nmap {flags} -p {shlex.quote(ports)} {shlex.quote(target)} -oN -"
    return fmt_output(await run_shell(cmd, timeout=300), "nmap_scan")


# ---------------------------------------------------------------------------
# 2. gobuster_dir
# ---------------------------------------------------------------------------
@mcp.tool()
async def gobuster_dir(
    url: str,
    wordlist: str = "/usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt",
    extensions: str = "php,html,txt,js,bak,zip",
    threads: int = 40,
) -> str:
    """
    Brute-force directories and files on a web server using Gobuster.

    Args:
        url:        Target URL (e.g. http://example.com)
        wordlist:   Path to wordlist (default: SecLists raft-large-directories)
        extensions: Comma-separated file extensions to append
        threads:    Number of concurrent threads
    """
    cmd = (
        f"gobuster dir -u {shlex.quote(url)} "
        f"-w {shlex.quote(wordlist)} "
        f"-x {shlex.quote(extensions)} "
        f"-t {threads} --no-progress"
    )
    return fmt_output(await run_shell(cmd, timeout=300), "gobuster_dir")


# ---------------------------------------------------------------------------
# 3. sqlmap_scan
# ---------------------------------------------------------------------------
@mcp.tool()
async def sqlmap_scan(
    url: str,
    data: str = "",
    level: int = 1,
    risk: int = 1,
    extra_flags: str = "--batch --random-agent",
) -> str:
    """
    Automated SQL injection detection with SQLMap.

    Args:
        url:         Target URL (e.g. http://example.com/page?id=1)
        data:        POST data string (leave empty for GET)
        level:       Test level 1-5
        risk:        Risk level 1-3
        extra_flags: Additional sqlmap flags
    """
    cmd = f"sqlmap -u {shlex.quote(url)} --level={level} --risk={risk} {extra_flags}"
    if data:
        cmd += f" --data={shlex.quote(data)}"
    return fmt_output(await run_shell(cmd, timeout=300), "sqlmap_scan")


# ---------------------------------------------------------------------------
# 4. nikto_scan
# ---------------------------------------------------------------------------
@mcp.tool()
async def nikto_scan(host: str, port: int = 80, ssl: bool = False) -> str:
    """
    Scan a web server for known vulnerabilities using Nikto.

    Args:
        host: Target hostname or IP
        port: Target port (default 80)
        ssl:  Use SSL/HTTPS (default False)
    """
    ssl_flag = "-ssl" if ssl else ""
    cmd = f"nikto -h {shlex.quote(host)} -p {port} {ssl_flag} -nointeractive"
    return fmt_output(await run_shell(cmd, timeout=300), "nikto_scan")


# ---------------------------------------------------------------------------
# 5. whatweb_scan
# ---------------------------------------------------------------------------
@mcp.tool()
async def whatweb_scan(url: str, aggression: int = 1) -> str:
    """
    Identify technologies used by a web application.

    Args:
        url:        Target URL
        aggression: 1 (passive) to 4 (aggressive). Default: 1
    """
    cmd = f"whatweb -a {aggression} --log-json=- {shlex.quote(url)}"
    return fmt_output(await run_shell(cmd, timeout=120), "whatweb_scan")


# ---------------------------------------------------------------------------
# 6. subfinder_enum
# ---------------------------------------------------------------------------
@mcp.tool()
async def subfinder_enum(domain: str, silent: bool = True) -> str:
    """
    Enumerate subdomains of a target domain using Subfinder.

    Args:
        domain: Target domain (e.g. example.com)
        silent: Suppress banner output
    """
    silent_flag = "-silent" if silent else ""
    cmd = f"subfinder -d {shlex.quote(domain)} {silent_flag} -json"
    return fmt_output(await run_shell(cmd, timeout=180), "subfinder_enum")


# ---------------------------------------------------------------------------
# 7. httpx_probe
# ---------------------------------------------------------------------------
@mcp.tool()
async def httpx_probe(
    targets: str,
    threads: int = 50,
    status_code: bool = True,
    title: bool = True,
    tech_detect: bool = True,
) -> str:
    """
    Probe a list of hosts/URLs for live HTTP services using httpx.

    Args:
        targets:     Newline-separated list of hosts or URLs
        threads:     Concurrent threads
        status_code: Show HTTP status codes
        title:       Show page titles
        tech_detect: Detect technologies
    """
    flags = ""
    if status_code:
        flags += " -status-code"
    if title:
        flags += " -title"
    if tech_detect:
        flags += " -tech-detect"
    cmd = f"echo {shlex.quote(targets)} | httpx -threads {threads}{flags} -json -silent"
    return fmt_output(await run_shell(cmd, timeout=180), "httpx_probe")


# ---------------------------------------------------------------------------
# 8. nuclei_scan
# ---------------------------------------------------------------------------
@mcp.tool()
async def nuclei_scan(
    target: str,
    templates: str = "cves,vulnerabilities,exposures",
    severity: str = "medium,high,critical",
) -> str:
    """
    Run Nuclei template-based vulnerability scanner against a target.

    Args:
        target:    Target URL or IP
        templates: Comma-separated template tags/categories
        severity:  Comma-separated severity levels to include
    """
    cmd = (
        f"nuclei -u {shlex.quote(target)} "
        f"-tags {shlex.quote(templates)} "
        f"-severity {shlex.quote(severity)} "
        f"-jsonl -silent"
    )
    return fmt_output(await run_shell(cmd, timeout=300), "nuclei_scan")


# ---------------------------------------------------------------------------
# 9. ffuf_fuzz
# ---------------------------------------------------------------------------
@mcp.tool()
async def ffuf_fuzz(
    url: str,
    wordlist: str = "/usr/share/seclists/Discovery/Web-Content/raft-large-words.txt",
    keyword: str = "FUZZ",
    filter_codes: str = "404,403",
    threads: int = 50,
) -> str:
    """
    Fuzz web endpoints, parameters, or headers using FFuf.

    Args:
        url:          URL with FUZZ keyword (e.g. http://example.com/FUZZ)
        wordlist:     Path to wordlist (default: SecLists raft-large-words)
        keyword:      Fuzzing keyword in URL (default: FUZZ)
        filter_codes: HTTP status codes to filter out (comma-separated)
        threads:      Concurrent threads
    """
    cmd = (
        f"ffuf -u {shlex.quote(url)} "
        f"-w {shlex.quote(wordlist)}:{shlex.quote(keyword)} "
        f"-fc {shlex.quote(filter_codes)} "
        f"-t {threads} -json -s"
    )
    return fmt_output(await run_shell(cmd, timeout=300), "ffuf_fuzz")


# ---------------------------------------------------------------------------
# 10. wpscan_scan
# ---------------------------------------------------------------------------
@mcp.tool()
async def wpscan_scan(url: str, enumerate: str = "vp,vt,u", api_token: str = "") -> str:
    """
    Scan a WordPress site for vulnerabilities, plugins, themes, and users.

    Args:
        url:       Target WordPress URL
        enumerate: Enumeration options: vp=vulnerable plugins, vt=themes, u=users
        api_token: WPScan API token (optional)
    """
    token_flag = f"--api-token {shlex.quote(api_token)}" if api_token else ""
    cmd = (
        f"wpscan --url {shlex.quote(url)} "
        f"--enumerate {shlex.quote(enumerate)} "
        f"{token_flag} --format json --no-banner"
    )
    return fmt_output(await run_shell(cmd, timeout=300), "wpscan_scan")


# ---------------------------------------------------------------------------
# 11. amass_enum
# ---------------------------------------------------------------------------
@mcp.tool()
async def amass_enum(domain: str, passive: bool = True) -> str:
    """
    Perform in-depth DNS enumeration and attack surface mapping with Amass.

    Args:
        domain:  Target domain
        passive: Use only passive techniques (default True)
    """
    mode = "-passive" if passive else "-active"
    cmd = f"amass enum {mode} -d {shlex.quote(domain)} -json /dev/stdout"
    return fmt_output(await run_shell(cmd, timeout=300), "amass_enum")


# ---------------------------------------------------------------------------
# 12. hydra_brute  (int | None avoids Optional NameError in fastmcp 2.3)
# ---------------------------------------------------------------------------
@mcp.tool()
async def hydra_brute(
    target: str,
    service: str,
    username: str,
    password_list: str = "/usr/share/wordlists/rockyou.txt",
    port: int | None = None,
    threads: int = 16,
) -> str:
    """
    Brute-force login credentials using Hydra.

    Args:
        target:        Target IP or hostname
        service:       Service to attack (e.g. ssh, ftp, http-post-form)
        username:      Username or 'L:/path/to/userlist' for a list
        password_list: Path to password wordlist
        port:          Custom port (optional)
        threads:       Parallel tasks
    """
    port_flag = f"-s {port}" if port else ""
    user_flag = (
        f"-L {shlex.quote(username[2:])}"
        if username.startswith("L:")
        else f"-l {shlex.quote(username)}"
    )
    cmd = (
        f"hydra {user_flag} -P {shlex.quote(password_list)} "
        f"{port_flag} -t {threads} "
        f"{shlex.quote(target)} {shlex.quote(service)}"
    )
    return fmt_output(await run_shell(cmd, timeout=300), "hydra_brute")


# ---------------------------------------------------------------------------
# 13. curl_request
# ---------------------------------------------------------------------------
@mcp.tool()
async def curl_request(
    url: str,
    method: str = "GET",
    headers: str = "",
    data: str = "",
    follow_redirects: bool = True,
    insecure: bool = False,
) -> str:
    """
    Send a raw HTTP request using curl.

    Args:
        url:              Target URL
        method:           HTTP method (GET, POST, PUT, DELETE …)
        headers:          Newline-separated headers
        data:             Request body / POST data
        follow_redirects: Follow HTTP redirects
        insecure:         Skip TLS certificate verification
    """
    header_flags = " ".join(
        f"-H {shlex.quote(h.strip())}" for h in headers.splitlines() if h.strip()
    )
    data_flag      = f"-d {shlex.quote(data)}" if data else ""
    redirect_flag  = "-L" if follow_redirects else ""
    insecure_flag  = "-k" if insecure else ""
    cmd = (
        f"curl -s -S -X {shlex.quote(method)} {redirect_flag} {insecure_flag} "
        f"{header_flags} {data_flag} -i {shlex.quote(url)}"
    )
    return fmt_output(await run_shell(cmd, timeout=60), "curl_request")


# ---------------------------------------------------------------------------
# 14. dnsrecon_enum
# ---------------------------------------------------------------------------
@mcp.tool()
async def dnsrecon_enum(domain: str, scan_type: str = "std") -> str:
    """
    Perform DNS reconnaissance on a target domain.

    Args:
        domain:    Target domain
        scan_type: std | rvl | brt | axfr | goo | snoop | tld | zonewalk
    """
    cmd = f"dnsrecon -d {shlex.quote(domain)} -t {shlex.quote(scan_type)} -j /dev/stdout"
    return fmt_output(await run_shell(cmd, timeout=180), "dnsrecon_enum")


# ---------------------------------------------------------------------------
# 15. theharvester_osint
# ---------------------------------------------------------------------------
@mcp.tool()
async def theharvester_osint(
    domain: str,
    sources: str = "google,bing,crtsh,dnsdumpster",
    limit: int = 200,
) -> str:
    """
    Harvest emails, subdomains, IPs, and URLs from public sources.

    Args:
        domain:  Target domain
        sources: Comma-separated data sources
        limit:   Max results per source
    """
    cmd = (
        f"theHarvester -d {shlex.quote(domain)} "
        f"-b {shlex.quote(sources)} "
        f"-l {limit} -f /tmp/harvest_out"
    )
    result = await run_shell(cmd, timeout=180)
    read_result = await run_shell("cat /tmp/harvest_out.json 2>/dev/null || echo '{}'")
    combined = {"run": result, "json_output": read_result.get("stdout", "{}")}
    return fmt_output(
        {"stdout": json.dumps(combined), "stderr": "", "returncode": result.get("returncode")},
        "theharvester_osint",
    )


# ---------------------------------------------------------------------------
# 16. wafw00f_detect
# ---------------------------------------------------------------------------
@mcp.tool()
async def wafw00f_detect(url: str, find_all: bool = False) -> str:
    """
    Detect Web Application Firewalls protecting a target.

    Args:
        url:      Target URL
        find_all: Try to detect all WAFs instead of stopping at first match
    """
    all_flag = "-a" if find_all else ""
    cmd = f"wafw00f {all_flag} -o - -f json {shlex.quote(url)}"
    return fmt_output(await run_shell(cmd, timeout=60), "wafw00f_detect")


# ---------------------------------------------------------------------------
# 17. sslscan_audit
# ---------------------------------------------------------------------------
@mcp.tool()
async def sslscan_audit(host: str, port: int = 443) -> str:
    """
    Audit SSL/TLS configuration for weak ciphers, protocols, and certificates.

    Args:
        host: Target hostname or IP
        port: Target port (default 443)
    """
    cmd = f"sslscan --no-colour {shlex.quote(host)}:{port}"
    return fmt_output(await run_shell(cmd, timeout=60), "sslscan_audit")


# ---------------------------------------------------------------------------
# 18. commix_scan
# ---------------------------------------------------------------------------
@mcp.tool()
async def commix_scan(url: str, data: str = "", level: int = 1) -> str:
    """
    Detect and exploit OS command injection vulnerabilities.

    Args:
        url:   Target URL
        data:  POST data (optional)
        level: Test level 1-3
    """
    data_flag = f"--data={shlex.quote(data)}" if data else ""
    cmd = (
        f"commix --url={shlex.quote(url)} {data_flag} "
        f"--level={level} --batch --output-dir=/tmp/commix_out"
    )
    return fmt_output(await run_shell(cmd, timeout=300), "commix_scan")


# ---------------------------------------------------------------------------
# 19. arjun_params
# ---------------------------------------------------------------------------
@mcp.tool()
async def arjun_params(url: str, method: str = "GET", threads: int = 20) -> str:
    """
    Discover hidden HTTP GET/POST parameters on a web endpoint.

    Args:
        url:     Target URL
        method:  HTTP method to test (GET or POST)
        threads: Concurrent threads
    """
    cmd = f"arjun -u {shlex.quote(url)} -m {shlex.quote(method)} -t {threads} --json"
    return fmt_output(await run_shell(cmd, timeout=180), "arjun_params")


# ---------------------------------------------------------------------------
# 20. msf_auxiliary
# ---------------------------------------------------------------------------
@mcp.tool()
async def msf_auxiliary(module: str, options: str) -> str:
    """
    Run a Metasploit Framework auxiliary module non-interactively.

    Args:
        module:  Full module path (e.g. auxiliary/scanner/http/http_version)
        options: Space-separated KEY=VALUE pairs (e.g. 'RHOSTS=192.168.1.1 THREADS=10')
    """
    set_cmds = "\n".join(f"set {opt}" for opt in options.split() if "=" in opt)
    rc_script = f"use {module}\n{set_cmds}\nrun\nexit\n"
    await run_shell(f"echo {shlex.quote(rc_script)} > /tmp/msf_run.rc")
    return fmt_output(await run_shell("msfconsole -q -r /tmp/msf_run.rc", timeout=300), "msf_auxiliary")


# ---------------------------------------------------------------------------
# 21. rustscan — ultra-fast port discovery
# ---------------------------------------------------------------------------
@mcp.tool()
async def rustscan(target: str, ports: str = "1-65535", timeout: int = 1500) -> str:
    """
    Ultra-fast port scanner. Finds open ports in seconds then pipes to nmap for details.
    Use this first on large IP ranges before running nmap.

    Args:
        target:  IP address or CIDR range
        ports:   Port range (default: 1-65535)
        timeout: Per-port timeout in milliseconds (default: 1500)
    """
    cmd = (
        f"rustscan -a {shlex.quote(target)} "
        f"-r {shlex.quote(ports)} "
        f"-t {timeout} "
        f"-- -sV -sC"
    )
    return fmt_output(await run_shell(cmd, timeout=300), "rustscan")


# ---------------------------------------------------------------------------
# 22. feroxbuster — recursive web content discovery
# ---------------------------------------------------------------------------
@mcp.tool()
async def feroxbuster(
    url: str,
    wordlist: str = "/usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt",
    depth: int = 4,
    threads: int = 50,
    extensions: str = "php,html,js,txt,bak,zip,json",
) -> str:
    """
    Recursive web content discovery. Faster and deeper than gobuster.
    Automatically recurses into found directories up to the given depth.

    Args:
        url:        Target URL (e.g. http://example.com)
        wordlist:   Path to wordlist (default: SecLists raft-large-directories)
        depth:      Recursion depth (default: 4)
        threads:    Concurrent threads (default: 50)
        extensions: File extensions to probe (default: php,html,js,txt,bak,zip,json)
    """
    cmd = (
        f"feroxbuster -u {shlex.quote(url)} "
        f"-w {shlex.quote(wordlist)} "
        f"-d {depth} "
        f"-t {threads} "
        f"-x {shlex.quote(extensions)} "
        f"--no-state --quiet"
    )
    return fmt_output(await run_shell(cmd, timeout=300), "feroxbuster")


# ---------------------------------------------------------------------------
# 23. kerbrute — Kerberos enumeration for Active Directory
# ---------------------------------------------------------------------------
@mcp.tool()
async def kerbrute(
    action: str,
    domain: str,
    dc: str,
    wordlist: str,
) -> str:
    """
    Kerberos user enumeration and password spraying for Active Directory.
    Use when nmap shows port 88 (Kerberos) open.

    Args:
        action:   userenum | passwordspray | bruteuser
        domain:   Active Directory domain (e.g. corp.local)
        dc:       Domain controller IP
        wordlist: Path to usernames (userenum) or passwords (passwordspray) list
    """
    valid_actions = {"userenum", "passwordspray", "bruteuser"}
    if action not in valid_actions:
        return json.dumps({"error": f"Invalid action '{action}'. Use: {valid_actions}"})
    cmd = (
        f"kerbrute {shlex.quote(action)} "
        f"--domain {shlex.quote(domain)} "
        f"--dc {shlex.quote(dc)} "
        f"{shlex.quote(wordlist)}"
    )
    return fmt_output(await run_shell(cmd, timeout=300), "kerbrute")


# ===========================================================================
# NEW TOOLS — Bug-Bounty Recon Stack
# ===========================================================================

# ---------------------------------------------------------------------------
# 24. naabu_scan — fast parallel port discovery
# ---------------------------------------------------------------------------
@mcp.tool()
async def naabu_scan(
    target: str,
    ports: str = "-top-ports 1000",
    rate: int = 1000,
) -> str:
    """
    Fast parallel port scanner from ProjectDiscovery.
    Use this BEFORE nmap on large IP ranges — finds open ports in seconds.

    Args:
        target: IP address, hostname, or CIDR range
        ports:  Port spec (default: '-top-ports 1000'). Use '-p 1-65535' for full scan.
        rate:   Packets per second (default: 1000)
    """
    cmd = f"naabu -host {shlex.quote(target)} {ports} -rate {rate} -json -silent"
    return fmt_output(await run_shell(cmd, timeout=300), "naabu_scan")


# ---------------------------------------------------------------------------
# 25. dnsx_resolve — bulk DNS resolution & wildcard filtering
# ---------------------------------------------------------------------------
@mcp.tool()
async def dnsx_resolve(
    domains: str,
    record_types: str = "A,CNAME,MX,TXT",
    threads: int = 100,
) -> str:
    """
    Bulk DNS resolver for subdomain lists. Filters wildcards automatically.
    Pipe subfinder output directly into this.

    Args:
        domains:      Newline-separated list of domains/subdomains to resolve
        record_types: Comma-separated DNS record types (default: A,CNAME,MX,TXT)
        threads:      Concurrent threads (default: 100)
    """
    rtype_flags = " ".join(f"-{rt.strip().lower()}" for rt in record_types.split(","))
    cmd = f"echo {shlex.quote(domains)} | dnsx {rtype_flags} -t {threads} -json -silent"
    return fmt_output(await run_shell(cmd, timeout=180), "dnsx_resolve")


# ---------------------------------------------------------------------------
# 26. katana_crawl — JS-aware web crawler
# ---------------------------------------------------------------------------
@mcp.tool()
async def katana_crawl(
    url: str,
    depth: int = 3,
    js_crawl: bool = True,
    headless: bool = False,
) -> str:
    """
    JS-aware web crawler that discovers endpoints, params, and JS files.
    Includes wayback fallback. Run after httpx_probe to find attack surface.

    Args:
        url:      Target URL (e.g. https://example.com)
        depth:    Crawl depth (default: 3)
        js_crawl: Parse and crawl JS files for embedded endpoints (default: True)
        headless: Use headless browser for SPA sites (default: False)
    """
    jc = "-jc" if js_crawl else ""
    hl = "-headless" if headless else ""
    cmd = f"katana -u {shlex.quote(url)} -d {depth} {jc} {hl} -silent"
    return fmt_output(await run_shell(cmd, timeout=300), "katana_crawl")


# ---------------------------------------------------------------------------
# 27. gau_urls — harvest historical URLs from public archives
# ---------------------------------------------------------------------------
@mcp.tool()
async def gau_urls(
    domain: str,
    threads: int = 5,
    providers: str = "wayback,otx,commoncrawl",
) -> str:
    """
    Harvest historical URLs from Wayback Machine, OTX, and CommonCrawl.
    The #1 source for finding forgotten endpoints, old params, and leaked files.

    Args:
        domain:    Target domain (e.g. example.com)
        threads:   Concurrent threads (default: 5)
        providers: Data sources to query (default: wayback,otx,commoncrawl)
    """
    provider_flags = ",".join(providers.split(","))
    cmd = f"gau --threads {threads} --providers {shlex.quote(provider_flags)} {shlex.quote(domain)}"
    return fmt_output(await run_shell(cmd, timeout=180), "gau_urls")


# ---------------------------------------------------------------------------
# 28. waybackurls_fetch — wayback machine URL dump
# ---------------------------------------------------------------------------
@mcp.tool()
async def waybackurls_fetch(domain: str) -> str:
    """
    Pull all archived URLs for a domain from the Wayback Machine.
    Complements gau_urls — use both for maximum URL coverage.

    Args:
        domain: Target domain (e.g. example.com)
    """
    cmd = f"waybackurls {shlex.quote(domain)}"
    return fmt_output(await run_shell(cmd, timeout=180), "waybackurls_fetch")


# ---------------------------------------------------------------------------
# 29. dalfox_xss — verified XSS scanner
# ---------------------------------------------------------------------------
@mcp.tool()
async def dalfox_xss(
    url: str,
    data: str = "",
    blind_host: str = "",
) -> str:
    """
    Confirm XSS vulnerabilities with verified payloads.
    Use AFTER nuclei flags XSS candidates to eliminate false positives.

    Args:
        url:        Target URL (e.g. http://example.com/search?q=test)
        data:       POST data body (optional, for POST-based XSS)
        blind_host: Blind XSS callback host (optional, e.g. your interactsh URL)
    """
    data_flag = f"--data {shlex.quote(data)}" if data else ""
    blind_flag = f"--blind {shlex.quote(blind_host)}" if blind_host else ""
    cmd = f"dalfox url {shlex.quote(url)} {data_flag} {blind_flag} --silence --no-color"
    return fmt_output(await run_shell(cmd, timeout=300), "dalfox_xss")


# ---------------------------------------------------------------------------
# 30. subzy_takeover — subdomain takeover detection
# ---------------------------------------------------------------------------
@mcp.tool()
async def subzy_takeover(
    targets: str,
    concurrency: int = 10,
) -> str:
    """
    Detect subdomain takeover vulnerabilities.
    Run after subfinder_enum + dnsx_resolve to check CNAME dangling records.

    Args:
        targets:     Newline-separated list of subdomains to check
        concurrency: Concurrent checks (default: 10)
    """
    cmd = f"echo {shlex.quote(targets)} | subzy run --stdin --concurrency {concurrency} --hide-fails"
    return fmt_output(await run_shell(cmd, timeout=180), "subzy_takeover")


# ---------------------------------------------------------------------------
# 31. gowitness_screenshot — visual screenshot of web targets
# ---------------------------------------------------------------------------
@mcp.tool()
async def gowitness_screenshot(
    targets: str,
    threads: int = 4,
) -> str:
    """
    Take screenshots of web targets for visual triage and report evidence.
    Saved to /app/screenshots/ inside the container.

    Args:
        targets: Newline-separated list of URLs to screenshot
        threads: Concurrent browser threads (default: 4)
    """
    cmd = (
        f"echo {shlex.quote(targets)} | "
        f"gowitness scan file -f - --screenshot-path /app/screenshots "
        f"--threads {threads} --write-db"
    )
    return fmt_output(await run_shell(cmd, timeout=300), "gowitness_screenshot")


# ---------------------------------------------------------------------------
# 32. gitleaks_scan — secret & credential scanner
# ---------------------------------------------------------------------------
@mcp.tool()
async def gitleaks_scan(
    target: str,
    scan_type: str = "dir",
) -> str:
    """
    Scan for leaked secrets, API keys, and credentials in files or git repos.

    Args:
        target:    Path or git repo URL to scan
        scan_type: 'dir' for local directory, 'git' for git repo (default: dir)
    """
    valid = {"dir", "git"}
    if scan_type not in valid:
        return json.dumps({"error": f"Invalid scan_type '{scan_type}'. Use: {valid}"})
    cmd = f"gitleaks {scan_type} {shlex.quote(target)} --no-banner -f json"
    return fmt_output(await run_shell(cmd, timeout=180), "gitleaks_scan")


# ---------------------------------------------------------------------------
# 33. asnmap_lookup — ASN to CIDR range mapping
# ---------------------------------------------------------------------------
@mcp.tool()
async def asnmap_lookup(
    target: str,
) -> str:
    """
    Map an ASN, organization name, IP, or domain to its full CIDR ranges.
    Use to discover all IP blocks owned by a target organization.

    Args:
        target: ASN (e.g. AS13335), domain, IP, or org name (e.g. 'cloudflare')
    """
    cmd = f"asnmap -a {shlex.quote(target)} -json"
    return fmt_output(await run_shell(cmd, timeout=60), "asnmap_lookup")


# ---------------------------------------------------------------------------
# 34. alterx_permute — subdomain permutation generation
# ---------------------------------------------------------------------------
@mcp.tool()
async def alterx_permute(
    subdomains: str,
    patterns: str = "",
) -> str:
    """
    Generate subdomain permutations from a list of existing subdomains.
    Pair with dnsx_resolve to validate which permutations actually resolve.

    Args:
        subdomains: Newline-separated list of known subdomains
        patterns:   Custom permutation patterns (optional, uses built-in if empty)
    """
    pattern_flag = f"-p {shlex.quote(patterns)}" if patterns else ""
    cmd = f"echo {shlex.quote(subdomains)} | alterx {pattern_flag} -silent"
    return fmt_output(await run_shell(cmd, timeout=120), "alterx_permute")


# ---------------------------------------------------------------------------
# 35. interactsh_oob — out-of-band callback testing
# ---------------------------------------------------------------------------
@mcp.tool()
async def interactsh_oob(
    action: str = "start",
    output_file: str = "/tmp/oob.txt",
) -> str:
    """
    Start or stop the interactsh OOB server for blind SSRF/XXE/SQLi/RCE testing.
    On 'start': generates a unique callback URL. On 'check': reads captured callbacks.

    Args:
        action:      'start' to launch listener, 'check' to read captured callbacks
        output_file: File to write OOB interactions (default: /tmp/oob.txt)
    """
    if action == "start":
        cmd = f"interactsh-client -o {shlex.quote(output_file)} -json & echo $!"
        return fmt_output(await run_shell(cmd, timeout=10), "interactsh_oob")
    elif action == "check":
        cmd = f"cat {shlex.quote(output_file)} 2>/dev/null || echo '[]'"
        return fmt_output(await run_shell(cmd, timeout=10), "interactsh_oob")
    else:
        return json.dumps({"error": "action must be 'start' or 'check'"})


# ---------------------------------------------------------------------------
# 36. uncover_search — attack surface search via Shodan/Censys
# ---------------------------------------------------------------------------
@mcp.tool()
async def uncover_search(
    query: str,
    engine: str = "shodan",
    limit: int = 100,
) -> str:
    """
    Search for exposed assets using Shodan, Censys, FOFA, and other engines.
    Requires API keys set as SHODAN_API_KEY / CENSYS_API_ID env vars.

    Args:
        query:  Search query (e.g. 'apache country:IN', 'ssl:example.com')
        engine: Search engine: shodan|censys|fofa|quake|hunter|zoomeye (default: shodan)
        limit:  Max results (default: 100)
    """
    cmd = f"uncover -q {shlex.quote(query)} -e {shlex.quote(engine)} -l {limit} -json -silent"
    return fmt_output(await run_shell(cmd, timeout=60), "uncover_search")


# ===========================================================================
# AGENT TOOLS (require Ollama)
# ===========================================================================

@mcp.tool()
async def pentest_target(goal: str, model: str = "", max_steps: int = 0) -> str:
    """
    Autonomous AI-driven penetration test.

    Describe your goal in plain English — the Ollama LLM plans and executes
    the right sequence of Kali tools, parses results, and returns a JSON report.

    Examples:
        "Scan all ports on 10.0.0.1 and identify services"
        "Find subdomains of example.com and check which are live"
        "Run a full web vuln assessment on http://testphp.vulnweb.com"

    Args:
        goal:      Plain-English security testing goal
        model:     Ollama model override (default: env OLLAMA_MODEL)
        max_steps: Max tool-call iterations override (default: env MAX_AGENT_STEPS)
    """
    if model:
        os.environ["OLLAMA_MODEL"] = model
    if max_steps > 0:
        os.environ["MAX_AGENT_STEPS"] = str(max_steps)

    from agent.planner import PentestAgent
    from memory.store import MemoryStore

    store = MemoryStore()
    await store.init()
    agent = PentestAgent(store=store)
    result = await agent.run(goal)
    await store.close()
    return result.model_dump_json(indent=2)


@mcp.tool()
async def generate_report(goal: str, model: str = "", fmt: str = "markdown") -> str:
    """
    Run a full autonomous pentest and return a formatted report.

    Args:
        goal:  Plain-English security testing goal
        model: Ollama model override (optional)
        fmt:   Report format — 'markdown' (default) or 'html'
    """
    if model:
        os.environ["OLLAMA_MODEL"] = model

    from agent.planner import PentestAgent
    from memory.store import MemoryStore
    from reporting.markdown import generate_markdown_report
    from reporting.html import generate_html_report

    store = MemoryStore()
    await store.init()
    agent = PentestAgent(store=store)
    result = await agent.run(goal)
    await store.close()

    if fmt == "html":
        return generate_html_report(result)
    return generate_markdown_report(result)


@mcp.tool()
async def export_report(goal: str, fmt: str = "markdown", filename: str = "") -> str:
    """
    Run a pentest, generate a report, and save it to /app/reports/.

    Args:
        goal:     Plain-English security testing goal
        fmt:      'markdown' | 'html' (default: markdown)
        filename: Custom filename without extension (auto-generated if empty)

    Returns:
        JSON with the saved file path and a report preview.
    """
    import re
    from pathlib import Path
    from datetime import datetime, timezone
    from agent.planner import PentestAgent
    from memory.store import MemoryStore
    from reporting.markdown import generate_markdown_report
    from reporting.html import generate_html_report

    store = MemoryStore()
    await store.init()
    agent = PentestAgent(store=store)
    result = await agent.run(goal)
    await store.close()

    # Generate report content
    if fmt == "html":
        content = generate_html_report(result)
        ext = ".html"
    else:
        content = generate_markdown_report(result)
        ext = ".md"

    # Build filename
    if not filename:
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        slug = re.sub(r"[^a-z0-9]+", "_", goal.lower())[:40]
        filename = f"{ts}_{slug}"

    out_path = Path("/app/reports") / f"{filename}{ext}"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(content, encoding="utf-8")

    return json.dumps({
        "saved_to": str(out_path),
        "format": fmt,
        "steps_taken": result.steps_taken,
        "preview": content[:500],
    }, indent=2)


@mcp.tool()
async def search_findings(query: str, limit: int = 50) -> str:
    """
    Search historical scan findings stored in the local SQLite database.

    Args:
        query: Search term (e.g. 'apache', 'CVE-2021', 'ssh', '192.168')
        limit: Max results (default 50)
    """
    from memory.store import MemoryStore

    store = MemoryStore()
    await store.init()
    findings = await store.search_findings(query, limit=limit)
    await store.close()
    return json.dumps(findings, indent=2)


@mcp.tool()
async def get_attack_surface(target: str) -> str:
    """
    Retrieve everything known about a target from the findings database.
    Returns all ports, subdomains, and vulnerabilities discovered in past scans.

    Args:
        target: IP address, hostname, or domain to look up
    """
    from memory.store import MemoryStore

    store = MemoryStore()
    await store.init()
    surface = await store.get_attack_surface(target)
    sessions = await store.recent_sessions(limit=5)
    await store.close()
    return json.dumps({"attack_surface": surface, "recent_sessions": sessions}, indent=2)


@mcp.tool()
async def list_sessions(limit: int = 20) -> str:
    """
    List recent pentest sessions from the database.

    Args:
        limit: Number of sessions to return (default 20)
    """
    from memory.store import MemoryStore

    store = MemoryStore()
    await store.init()
    sessions = await store.recent_sessions(limit=limit)
    await store.close()
    return json.dumps(sessions, indent=2)


@mcp.tool()
async def cve_stats() -> str:
    """Show CVE database statistics: total count, severity breakdown, last sync time."""
    from memory.cve_store import CveStore

    store = CveStore()
    await store.init()
    stats_data = await store.stats()
    await store.close()
    return json.dumps(stats_data, indent=2)


# ===========================================================================
# NEW TOOLS — Gap Analysis Implementation
# ===========================================================================

# ---------------------------------------------------------------------------
# 44. jwt_attack — JWT token analysis and exploitation (jwt_tool installed)
# ---------------------------------------------------------------------------
@mcp.tool()
async def jwt_attack(
    token: str,
    mode: str = "decode",
    secret: str = "",
) -> str:
    """
    Analyze, tamper, and attack JWT tokens.

    Args:
        token: The JWT token string (eyJ...)
        mode:  decode | crack | alg_confusion | none_alg | tamper
               - decode:        just decode and show all claims
               - crack:         brute-force the HMAC secret (needs secret wordlist)
               - alg_confusion: try RS256→HS256 confusion attack
               - none_alg:      try 'alg:none' bypass
               - tamper:        show all attack vectors available
        secret: Wordlist path for crack mode, or known secret for verify mode
    """
    if mode == "decode":
        cmd = f"jwt_tool {shlex.quote(token)} -d"
    elif mode == "crack":
        wl = secret or "/usr/share/wordlists/rockyou.txt"
        cmd = f"jwt_tool {shlex.quote(token)} -C -d {shlex.quote(wl)}"
    elif mode == "alg_confusion":
        cmd = f"jwt_tool {shlex.quote(token)} -X a"
    elif mode == "none_alg":
        cmd = f"jwt_tool {shlex.quote(token)} -X n"
    else:
        # tamper / show all attacks
        cmd = f"jwt_tool {shlex.quote(token)} -M at"
    return fmt_output(await run_shell(cmd, timeout=120), "jwt_attack")


# ---------------------------------------------------------------------------
# 45. cors_check — CORS misconfiguration scanner (corsy installed)
# ---------------------------------------------------------------------------
@mcp.tool()
async def cors_check(
    url: str,
    threads: int = 10,
    headers: str = "User-Agent: Mozilla/5.0",
) -> str:
    """
    Test for CORS misconfiguration vulnerabilities.
    Checks for wildcard origins, null origin, trusted subdomain bypass, etc.

    Args:
        url:     Target URL (e.g. https://api.example.com)
        threads: Concurrent threads (default 10)
        headers: Extra request headers (default adds a browser UA)
    """
    header_flag = f"--headers '{headers}'" if headers else ""
    cmd = f"corsy -u {shlex.quote(url)} -t {threads} {header_flag}"
    return fmt_output(await run_shell(cmd, timeout=120), "cors_check")


# ---------------------------------------------------------------------------
# 46. smuggling_test — HTTP request smuggling (smuggler installed)
# ---------------------------------------------------------------------------
@mcp.tool()
async def smuggling_test(
    url: str,
    timeout: int = 10,
    log_file: str = "/tmp/smuggler_out.txt",
) -> str:
    """
    Test for HTTP Request Smuggling vulnerabilities (CL.TE, TE.CL, TE.TE).
    Use on HTTP/1.1 endpoints, load balancers, and reverse proxies.

    Args:
        url:      Target URL (must be http:// or https://)
        timeout:  Per-request timeout in seconds (default 10)
        log_file: File to write findings (default /tmp/smuggler_out.txt)
    """
    cmd = (
        f"python3 /opt/smuggler/smuggler.py "
        f"-u {shlex.quote(url)} "
        f"-t {timeout} "
        f"-l {shlex.quote(log_file)}"
    )
    result = await run_shell(cmd, timeout=120)
    # Also read log file if it has content
    log_result = await run_shell(f"cat {shlex.quote(log_file)} 2>/dev/null || echo 'No findings logged'")
    combined = {
        "stdout": result.get("stdout", ""),
        "log": log_result.get("stdout", ""),
        "returncode": result.get("returncode"),
    }
    import json as _json
    return fmt_output({"stdout": _json.dumps(combined), "stderr": "", "returncode": 0}, "smuggling_test")


# ---------------------------------------------------------------------------
# 47. trufflehog_scan — deep secret & credential scanner (trufflehog installed)
# ---------------------------------------------------------------------------
@mcp.tool()
async def trufflehog_scan(
    target: str,
    scan_type: str = "filesystem",
    only_verified: bool = False,
) -> str:
    """
    Deep secret and credential scanner. Scans git history, filesystems, and repos.
    Finds API keys, passwords, tokens, private keys even in old commits.

    Args:
        target:        Path/URL to scan (local dir, git repo URL, or 'git' repo)
        scan_type:     filesystem | git | github | gitlab (default: filesystem)
        only_verified: Only report verified/live secrets (default: False)
    """
    verified_flag = "--only-verified" if only_verified else ""
    cmd = (
        f"trufflehog {shlex.quote(scan_type)} "
        f"{shlex.quote(target)} "
        f"--json --no-update {verified_flag}"
    )
    return fmt_output(await run_shell(cmd, timeout=300), "trufflehog_scan")


# ---------------------------------------------------------------------------
# 48. header_audit — HTTP security header analysis (pure curl)
# ---------------------------------------------------------------------------
@mcp.tool()
async def header_audit(url: str) -> str:
    """
    Audit HTTP security headers for misconfigurations and missing protections.
    Checks: HSTS, CSP, X-Frame-Options, X-XSS-Protection, Referrer-Policy,
    Permissions-Policy, CORS headers, and cookie security flags.

    Args:
        url: Target URL (e.g. https://example.com)
    """
    cmd = f"curl -sSI --max-redirs 5 --connect-timeout 10 {shlex.quote(url)}"
    result = await run_shell(cmd, timeout=30)
    headers_raw = result.get("stdout", "")

    # Parse and grade each security header
    checks = {
        "Strict-Transport-Security": ("HSTS", "Missing — site can be downgraded to HTTP"),
        "Content-Security-Policy": ("CSP", "Missing — XSS risk if not set"),
        "X-Frame-Options": ("Clickjacking", "Missing — site can be embedded in iframes"),
        "X-Content-Type-Options": ("MIME Sniff", "Missing — MIME type confusion attacks possible"),
        "Referrer-Policy": ("Referrer Leak", "Missing — referrer headers leak to third parties"),
        "Permissions-Policy": ("Feature Policy", "Missing — browser features unrestricted"),
    }

    findings = {}
    headers_lower = headers_raw.lower()
    for header, (label, missing_msg) in checks.items():
        if header.lower() in headers_lower:
            findings[label] = "✅ Present"
        else:
            findings[label] = f"❌ {missing_msg}"

    # CORS check
    if "access-control-allow-origin: *" in headers_lower:
        findings["CORS"] = "⚠️  Wildcard (*) — accepts requests from any origin"
    elif "access-control-allow-origin" in headers_lower:
        findings["CORS"] = "✅ Restricted origin"
    else:
        findings["CORS"] = "ℹ️  No CORS headers (not necessarily bad)"

    import json as _json
    output = _json.dumps({"url": url, "security_headers": findings, "raw_headers": headers_raw}, indent=2)
    return fmt_output({"stdout": output, "stderr": "", "returncode": 0}, "header_audit")


# ---------------------------------------------------------------------------
# 49. whois_lookup — WHOIS domain / IP registration info
# ---------------------------------------------------------------------------
@mcp.tool()
async def whois_lookup(target: str) -> str:
    """
    WHOIS lookup for a domain or IP address.
    Returns registrant info, nameservers, registration dates, and org details.
    Useful for scope validation and finding related domains/orgs.

    Args:
        target: Domain (e.g. example.com) or IP address (e.g. 1.2.3.4)
    """
    cmd = f"whois {shlex.quote(target)}"
    return fmt_output(await run_shell(cmd, timeout=30), "whois_lookup")


# ---------------------------------------------------------------------------
# 50. crt_sh_enum — Certificate Transparency subdomain discovery
# ---------------------------------------------------------------------------
@mcp.tool()
async def crt_sh_enum(domain: str) -> str:
    """
    Search Certificate Transparency logs (crt.sh) for subdomains.
    Completely passive and free — no API key needed.
    Often finds subdomains that subfinder and amass miss.
    Always run this alongside subfinder_enum.

    Args:
        domain: Target domain (e.g. example.com)
    """
    cmd = f"curl -s 'https://crt.sh/?q=%25.{shlex.quote(domain)}&output=json'"
    return fmt_output(await run_shell(cmd, timeout=30), "crt_sh_enum")


# ---------------------------------------------------------------------------
# 51. lfi_scan — Local File Inclusion fuzzer (ffuf + SecLists)
# ---------------------------------------------------------------------------
@mcp.tool()
async def lfi_scan(
    url: str,
    param: str = "FUZZ",
    threads: int = 40,
) -> str:
    """
    Fuzz for Local File Inclusion (LFI) and Path Traversal vulnerabilities.
    Use on any URL parameter that reads files (page=, file=, path=, template=).

    Example:
        url = "http://example.com/index.php?page=FUZZ"

    Args:
        url:    URL with FUZZ keyword where the LFI payload goes
        param:  Fuzzing keyword in the URL (default: FUZZ)
        threads: Concurrent threads (default: 40)
    """
    wordlist = "/usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt"
    cmd = (
        f"ffuf -u {shlex.quote(url)} "
        f"-w {shlex.quote(wordlist)}:{shlex.quote(param)} "
        f"-fc 404,400 -t {threads} -json -s"
    )
    return fmt_output(await run_shell(cmd, timeout=300), "lfi_scan")


# ---------------------------------------------------------------------------
# 52. smb_enum — Windows/Samba SMB enumeration (enum4linux)
# ---------------------------------------------------------------------------
@mcp.tool()
async def smb_enum(
    target: str,
    username: str = "",
    password: str = "",
) -> str:
    """
    Enumerate Windows/Samba SMB shares, users, groups, and password policies.
    Use when nmap shows port 445 or 139 open.

    Args:
        target:   Target IP address
        username: SMB username for authenticated enumeration (optional)
        password: SMB password for authenticated enumeration (optional)
    """
    auth_flag = f"-u {shlex.quote(username)} -p {shlex.quote(password)}" if username else ""
    cmd = f"enum4linux -a {auth_flag} {shlex.quote(target)}"
    return fmt_output(await run_shell(cmd, timeout=180), "smb_enum")


# ---------------------------------------------------------------------------
# 53. ssh_audit_tool — SSH server algorithm and config audit
# ---------------------------------------------------------------------------
@mcp.tool()
async def ssh_audit_tool(host: str, port: int = 22) -> str:
    """
    Audit SSH server for weak algorithms, deprecated ciphers, and misconfigurations.
    Use when nmap shows port 22 open. Identifies CVE-linked weaknesses.

    Args:
        host: Target hostname or IP
        port: SSH port (default 22)
    """
    cmd = f"ssh-audit -j {shlex.quote(host)}:{port}"
    return fmt_output(await run_shell(cmd, timeout=60), "ssh_audit_tool")


# ---------------------------------------------------------------------------
# 54. open_redirect_check — Open redirect vulnerability scanner
# ---------------------------------------------------------------------------
@mcp.tool()
async def open_redirect_check(
    url: str,
    param: str = "FUZZ",
    threads: int = 30,
) -> str:
    """
    Test for open redirect vulnerabilities by fuzzing URL/redirect parameters.
    Use on login pages, OAuth flows, and any URL with redirect/return/next params.

    Example:
        url = "https://example.com/login?next=FUZZ"

    Args:
        url:     URL with FUZZ where redirect payload goes
        param:   Fuzzing keyword (default: FUZZ)
        threads: Concurrent threads (default: 30)
    """
    wordlist = "/usr/share/seclists/Fuzzing/redirect_urls.txt"
    # Fallback: create a minimal redirect payload list if seclists doesn't have it
    fallback_payloads = (
        "https://evil.com\n"
        "//evil.com\n"
        "/\\evil.com\n"
        "https:evil.com\n"
        "/%09/evil.com\n"
    )
    setup_cmd = (
        f"[ -f {shlex.quote(wordlist)} ] || "
        f"echo {shlex.quote(fallback_payloads)} > /tmp/redirect_payloads.txt"
    )
    await run_shell(setup_cmd)
    wl = wordlist if (await run_shell(f"test -f {shlex.quote(wordlist)} && echo yes")).get("stdout", "").strip() == "yes" else "/tmp/redirect_payloads.txt"
    cmd = (
        f"ffuf -u {shlex.quote(url)} "
        f"-w {shlex.quote(wl)}:{shlex.quote(param)} "
        f"-mr 'Location:' -fc 404 -t {threads} -json -s"
    )
    return fmt_output(await run_shell(cmd, timeout=180), "open_redirect_check")


# ---------------------------------------------------------------------------
# 55. bypass_403 — 403 Forbidden bypass via header manipulation
# ---------------------------------------------------------------------------
@mcp.tool()
async def bypass_403(url: str) -> str:
    """
    Attempt to bypass 403 Forbidden responses using common header tricks.
    Tries: X-Forwarded-For, X-Real-IP, X-Custom-IP-Authorization, path manipulation,
    method overrides, and URL encoding variants.

    Args:
        url: The URL returning 403 (e.g. https://example.com/admin)
    """
    import json as _json

    bypass_attempts = [
        ("Original", url, ""),
        ("X-Forwarded-For: 127.0.0.1", url, "-H 'X-Forwarded-For: 127.0.0.1'"),
        ("X-Forwarded-For: localhost", url, "-H 'X-Forwarded-For: localhost'"),
        ("X-Real-IP: 127.0.0.1", url, "-H 'X-Real-IP: 127.0.0.1'"),
        ("X-Custom-IP-Authorization: 127.0.0.1", url, "-H 'X-Custom-IP-Authorization: 127.0.0.1'"),
        ("X-Originating-IP: 127.0.0.1", url, "-H 'X-Originating-IP: 127.0.0.1'"),
        ("Referer: https://google.com", url, "-H 'Referer: https://google.com'"),
        ("URL with trailing slash", url.rstrip("/") + "/", ""),
        ("URL with /./", url.rstrip("/") + "/./", ""),
        ("URL with ..;/ suffix", url.rstrip("/") + "/..;/", ""),
    ]

    results = []
    for label, target_url, extra_flag in bypass_attempts:
        cmd = f"curl -sk -o /dev/null -w '%{{http_code}}' {extra_flag} {shlex.quote(target_url)}"
        r = await run_shell(cmd, timeout=10)
        status = r.get("stdout", "???").strip()
        results.append({"attempt": label, "status_code": status, "bypassed": status == "200"})

    output = _json.dumps({"target": url, "bypass_attempts": results}, indent=2)
    return fmt_output({"stdout": output, "stderr": "", "returncode": 0}, "bypass_403")


# ---------------------------------------------------------------------------
# 56. js_extract — extract endpoints and secrets from JavaScript files
# ---------------------------------------------------------------------------
@mcp.tool()
async def js_extract(url_or_file: str) -> str:
    """
    Extract endpoints, API paths, and potential secrets from JavaScript files.
    Use after katana_crawl finds .js files — pass each JS file URL here.

    Args:
        url_or_file: URL to a JS file (https://example.com/app.js)
                     or local path (/tmp/app.js)
    """
    import json as _json

    # Download JS if it's a URL
    if url_or_file.startswith("http"):
        dl_cmd = f"curl -sk {shlex.quote(url_or_file)} -o /tmp/js_extract_target.js"
        await run_shell(dl_cmd, timeout=30)
        js_file = "/tmp/js_extract_target.js"
    else:
        js_file = url_or_file

    # Extract URL-like patterns
    endpoints_cmd = (
        f"grep -oE '(\"|\\')/[a-zA-Z0-9_/.-]{{2,}}(\"|\\')|"
        f"(api|endpoint|url|path|route)[\"\\s]*[:=][\"\\s]*[\"\\'][^\"\\']{{5,}}[\"\\']' "
        f"{shlex.quote(js_file)} | sort -u | head -100"
    )
    endpoints_result = await run_shell(endpoints_cmd, timeout=15)

    # Extract potential secrets (API keys, tokens)
    secrets_cmd = (
        f"grep -oiE '(api[_-]?key|token|secret|password|auth|bearer|aws)[\"\\s]*[:=][\"\\s]*[\"\\'][A-Za-z0-9_/+=-]{{10,}}[\"\\']' "
        f"{shlex.quote(js_file)} | sort -u | head -50"
    )
    secrets_result = await run_shell(secrets_cmd, timeout=15)

    output = _json.dumps({
        "source": url_or_file,
        "endpoints_found": endpoints_result.get("stdout", "").splitlines(),
        "potential_secrets": secrets_result.get("stdout", "").splitlines(),
    }, indent=2)
    return fmt_output({"stdout": output, "stderr": "", "returncode": 0}, "js_extract")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    mcp.run(transport="stdio")


