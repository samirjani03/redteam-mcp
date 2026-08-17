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


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    mcp.run(transport="stdio")

