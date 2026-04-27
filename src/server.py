"""
Red Team MCP Server
Exposes 20 penetration testing tools via the Model Context Protocol.
Runs inside a Kali Linux Docker container.
"""

import asyncio
import json
import shlex
from typing import Optional
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("RedTeamMCP")


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

async def _run(cmd: str, timeout: int = 120) -> dict:
    """Execute a shell command and return stdout/stderr/returncode."""
    proc = await asyncio.create_subprocess_shell(
        cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        return {"stdout": "", "stderr": f"Command timed out after {timeout}s", "returncode": -1}
    return {
        "stdout": stdout.decode(errors="replace").strip(),
        "stderr": stderr.decode(errors="replace").strip(),
        "returncode": proc.returncode,
    }


# ---------------------------------------------------------------------------
# 1. Nmap – Port & Service Scanner
# ---------------------------------------------------------------------------

@mcp.tool()
async def nmap_scan(
    target: str,
    ports: str = "1-1000",
    flags: str = "-sV -sC",
) -> str:
    """
    Run an Nmap scan against a target.

    Args:
        target: IP address, hostname, or CIDR range (e.g. 192.168.1.1 or 10.0.0.0/24)
        ports:  Port range or list (e.g. '80,443' or '1-65535'). Default: 1-1000
        flags:  Extra nmap flags (e.g. '-A -T4'). Default: '-sV -sC'
    """
    cmd = f"nmap {flags} -p {shlex.quote(ports)} {shlex.quote(target)} -oN -"
    result = await _run(cmd, timeout=300)
    return json.dumps(result)


# ---------------------------------------------------------------------------
# 2. Gobuster – Directory / DNS Brute-Force
# ---------------------------------------------------------------------------

@mcp.tool()
async def gobuster_dir(
    url: str,
    wordlist: str = "/usr/share/wordlists/dirb/common.txt",
    extensions: str = "php,html,txt,js",
    threads: int = 30,
) -> str:
    """
    Brute-force directories and files on a web server using Gobuster.

    Args:
        url:       Target URL (e.g. http://example.com)
        wordlist:  Path to wordlist inside the container
        extensions: Comma-separated file extensions to append
        threads:   Number of concurrent threads
    """
    cmd = (
        f"gobuster dir -u {shlex.quote(url)} "
        f"-w {shlex.quote(wordlist)} "
        f"-x {shlex.quote(extensions)} "
        f"-t {threads} --no-progress"
    )
    result = await _run(cmd, timeout=300)
    return json.dumps(result)


# ---------------------------------------------------------------------------
# 3. SQLMap – SQL Injection Scanner
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
    Automated SQL injection detection and exploitation with SQLMap.

    Args:
        url:         Target URL (e.g. http://example.com/page?id=1)
        data:        POST data string (leave empty for GET)
        level:       Test level 1-5 (higher = more tests)
        risk:        Risk level 1-3 (higher = more dangerous payloads)
        extra_flags: Additional sqlmap flags
    """
    cmd = f"sqlmap -u {shlex.quote(url)} --level={level} --risk={risk} {extra_flags}"
    if data:
        cmd += f" --data={shlex.quote(data)}"
    result = await _run(cmd, timeout=300)
    return json.dumps(result)


# ---------------------------------------------------------------------------
# 4. Nikto – Web Server Vulnerability Scanner
# ---------------------------------------------------------------------------

@mcp.tool()
async def nikto_scan(
    host: str,
    port: int = 80,
    ssl: bool = False,
) -> str:
    """
    Scan a web server for known vulnerabilities using Nikto.

    Args:
        host: Target hostname or IP
        port: Target port (default 80)
        ssl:  Use SSL/HTTPS (default False)
    """
    ssl_flag = "-ssl" if ssl else ""
    cmd = f"nikto -h {shlex.quote(host)} -p {port} {ssl_flag} -nointeractive"
    result = await _run(cmd, timeout=300)
    return json.dumps(result)


# ---------------------------------------------------------------------------
# 5. WhatWeb – Web Technology Fingerprinting
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
    result = await _run(cmd, timeout=120)
    return json.dumps(result)


# ---------------------------------------------------------------------------
# 6. Subfinder – Subdomain Enumeration
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
    result = await _run(cmd, timeout=180)
    return json.dumps(result)


# ---------------------------------------------------------------------------
# 7. Httpx – HTTP Probing
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
        targets:     Newline-separated list of hosts or URLs (passed via stdin)
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
    result = await _run(cmd, timeout=180)
    return json.dumps(result)


# ---------------------------------------------------------------------------
# 8. Nuclei – Vulnerability Template Scanner
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
        f"-json -silent"
    )
    result = await _run(cmd, timeout=300)
    return json.dumps(result)


# ---------------------------------------------------------------------------
# 9. FFuf – Fast Web Fuzzer
# ---------------------------------------------------------------------------

@mcp.tool()
async def ffuf_fuzz(
    url: str,
    wordlist: str = "/usr/share/wordlists/dirb/common.txt",
    keyword: str = "FUZZ",
    filter_codes: str = "404",
    threads: int = 40,
) -> str:
    """
    Fuzz web endpoints, parameters, or headers using FFuf.

    Args:
        url:          URL with FUZZ keyword (e.g. http://example.com/FUZZ)
        wordlist:     Path to wordlist
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
    result = await _run(cmd, timeout=300)
    return json.dumps(result)


# ---------------------------------------------------------------------------
# 10. WPScan – WordPress Vulnerability Scanner
# ---------------------------------------------------------------------------

@mcp.tool()
async def wpscan_scan(
    url: str,
    enumerate: str = "vp,vt,u",
    api_token: str = "",
) -> str:
    """
    Scan a WordPress site for vulnerabilities, plugins, themes, and users.

    Args:
        url:       Target WordPress URL
        enumerate: Enumeration options: vp=vulnerable plugins, vt=vulnerable themes, u=users
        api_token: WPScan API token for vulnerability data (optional)
    """
    token_flag = f"--api-token {shlex.quote(api_token)}" if api_token else ""
    cmd = (
        f"wpscan --url {shlex.quote(url)} "
        f"--enumerate {shlex.quote(enumerate)} "
        f"{token_flag} --format json --no-banner"
    )
    result = await _run(cmd, timeout=300)
    return json.dumps(result)


# ---------------------------------------------------------------------------
# 11. Amass – Attack Surface Mapping
# ---------------------------------------------------------------------------

@mcp.tool()
async def amass_enum(domain: str, passive: bool = True) -> str:
    """
    Perform in-depth DNS enumeration and attack surface mapping with Amass.

    Args:
        domain:  Target domain
        passive: Use only passive techniques (no direct interaction with target)
    """
    mode = "-passive" if passive else "-active"
    cmd = f"amass enum {mode} -d {shlex.quote(domain)} -json /dev/stdout"
    result = await _run(cmd, timeout=300)
    return json.dumps(result)


# ---------------------------------------------------------------------------
# 12. Hydra – Online Password Brute-Forcer
# ---------------------------------------------------------------------------

@mcp.tool()
async def hydra_brute(
    target: str,
    service: str,
    username: str,
    password_list: str = "/usr/share/wordlists/rockyou.txt",
    port: Optional[int] = None,
    threads: int = 16,
) -> str:
    """
    Brute-force login credentials using Hydra.

    Args:
        target:        Target IP or hostname
        service:       Service to attack (e.g. ssh, ftp, http-post-form)
        username:      Username or path to username list (prefix with 'L:' for list)
        password_list: Path to password wordlist
        port:          Custom port (optional)
        threads:       Parallel tasks
    """
    port_flag = f"-s {port}" if port else ""
    user_flag = f"-L {shlex.quote(username)}" if username.startswith("L:") else f"-l {shlex.quote(username)}"
    cmd = (
        f"hydra {user_flag} -P {shlex.quote(password_list)} "
        f"{port_flag} -t {threads} "
        f"{shlex.quote(target)} {shlex.quote(service)}"
    )
    result = await _run(cmd, timeout=300)
    return json.dumps(result)


# ---------------------------------------------------------------------------
# 13. Curl – Raw HTTP Request
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
    Send a raw HTTP request using curl — useful for manual testing and PoC verification.

    Args:
        url:              Target URL
        method:           HTTP method (GET, POST, PUT, DELETE, etc.)
        headers:          Newline-separated headers (e.g. 'Authorization: Bearer token')
        data:             Request body / POST data
        follow_redirects: Follow HTTP redirects
        insecure:         Skip TLS certificate verification
    """
    header_flags = " ".join(
        f"-H {shlex.quote(h.strip())}" for h in headers.splitlines() if h.strip()
    )
    data_flag = f"-d {shlex.quote(data)}" if data else ""
    redirect_flag = "-L" if follow_redirects else ""
    insecure_flag = "-k" if insecure else ""
    cmd = (
        f"curl -s -X {shlex.quote(method)} {redirect_flag} {insecure_flag} "
        f"{header_flags} {data_flag} -i {shlex.quote(url)}"
    )
    result = await _run(cmd, timeout=60)
    return json.dumps(result)


# ---------------------------------------------------------------------------
# 14. DNSRecon – DNS Enumeration
# ---------------------------------------------------------------------------

@mcp.tool()
async def dnsrecon_enum(
    domain: str,
    scan_type: str = "std",
) -> str:
    """
    Perform DNS reconnaissance on a target domain.

    Args:
        domain:    Target domain
        scan_type: Scan type: std, rvl, brt, axfr, goo, snoop, tld, zonewalk
    """
    cmd = f"dnsrecon -d {shlex.quote(domain)} -t {shlex.quote(scan_type)} -j /dev/stdout"
    result = await _run(cmd, timeout=180)
    return json.dumps(result)


# ---------------------------------------------------------------------------
# 15. TheHarvester – OSINT Email & Subdomain Harvesting
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
    result = await _run(cmd, timeout=180)
    # Also try to read JSON output if written
    read_result = await _run("cat /tmp/harvest_out.json 2>/dev/null || echo '{}'")
    return json.dumps({"run": result, "json_output": read_result["stdout"]})


# ---------------------------------------------------------------------------
# 16. Wafw00f – WAF Detection
# ---------------------------------------------------------------------------

@mcp.tool()
async def wafw00f_detect(url: str, find_all: bool = False) -> str:
    """
    Detect Web Application Firewalls (WAF) protecting a target.

    Args:
        url:      Target URL
        find_all: Try to detect all WAFs instead of stopping at first match
    """
    all_flag = "-a" if find_all else ""
    cmd = f"wafw00f {all_flag} -o - -f json {shlex.quote(url)}"
    result = await _run(cmd, timeout=60)
    return json.dumps(result)


# ---------------------------------------------------------------------------
# 17. SSLScan – SSL/TLS Configuration Auditor
# ---------------------------------------------------------------------------

@mcp.tool()
async def sslscan_audit(host: str, port: int = 443) -> str:
    """
    Audit SSL/TLS configuration of a target for weak ciphers, protocols, and certificates.

    Args:
        host: Target hostname or IP
        port: Target port (default 443)
    """
    cmd = f"sslscan --no-colour {shlex.quote(host)}:{port}"
    result = await _run(cmd, timeout=60)
    return json.dumps(result)


# ---------------------------------------------------------------------------
# 18. Commix – Command Injection Exploiter
# ---------------------------------------------------------------------------

@mcp.tool()
async def commix_scan(
    url: str,
    data: str = "",
    level: int = 1,
) -> str:
    """
    Detect and exploit OS command injection vulnerabilities.

    Args:
        url:   Target URL (e.g. http://example.com/page?cmd=ls)
        data:  POST data (optional)
        level: Test level 1-3
    """
    data_flag = f"--data={shlex.quote(data)}" if data else ""
    cmd = (
        f"commix --url={shlex.quote(url)} {data_flag} "
        f"--level={level} --batch --output-dir=/tmp/commix_out"
    )
    result = await _run(cmd, timeout=300)
    return json.dumps(result)


# ---------------------------------------------------------------------------
# 19. Arjun – HTTP Parameter Discovery
# ---------------------------------------------------------------------------

@mcp.tool()
async def arjun_params(
    url: str,
    method: str = "GET",
    threads: int = 20,
) -> str:
    """
    Discover hidden HTTP GET/POST parameters on a web endpoint.

    Args:
        url:     Target URL
        method:  HTTP method to test (GET or POST)
        threads: Concurrent threads
    """
    cmd = (
        f"arjun -u {shlex.quote(url)} "
        f"-m {shlex.quote(method)} "
        f"-t {threads} --json"
    )
    result = await _run(cmd, timeout=180)
    return json.dumps(result)


# ---------------------------------------------------------------------------
# 20. Metasploit – Auxiliary Module Runner
# ---------------------------------------------------------------------------

@mcp.tool()
async def msf_auxiliary(
    module: str,
    options: str,
) -> str:
    """
    Run a Metasploit Framework auxiliary module non-interactively.

    Args:
        module:  Full module path (e.g. auxiliary/scanner/http/http_version)
        options: Space-separated KEY=VALUE pairs (e.g. 'RHOSTS=192.168.1.1 THREADS=10')
    """
    set_cmds = "\n".join(f"set {opt}" for opt in options.split() if "=" in opt)
    rc_script = f"use {module}\n{set_cmds}\nrun\nexit\n"
    # Write RC script to temp file and execute
    write_cmd = f"echo {shlex.quote(rc_script)} > /tmp/msf_run.rc"
    await _run(write_cmd)
    cmd = "msfconsole -q -r /tmp/msf_run.rc"
    result = await _run(cmd, timeout=300)
    return json.dumps(result)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    mcp.run(transport="stdio")
