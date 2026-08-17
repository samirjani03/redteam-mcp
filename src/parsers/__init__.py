"""src/parsers — typed output parsers for every tool."""
from parsers.base import ScanResult, Finding, Port, Subdomain
from parsers.nmap import parse_nmap
from parsers.nuclei import parse_nuclei
from parsers.subfinder import parse_subfinder
from parsers.gobuster import parse_gobuster
from parsers.nikto import parse_nikto
from parsers.whatweb import parse_whatweb
from parsers.httpx import parse_httpx

__all__ = [
    "ScanResult", "Finding", "Port", "Subdomain",
    "parse_nmap", "parse_nuclei", "parse_subfinder",
    "parse_gobuster", "parse_nikto", "parse_whatweb", "parse_httpx",
]
