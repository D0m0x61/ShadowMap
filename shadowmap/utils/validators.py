import re
import socket
from typing import Tuple

_IP_RE     = re.compile(r"^((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)$")
_DOMAIN_RE = re.compile(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$")
_CVE_RE    = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)


def is_ip(value: str) -> bool:
    return bool(_IP_RE.match(value.strip()))


def is_domain(value: str) -> bool:
    return bool(_DOMAIN_RE.match(value.strip()))


def is_cve(value: str) -> bool:
    return bool(_CVE_RE.match(value.strip()))


def normalize_target(target: str) -> Tuple[str, str]:
    target = target.strip().lower().removeprefix("http://").removeprefix("https://").rstrip("/")
    if is_ip(target):
        return target, "ip"
    if is_domain(target):
        return target, "domain"
    raise ValueError(f"'{target}' is not a valid IPv4 address or domain name.")


def resolve_domain(domain: str) -> str:
    try:
        return socket.gethostbyname(domain)
    except socket.gaierror:
        return ""
