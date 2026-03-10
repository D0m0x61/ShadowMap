import socket
from collections import defaultdict
from typing import Dict, List, Set

from shadowmap.config import Config
from shadowmap.utils.http_client import get_session
from shadowmap.utils.rate_limiter import RateLimiter
from shadowmap.utils.logger import get_logger

logger  = get_logger(__name__)
session = get_session()
_crtsh  = RateLimiter(Config.DELAY_CRTSH)
_ht     = RateLimiter(Config.DELAY_DEFAULT)


def _from_crtsh(domain: str) -> Set[str]:
    found: Set[str] = set()
    try:
        _crtsh.wait()
        resp = session.get(
            f"{Config.CRTSH_URL}/?q=%.{domain}&output=json",
            timeout=Config.HTTP_TIMEOUT,
        )
        resp.raise_for_status()
        for entry in resp.json():
            for name in entry.get("name_value", "").splitlines():
                name = name.strip().lstrip("*.")
                if name.endswith(f".{domain}") or name == domain:
                    found.add(name)
    except Exception as e:
        logger.warning(f"[subdomain/crtsh] {e}")
    return found


def _from_hackertarget(domain: str) -> Set[str]:
    found: Set[str] = set()
    try:
        _ht.wait()
        resp = session.get(
            f"{Config.HACKERTARGET_URL}/hostsearch/?q={domain}",
            timeout=Config.HTTP_TIMEOUT,
        )
        resp.raise_for_status()
        for line in resp.text.strip().splitlines():
            if "," in line and not line.startswith("error"):
                sub = line.split(",")[0].strip()
                if sub.endswith(f".{domain}") or sub == domain:
                    found.add(sub)
    except Exception as e:
        logger.warning(f"[subdomain/hackertarget] {e}")
    return found


def _resolve(hostname: str) -> str:
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror:
        return ""


def enumerate(domain: str) -> List[Dict]:
    logger.info(f"[subdomain] enumerating {domain}")
    sources: Dict[str, Set[str]] = defaultdict(set)

    for sub in _from_crtsh(domain):
        sources[sub].add("crt.sh")
    for sub in _from_hackertarget(domain):
        sources[sub].add("hackertarget")

    results = [
        {"subdomain": sub, "ip": _resolve(sub), "sources": sorted(srcs)}
        for sub, srcs in sorted(sources.items())
    ]
    logger.info(f"[subdomain] found {len(results)} subdomains")
    return results
