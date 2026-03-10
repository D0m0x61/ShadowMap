from typing import Dict, List, Set

from shadowmap.config import Config
from shadowmap.utils.http_client import get_session
from shadowmap.utils.rate_limiter import RateLimiter
from shadowmap.utils.logger import get_logger

logger  = get_logger(__name__)
session = get_session()
limiter = RateLimiter(Config.DELAY_DEFAULT)


def get_ip_info(ip: str) -> Dict:
    try:
        limiter.wait()
        url = f"{Config.IPINFO_URL}/{ip}/json"
        if Config.IPINFO_TOKEN:
            url += f"?token={Config.IPINFO_TOKEN}"
        resp = session.get(url, timeout=Config.HTTP_TIMEOUT)
        resp.raise_for_status()
        data  = resp.json()
        # IPInfo returns org as "AS13335 Cloudflare, Inc." — split into ASN + name
        org   = data.get("org", "")
        parts = org.split(" ", 1)
        asn      = parts[0] if parts and parts[0].startswith("AS") else ""
        asn_name = parts[1] if len(parts) > 1 else org
        return {
            "ip":       ip,
            "hostname": data.get("hostname", ""),
            "city":     data.get("city", ""),
            "region":   data.get("region", ""),
            "country":  data.get("country", ""),
            "org":      org,
            "asn":      asn,
            "timezone": data.get("timezone", ""),
            "asn_details": {
                "asn":         asn,
                "name":        asn_name,
                "description": asn_name,
                "country":     data.get("country", ""),
            },
            "asn_peers": [],
        }
    except Exception as e:
        logger.warning(f"[ip_asn] ipinfo {ip}: {e}")
        return {"ip": ip}


def enrich(ip_list: List[str]) -> List[Dict]:
    logger.info(f"[ip_asn] enriching {len(ip_list)} IPs")
    seen: Set[str] = set()
    results = []
    for ip in ip_list:
        if not ip or ip in seen:
            continue
        seen.add(ip)
        results.append(get_ip_info(ip))
    return results
