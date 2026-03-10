from typing import Dict, List, Set

from shadowmap.config import Config
from shadowmap.utils.rate_limiter import RateLimiter
from shadowmap.utils.logger import get_logger

logger  = get_logger(__name__)
limiter = RateLimiter(Config.DELAY_SHODAN)

_BANNER_MAX = 300


def _api():
    try:
        import shodan
    except ImportError:
        raise ImportError("Run: pip install shodan")
    if not Config.SHODAN_API_KEY:
        raise ValueError("SHODAN_API_KEY not set in .env")
    return shodan.Shodan(Config.SHODAN_API_KEY)


def lookup(ip: str) -> Dict:
    if not ip:
        return {}
    try:
        limiter.wait()
        host = _api().host(ip)
        services = [
            {
                "port":      item.get("port"),
                "transport": item.get("transport", "tcp"),
                "product":   item.get("product", ""),
                "version":   item.get("version", ""),
                "cpe":       item.get("cpe", []),
                "banner":    item.get("data", "")[:_BANNER_MAX],
            }
            for item in host.get("data", [])
        ]
        logger.info(f"[shodan] {ip}: {len(host.get('ports', []))} ports")
        return {
            "ip":                ip,
            "os":                host.get("os", ""),
            "country":           host.get("country_name", ""),
            "isp":               host.get("isp", ""),
            "org":               host.get("org", ""),
            "ports":             host.get("ports", []),
            "services":          services,
            "vulns_from_shodan": list(host.get("vulns", {}).keys()),
            "tags":              host.get("tags", []),
            "last_update":       host.get("last_update", ""),
        }
    except Exception as e:
        logger.warning(f"[shodan] {ip}: {e}")
        return {"ip": ip, "error": str(e)}


def scan(ip_list: List[str]) -> List[Dict]:
    logger.info(f"[shodan] scanning {len(ip_list)} IPs")
    seen: Set[str] = set()
    results = []
    for ip in ip_list:
        if not ip or ip in seen:
            continue
        seen.add(ip)
        r = lookup(ip)
        if r:
            results.append(r)
    return results
