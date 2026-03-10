from typing import Dict, List, Set

from shadowmap.config import Config
from shadowmap.utils.http_client import get_session
from shadowmap.utils.rate_limiter import RateLimiter
from shadowmap.utils.logger import get_logger

logger  = get_logger(__name__)
session = get_session()
limiter = RateLimiter(Config.DELAY_ABUSEIPDB)


def _risk(score: int) -> str:
    if score >= 80: return "HIGH"
    if score >= 40: return "MEDIUM"
    if score > 0:   return "LOW"
    return "CLEAN"


def check(ip: str) -> Dict:
    if not Config.ABUSEIPDB_API_KEY:
        logger.warning("[reputation] ABUSEIPDB_API_KEY not set")
        return {"ip": ip, "skipped": True}
    try:
        limiter.wait()
        resp = session.get(
            f"{Config.ABUSEIPDB_URL}/check",
            headers={"Key": Config.ABUSEIPDB_API_KEY, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": True},
            timeout=Config.HTTP_TIMEOUT,
        )
        resp.raise_for_status()
        data  = resp.json().get("data", {})
        score = data.get("abuseConfidenceScore", 0)
        logger.info(f"[reputation] {ip}: score={score}")
        return {
            "ip":               ip,
            "abuse_confidence": score,
            "risk_level":       _risk(score),
            "total_reports":    data.get("totalReports", 0),
            "last_reported":    data.get("lastReportedAt", ""),
            "is_tor":           data.get("isTor", False),
            "isp":              data.get("isp", ""),
            "domain":           data.get("domain", ""),
            "country":          data.get("countryCode", ""),
            "usage_type":       data.get("usageType", ""),
        }
    except Exception as e:
        logger.warning(f"[reputation] {ip}: {e}")
        return {"ip": ip, "error": str(e)}


def check_bulk(ip_list: List[str]) -> List[Dict]:
    logger.info(f"[reputation] checking {len(ip_list)} IPs")
    seen: Set[str] = set()
    results = []
    for ip in ip_list:
        if not ip or ip in seen:
            continue
        seen.add(ip)
        results.append(check(ip))
    return results
