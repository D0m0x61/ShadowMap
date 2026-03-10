from typing import Dict, List, Set

from shadowmap.config import Config
from shadowmap.utils.http_client import get_session
from shadowmap.utils.rate_limiter import RateLimiter
from shadowmap.utils.logger import get_logger

logger  = get_logger(__name__)
session = get_session()
limiter = RateLimiter(Config.DELAY_CRTSH)


def _fetch(domain: str) -> List[Dict]:
    try:
        limiter.wait()
        resp = session.get(
            f"{Config.CRTSH_URL}/?q={domain}&output=json",
            timeout=Config.HTTP_TIMEOUT,
        )
        resp.raise_for_status()
        seen: Set[int] = set()
        certs = []
        for entry in resp.json():
            cid = entry.get("id")
            if cid in seen:
                continue
            seen.add(cid)
            names = [
                n.strip().lstrip("*.")
                for n in entry.get("name_value", "").splitlines()
                if n.strip()
            ]
            certs.append({
                "cert_id":     cid,
                "issuer":      entry.get("issuer_name", ""),
                "common_name": entry.get("common_name", ""),
                "san_names":   names,
                "not_before":  entry.get("not_before", ""),
                "not_after":   entry.get("not_after", ""),
            })
        return certs
    except Exception as e:
        logger.warning(f"[certs] crtsh {domain}: {e}")
        return []


def analyze(domain: str) -> Dict:
    logger.info(f"[certs] analyzing {domain}")
    certs = _fetch(domain)
    if not certs:
        return {"total_certs": 0, "correlated_domains": [], "top_issuers": [], "sample_certs": []}

    correlated: Set[str] = set()
    issuer_counts: Dict[str, int] = {}

    for cert in certs:
        issuer = cert.get("issuer", "")
        if issuer:
            issuer_counts[issuer] = issuer_counts.get(issuer, 0) + 1
        for name in cert.get("san_names", []):
            if name and name != domain and not name.startswith("*."):
                correlated.add(name)

    top_issuers = [
        {"issuer": k, "count": v}
        for k, v in sorted(issuer_counts.items(), key=lambda x: x[1], reverse=True)[:5]
    ]

    logger.info(f"[certs] {len(certs)} certs, {len(correlated)} correlated domains")
    return {
        "total_certs":        len(certs),
        "correlated_domains": sorted(correlated),
        "top_issuers":        top_issuers,
        "sample_certs":       certs[:5],
    }
