from typing import Dict, List, Optional, Set

from shadowmap.config import Config
from shadowmap.utils.http_client import get_session
from shadowmap.utils.rate_limiter import RateLimiter
from shadowmap.utils.logger import get_logger

logger  = get_logger(__name__)
session = get_session()
limiter = RateLimiter(Config.DELAY_NVD)

_kev_cache: Optional[Set[str]] = None


def _kev() -> Set[str]:
    global _kev_cache
    if _kev_cache is not None:
        return _kev_cache
    try:
        resp = session.get(Config.CISA_KEV_URL, timeout=Config.HTTP_TIMEOUT)
        resp.raise_for_status()
        _kev_cache = {v["cveID"] for v in resp.json().get("vulnerabilities", [])}
        logger.info(f"[cve] loaded {len(_kev_cache)} CISA KEV entries")
    except Exception as e:
        logger.warning(f"[cve] KEV load failed: {e}")
        _kev_cache = set()
    return _kev_cache


def _epss(cve_ids: List[str]) -> Dict[str, float]:
    if not cve_ids:
        return {}
    try:
        resp = session.get(
            Config.EPSS_URL,
            params={"cve": ",".join(cve_ids)},
            timeout=Config.HTTP_TIMEOUT,
        )
        resp.raise_for_status()
        return {item["cve"]: float(item.get("epss", 0.0)) for item in resp.json().get("data", [])}
    except Exception as e:
        logger.warning(f"[cve] EPSS fetch: {e}")
        return {}


def _nvd(cve_id: str) -> Dict:
    try:
        limiter.wait()
        resp = session.get(Config.NVD_URL, params={"cveId": cve_id}, timeout=Config.HTTP_TIMEOUT)
        resp.raise_for_status()
        items = resp.json().get("vulnerabilities", [])
        if not items:
            return {"cve_id": cve_id}

        cve_data = items[0].get("cve", {})
        metrics  = cve_data.get("metrics", {})
        cvss_score, cvss_vector, cvss_version = 0.0, "", ""

        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if key in metrics:
                m = metrics[key][0]["cvssData"]
                cvss_score   = m.get("baseScore", 0.0)
                cvss_vector  = m.get("vectorString", "")
                cvss_version = key.replace("cvssMetric", "")
                break

        description = next(
            (d["value"] for d in cve_data.get("descriptions", []) if d.get("lang") == "en"), ""
        )
        return {
            "cve_id":       cve_id,
            "description":  description,
            "cvss_score":   cvss_score,
            "cvss_vector":  cvss_vector,
            "cvss_version": cvss_version,
            "published":    cve_data.get("published", ""),
            "modified":     cve_data.get("lastModified", ""),
        }
    except Exception as e:
        logger.warning(f"[cve] NVD {cve_id}: {e}")
        return {"cve_id": cve_id}


def _priority(score: float) -> str:
    if score >= 0.7: return "CRITICAL"
    if score >= 0.5: return "HIGH"
    if score >= 0.3: return "MEDIUM"
    return "LOW"


def prioritize(cve_ids: List[str]) -> List[Dict]:
    cve_ids = list(dict.fromkeys(c.upper() for c in cve_ids if c))
    if not cve_ids:
        return []

    logger.info(f"[cve] prioritizing {len(cve_ids)} CVEs")
    kev          = _kev()
    epss_scores  = _epss(cve_ids)
    results      = []

    for cve_id in cve_ids:
        details   = _nvd(cve_id)
        cvss      = details.get("cvss_score", 0.0)
        epss      = epss_scores.get(cve_id, 0.0)
        in_kev    = cve_id in kev
        composite = round((cvss / 10 * 0.4) + (epss * 0.4) + (0.2 if in_kev else 0), 4)

        results.append({
            **details,
            "epss_score":       round(epss, 4),
            "in_cisa_kev":      in_kev,
            "composite_score":  composite,
            "priority":         _priority(composite),
        })

    results.sort(key=lambda x: x["composite_score"], reverse=True)
    return results
