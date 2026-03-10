import time
from typing import Dict, List, Set

from shadowmap.config import Config
from shadowmap.utils.http_client import get_session
from shadowmap.utils.rate_limiter import RateLimiter
from shadowmap.utils.logger import get_logger

logger  = get_logger(__name__)
session = get_session()
limiter = RateLimiter(Config.DELAY_GITHUB)

_SEARCH_URL   = "https://api.github.com/search/code"
_PER_DORK     = 5
_HIGH_WORDS   = {"password", "secret", "token", "credentials", "db_password", "private_key"}


def _severity(dork: str) -> str:
    return "HIGH" if any(w in dork for w in _HIGH_WORDS) else "MEDIUM"


def search(domain: str) -> List[Dict]:
    headers: Dict[str, str] = {"Accept": "application/vnd.github+json"}
    if Config.GITHUB_TOKEN:
        headers["Authorization"] = f"Bearer {Config.GITHUB_TOKEN}"
    else:
        logger.warning("[leaks] GITHUB_TOKEN not set — rate limit is 10 req/min")

    findings: List[Dict] = []
    seen: Set[str]       = set()

    for dork_template in Config.GITHUB_DORKS:
        query = dork_template.format(domain=domain)
        try:
            limiter.wait()
            resp = session.get(
                _SEARCH_URL,
                headers=headers,
                params={"q": query, "per_page": _PER_DORK},
                timeout=Config.HTTP_TIMEOUT,
            )
            if resp.status_code == 403:
                wait = max(int(resp.headers.get("X-RateLimit-Reset", 0)) - int(time.time()), 10)
                logger.warning(f"[leaks] rate limit hit, waiting {wait}s")
                time.sleep(wait)
                continue
            if resp.status_code == 422:
                continue
            resp.raise_for_status()

            for item in resp.json().get("items", []):
                url = item.get("html_url", "")
                if url in seen:
                    continue
                seen.add(url)
                repo = item.get("repository", {})
                findings.append({
                    "query":    query,
                    "repo":     repo.get("full_name", ""),
                    "repo_url": repo.get("html_url", ""),
                    "file":     item.get("name", ""),
                    "path":     item.get("path", ""),
                    "url":      url,
                    "severity": _severity(dork_template),
                })
        except Exception as e:
            logger.warning(f"[leaks] '{query}': {e}")

    logger.info(f"[leaks] {len(findings)} findings for {domain}")
    return findings
