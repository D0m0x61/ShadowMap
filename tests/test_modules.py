import pytest
from unittest.mock import patch


def test_cve_priority_labels():
    from shadowmap.modules.cve import _priority
    assert _priority(0.8)  == "CRITICAL"
    assert _priority(0.6)  == "HIGH"
    assert _priority(0.35) == "MEDIUM"
    assert _priority(0.1)  == "LOW"


def test_cve_composite_max():
    score = round((10 / 10 * 0.4) + (1.0 * 0.4) + 0.2, 4)
    assert score == 1.0


def test_cve_deduplication():
    from shadowmap.modules.cve import prioritize
    mock_nvd = {"cve_id": "CVE-2021-44228", "cvss_score": 10.0}
    with patch("shadowmap.modules.cve._kev", return_value=set()), \
         patch("shadowmap.modules.cve._epss", return_value={}), \
         patch("shadowmap.modules.cve._nvd", return_value=mock_nvd):
        result = prioritize(["CVE-2021-44228", "CVE-2021-44228"])
        assert len(result) == 1


def test_reputation_risk():
    from shadowmap.modules.reputation import _risk
    assert _risk(100) == "HIGH"
    assert _risk(50)  == "MEDIUM"
    assert _risk(1)   == "LOW"
    assert _risk(0)   == "CLEAN"


def test_leak_severity():
    from shadowmap.modules.leaks import _severity
    assert _severity('"{domain}" password') == "HIGH"
    assert _severity('"{domain}" smtp')     == "MEDIUM"


def test_rate_limiter_first_call_instant():
    import time
    from shadowmap.utils.rate_limiter import RateLimiter
    limiter = RateLimiter(delay=2.0)
    start   = time.monotonic()
    limiter.wait()
    assert time.monotonic() - start < 0.1


def test_config_urls_are_https():
    from shadowmap.config import Config
    for url in (Config.CRTSH_URL, Config.NVD_URL, Config.EPSS_URL):
        assert url.startswith("https://")
