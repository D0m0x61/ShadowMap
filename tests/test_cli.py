import pytest
from unittest.mock import patch


def test_version_exits_zero():
    from shadowmap.cli import _parser
    with pytest.raises(SystemExit) as exc:
        _parser().parse_args(["--version"])
    assert exc.value.code == 0


def test_invalid_target_exits_one():
    from shadowmap.cli import run
    with patch("sys.argv", ["shadowmap", "NOT_VALID!!!"]):
        with pytest.raises(SystemExit) as exc:
            run()
    assert exc.value.code == 1


def test_empty_results_keys():
    from shadowmap.cli import _empty
    r = _empty("example.com", "domain")
    expected = {"meta", "whois_dns", "subdomains", "ip_enrichment",
                "certificates", "shodan", "cves", "reputation", "leaks"}
    assert set(r.keys()) == expected
    assert r["meta"]["target"] == "example.com"
