import pytest
from shadowmap.utils.validators import is_ip, is_domain, is_cve, normalize_target


def test_is_ip():
    assert is_ip("192.168.1.1")
    assert is_ip("8.8.8.8")
    assert not is_ip("256.1.1.1")
    assert not is_ip("example.com")
    assert not is_ip("")


def test_is_domain():
    assert is_domain("example.com")
    assert is_domain("sub.example.com")
    assert not is_domain("192.168.1.1")
    assert not is_domain("not_valid")


def test_is_cve():
    assert is_cve("CVE-2021-44228")
    assert is_cve("cve-2021-44228")
    assert not is_cve("NOT-A-CVE")


def test_normalize_strips_scheme():
    target, kind = normalize_target("https://example.com/")
    assert target == "example.com"
    assert kind == "domain"


def test_normalize_ip():
    target, kind = normalize_target("8.8.8.8")
    assert kind == "ip"


def test_normalize_invalid():
    with pytest.raises(ValueError):
        normalize_target("not valid!!!")
