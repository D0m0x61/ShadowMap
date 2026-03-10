import socket
from typing import Any, Dict, List

try:
    import whois as python_whois
except ImportError:
    python_whois = None

try:
    import dns.resolver
    import dns.exception
except ImportError:
    dns = None

from shadowmap.utils.logger import get_logger

logger = get_logger(__name__)

_DNS_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]


def get_whois(target: str) -> Dict[str, Any]:
    if python_whois is None:
        return {"error": "python-whois not installed"}
    try:
        w = python_whois.whois(target)
        return {
            "domain_name":     _scalar(w.domain_name),
            "registrar":       _scalar(w.registrar),
            "creation_date":   _date(w.creation_date),
            "expiration_date": _date(w.expiration_date),
            "updated_date":    _date(w.updated_date),
            "name_servers":    _list(w.name_servers),
            "emails":          _list(w.emails),
            "status":          _list(w.status),
            "country":         _scalar(w.country),
            "org":             _scalar(w.org),
        }
    except Exception as e:
        logger.warning(f"[whois] {target}: {e}")
        return {"error": str(e)}


def get_dns_records(domain: str) -> Dict[str, List[str]]:
    if dns is None:
        return {"error": "dnspython not installed"}
    resolver = dns.resolver.Resolver()
    resolver.timeout = 5
    resolver.lifetime = 10
    records: Dict[str, List[str]] = {}
    for rtype in _DNS_TYPES:
        try:
            answers = resolver.resolve(domain, rtype)
            records[rtype] = [_rdata_str(rtype, r) for r in answers]
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            records[rtype] = []
        except dns.exception.Timeout:
            records[rtype] = []
        except Exception as e:
            logger.warning(f"[dns] {rtype} {domain}: {e}")
            records[rtype] = []
    return records


def get_reverse_dns(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror):
        return ""


def analyze(target: str, is_ip: bool = False) -> Dict[str, Any]:
    result: Dict[str, Any] = {"whois": get_whois(target)}
    if is_ip:
        result["reverse_dns"] = get_reverse_dns(target)
    else:
        result["dns_records"] = get_dns_records(target)
    return result


def _scalar(v: Any) -> str:
    if isinstance(v, list):
        return str(v[0]) if v else ""
    return str(v) if v else ""


def _list(v: Any) -> List[str]:
    if isinstance(v, list):
        return [str(x).lower() for x in v if x]
    return [str(v).lower()] if v else []


def _date(v: Any) -> str:
    if isinstance(v, list):
        v = v[0] if v else None
    if v is None:
        return ""
    try:
        return v.isoformat()
    except AttributeError:
        return str(v)


def _rdata_str(rtype: str, rdata: Any) -> str:
    if rtype == "MX":
        return f"{rdata.preference} {rdata.exchange}"
    if rtype == "SOA":
        return f"mname={rdata.mname} rname={rdata.rname} serial={rdata.serial}"
    return rdata.to_text()
