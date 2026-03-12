import argparse
import os
import sys
from datetime import datetime
from typing import Any, Dict, List

from shadowmap import __version__
from shadowmap.config import Config
from shadowmap.utils.logger import get_logger
from shadowmap.utils.validators import normalize_target

logger = get_logger("shadowmap")


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="shadowmap",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
modules: whois subdomains ip certs shodan cves reputation leaks all

examples:
  shadowmap example.com
  shadowmap example.com --modules whois subdomains certs ip
  shadowmap 203.0.113.42 --modules whois ip shodan reputation cves
  shadowmap example.com --no-shodan --no-leaks --format html
  shadowmap example.com --limit-cves 10
        """,
    )
    p.add_argument("target")
    p.add_argument("--modules", "-m", nargs="+",
        choices=["whois","subdomains","ip","certs","shodan","cves","reputation","leaks","all"],
        default=["all"], metavar="MODULE")
    p.add_argument("--format", "-f", choices=["html","json","both"], default="both")
    p.add_argument("--output", "-o", default=None)
    p.add_argument("--no-shodan", action="store_true")
    p.add_argument("--no-leaks", action="store_true")
    p.add_argument("--limit-cves", type=int, default=None, metavar="N",
        help="process only the top N CVEs by EPSS score (default: all)")
    p.add_argument("--version", "-v", action="version", version=f"ShadowMap {__version__}")
    return p


def _empty(target: str, target_type: str) -> Dict[str, Any]:
    return {
        "meta": {
            "target":      target,
            "target_type": target_type,
            "timestamp":   datetime.now().isoformat(),
            "version":     __version__,
            "modules_run": [],
        },
        "whois_dns":     {},
        "subdomains":    [],
        "ip_enrichment": [],
        "certificates":  {},
        "shodan":        [],
        "cves":          [],
        "reputation":    [],
        "leaks":         [],
    }


def _pipeline(target: str, target_type: str, modules: List[str],
              no_shodan: bool, no_leaks: bool, limit_cves: int = None) -> Dict[str, Any]:
    run_all = "all" in modules
    results = _empty(target, target_type)
    is_ip   = target_type == "ip"
    ip_list: List[str] = []

    def active(name: str) -> bool:
        return run_all or name in modules

    if active("whois"):
        from shadowmap.modules import dns
        results["whois_dns"] = dns.analyze(target, is_ip=is_ip)
        results["meta"]["modules_run"].append("whois")
        if not is_ip:
            ip_list.extend(results["whois_dns"].get("dns_records", {}).get("A", []))

    if not is_ip and active("subdomains"):
        from shadowmap.modules import subdomains
        subs = subdomains.enumerate(target)
        results["subdomains"] = subs
        results["meta"]["modules_run"].append("subdomains")
        ip_list.extend(s["ip"] for s in subs if s.get("ip"))

    target_ips = [target] if is_ip else list(dict.fromkeys(filter(None, ip_list)))

    if active("ip") and target_ips:
        from shadowmap.modules import ip_enrichment
        results["ip_enrichment"] = ip_enrichment.enrich(target_ips)
        results["meta"]["modules_run"].append("ip")

    if not is_ip and active("certs"):
        from shadowmap.modules import certificates
        results["certificates"] = certificates.analyze(target)
        results["meta"]["modules_run"].append("certs")

    cve_ids: List[str] = []
    if not no_shodan and active("shodan") and target_ips:
        from shadowmap.modules import shodan
        shodan_results = shodan.scan(target_ips)
        results["shodan"] = shodan_results
        results["meta"]["modules_run"].append("shodan")
        for h in shodan_results:
            cve_ids.extend(h.get("vulns_from_shodan", []))

    if active("cves") and cve_ids:
        from shadowmap.modules import cve
        if limit_cves:
            epss_map = cve._epss(cve_ids)
            cve_ids  = sorted(set(cve_ids), key=lambda c: epss_map.get(c, 0.0), reverse=True)[:limit_cves]
            logger.info(f"[cve] limited to top {limit_cves} CVEs by EPSS score")
        results["cves"] = cve.prioritize(cve_ids)
        results["meta"]["modules_run"].append("cves")

    if active("reputation") and target_ips:
        from shadowmap.modules import reputation
        results["reputation"] = reputation.check_bulk(target_ips)
        results["meta"]["modules_run"].append("reputation")

    if not no_leaks and not is_ip and active("leaks"):
        from shadowmap.modules import leaks
        results["leaks"] = leaks.search(target)
        results["meta"]["modules_run"].append("leaks")

    return results


def run() -> None:
    args = _parser().parse_args()

    try:
        target, target_type = normalize_target(args.target)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    if args.output:
        Config.OUTPUT_DIR = args.output
    os.makedirs(Config.OUTPUT_DIR, exist_ok=True)

    print(f"\n  ShadowMap {__version__}")
    print(f"  target  : {target} ({target_type})")
    print(f"  modules : {', '.join(args.modules)}")
    print(f"  output  : {Config.OUTPUT_DIR}\n")

    try:
        results = _pipeline(
            target, target_type, args.modules,
            args.no_shodan, args.no_leaks, args.limit_cves,
        )
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        sys.exit(130)
    except Exception as e:
        logger.exception(f"pipeline error: {e}")
        sys.exit(1)

    paths = []
    if args.format in ("json", "both"):
        from shadowmap.output import json as out_json
        paths.append(out_json.save(results, target))
    if args.format in ("html", "both"):
        from shadowmap.output import html as out_html
        paths.append(out_html.save(results, target))

    print("\n  Done.")
    for p in paths:
        print(f"  → {p}")
    print()


if __name__ == "__main__":
    run()
