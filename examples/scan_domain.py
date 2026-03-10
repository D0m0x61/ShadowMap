from shadowmap.modules import dns, subdomains, certificates, ip_enrichment, cve
from shadowmap.output import html, json
from datetime import datetime

TARGET = "example.com"

wdns  = dns.analyze(TARGET)
subs  = subdomains.enumerate(TARGET)
ips   = ip_enrichment.enrich([s["ip"] for s in subs if s.get("ip")])
certs = certificates.analyze(TARGET)
cves  = cve.prioritize(["CVE-2021-44228", "CVE-2023-23397", "CVE-2022-30190"])

results = {
    "meta": {
        "target": TARGET, "target_type": "domain",
        "timestamp": datetime.now().isoformat(),
        "modules_run": ["whois", "subdomains", "ip", "certs", "cves"],
    },
    "whois_dns": wdns, "subdomains": subs, "ip_enrichment": ips,
    "certificates": certs, "shodan": [], "cves": cves,
    "reputation": [], "leaks": [],
}

print(json.save(results, TARGET))
print(html.save(results, TARGET))
