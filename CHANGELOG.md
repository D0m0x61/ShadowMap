# Changelog

## [1.0.2] — 2026-03-10

### Fixed

- `cves`: NVD API key support — 50 req/30s vs 5 req/10s unauthenticated; automatic 429 retry

## [1.0.1] — 2026-03-10

### Fixed

- `shodan`: automatic fallback to InternetDB when API returns 403. Returns ports, CVEs, and tags without requiring a paid Shodan plan.
- `dns`: WHOIS warning truncated to first line, removing VeriSign boilerplate

## [1.0.0] — 2026-03-10

### Modules

- `dns` — WHOIS + DNS records (A, AAAA, MX, NS, TXT, CNAME, SOA)
- `subdomains` — passive enumeration via crt.sh and HackerTarget
- `ip_enrichment` — geolocation and ASN via IPInfo
- `certificates` — TLS cert history and correlated domain pivot via crt.sh
- `shodan` — open ports, banners, CVEs from Shodan API
- `cve` — composite scoring: CVSS (NVD) + EPSS (FIRST.org) + CISA KEV
- `reputation` — abuse confidence score and TOR node detection via AbuseIPDB
- `leaks` — credential and secret leak search via GitHub Search API

### CLI

- `shadowmap <target>` entry point + `python -m shadowmap` alias
- `--modules` to run a subset
- `--no-shodan` and `--no-leaks` for keyless runs
- `--format html|json|both` and `--output <dir>`

### Output

- Dark-theme HTML report with D3.js infrastructure graph (domain → subdomains → IPs → ASNs → certs → CVEs)
- JSON report with the same data structure

### Utilities

- Shared HTTP session with retry and exponential backoff
- Per-API rate limiter (first call always instant)
- Logger factory using `__name__` for per-module filtering
- Input normalizer: handles raw URLs, bare domains, IPs
