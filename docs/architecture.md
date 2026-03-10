# Architecture

## Design

No database, no server, no persistent state. Each run is a fresh CLI execution: hit APIs, assemble a result dict, write to disk.

Core constraints:
- **Passive only** — no packets to the target, all data comes from already-indexed sources
- **Modular** — each source is a separate file with one public function, importable standalone
- **Fail gracefully** — a missing key or timeout on one source doesn't abort the scan
- **Rate-limit per API** — each module has its own `RateLimiter`, no global throttle

---

## Data flow

```
CLI input: domain or IP
        │
        ├── dns.py            WHOIS + A/MX/NS/TXT records
        │      └── A records ─────────────────────────────┐
        │                                                  │
        ├── subdomains.py     crt.sh + HackerTarget        │
        │      └── resolved IPs ─────────────────────────┐ │
        │                                                 ▼ ▼
        ├── ip_enrichment.py  IPInfo  ←── ip_list
        │
        ├── certificates.py   crt.sh pivot (domain only)
        │
        ├── shodan.py         Shodan API  ←── ip_list
        │      └── CVE IDs ─────────────────────────────────┐
        │                                                    ▼
        ├── cve.py            NVD + EPSS + CISA KEV  ←── cve_list
        │
        ├── reputation.py     AbuseIPDB  ←── ip_list
        │
        └── leaks.py          GitHub Search API (domain only)
                │
                ▼
        output/html.py  ·  output/json.py
```

IP list is built incrementally: DNS A records first, then subdomain IPs appended. Deduplication happens in `cli.py` before downstream modules.

---

## Module interface

| Module | Function | Input | Output |
|---|---|---|---|
| `dns` | `analyze(target, is_ip)` | str, bool | Dict |
| `subdomains` | `enumerate(domain)` | str | List[Dict] |
| `ip_enrichment` | `enrich(ip_list)` | List[str] | List[Dict] |
| `certificates` | `analyze(domain)` | str | Dict |
| `shodan` | `scan(ip_list)` | List[str] | List[Dict] |
| `cve` | `prioritize(cve_ids)` | List[str] | List[Dict] |
| `reputation` | `check_bulk(ip_list)` | List[str] | List[Dict] |
| `leaks` | `search(domain)` | str | List[Dict] |

---

## HTML report

Self-contained file, no server needed, works offline after D3.js loads from cdnjs.

The infrastructure graph has six node types:

| Node | Color | Content |
|---|---|---|
| `domain` | blue | root target |
| `subdomain` | indigo | enumerated subdomains |
| `ip` | green | resolved IPs |
| `asn` | orange | autonomous systems |
| `cert` | purple | correlated domains from TLS history |
| `cve` | red | CRITICAL/HIGH CVEs only |

Edges: domain → subdomain → ip → asn, domain → cert, ip → cve. Nodes are draggable, zoomable, hover shows details. LOW/MEDIUM CVEs are omitted from the graph but appear in the table.

---

## Utilities

| File | Purpose |
|---|---|
| `http_client.py` | `requests.Session` with retry + shared User-Agent |
| `rate_limiter.py` | Per-instance delay tracking, first call always instant |
| `logger.py` | Logger factory via `__name__`, consistent format |
| `validators.py` | Input normalization and type detection (IP / domain / CVE) |
