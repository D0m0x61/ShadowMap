# ShadowMap

Passive infrastructure mapping and threat intelligence CLI. Given a domain or IP, maps subdomains, DNS records, TLS certificate history, open ports via Shodan, scores CVEs using CVSS + EPSS + CISA KEV, checks IP reputation, and searches for credential leaks in public repos — without sending a packet to the target.

The HTML report includes an interactive D3.js graph of the infrastructure.

![CI](https://github.com/D0m0x61/ShadowMap/actions/workflows/ci.yml/badge.svg)
![Python](https://img.shields.io/badge/python-3.9%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

---

## Modules

| Module | Data source | API key |
|---|---|---|
| `whois` | python-whois, dnspython | — |
| `subdomains` | crt.sh, HackerTarget | — |
| `ip` | IPInfo | optional |
| `certs` | crt.sh | — |
| `shodan` | Shodan API | free |
| `cves` | NVD, FIRST.org, CISA KEV | — |
| `reputation` | AbuseIPDB | free |
| `leaks` | GitHub Search API | optional |

---

## Installation

**Requirements:** Python 3.9+, Git

### macOS

```bash
brew install python git
git clone https://github.com/D0m0x61/ShadowMap.git
cd ShadowMap
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt && pip install -e .
cp .env.example .env && nano .env
```

### Linux (Debian / Ubuntu)

```bash
sudo apt install python3 python3-pip python3-venv git -y
git clone https://github.com/D0m0x61/ShadowMap.git
cd ShadowMap
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt && pip install -e .
cp .env.example .env && nano .env
```

### Windows — WSL (recommended)

```powershell
wsl --install
```

Restart, open the Ubuntu app, then follow the Linux instructions above.

### Windows — Native

1. Install Python from https://www.python.org/downloads/ — check **Add Python to PATH**
2. Install Git from https://git-scm.com/download/win

```powershell
git clone https://github.com/D0m0x61/ShadowMap.git
cd ShadowMap
python -m venv venv && venv\Scripts\activate
pip install -r requirements.txt && pip install -e .
copy .env.example .env && notepad .env
```

---

## API Keys

| Variable | Module | Free limit | Registration |
|---|---|---|---|
| `SHODAN_API_KEY` | shodan | 1 req/sec | [account.shodan.io](https://account.shodan.io/register) |
| `ABUSEIPDB_API_KEY` | reputation | 1,000/day | [abuseipdb.com](https://www.abuseipdb.com/register) |
| `GITHUB_TOKEN` | leaks | 30 req/min | [github.com/settings/tokens](https://github.com/settings/tokens) |
| `IPINFO_TOKEN` | ip | 50k/month | [ipinfo.io](https://ipinfo.io/signup) |

No key required: crt.sh · HackerTarget · NVD · EPSS · CISA KEV

Full setup instructions: [docs/api_keys.md](docs/api_keys.md)

---

## Usage

```bash
source venv/bin/activate       # macOS/Linux
venv\Scripts\activate          # Windows

shadowmap example.com
shadowmap example.com --modules whois subdomains certs ip
shadowmap 203.0.113.42 --modules whois ip shodan reputation cves
shadowmap example.com --no-shodan --no-leaks
shadowmap example.com --format json --output ~/Desktop/reports
shadowmap --help
```

Reports are saved to `./reports/` by default. Open the HTML with `open reports/*.html` on macOS.

---

## CVE Scoring

```
score = (CVSS/10 × 0.4) + (EPSS × 0.4) + (0.2 if in CISA KEV)
```

- **CVSS** (NVD) — base severity
- **EPSS** (FIRST.org) — exploitation probability in the next 30 days
- **CISA KEV** — confirmed active exploitation

Thresholds: `CRITICAL` ≥ 0.7 · `HIGH` ≥ 0.5 · `MEDIUM` ≥ 0.3 · `LOW` < 0.3

---

## Structure

```
shadowmap/
├── modules/
│   ├── dns.py
│   ├── subdomains.py
│   ├── ip_enrichment.py
│   ├── certificates.py
│   ├── shodan.py
│   ├── cve.py
│   ├── reputation.py
│   └── leaks.py
├── output/
│   ├── html.py
│   └── json.py
└── utils/
    ├── http_client.py
    ├── rate_limiter.py
    ├── logger.py
    └── validators.py
```

---

## Tests

```bash
pytest tests/ -v
```

---

## Legal

Queries public, already-indexed data only. No packets are sent to target systems. You are responsible for compliance with applicable laws and each API provider's terms of service.

---

## License

MIT — see [LICENSE](LICENSE).
