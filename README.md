# ShadowMap

CLI for passive infrastructure reconnaissance and threat intelligence. Point it at a domain or IP and it pulls subdomains, DNS records, TLS cert history, open ports, CVE scores, IP reputation, and GitHub leaks — all from public sources, nothing sent to the target.

Output is a self-contained HTML report with an interactive infrastructure graph, plus JSON.

![CI](https://github.com/D0m0x61/ShadowMap/actions/workflows/ci.yml/badge.svg)
![Python](https://img.shields.io/badge/python-3.9%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

> This product uses the NVD API but is not endorsed or certified by the NVD.

---

## Modules

| Module | Source | Key |
|---|---|---|
| `whois` | python-whois, dnspython | — |
| `subdomains` | crt.sh, HackerTarget | — |
| `ip` | IPInfo | optional |
| `certs` | crt.sh | — |
| `shodan` | Shodan API + InternetDB fallback | free |
| `cves` | NVD, EPSS, CISA KEV | optional |
| `reputation` | AbuseIPDB | free |
| `leaks` | GitHub Search | optional |

---

## Setup

**Python 3.9+, Git**

```bash
git clone https://github.com/D0m0x61/ShadowMap.git
cd ShadowMap
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt && pip install -e .
cp .env.example .env
```

Edit `.env` and add your API keys. On Windows use `venv\Scripts\activate` and `copy` instead of `cp`.

WSL is recommended on Windows — `wsl --install` in PowerShell as admin, then follow the steps above inside Ubuntu.

---

## API Keys

| Variable | Module | Limit | Get it |
|---|---|---|---|
| `SHODAN_API_KEY` | shodan | 1 req/s | [account.shodan.io](https://account.shodan.io/register) |
| `ABUSEIPDB_API_KEY` | reputation | 1k/day | [abuseipdb.com](https://www.abuseipdb.com/register) |
| `NVD_API_KEY` | cves | 50 req/30s | [nvd.nist.gov](https://nvd.nist.gov/developers/request-an-api-key) |
| `GITHUB_TOKEN` | leaks | 30 req/min | [github.com/settings/tokens](https://github.com/settings/tokens) |
| `IPINFO_TOKEN` | ip | 50k/month | [ipinfo.io](https://ipinfo.io/signup) |

No key needed: crt.sh · HackerTarget · InternetDB · EPSS · CISA KEV

See [docs/api_keys.md](docs/api_keys.md) for step-by-step instructions.

---

## Usage

```bash
source venv/bin/activate

shadowmap example.com
shadowmap example.com --modules whois subdomains certs ip
shadowmap 203.0.113.42 --modules ip shodan reputation cves
shadowmap example.com --no-shodan --no-leaks
shadowmap example.com --limit-cves 10
shadowmap example.com --format json --output ~/Desktop/reports
```

Reports go to `./reports/`. Open with `open reports/*.html` on macOS.

---

## CVE Scoring

Each CVE gets a composite score from three independent sources:

```
score = (CVSS/10 × 0.4) + (EPSS × 0.4) + (0.2 if in CISA KEV)
```

CVSS measures intrinsic severity, EPSS the probability of exploitation in the next 30 days, CISA KEV flags vulnerabilities with confirmed active exploitation in the wild.

`CRITICAL` ≥ 0.7 · `HIGH` ≥ 0.5 · `MEDIUM` ≥ 0.3 · `LOW` < 0.3

---

## Tests

```bash
pytest tests/ -v
```

---

## Legal

Passive only — queries public, already-indexed data. No packets sent to targets. Comply with applicable laws and each provider's ToS.

---

MIT — see [LICENSE](LICENSE).
