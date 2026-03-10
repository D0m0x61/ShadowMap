# API Keys

The WHOIS, DNS, subdomain, certificate, and CVE modules use public APIs with no registration required. The four keys below unlock the remaining modules.

---

## Shodan

**Module:** `shodan` · **Free limit:** 1 req/sec

1. Register at https://account.shodan.io/register
2. Go to **My Account** → copy the API key
3. Add to `.env`:
   ```
   SHODAN_API_KEY=your_key_here
   ```

---

## AbuseIPDB

**Module:** `reputation` · **Free limit:** 1,000 checks/day

1. Register at https://www.abuseipdb.com/register
2. Confirm email
3. Go to **Account** → **API** → **Create Key**
4. Add to `.env`:
   ```
   ABUSEIPDB_API_KEY=your_key_here
   ```

---

## GitHub Token

**Module:** `leaks` · **Free limit:** 30 req/min (10 without token)

No scopes needed — public code search works without any permissions.

1. Go to https://github.com/settings/tokens
2. **Generate new token (classic)** — leave all scopes unchecked
3. Copy immediately, GitHub only shows it once
4. Add to `.env`:
   ```
   GITHUB_TOKEN=your_token_here
   ```

---

## IPInfo

**Module:** `ip` · **Free limit:** 50,000 req/month · **Optional**

If skipped, geolocation fields are empty but ASN data still comes from IPInfo's free tier (no token required for basic lookups).

1. Register at https://ipinfo.io/signup
2. Copy the token from the dashboard
3. Add to `.env`:
   ```
   IPINFO_TOKEN=your_token_here
   ```

---

## No-key APIs

| API | Module | URL |
|---|---|---|
| crt.sh | `subdomains`, `certs` | https://crt.sh |
| HackerTarget | `subdomains` | https://api.hackertarget.com |
| NVD (NIST) | `cves` | https://services.nvd.nist.gov |
| EPSS (FIRST.org) | `cves` | https://api.first.org |
| CISA KEV | `cves` | https://www.cisa.gov |
