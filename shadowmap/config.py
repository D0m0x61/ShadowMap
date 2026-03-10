import os
from dotenv import load_dotenv

load_dotenv()


class Config:
    SHODAN_API_KEY: str     = os.getenv("SHODAN_API_KEY", "")
    GITHUB_TOKEN: str       = os.getenv("GITHUB_TOKEN", "")
    ABUSEIPDB_API_KEY: str  = os.getenv("ABUSEIPDB_API_KEY", "")
    IPINFO_TOKEN: str       = os.getenv("IPINFO_TOKEN", "")
    NVD_API_KEY: str        = os.getenv("NVD_API_KEY", "")

    CRTSH_URL: str          = "https://crt.sh"
    NVD_URL: str            = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    EPSS_URL: str           = "https://api.first.org/data/v1/epss"
    CISA_KEV_URL: str       = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    HACKERTARGET_URL: str   = "https://api.hackertarget.com"
    IPINFO_URL: str         = "https://ipinfo.io"
    ABUSEIPDB_URL: str      = "https://api.abuseipdb.com/api/v2"

    DELAY_DEFAULT: float    = 1.0
    DELAY_SHODAN: float     = 1.0
    DELAY_GITHUB: float     = 2.0
    DELAY_NVD: float        = 0.6   # with API key: 50 req/30s
    DELAY_NVD_UNAUTH: float = 2.0   # without API key: 5 req/10s
    DELAY_ABUSEIPDB: float  = 1.0
    DELAY_CRTSH: float      = 1.5

    HTTP_TIMEOUT: int       = 15
    HTTP_RETRIES: int       = 3
    HTTP_BACKOFF: float     = 1.0
    USER_AGENT: str         = "ShadowMap/1.0"

    OUTPUT_DIR: str         = os.getenv("OUTPUT_DIR", "./reports")
    LOG_LEVEL: str          = os.getenv("LOG_LEVEL", "INFO")

    GITHUB_DORKS: list = [
        '"{domain}" password',
        '"{domain}" api_key',
        '"{domain}" secret',
        '"{domain}" token',
        '"{domain}" credentials',
        '"{domain}" db_password',
        '"{domain}" smtp',
        '"{domain}" private_key',
    ]
