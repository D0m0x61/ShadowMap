from shadowmap.modules.cve import prioritize

CVE_LIST = [
    "CVE-2021-44228",  # Log4Shell
    "CVE-2022-30190",  # Follina
    "CVE-2023-23397",  # Outlook NTLM relay
    "CVE-2021-34527",  # PrintNightmare
    "CVE-2020-1472",   # Zerologon
]

for c in prioritize(CVE_LIST):
    kev = " [KEV]" if c.get("in_cisa_kev") else ""
    print(f"{c['cve_id']}  {c['priority']}{kev}  cvss={c.get('cvss_score')}  epss={c.get('epss_score')}  score={c['composite_score']}")
