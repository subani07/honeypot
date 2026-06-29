"""
Central configuration for the Honeypot system.
Edit this file to change ports, banners, and API keys.
"""

# ── Database ─────────────────────────────────────────────────────────────────
DB_PATH = "data/honeypot.db"
MALWARE_DIR = "data/malware"

# ── Dashboard ─────────────────────────────────────────────────────────────────
DASHBOARD_HOST = "0.0.0.0"
DASHBOARD_PORT = 5000
SECRET_KEY = "honeypot-secret-2024"

# ── Service Ports (non-privileged, no admin needed) ──────────────────────────
SERVICES = {
    "ssh":    {"port": 2222,  "enabled": True},
    "http":   {"port": 8080,  "enabled": True},
    "ftp":    {"port": 2121,  "enabled": True},
    "telnet": {"port": 2323,  "enabled": True},
    "smtp":   {"port": 2525,  "enabled": True},
}

# ── Fake Service Banners ──────────────────────────────────────────────────────
BANNERS = {
    "ssh":    "SSH-2.0-OpenSSH_7.4",
    "ftp":    "220 (vsFTPd 2.3.4)",
    "telnet": "\r\nUbuntu 18.04.6 LTS\r\n\r\nlogin: ",
    "smtp":   "220 mail.example.com ESMTP Postfix",
}

# ── Threat Intelligence ───────────────────────────────────────────────────────
# Free GeoIP — no key needed
GEOIP_API = "http://ip-api.com/json/{ip}?fields=status,country,countryCode,city,isp,org,as,query"

# Optional: AbuseIPDB key for IP reputation (leave empty to skip)
ABUSEIPDB_KEY = ""

# ── Logging ───────────────────────────────────────────────────────────────────
LOG_TO_CONSOLE = True
MAX_PAYLOAD_SIZE = 4096   # bytes — cap captured payload size
