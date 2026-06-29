"""
Threat intelligence — GeoIP lookup, IP reputation, attack classification.
"""

import re
import os
import sys
import requests

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
import config
from core import logger

# ── Country flag emoji helper ─────────────────────────────────────────────────
def _flag(code: str) -> str:
    if not code or len(code) != 2:
        return "🌐"
    return chr(0x1F1E6 + ord(code[0].upper()) - 65) + chr(0x1F1E6 + ord(code[1].upper()) - 65)


# ── GeoIP lookup (with DB caching) ───────────────────────────────────────────
def get_geo(ip: str) -> dict:
    """Return geo info for an IP. Caches results in SQLite."""
    # Skip private/loopback addresses
    if ip.startswith(("127.", "10.", "192.168.", "172.")) or ip == "::1":
        return {"country": "Local", "city": "localhost", "isp": "", "lat": None, "lon": None, "flag": "🏠"}

    cached = logger.geo_cache_get(ip)
    if cached:
        cached["flag"] = _flag(cached.get("country_code", ""))
        return cached

    try:
        url = config.GEOIP_API.format(ip=ip)
        r = requests.get(url, timeout=4)
        data = r.json()
        if data.get("status") == "success":
            result = {
                "country":      data.get("country", ""),
                "country_code": data.get("countryCode", ""),
                "city":         data.get("city", ""),
                "isp":          data.get("isp", data.get("org", "")),
                "lat":          data.get("lat"),
                "lon":          data.get("lon"),
                "flag":         _flag(data.get("countryCode", "")),
            }
            logger.geo_cache_set(ip, result)
            return result
    except Exception:
        pass

    return {"country": "", "city": "", "isp": "", "lat": None, "lon": None, "flag": "🌐"}


# ── Attack pattern classifier ─────────────────────────────────────────────────
SCANNER_UA = re.compile(
    r"(nmap|masscan|zgrab|shodan|censys|python-requests|go-http|curl|wget|nikto|sqlmap)",
    re.IGNORECASE,
)

EXPLOIT_PATTERNS = [
    re.compile(r"(\.\./){2,}"),                       # Path traversal
    re.compile(r"(union.*select|select.*from)", re.I), # SQLi
    re.compile(r"<script.*?>", re.I),                  # XSS
    re.compile(r"(\$\{|#\{|%\{)"),                    # Template injection
    re.compile(r"(;|\||\|\||&&)\s*(id|whoami|uname|cat /etc/passwd)", re.I),  # RCE
    re.compile(r"(cmd\.exe|powershell|/bin/sh|/bin/bash)", re.I),
    re.compile(r"base64_decode|eval\(|exec\(", re.I),
]

BRUTE_FORCE_USERS = {
    "root", "admin", "administrator", "user", "test", "guest",
    "ubuntu", "pi", "oracle", "postgres", "mysql", "jenkins",
}


def classify_attack(event_type: str, username: str = "", payload: str = "") -> str:
    """Return a human-readable attack category."""
    payload = payload or ""
    username = (username or "").lower()

    if event_type in ("ssh_login_attempt", "ftp_login_attempt", "telnet_login"):
        if username in BRUTE_FORCE_USERS:
            return "brute_force"
        return "credential_spray"

    if event_type == "http_request":
        if SCANNER_UA.search(payload):
            return "scanner"
        for pat in EXPLOIT_PATTERNS:
            if pat.search(payload):
                return "exploit_attempt"
        return "probe"

    if event_type == "smtp_relay_attempt":
        return "spam_relay"

    return "unknown"


def classify_payload(payload: str) -> dict:
    """Analyse a raw payload and return detected threat indicators."""
    if not payload:
        return {}
    indicators = []
    for pat in EXPLOIT_PATTERNS:
        if pat.search(payload):
            indicators.append(pat.pattern)
    is_binary = any(c < 32 and c not in (9, 10, 13) for c in payload.encode("utf-8", "replace"))
    return {
        "indicators": indicators,
        "is_binary":  is_binary,
        "length":     len(payload),
    }
