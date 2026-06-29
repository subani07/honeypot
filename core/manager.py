"""
Service manager — starts and stops all honeypot services in daemon threads.
"""

import threading
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
import config
from core.services import ssh_honeypot, http_honeypot, ftp_honeypot, telnet_honeypot, smtp_honeypot

_SERVICE_MAP = {
    "ssh":    ssh_honeypot.start,
    "http":   http_honeypot.start,
    "ftp":    ftp_honeypot.start,
    "telnet": telnet_honeypot.start,
    "smtp":   smtp_honeypot.start,
}

_threads:    list[threading.Thread] = []
_stop_event: threading.Event        = threading.Event()


def start_all():
    """Start every enabled service in its own daemon thread."""
    _stop_event.clear()
    for name, fn in _SERVICE_MAP.items():
        if config.SERVICES.get(name, {}).get("enabled", False):
            t = threading.Thread(
                target=fn,
                args=(_stop_event,),
                name=f"honeypot-{name}",
                daemon=True,
            )
            t.start()
            _threads.append(t)
    print(f"[Manager] {len(_threads)} service(s) started.")


def stop_all():
    """Signal all services to stop and wait for clean shutdown."""
    print("[Manager] Stopping services…")
    _stop_event.set()
    for t in _threads:
        t.join(timeout=3)
    _threads.clear()
    print("[Manager] All services stopped.")
