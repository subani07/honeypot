"""
HoneyShield — main entry point.

Usage:
    python main.py              # Start honeypot + dashboard
    python main.py --stats      # Print summary stats and exit
    python main.py --no-dashboard  # Honeypot only (no web UI)
"""

import warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)

import argparse
import signal
import sys
import threading
import time
import os

# ── Ensure project root on path ───────────────────────────────────────────────
sys.path.insert(0, os.path.dirname(__file__))

import config
from core import manager
from core import logger


def print_banner():
    print("""
  ============================================================
   HoneyShield Honeypot  --  Threat Intelligence Dashboard
  ============================================================
   [SSH]    port 2222    [HTTP]   port 8080
   [FTP]    port 2121    [TELNET] port 2323    [SMTP] port 2525
   Dashboard  -->  http://127.0.0.1:5000
  ============================================================
""")


def print_stats():
    """Print a formatted statistics summary."""
    stats = logger.get_stats()
    print("\n" + "=" * 60)
    print("  HoneyShield — Attack Statistics")
    print("=" * 60)
    print(f"  Total events:       {stats['total_events']:,}")
    print(f"  Unique attackers:   {stats['unique_attackers']:,}")
    print()
    print("  By service:")
    for row in stats.get("by_service", []):
        bar = "#" * min(30, int(30 * row["cnt"] / max(stats["total_events"], 1)))
        print(f"    {row['service'].upper():8}  {row['cnt']:6,}  {bar}")
    print()
    print("  Top 5 attackers:")
    for i, row in enumerate(stats.get("top_ips", [])[:5], 1):
        loc = f"{row.get('flag','')} {row.get('country','?')}"
        print(f"    {i}. {row['src_ip']:16}  {loc:20}  {row['cnt']:,} hits")
    print("=" * 60 + "\n")


def main():
    parser = argparse.ArgumentParser(description="HoneyShield Honeypot")
    parser.add_argument("--stats",        action="store_true", help="Print stats and exit")
    parser.add_argument("--no-dashboard", action="store_true", help="Run without web dashboard")
    args = parser.parse_args()

    if args.stats:
        print_stats()
        return

    print_banner()

    # Start all honeypot services
    manager.start_all()

    if args.no_dashboard:
        print("[Main] Dashboard disabled. Press Ctrl+C to stop.\n")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            pass
    else:
        # Start dashboard in background thread
        from dashboard.app import run as run_dashboard
        dash_thread = threading.Thread(target=run_dashboard, daemon=True)
        dash_thread.start()

        print("[Main] Press Ctrl+C to stop all services.\n")

        def _shutdown(sig, frame):
            print("\n[Main] Shutting down…")
            manager.stop_all()
            sys.exit(0)

        signal.signal(signal.SIGINT,  _shutdown)
        signal.signal(signal.SIGTERM, _shutdown)

        # Block main thread
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            _shutdown(None, None)


if __name__ == "__main__":
    main()
