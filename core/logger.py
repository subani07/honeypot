"""
Central logger — writes all honeypot events to SQLite.
"""

import sqlite3
import threading
import datetime
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
import config

_lock = threading.Lock()
_conn: sqlite3.Connection | None = None

# ─── Callbacks registered by the dashboard for real-time push ────────────────
_listeners: list = []


def add_listener(fn):
    """Register a callback(event_dict) for live dashboard updates."""
    _listeners.append(fn)


def _get_conn() -> sqlite3.Connection:
    global _conn
    if _conn is None:
        os.makedirs(os.path.dirname(config.DB_PATH), exist_ok=True)
        _conn = sqlite3.connect(config.DB_PATH, check_same_thread=False)
        _conn.row_factory = sqlite3.Row
        _init_db(_conn)
    return _conn


def _init_db(conn: sqlite3.Connection):
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS events (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   TEXT    NOT NULL,
            service     TEXT    NOT NULL,
            src_ip      TEXT    NOT NULL,
            src_port    INTEGER,
            event_type  TEXT    NOT NULL,
            username    TEXT,
            password    TEXT,
            payload     TEXT,
            country     TEXT,
            city        TEXT,
            isp         TEXT,
            lat         REAL,
            lon         REAL,
            flag        TEXT
        );

        CREATE TABLE IF NOT EXISTS geo_cache (
            ip          TEXT PRIMARY KEY,
            country     TEXT,
            country_code TEXT,
            city        TEXT,
            isp         TEXT,
            lat         REAL,
            lon         REAL,
            cached_at   TEXT
        );
    """)
    conn.commit()


def log_event(
    service: str,
    src_ip: str,
    event_type: str,
    src_port: int = None,
    username: str = None,
    password: str = None,
    payload: str = None,
    geo: dict = None,
):
    """Insert one event row and notify dashboard listeners."""
    ts = datetime.datetime.utcnow().isoformat(timespec="seconds") + "Z"

    # Truncate oversized payloads
    if payload and len(payload) > config.MAX_PAYLOAD_SIZE:
        payload = payload[: config.MAX_PAYLOAD_SIZE] + "…[truncated]"

    geo = geo or {}
    country  = geo.get("country", "")
    city     = geo.get("city", "")
    isp      = geo.get("isp", "")
    lat      = geo.get("lat")
    lon      = geo.get("lon")
    flag     = geo.get("flag", "")

    row = dict(
        timestamp=ts, service=service, src_ip=src_ip, src_port=src_port,
        event_type=event_type, username=username, password=password,
        payload=payload, country=country, city=city, isp=isp,
        lat=lat, lon=lon, flag=flag,
    )

    with _lock:
        conn = _get_conn()
        conn.execute("""
            INSERT INTO events
                (timestamp, service, src_ip, src_port, event_type,
                 username, password, payload, country, city, isp, lat, lon, flag)
            VALUES
                (:timestamp, :service, :src_ip, :src_port, :event_type,
                 :username, :password, :payload, :country, :city, :isp, :lat, :lon, :flag)
        """, row)
        conn.commit()

    if config.LOG_TO_CONSOLE:
        flag_str = f" {flag}" if flag else ""
        loc = f"{city}, {country}{flag_str}" if country else src_ip
        cred = f" [{username}/{password}]" if username else ""
        pay = f" payload={payload[:60]!r}" if payload else ""
        print(f"[{ts}] [{service.upper():6}] {event_type:20} {src_ip:15} → {loc}{cred}{pay}")

    # Notify live listeners (dashboard)
    for fn in _listeners:
        try:
            fn(row)
        except Exception:
            pass


# ─── Query helpers for dashboard ─────────────────────────────────────────────

def get_recent_events(limit: int = 50) -> list[dict]:
    with _lock:
        conn = _get_conn()
        rows = conn.execute(
            "SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
    return [dict(r) for r in rows]


def get_stats() -> dict:
    with _lock:
        conn = _get_conn()
        total   = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        unique  = conn.execute("SELECT COUNT(DISTINCT src_ip) FROM events").fetchone()[0]
        by_svc  = conn.execute(
            "SELECT service, COUNT(*) as cnt FROM events GROUP BY service ORDER BY cnt DESC"
        ).fetchall()
        top_ips = conn.execute(
            "SELECT src_ip, country, flag, COUNT(*) as cnt FROM events "
            "GROUP BY src_ip ORDER BY cnt DESC LIMIT 10"
        ).fetchall()
        hourly  = conn.execute(
            "SELECT strftime('%Y-%m-%dT%H:00:00Z', timestamp) as hour, COUNT(*) as cnt "
            "FROM events WHERE timestamp >= datetime('now','-24 hours') "
            "GROUP BY hour ORDER BY hour"
        ).fetchall()

    return {
        "total_events":    total,
        "unique_attackers": unique,
        "by_service":      [dict(r) for r in by_svc],
        "top_ips":         [dict(r) for r in top_ips],
        "hourly":          [dict(r) for r in hourly],
    }


def get_credentials(limit: int = 100) -> list[dict]:
    with _lock:
        conn = _get_conn()
        rows = conn.execute(
            "SELECT timestamp, src_ip, country, flag, username, password "
            "FROM events WHERE username IS NOT NULL "
            "ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
    return [dict(r) for r in rows]


def geo_cache_get(ip: str) -> dict | None:
    with _lock:
        conn = _get_conn()
        row = conn.execute("SELECT * FROM geo_cache WHERE ip = ?", (ip,)).fetchone()
    return dict(row) if row else None


def geo_cache_set(ip: str, data: dict):
    ts = datetime.datetime.utcnow().isoformat(timespec="seconds") + "Z"
    with _lock:
        conn = _get_conn()
        conn.execute("""
            INSERT OR REPLACE INTO geo_cache
                (ip, country, country_code, city, isp, lat, lon, cached_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            ip,
            data.get("country", ""),
            data.get("country_code", ""),
            data.get("city", ""),
            data.get("isp", ""),
            data.get("lat"),
            data.get("lon"),
            ts,
        ))
        conn.commit()
