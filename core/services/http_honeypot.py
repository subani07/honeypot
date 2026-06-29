"""
Fake HTTP honeypot — emulates Apache/2.4.49.
Detects path traversal, SQLi, scanners, and common attack probes.
"""

import socket
import threading
import os
import sys
import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
import config
from core import logger
from core.threat_intel import get_geo, classify_attack

# ── Fake HTTP response templates ──────────────────────────────────────────────
_SERVER_HEADER = "Apache/2.4.49 (Unix)"

_404_BODY = """\
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head><title>404 Not Found</title></head>
<body><h1>Not Found</h1>
<p>The requested URL was not found on this server.</p>
<hr><address>Apache/2.4.49 (Unix) Server at example.com Port 80</address>
</body></html>"""

_200_INDEX = """\
<!DOCTYPE html><html><head><title>Apache2 Ubuntu Default Page</title></head>
<body><h1>Apache2 Ubuntu Default Page</h1><p>It works!</p></body></html>"""

_401_BODY = """\
<!DOCTYPE HTML><html><head><title>401 Unauthorized</title></head>
<body><h1>Unauthorized</h1><p>This server could not verify that you are
authorized to access the document requested.</p></body></html>"""


def _make_response(code: int, body: str, extra_headers: str = "") -> bytes:
    reason = {200: "OK", 401: "Unauthorized", 404: "Not Found", 500: "Internal Server Error"}.get(code, "OK")
    now    = datetime.datetime.utcnow().strftime("%a, %d %b %Y %H:%M:%S GMT")
    resp   = (
        f"HTTP/1.1 {code} {reason}\r\n"
        f"Date: {now}\r\n"
        f"Server: {_SERVER_HEADER}\r\n"
        f"Content-Type: text/html; charset=utf-8\r\n"
        f"Content-Length: {len(body.encode())}\r\n"
        f"Connection: close\r\n"
        f"{extra_headers}"
        f"\r\n"
        f"{body}"
    )
    return resp.encode("utf-8", "replace")


# ── Sensitive path patterns that draw attackers ───────────────────────────────
_SENSITIVE = {
    "/admin", "/wp-admin", "/phpmyadmin", "/manager", "/console",
    "/.env", "/config", "/backup", "/.git", "/shell", "/cmd",
    "/wp-login.php", "/xmlrpc.php", "/.aws/credentials",
}


def _classify_request(method: str, path: str, headers: str, body: str) -> str:
    combined = f"{method} {path} {headers} {body}"
    return classify_attack("http_request", payload=combined)


def _handle_client(sock: socket.socket, addr):
    client_ip, client_port = addr[0], addr[1]
    geo = get_geo(client_ip)

    try:
        sock.settimeout(10)
        raw = b""
        while b"\r\n\r\n" not in raw:
            chunk = sock.recv(4096)
            if not chunk:
                break
            raw += chunk

        if not raw:
            return

        text     = raw.decode("utf-8", "replace")
        lines    = text.split("\r\n")
        req_line = lines[0] if lines else ""
        parts    = req_line.split(" ")
        method   = parts[0] if len(parts) > 0 else "?"
        path     = parts[1] if len(parts) > 1 else "/"
        headers  = "\r\n".join(lines[1:])

        # Read body if Content-Length present
        body = ""
        if "\r\n\r\n" in text:
            body = text.split("\r\n\r\n", 1)[1]

        attack_type = _classify_request(method, path, headers, body)

        logger.log_event(
            service="http",
            src_ip=client_ip,
            src_port=client_port,
            event_type=f"http_{attack_type}",
            payload=f"{method} {path}\n{headers[:500]}",
            geo=geo,
        )

        # Serve realistic responses based on path
        path_lower = path.lower().split("?")[0]
        if path_lower in ("/", "/index.html"):
            sock.sendall(_make_response(200, _200_INDEX))
        elif any(path_lower.startswith(s) for s in _SENSITIVE):
            sock.sendall(_make_response(401, _401_BODY, "WWW-Authenticate: Basic realm=\"Secure Area\"\r\n"))
        else:
            sock.sendall(_make_response(404, _404_BODY))

    except Exception:
        pass
    finally:
        try:
            sock.close()
        except Exception:
            pass


def start(stop_event: threading.Event):
    port = config.SERVICES["http"]["port"]
    srv  = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", port))
    srv.listen(100)
    srv.settimeout(1.0)
    print(f"[HTTP  ] Listening on port {port}")

    while not stop_event.is_set():
        try:
            sock, addr = srv.accept()
            t = threading.Thread(target=_handle_client, args=(sock, addr), daemon=True)
            t.start()
        except socket.timeout:
            continue
        except Exception as e:
            if not stop_event.is_set():
                print(f"[HTTP] Error: {e}")

    srv.close()
    print("[HTTP  ] Stopped.")
