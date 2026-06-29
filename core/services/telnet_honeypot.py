"""
Fake Telnet honeypot — simulates an Ubuntu 18.04 login prompt.
Great at catching IoT botnets (Mirai variants).
"""

import socket
import threading
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
import config
from core import logger
from core.threat_intel import get_geo

# Telnet negotiation bytes — suppress go-ahead, echo, etc.
_TELNET_OPTS = bytes([
    255, 251, 1,   # IAC WILL ECHO
    255, 251, 3,   # IAC WILL SGA
    255, 253, 24,  # IAC DO TERM-TYPE
])

_MOTD = (
    "\r\n"
    "Ubuntu 18.04.6 LTS\r\n"
    "Kernel 4.15.0-213-generic\r\n"
    "\r\n"
)


def _send(sock: socket.socket, msg: str):
    sock.sendall(msg.encode("utf-8", "replace"))


def _recv_line(sock: socket.socket) -> str:
    buf = b""
    while True:
        ch = sock.recv(1)
        if not ch or ch == b"\n":
            break
        if ch[0] == 255:          # strip Telnet IAC sequences
            sock.recv(2)
            continue
        if ch != b"\r":
            buf += ch
    return buf.decode("utf-8", "replace").strip()


def _handle_client(sock: socket.socket, addr):
    client_ip, client_port = addr[0], addr[1]
    geo = get_geo(client_ip)

    logger.log_event(
        service="telnet",
        src_ip=client_ip,
        src_port=client_port,
        event_type="telnet_connect",
        geo=geo,
    )

    try:
        sock.settimeout(30)
        sock.sendall(_TELNET_OPTS)
        _send(sock, _MOTD)

        # ── Username prompt ───────────────────────────────────────────────────
        _send(sock, config.BANNERS["telnet"])
        username = _recv_line(sock)

        # ── Password prompt ───────────────────────────────────────────────────
        _send(sock, "Password: ")
        password = _recv_line(sock)

        logger.log_event(
            service="telnet",
            src_ip=client_ip,
            src_port=client_port,
            event_type="telnet_login",
            username=username,
            password=password,
            geo=geo,
        )

        # Fake failure
        _send(sock, "\r\nLogin incorrect\r\n\r\n")

    except Exception:
        pass
    finally:
        try:
            sock.close()
        except Exception:
            pass


def start(stop_event: threading.Event):
    port = config.SERVICES["telnet"]["port"]
    srv  = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", port))
    srv.listen(50)
    srv.settimeout(1.0)
    print(f"[TELNET] Listening on port {port}")

    while not stop_event.is_set():
        try:
            sock, addr = srv.accept()
            t = threading.Thread(target=_handle_client, args=(sock, addr), daemon=True)
            t.start()
        except socket.timeout:
            continue
        except Exception as e:
            if not stop_event.is_set():
                print(f"[TELNET] Error: {e}")

    srv.close()
    print("[TELNET] Stopped.")
