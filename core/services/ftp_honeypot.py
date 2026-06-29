"""
Fake FTP honeypot — emulates vsFTPd 2.3.4 (notorious backdoor version).
Captures all login attempts.
"""

import socket
import threading
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
import config
from core import logger
from core.threat_intel import get_geo

_FAKE_FILES = [
    "drwxr-xr-x    2 0        0            4096 Jan 01 00:00 pub",
    "-rw-r--r--    1 0        0           12345 Jan 01 00:00 readme.txt",
    "-rw-r--r--    1 0        0          102400 Jan 01 00:00 backup.tar.gz",
]


def _send(sock: socket.socket, msg: str):
    sock.sendall((msg + "\r\n").encode())


def _handle_client(sock: socket.socket, addr):
    client_ip, client_port = addr[0], addr[1]
    geo = get_geo(client_ip)

    logger.log_event(
        service="ftp",
        src_ip=client_ip,
        src_port=client_port,
        event_type="ftp_connect",
        geo=geo,
    )

    try:
        sock.settimeout(30)
        _send(sock, config.BANNERS["ftp"])

        username = None
        buf = ""

        while True:
            try:
                data = sock.recv(1024).decode("utf-8", "replace")
            except socket.timeout:
                break
            if not data:
                break

            buf += data
            while "\r\n" in buf or "\n" in buf:
                sep   = "\r\n" if "\r\n" in buf else "\n"
                line  = buf[:buf.index(sep)].strip()
                buf   = buf[buf.index(sep) + len(sep):]

                if not line:
                    continue

                cmd_parts = line.split(None, 1)
                cmd       = cmd_parts[0].upper()
                arg       = cmd_parts[1] if len(cmd_parts) > 1 else ""

                if cmd == "USER":
                    username = arg
                    _send(sock, "331 Please specify the password.")

                elif cmd == "PASS":
                    logger.log_event(
                        service="ftp",
                        src_ip=client_ip,
                        src_port=client_port,
                        event_type="ftp_login_attempt",
                        username=username,
                        password=arg,
                        geo=geo,
                    )
                    # Always fail auth
                    _send(sock, "530 Login incorrect.")

                elif cmd == "QUIT":
                    _send(sock, "221 Goodbye.")
                    return

                elif cmd == "SYST":
                    _send(sock, "215 UNIX Type: L8")

                elif cmd == "FEAT":
                    _send(sock, "211-Features:\r\n PASV\r\n UTF8\r\n211 End")

                elif cmd in ("LIST", "NLST"):
                    _send(sock, "150 Here comes the directory listing.")
                    _send(sock, "\r\n".join(_FAKE_FILES))
                    _send(sock, "226 Directory send OK.")

                else:
                    _send(sock, f"500 Unknown command '{cmd}'.")

    except Exception:
        pass
    finally:
        try:
            sock.close()
        except Exception:
            pass


def start(stop_event: threading.Event):
    port = config.SERVICES["ftp"]["port"]
    srv  = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", port))
    srv.listen(50)
    srv.settimeout(1.0)
    print(f"[FTP   ] Listening on port {port}")

    while not stop_event.is_set():
        try:
            sock, addr = srv.accept()
            t = threading.Thread(target=_handle_client, args=(sock, addr), daemon=True)
            t.start()
        except socket.timeout:
            continue
        except Exception as e:
            if not stop_event.is_set():
                print(f"[FTP] Error: {e}")

    srv.close()
    print("[FTP   ] Stopped.")
