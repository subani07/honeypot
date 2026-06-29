"""
Fake SMTP honeypot — simulates an open mail relay (Postfix).
Captures spam attempts and harvests sender/recipient addresses.
"""

import socket
import threading
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
import config
from core import logger
from core.threat_intel import get_geo


def _send(sock: socket.socket, msg: str):
    sock.sendall((msg + "\r\n").encode())


def _handle_client(sock: socket.socket, addr):
    client_ip, client_port = addr[0], addr[1]
    geo = get_geo(client_ip)

    logger.log_event(
        service="smtp",
        src_ip=client_ip,
        src_port=client_port,
        event_type="smtp_connect",
        geo=geo,
    )

    try:
        sock.settimeout(30)
        _send(sock, config.BANNERS["smtp"])

        mail_from    = None
        rcpt_to_list = []
        in_data      = False
        mail_data    = []
        buf          = ""

        while True:
            try:
                chunk = sock.recv(2048).decode("utf-8", "replace")
            except socket.timeout:
                break
            if not chunk:
                break

            buf += chunk
            while "\r\n" in buf or "\n" in buf:
                sep  = "\r\n" if "\r\n" in buf else "\n"
                line = buf[:buf.index(sep)]
                buf  = buf[buf.index(sep) + len(sep):]

                if in_data:
                    if line.strip() == ".":
                        in_data   = False
                        body_text = "\n".join(mail_data)
                        logger.log_event(
                            service="smtp",
                            src_ip=client_ip,
                            src_port=client_port,
                            event_type="smtp_relay_attempt",
                            username=mail_from,
                            payload=f"TO:{','.join(rcpt_to_list)}\n{body_text[:1000]}",
                            geo=geo,
                        )
                        _send(sock, "250 Ok: queued")
                        mail_data    = []
                        rcpt_to_list = []
                        mail_from    = None
                    else:
                        mail_data.append(line)
                    continue

                cmd = line.strip().upper()[:4]

                if cmd == "EHLO" or cmd == "HELO":
                    domain = line.strip().split(None, 1)[1] if " " in line else ""
                    _send(sock, f"250-mail.example.com Hello {domain}")
                    _send(sock, "250-SIZE 10240000")
                    _send(sock, "250-AUTH LOGIN PLAIN")
                    _send(sock, "250 HELP")

                elif cmd == "MAIL":
                    mail_from = line.strip()
                    _send(sock, "250 Ok")

                elif cmd == "RCPT":
                    rcpt_to_list.append(line.strip())
                    _send(sock, "250 Ok")

                elif cmd == "DATA":
                    in_data = True
                    _send(sock, "354 End data with <CR><LF>.<CR><LF>")

                elif cmd == "AUTH":
                    # Log auth attempt
                    logger.log_event(
                        service="smtp",
                        src_ip=client_ip,
                        src_port=client_port,
                        event_type="smtp_auth_attempt",
                        payload=line.strip(),
                        geo=geo,
                    )
                    _send(sock, "535 Authentication credentials invalid")

                elif cmd == "QUIT":
                    _send(sock, "221 Bye")
                    return

                elif cmd == "NOOP":
                    _send(sock, "250 Ok")

                elif cmd == "RSET":
                    mail_from    = None
                    rcpt_to_list = []
                    mail_data    = []
                    _send(sock, "250 Ok")

                else:
                    _send(sock, f"502 Command not implemented")

    except Exception:
        pass
    finally:
        try:
            sock.close()
        except Exception:
            pass


def start(stop_event: threading.Event):
    port = config.SERVICES["smtp"]["port"]
    srv  = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", port))
    srv.listen(50)
    srv.settimeout(1.0)
    print(f"[SMTP  ] Listening on port {port}")

    while not stop_event.is_set():
        try:
            sock, addr = srv.accept()
            t = threading.Thread(target=_handle_client, args=(sock, addr), daemon=True)
            t.start()
        except socket.timeout:
            continue
        except Exception as e:
            if not stop_event.is_set():
                print(f"[SMTP] Error: {e}")

    srv.close()
    print("[SMTP  ] Stopped.")
