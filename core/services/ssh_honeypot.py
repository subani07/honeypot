"""
Fake SSH honeypot — emulates OpenSSH 7.4.
Captures every login attempt (username + password).
"""

import socket
import threading
import os
import sys
import traceback

import paramiko

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
import config
from core import logger
from core.threat_intel import get_geo

# ── RSA host key (auto-generated once) ───────────────────────────────────────
KEY_PATH = "data/ssh_host_rsa.key"


def _load_or_generate_key() -> paramiko.RSAKey:
    os.makedirs("data", exist_ok=True)
    if os.path.exists(KEY_PATH):
        return paramiko.RSAKey(filename=KEY_PATH)
    key = paramiko.RSAKey.generate(2048)
    key.write_private_key_file(KEY_PATH)
    return key


HOST_KEY = _load_or_generate_key()


# ── Paramiko server interface ─────────────────────────────────────────────────
class _HoneypotSSHServer(paramiko.ServerInterface):
    def __init__(self, client_ip: str, client_port: int):
        self.client_ip   = client_ip
        self.client_port = client_port
        self.geo         = get_geo(client_ip)

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username: str, password: str):
        logger.log_event(
            service="ssh",
            src_ip=self.client_ip,
            src_port=self.client_port,
            event_type="ssh_login_attempt",
            username=username,
            password=password,
            geo=self.geo,
        )
        # Always reject — we never let them in
        return paramiko.AUTH_FAILED

    def check_auth_publickey(self, username, key):
        logger.log_event(
            service="ssh",
            src_ip=self.client_ip,
            src_port=self.client_port,
            event_type="ssh_pubkey_attempt",
            username=username,
            payload=f"key_type={key.get_name()} fingerprint={key.get_fingerprint().hex()}",
            geo=self.geo,
        )
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        return "password,publickey"


# ── Per-client handler ────────────────────────────────────────────────────────
def _handle_client(sock: socket.socket, addr):
    client_ip, client_port = addr[0], addr[1]
    geo = get_geo(client_ip)

    logger.log_event(
        service="ssh",
        src_ip=client_ip,
        src_port=client_port,
        event_type="ssh_connect",
        geo=geo,
    )

    transport = None
    try:
        transport = paramiko.Transport(sock)
        transport.local_version = config.BANNERS["ssh"]
        transport.add_server_key(HOST_KEY)

        server = _HoneypotSSHServer(client_ip, client_port)
        transport.start_server(server=server)

        # Wait briefly for auth attempts then close
        chan = transport.accept(30)
        if chan:
            chan.close()
    except Exception:
        pass
    finally:
        try:
            if transport:
                transport.close()
            sock.close()
        except Exception:
            pass


# ── Main service loop ─────────────────────────────────────────────────────────
def start(stop_event: threading.Event):
    port = config.SERVICES["ssh"]["port"]
    srv  = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", port))
    srv.listen(50)
    srv.settimeout(1.0)
    print(f"[SSH   ] Listening on port {port}")

    while not stop_event.is_set():
        try:
            sock, addr = srv.accept()
            t = threading.Thread(target=_handle_client, args=(sock, addr), daemon=True)
            t.start()
        except socket.timeout:
            continue
        except Exception as e:
            if not stop_event.is_set():
                print(f"[SSH] Error: {e}")

    srv.close()
    print("[SSH   ] Stopped.")
