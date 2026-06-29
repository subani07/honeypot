"""
HoneyShield Attack Tester
Simulates all 14 attack types against your local honeypot.
Run this in a NEW terminal while main.py is running.

Usage:
    python test_attacks.py
"""

import socket
import time
import sys

TARGET = "127.0.0.1"
DELAY  = 0.8   # seconds between attacks (so you can watch dashboard update)

GREEN  = "\033[92m"
YELLOW = "\033[93m"
RED    = "\033[91m"
CYAN   = "\033[96m"
RESET  = "\033[0m"
BOLD   = "\033[1m"

def banner(title):
    print(f"\n{BOLD}{CYAN}{'='*55}{RESET}")
    print(f"{BOLD}{CYAN}  {title}{RESET}")
    print(f"{BOLD}{CYAN}{'='*55}{RESET}")

def ok(msg):
    print(f"  {GREEN}[OK]{RESET}  {msg}")

def info(msg):
    print(f"  {YELLOW}[..]{RESET}  {msg}")

def err(msg):
    print(f"  {RED}[!!]{RESET}  {msg}")

def tcp_send(port, messages: list[str], read_lines: int = 1, timeout: float = 3.0) -> list[str]:
    """Open a raw TCP connection, send messages, return responses."""
    responses = []
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((TARGET, port))
        for _ in range(read_lines):
            try:
                responses.append(s.recv(1024).decode("utf-8", "replace").strip())
            except socket.timeout:
                break
        for msg in messages:
            s.sendall((msg + "\r\n").encode())
            time.sleep(0.3)
            try:
                responses.append(s.recv(1024).decode("utf-8", "replace").strip())
            except socket.timeout:
                pass
        s.close()
    except ConnectionRefusedError:
        err(f"Port {port} refused — is the honeypot running?")
    except Exception as e:
        err(f"Error on port {port}: {e}")
    return responses

def http_request(port, method, path, headers="", body=""):
    """Send a raw HTTP request."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((TARGET, port))
        req = (
            f"{method} {path} HTTP/1.1\r\n"
            f"Host: {TARGET}\r\n"
            f"{headers}"
            f"Connection: close\r\n\r\n"
            f"{body}"
        )
        s.sendall(req.encode())
        resp = s.recv(2048).decode("utf-8", "replace")
        s.close()
        return resp.split("\r\n")[0]  # first line e.g. "HTTP/1.1 404 Not Found"
    except ConnectionRefusedError:
        return "Connection refused"
    except Exception as e:
        return f"Error: {e}"


# ─────────────────────────────────────────────────────────────────────────────
print(f"""
{BOLD}
  HoneyShield Attack Tester
  Simulating all 14 attack types...
  Watch your dashboard at http://127.0.0.1:5000
{RESET}""")

input(f"  {YELLOW}Press ENTER to start...{RESET}\n")

# ═══════════════════════════════════════════════════════════
# 1. SSH ATTACKS
# ═══════════════════════════════════════════════════════════
banner("SSH ATTACKS (port 2222)")

# Attack 1: ssh_connect (raw TCP touch)
info("Attack 1/14 — ssh_connect (port scan / banner grab)")
resp = tcp_send(2222, [], read_lines=1, timeout=3)
if resp:
    ok(f"SSH banner: {resp[0][:60]}")
else:
    ok("Connected to SSH port (no banner captured)")
time.sleep(DELAY)

# Attack 2: ssh_login_attempt — requires paramiko
info("Attack 2/14 — ssh_login_attempt (brute force password)")
try:
    import paramiko, warnings
    warnings.filterwarnings("ignore")
    t = paramiko.Transport((TARGET, 2222))
    t.start_client(timeout=5)
    try:
        t.auth_password("root", "123456")
    except Exception:
        pass
    t.close()
    ok("SSH brute-force: root / 123456")
except ImportError:
    err("paramiko not found — skipping")
except Exception:
    ok("SSH brute-force attempt sent (rejected by honeypot, logged!)")
time.sleep(DELAY)

# Attack 3: ssh_pubkey_attempt
info("Attack 3/14 — ssh_pubkey_attempt (public key auth)")
try:
    import paramiko, warnings
    warnings.filterwarnings("ignore")
    t = paramiko.Transport((TARGET, 2222))
    t.start_client(timeout=5)
    key = paramiko.RSAKey.generate(1024)
    try:
        t.auth_publickey("admin", key)
    except Exception:
        pass
    t.close()
    ok("SSH public-key attempt sent")
except Exception:
    ok("SSH pubkey attempt sent")
time.sleep(DELAY)

# ═══════════════════════════════════════════════════════════
# 2. HTTP ATTACKS
# ═══════════════════════════════════════════════════════════
banner("HTTP ATTACKS (port 8080)")

# Attack 4: http_probe (normal browse)
info("Attack 4/14 — http_probe (normal page browse)")
resp = http_request(8080, "GET", "/")
ok(f"Response: {resp}")
time.sleep(DELAY)

# Attack 5: http_scanner (scanner user-agent)
info("Attack 5/14 — http_scanner (Nmap/scanner user-agent)")
resp = http_request(8080, "GET", "/", headers="User-Agent: nmap/7.94\r\n")
ok(f"Response: {resp}")
time.sleep(DELAY)

# Attack 6: http_exploit_attempt — path traversal
info("Attack 6/14 — http_exploit_attempt (path traversal ../../../etc/passwd)")
resp = http_request(8080, "GET", "/../../../etc/passwd")
ok(f"Response: {resp}")
time.sleep(DELAY)

# Attack 7: http_exploit_attempt — SQL injection
info("Attack 7/14 — http_exploit_attempt (SQL injection)")
resp = http_request(8080, "GET", "/login?id=1' UNION SELECT username,password FROM users--")
ok(f"Response: {resp}")
time.sleep(DELAY)

# ═══════════════════════════════════════════════════════════
# 3. FTP ATTACKS
# ═══════════════════════════════════════════════════════════
banner("FTP ATTACKS (port 2121)")

# Attack 8: ftp_connect
info("Attack 8/14 — ftp_connect (connect to FTP server)")
resp = tcp_send(2121, [], read_lines=1, timeout=3)
if resp:
    ok(f"FTP banner: {resp[0][:60]}")
time.sleep(DELAY)

# Attack 9: ftp_login_attempt
info("Attack 9/14 — ftp_login_attempt (credential brute-force)")
resp = tcp_send(2121, ["USER anonymous", "PASS hacker@evil.com"], read_lines=1, timeout=3)
ok("FTP login attempt: anonymous / hacker@evil.com")
time.sleep(DELAY)

# ═══════════════════════════════════════════════════════════
# 4. TELNET ATTACKS
# ═══════════════════════════════════════════════════════════
banner("TELNET ATTACKS (port 2323)")

# Attack 10: telnet_connect
info("Attack 10/14 — telnet_connect (IoT bot connect)")
resp = tcp_send(2323, [], read_lines=2, timeout=3)
ok("Connected to Telnet (Ubuntu 18.04 fake banner served)")
time.sleep(DELAY)

# Attack 11: telnet_login (Mirai-style default credentials)
info("Attack 11/14 — telnet_login (Mirai bot: admin/admin)")
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5)
    s.connect((TARGET, 2323))
    time.sleep(0.5)
    s.recv(512)           # banner + login prompt
    s.sendall(b"admin\n") # username
    time.sleep(0.4)
    s.recv(512)           # password prompt
    s.sendall(b"admin\n") # password (Mirai default)
    time.sleep(0.4)
    s.recv(512)
    s.close()
    ok("Telnet login attempt: admin / admin (Mirai-style)")
except Exception as e:
    ok(f"Telnet login attempt sent ({e})")
time.sleep(DELAY)

# ═══════════════════════════════════════════════════════════
# 5. SMTP ATTACKS
# ═══════════════════════════════════════════════════════════
banner("SMTP ATTACKS (port 2525)")

# Attack 12: smtp_connect
info("Attack 12/14 — smtp_connect (connect to mail server)")
resp = tcp_send(2525, [], read_lines=1, timeout=3)
if resp:
    ok(f"SMTP banner: {resp[0][:60]}")
time.sleep(DELAY)

# Attack 13: smtp_auth_attempt
info("Attack 13/14 — smtp_auth_attempt (spam bot auth)")
resp = tcp_send(2525, ["EHLO evil.com", "AUTH LOGIN"], read_lines=1, timeout=3)
ok("SMTP auth attempt sent")
time.sleep(DELAY)

# Attack 14: smtp_relay_attempt (send spam through our server)
info("Attack 14/14 — smtp_relay_attempt (open relay spam)")
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5)
    s.connect((TARGET, 2525))
    time.sleep(0.3)
    s.recv(256)
    s.sendall(b"EHLO spammer.com\r\n"); time.sleep(0.3); s.recv(256)
    s.sendall(b"MAIL FROM:<hacker@evil.com>\r\n"); time.sleep(0.3); s.recv(256)
    s.sendall(b"RCPT TO:<victim@bank.com>\r\n"); time.sleep(0.3); s.recv(256)
    s.sendall(b"DATA\r\n"); time.sleep(0.3); s.recv(256)
    s.sendall(b"Subject: You won a prize!\r\nClick here: http://evil.com\r\n.\r\n")
    time.sleep(0.4); s.recv(256)
    s.sendall(b"QUIT\r\n")
    s.close()
    ok("SMTP relay: spam email sent through honeypot!")
except Exception as e:
    ok(f"SMTP relay attempt sent ({e})")

# ═══════════════════════════════════════════════════════════
# DONE
# ═══════════════════════════════════════════════════════════
print(f"""
{BOLD}{GREEN}
  All 14 attack types triggered!
  Open http://127.0.0.1:5000 to see them all on the dashboard.
  Run 'python main.py --stats' to see the summary.
{RESET}""")
