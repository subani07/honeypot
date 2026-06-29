# 🍯 HoneyShield — Threat Intelligence Honeypot

HoneyShield is a multi-service Python-based honeypot system designed to attract, detect, and analyze malicious traffic in real time. It features a modern, premium dark-mode web dashboard that visualizes attack patterns, geolocation data, and captured credentials.

---

## 🚀 Key Features

*   **5 Emulated Services**:
    *   🔐 **SSH (Port 2222)**: Emulates OpenSSH 7.4. Captures brute-force login attempts and key details.
    *   🌐 **HTTP (Port 8080)**: Emulates Apache 2.4.49. Detects common vulnerability scans, SQL injection, XSS, and path traversal attempts.
    *   📁 **FTP (Port 2121)**: Emulates a vulnerable vsFTPd 2.3.4 server. Logs login credentials.
    *   💻 **Telnet (Port 2323)**: Simulates an Ubuntu IoT login prompt, logging botnet (e.g. Mirai) brute-force credentials.
    *   📧 **SMTP (Port 2525)**: Simulates a mail relay server. Captures spam email payloads and bot connections.
*   **Real-Time Web Dashboard**: High-performance dashboard built with Flask and WebSockets (Socket.IO).
*   **Threat Intelligence Engine**: Includes local attack pattern classification (Scanners, Exploits, Brute-Force) and automatic GeoIP lookups.
*   **SQLite Storage**: A lightweight, file-based database logging timestamps, IP addresses, services targeted, usernames, passwords, and payloads.

---

## 🛠️ Project Structure

```text
honeypot/
├── core/
│   ├── services/           # Service simulators (SSH, HTTP, FTP, etc.)
│   ├── logger.py           # SQLite db manager & socket listeners
│   ├── manager.py          # Starts/stops threads for all services
│   └── threat_intel.py     # Geolocation & attack parsing
├── dashboard/
│   ├── templates/          # HTML files
│   ├── static/             # JS/CSS styling
│   └── app.py              # Flask server
├── config.py               # Global settings (ports, banners)
├── main.py                 # Project main entry point
├── test_attacks.py         # Automated simulation script
└── requirements.txt        # System requirements
```

---

## 💻 Quick Start

### 1. Install Dependencies
Make sure you have Python 3.9+ installed, then run:
```bash
pip install -r requirements.txt
```

### 2. Run the Honeypot
Start all fake services and the dashboard server by running:
```bash
python main.py
```

### 3. Open the Dashboard
Open your browser and navigate to:
```text
http://127.0.0.1:5000
```

### 4. Run the Attack Simulator
To verify everything is working, open a separate terminal and run the test script:
```bash
python test_attacks.py
```
This triggers all 14 supported attack types so you can see them light up on the live dashboard.

---

## 📝 License
This project is for educational and network defense research purposes only. Ensure you have authorization before deploying honeypots on networks.
