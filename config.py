"""
NetSentry Configuration Module
Network Intelligence & Live Threat Monitoring System
Developer: Mohsin
"""

import os
from pathlib import Path

# Base Paths
BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
LOGS_DIR = BASE_DIR / "logs"
EXPORTS_DIR = BASE_DIR / "exports"
FRONTEND_DIR = BASE_DIR / "frontend"

DATA_DIR.mkdir(exist_ok=True)
LOGS_DIR.mkdir(exist_ok=True)
EXPORTS_DIR.mkdir(exist_ok=True)

# Database
DB_PATH = DATA_DIR / "netsentry.db"

# Server Configuration
SERVER_HOST = "127.0.0.1"
SERVER_PORT = 8088
AUTO_OPEN_BROWSER = True

# Monitoring Intervals (seconds)
MONITOR_INTERVAL = 1.5           # Connection polling cadence
TRAFFIC_INTERVAL = 1.0           # System I/O rate calculation
DB_SYNC_INTERVAL = 5.0           # Periodic database sync interval
HISTORY_RETENTION_DAYS = 14      # Default history retention

# IP Intelligence (ipwho.is)
IPWHOIS_API_URL = "https://ipwho.is/{ip}"
IP_CACHE_TTL_DAYS = 30           # Cache lookup results for 30 days
IP_LOOKUP_RATE_LIMIT = 0.25      # Min seconds between external API calls (4 req/sec)

# Critical Windows System Processes (Never terminate automatically)
CRITICAL_SYSTEM_PROCESSES = {
    "system",
    "registry",
    "smss.exe",
    "csrss.exe",
    "wininit.exe",
    "services.exe",
    "lsass.exe",
    "svchost.exe",
    "fontdrvhost.exe",
    "winlogon.exe",
    "dwm.exe",
    "spoolsv.exe",
    "explorer.exe",
    "taskhostw.exe",
    "sihost.exe",
    "runtimebroker.exe",
    "securityhealthservice.exe",
    "searchindexer.exe"
}

# Suspicious Outbound Ports (Well-known malware/C2/exploitation/unusual services)
SUSPICIOUS_PORTS = {
    23: ("Telnet", "Unencrypted remote terminal session"),
    1337: ("Elite/Backdoor", "Common hacker/backdoor port"),
    31337: ("Back Orifice", "Classic trojan remote administration port"),
    4444: ("Metasploit", "Common Metasploit default payload listener"),
    5555: ("ADB / Trojan", "Android Debug Bridge or unauthorized shell"),
    6667: ("IRC Botnet", "Internet Relay Chat frequently used for botnet C2"),
    7777: ("Backdoor Shell", "Common default port for remote shells"),
    8888: ("Alternate HTTP / Proxy", "Often used by illicit proxy/C2 tunnels"),
    9001: ("Tor Relay", "Tor network router/hidden service traffic"),
    9050: ("Tor SOCKS Proxy", "Tor local socks proxy tunnel"),
    3333: ("Stratum Mining", "Cryptocurrency mining pool protocol"),
    14444: ("Cryptonight Mining", "Cryptocurrency mining pool protocol"),
    14433: ("Mining SSL", "Encrypted cryptocurrency mining connection"),
    5900: ("VNC", "Virtual Network Computing unencrypted remote control")
}

# Suspicious File Path Substrings (Locations where legitimate services rarely live)
SUSPICIOUS_PATH_PATTERNS = [
    r"\AppData\Local\Temp",
    r"\AppData\Roaming",
    r"\Users\Public",
    r"\Recycle.Bin",
    r"\Windows\Temp",
    r"\PerfLogs",
    r"\ProgramData" # flag if combined with unsigned or high-risk port
]

# Detection Engine Thresholds
RAPID_CONNECTION_THRESHOLD = 12   # >12 distinct foreign IPs in a 30s window triggers fan-out alert
HIGH_OUTBOUND_BYTE_RATE = 5 * 1024 * 1024  # 5 MB/s outbound continuous rate threshold
UNEXPECTED_LISTENER_PORTS = {80, 443, 8080, 8443, 3389, 5900, 22, 21, 23}

