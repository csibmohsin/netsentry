"""
NetSentry Database Models & Schema Definitions
Developer: Mohsin
"""

from dataclasses import dataclass, asdict
from typing import Optional, List, Dict, Any
from datetime import datetime

SCHEMA_SQL = """
PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;

CREATE TABLE IF NOT EXISTS connections_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    connection_key TEXT NOT NULL,
    pid INTEGER,
    process_name TEXT,
    exe_path TEXT,
    protocol TEXT,
    local_ip TEXT,
    local_port INTEGER,
    remote_ip TEXT,
    remote_port INTEGER,
    connection_state TEXT,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    duration_seconds REAL DEFAULT 0.0,
    bytes_sent INTEGER DEFAULT 0,
    bytes_received INTEGER DEFAULT 0,
    risk_level TEXT DEFAULT 'SAFE',
    risk_score INTEGER DEFAULT 0,
    alert_reasons TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_conn_remote_ip ON connections_history(remote_ip);
CREATE INDEX IF NOT EXISTS idx_conn_proc_name ON connections_history(process_name);
CREATE INDEX IF NOT EXISTS idx_conn_last_seen ON connections_history(last_seen);
CREATE INDEX IF NOT EXISTS idx_conn_risk_level ON connections_history(risk_level);
CREATE INDEX IF NOT EXISTS idx_conn_key ON connections_history(connection_key);

CREATE TABLE IF NOT EXISTS alerts_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    pid INTEGER,
    process_name TEXT,
    remote_ip TEXT,
    remote_port INTEGER,
    protocol TEXT,
    severity TEXT NOT NULL,
    rule_name TEXT NOT NULL,
    reason TEXT NOT NULL,
    details_json TEXT
);

CREATE INDEX IF NOT EXISTS idx_alert_timestamp ON alerts_history(timestamp);
CREATE INDEX IF NOT EXISTS idx_alert_severity ON alerts_history(severity);
CREATE INDEX IF NOT EXISTS idx_alert_remote_ip ON alerts_history(remote_ip);

CREATE TABLE IF NOT EXISTS ip_intelligence_cache (
    ip TEXT PRIMARY KEY,
    ip_version INTEGER DEFAULT 4,
    is_valid INTEGER DEFAULT 1,
    country TEXT,
    country_code TEXT,
    region TEXT,
    city TEXT,
    latitude REAL,
    longitude REAL,
    isp TEXT,
    org TEXT,
    asn TEXT,
    domain TEXT,
    timezone TEXT,
    raw_json TEXT,
    cached_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS system_traffic_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    bytes_sent_rate REAL DEFAULT 0.0,
    bytes_recv_rate REAL DEFAULT 0.0,
    total_connections INTEGER DEFAULT 0,
    established_connections INTEGER DEFAULT 0,
    suspicious_connections INTEGER DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_traffic_timestamp ON system_traffic_history(timestamp);

CREATE TABLE IF NOT EXISTS dns_queries_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    domain TEXT NOT NULL,
    qtype TEXT DEFAULT 'A',
    client_ip TEXT,
    dns_server TEXT,
    answers TEXT DEFAULT '[]',
    is_suspicious INTEGER DEFAULT 0,
    suspicious_reason TEXT DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_dns_timestamp ON dns_queries_history(timestamp);
CREATE INDEX IF NOT EXISTS idx_dns_domain ON dns_queries_history(domain);
CREATE INDEX IF NOT EXISTS idx_dns_suspicious ON dns_queries_history(is_suspicious);
"""

@dataclass
class ConnectionRecord:
    connection_key: str
    pid: Optional[int]
    process_name: str
    exe_path: str
    protocol: str
    local_ip: str
    local_port: int
    remote_ip: str
    remote_port: int
    connection_state: str
    first_seen: str
    last_seen: str
    duration_seconds: float = 0.0
    bytes_sent: int = 0
    bytes_received: int = 0
    risk_level: str = "SAFE"
    risk_score: int = 0
    alert_reasons: str = "[]"
    id: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

@dataclass
class AlertRecord:
    timestamp: str
    pid: Optional[int]
    process_name: str
    remote_ip: str
    remote_port: int
    protocol: str
    severity: str
    rule_name: str
    reason: str
    details_json: str = "{}"
    id: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

