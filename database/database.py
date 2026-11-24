"""
NetSentry Database Manager
Persistent SQLite storage with thread safety and automated maintenance.
Developer: Mohsin
"""

import sqlite3
import threading
import json
import logging
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
from config import DB_PATH, HISTORY_RETENTION_DAYS
from database.models import SCHEMA_SQL, ConnectionRecord, AlertRecord

logger = logging.getLogger("NetSentry.Database")

class DatabaseManager:
    _instance = None
    _lock = threading.Lock()

    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            with cls._lock:
                if not cls._instance:
                    cls._instance = super().__new__(cls)
                    cls._instance._initialized = False
        return cls._instance

    def __init__(self, db_path=DB_PATH):
        if getattr(self, "_initialized", False):
            return
        self.db_path = str(db_path)
        self._write_lock = threading.Lock()
        self._init_db()
        self._initialized = True

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=30.0)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        with self._write_lock:
            conn = self._get_connection()
            try:
                conn.executescript(SCHEMA_SQL)
                conn.commit()
                logger.info("Database initialized successfully at %s", self.db_path)
            except Exception as e:
                logger.error("Failed to initialize database: %s", e)
                raise
            finally:
                conn.close()

    # ----------------- Connections History -----------------
    def upsert_connection_snapshot(self, record: ConnectionRecord):
        """
        Record or update connection activity in the persistent database.
        If an existing open connection key exists within the recent window, updates last_seen and duration.
        """
        with self._write_lock:
            conn = self._get_connection()
            try:
                cursor = conn.cursor()
                # Check for existing record matching this connection key
                cursor.execute("""
                    SELECT id, first_seen, bytes_sent, bytes_received 
                    FROM connections_history 
                    WHERE connection_key = ? 
                    ORDER BY id DESC LIMIT 1
                """, (record.connection_key,))
                existing = cursor.fetchone()

                if existing:
                    rec_id = existing["id"]
                    first_seen = existing["first_seen"]
                    cursor.execute("""
                        UPDATE connections_history
                        SET last_seen = ?,
                            duration_seconds = ?,
                            connection_state = ?,
                            bytes_sent = ?,
                            bytes_received = ?,
                            risk_level = ?,
                            risk_score = ?,
                            alert_reasons = ?
                        WHERE id = ?
                    """, (
                        record.last_seen,
                        record.duration_seconds,
                        record.connection_state,
                        max(record.bytes_sent, existing["bytes_sent"]),
                        max(record.bytes_received, existing["bytes_received"]),
                        record.risk_level,
                        record.risk_score,
                        record.alert_reasons,
                        rec_id
                    ))
                else:
                    cursor.execute("""
                        INSERT INTO connections_history (
                            connection_key, pid, process_name, exe_path, protocol,
                            local_ip, local_port, remote_ip, remote_port,
                            connection_state, first_seen, last_seen, duration_seconds,
                            bytes_sent, bytes_received, risk_level, risk_score, alert_reasons
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        record.connection_key, record.pid, record.process_name, record.exe_path,
                        record.protocol, record.local_ip, record.local_port, record.remote_ip,
                        record.remote_port, record.connection_state, record.first_seen,
                        record.last_seen, record.duration_seconds, record.bytes_sent,
                        record.bytes_received, record.risk_level, record.risk_score,
                        record.alert_reasons
                    ))
                conn.commit()
            except Exception as e:
                logger.error("Error upserting connection: %s", e)
            finally:
                conn.close()

    def get_historical_connections(
        self,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
        process_name: Optional[str] = None,
        remote_ip: Optional[str] = None,
        protocol: Optional[str] = None,
        risk_level: Optional[str] = None,
        limit: int = 100,
        offset: int = 0
    ) -> List[Dict[str, Any]]:
        conn = self._get_connection()
        try:
            query = "SELECT * FROM connections_history WHERE 1=1"
            params = []

            if start_time:
                query += " AND last_seen >= ?"
                params.append(start_time)
            if end_time:
                query += " AND first_seen <= ?"
                params.append(end_time)
            if process_name:
                query += " AND process_name LIKE ?"
                params.append(f"%{process_name}%")
            if remote_ip:
                query += " AND remote_ip LIKE ?"
                params.append(f"%{remote_ip}%")
            if protocol:
                query += " AND protocol = ?"
                params.append(protocol.upper())
            if risk_level:
                query += " AND risk_level = ?"
                params.append(risk_level.upper())

            query += " ORDER BY id DESC LIMIT ? OFFSET ?"
            params.extend([limit, offset])

            cursor = conn.cursor()
            cursor.execute(query, params)
            rows = cursor.fetchall()
            return [dict(row) for row in rows]
        finally:
            conn.close()

    def get_historical_connections_count(
        self,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
        process_name: Optional[str] = None,
        remote_ip: Optional[str] = None,
        protocol: Optional[str] = None,
        risk_level: Optional[str] = None
    ) -> int:
        conn = self._get_connection()
        try:
            query = "SELECT COUNT(*) as count FROM connections_history WHERE 1=1"
            params = []
            if start_time:
                query += " AND last_seen >= ?"
                params.append(start_time)
            if end_time:
                query += " AND first_seen <= ?"
                params.append(end_time)
            if process_name:
                query += " AND process_name LIKE ?"
                params.append(f"%{process_name}%")
            if remote_ip:
                query += " AND remote_ip LIKE ?"
                params.append(f"%{remote_ip}%")
            if protocol:
                query += " AND protocol = ?"
                params.append(protocol.upper())
            if risk_level:
                query += " AND risk_level = ?"
                params.append(risk_level.upper())

            cursor = conn.cursor()
            cursor.execute(query, params)
            row = cursor.fetchone()
            return row["count"] if row else 0
        finally:
            conn.close()

    # ----------------- Alerts History -----------------
    def record_alert(self, alert: AlertRecord):
        with self._write_lock:
            conn = self._get_connection()
            try:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO alerts_history (
                        timestamp, pid, process_name, remote_ip, remote_port,
                        protocol, severity, rule_name, reason, details_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    alert.timestamp, alert.pid, alert.process_name, alert.remote_ip,
                    alert.remote_port, alert.protocol, alert.severity, alert.rule_name,
                    alert.reason, alert.details_json
                ))
                conn.commit()
            except Exception as e:
                logger.error("Error saving alert: %s", e)
            finally:
                conn.close()

    def get_alerts(
        self,
        severity: Optional[str] = None,
        remote_ip: Optional[str] = None,
        process_name: Optional[str] = None,
        limit: int = 100,
        offset: int = 0
    ) -> List[Dict[str, Any]]:
        conn = self._get_connection()
        try:
            query = "SELECT * FROM alerts_history WHERE 1=1"
            params = []
            if severity and severity.upper() != "ALL":
                query += " AND severity = ?"
                params.append(severity.upper())
            if remote_ip:
                query += " AND remote_ip LIKE ?"
                params.append(f"%{remote_ip}%")
            if process_name:
                query += " AND process_name LIKE ?"
                params.append(f"%{process_name}%")

            query += " ORDER BY id DESC LIMIT ? OFFSET ?"
            params.extend([limit, offset])

            cursor = conn.cursor()
            cursor.execute(query, params)
            return [dict(row) for row in cursor.fetchall()]
        finally:
            conn.close()

    # ----------------- IP Intelligence Cache -----------------
    def get_cached_ip(self, ip: str) -> Optional[Dict[str, Any]]:
        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM ip_intelligence_cache WHERE ip = ?", (ip,))
            row = cursor.fetchone()
            if row:
                data = dict(row)
                if data.get("raw_json"):
                    try:
                        data["raw"] = json.loads(data["raw_json"])
                    except Exception:
                        pass
                return data
            return None
        finally:
            conn.close()

    def save_cached_ip(self, ip_data: Dict[str, Any]):
        with self._write_lock:
            conn = self._get_connection()
            try:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT OR REPLACE INTO ip_intelligence_cache (
                        ip, ip_version, is_valid, country, country_code, region,
                        city, latitude, longitude, isp, org, asn, domain, timezone,
                        raw_json, cached_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    ip_data.get("ip"),
                    ip_data.get("ip_version", 4),
                    1 if ip_data.get("is_valid", True) else 0,
                    ip_data.get("country"),
                    ip_data.get("country_code"),
                    ip_data.get("region"),
                    ip_data.get("city"),
                    ip_data.get("latitude"),
                    ip_data.get("longitude"),
                    ip_data.get("isp"),
                    ip_data.get("org"),
                    ip_data.get("asn"),
                    ip_data.get("domain"),
                    ip_data.get("timezone"),
                    json.dumps(ip_data.get("raw", {})),
                    datetime.now().isoformat()
                ))
                conn.commit()
            except Exception as e:
                logger.error("Error saving IP cache: %s", e)
            finally:
                conn.close()

    def get_all_cached_ips(self, limit: int = 200) -> List[Dict[str, Any]]:
        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM ip_intelligence_cache ORDER BY cached_at DESC LIMIT ?", (limit,))
            return [dict(row) for row in cursor.fetchall()]
        finally:
            conn.close()

    def load_all_cached_ips_into_dict(self) -> Dict[str, Dict[str, Any]]:
        """Loads all cached IP records permanently into memory to guarantee zero repeated API requests."""
        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM ip_intelligence_cache")
            rows = cursor.fetchall()
            cached_dict = {}
            for r in rows:
                d = dict(r)
                if d.get("raw_json"):
                    try:
                        d["raw"] = json.loads(d["raw_json"])
                    except Exception:
                        pass
                cached_dict[d["ip"]] = d
            return cached_dict
        finally:
            conn.close()

    # ----------------- DNS Queries History -----------------
    def record_dns_query(self, q: Dict[str, Any]):
        with self._write_lock:
            conn = self._get_connection()
            try:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO dns_queries_history (
                        timestamp, domain, qtype, client_ip, dns_server, answers, is_suspicious, suspicious_reason
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    q.get("timestamp") or datetime.now().isoformat(),
                    q.get("domain", ""),
                    q.get("qtype", "A"),
                    q.get("client_ip", ""),
                    q.get("dns_server", ""),
                    json.dumps(q.get("answers", [])),
                    1 if q.get("is_suspicious") else 0,
                    q.get("suspicious_reason", "")
                ))
                conn.commit()
            except Exception as e:
                logger.error("Error saving DNS query: %s", e)
            finally:
                conn.close()

    def get_dns_queries(
        self,
        domain: Optional[str] = None,
        suspicious_only: bool = False,
        limit: int = 100,
        offset: int = 0
    ) -> List[Dict[str, Any]]:
        conn = self._get_connection()
        try:
            query = "SELECT * FROM dns_queries_history WHERE 1=1"
            params = []
            if domain:
                query += " AND domain LIKE ?"
                params.append(f"%{domain}%")
            if suspicious_only:
                query += " AND is_suspicious = 1"

            query += " ORDER BY id DESC LIMIT ? OFFSET ?"
            params.extend([limit, offset])

            cursor = conn.cursor()
            cursor.execute(query, params)
            rows = cursor.fetchall()
            results = []
            for r in rows:
                item = dict(r)
                if item.get("answers"):
                    try:
                        item["answers"] = json.loads(item["answers"])
                    except Exception:
                        pass
                results.append(item)
            return results
        finally:
            conn.close()

    def clear_dns_queries(self):
        with self._write_lock:
            conn = self._get_connection()
            try:
                cursor = conn.cursor()
                cursor.execute("DELETE FROM dns_queries_history")
                conn.commit()
            finally:
                conn.close()

    # ----------------- System Traffic History -----------------
    def record_traffic_metric(
        self,
        bytes_sent_rate: float,
        bytes_recv_rate: float,
        total_connections: int,
        established_connections: int,
        suspicious_connections: int
    ):
        with self._write_lock:
            conn = self._get_connection()
            try:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO system_traffic_history (
                        timestamp, bytes_sent_rate, bytes_recv_rate,
                        total_connections, established_connections, suspicious_connections
                    ) VALUES (?, ?, ?, ?, ?, ?)
                """, (
                    datetime.now().isoformat(),
                    bytes_sent_rate,
                    bytes_recv_rate,
                    total_connections,
                    established_connections,
                    suspicious_connections
                ))
                conn.commit()
            except Exception as e:
                logger.error("Error recording traffic metric: %s", e)
            finally:
                conn.close()

    def get_recent_traffic_metrics(self, points: int = 60) -> List[Dict[str, Any]]:
        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT * FROM system_traffic_history 
                ORDER BY id DESC LIMIT ?
            """, (points,))
            rows = cursor.fetchall()
            return [dict(r) for r in reversed(rows)]
        finally:
            conn.close()

    def get_activity_timeline(self, hours: int = 24) -> List[Dict[str, Any]]:
        conn = self._get_connection()
        try:
            cutoff = (datetime.now() - timedelta(hours=hours)).isoformat()
            cursor = conn.cursor()
            cursor.execute("""
                SELECT 
                    substr(first_seen, 1, 13) || ':00:00' as time_bucket,
                    COUNT(*) as connection_count,
                    SUM(CASE WHEN risk_level IN ('HIGH', 'CRITICAL') THEN 1 ELSE 0 END) as threat_count,
                    COUNT(DISTINCT remote_ip) as unique_ips,
                    COUNT(DISTINCT process_name) as unique_processes
                FROM connections_history
                WHERE first_seen >= ?
                GROUP BY time_bucket
                ORDER BY time_bucket ASC
            """, (cutoff,))
            return [dict(r) for r in cursor.fetchall()]
        finally:
            conn.close()

    # ----------------- Maintenance & Retention -----------------
    def cleanup_old_records(self, days: int = HISTORY_RETENTION_DAYS) -> Dict[str, int]:
        """
        Deletes historical connection records and metrics older than the specified retention window.
        """
        if days <= 0:
            return {"deleted_connections": 0, "deleted_alerts": 0, "deleted_traffic": 0}

        cutoff = (datetime.now() - timedelta(days=days)).isoformat()
        with self._write_lock:
            conn = self._get_connection()
            deleted = {}
            try:
                cursor = conn.cursor()
                cursor.execute("DELETE FROM connections_history WHERE last_seen < ?", (cutoff,))
                deleted["deleted_connections"] = cursor.rowcount

                cursor.execute("DELETE FROM alerts_history WHERE timestamp < ?", (cutoff,))
                deleted["deleted_alerts"] = cursor.rowcount

                cursor.execute("DELETE FROM system_traffic_history WHERE timestamp < ?", (cutoff,))
                deleted["deleted_traffic"] = cursor.rowcount

                conn.commit()
                cursor.execute("PRAGMA incremental_vacuum;")
                conn.commit()
                logger.info("Cleaned up old records beyond %d days: %s", days, deleted)
                return deleted
            except Exception as e:
                logger.error("Error during database cleanup: %s", e)
                return {"error": str(e)}
            finally:
                conn.close()

