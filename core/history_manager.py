"""
NetSentry History Manager
Persistent SQLite history persistence, search, aggregation, and export utilities.
Developer: Mohsin
"""

import io
import csv
import json
import logging
from typing import Dict, Any, List, Optional
from database.database import DatabaseManager
from database.models import ConnectionRecord, AlertRecord
from config import HISTORY_RETENTION_DAYS

logger = logging.getLogger("NetSentry.HistoryManager")

class HistoryManager:
    def __init__(self):
        self.db = DatabaseManager()

    def record_connection(self, conn_data: Dict[str, Any]):
        """
        Saves or updates connection record in SQLite.
        """
        try:
            alert_reasons = json.dumps(conn_data.get("alerts", []))
            record = ConnectionRecord(
                connection_key=conn_data.get("connection_key", ""),
                pid=conn_data.get("pid"),
                process_name=conn_data.get("process_name", "Unknown"),
                exe_path=conn_data.get("exe_path", ""),
                protocol=conn_data.get("protocol", "TCP"),
                local_ip=conn_data.get("local_ip", ""),
                local_port=conn_data.get("local_port", 0),
                remote_ip=conn_data.get("remote_ip", ""),
                remote_port=conn_data.get("remote_port", 0),
                connection_state=conn_data.get("connection_state", ""),
                first_seen=conn_data.get("first_seen", ""),
                last_seen=conn_data.get("last_seen", ""),
                duration_seconds=conn_data.get("duration_seconds", 0.0),
                bytes_sent=conn_data.get("bytes_sent", 0),
                bytes_received=conn_data.get("bytes_received", 0),
                risk_level=conn_data.get("risk_level", "SAFE"),
                risk_score=conn_data.get("risk_score", 0),
                alert_reasons=alert_reasons
            )
            self.db.upsert_connection_snapshot(record)
        except Exception as e:
            logger.error("Failed to record connection: %s", e)

    def record_alert(self, alert_dict: Dict[str, Any], conn_data: Dict[str, Any]):
        """
        Records an identified threat alert to the alerts_history table.
        """
        try:
            record = AlertRecord(
                timestamp=conn_data.get("last_seen") or "",
                pid=conn_data.get("pid"),
                process_name=conn_data.get("process_name", "Unknown"),
                remote_ip=conn_data.get("remote_ip", ""),
                remote_port=conn_data.get("remote_port", 0),
                protocol=conn_data.get("protocol", "TCP"),
                severity=alert_dict.get("severity", "LOW"),
                rule_name=alert_dict.get("rule_name", "Unknown Rule"),
                reason=alert_dict.get("reason", ""),
                details_json=json.dumps(alert_dict)
            )
            self.db.record_alert(record)
        except Exception as e:
            logger.error("Failed to record alert: %s", e)

    def query_connections(
        self,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
        process_name: Optional[str] = None,
        remote_ip: Optional[str] = None,
        protocol: Optional[str] = None,
        risk_level: Optional[str] = None,
        limit: int = 100,
        offset: int = 0
    ) -> Dict[str, Any]:
        records = self.db.get_historical_connections(
            start_time=start_time,
            end_time=end_time,
            process_name=process_name,
            remote_ip=remote_ip,
            protocol=protocol,
            risk_level=risk_level,
            limit=limit,
            offset=offset
        )
        total = self.db.get_historical_connections_count(
            start_time=start_time,
            end_time=end_time,
            process_name=process_name,
            remote_ip=remote_ip,
            protocol=protocol,
            risk_level=risk_level
        )
        # Parse alert reasons
        for r in records:
            if r.get("alert_reasons"):
                try:
                    r["alerts"] = json.loads(r["alert_reasons"])
                except Exception:
                    r["alerts"] = []
            else:
                r["alerts"] = []
        return {
            "total": total,
            "records": records,
            "limit": limit,
            "offset": offset
        }

    def query_alerts(
        self,
        severity: Optional[str] = None,
        remote_ip: Optional[str] = None,
        process_name: Optional[str] = None,
        limit: int = 100,
        offset: int = 0
    ) -> List[Dict[str, Any]]:
        return self.db.get_alerts(
            severity=severity,
            remote_ip=remote_ip,
            process_name=process_name,
            limit=limit,
            offset=offset
        )

    def get_timeline(self, hours: int = 24) -> List[Dict[str, Any]]:
        return self.db.get_activity_timeline(hours=hours)

    def export_csv(self, records: List[Dict[str, Any]]) -> str:
        output = io.StringIO()
        if not records:
            return ""
        
        fieldnames = [
            "process_name", "pid", "exe_path", "protocol", "local_ip", "local_port",
            "remote_ip", "remote_port", "connection_state", "first_seen", "last_seen",
            "duration_seconds", "bytes_sent", "bytes_received", "risk_level", "risk_score"
        ]
        
        writer = csv.DictWriter(output, fieldnames=fieldnames, extrasaction='ignore')
        writer.writeheader()
        for r in records:
            writer.writerow(r)
        return output.getvalue()

    def export_json(self, records: List[Dict[str, Any]]) -> str:
        return json.dumps(records, indent=2)

    def cleanup(self, days: int = HISTORY_RETENTION_DAYS) -> Dict[str, Any]:
        return self.db.cleanup_old_records(days=days)

