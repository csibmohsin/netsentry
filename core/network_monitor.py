"""
NetSentry Network Monitor Engine
Continuous Windows TCP/UDP connection polling, metadata enrichment, intelligence linking, and event broadcast.
Developer: Mohsin
"""

import time
import socket
import psutil
import logging
import threading
from typing import Dict, Any, List, Optional
from config import MONITOR_INTERVAL, DB_SYNC_INTERVAL
from core.process_monitor import ProcessMonitor
from core.ip_intelligence import IPIntelligenceManager
from core.detection_engine import DetectionEngine
from core.traffic_monitor import TrafficMonitor
from core.connection_tracker import ConnectionTracker
from core.history_manager import HistoryManager

logger = logging.getLogger("NetSentry.NetworkMonitor")

class NetworkMonitor:
    _instance = None
    _lock = threading.Lock()

    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            with cls._lock:
                if not cls._instance:
                    cls._instance = super().__new__(cls)
                    cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if getattr(self, "_initialized", False):
            return
        
        self.process_monitor = ProcessMonitor()
        self.ip_intelligence = IPIntelligenceManager()
        self.detection_engine = DetectionEngine()
        self.traffic_monitor = TrafficMonitor()
        self.tracker = ConnectionTracker()
        self.history = HistoryManager()

        self.running = False
        self.monitor_thread = None
        self.snapshot_lock = threading.Lock()

        # Cached live state
        self.latest_connections: List[Dict[str, Any]] = []
        self.latest_connections_by_key: Dict[str, Dict[str, Any]] = {}
        self.latest_stats: Dict[str, Any] = {
            "total_connections": 0,
            "established_tcp": 0,
            "listening_ports": 0,
            "unique_remote_ips": 0,
            "active_processes": 0,
            "suspicious_connections": 0,
            "traffic": {}
        }
        self.recent_alerts: List[Dict[str, Any]] = []

        self.last_db_sync = time.time()
        self._initialized = True

    def start(self):
        """Starts the background continuous monitoring thread."""
        if self.running:
            return
        self.running = True
        try:
            self.poll_connections()
        except Exception as e:
            logger.error("Initial poll error: %s", e)
        self.monitor_thread = threading.Thread(target=self._run_loop, daemon=True, name="NetSentry-Worker")
        self.monitor_thread.start()
        logger.info("NetSentry continuous monitoring engine started.")

    def stop(self):
        """Stops the background continuous monitoring thread."""
        self.running = False
        if self.monitor_thread and self.monitor_thread.is_alive():
            self.monitor_thread.join(timeout=3.0)
        logger.info("NetSentry monitoring engine stopped.")

    def _generate_connection_key(self, pid: Optional[int], proto: str, lip: str, lport: int, rip: str, rport: int) -> str:
        return f"{pid or 0}:{lip}:{lport}:{rip}:{rport}:{proto.lower()}"

    def poll_connections(self):
        """
        Polls current OS network connections, enriches each with process, intelligence, and threat heuristics.
        """
        try:
            # Poll all TCP and UDP connections on Windows
            raw_connections = psutil.net_connections(kind="all")
        except Exception as e:
            logger.error("Failed to query psutil.net_connections: %s", e)
            return

        current_active_keys = set()
        enriched_list = []
        unique_remote_ips = set()
        active_pids = set()
        established_count = 0
        listening_count = 0
        suspicious_count = 0

        # Pre-cache process summaries for distinct active PIDs in this cycle
        pids_in_cycle = {conn.pid for conn in raw_connections if conn.pid is not None}
        proc_cache: Dict[int, Optional[Dict[str, Any]]] = {}
        for pid in pids_in_cycle:
            proc_cache[pid] = self.process_monitor.get_process_summary(pid)

        for conn in raw_connections:
            try:
                pid = conn.pid
                protocol = "TCP" if conn.type == socket.SOCK_STREAM else "UDP"
                state = conn.status if conn.status else ("LISTEN" if not conn.raddr else "ESTABLISHED")
                
                lip = conn.laddr.ip if conn.laddr else "0.0.0.0"
                lport = conn.laddr.port if conn.laddr else 0
                rip = conn.raddr.ip if conn.raddr else ""
                rport = conn.raddr.port if conn.raddr else 0

                key = self._generate_connection_key(pid, protocol, lip, lport, rip, rport)
                current_active_keys.add(key)

                if pid:
                    active_pids.add(pid)

                if state == "ESTABLISHED":
                    established_count += 1
                elif state == "LISTEN":
                    listening_count += 1

                if rip and rip not in ("0.0.0.0", "127.0.0.1", "::1"):
                    unique_remote_ips.add(rip)

                # Process info
                proc_info = proc_cache.get(pid) if pid else None
                proc_name = proc_info.get("name", "System / Unknown") if proc_info else ("System" if pid == 4 else "Unknown")
                exe_path = proc_info.get("exe", "") if proc_info else ""

                # Track connection lifetime & duration
                track_data = self.tracker.track(
                    connection_key=key,
                    pid=pid,
                    proc_name=proc_name,
                    exe_path=exe_path,
                    protocol=protocol,
                    local_ip=lip,
                    local_port=lport,
                    remote_ip=rip,
                    remote_port=rport,
                    state=state
                )

                # IP Intelligence
                intel_data = self.ip_intelligence.get_ip_info(rip)

                # Detection Engine Analysis
                is_new_dest = rip and (rip not in self.detection_engine.known_destinations)
                conn_context = {
                    "connection_key": key,
                    "pid": pid,
                    "process_name": proc_name,
                    "exe_path": exe_path,
                    "protocol": protocol,
                    "local_ip": lip,
                    "local_port": lport,
                    "remote_ip": rip,
                    "remote_port": rport,
                    "connection_state": state,
                    "duration_seconds": track_data.get("duration_seconds", 0.0),
                    "is_private": intel_data.get("is_private", False)
                }

                risk_level, risk_score, alerts = self.detection_engine.analyze_connection(
                    conn_context,
                    proc_info=proc_info,
                    is_new_destination=is_new_dest
                )

                if risk_level in ("MEDIUM", "HIGH", "CRITICAL"):
                    suspicious_count += 1
                    for alert in alerts:
                        self.history.record_alert(alert, conn_context)
                        # Add to recent alerts buffer
                        alert_item = {
                            "timestamp": time.strftime("%H:%M:%S"),
                            "process_name": proc_name,
                            "pid": pid,
                            "remote_ip": rip,
                            "remote_port": rport,
                            "severity": alert["severity"],
                            "rule_name": alert["rule_name"],
                            "reason": alert["reason"]
                        }
                        self.recent_alerts.insert(0, alert_item)
                        if len(self.recent_alerts) > 50:
                            self.recent_alerts.pop()

                item = {
                    "connection_key": key,
                    "pid": pid,
                    "process_name": proc_name,
                    "exe_path": exe_path,
                    "protocol": protocol,
                    "local_ip": lip,
                    "local_port": lport,
                    "remote_ip": rip,
                    "remote_port": rport,
                    "connection_state": state,
                    "first_seen": track_data.get("first_seen"),
                    "last_seen": track_data.get("last_seen"),
                    "duration_seconds": track_data.get("duration_seconds", 0.0),
                    "duration_formatted": track_data.get("duration_formatted", "0s"),
                    "bytes_sent": track_data.get("bytes_sent", 0),
                    "bytes_received": track_data.get("bytes_received", 0),
                    "risk_level": risk_level,
                    "risk_score": risk_score,
                    "alerts": alerts,
                    "intelligence": intel_data,
                    "process_summary": {
                        "cpu_percent": proc_info.get("cpu_percent", 0.0) if proc_info else 0.0,
                        "memory_mb": proc_info.get("memory_mb", 0.0) if proc_info else 0.0,
                        "is_critical": proc_info.get("is_critical", False) if proc_info else False,
                        "signature": proc_info.get("signature", {}) if proc_info else {}
                    }
                }
                enriched_list.append(item)

            except Exception as item_err:
                logger.debug("Error processing individual connection: %s", item_err)
                continue

        # Prune inactive connections from the tracker
        closed_connections = self.tracker.prune_inactive(current_active_keys)
        # Flush closed connections to SQLite
        for closed_conn in closed_connections.values():
            self.history.record_connection(closed_conn)

        # Update Traffic Monitor
        traffic_point = self.traffic_monitor.update()

        # Record system traffic metrics in DB
        self.history.db.record_traffic_metric(
            bytes_sent_rate=traffic_point.get("sent_rate_bytes", 0.0),
            bytes_recv_rate=traffic_point.get("recv_rate_bytes", 0.0),
            total_connections=len(enriched_list),
            established_connections=established_count,
            suspicious_connections=suspicious_count
        )

        # Periodic DB snapshot synchronization for active connections
        now = time.time()
        if now - self.last_db_sync >= DB_SYNC_INTERVAL:
            for item in enriched_list:
                # Save snapshot to DB
                self.history.record_connection(item)
            self.last_db_sync = now

        # Update memory state atomically
        with self.snapshot_lock:
            self.latest_connections = enriched_list
            self.latest_connections_by_key = {item["connection_key"]: item for item in enriched_list}
            self.latest_stats = {
                "total_connections": len(enriched_list),
                "established_tcp": established_count,
                "listening_ports": listening_count,
                "unique_remote_ips": len(unique_remote_ips),
                "active_processes": len(active_pids),
                "suspicious_connections": suspicious_count,
                "traffic": traffic_point
            }

    def _run_loop(self):
        """Continuous background loop for network polling."""
        while self.running:
            try:
                self.poll_connections()
            except Exception as e:
                logger.error("Error in network monitoring poll cycle: %s", e)
            time.sleep(MONITOR_INTERVAL)

    def get_live_state(self) -> Dict[str, Any]:
        """Returns thread-safe snapshot of current network state."""
        with self.snapshot_lock:
            return {
                "stats": self.latest_stats,
                "connections": list(self.latest_connections),
                "recent_alerts": list(self.recent_alerts[:15]),
                "traffic_history": self.traffic_monitor.get_history()
            }

    def get_connection(self, key: str) -> Optional[Dict[str, Any]]:
        """Retrieves complete details for a specific connection key."""
        with self.snapshot_lock:
            return self.latest_connections_by_key.get(key)
