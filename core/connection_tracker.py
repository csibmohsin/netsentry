"""
NetSentry Connection Tracker
Maintains real-time connection state, calculates durations, and tracks lifecycle deltas.
Developer: Mohsin
"""

import time
from datetime import datetime
from typing import Dict, Any, Optional

class ConnectionTracker:
    def __init__(self):
        # connection_key -> dict of tracking state
        self.active_tracks: Dict[str, Dict[str, Any]] = {}

    @staticmethod
    def format_duration(seconds: float) -> str:
        sec = int(seconds)
        if sec < 60:
            return f"{sec}s"
        elif sec < 3600:
            m = sec // 60
            s = sec % 60
            return f"{m}m {s}s"
        else:
            h = sec // 3600
            m = (sec % 3600) // 60
            return f"{h}h {m}m"

    def track(
        self,
        connection_key: str,
        pid: Optional[int],
        proc_name: str,
        exe_path: str,
        protocol: str,
        local_ip: str,
        local_port: int,
        remote_ip: str,
        remote_port: int,
        state: str,
        bytes_sent: int = 0,
        bytes_recv: int = 0
    ) -> Dict[str, Any]:
        """
        Updates or instantiates tracking state for an active socket connection.
        """
        now = time.time()
        iso_now = datetime.fromtimestamp(now).isoformat()

        if connection_key in self.active_tracks:
            entry = self.active_tracks[connection_key]
            first_seen_epoch = entry["first_seen_epoch"]
            duration = now - first_seen_epoch

            entry["last_seen"] = iso_now
            entry["last_seen_epoch"] = now
            entry["duration_seconds"] = duration
            entry["duration_formatted"] = self.format_duration(duration)
            entry["connection_state"] = state
            entry["bytes_sent"] = max(entry.get("bytes_sent", 0), bytes_sent)
            entry["bytes_received"] = max(entry.get("bytes_received", 0), bytes_recv)
            return entry
        else:
            new_entry = {
                "connection_key": connection_key,
                "pid": pid,
                "process_name": proc_name,
                "exe_path": exe_path,
                "protocol": protocol,
                "local_ip": local_ip,
                "local_port": local_port,
                "remote_ip": remote_ip,
                "remote_port": remote_port,
                "connection_state": state,
                "first_seen": iso_now,
                "first_seen_epoch": now,
                "last_seen": iso_now,
                "last_seen_epoch": now,
                "duration_seconds": 0.0,
                "duration_formatted": "0s",
                "bytes_sent": bytes_sent,
                "bytes_received": bytes_recv
            }
            self.active_tracks[connection_key] = new_entry
            return new_entry

    def prune_inactive(self, current_active_keys: set) -> Dict[str, Dict[str, Any]]:
        """
        Removes closed connections and returns them so they can be committed to permanent history.
        """
        closed = {}
        for key in list(self.active_tracks.keys()):
            if key not in current_active_keys:
                closed[key] = self.active_tracks.pop(key)
        return closed

    def get_track(self, key: str) -> Optional[Dict[str, Any]]:
        return self.active_tracks.get(key)

