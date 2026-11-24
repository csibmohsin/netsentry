"""
NetSentry System Traffic Monitor
Tracks incoming and outgoing network transfer throughput.
Developer: Mohsin
"""

import time
import psutil
from collections import deque
from typing import Dict, Any, List

class TrafficMonitor:
    def __init__(self, history_limit: int = 120):
        self.history_limit = history_limit
        self.history: deque = deque(maxlen=history_limit)
        
        # Initial baseline
        initial_io = psutil.net_io_counters()
        self.last_bytes_sent = initial_io.bytes_sent
        self.last_bytes_recv = initial_io.bytes_recv
        self.last_check_time = time.time()
        
        self.current_sent_rate = 0.0  # bytes/sec
        self.current_recv_rate = 0.0  # bytes/sec

    def update(self) -> Dict[str, Any]:
        """
        Polls current network I/O counters, computes current bytes/sec, and appends to history.
        """
        now = time.time()
        time_delta = now - self.last_check_time
        if time_delta <= 0:
            time_delta = 1.0

        try:
            current_io = psutil.net_io_counters()
            bytes_sent_delta = max(0, current_io.bytes_sent - self.last_bytes_sent)
            bytes_recv_delta = max(0, current_io.bytes_recv - self.last_bytes_recv)

            self.current_sent_rate = bytes_sent_delta / time_delta
            self.current_recv_rate = bytes_recv_delta / time_delta

            self.last_bytes_sent = current_io.bytes_sent
            self.last_bytes_recv = current_io.bytes_recv
            self.last_check_time = now

            entry = {
                "timestamp": time.strftime("%H:%M:%S", time.localtime(now)),
                "epoch": now,
                "sent_rate_bytes": self.current_sent_rate,
                "recv_rate_bytes": self.current_recv_rate,
                "sent_rate_kb": round(self.current_sent_rate / 1024, 2),
                "recv_rate_kb": round(self.current_recv_rate / 1024, 2),
                "total_sent_bytes": current_io.bytes_sent,
                "total_recv_bytes": current_io.bytes_recv,
                "formatted_sent": self.format_bytes(self.current_sent_rate) + "/s",
                "formatted_recv": self.format_bytes(self.current_recv_rate) + "/s"
            }
            self.history.append(entry)
            return entry
        except Exception as e:
            return {
                "timestamp": time.strftime("%H:%M:%S"),
                "sent_rate_bytes": 0.0,
                "recv_rate_bytes": 0.0,
                "sent_rate_kb": 0.0,
                "recv_rate_kb": 0.0,
                "error": str(e)
            }

    def get_history(self) -> List[Dict[str, Any]]:
        return list(self.history)

    def get_current_rates(self) -> Dict[str, Any]:
        return {
            "sent_rate_bytes": self.current_sent_rate,
            "recv_rate_bytes": self.current_recv_rate,
            "sent_rate_kb": round(self.current_sent_rate / 1024, 2),
            "recv_rate_kb": round(self.current_recv_rate / 1024, 2),
            "formatted_sent": self.format_bytes(self.current_sent_rate) + "/s",
            "formatted_recv": self.format_bytes(self.current_recv_rate) + "/s"
        }

    @staticmethod
    def format_bytes(b: float) -> str:
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if b < 1024.0:
                return f"{b:.1f} {unit}"
            b /= 1024.0
        return f"{b:.1f} PB"

