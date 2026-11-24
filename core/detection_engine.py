"""
NetSentry Suspicious Activity Detection Engine
Multi-rule behavioral analysis with calibrated risk scoring and threat attribution.
Developer: Mohsin
"""

import os
import re
import logging
from typing import Dict, Any, List, Tuple, Set, Optional
from collections import defaultdict, deque
import time
from config import (
    SUSPICIOUS_PORTS,
    SUSPICIOUS_PATH_PATTERNS,
    RAPID_CONNECTION_THRESHOLD,
    UNEXPECTED_LISTENER_PORTS
)

logger = logging.getLogger("NetSentry.DetectionEngine")

# Common web browsers and legitimate network tools that naturally connect to diverse CDNs
LEGITIMATE_FANOUT_PROCS = {
    "chrome.exe", "msedge.exe", "firefox.exe", "brave.exe", "opera.exe",
    "steam.exe", "discord.exe", "slack.exe", "spotify.exe", "code.exe"
}

class DetectionEngine:
    def __init__(self):
        # Fan-out tracker: pid -> deque of (remote_ip, timestamp)
        self.proc_destinations: Dict[int, deque] = defaultdict(lambda: deque(maxlen=100))
        # Known destinations cache to detect newly observed destinations
        self.known_destinations: Set[str] = set()

    def register_seen_destination(self, ip: str):
        if ip and ip not in ("0.0.0.0", "127.0.0.1", "::1", "*"):
            self.known_destinations.add(ip)

    def analyze_connection(
        self,
        conn_data: Dict[str, Any],
        proc_info: Optional[Dict[str, Any]] = None,
        is_new_destination: bool = False
    ) -> Tuple[str, int, List[Dict[str, Any]]]:
        """
        Evaluates a network connection against detection rules.
        Returns:
            - overall_severity: 'SAFE', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'
            - risk_score: 0 to 100
            - alerts: List of triggered alert dicts
        """
        alerts = []
        risk_score = 0

        remote_ip = conn_data.get("remote_ip") or ""
        remote_port = conn_data.get("remote_port") or 0
        local_port = conn_data.get("local_port") or 0
        state = conn_data.get("connection_state") or ""
        protocol = conn_data.get("protocol") or "TCP"
        pid = conn_data.get("pid") or 0
        proc_name = (conn_data.get("process_name") or "").lower()
        exe_path = conn_data.get("exe_path") or ""
        duration = conn_data.get("duration_seconds") or 0.0

        # Extract digital signature info if available
        sig_info = proc_info.get("signature", {}) if proc_info else {}
        is_signed = sig_info.get("is_signed", True)
        sig_status = sig_info.get("status", "Unknown")

        # ---------------- Rule 1: Unusual Outbound Ports ----------------
        if remote_port in SUSPICIOUS_PORTS:
            tag, desc = SUSPICIOUS_PORTS[remote_port]
            severity = "HIGH" if remote_port in (4444, 31337, 1337, 5555, 6667) else "MEDIUM"
            score_addition = 35 if severity == "HIGH" else 20
            alerts.append({
                "rule_id": "RULE_UNUSUAL_PORT",
                "rule_name": f"Known Suspicious Port: {remote_port} ({tag})",
                "severity": severity,
                "reason": f"Outbound connection directed to port {remote_port} associated with {desc}.",
                "recommendation": "Inspect remote destination and verify whether this port aligns with authorized software behavior."
            })
            risk_score += score_addition
        elif remote_port > 49152 and state == "ESTABLISHED" and remote_port not in (8080, 8443):
            # Dynamic high port destination
            pass

        # ---------------- Rule 2: Unexpected Executable Path ----------------
        if exe_path and exe_path != "Access Denied":
            matched_pattern = None
            for pattern in SUSPICIOUS_PATH_PATTERNS:
                if re.search(re.escape(pattern), exe_path, re.IGNORECASE):
                    matched_pattern = pattern
                    break

            if matched_pattern:
                severity = "HIGH" if not is_signed else "MEDIUM"
                score_addition = 35 if not is_signed else 20
                alerts.append({
                    "rule_id": "RULE_SUSPICIOUS_PATH",
                    "rule_name": "Execution from Ephemeral/Staging Directory",
                    "severity": severity,
                    "reason": f"Process executable is located in a high-risk staging directory ({matched_pattern}): {exe_path}",
                    "recommendation": "Verify the integrity of this executable. Malware frequently stages payloads in temporary user folders."
                })
                risk_score += score_addition

        # ---------------- Rule 3: Unsigned / Untrusted Executable ----------------
        if exe_path and exe_path != "Access Denied" and sig_status not in ("Valid", "Unknown"):
            if not is_signed:
                # Unsigned binary communicating on network
                alerts.append({
                    "rule_id": "RULE_UNSIGNED_EXE",
                    "rule_name": "Unverified Digital Signature",
                    "severity": "LOW",
                    "reason": f"Executable file lacks a verified Authenticode digital signature (Status: {sig_status}).",
                    "recommendation": "Check publisher information and checksum of the binary."
                })
                risk_score += 10

        # ---------------- Rule 4: Process Destination Fan-Out ----------------
        if pid and remote_ip and not conn_data.get("is_private", False):
            now = time.time()
            proc_q = self.proc_destinations[pid]
            proc_q.append((remote_ip, now))

            # Filter events within last 30 seconds
            recent_unique_ips = {ip for ip, t in proc_q if now - t <= 30.0}
            if len(recent_unique_ips) >= RAPID_CONNECTION_THRESHOLD and proc_name not in LEGITIMATE_FANOUT_PROCS:
                alerts.append({
                    "rule_id": "RULE_IP_FANOUT",
                    "rule_name": "Rapid Connection Fan-Out",
                    "severity": "HIGH",
                    "reason": f"Process contacted {len(recent_unique_ips)} distinct external IPs within 30 seconds. Potential scanning, scraping, or C2 discovery.",
                    "recommendation": "Review process network behavior for port scanning or botnet activity."
                })
                risk_score += 30

        # ---------------- Rule 5: Unexpected Listening Ports on 0.0.0.0 ----------------
        if state == "LISTEN" and conn_data.get("local_ip") in ("0.0.0.0", "::"):
            if local_port in (21, 23, 1337, 4444, 5555, 31337):
                alerts.append({
                    "rule_id": "RULE_UNEXPECTED_LISTENER",
                    "rule_name": f"High-Risk Listening Service on Port {local_port}",
                    "severity": "CRITICAL",
                    "reason": f"Process opened a network listener on wildcard interface 0.0.0.0:{local_port}.",
                    "recommendation": "Investigate immediately. Unrestricted wildcard listener on sensitive port may indicate a backdoor."
                })
                risk_score += 50
            elif local_port in UNEXPECTED_LISTENER_PORTS and not is_signed:
                alerts.append({
                    "rule_id": "RULE_UNEXPECTED_LISTENER",
                    "rule_name": f"Unsigned Wildcard Service Listener (Port {local_port})",
                    "severity": "MEDIUM",
                    "reason": f"Unsigned process is listening on wildcard network interface on port {local_port}.",
                    "recommendation": "Verify whether an incoming server service is intended on this host."
                })
                risk_score += 20

        # ---------------- Rule 6: Newly Observed Network Destination ----------------
        if is_new_destination and remote_ip and not conn_data.get("is_private", False):
            # As per guideline: do not classify as malware merely because it's unfamiliar
            alerts.append({
                "rule_id": "RULE_NEW_DESTINATION",
                "rule_name": "Newly Observed External Destination",
                "severity": "LOW",
                "reason": f"NetSentry has not previously observed network traffic to destination {remote_ip}.",
                "recommendation": "Informational context. Destination IP will be cached in historical logs."
            })
            risk_score += 5

        # ---------------- Rule 7: Repeated Failed / SYN_SENT Connection ----------------
        if state == "SYN_SENT" and duration > 10.0:
            alerts.append({
                "rule_id": "RULE_RAPID_FAILED",
                "rule_name": "Hanging Connection in SYN_SENT State",
                "severity": "LOW",
                "reason": f"Connection has remained in SYN_SENT towards {remote_ip}:{remote_port} for {int(duration)}s without ACK handshake completion.",
                "recommendation": "Remote server may be unresponsive, firewalled, or connection is being filtered."
            })
            risk_score += 10

        # ---------------- Rule 8: Long-Lived Persistent Connection with Anomalies ----------------
        if duration > 3600.0 and remote_port in SUSPICIOUS_PORTS:
            alerts.append({
                "rule_id": "RULE_PERSISTENT_UNUSUAL",
                "rule_name": "Long-Lived Persistent Connection to Suspicious Port",
                "severity": "HIGH",
                "reason": f"Connection to port {remote_port} has persisted continuously for over 1 hour ({int(duration // 60)} minutes).",
                "recommendation": "Verify persistent remote channel or reverse shell tunnel."
            })
            risk_score += 25

        # Calculate overall severity
        risk_score = min(100, risk_score)
        if risk_score >= 70:
            overall_severity = "CRITICAL"
        elif risk_score >= 45:
            overall_severity = "HIGH"
        elif risk_score >= 20:
            overall_severity = "MEDIUM"
        elif risk_score > 0:
            overall_severity = "LOW"
        else:
            overall_severity = "SAFE"

        # Record this destination as seen
        if remote_ip:
            self.register_seen_destination(remote_ip)

        return overall_severity, risk_score, alerts
