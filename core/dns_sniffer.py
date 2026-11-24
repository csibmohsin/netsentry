"""
NetSentry Live DNS Query Sniffer
Scapy-powered real-time DNS inspection, domain anomaly detection, and tunneling heuristics.
Developer: Mohsin
"""

import time
import math
import logging
import threading
from collections import deque
from datetime import datetime
from typing import Dict, Any, List, Optional

logger = logging.getLogger("NetSentry.DNSSniffer")

# Known high-risk or dynamic DNS TLDs and providers commonly abused by malware
SUSPICIOUS_TLDS = {
    ".top", ".xyz", ".buzz", ".fit", ".rest", ".tk", ".ml", ".ga", ".cf", ".gq",
    ".duckdns.org", ".ngrok.io", ".onion", ".bit", ".biz", ".cc", ".su"
}

def calculate_entropy(s: str) -> float:
    """Calculates Shannon entropy to detect DGA (Domain Generation Algorithm) randomized domains."""
    if not s:
        return 0.0
    prob = [float(s.count(c)) / len(s) for c in dict.fromkeys(list(s))]
    return -sum([p * math.log(p) / math.log(2.0) for p in prob])

class DNSSniffer:
    _instance = None
    _lock = threading.Lock()

    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            with cls._lock:
                if not cls._instance:
                    cls._instance = super().__new__(cls)
                    cls._instance._initialized = False
        return cls._instance

    def __init__(self, buffer_size: int = 500):
        if getattr(self, "_initialized", False):
            return
        self.buffer_size = buffer_size
        self.query_buffer: deque = deque(maxlen=buffer_size)
        self.running = False
        self.sniffer_thread = None
        self.data_lock = threading.Lock()
        self._initialized = True

    def start(self):
        """Starts the background DNS sniffing thread."""
        if self.running:
            return
        self.running = True
        self.sniffer_thread = threading.Thread(target=self._sniff_loop, daemon=True, name="NetSentry-DNS-Sniffer")
        self.sniffer_thread.start()
        logger.info("Live DNS Sniffer engine started.")

    def stop(self):
        """Stops the DNS sniffing thread."""
        self.running = False

    def _analyze_domain_threat(self, domain: str) -> tuple[bool, str]:
        """
        Heuristic rule evaluation to identify suspicious DNS requests.
        """
        if not domain:
            return False, ""

        d_lower = domain.lower()

        # Check Suspicious TLDs
        for tld in SUSPICIOUS_TLDS:
            if d_lower.endswith(tld):
                return True, f"High-risk or dynamic DNS domain extension ({tld})"

        # Check DNS Tunneling / Excessive Subdomain Length
        parts = d_lower.split('.')
        if len(d_lower) > 48:
            return True, f"Anomalously long domain name ({len(d_lower)} chars) - potential DNS tunneling or payload stage"

        # Check DGA (Domain Generation Algorithm) randomness on main label
        if parts:
            main_label = parts[0]
            if len(main_label) >= 12 and calculate_entropy(main_label) > 3.65:
                return True, "High Shannon entropy - possible automated DGA malware beaconing"

        return False, ""

    def _process_packet(self, pkt):
        try:
            from scapy.all import IP, IPv6, DNS, DNSQR, DNSRR

            if not pkt.haslayer(DNS):
                return

            dns = pkt[DNS]
            if not dns.qd:
                return

            # Extract client & server IPs
            src_ip = "Unknown"
            dst_ip = "Unknown"
            if pkt.haslayer(IP):
                src_ip = pkt[IP].src
                dst_ip = pkt[IP].dst
            elif pkt.haslayer(IPv6):
                src_ip = pkt[IPv6].src
                dst_ip = pkt[IPv6].dst

            is_response = (dns.qr == 1)
            client_ip = dst_ip if is_response else src_ip
            dns_server = src_ip if is_response else dst_ip

            # Extract Query Name and Type
            qname = dns.qd.qname.decode('utf-8', errors='ignore').rstrip('.')
            try:
                qtype_name = dns.qd.get_field('qtype').i2repr(dns.qd, dns.qd.qtype)
            except Exception:
                qtype_name = "A"

            # Extract Resolved Answers if DNS Response
            answers = []
            if is_response and dns.an:
                curr_rr = dns.an
                while curr_rr:
                    if hasattr(curr_rr, 'rdata'):
                        rdata_str = curr_rr.rdata
                        if isinstance(rdata_str, bytes):
                            rdata_str = rdata_str.decode('utf-8', errors='ignore')
                        answers.append(str(rdata_str))
                    curr_rr = getattr(curr_rr, 'payload', None)
                    if not isinstance(curr_rr, DNSRR):
                        break

            # Threat Analysis
            is_suspicious, reason = self._analyze_domain_threat(qname)

            now_epoch = time.time()
            entry = {
                "id": f"{int(now_epoch*1000)}",
                "timestamp": time.strftime("%H:%M:%S", time.localtime(now_epoch)),
                "iso_time": datetime.fromtimestamp(now_epoch).isoformat(),
                "domain": qname,
                "qtype": qtype_name,
                "client_ip": client_ip,
                "dns_server": dns_server,
                "is_response": is_response,
                "answers": answers[:6],
                "is_suspicious": is_suspicious,
                "suspicious_reason": reason
            }

            with self.data_lock:
                self.query_buffer.appendleft(entry)

            # Record in SQLite (asynchronously or throttled)
            if is_suspicious or is_response:
                from database.database import DatabaseManager
                DatabaseManager().record_dns_query(entry)

        except Exception as e:
            logger.debug("Error processing DNS packet: %s", e)

    def _sniff_loop(self):
        """Continuous packet capture loop targeting UDP/TCP port 53."""
        try:
            from scapy.all import sniff
            logger.info("Scapy sniffing started on udp port 53 or tcp port 53...")
            sniff(
                filter="udp port 53 or tcp port 53",
                prn=self._process_packet,
                store=False,
                stop_filter=lambda x: not self.running
            )
        except Exception as e:
            logger.error("Scapy sniffing terminated with error: %s", e)

    def get_queries(
        self,
        search: Optional[str] = None,
        suspicious_only: bool = False,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        with self.data_lock:
            queries = list(self.query_buffer)

        if search:
            s_lower = search.lower()
            queries = [q for q in queries if s_lower in q["domain"].lower() or s_lower in q["client_ip"]]

        if suspicious_only:
            queries = [q for q in queries if q["is_suspicious"]]

        return queries[:limit]

    def clear(self):
        with self.data_lock:
            self.query_buffer.clear()
        from database.database import DatabaseManager
        DatabaseManager().clear_dns_queries()

