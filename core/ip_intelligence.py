"""
NetSentry IP Intelligence Module
Integrates ipwho.is with smart caching, non-public IP filtering, and background lookups.
Developer: Mohsin
"""

import ipaddress
import logging
import threading
import time
import queue
import requests
from typing import Dict, Any, Optional
from config import IPWHOIS_API_URL, IP_LOOKUP_RATE_LIMIT
from database.database import DatabaseManager

logger = logging.getLogger("NetSentry.IPIntelligence")

GEO_DISCLAIMER = "Approximate IP geolocation provided by ipwho.is based on ISP routing. Geolocation estimates indicate ISP routing centers and are not exact device physical locations."

class IPIntelligenceManager:
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
        self.db = DatabaseManager()
        self.memory_cache: Dict[str, Dict[str, Any]] = {}
        # Preload all previously cached IPs from persistent SQLite database
        try:
            preloaded = self.db.load_all_cached_ips_into_dict()
            self.memory_cache.update(preloaded)
            logger.info("Preloaded %d cached IP intelligence records from database.", len(preloaded))
        except Exception as e:
            logger.warning("Could not preload cached IPs: %s", e)

        self.lookup_queue: queue.Queue = queue.Queue()
        self.pending_ips = set()
        self.attempted_ips = set(self.memory_cache.keys())
        self.pending_lock = threading.Lock()
        self.last_api_call = 0.0
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "NetSentry-Network-Monitor/1.0"
        })

        # Start asynchronous lookup worker thread
        self.worker_thread = threading.Thread(target=self._lookup_worker, daemon=True)
        self.worker_thread.start()
        self._initialized = True

    @staticmethod
    def is_private_or_special(ip_str: str) -> bool:
        """
        Determines whether the given IP is private, loopback, multicast, link-local, or special.
        """
        if not ip_str or ip_str in ("0.0.0.0", "::", "127.0.0.1", "*"):
            return True
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            return (
                ip_obj.is_private or
                ip_obj.is_loopback or
                ip_obj.is_link_local or
                ip_obj.is_multicast or
                ip_obj.is_reserved or
                ip_obj.is_unspecified
            )
        except ValueError:
            return True

    def _create_private_response(self, ip_str: str) -> Dict[str, Any]:
        """
        Synthesizes intelligence for private / loopback IP addresses without external network calls.
        """
        return {
            "ip": ip_str,
            "ip_version": 6 if ":" in ip_str else 4,
            "is_valid": True,
            "is_private": True,
            "country": "Local Network",
            "country_code": "LAN",
            "region": "Private Subnet",
            "city": "Internal Host",
            "latitude": None,
            "longitude": None,
            "isp": "Local Network Interface",
            "org": "Private / RFC 1918 / Loopback",
            "asn": "N/A",
            "domain": "local",
            "timezone": "Local Time",
            "disclaimer": "Local / Private IP address. External intelligence lookups are bypassed.",
            "cached": True
        }

    def get_ip_info(self, ip_str: str, allow_queue: bool = True) -> Dict[str, Any]:
        """
        Retrieves IP intelligence from memory cache or database cache.
        If not cached and public, queues for asynchronous background fetching.
        """
        if not ip_str or ip_str == "*":
            return self._create_private_response("0.0.0.0")

        # Check if local/private
        if self.is_private_or_special(ip_str):
            return self._create_private_response(ip_str)

        # Check in-memory cache
        if ip_str in self.memory_cache:
            return self.memory_cache[ip_str]

        # Check database cache
        db_record = self.db.get_cached_ip(ip_str)
        if db_record:
            db_record["is_private"] = False
            db_record["disclaimer"] = GEO_DISCLAIMER
            db_record["cached"] = True
            self.memory_cache[ip_str] = db_record
            return db_record

        # Enqueue for background fetching ONLY if never attempted before
        if allow_queue:
            with self.pending_lock:
                if ip_str not in self.pending_ips and ip_str not in self.attempted_ips:
                    self.pending_ips.add(ip_str)
                    self.attempted_ips.add(ip_str)
                    self.lookup_queue.put(ip_str)

        # Return a pending placeholder so callers never block
        return {
            "ip": ip_str,
            "ip_version": 6 if ":" in ip_str else 4,
            "is_valid": True,
            "is_private": False,
            "country": "Resolving...",
            "country_code": "",
            "region": "Looking up",
            "city": "Looking up",
            "latitude": None,
            "longitude": None,
            "isp": "Fetching...",
            "org": "Fetching...",
            "asn": "Pending",
            "domain": "",
            "timezone": "Pending",
            "disclaimer": GEO_DISCLAIMER,
            "cached": False,
            "resolving": True
        }

    def fetch_ip_direct(self, ip_str: str) -> Dict[str, Any]:
        """
        Directly performs lookup for an IP, updates caches, and returns result.
        """
        if not ip_str or self.is_private_or_special(ip_str):
            return self._create_private_response(ip_str)

        # Check cache
        if ip_str in self.memory_cache:
            return self.memory_cache[ip_str]

        db_rec = self.db.get_cached_ip(ip_str)
        if db_rec:
            db_rec["is_private"] = False
            db_rec["disclaimer"] = GEO_DISCLAIMER
            self.memory_cache[ip_str] = db_rec
            return db_rec

        # Rate limit throttling
        elapsed = time.time() - self.last_api_call
        if elapsed < IP_LOOKUP_RATE_LIMIT:
            time.sleep(IP_LOOKUP_RATE_LIMIT - elapsed)

        result = self._query_api(ip_str)
        self.last_api_call = time.time()

        if result:
            self.memory_cache[ip_str] = result
            self.db.save_cached_ip(result)
            return result
        else:
            fallback = {
                "ip": ip_str,
                "ip_version": 6 if ":" in ip_str else 4,
                "is_valid": False,
                "is_private": False,
                "country": "Lookup Unavailable",
                "country_code": "",
                "region": "External Network",
                "city": "Remote Node",
                "latitude": None,
                "longitude": None,
                "isp": "Provider Unavailable",
                "org": "Public Network",
                "asn": "N/A",
                "domain": "",
                "timezone": "UTC",
                "disclaimer": GEO_DISCLAIMER,
                "cached": True
            }
            # Cache failure locally so we never retry and never hit timeouts repeatedly
            self.memory_cache[ip_str] = fallback
            self.db.save_cached_ip(fallback)
            return fallback

    def _query_api(self, ip_str: str) -> Optional[Dict[str, Any]]:
        try:
            url = IPWHOIS_API_URL.format(ip=ip_str)
            response = self.session.get(url, timeout=3.5)
            if response.status_code == 200:
                data = response.json()
                if data.get("success", True):
                    connection_info = data.get("connection", {})
                    timezone_info = data.get("timezone", {})
                    
                    return {
                        "ip": data.get("ip", ip_str),
                        "ip_version": data.get("type", "IPv4"),
                        "is_valid": True,
                        "is_private": False,
                        "country": data.get("country", "Unknown"),
                        "country_code": data.get("country_code", ""),
                        "region": data.get("region", ""),
                        "city": data.get("city", ""),
                        "latitude": data.get("latitude"),
                        "longitude": data.get("longitude"),
                        "isp": connection_info.get("isp") or data.get("isp", "Unknown ISP"),
                        "org": connection_info.get("org") or data.get("org", "Unknown Org"),
                        "asn": connection_info.get("asn") or data.get("asn", "N/A"),
                        "domain": connection_info.get("domain") or data.get("domain", ""),
                        "timezone": timezone_info.get("id") or timezone_info.get("current_time", "Unknown"),
                        "disclaimer": GEO_DISCLAIMER,
                        "cached": False,
                        "raw": data
                    }
                else:
                    logger.warning("ipwho.is reported failure for IP %s: %s", ip_str, data.get("message"))
            elif response.status_code == 429:
                logger.warning("ipwho.is rate limit reached (HTTP 429). Will back off.")
                time.sleep(3.0)
        except requests.exceptions.Timeout:
            logger.warning("ipwho.is timeout for IP %s", ip_str)
        except Exception as e:
            logger.error("Exception querying ipwho.is for IP %s: %s", ip_str, e)
        return None

    def _lookup_worker(self):
        """
        Background worker that processes IP lookups sequentially with rate limiting.
        """
        while True:
            try:
                ip_str = self.lookup_queue.get(timeout=1.0)
                try:
                    # Double check if in cache
                    if ip_str not in self.memory_cache and not self.db.get_cached_ip(ip_str):
                        elapsed = time.time() - self.last_api_call
                        if elapsed < IP_LOOKUP_RATE_LIMIT:
                            time.sleep(IP_LOOKUP_RATE_LIMIT - elapsed)

                        data = self._query_api(ip_str)
                        self.last_api_call = time.time()

                        if data:
                            self.memory_cache[ip_str] = data
                            self.db.save_cached_ip(data)
                            logger.info("Successfully resolved and cached IP: %s (%s, %s)", ip_str, data.get("country"), data.get("city"))
                        else:
                            # Cache fallback to prevent repeated API hitting
                            fallback = {
                                "ip": ip_str,
                                "ip_version": 6 if ":" in ip_str else 4,
                                "is_valid": False,
                                "is_private": False,
                                "country": "Lookup Unavailable",
                                "country_code": "",
                                "region": "External Network",
                                "city": "Remote Node",
                                "latitude": None,
                                "longitude": None,
                                "isp": "Provider Unavailable",
                                "org": "Public Network",
                                "asn": "N/A",
                                "domain": "",
                                "timezone": "UTC",
                                "disclaimer": GEO_DISCLAIMER,
                                "cached": True
                            }
                            self.memory_cache[ip_str] = fallback
                            self.db.save_cached_ip(fallback)
                finally:
                    with self.pending_lock:
                        self.pending_ips.discard(ip_str)
                    self.lookup_queue.task_done()
            except queue.Empty:
                continue
            except Exception as e:
                logger.error("Unexpected error in IP lookup worker: %s", e)
                time.sleep(1.0)

