"""
NetSentry Process Monitor
Real-time Windows process inspection, digital signature verification, and protected termination.
Developer: Mohsin
"""

import os
import sys
import psutil
import logging
import subprocess
import threading
import queue
from typing import Dict, Any, List, Optional
from config import CRITICAL_SYSTEM_PROCESSES

logger = logging.getLogger("NetSentry.ProcessMonitor")

class ProcessMonitor:
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
        self.signature_cache: Dict[str, Dict[str, Any]] = {}
        self.signature_lock = threading.Lock()
        self.sig_queue = queue.Queue()
        self.queued_paths = set()
        
        # Start background worker for Authenticode signatures
        self.sig_worker = threading.Thread(target=self._signature_worker, daemon=True, name="NetSentry-SigWorker")
        self.sig_worker.start()
        self._initialized = True

    def is_critical_process(self, pid: int, name: str) -> bool:
        """
        Determines whether a process is an essential Windows OS component.
        """
        if pid in (0, 4):  # System Idle Process, System kernel
            return True
        if name and name.lower() in CRITICAL_SYSTEM_PROCESSES:
            return True
        return False

    def verify_digital_signature(self, exe_path: str) -> Dict[str, Any]:
        """
        Retrieves Authenticode signature information.
        Fast path for Windows system binaries, and asynchronous queue for third-party executables.
        """
        if not exe_path or not os.path.exists(exe_path):
            return {"status": "Unknown", "signer": "File not found / inaccessible", "is_signed": False}

        with self.signature_lock:
            if exe_path in self.signature_cache:
                return self.signature_cache[exe_path]

        # Fast path for known Windows System32 core binaries
        lower_path = exe_path.lower()
        if r"c:\windows\system32" in lower_path or r"c:\windows\syswow64" in lower_path:
            fast_info = {"status": "Valid", "is_signed": True, "signer": "Microsoft Windows Publisher"}
            with self.signature_lock:
                self.signature_cache[exe_path] = fast_info
            return fast_info

        # Queue for background verification to avoid blocking the network polling loop
        with self.signature_lock:
            if exe_path not in self.queued_paths:
                self.queued_paths.add(exe_path)
                self.sig_queue.put(exe_path)

        # Return provisional status while background worker resolves
        return {"status": "Verifying...", "is_signed": True, "signer": "Authenticode inspection in background"}

    def _signature_worker(self):
        """Background thread executing PowerShell Get-AuthenticodeSignature without stalling monitoring."""
        while True:
            try:
                exe_path = self.sig_queue.get(timeout=2.0)
                try:
                    cmd = [
                        "powershell.exe",
                        "-NoProfile",
                        "-NonInteractive",
                        "-Command",
                        f"(Get-AuthenticodeSignature -FilePath '{exe_path}').Status"
                    ]
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=5.0)
                    status_text = result.stdout.strip()
                    is_valid = status_text.lower() == "valid"
                    sig_info = {
                        "status": status_text if status_text else "Unsigned",
                        "is_signed": is_valid,
                        "signer": "Verified Publisher" if is_valid else "Unverified / Self-signed"
                    }
                    with self.signature_lock:
                        self.signature_cache[exe_path] = sig_info
                except Exception as e:
                    with self.signature_lock:
                        self.signature_cache[exe_path] = {
                            "status": "Unknown",
                            "is_signed": False,
                            "signer": f"Inspection error: {str(e)}"
                        }
                finally:
                    self.sig_queue.task_done()
            except queue.Empty:
                continue
            except Exception:
                continue

    def get_process_summary(self, pid: int) -> Optional[Dict[str, Any]]:
        """
        Retrieves detailed information for a specific PID.
        """
        try:
            proc = psutil.Process(pid)
            with proc.oneshot():
                name = proc.name()
                try:
                    exe = proc.exe()
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    exe = "Access Denied"

                try:
                    cmdline = proc.cmdline()
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    cmdline = []

                try:
                    ppid = proc.ppid()
                    parent_name = psutil.Process(ppid).name() if ppid else "None"
                except Exception:
                    ppid = None
                    parent_name = "Unknown"

                try:
                    cpu_percent = proc.cpu_percent(interval=None)
                except Exception:
                    cpu_percent = 0.0

                try:
                    mem_info = proc.memory_info()
                    mem_rss = mem_info.rss
                    mem_mb = round(mem_rss / (1024 * 1024), 2)
                except Exception:
                    mem_rss = 0
                    mem_mb = 0.0

                try:
                    connections = proc.net_connections(kind="all")
                    conn_count = len(connections)
                except Exception:
                    connections = []
                    conn_count = 0

                try:
                    username = proc.username()
                except Exception:
                    username = "SYSTEM / Unknown"

                try:
                    create_time = proc.create_time()
                except Exception:
                    create_time = 0.0

                is_critical = self.is_critical_process(pid, name)
                sig_info = self.verify_digital_signature(exe) if exe and exe != "Access Denied" else {"status": "Unknown", "is_signed": False}

                return {
                    "pid": pid,
                    "name": name,
                    "exe": exe,
                    "ppid": ppid,
                    "parent_name": parent_name,
                    "cmdline": " ".join(cmdline) if cmdline else "",
                    "cpu_percent": round(cpu_percent, 1),
                    "memory_bytes": mem_rss,
                    "memory_mb": mem_mb,
                    "connection_count": conn_count,
                    "username": username,
                    "create_time": create_time,
                    "is_critical": is_critical,
                    "signature": sig_info
                }
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return None

    def get_all_network_processes(self, active_pids: Optional[set] = None) -> List[Dict[str, Any]]:
        """
        Lists all processes currently utilizing the network or running on the system.
        If active_pids is provided, prioritizes or enriches processes with active network connections.
        """
        process_list = []
        for proc in psutil.process_iter(['pid', 'name', 'exe', 'ppid', 'cpu_percent', 'memory_info', 'username']):
            try:
                info = proc.info
                pid = info['pid']
                name = info['name'] or "Unknown"
                exe = info['exe'] or ""
                ppid = info['ppid']
                
                # Check memory
                mem = info['memory_info']
                mem_rss = mem.rss if mem else 0
                mem_mb = round(mem_rss / (1024 * 1024), 2)

                is_critical = self.is_critical_process(pid, name)
                
                process_list.append({
                    "pid": pid,
                    "name": name,
                    "exe": exe,
                    "ppid": ppid,
                    "cpu_percent": round(info['cpu_percent'] or 0.0, 1),
                    "memory_mb": mem_mb,
                    "username": info.get('username') or "",
                    "is_critical": is_critical,
                    "has_active_network": (pid in active_pids) if active_pids else False
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        # Sort so processes with network activity and higher memory come first
        process_list.sort(key=lambda x: (x["has_active_network"], x["memory_mb"]), reverse=True)
        return process_list

    def terminate_process(self, pid: int) -> Dict[str, Any]:
        """
        Safely attempts to terminate a process by PID.
        Guards against critical Windows processes.
        """
        try:
            if not psutil.pid_exists(pid):
                return {
                    "success": False,
                    "error": "NOT_FOUND",
                    "message": f"Process PID {pid} no longer exists."
                }

            proc = psutil.Process(pid)
            name = proc.name()

            # Safety check: Prevent OS crash
            if self.is_critical_process(pid, name):
                return {
                    "success": False,
                    "error": "CRITICAL_SYSTEM_PROCESS",
                    "message": f"Termination Blocked: '{name}' (PID: {pid}) is a vital Windows system process. Terminating it would crash or corrupt the operating system."
                }

            # Count sockets that will be closed
            try:
                sockets = len(proc.net_connections(kind="all"))
            except Exception:
                sockets = 0

            # Terminate
            proc.terminate()
            try:
                proc.wait(timeout=2.0)
            except psutil.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=2.0)

            return {
                "success": True,
                "pid": pid,
                "process_name": name,
                "sockets_closed": sockets,
                "message": f"Successfully terminated process '{name}' (PID: {pid}). Note: Closing this process has permanently shut down all {sockets} associated network socket(s)."
            }

        except psutil.AccessDenied:
            return {
                "success": False,
                "error": "ACCESS_DENIED",
                "message": f"Access Denied: NetSentry requires Administrator privileges to terminate process PID {pid}. Please run NetSentry as Administrator."
            }
        except Exception as e:
            logger.error("Failed to terminate process %s: %s", pid, e)
            return {
                "success": False,
                "error": "EXECUTION_ERROR",
                "message": f"Failed to terminate process PID {pid}: {str(e)}"
            }
