"""
NetSentry REST API Endpoints
Developer: Mohsin
"""

import os
import json
import logging
from typing import Optional, List
from fastapi import APIRouter, HTTPException, Query, Response, Body
from pydantic import BaseModel
from core.network_monitor import NetworkMonitor
from core.process_monitor import ProcessMonitor
from core.ip_intelligence import IPIntelligenceManager
from core.history_manager import HistoryManager
from core.dns_sniffer import DNSSniffer
from config import HISTORY_RETENTION_DAYS, MONITOR_INTERVAL

logger = logging.getLogger("NetSentry.API")

router = APIRouter(prefix="/api")

monitor = NetworkMonitor()
process_monitor = ProcessMonitor()
ip_intelligence = IPIntelligenceManager()
history_manager = HistoryManager()
dns_sniffer = DNSSniffer()

# ----------------- Dashboard & Overview -----------------
@router.get("/overview")
def get_dashboard_overview():
    """
    Returns high-level overview metrics, system traffic rates, active alert count, and top processes.
    """
    state = monitor.get_live_state()
    connections = state["connections"]
    stats = state["stats"]

    # Calculate top active processes by open connection count
    proc_counter = {}
    for c in connections:
        pname = c.get("process_name") or "Unknown"
        proc_counter[pname] = proc_counter.get(pname, 0) + 1
    
    top_processes = sorted(
        [{"name": k, "connections": v} for k, v in proc_counter.items()],
        key=lambda x: x["connections"],
        reverse=True
    )[:8]

    return {
        "status": "online",
        "stats": stats,
        "traffic_history": state["traffic_history"][-30:],
        "recent_alerts": state["recent_alerts"],
        "top_processes": top_processes
    }

# ----------------- Live Connections Explorer -----------------
@router.get("/connections")
def get_live_connections(
    search: Optional[str] = Query(None, description="Search by process name or executable path"),
    protocol: Optional[str] = Query(None, description="Filter by TCP or UDP"),
    state: Optional[str] = Query(None, description="Filter by connection state (e.g. ESTABLISHED, LISTEN)"),
    remote_ip: Optional[str] = Query(None, description="Filter by remote IP"),
    risk: Optional[str] = Query(None, description="Filter by risk status (SAFE, LOW, MEDIUM, HIGH, CRITICAL)"),
    network_scope: str = Query("ALL", description="Filter by network scope: 'ALL', 'PUBLIC_ONLY' (Exclude Local/LAN), 'LOCAL_ONLY'"),
    sort_by: str = Query("duration", description="Sort by duration, pid, name, or risk"),
    sort_desc: bool = Query(True, description="Sort descending"),
    limit: int = Query(500, description="Max connections to return"),
    offset: int = Query(0, description="Pagination offset")
):
    """
    Returns filtered and sorted active connections.
    """
    live_state = monitor.get_live_state()
    conns = live_state["connections"]

    # Filtering
    if search:
        s_term = search.lower()
        conns = [c for c in conns if s_term in c["process_name"].lower() or s_term in c.get("exe_path", "").lower()]

    if protocol and protocol.upper() != "ALL":
        conns = [c for c in conns if c["protocol"].upper() == protocol.upper()]

    if state and state.upper() != "ALL":
        conns = [c for c in conns if c["connection_state"].upper() == state.upper()]

    if remote_ip:
        conns = [c for c in conns if remote_ip in c["remote_ip"]]

    if risk and risk.upper() != "ALL":
        conns = [c for c in conns if c["risk_level"].upper() == risk.upper()]

    # Network Scope Filtering (Public / WAN Only vs Local / LAN Only)
    if network_scope == "PUBLIC_ONLY":
        conns = [
            c for c in conns
            if c.get("remote_ip")
            and c.get("remote_ip") not in ("0.0.0.0", "127.0.0.1", "::1", "*")
            and not (c.get("intelligence", {}).get("is_private") if c.get("intelligence") else False)
            and not ip_intelligence.is_private_or_special(c.get("remote_ip"))
        ]
    elif network_scope == "LOCAL_ONLY":
        conns = [
            c for c in conns
            if not c.get("remote_ip")
            or c.get("remote_ip") in ("0.0.0.0", "127.0.0.1", "::1", "*")
            or (c.get("intelligence", {}).get("is_private") if c.get("intelligence") else False)
            or ip_intelligence.is_private_or_special(c.get("remote_ip"))
            or c.get("connection_state") == "LISTEN"
        ]

    # Sorting
    if sort_by == "duration":
        conns.sort(key=lambda x: x.get("duration_seconds", 0.0), reverse=sort_desc)
    elif sort_by == "pid":
        conns.sort(key=lambda x: (x.get("pid") or 0), reverse=sort_desc)
    elif sort_by == "name":
        conns.sort(key=lambda x: x.get("process_name", "").lower(), reverse=sort_desc)
    elif sort_by == "risk":
        conns.sort(key=lambda x: x.get("risk_score", 0), reverse=sort_desc)
    elif sort_by == "remote_ip":
        conns.sort(key=lambda x: x.get("remote_ip", ""), reverse=sort_desc)

    total_matched = len(conns)
    paginated = conns[offset:offset + limit]

    return {
        "total": total_matched,
        "returned": len(paginated),
        "limit": limit,
        "offset": offset,
        "connections": paginated
    }

@router.get("/connections/details")
def get_connection_details(key: str = Query(..., description="Unique connection key")):
    """
    Returns exhaustive details for an individual connection.
    """
    conn = monitor.get_connection(key)
    if not conn:
        # Check historical records
        records = history_manager.query_connections(limit=1, offset=0)
        found = None
        for r in records.get("records", []):
            if r.get("connection_key") == key:
                found = r
                break
        if not found:
            raise HTTPException(status_code=404, detail="Connection not found or already closed.")
        conn = found

    # Enrich with full process summary and IP intelligence
    pid = conn.get("pid")
    proc_info = process_monitor.get_process_summary(pid) if pid else None
    remote_ip = conn.get("remote_ip")
    intel = ip_intelligence.get_ip_info(remote_ip, allow_queue=False) if remote_ip else {}

    return {
        "connection": conn,
        "process": proc_info,
        "intelligence": intel
    }

# ----------------- Process Monitor & Explorer -----------------
@router.get("/processes")
def get_processes(search: Optional[str] = Query(None)):
    """
    Lists running processes with CPU, memory, socket counts, and critical status.
    """
    live_conns = monitor.get_live_state()["connections"]
    active_pids = {c["pid"] for c in live_conns if c["pid"]}
    
    # Count sockets per PID
    socket_counts = {}
    for c in live_conns:
        p = c["pid"]
        if p:
            socket_counts[p] = socket_counts.get(p, 0) + 1

    procs = process_monitor.get_all_network_processes(active_pids=active_pids)
    
    for p in procs:
        p["active_sockets"] = socket_counts.get(p["pid"], 0)

    if search:
        s_term = search.lower()
        procs = [p for p in procs if s_term in p["name"].lower() or s_term in p.get("exe", "").lower() or s_term == str(p["pid"])]

    return {
        "total": len(procs),
        "processes": procs
    }

@router.get("/processes/{pid}")
def get_process_detail(pid: int):
    """
    Returns in-depth process inspection details.
    """
    info = process_monitor.get_process_summary(pid)
    if not info:
        raise HTTPException(status_code=404, detail=f"Process PID {pid} not found or access denied.")
    
    # Associated connections
    live_conns = [c for c in monitor.get_live_state()["connections"] if c.get("pid") == pid]
    return {
        "process": info,
        "active_connections": live_conns
    }

class TerminateRequest(BaseModel):
    confirm: bool = False

@router.post("/processes/{pid}/terminate")
def terminate_process_endpoint(pid: int, body: TerminateRequest):
    """
    Terminates a process with mandatory confirmation and protection for critical system processes.
    """
    if not body.confirm:
        raise HTTPException(status_code=400, detail="Action requires explicit user confirmation.")

    result = process_monitor.terminate_process(pid)
    if not result.get("success"):
        raise HTTPException(status_code=403 if "CRITICAL" in result.get("error", "") else 400, detail=result["message"])
    return result

# ----------------- IP Intelligence -----------------
@router.get("/intelligence/{ip}")
def get_ip_intel(ip: str):
    """
    Retrieves IP geolocation, ASN, ISP details from cache or ipwho.is.
    """
    info = ip_intelligence.fetch_ip_direct(ip)
    return info

@router.get("/intelligence/cache/all")
def get_cached_ips(limit: int = 100):
    """
    Returns list of cached IP intelligence records.
    """
    cached = history_manager.db.get_all_cached_ips(limit=limit)
    return {
        "total": len(cached),
        "cached_ips": cached
    }

# ----------------- Long-Term History & Analytics -----------------
@router.get("/history/connections")
def query_history(
    start_time: Optional[str] = Query(None),
    end_time: Optional[str] = Query(None),
    process_name: Optional[str] = Query(None),
    remote_ip: Optional[str] = Query(None),
    protocol: Optional[str] = Query(None),
    risk_level: Optional[str] = Query(None),
    limit: int = Query(100),
    offset: int = Query(0)
):
    """
    Queries historical connection logs from persistent SQLite database.
    """
    return history_manager.query_connections(
        start_time=start_time,
        end_time=end_time,
        process_name=process_name,
        remote_ip=remote_ip,
        protocol=protocol,
        risk_level=risk_level,
        limit=limit,
        offset=offset
    )

@router.get("/history/alerts")
def query_alerts(
    severity: Optional[str] = Query(None),
    process_name: Optional[str] = Query(None),
    remote_ip: Optional[str] = Query(None),
    limit: int = Query(100),
    offset: int = Query(0)
):
    """
    Queries persistent detection alerts history.
    """
    alerts = history_manager.query_alerts(
        severity=severity,
        process_name=process_name,
        remote_ip=remote_ip,
        limit=limit,
        offset=offset
    )
    return {
        "total": len(alerts),
        "alerts": alerts
    }

@router.get("/history/timeline")
def query_timeline(hours: int = Query(24)):
    """
    Returns activity aggregation timeline for charts.
    """
    timeline = history_manager.get_timeline(hours=hours)
    return {
        "hours": hours,
        "timeline": timeline
    }

@router.post("/history/cleanup")
def cleanup_history(days: int = Query(HISTORY_RETENTION_DAYS)):
    """
    Triggers automatic or configurable retention database vacuum.
    """
    result = history_manager.cleanup(days=days)
    return {
        "message": f"Cleaned up records older than {days} days.",
        "result": result
    }

# ----------------- Traffic Rates -----------------
@router.get("/traffic")
def get_traffic_rates():
    """
    Returns recent system network I/O traffic rates.
    """
    rates = monitor.traffic_monitor.get_current_rates()
    history = monitor.traffic_monitor.get_history()
    return {
        "current": rates,
        "history": history
    }

# ----------------- Data Export (CSV & JSON) -----------------
@router.get("/export/csv")
def export_csv_data(dataset: str = Query("connections", description="Dataset: 'connections', 'processes', or 'history'")):
    """
    Generates and returns downloadable CSV data.
    """
    if dataset == "connections":
        data = monitor.get_live_state()["connections"]
        csv_str = history_manager.export_csv(data)
        filename = "netsentry_live_connections.csv"
    elif dataset == "history":
        res = history_manager.query_connections(limit=2000)
        csv_str = history_manager.export_csv(res["records"])
        filename = "netsentry_connection_history.csv"
    elif dataset == "processes":
        procs = process_monitor.get_all_network_processes()
        import io, csv
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=["pid", "name", "exe", "ppid", "cpu_percent", "memory_mb", "username", "is_critical"])
        writer.writeheader()
        for p in procs:
            writer.writerow({k: p.get(k, "") for k in writer.fieldnames})
        csv_str = output.getvalue()
        filename = "netsentry_processes.csv"
    else:
        raise HTTPException(status_code=400, detail="Invalid dataset specified.")

    return Response(
        content=csv_str,
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )

@router.get("/export/json")
def export_json_data(dataset: str = Query("connections")):
    """
    Generates and returns downloadable JSON data.
    """
    if dataset == "connections":
        data = monitor.get_live_state()["connections"]
        json_str = history_manager.export_json(data)
        filename = "netsentry_live_connections.json"
    elif dataset == "history":
        res = history_manager.query_connections(limit=2000)
        json_str = history_manager.export_json(res["records"])
        filename = "netsentry_history.json"
    elif dataset == "alerts":
        alerts = history_manager.query_alerts(limit=1000)
        json_str = history_manager.export_json(alerts)
        filename = "netsentry_alerts.json"
    else:
        raise HTTPException(status_code=400, detail="Invalid dataset specified.")

    return Response(
        content=json_str,
        media_type="application/json",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )

# ----------------- DNS Sniffer -----------------
@router.get("/dns/queries")
def get_dns_queries(
    search: Optional[str] = Query(None, description="Search query by domain name or client IP"),
    suspicious_only: bool = Query(False, description="Filter only suspicious DNS requests"),
    limit: int = Query(100, description="Max queries to return")
):
    """
    Returns live sniffed DNS queries with threat heuristics.
    """
    queries = dns_sniffer.get_queries(search=search, suspicious_only=suspicious_only, limit=limit)
    return {
        "total": len(queries),
        "queries": queries
    }

@router.post("/dns/clear")
def clear_dns_queries():
    dns_sniffer.clear()
    return {"message": "DNS query log cleared."}

# ----------------- Interactive World Threat Map Data -----------------
@router.get("/map/endpoints")
def get_map_endpoints():
    """
    Returns geolocated active remote endpoints for the interactive Leaflet World Threat Map.
    Zero latency - reads strictly from local memory and pre-cached intelligence.
    """
    conns = monitor.get_live_state()["connections"]
    seen_ips = set()
    map_points = []
    country_counts = {}
    high_risk_count = 0

    for c in conns:
        rip = c.get("remote_ip")
        if not rip or rip in ("0.0.0.0", "127.0.0.1", "::1", "*") or rip in seen_ips:
            continue

        intel = c.get("intelligence") or ip_intelligence.get_ip_info(rip, allow_queue=False)
        if intel and not intel.get("is_private") and intel.get("latitude") and intel.get("longitude"):
            seen_ips.add(rip)
            country = intel.get("country", "Unknown")
            country_counts[country] = country_counts.get(country, 0) + 1

            if c.get("risk_level") in ("HIGH", "CRITICAL"):
                high_risk_count += 1

            map_points.append({
                "ip": rip,
                "port": c.get("remote_port", 0),
                "latitude": intel["latitude"],
                "longitude": intel["longitude"],
                "country": country,
                "country_code": intel.get("country_code", ""),
                "city": intel.get("city", "Unknown City"),
                "isp": intel.get("isp") or intel.get("org") or "Unknown ISP",
                "asn": intel.get("asn", "N/A"),
                "domain": intel.get("domain", ""),
                "process_name": c.get("process_name", "Unknown"),
                "pid": c.get("pid"),
                "protocol": c.get("protocol", "TCP"),
                "risk_level": c.get("risk_level", "SAFE"),
                "risk_score": c.get("risk_score", 0),
                "duration": c.get("duration_formatted", "0s"),
                "connection_key": c.get("connection_key")
            })

    top_countries = sorted(
        [{"country": k, "count": v} for k, v in country_counts.items()],
        key=lambda x: x["count"],
        reverse=True
    )[:6]

    return {
        "total_endpoints": len(map_points),
        "high_risk_count": high_risk_count,
        "top_countries": top_countries,
        "endpoints": map_points
    }

# ----------------- Configuration Settings -----------------
@router.get("/config")
def get_config():
    return {
        "monitor_interval": MONITOR_INTERVAL,
        "retention_days": HISTORY_RETENTION_DAYS,
        "db_path": str(history_manager.db.db_path),
        "app_name": "NetSentry",
        "developer": "Mohsin"
    }

