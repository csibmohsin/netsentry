"""
NetSentry WebSocket Manager
Provides live streaming connection, metric, and threat feeds directly to the browser dashboard.
Developer: Mohsin
"""

import asyncio
import logging
from typing import List
from fastapi import WebSocket, WebSocketDisconnect
from core.network_monitor import NetworkMonitor

logger = logging.getLogger("NetSentry.WebSocket")

class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        logger.info("WebSocket client connected. Active clients: %d", len(self.active_connections))

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
            logger.info("WebSocket client disconnected. Active clients: %d", len(self.active_connections))

    async def broadcast(self, message: dict):
        for connection in list(self.active_connections):
            try:
                await connection.send_json(message)
            except Exception:
                self.disconnect(connection)

ws_manager = ConnectionManager()

async def websocket_streamer_task():
    """
    Background asynchronous loop broadcasting live monitoring telemetry to WebSockets.
    """
    monitor = NetworkMonitor()
    while True:
        try:
            if ws_manager.active_connections:
                live_state = monitor.get_live_state()
                # Broadcast condensed real-time payload
                payload = {
                    "type": "telemetry_update",
                    "stats": live_state["stats"],
                    "traffic": live_state["stats"].get("traffic", {}),
                    "recent_alerts": live_state["recent_alerts"][:5],
                    "total_connections": len(live_state["connections"])
                }
                await ws_manager.broadcast(payload)
        except Exception as e:
            logger.error("Error in websocket broadcasting task: %s", e)
        await asyncio.sleep(1.5)

