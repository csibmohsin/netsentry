"""
NetSentry - Network Intelligence & Live Threat Monitoring System
Main Application Entrypoint
Developer: Mohsin
"""

import sys
import os
import asyncio
import webbrowser
import logging
from contextlib import asynccontextmanager
from pathlib import Path

import uvicorn
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse

from config import (
    SERVER_HOST,
    SERVER_PORT,
    AUTO_OPEN_BROWSER,
    FRONTEND_DIR,
    LOGS_DIR
)
from database.database import DatabaseManager
from core.network_monitor import NetworkMonitor
from core.dns_sniffer import DNSSniffer
from api.routes import router as api_router
from api.websocket import ws_manager, websocket_streamer_task

# Configure logging
log_file = LOGS_DIR / "netsentry.log"
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.FileHandler(str(log_file), encoding="utf-8"),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger("NetSentry.App")

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    logger.info("==================================================")
    logger.info("   NetSentry: Network Intelligence & Threat Monitor")
    logger.info("   Developer: Mohsin")
    logger.info("==================================================")
    
    # Initialize DB
    DatabaseManager()
    
    # Start background Network Monitor engine
    monitor = NetworkMonitor()
    monitor.start()

    # Start Live DNS Sniffer engine
    dns_sniffer = DNSSniffer()
    dns_sniffer.start()

    # Start WebSocket background streaming task
    streamer_task = asyncio.create_task(websocket_streamer_task())

    # Auto open browser
    if AUTO_OPEN_BROWSER:
        def open_browser():
            import time
            time.sleep(1.2)
            url = f"http://{SERVER_HOST}:{SERVER_PORT}"
            logger.info("Opening dashboard in web browser: %s", url)
            webbrowser.open(url)
        
        import threading
        threading.Thread(target=open_browser, daemon=True).start()

    yield

    # Shutdown
    logger.info("Shutting down NetSentry engine...")
    monitor.stop()
    dns_sniffer.stop()
    streamer_task.cancel()
    try:
        await streamer_task
    except asyncio.CancelledError:
        pass
    logger.info("NetSentry stopped cleanly.")

app = FastAPI(
    title="NetSentry",
    description="Network Intelligence & Live Threat Monitoring System",
    version="1.0.0",
    lifespan=lifespan
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# WebSocket Endpoint
@app.websocket("/ws/live")
async def websocket_endpoint(websocket: WebSocket):
    await ws_manager.connect(websocket)
    try:
        while True:
            # Keep receiving pings or client messages
            data = await websocket.receive_text()
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)
    except Exception:
        ws_manager.disconnect(websocket)

# Include REST API
app.include_router(api_router)

# Mount Frontend static files
app.mount("/static", StaticFiles(directory=str(FRONTEND_DIR)), name="static")

@app.get("/")
def serve_index():
    index_file = FRONTEND_DIR / "index.html"
    return FileResponse(str(index_file))

def main():
    print(f"\n[NetSentry] Starting web dashboard at http://{SERVER_HOST}:{SERVER_PORT}\n")
    uvicorn.run("app:app", host=SERVER_HOST, port=SERVER_PORT, reload=False, log_level="info")

if __name__ == "__main__":
    main()

