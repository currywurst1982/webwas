#!/usr/bin/env python3
"""
WildFly Agent Controller
=========================
Central hub that receives reports from multiple WildFly monitoring agents,
stores anomaly history, and serves a real-time web dashboard over WebSocket.

Usage:
    python controller.py [config.yaml]
"""

import asyncio
import json
import logging
import os
import sys
from collections import deque, defaultdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Set

try:
    import uvicorn
    import yaml
    from fastapi import FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect
    from fastapi.middleware.cors import CORSMiddleware
    from fastapi.responses import HTMLResponse, JSONResponse
    from fastapi.staticfiles import StaticFiles
except ImportError:
    print("[ERROR] Missing dependencies. Run: pip install fastapi 'uvicorn[standard]' pyyaml")
    sys.exit(1)

# ─── Logging ──────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)-8s] %(name)s - %(message)s",
)
logger = logging.getLogger("wildfly-controller")

# ─── Config ───────────────────────────────────────────────────────────────────
def _load_cfg(path: str = "config.yaml") -> dict:
    p = Path(path)
    if p.exists():
        with open(p) as f:
            return yaml.safe_load(f) or {}
    return {}


_cfg = _load_cfg(sys.argv[1] if len(sys.argv) > 1 else "config.yaml")
_ctrl = _cfg.get("controller", {})

HOST = _ctrl.get("host", "0.0.0.0")
PORT = int(_ctrl.get("port", 8080))
API_KEY = _ctrl.get("api_key", "")
AGENT_TIMEOUT_SEC = int(_ctrl.get("agent_timeout", 90))
MAX_PER_AGENT = int(_ctrl.get("max_anomalies_per_agent", 200))
MAX_GLOBAL = int(_ctrl.get("max_global_anomalies", 1000))

# ─── Data models ──────────────────────────────────────────────────────────────
class AgentRecord:
    def __init__(self, data: dict):
        self.server_id: str = data["server_id"]
        self.host: str = data.get("host", "unknown")
        self.wildfly_version: str = data.get("wildfly_version", "26")
        self.log_path: str = data.get("log_path", "")
        self.simulate: bool = data.get("simulate", False)
        self.registered_at: str = data.get("registered_at", datetime.now().isoformat())
        self.last_heartbeat: Optional[datetime] = datetime.now()
        self.stats: dict = {}
        self.anomalies: deque = deque(maxlen=MAX_PER_AGENT)
        self.anomaly_counts: Dict[str, int] = defaultdict(int)

    @property
    def status(self) -> str:
        if self.last_heartbeat is None:
            return "unknown"
        age = (datetime.now() - self.last_heartbeat).total_seconds()
        if age > AGENT_TIMEOUT_SEC:
            return "offline"
        if self.anomaly_counts.get("CRITICAL", 0) > 0:
            return "critical"
        if self.anomaly_counts.get("HIGH", 0) > 0:
            return "warning"
        return "online"

    def to_dict(self) -> dict:
        return {
            "server_id": self.server_id,
            "host": self.host,
            "wildfly_version": self.wildfly_version,
            "log_path": self.log_path,
            "simulate": self.simulate,
            "registered_at": self.registered_at,
            "last_heartbeat": (
                self.last_heartbeat.isoformat() if self.last_heartbeat else None
            ),
            "status": self.status,
            "stats": self.stats,
            "anomaly_counts": dict(self.anomaly_counts),
            "recent_anomalies": list(self.anomalies)[-10:],
        }


# ─── In-memory store ──────────────────────────────────────────────────────────
agents: Dict[str, AgentRecord] = {}
global_anomalies: deque = deque(maxlen=MAX_GLOBAL)
ws_clients: Set[WebSocket] = set()


# ─── WebSocket broadcast ──────────────────────────────────────────────────────
async def broadcast(event_type: str, data: dict):
    if not ws_clients:
        return
    msg = json.dumps({"type": event_type, "data": data, "ts": datetime.now().isoformat()})
    dead: Set[WebSocket] = set()
    for ws in list(ws_clients):
        try:
            await ws.send_text(msg)
        except Exception:
            dead.add(ws)
    ws_clients.difference_update(dead)


# ─── FastAPI app ──────────────────────────────────────────────────────────────
app = FastAPI(title="WildFly Agent Controller", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

_static_dir = Path(__file__).parent / "static"
if _static_dir.exists():
    app.mount("/static", StaticFiles(directory=str(_static_dir)), name="static")


def _check_key(request: Request) -> bool:
    if not API_KEY:
        return True
    return request.headers.get("X-API-Key") == API_KEY


# ─── Background: offline checker ──────────────────────────────────────────────
@app.on_event("startup")
async def _startup():
    asyncio.create_task(_offline_checker())
    logger.info("Controller listening on %s:%d", HOST, PORT)


async def _offline_checker():
    """Broadcast agent_offline events when heartbeat times out."""
    last_offline: Dict[str, bool] = {}
    while True:
        await asyncio.sleep(15)
        for agent in list(agents.values()):
            if agent.last_heartbeat:
                age = (datetime.now() - agent.last_heartbeat).total_seconds()
                is_offline = age > AGENT_TIMEOUT_SEC
                was_offline = last_offline.get(agent.server_id, False)
                if is_offline and not was_offline:
                    await broadcast(
                        "agent_offline",
                        {
                            "server_id": agent.server_id,
                            "last_heartbeat": agent.last_heartbeat.isoformat(),
                        },
                    )
                last_offline[agent.server_id] = is_offline


# ─── Routes ───────────────────────────────────────────────────────────────────
@app.get("/", response_class=HTMLResponse)
async def dashboard():
    html = _static_dir / "index.html"
    if html.exists():
        return HTMLResponse(html.read_text(encoding="utf-8"))
    return HTMLResponse(
        "<h2>Dashboard not found</h2><p>Ensure <code>static/index.html</code> exists.</p>"
    )


@app.post("/api/agents/register")
async def register_agent(request: Request):
    if not _check_key(request):
        raise HTTPException(403, "Invalid API key")

    data = await request.json()
    server_id = data.get("server_id")
    if not server_id:
        raise HTTPException(400, "server_id is required")

    is_new = server_id not in agents
    agents[server_id] = AgentRecord(data)

    logger.info(
        "Agent %s: %s @ %s", "registered" if is_new else "re-registered",
        server_id, data.get("host"),
    )

    await broadcast(
        "agent_registered",
        {"server_id": server_id, "is_new": is_new, "agent": agents[server_id].to_dict()},
    )
    return JSONResponse({"status": "ok", "server_id": server_id})


@app.post("/api/agents/heartbeat")
async def agent_heartbeat(request: Request):
    if not _check_key(request):
        raise HTTPException(403, "Invalid API key")

    data = await request.json()
    server_id = data.get("server_id")
    if not server_id:
        raise HTTPException(400, "server_id is required")

    if server_id not in agents:
        agents[server_id] = AgentRecord({"server_id": server_id})

    agent = agents[server_id]
    agent.last_heartbeat = datetime.now()
    agent.stats = data.get("stats", {})

    await broadcast(
        "heartbeat",
        {
            "server_id": server_id,
            "timestamp": data.get("timestamp"),
            "stats": agent.stats,
            "status": agent.status,
        },
    )
    return JSONResponse({"status": "ok"})


@app.post("/api/anomalies")
async def receive_anomalies(request: Request):
    if not _check_key(request):
        raise HTTPException(403, "Invalid API key")

    data = await request.json()
    server_id = data.get("server_id")
    host = data.get("host", "unknown")
    anomalies: List[dict] = data.get("anomalies", [])

    if not anomalies:
        return JSONResponse({"status": "ok", "count": 0})

    if server_id not in agents:
        agents[server_id] = AgentRecord({"server_id": server_id, "host": host})

    agent = agents[server_id]
    received_at = datetime.now().isoformat()

    for a in anomalies:
        a["server_id"] = server_id
        a["host"] = host
        a["received_at"] = received_at
        agent.anomalies.append(a)
        agent.anomaly_counts[a.get("severity", "UNKNOWN")] += 1
        global_anomalies.append(a)

    logger.info("Received %d anomalies from %s", len(anomalies), server_id)

    await broadcast(
        "anomalies",
        {
            "server_id": server_id,
            "host": host,
            "anomalies": anomalies,
            "agent_status": agent.status,
        },
    )
    return JSONResponse({"status": "ok", "count": len(anomalies)})


@app.get("/api/agents")
async def list_agents():
    return JSONResponse([a.to_dict() for a in agents.values()])


@app.get("/api/agents/{server_id}")
async def get_agent(server_id: str):
    if server_id not in agents:
        raise HTTPException(404, "Agent not found")
    return JSONResponse(agents[server_id].to_dict())


@app.get("/api/anomalies")
async def list_anomalies(
    server_id: Optional[str] = None,
    severity: Optional[str] = None,
    limit: int = 100,
):
    results = list(global_anomalies)
    if server_id:
        results = [a for a in results if a.get("server_id") == server_id]
    if severity:
        results = [a for a in results if a.get("severity", "").upper() == severity.upper()]
    # Most recent first, capped at limit
    results = list(reversed(results[-limit:]))
    return JSONResponse(results)


@app.get("/api/stats")
async def get_stats():
    all_agents = list(agents.values())
    by_status = defaultdict(int)
    for a in all_agents:
        by_status[a.status] += 1

    by_severity: Dict[str, int] = defaultdict(int)
    for a in all_agents:
        for sev, cnt in a.anomaly_counts.items():
            by_severity[sev] += cnt

    return JSONResponse(
        {
            "agents": {
                "total": len(all_agents),
                "online": by_status["online"],
                "critical": by_status["critical"],
                "warning": by_status["warning"],
                "offline": by_status["offline"],
                "unknown": by_status["unknown"],
            },
            "anomalies": {
                "total": len(global_anomalies),
                "by_severity": dict(by_severity),
            },
        }
    )


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    ws_clients.add(websocket)
    client_addr = websocket.client
    logger.info("Dashboard connected: %s", client_addr)

    # Send full current state immediately
    try:
        await websocket.send_text(
            json.dumps(
                {
                    "type": "state",
                    "data": {
                        "agents": {sid: a.to_dict() for sid, a in agents.items()},
                        "recent_anomalies": list(global_anomalies)[-100:],
                    },
                    "ts": datetime.now().isoformat(),
                }
            )
        )

        while True:
            try:
                msg = await asyncio.wait_for(websocket.receive_text(), timeout=30)
                if msg == "ping":
                    await websocket.send_text(json.dumps({"type": "pong"}))
            except asyncio.TimeoutError:
                # Send server-side ping
                await websocket.send_text(json.dumps({"type": "ping"}))

    except WebSocketDisconnect:
        logger.info("Dashboard disconnected: %s", client_addr)
    except Exception as e:
        logger.debug("WebSocket closed: %s", e)
    finally:
        ws_clients.discard(websocket)


# ─── Entry point ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    uvicorn.run(app, host=HOST, port=PORT, log_level="info")
