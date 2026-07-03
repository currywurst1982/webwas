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
import sqlite3
import sys
import uuid
from collections import deque, defaultdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Literal, Optional, Set
from urllib.parse import quote

try:
    import uvicorn
    import yaml
    from fastapi import FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect
    from fastapi.middleware.cors import CORSMiddleware
    from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
    from fastapi.staticfiles import StaticFiles
    from pydantic import BaseModel
except ImportError:
    print("[ERROR] Missing dependencies. Run: pip install fastapi 'uvicorn[standard]' pyyaml")
    sys.exit(1)

import report_export
import report_store
import security_scan
import security_store

# Optional: Anthropic Claude AI
try:
    from anthropic import AsyncAnthropic
    _anthropic_available = True
except ImportError:
    _anthropic_available = False

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

# ─── Claude AI config ─────────────────────────────────────────────────────────
_claude_cfg = _cfg.get("claude", {})
CLAUDE_ENABLED = _claude_cfg.get("enabled", False)
CLAUDE_API_KEY = _claude_cfg.get("api_key", "") or os.environ.get("ANTHROPIC_API_KEY", "")
CLAUDE_MODEL = _claude_cfg.get("model", "claude-opus-4-6")
CLAUDE_AUTO_ANALYZE = _claude_cfg.get("auto_analyze", False)

claude_client = None
if CLAUDE_ENABLED:
    if not _anthropic_available:
        logger.warning("Claude AI enabled but 'anthropic' package not installed. Run: pip install anthropic")
        CLAUDE_ENABLED = False
    elif not CLAUDE_API_KEY:
        logger.warning("Claude AI enabled but no API key set (claude.api_key or ANTHROPIC_API_KEY)")
        CLAUDE_ENABLED = False
    else:
        claude_client = AsyncAnthropic(api_key=CLAUDE_API_KEY)
        logger.info("Claude AI integration enabled (model: %s, auto_analyze: %s)", CLAUDE_MODEL, CLAUDE_AUTO_ANALYZE)

# ─── Data models ──────────────────────────────────────────────────────────────
class RemediationTask:
    def __init__(self, server_id: str, rule_name: str, cli_commands: List[str],
                 anomaly_id: str = "", description: str = "",
                 os_commands: List[str] = None):
        self.task_id: str = str(uuid.uuid4())[:12]
        self.server_id: str = server_id
        self.rule_name: str = rule_name
        self.cli_commands: List[str] = cli_commands
        self.os_commands: List[str] = os_commands or []
        self.anomaly_id: str = anomaly_id
        self.description: str = description
        self.created_at: str = datetime.now().isoformat()
        self.status: str = "pending"   # pending | done | failed
        self.result: Optional[dict] = None
        self.executed_at: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "task_id": self.task_id,
            "server_id": self.server_id,
            "rule_name": self.rule_name,
            "cli_commands": self.cli_commands,
            "os_commands": self.os_commands,
            "anomaly_id": self.anomaly_id,
            "description": self.description,
            "created_at": self.created_at,
            "status": self.status,
            "result": self.result,
            "executed_at": self.executed_at,
        }


class AgentRecord:
    def __init__(self, data: dict):
        self.server_id: str = data["server_id"]
        self.host: str = data.get("host", "unknown")
        self.server_type: str = data.get("server_type", "wildfly")   # wildfly | apache
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
            "server_type": self.server_type,
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

# Task store
agent_task_queues: Dict[str, List[RemediationTask]] = defaultdict(list)  # pending tasks per agent
all_tasks: Dict[str, RemediationTask] = {}                                # all tasks by task_id


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

report_store.init_db()
security_store.init_db()


def _check_key(request: Request) -> bool:
    if not API_KEY:
        return True
    return request.headers.get("X-API-Key") == API_KEY


# ─── Claude AI analysis ───────────────────────────────────────────────────────
async def analyze_with_claude(anomaly: dict) -> str:
    """Send anomaly details to Claude and return analysis text in Korean."""
    if not claude_client:
        return "Claude AI가 비활성화되어 있거나 API 키가 설정되지 않았습니다."

    log_msg   = (anomaly.get("log_entry") or {}).get("message", "(로그 없음)")
    rule_name = anomaly.get("rule_name", "알 수 없는 이상")
    desc      = anomaly.get("description", "")
    severity  = anomaly.get("severity", "")
    server_id = anomaly.get("server_id", "")
    remedy    = anomaly.get("remedy", [])
    remedy_text = "\n".join(f"- {r}" for r in remedy) if remedy else "없음"

    prompt = f"""당신은 WildFly 26 JBoss 애플리케이션 서버 전문가입니다.
아래 서버 로그 이상 탐지 정보를 분석하고 **한국어**로 상세한 원인 분석과 조치 방안을 제공해 주세요.

**서버:** {server_id}
**이상 유형:** {rule_name}
**심각도:** {severity}
**감지된 문제 설명:** {desc}
**기본 조치 방안 (참고):** {remedy_text}

**원본 로그 메시지:**
```
{log_msg}
```

위 로그를 분석하여 다음 항목을 포함한 한국어 답변을 제공해 주세요:

## 1. 원인 분석
이 오류/경고가 발생한 근본 원인을 설명해 주세요.

## 2. 즉각적인 조치 방법
지금 당장 취해야 할 구체적인 조치를 단계별로 설명해 주세요.

## 3. WildFly 26 설정 최적화
이 문제를 예방하기 위한 WildFly 26 설정 변경 사항을 설명해 주세요.

## 4. 추가 모니터링 포인트
이후 어떤 지표나 로그를 추가로 모니터링해야 하는지 알려주세요."""

    try:
        response = await claude_client.messages.create(
            model=CLAUDE_MODEL,
            max_tokens=2048,
            thinking={"type": "adaptive"},
            messages=[{"role": "user", "content": prompt}],
        )
        text = "\n".join(
            b.text for b in response.content if hasattr(b, "text")
        ).strip()
        return text or "응답을 받지 못했습니다."
    except Exception as e:
        logger.error("Claude analysis failed: %s", e)
        return f"Claude 분석 중 오류가 발생했습니다: {e}"


async def _auto_analyze(anomaly: dict):
    """Background task: analyze anomaly and broadcast result."""
    analysis = await analyze_with_claude(anomaly)
    await broadcast("claude_analysis", {
        "anomaly_id": anomaly.get("id", ""),
        "server_id":  anomaly.get("server_id", ""),
        "rule_name":  anomaly.get("rule_name", ""),
        "analysis":   analysis,
    })


# ─── Background: offline checker ──────────────────────────────────────────────
@app.on_event("startup")
async def _startup():
    asyncio.ensure_future(_offline_checker())
    asyncio.ensure_future(_security_watch_loop())
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


# ─── Background: KISA 보안공지 감시 ─────────────────────────────────────────────
SECURITY_CHECK_INTERVAL_SEC = 24 * 3600
_security_check_lock = asyncio.Lock()


async def run_security_check() -> Dict:
    """수동/자동 확인이 겹치지 않도록 잠금을 건 뒤 블로킹 스크래핑을
    스레드에서 실행한다."""
    async with _security_check_lock:
        return await asyncio.to_thread(security_scan.run_check)


async def _security_watch_loop():
    # 컨트롤러 시작 직후 한 번 확인하고, 이후 24시간마다 반복한다.
    while True:
        try:
            await run_security_check()
        except Exception:
            logger.exception("보안공지 확인 중 오류가 발생했습니다")
        await asyncio.sleep(SECURITY_CHECK_INTERVAL_SEC)


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

    # Auto-analyze CRITICAL/HIGH anomalies with Claude if enabled
    if CLAUDE_AUTO_ANALYZE and claude_client:
        for anom in anomalies:
            if anom.get("severity") in ("CRITICAL", "HIGH"):
                asyncio.ensure_future(_auto_analyze(anom))

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


# ─── Claude AI analysis endpoint ──────────────────────────────────────────────
@app.post("/api/anomalies/analyze")
async def analyze_anomaly_endpoint(request: Request):
    """Dashboard → Controller: request Claude AI analysis for an anomaly log."""
    if not CLAUDE_ENABLED or not claude_client:
        return JSONResponse(
            {"error": "Claude AI가 비활성화되어 있습니다. controller/config.yaml에서 claude.enabled와 api_key를 설정하세요."},
            status_code=503,
        )

    data   = await request.json()
    anomaly = data.get("anomaly", data)

    analysis = await analyze_with_claude(anomaly)

    await broadcast("claude_analysis", {
        "anomaly_id": anomaly.get("id", ""),
        "server_id":  anomaly.get("server_id", ""),
        "rule_name":  anomaly.get("rule_name", ""),
        "analysis":   analysis,
    })

    return JSONResponse({"analysis": analysis})


# ─── Remediation task endpoints ───────────────────────────────────────────────

@app.post("/api/agents/{server_id}/remediate")
async def request_remediation(server_id: str, request: Request):
    """Dashboard → Controller: request jboss-cli remediation on a specific agent."""
    if not _check_key(request):
        raise HTTPException(403, "Invalid API key")

    data = await request.json()
    rule_name    = data.get("rule_name", "unknown")
    cli_commands = data.get("cli_commands", [])
    os_commands  = data.get("os_commands", [])
    anomaly_id   = data.get("anomaly_id", "")
    description  = data.get("description", "")

    if not cli_commands and not os_commands:
        raise HTTPException(400, "cli_commands 또는 os_commands 필드가 필요합니다")
    if server_id not in agents:
        raise HTTPException(404, f"Agent '{server_id}'를 찾을 수 없습니다")

    task = RemediationTask(server_id, rule_name, cli_commands, anomaly_id, description,
                           os_commands=os_commands)
    agent_task_queues[server_id].append(task)
    all_tasks[task.task_id] = task

    logger.info("Remediation task %s queued for %s [%s] cli:%d os:%d",
                task.task_id, server_id, rule_name, len(cli_commands), len(os_commands))

    await broadcast("task_queued", {
        "task_id":     task.task_id,
        "server_id":   server_id,
        "rule_name":   rule_name,
        "cli_commands": cli_commands,
        "os_commands":  os_commands,
        "created_at":  task.created_at,
    })

    return JSONResponse({"status": "queued", "task_id": task.task_id})


@app.get("/api/agents/{server_id}/tasks")
async def get_agent_tasks(server_id: str, request: Request):
    """Agent → Controller: fetch pending remediation tasks (polling)."""
    if not _check_key(request):
        raise HTTPException(403, "Invalid API key")

    pending = agent_task_queues.get(server_id, [])
    if not pending:
        return JSONResponse([])

    # Hand off all pending tasks; agent will report results back
    tasks_out = [t.to_dict() for t in pending]
    for t in pending:
        t.status = "running"
    agent_task_queues[server_id].clear()

    return JSONResponse(tasks_out)


@app.post("/api/tasks/{task_id}/result")
async def task_result(task_id: str, request: Request):
    """Agent → Controller: report execution result of a remediation task."""
    if not _check_key(request):
        raise HTTPException(403, "Invalid API key")

    data = await request.json()
    result = data.get("result", {})

    if task_id not in all_tasks:
        raise HTTPException(404, "Task not found")

    task = all_tasks[task_id]
    task.result      = result
    task.executed_at = data.get("executed_at", datetime.now().isoformat())
    task.status      = "done" if result.get("success") else "failed"

    logger.info("Task %s [%s] → %s", task_id, task.rule_name, task.status)

    await broadcast("task_result", {
        "task_id":     task_id,
        "server_id":   task.server_id,
        "rule_name":   task.rule_name,
        "status":      task.status,
        "result":      result,
        "executed_at": task.executed_at,
    })

    return JSONResponse({"status": "ok"})


@app.get("/api/tasks")
async def list_tasks(server_id: Optional[str] = None, limit: int = 50):
    """List recent remediation tasks."""
    tasks = list(all_tasks.values())
    if server_id:
        tasks = [t for t in tasks if t.server_id == server_id]
    tasks.sort(key=lambda t: t.created_at, reverse=True)
    return JSONResponse([t.to_dict() for t in tasks[:limit]])


# ─── Weekly WEB/WAS Operations Report ─────────────────────────────────────────
class ReportWeekIn(BaseModel):
    start_date: str
    end_date: str
    next_start_date: Optional[str] = None
    next_end_date: Optional[str] = None


class OperationStatusIn(BaseModel):
    client_name: str
    sort_order: int = 0
    last_web: int = 0
    last_was: int = 0
    last_dev: int = 0
    this_web: int = 0
    this_was: int = 0
    this_dev: int = 0


class WorkLogIn(BaseModel):
    section: Literal["current", "next"]
    sort_order: int = 0
    category: str = ""
    request_date: str = ""
    requester: str = ""
    work_date: str = ""
    work_content: str = ""
    web_count: int = 0
    was_count: int = 0
    etc_count: int = 0


class SpecialNoteIn(BaseModel):
    sort_order: int = 0
    category: str = ""
    note_date: str = ""
    title: str = ""
    service_name: str = ""
    detail: str = ""


@app.get("/report", response_class=HTMLResponse)
async def report_page():
    html = _static_dir / "report.html"
    if html.exists():
        return HTMLResponse(html.read_text(encoding="utf-8"))
    return HTMLResponse("<h2>Report page not found</h2><p>static/report.html이 없습니다.</p>", status_code=404)


@app.get("/api/report/weeks")
async def list_report_weeks():
    return JSONResponse(report_store.list_weeks())


@app.post("/api/report/weeks")
async def create_report_week(body: ReportWeekIn):
    try:
        week = report_store.create_week(
            body.start_date, body.end_date, body.next_start_date, body.next_end_date
        )
    except sqlite3.IntegrityError:
        raise HTTPException(409, "이미 동일한 기간의 주간 보고서가 존재합니다")
    return JSONResponse(week)


@app.get("/api/report/weeks/{week_id}")
async def get_report_week(week_id: int):
    bundle = report_store.get_report_bundle(week_id)
    if not bundle:
        raise HTTPException(404, "해당 주간 보고서를 찾을 수 없습니다")
    return JSONResponse(bundle)


@app.put("/api/report/weeks/{week_id}")
async def update_report_week(week_id: int, body: ReportWeekIn):
    if not report_store.get_week(week_id):
        raise HTTPException(404, "해당 주간 보고서를 찾을 수 없습니다")
    try:
        week = report_store.update_week(
            week_id, body.start_date, body.end_date, body.next_start_date, body.next_end_date
        )
    except sqlite3.IntegrityError:
        raise HTTPException(409, "이미 동일한 기간의 주간 보고서가 존재합니다")
    return JSONResponse(week)


@app.delete("/api/report/weeks/{week_id}")
async def delete_report_week(week_id: int):
    if not report_store.delete_week(week_id):
        raise HTTPException(404, "해당 주간 보고서를 찾을 수 없습니다")
    return JSONResponse({"status": "ok"})


@app.post("/api/report/weeks/{week_id}/operation-status")
async def add_operation_status_row(week_id: int, body: OperationStatusIn):
    if not report_store.get_week(week_id):
        raise HTTPException(404, "해당 주간 보고서를 찾을 수 없습니다")
    row = report_store.add_operation_status(
        week_id, body.client_name, body.sort_order,
        body.last_web, body.last_was, body.last_dev,
        body.this_web, body.this_was, body.this_dev,
    )
    return JSONResponse(row)


@app.put("/api/report/operation-status/{row_id}")
async def update_operation_status_row(row_id: int, body: OperationStatusIn):
    row = report_store.update_operation_status(
        row_id, body.client_name, body.sort_order,
        body.last_web, body.last_was, body.last_dev,
        body.this_web, body.this_was, body.this_dev,
    )
    if not row:
        raise HTTPException(404, "해당 항목을 찾을 수 없습니다")
    return JSONResponse(row)


@app.delete("/api/report/operation-status/{row_id}")
async def delete_operation_status_row(row_id: int):
    if not report_store.delete_operation_status(row_id):
        raise HTTPException(404, "해당 항목을 찾을 수 없습니다")
    return JSONResponse({"status": "ok"})


@app.post("/api/report/weeks/{week_id}/work-logs")
async def add_work_log_row(week_id: int, body: WorkLogIn):
    if not report_store.get_week(week_id):
        raise HTTPException(404, "해당 주간 보고서를 찾을 수 없습니다")
    row = report_store.add_work_log(
        week_id, body.section, body.sort_order, body.category,
        body.request_date, body.requester, body.work_date, body.work_content,
        body.web_count, body.was_count, body.etc_count,
    )
    return JSONResponse(row)


@app.put("/api/report/work-logs/{row_id}")
async def update_work_log_row(row_id: int, body: WorkLogIn):
    row = report_store.update_work_log(
        row_id, body.section, body.sort_order, body.category,
        body.request_date, body.requester, body.work_date, body.work_content,
        body.web_count, body.was_count, body.etc_count,
    )
    if not row:
        raise HTTPException(404, "해당 항목을 찾을 수 없습니다")
    return JSONResponse(row)


@app.delete("/api/report/work-logs/{row_id}")
async def delete_work_log_row(row_id: int):
    if not report_store.delete_work_log(row_id):
        raise HTTPException(404, "해당 항목을 찾을 수 없습니다")
    return JSONResponse({"status": "ok"})


@app.post("/api/report/weeks/{week_id}/special-notes")
async def add_special_note_row(week_id: int, body: SpecialNoteIn):
    if not report_store.get_week(week_id):
        raise HTTPException(404, "해당 주간 보고서를 찾을 수 없습니다")
    row = report_store.add_special_note(
        week_id, body.sort_order, body.category, body.note_date,
        body.title, body.service_name, body.detail,
    )
    return JSONResponse(row)


@app.put("/api/report/special-notes/{row_id}")
async def update_special_note_row(row_id: int, body: SpecialNoteIn):
    row = report_store.update_special_note(
        row_id, body.sort_order, body.category, body.note_date,
        body.title, body.service_name, body.detail,
    )
    if not row:
        raise HTTPException(404, "해당 항목을 찾을 수 없습니다")
    return JSONResponse(row)


@app.delete("/api/report/special-notes/{row_id}")
async def delete_special_note_row(row_id: int):
    if not report_store.delete_special_note(row_id):
        raise HTTPException(404, "해당 항목을 찾을 수 없습니다")
    return JSONResponse({"status": "ok"})


@app.get("/api/report/weeks/{week_id}/export")
async def export_report_week(week_id: int):
    """Render the current state of one week's report back into an .xlsx file
    laid out like the original weekly-report template."""
    bundle = report_store.get_report_bundle(week_id)
    if not bundle:
        raise HTTPException(404, "해당 주간 보고서를 찾을 수 없습니다")

    buf = report_export.build_workbook(bundle)
    week = bundle["week"]
    display_name = f"운영보고서_{week['start_date']}_{week['end_date']}.xlsx"
    ascii_fallback = f"report_{week['start_date']}_{week['end_date']}.xlsx"
    headers = {
        "Content-Disposition": (
            f'attachment; filename="{ascii_fallback}"; '
            f"filename*=UTF-8''{quote(display_name)}"
        )
    }
    return StreamingResponse(
        buf,
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers=headers,
    )


# ─── KISA 보안공지 감시 ────────────────────────────────────────────────────────
@app.get("/security", response_class=HTMLResponse)
async def security_page():
    html = _static_dir / "security.html"
    if html.exists():
        return HTMLResponse(html.read_text(encoding="utf-8"))
    return HTMLResponse("<h2>Security page not found</h2><p>static/security.html이 없습니다.</p>", status_code=404)


@app.get("/api/security/notices")
async def list_security_notices(product: Optional[str] = None):
    return JSONResponse(security_store.list_notices(product, since=security_scan.SCAN_SINCE_DATE))


@app.get("/api/security/status")
async def security_status():
    return JSONResponse({
        "last_checked_at": security_store.get_meta("last_checked_at"),
        "last_error": security_store.get_meta("last_error") or "",
        "last_scanned_count": security_store.get_meta("last_scanned_count"),
        "checking": _security_check_lock.locked(),
    })


@app.post("/api/security/check")
async def trigger_security_check():
    if _security_check_lock.locked():
        raise HTTPException(409, "이미 확인이 진행 중입니다")
    summary = await run_security_check()
    return JSONResponse(summary)


# ─── Entry point ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    uvicorn.run(app, host=HOST, port=PORT, log_level="info")
