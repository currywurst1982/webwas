#!/usr/bin/env python3
"""ip_tracker 기능을 MCP(Model Context Protocol) 도구로 노출하는 STDIO 서버.

Claude Desktop 같은 AI 채팅 앱에 wildfly-mcp 서버와 "나란히" 등록해서 사용한다.
  - wildfly-mcp       : 서버 상태, 로그 일부 조회, CLI 실행 등 (WildFly 관리 포트 경유)
  - 이 서버(ip-tracker): 로그 "파일" 전체를 읽어 특정 IP 이력/위험도/타임테이블 생성

외부 라이브러리 없이 표준 입출력으로 JSON-RPC 2.0 메시지를 한 줄씩 주고받는다.
환경 변수
  WILDFLY_LOG_DIR : 로그 폴더 (기본값 ./samples). 쉼표로 여러 개 지정 가능.
  REPORT_DIR      : HTML/CSV 보고서 저장 폴더 (기본값 ./reports)
"""
from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ip_tracker as t  # noqa: E402

PROTOCOL_VERSION = "2025-06-18"
HERE = os.path.dirname(os.path.abspath(__file__))
LOG_DIRS = [p.strip() for p in os.environ.get("WILDFLY_LOG_DIR", os.path.join(HERE, "samples")).split(",") if p.strip()]
REPORT_DIR = os.environ.get("REPORT_DIR", os.path.join(HERE, "reports"))

TOOLS = [
    {
        "name": "listTopIps",
        "description": "WildFly 액세스 로그에서 요청이 많은 IP 상위 N개와 의심 요청 수를 보여준다.",
        "inputSchema": {"type": "object", "properties": {
            "limit": {"type": "integer", "description": "표시할 개수 (기본 10)"}}},
    },
    {
        "name": "getIpHistory",
        "description": "특정 IP(또는 CIDR 대역)의 접속 이력, 위험도, 판단 근거, 권장 WildFly CLI 조치를 돌려준다.",
        "inputSchema": {"type": "object", "required": ["ip"], "properties": {
            "ip": {"type": "string", "description": "예: 203.0.113.45 또는 203.0.113.0/24"},
            "since": {"type": "string", "description": "시작 시각 ISO 형식 (선택)"},
            "until": {"type": "string", "description": "종료 시각 ISO 형식 (선택)"},
            "maxEvents": {"type": "integer", "description": "돌려줄 최근 이력 수 (기본 50)"}}},
    },
    {
        "name": "createIpTimetable",
        "description": "특정 IP의 날짜×시간대 타임테이블 HTML과 CSV 파일을 만들고 경로를 돌려준다.",
        "inputSchema": {"type": "object", "required": ["ip"], "properties": {
            "ip": {"type": "string"},
            "since": {"type": "string"}, "until": {"type": "string"}}},
    },
]


def call_tool(name: str, args: dict) -> str:
    if name == "listTopIps":
        rows = t.top_ips(t.find_log_files(LOG_DIRS), int(args.get("limit", 10)))
        return json.dumps([{"ip": ip, "requests": c, "suspicious": b} for ip, c, b in rows], ensure_ascii=False)
    if name == "getIpHistory":
        ev = t.collect(args["ip"], LOG_DIRS, args.get("since"), args.get("until"))
        r = t.analyze(ev, args["ip"])
        n = int(args.get("maxEvents", 50))
        r["recent_events"] = [e.to_dict() for e in ev[-n:]]
        return json.dumps(r, ensure_ascii=False, default=str)
    if name == "createIpTimetable":
        ev = t.collect(args["ip"], LOG_DIRS, args.get("since"), args.get("until"))
        r = t.analyze(ev, args["ip"])
        os.makedirs(REPORT_DIR, exist_ok=True)
        base = os.path.join(REPORT_DIR, "ip_" + args["ip"].replace("/", "_").replace(":", "_"))
        t.write_html(r, ev, base + ".html")
        t.write_csv(ev, base + ".csv")
        return json.dumps({"html": base + ".html", "csv": base + ".csv",
                           "risk_level": r["risk_level"], "events": len(ev)}, ensure_ascii=False)
    raise ValueError(f"알 수 없는 도구: {name}")


def handle(msg: dict):
    method, mid = msg.get("method"), msg.get("id")
    if mid is None:          # 알림(notification)에는 응답하지 않는다
        return None
    if method == "initialize":
        result = {"protocolVersion": msg.get("params", {}).get("protocolVersion", PROTOCOL_VERSION),
                  "capabilities": {"tools": {}},
                  "serverInfo": {"name": "wildfly-ip-tracker", "version": "0.1.0"}}
    elif method == "tools/list":
        result = {"tools": TOOLS}
    elif method == "tools/call":
        p = msg.get("params", {})
        try:
            text = call_tool(p.get("name"), p.get("arguments") or {})
            result = {"content": [{"type": "text", "text": text}], "isError": False}
        except Exception as ex:  # 도구 오류는 AI에게 문장으로 알려준다
            result = {"content": [{"type": "text", "text": f"오류: {ex}"}], "isError": True}
    elif method == "ping":
        result = {}
    else:
        return {"jsonrpc": "2.0", "id": mid, "error": {"code": -32601, "message": f"Method not found: {method}"}}
    return {"jsonrpc": "2.0", "id": mid, "result": result}


def main():
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            resp = handle(json.loads(line))
        except json.JSONDecodeError:
            resp = {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "Parse error"}}
        if resp is not None:
            sys.stdout.write(json.dumps(resp, ensure_ascii=False) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    main()
