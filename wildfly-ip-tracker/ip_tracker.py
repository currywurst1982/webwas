#!/usr/bin/env python3
"""WildFly 로그에서 특정 IP의 접속 이력을 뽑아 분석하고, 조치 방법과 타임테이블(HTML)을 만든다.

외부 라이브러리 없이 Python 3.8+ 표준 기능만 사용한다.

읽는 로그
  1) Undertow 액세스 로그 (access_log.*.log, .gz 포함)
     - WildFly 기본 패턴 "common":  %h %l %u %t "%r" %s %b
     - "combined" 패턴(Referer, User-Agent 추가)도 자동 인식
  2) server.log (기본 패턴: %d{yyyy-MM-dd HH:mm:ss,SSS} %-5p [%c] (%t) %s%e%n)
     - IP 문자열이 들어 있는 줄만 골라낸다 (로그인 실패 등 앱/보안 로그)

사용 예
  python3 ip_tracker.py --ip 203.0.113.45 --logs samples/ --html report.html
  python3 ip_tracker.py --top 10 --logs /opt/wildfly/standalone/log
"""
from __future__ import annotations

import argparse
import csv
import gzip
import html
import ipaddress
import json
import os
import re
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from typing import Iterable, Iterator, List, Optional

# ---------------------------------------------------------------------------
# 1. 로그 한 줄을 읽어 "이벤트"로 바꾸는 부분
# ---------------------------------------------------------------------------

# common: 203.0.113.45 - - [20/Oct/2026:09:15:02 +0900] "GET /app/ HTTP/1.1" 200 512
# combined: 위 형식 뒤에 "Referer" "User-Agent"
ACCESS_RE = re.compile(
    r'^(?P<ip>\S+) (?P<ident>\S+) (?P<user>\S+) \[(?P<time>[^\]]+)\] '
    r'"(?P<request>[^"]*)" (?P<status>\d{3}|-) (?P<size>\d+|-)'
    r'(?: "(?P<referer>[^"]*)" "(?P<agent>[^"]*)")?'
)
ACCESS_TIME_FMT = "%d/%b/%Y:%H:%M:%S %z"

# server.log: 2026-10-20 09:15:02,123 WARN  [org.example] (default task-1) message
SERVER_RE = re.compile(
    r'^(?P<time>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3}) +(?P<level>[A-Z]+) +'
    r'\[(?P<category>[^\]]*)\] \((?P<thread>[^)]*)\) (?P<message>.*)$'
)
SERVER_TIME_FMT = "%Y-%m-%d %H:%M:%S,%f"

IP_IN_TEXT_RE = re.compile(r'(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])')


@dataclass
class Event:
    time: datetime
    ip: str
    source: str            # "access" 또는 "server"
    file: str
    method: str = ""
    path: str = ""
    status: int = 0
    size: int = 0
    user: str = ""
    agent: str = ""
    level: str = ""
    message: str = ""
    tags: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["time"] = self.time.isoformat()
        return d


def _open(path: str):
    if path.endswith(".gz"):
        return gzip.open(path, "rt", encoding="utf-8", errors="replace")
    return open(path, "r", encoding="utf-8", errors="replace")


def parse_access_line(line: str, file: str) -> Optional[Event]:
    m = ACCESS_RE.match(line)
    if not m:
        return None
    try:
        t = datetime.strptime(m["time"], ACCESS_TIME_FMT).replace(tzinfo=None)
    except ValueError:
        return None
    parts = m["request"].split(" ")
    method = parts[0] if parts else ""
    path = parts[1] if len(parts) > 1 else ""
    return Event(
        time=t, ip=m["ip"], source="access", file=os.path.basename(file),
        method=method, path=path,
        status=int(m["status"]) if m["status"].isdigit() else 0,
        size=int(m["size"]) if m["size"].isdigit() else 0,
        user="" if m["user"] == "-" else m["user"],
        agent=m["agent"] or "",
    )


def parse_server_line(line: str, file: str) -> List[Event]:
    """server.log 한 줄에 들어 있는 IP마다 이벤트를 하나씩 만든다."""
    m = SERVER_RE.match(line)
    if not m:
        return []
    ips = set(IP_IN_TEXT_RE.findall(m["message"]))
    if not ips:
        return []
    t = datetime.strptime(m["time"], SERVER_TIME_FMT)
    return [Event(time=t, ip=ip, source="server", file=os.path.basename(file),
                  level=m["level"], message=m["message"][:500]) for ip in ips]


def find_log_files(paths: Iterable[str]) -> List[str]:
    files = []
    for p in paths:
        if os.path.isdir(p):
            for name in sorted(os.listdir(p)):
                full = os.path.join(p, name)
                if os.path.isfile(full) and (".log" in name or name.endswith(".gz")):
                    files.append(full)
        elif os.path.isfile(p):
            files.append(p)
        else:
            print(f"[경고] 경로를 찾을 수 없습니다: {p}", file=sys.stderr)
    return files


# 파일별로 "형식을 몰라 건너뛴 줄 수"를 기록 (로그 패턴이 기본값과 다를 때 확인용)
SKIPPED: Counter = Counter()


def read_events(files: Iterable[str]) -> Iterator[Event]:
    for f in files:
        is_server = os.path.basename(f).startswith("server.log")
        with _open(f) as fh:
            for line in fh:
                line = line.rstrip("\n")
                if not line:
                    continue
                if is_server:
                    if not SERVER_RE.match(line):
                        SKIPPED[os.path.basename(f)] += 1  # 스택트레이스 등 여러 줄 메시지 포함
                    yield from parse_server_line(line, f)
                else:
                    ev = parse_access_line(line, f)
                    if ev:
                        yield ev
                    elif SERVER_RE.match(line):  # 파일명이 달라도 server.log 형식이면 처리
                        yield from parse_server_line(line, f)
                    else:
                        SKIPPED[os.path.basename(f)] += 1


def ip_matcher(target: str):
    """'1.2.3.4' 같은 단일 IP 또는 '1.2.3.0/24' 같은 대역을 받는다."""
    net = ipaddress.ip_network(target, strict=False)

    def match(ip: str) -> bool:
        try:
            return ipaddress.ip_address(ip) in net
        except ValueError:
            return False
    return match


# ---------------------------------------------------------------------------
# 2. 분석: 어떤 행동을 했는지 태그를 붙이고 위험도를 계산
# ---------------------------------------------------------------------------

# 공격 도구가 흔히 찔러보는 경로 (일반적인 스캐너 패턴, 필요하면 추가하세요)
SCAN_PATTERNS = [
    r"/\.env", r"/\.git", r"wp-(admin|login)", r"phpmyadmin", r"/manager/html",
    r"/jmx-console", r"/web-console", r"/invoker/", r"/console(/|$)", r"/actuator",
    r"\.\./", r"%2e%2e", r"/etc/passwd", r"cgi-bin", r"\.php(\?|$)", r"/admin(/|$)",
]
SCAN_RE = re.compile("|".join(SCAN_PATTERNS), re.IGNORECASE)
INJECTION_RE = re.compile(r"(union(\s|%20)+select|<script|%3cscript|\$\{jndi:|or(\s|%20)+1=1|sleep\()",
                          re.IGNORECASE)
AUTH_FAIL_RE = re.compile(r"(login fail|authentication fail|invalid (user|password)|ELY0\d+|unauthori[sz]ed)",
                          re.IGNORECASE)
NORMAL_METHODS = {"GET", "POST", "HEAD", "PUT", "DELETE", "OPTIONS", "PATCH"}


def tag_event(ev: Event) -> None:
    if ev.source == "access":
        if SCAN_RE.search(ev.path):
            ev.tags.append("스캔")
        if INJECTION_RE.search(ev.path):
            ev.tags.append("인젝션시도")
        if ev.status in (401, 403):
            ev.tags.append("인증실패")
        elif 500 <= ev.status < 600:
            ev.tags.append("서버오류")
        elif ev.status == 404:
            ev.tags.append("없는경로")
        if ev.method and ev.method not in NORMAL_METHODS:
            ev.tags.append("비정상메서드")
    else:
        if AUTH_FAIL_RE.search(ev.message):
            ev.tags.append("인증실패")
        if ev.level in ("ERROR", "FATAL"):
            ev.tags.append("서버오류")
        if INJECTION_RE.search(ev.message):
            ev.tags.append("인젝션시도")


def analyze(events: List[Event], ip: str) -> dict:
    events.sort(key=lambda e: e.time)
    for e in events:
        tag_event(e)

    access = [e for e in events if e.source == "access"]
    tag_count = Counter(t for e in events for t in e.tags)
    status_count = Counter(e.status for e in access)
    per_minute = Counter(e.time.replace(second=0, microsecond=0) for e in access)
    peak_minute, peak_count = (per_minute.most_common(1)[0] if per_minute else (None, 0))

    # 위험도 점수 (기준은 단순 휴리스틱 — 운영 환경에 맞게 조정 필요)
    score = 0
    reasons = []
    if tag_count["인젝션시도"]:
        score += 50; reasons.append(f"인젝션 시도 {tag_count['인젝션시도']}건 (SQL/스크립트/JNDI 패턴)")
    if tag_count["스캔"] >= 3:
        score += 30; reasons.append(f"관리/민감 경로 스캔 {tag_count['스캔']}건")
    elif tag_count["스캔"]:
        score += 10; reasons.append(f"관리/민감 경로 접근 {tag_count['스캔']}건")
    if tag_count["인증실패"] >= 10:
        score += 30; reasons.append(f"인증 실패 {tag_count['인증실패']}건 (무차별 대입 의심)")
    elif tag_count["인증실패"] >= 3:
        score += 10; reasons.append(f"인증 실패 {tag_count['인증실패']}건")
    if peak_count >= 120:
        score += 30; reasons.append(f"분당 최대 {peak_count}회 요청 (과도한 요청)")
    elif peak_count >= 60:
        score += 10; reasons.append(f"분당 최대 {peak_count}회 요청")
    if access and tag_count["없는경로"] / len(access) > 0.5 and len(access) >= 10:
        score += 10; reasons.append("요청의 절반 이상이 404 (경로 탐색 의심)")
    if tag_count["비정상메서드"]:
        score += 10; reasons.append(f"비표준 HTTP 메서드 {tag_count['비정상메서드']}건")

    level = "높음" if score >= 50 else "중간" if score >= 20 else "낮음"
    return {
        "ip": ip,
        "total_events": len(events),
        "access_requests": len(access),
        "server_log_lines": len(events) - len(access),
        "first_seen": events[0].time.isoformat() if events else None,
        "last_seen": events[-1].time.isoformat() if events else None,
        "status_count": {str(k): v for k, v in sorted(status_count.items())},
        "tag_count": dict(tag_count),
        "top_paths": Counter(e.path for e in access).most_common(10),
        "user_agents": Counter(e.agent for e in access if e.agent).most_common(5),
        "users": sorted({e.user for e in access if e.user}),
        "peak_minute": peak_minute.isoformat() if peak_minute else None,
        "peak_per_minute": peak_count,
        "risk_score": score,
        "risk_level": level,
        "reasons": reasons or ["특이 패턴 없음"],
        "actions": recommend_actions(ip, level),
    }


# ---------------------------------------------------------------------------
# 3. 조치 방법 (WildFly CLI 명령어)
# ---------------------------------------------------------------------------

def recommend_actions(ip: str, level: str) -> List[dict]:
    """WildFly Undertow의 expression-filter + ip-access-control 로 IP를 막는 명령을 만든다."""
    safe = re.sub(r"[^0-9A-Za-z]", "_", ip)
    block = [
        f"/subsystem=undertow/configuration=filter/expression-filter=block-{safe}:add("
        f"expression=\"ip-access-control(default-allow=true, acl={{'{ip} deny'}})\")",
        f"/subsystem=undertow/server=default-server/host=default-host/filter-ref=block-{safe}:add",
        ":reload",
    ]
    unblock = [
        f"/subsystem=undertow/server=default-server/host=default-host/filter-ref=block-{safe}:remove",
        f"/subsystem=undertow/configuration=filter/expression-filter=block-{safe}:remove",
        ":reload",
    ]
    actions = []
    if level == "높음":
        actions.append({"title": "1) 즉시 차단 (WildFly에서 403 응답)", "cli": block})
        actions.append({"title": "2) 방화벽/WAF/로드밸런서에서도 차단 권장 (서버 앞단에서 막는 것이 더 효과적)", "cli": []})
        actions.append({"title": "3) 해당 시간대의 server.log ERROR 와 배포 앱 로그를 함께 검토", "cli": []})
    elif level == "중간":
        actions.append({"title": "1) 당분간 모니터링 — 같은 명령으로 며칠 뒤 재분석", "cli": []})
        actions.append({"title": "2) 반복되면 아래 명령으로 차단", "cli": block})
    else:
        actions.append({"title": "조치 불필요 (정상 사용자로 보임). 필요 시 아래 명령으로 차단 가능", "cli": block})
    actions.append({"title": "차단 해제 방법", "cli": unblock})
    return actions


# ---------------------------------------------------------------------------
# 4. 출력: 텍스트 / CSV / JSON / HTML 타임테이블
# ---------------------------------------------------------------------------

def print_report(r: dict, events: List[Event], limit: int = 30) -> None:
    print("=" * 70)
    print(f" IP 이력 보고서: {r['ip']}")
    print("=" * 70)
    if not r["total_events"]:
        print(" 해당 IP 기록이 없습니다.")
        return
    print(f" 최초 접속 : {r['first_seen']}")
    print(f" 마지막 접속: {r['last_seen']}")
    print(f" 액세스 요청: {r['access_requests']}건 / server.log 언급: {r['server_log_lines']}건")
    print(f" 응답 코드  : {r['status_count']}")
    print(f" 분당 최대  : {r['peak_per_minute']}회 ({r['peak_minute']})")
    print(f" 위험도     : {r['risk_level']} (점수 {r['risk_score']})")
    for reason in r["reasons"]:
        print(f"   - {reason}")
    print("\n[많이 요청한 경로]")
    for p, c in r["top_paths"]:
        print(f"   {c:>5}  {p}")
    print(f"\n[시간순 이력 — 최근 {limit}건]")
    for e in events[-limit:]:
        what = f"{e.method} {e.path} -> {e.status}" if e.source == "access" else f"{e.level} {e.message[:80]}"
        tags = f" [{','.join(e.tags)}]" if e.tags else ""
        print(f"   {e.time:%Y-%m-%d %H:%M:%S}  {e.source:<6} {what}{tags}")
    print("\n[권장 조치]")
    for a in r["actions"]:
        print(f" {a['title']}")
        for c in a["cli"]:
            print(f"     {c}")
    print("\n * 명령은 WildFly 설치 폴더의 bin/jboss-cli.sh --connect 실행 후 입력합니다.")
    print_skipped()


def print_skipped() -> None:
    if SKIPPED:
        print("\n[참고] 형식을 인식하지 못해 건너뛴 줄 (server.log는 스택트레이스 줄이 정상적으로 포함됨):")
        for f, c in SKIPPED.most_common():
            print(f"   {f}: {c}줄")


def write_csv(events: List[Event], path: str) -> None:
    with open(path, "w", newline="", encoding="utf-8-sig") as fh:  # 엑셀 한글 깨짐 방지
        w = csv.writer(fh)
        w.writerow(["시간", "IP", "출처", "파일", "메서드", "경로", "상태", "크기", "사용자", "레벨", "메시지", "태그"])
        for e in events:
            w.writerow([e.time.strftime("%Y-%m-%d %H:%M:%S"), e.ip, e.source, e.file, e.method, e.path,
                        e.status or "", e.size or "", e.user, e.level, e.message, ",".join(e.tags)])


def top_ips(files: List[str], n: int) -> List[tuple]:
    c = Counter()
    bad = Counter()
    for e in read_events(files):
        if e.source == "access":
            c[e.ip] += 1
            if e.status in (401, 403) or SCAN_RE.search(e.path) or INJECTION_RE.search(e.path):
                bad[e.ip] += 1
    return [(ip, cnt, bad[ip]) for ip, cnt in c.most_common(n)]


def write_html(r: dict, events: List[Event], path: str) -> None:
    """요일·날짜 x 시간(0~23시) 타임테이블 + 시간순 상세 표를 한 파일 HTML로 만든다."""
    grid = defaultdict(lambda: [0] * 24)
    bad_grid = defaultdict(lambda: [0] * 24)
    for e in events:
        d = e.time.strftime("%Y-%m-%d")
        grid[d][e.time.hour] += 1
        if e.tags and e.tags != ["없는경로"]:
            bad_grid[d][e.time.hour] += 1
    days = []
    if events:
        d0, d1 = events[0].time.date(), events[-1].time.date()
        while d0 <= d1:
            days.append(d0.strftime("%Y-%m-%d"))
            d0 += timedelta(days=1)
    vmax = max([v for row in grid.values() for v in row] or [1])
    week = "월화수목금토일"

    rows = []
    for d in days:
        cells = []
        for h in range(24):
            v, b = grid[d][h], bad_grid[d][h]
            alpha = 0 if v == 0 else 0.15 + 0.85 * (v / vmax)
            cls = "bad" if b else "ok"
            title = f"{d} {h:02d}시: {v}건" + (f" (의심 {b}건)" if b else "")
            cells.append(f'<td class="{cls}" style="--a:{alpha:.2f}" title="{title}" '
                         f'data-day="{d}" data-hour="{h}">{v or ""}</td>')
        wd = week[datetime.strptime(d, "%Y-%m-%d").weekday()]
        rows.append(f"<tr><th>{d} ({wd})</th>{''.join(cells)}</tr>")

    detail = []
    for e in events:
        what = (f"{html.escape(e.method)} {html.escape(e.path)}" if e.source == "access"
                else f"{html.escape(e.level)} {html.escape(e.message)}")
        tags = "".join(f'<span class="tag">{html.escape(t)}</span>' for t in e.tags)
        detail.append(
            f'<tr data-day="{e.time:%Y-%m-%d}" data-hour="{e.time.hour}"><td>{e.time:%Y-%m-%d %H:%M:%S}</td>'
            f"<td>{e.source}</td><td class='w'>{what}</td><td>{e.status or ''}</td><td>{tags}</td></tr>")

    actions = "".join(
        f"<li>{html.escape(a['title'])}" +
        (f"<pre>{html.escape(chr(10).join(a['cli']))}</pre>" if a["cli"] else "") + "</li>"
        for a in r["actions"])
    reasons = "".join(f"<li>{html.escape(x)}</li>" for x in r["reasons"])
    level_cls = {"높음": "hi", "중간": "mid"}.get(r["risk_level"], "lo")

    doc = f"""<!doctype html>
<html lang="ko"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>IP 접속 타임테이블</title>
<style>
:root{{--bg:#fff;--fg:#1d1d1f;--mut:#666;--line:#e3e3e8;--ok:37,99,235;--bad:220,38,38;--card:#f6f6f8}}
@media (prefers-color-scheme:dark){{:root{{--bg:#16161a;--fg:#ececf1;--mut:#9a9aa5;--line:#2c2c33;--card:#1f1f25}}}}
body{{background:var(--bg);color:var(--fg);font:14px/1.5 system-ui,sans-serif;margin:0;padding:16px;max-width:1200px;margin:auto}}
h1{{font-size:20px}} h2{{font-size:16px;margin-top:28px}}
.cards{{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:8px}}
.card{{background:var(--card);border-radius:8px;padding:10px}} .card b{{display:block;font-size:18px}}
.hi b{{color:rgb(var(--bad))}} .mid b{{color:#d97706}} .lo b{{color:#16a34a}}
.scroll{{overflow-x:auto}}
table{{border-collapse:collapse;width:100%}} th,td{{border:1px solid var(--line);padding:3px 5px;font-size:12px}}
.grid td{{text-align:center;min-width:26px;cursor:pointer}}
.grid td.ok{{background:rgba(var(--ok),var(--a))}} .grid td.bad{{background:rgba(var(--bad),var(--a));outline:1px solid rgb(var(--bad))}}
.grid th{{white-space:nowrap;text-align:left}}
.w{{word-break:break-all}} .tag{{background:rgba(var(--bad),.15);border-radius:4px;padding:0 4px;margin-right:3px}}
pre{{background:var(--card);padding:8px;overflow-x:auto;font-size:12px}}
.mut{{color:var(--mut)}} button{{margin:6px 0}}
</style></head><body>
<h1>IP 접속 이력 · {html.escape(r['ip'])}</h1>
<div class="cards">
<div class="card">최초 접속<b>{r['first_seen'] or '-'}</b></div>
<div class="card">마지막 접속<b>{r['last_seen'] or '-'}</b></div>
<div class="card">액세스 요청<b>{r['access_requests']}건</b></div>
<div class="card">분당 최대<b>{r['peak_per_minute']}회</b></div>
<div class="card {level_cls}">위험도<b>{r['risk_level']} ({r['risk_score']}점)</b></div>
</div>
<h2>판단 근거</h2><ul>{reasons}</ul>
<h2>타임테이블 (날짜 × 시간대)</h2>
<p class="mut">칸 숫자 = 요청 건수. 진할수록 많음, 빨간 테두리 = 의심 행동 포함. 칸을 누르면 아래 상세 이력이 그 시간대만 보입니다.</p>
<div class="scroll"><table class="grid"><tr><th>날짜</th>{''.join(f'<th>{h:02d}</th>' for h in range(24))}</tr>
{''.join(rows)}</table></div>
<h2>권장 조치</h2><ol>{actions}</ol>
<p class="mut">명령 입력 위치: WildFly 설치 폴더에서 <code>bin/jboss-cli.sh --connect</code> 실행 후.</p>
<h2>시간순 상세 이력 <span id="flt" class="mut"></span></h2>
<button id="all">전체 보기</button>
<div class="scroll"><table id="detail"><tr><th>시간</th><th>출처</th><th>내용</th><th>상태</th><th>태그</th></tr>
{''.join(detail)}</table></div>
<script>
document.querySelectorAll('.grid td').forEach(td=>td.onclick=()=>{{
  const d=td.dataset.day,h=td.dataset.hour;
  document.querySelectorAll('#detail tr[data-day]').forEach(tr=>tr.hidden=!(tr.dataset.day===d&&tr.dataset.hour===h));
  document.getElementById('flt').textContent='— '+d+' '+String(h).padStart(2,'0')+'시';
}});
document.getElementById('all').onclick=()=>{{document.querySelectorAll('#detail tr').forEach(tr=>tr.hidden=false);
  document.getElementById('flt').textContent='';}};
</script>
</body></html>"""
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(doc)


# ---------------------------------------------------------------------------
# 5. 공용 함수 (MCP 서버에서도 사용)
# ---------------------------------------------------------------------------

def collect(ip: str, log_paths: List[str], since: Optional[str] = None,
            until: Optional[str] = None) -> List[Event]:
    match = ip_matcher(ip)
    t0 = datetime.fromisoformat(since) if since else None
    t1 = datetime.fromisoformat(until) if until else None
    out = []
    for e in read_events(find_log_files(log_paths)):
        if match(e.ip) and (not t0 or e.time >= t0) and (not t1 or e.time <= t1):
            out.append(e)
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="WildFly 로그 특정 IP 이력 분석기")
    ap.add_argument("--logs", nargs="+", default=["."], help="로그 파일 또는 폴더 (여러 개 가능)")
    ap.add_argument("--ip", help="조회할 IP 또는 대역 (예: 203.0.113.45, 203.0.113.0/24)")
    ap.add_argument("--since", help="시작 시각 (예: 2026-10-20 또는 2026-10-20T09:00)")
    ap.add_argument("--until", help="종료 시각")
    ap.add_argument("--top", type=int, help="IP 없이 실행 시: 요청이 많은 IP 상위 N개 표시")
    ap.add_argument("--html", help="타임테이블 HTML 저장 경로")
    ap.add_argument("--csv", help="이력 CSV 저장 경로 (엑셀에서 열기)")
    ap.add_argument("--json", action="store_true", help="결과를 JSON으로 출력")
    ap.add_argument("--limit", type=int, default=30, help="화면에 보여줄 이력 수")
    a = ap.parse_args(argv)

    if not a.ip:
        files = find_log_files(a.logs)
        print(f"{'IP':<40}{'요청수':>8}{'의심요청':>10}")
        for ip, cnt, bad in top_ips(files, a.top or 10):
            print(f"{ip:<40}{cnt:>8}{bad:>10}")
        print("\n자세히 보려면: --ip <IP> 를 붙여 다시 실행하세요.")
        print_skipped()
        return 0

    events = collect(a.ip, a.logs, a.since, a.until)
    r = analyze(events, a.ip)
    if a.json:
        print(json.dumps({"summary": r, "events": [e.to_dict() for e in events]}, ensure_ascii=False, indent=2))
    else:
        print_report(r, events, a.limit)
    if a.csv:
        write_csv(events, a.csv); print(f"\nCSV 저장: {a.csv}")
    if a.html:
        write_html(r, events, a.html); print(f"HTML 타임테이블 저장: {a.html}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
