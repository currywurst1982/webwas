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
# 콘솔 로그(nohup.out 등)는 날짜 없이 시각만 찍히므로 날짜는 생략 가능, 밀리초 구분자는 , 또는 .
SERVER_RE = re.compile(
    r'^(?:(?P<date>\d{4}-\d{2}-\d{2})[ T])?(?P<time>\d{2}:\d{2}:\d{2})[,.](?P<ms>\d{3}) +(?P<level>[A-Z]+) +'
    r'\[(?P<category>[^\]]*)\] \((?P<thread>[^)]*)\) (?P<message>.*)$'
)
ANSI_RE = re.compile(r'\x1b\[[0-9;]*[A-Za-z]')   # 콘솔 로그의 색상 코드
# 형식을 모르는 줄에서 시각을 찾는 규칙 (위에서부터 먼저 맞는 것 사용)
TS_FULL_RE = re.compile(r'(\d{4})[-/.](\d{2})[-/.](\d{2})[ T](\d{2}):(\d{2}):(\d{2})')
TS_COMMON_RE = re.compile(r'(\d{2})/(\w{3})/(\d{4}):(\d{2}):(\d{2}):(\d{2})')
TS_TIME_RE = re.compile(r'(?:^|[\s\[])(\d{2}):(\d{2}):(\d{2})(?:[,.]\d+)?(?=[\s\]])')
FILE_DATE_RE = re.compile(r'(\d{4})-?(\d{2})-?(\d{2})')
MONTHS = {m: i for i, m in enumerate(["Jan", "Feb", "Mar", "Apr", "May", "Jun",
                                       "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], 1)}

IP_IN_TEXT_RE = re.compile(r'(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])')


@dataclass
class Event:
    time: datetime
    ip: str
    source: str            # "access", "server", "other"(형식 모름)
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


def _valid_ips(text: str) -> List[str]:
    out = []
    for ip in IP_IN_TEXT_RE.findall(text):
        if all(int(x) <= 255 for x in ip.split(".")) and ip not in out:
            out.append(ip)
    return out


def file_base_date(path: str) -> Optional[datetime]:
    """파일 이름의 날짜(access_log.2026-10-20.log 등), 없으면 파일 수정일."""
    m = FILE_DATE_RE.search(os.path.basename(path))
    if m and 1 <= int(m[2]) <= 12 and 1 <= int(m[3]) <= 31:
        return datetime(int(m[1]), int(m[2]), int(m[3]))
    try:
        return datetime.fromtimestamp(os.path.getmtime(path))
    except OSError:
        return None


def find_time(line: str, base: Optional[datetime]) -> Optional[datetime]:
    m = TS_FULL_RE.search(line)
    if m:
        try:
            return datetime(*map(int, m.groups()))
        except ValueError:
            pass
    m = TS_COMMON_RE.search(line)
    if m and m[2] in MONTHS:
        return datetime(int(m[3]), MONTHS[m[2]], int(m[1]), int(m[4]), int(m[5]), int(m[6]))
    m = TS_TIME_RE.search(line)
    if m and base:
        return base.replace(hour=int(m[1]), minute=int(m[2]), second=int(m[3]), microsecond=0)
    return None


def parse_server_line(line: str, file: str, base: Optional[datetime] = None) -> List[Event]:
    """server.log 한 줄에 들어 있는 IP마다 이벤트를 하나씩 만든다."""
    m = SERVER_RE.match(line)
    if not m:
        return []
    ips = _valid_ips(m["message"])
    if not ips:
        return []
    if m["date"]:
        t = datetime.strptime(f"{m['date']} {m['time']}", "%Y-%m-%d %H:%M:%S")
    elif base:
        t = datetime.strptime(f"{base:%Y-%m-%d} {m['time']}", "%Y-%m-%d %H:%M:%S")
    else:
        return []
    t = t.replace(microsecond=int(m["ms"]) * 1000)
    return [Event(time=t, ip=ip, source="server", file=os.path.basename(file),
                  level=m["level"], message=m["message"][:500]) for ip in ips]


def parse_other_line(line: str, file: str, base: Optional[datetime]) -> List[Event]:
    """형식을 모르는 줄: IP와 시각만 있으면 줄 전체를 내용으로 사용."""
    ips = _valid_ips(line)
    t = find_time(line, base) if ips else None
    if not t:
        return []
    return [Event(time=t, ip=ip, source="other", file=os.path.basename(file), message=line[:500]) for ip in ips]


def find_log_files(paths: Iterable[str]) -> List[str]:
    files = []
    for p in paths:
        if os.path.isdir(p):
            for name in sorted(os.listdir(p)):
                full = os.path.join(p, name)
                if os.path.isfile(full) and (".log" in name or name.endswith((".gz", ".out", ".txt"))):
                    files.append(full)
        elif os.path.isfile(p):
            files.append(p)
        else:
            print(f"[경고] 경로를 찾을 수 없습니다: {p}", file=sys.stderr)
    return files


# 파일별로 "IP는 있는데 형식·시각을 몰라 건너뛴 줄 수"를 기록 (로그 패턴이 다를 때 확인용)
SKIPPED: Counter = Counter()


def parse_line(line: str, f: str, base: Optional[datetime], is_server: bool) -> List[Event]:
    line = ANSI_RE.sub("", line)
    if not is_server:
        ev = parse_access_line(line, f)
        if ev:
            return [ev]
    if SERVER_RE.match(line):
        return parse_server_line(line, f, base)
    return parse_other_line(line, f, base)


def read_events(files: Iterable[str], sys_out: Optional[list] = None) -> Iterator[Event]:
    """sys_out 에 리스트를 주면 server.log 의 배포·재시작 기록도 모아 준다."""
    for f in files:
        is_server = os.path.basename(f).startswith("server.log")
        base = file_base_date(f)
        with _open(f) as fh:
            for line in fh:
                line = line.rstrip("\r\n")
                if not line.strip():
                    continue
                evs = parse_line(line, f, base, is_server)
                if evs:
                    base = evs[0].time   # 날짜 없는 다음 줄은 이 날짜를 이어받음
                    yield from evs
                    continue
                if sys_out is not None:
                    se = sys_event(line, base)
                    if se:
                        se["file"] = os.path.basename(f)
                        sys_out.append(se)
                        base = se["time"]
                        continue
                if _valid_ips(ANSI_RE.sub("", line)):
                    SKIPPED[os.path.basename(f)] += 1


def raw_search(ip: str, log_paths: List[str]) -> dict:
    """자동 인식으로 못 찾을 때 원문에서 글자 그대로 찾는다 (프록시 뒤 실제 IP, 특이한 형식)."""
    pat = re.compile(r"(?<![\d.])" + re.escape(ip) + r"(?![\d.])")
    events, front, samples, hits = [], Counter(), [], 0
    for f in find_log_files(log_paths):
        base = file_base_date(f)
        with _open(f) as fh:
            for line in fh:
                line = ANSI_RE.sub("", line.rstrip("\r\n"))
                if not pat.search(line):
                    continue
                hits += 1
                if len(samples) < 5:
                    samples.append(line[:300])
                ev = parse_access_line(line, f)
                if ev:
                    front[ev.ip] += 1
                    ev.tags.append("프록시경유")
                else:
                    t = find_time(line, base)
                    if not t:
                        continue
                    ev = Event(time=t, ip=ip, source="other", file=os.path.basename(f), message=line[:500])
                base = ev.time
                ev.ip = ip
                events.append(ev)
    return {"events": events, "front": front, "samples": samples, "hits": hits}


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
    if getattr(ev, "_tagged", False):
        return
    ev._tagged = True
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
        if ev.source == "other" and SCAN_RE.search(ev.message):
            ev.tags.append("스캔")


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
        "timeline": timeline_dicts(build_timeline(events)),
    }


# ---------------------------------------------------------------------------
# 2-1. 활동 타임라인: 시간순으로 "무엇을 했고 어떻게 처리됐나"를 묶어서 정리
#      (web/index.template.html 의 buildTimeline 과 같은 규칙)
# ---------------------------------------------------------------------------

SESSION_GAP = timedelta(minutes=30)      # 30분 넘게 기록이 없으면 새 접속으로 본다
STATIC_RE = re.compile(r"\.(css|js|png|jpe?g|gif|svg|ico|woff2?|ttf|map)(\?|$)", re.I)
TOOL_UA_RE = re.compile(r"(sqlmap|nikto|nmap|masscan|zgrab|nuclei|dirbuster|gobuster|wpscan|python-requests|"
                        r"Go-http-client|curl/|wget/|libwww-perl|httpclient)", re.I)
LOGIN_PATH_RE = re.compile(r"login|signin|j_security_check", re.I)
USER_RE = re.compile(r"user(?:name)?\s*[:=]?\s*'?([\w.@-]+)'?", re.I)
KIND = {
    "attack":   ("시도", "공격 시도 (인젝션 패턴)"),
    "scan":     ("시도", "관리·민감 경로 탐색"),
    "authfail": ("시도", "로그인·인증 실패"),
    "odd":      ("시도", "비표준 HTTP 요청"),
    "error":    ("특이사항", "서버 오류 발생"),
    "notfound": ("특이사항", "없는 주소 요청"),
    "burst":    ("특이사항", "과도한 반복 요청"),
    "warn":     ("특이사항", "서버 경고 기록"),
    "login":    ("업무", "로그인"),
    "work":     ("업무", "업무 요청"),
    "info":     ("업무", "서버 기록 (정상)"),
}
VERB = {"GET": "조회", "HEAD": "조회", "POST": "등록·처리", "PUT": "수정", "PATCH": "수정",
        "DELETE": "삭제", "OPTIONS": "확인"}


def _kind_of(e: Event) -> str:
    t = e.tags
    if "인젝션시도" in t: return "attack"
    if "스캔" in t: return "scan"
    if "인증실패" in t: return "authfail"
    if "비정상메서드" in t: return "odd"
    if "서버오류" in t: return "error"
    if e.source == "access":
        if e.status == 404:
            return "work" if STATIC_RE.search(e.path) else "notfound"
        if LOGIN_PATH_RE.search(e.path) and e.method == "POST" and e.status < 400:
            return "login"
        return "work"
    if e.level == "WARN":
        return "warn"
    if re.search(r"login (success|succeeded)|logged in", e.message, re.I):
        return "login"
    return "info"


def _norm_path(p: str) -> str:
    p = re.sub(r"/\d+(?=/|$)", "/{번호}", (p or "").split("?")[0])
    return re.sub(r"/[0-9a-f]{16,}(?=/|$)", "/{ID}", p, flags=re.I) or "/"


def _peak_per_minute(evs: List[Event]) -> int:
    c = Counter(e.time.replace(second=0, microsecond=0) for e in evs)
    return max(c.values()) if c else 0


def _block_detail(b: dict) -> None:
    acc = [e for e in b["events"] if e.source == "access"]
    logs = [e for e in b["events"] if e.source != "access"]
    what = []
    if acc:
        if b["kind"] in ("attack", "scan", "notfound"):
            paths = list(dict.fromkeys(e.path for e in acc))
            what.append(", ".join(paths[:5]) + (f" 외 {len(paths) - 5}개" if len(paths) > 5 else ""))
        else:
            main = [e for e in acc if not STATIC_RE.search(e.path)]
            c = Counter(f"{VERB.get(e.method, e.method)} {_norm_path(e.path)}" for e in (main or acc))
            txt = ", ".join(f"{k}{f' ×{v}' if v > 1 else ''}" for k, v in c.most_common(3))
            if len(c) > 3: txt += f" 외 {len(c) - 3}종"
            if main and len(main) < len(acc): txt += f" (화면 파일 {len(acc) - len(main)}건 제외)"
            what.append(txt)
    if logs:
        users = list(dict.fromkeys(m[1] for m in (USER_RE.search(e.message) for e in logs) if m))
        if users:
            what.append(f"{'시도한 계정' if b['kind'] == 'authfail' else '계정'}: {', '.join(users[:5])}")
        if not acc:
            what.append(logs[0].message[:120] + (f" 외 {len(logs) - 1}줄" if len(logs) > 1 else ""))
    res = []
    if acc:
        groups = [("성공", lambda s: 200 <= s < 400), ("거부", lambda s: s in (401, 403)),
                  ("없음(404)", lambda s: s == 404),
                  ("잘못된 요청", lambda s: 400 <= s < 500 and s not in (401, 403, 404)),
                  ("서버 오류", lambda s: s >= 500)]
        for name, f in groups:
            n = sum(1 for e in acc if f(e.status))
            if n: res.append(f"{name} {n}")
    if logs:
        lv = Counter(e.level or "기록" for e in logs)
        res.append("로그 " + ", ".join(f"{k} {v}" for k, v in lv.most_common(3)))
    note = []
    peak = _peak_per_minute(acc)
    if peak >= 60:
        note.append(f"분당 최대 {peak}회 (사람이 하기 어려운 속도)")
    elif len(acc) >= 10 and (b["end"] - b["start"]) < timedelta(minutes=1):
        note.append(f"1분 안에 {len(acc)}회 (자동화 의심)")
    if b["start"].hour < 6:
        note.append("새벽 시간대")
    tools = list(dict.fromkeys(m[1] for m in (TOOL_UA_RE.search(e.agent or "") for e in acc) if m))
    if tools:
        note.append(f"자동화 도구 흔적: {', '.join(tools)}")
    if any("프록시경유" in e.tags for e in b["events"]):
        note.append("프록시 경유 기록")
    if b["kind"] in ("scan", "attack") and any(e.status == 200 for e in acc):
        note.append("⚠ 일부 요청이 성공(200) — 실제 노출 여부 확인 필요")
    if b["kind"] == "attack" and any(e.status >= 500 for e in acc):
        note.append("⚠ 서버 오류로 응답 — 공격 입력이 내부(DB 등)까지 전달됐을 수 있음, 개발 담당 확인 필요")
    b.update(what=" · ".join(what) or "-", result=", ".join(res) or "-", notes=note)


def build_timeline(events: List[Event]) -> List[dict]:
    """시간순 이벤트를 같은 종류끼리 묶은 블록 목록으로 만든다. events 는 태그가 붙은 상태여야 한다."""
    out: List[dict] = []
    cur = None
    prev_end = None
    for e in events:
        k = _kind_of(e)
        new_sess = prev_end is None or e.time - prev_end > SESSION_GAP
        if cur is None or new_sess or cur["kind"] != k:
            cur = {"kind": k, "start": e.time, "end": e.time, "events": [],
                   "gap_before": (e.time - prev_end) if (new_sess and prev_end) else None}
            out.append(cur)
        cur["events"].append(e)
        cur["end"] = e.time
        prev_end = e.time
    for b in out:
        if b["kind"] == "work" and _peak_per_minute(b["events"]) >= 60:
            b["kind"] = "burst"
        b["group"], b["title"] = KIND[b["kind"]]
        _block_detail(b)
    return out


def _span(b: dict) -> str:
    s, e = b["start"], b["end"]
    if s == e:
        return f"{s:%H:%M:%S}"
    if s.replace(second=0, microsecond=0) == e.replace(second=0, microsecond=0):
        return f"{s:%H:%M:%S}~{e:%H:%M:%S}"
    return f"{s:%H:%M}~{e:%H:%M}"


def _dur(td: timedelta) -> str:
    sec = td.total_seconds()
    if sec < 60: return f"{max(1, round(sec))}초"
    if sec < 3600: return f"{round(sec / 60)}분"
    if sec < 86400: return f"{sec / 3600:.1f}시간"
    return f"{sec / 86400:.1f}일"


def timeline_text(label: str, tl: List[dict]) -> str:
    lines = [f"[IP 활동 타임라인] {label}"]
    day = None
    for b in tl:
        if b["start"].date() != day:
            day = b["start"].date()
            lines.append(f"\n■ {day} ({'월화수목금토일'[day.weekday()]})")
        gap = f"  ← 이전 활동 후 {_dur(b['gap_before'])} 만에 접속" if b["gap_before"] else ""
        lines.append(f"{_span(b)}  [{b['group']}] {b['title']} ({len(b['events'])}건){gap}")
        lines.append(f"    - 내용: {b['what']}")
        lines.append(f"    - 처리: {b['result']}")
        if b["notes"]:
            lines.append(f"    - 특이: {' / '.join(b['notes'])}")
    return "\n".join(lines)


def timeline_dicts(tl: List[dict]) -> List[dict]:
    return [{"start": b["start"].isoformat(), "end": b["end"].isoformat(), "group": b["group"],
             "title": b["title"], "count": len(b["events"]), "what": b["what"],
             "result": b["result"], "notes": b["notes"]} for b in tl]


# ---------------------------------------------------------------------------
# 2-2. 침해 시도 판정: 시도 유형별로 "성공했는가"를 로그 근거로 판단
#      (web/index.template.html 의 judgeFindings 와 같은 규칙)
#      판정: success=성공 정황 / check=확인 필요(로그만으로 판단 불가) / fail=실패·차단
# ---------------------------------------------------------------------------

VERDICT = {"success": ("성공 정황", 0), "check": ("확인 필요", 1), "fail": ("실패·차단", 2)}
SIGS = [
    ("webshell", "웹셸·명령 실행 시도", re.compile(
        r"(^|[?&;])(cmd|exec|command|execute|run)=|whoami|/bin/(ba)?sh|cmd\.exe|powershell|[;|`]\s*(id|uname|ls)\b|"
        r"\b(wget|curl)\s+https?:|/(shell|cmd|backdoor|webshell|jspspy|behinder|godzilla)\w*\.jspx?", re.I), False),
    ("jboss", "JBoss·WildFly 알려진 취약 경로", re.compile(
        r"/invoker/(JMXInvokerServlet|EJBInvokerServlet|readonly)|/jmx-console|/web-console|/admin-console|"
        r"/jbossmq-httpil|/status\?full", re.I), False),
    ("jndi", "Log4Shell(JNDI) 시도", re.compile(r"\$\{\s*(jndi|lower|upper|env|sys|::-)", re.I), True),
    ("sqli", "SQL 인젝션 시도", re.compile(
        r"union\s+(all\s+)?select|(\s|')or\s+'?1'?\s*=\s*'?1|sleep\s*\(|benchmark\s*\(|waitfor\s+delay|"
        r"information_schema|'\s*--", re.I), False),
    ("xss", "스크립트 삽입(XSS) 시도", re.compile(r"<script|javascript:|onerror\s*=|onload\s*=|<svg", re.I), False),
    ("traversal", "경로 조작(상위 폴더·시스템 파일)", re.compile(
        r"\.\.[/\\]|/etc/(passwd|shadow)|win\.ini|WEB-INF/(web|jboss-web)\.xml", re.I), False),
    ("sensitive", "민감 파일 탐색", re.compile(
        r"/\.env\b|/\.git/|/\.svn|/\.DS_Store|\.(bak|old|swp|sql|tar|tgz|zip)(\?|$)|/backup|"
        r"/config\.(php|json|ya?ml)|/server-status|/phpinfo", re.I), False),
    ("admin", "관리 화면 접근", re.compile(
        r"/manager/html|/console(/|$)|wp-admin|wp-login|phpmyadmin|/admin(/|$)|/actuator", re.I), False),
]
LOGIN_OK_RE = re.compile(r"login (success|succeeded)|logged in", re.I)
# server.log 에 남는 서버 변경 기록 (WildFly 37 실제 메시지 코드로 확인)
SYS_RULES = [
    (re.compile(r"WFLYDR0001|Content added at location"), "배포 파일 추가", "deploy"),
    (re.compile(r"WFLYUT0021|Registered web context"), "새 웹 경로 등록", "deploy"),
    (re.compile(r'WFLYSRV0010|Deployed "'), "배포 완료", "deploy"),
    (re.compile(r"WFLYSRV0016|Replaced deployment"), "배포 교체", "deploy"),
    (re.compile(r"WFLYSRV0153|Failed to process phase"), "배포 실패", "deploy"),
    (re.compile(r'WFLYSRV0009|Undeployed "'), "배포 제거", "undeploy"),
    (re.compile(r"WFLYDR0002|Content removed from location"), "배포 파일 삭제", "undeploy"),
    (re.compile(r"WFLYSRV0241|Shutting down in response to management"), "관리 명령으로 종료", "restart"),
    (re.compile(r"WFLYSRV0050"), "서버 종료", "restart"),
    (re.compile(r"WFLYSRV0025|WFLYSRV0026"), "서버 시작", "restart"),
    (re.compile(r"WFLYCTL0013"), "관리 작업 실패", "mgmt"),
]


def sys_event(line: str, base: Optional[datetime]) -> Optional[dict]:
    m = SERVER_RE.match(ANSI_RE.sub("", line))
    if not m:
        return None
    rule = next((r for r in SYS_RULES if r[0].search(m["message"])), None)
    if not rule:
        return None
    if m["date"]:
        t = datetime.strptime(f"{m['date']} {m['time']}", "%Y-%m-%d %H:%M:%S")
    elif base:
        t = datetime.strptime(f"{base:%Y-%m-%d} {m['time']}", "%Y-%m-%d %H:%M:%S")
    else:
        return None
    tm = re.search(r'"([^"]+)"|\'([^\']+)\'', m["message"])
    return {"time": t, "label": rule[1], "cat": rule[2],
            "target": (tm[1] or tm[2]) if tm else "", "msg": m["message"][:300]}


def _decode(x: str) -> str:
    from urllib.parse import unquote_plus
    try:
        return unquote_plus(x or "")
    except Exception:
        return x or ""


def _kb(n: int) -> str:
    return f"{n / 1048576:.1f}MB" if n >= 1048576 else f"{n / 1024:.1f}KB" if n >= 1024 else f"{n}바이트"


def _short(x: str) -> str:
    x = _decode(x)
    return x if len(x) <= 70 else x[:67] + "…"


def _ex(e: Event) -> str:
    return f"{e.time:%H:%M:%S} {_short(e.path)} → {e.status}, {_kb(e.size)}"


def _status_summary(A: List[Event]) -> str:
    c = Counter(e.status or "-" for e in A)
    return ", ".join(f"{k}×{v}" for k, v in c.items())


def _median(v: list):
    v = sorted(v)
    return v[len(v) // 2]


def build_baseline(events: Iterable[Event]) -> dict:
    """주소별 평소 응답 크기. 한 IP가 많이 요청해도 쏠리지 않게 IP별 중앙값의 중앙값."""
    m: dict = defaultdict(lambda: defaultdict(list))
    for e in events:
        if e.source == "access" and 200 <= e.status < 300 and not e.tags:
            m[e.path.split("?")[0]][e.ip].append(e.size)
    return {k: _median([_median(v) for v in by_ip.values()]) for k, by_ip in m.items()}


def _judge(sig: str, A: List[Event], hits: List[Event], base: dict):
    ok = [e for e in A if 200 <= e.status < 300]
    redir = [e for e in A if 300 <= e.status < 400]
    err = [e for e in A if e.status >= 500]
    ok_sized = [e for e in ok if e.size > 0]
    fail = ("fail", f"{len(A)}건 모두 실패·차단 ({_status_summary(A)})" if A else f"서버 로그에만 {len(hits)}줄 기록", "")
    if sig == "webshell":
        if ok:
            return ("success", f"명령 실행 형태의 요청이 200으로 응답됨 {len(ok)}건 (예: {_ex(ok[0])})",
                    "해당 파일이 서버에 실제로 있는지 즉시 확인(배포 폴더, 업로드 폴더). 있으면 서버를 네트워크에서 분리하고 "
                    "파일·로그를 지우지 말고 보존한 뒤 보안 담당에 보고하세요.")
        if err:
            return ("check", f"서버 오류(5xx) {len(err)}건 — 명령이 일부 처리됐을 수 있음", "같은 시각 server.log의 ERROR 내용을 확인하세요.")
        return fail
    if sig == "jboss":
        if ok:
            return ("success", f"알려진 취약 관리 경로가 200으로 응답 {len(ok)}건 (예: {_ex(ok[0])})",
                    "이 경로를 외부에서 즉시 막고, 같은 시각 이후 server.log의 배포·관리 기록을 확인하세요.")
        if redir:
            return ("check", f"다른 페이지로 이동(3xx) {len(redir)}건 — 로그인 화면으로 보냈을 가능성",
                    "해당 주소를 브라우저로 열어 무엇이 나오는지 확인하세요.")
        return fail
    if sig == "jndi":
        n = len(A) or len(hits)
        return ("check", f"{n}건" + (f" (응답: {_status_summary(A)})" if A else "") + " — 웹 로그만으로는 성공 여부를 알 수 없음",
                "같은 시각에 서버에서 외부로 나간 연결(LDAP 389·1389, RMI 1099, 의심 도메인 DNS 조회)이 있었는지 방화벽·DNS 로그를 "
                "확인하고, 배포된 앱에 log4j-core 2.0~2.14.1이 들어 있는지 확인하세요.")
    if sig == "sqli":
        def is_big(e):
            b = base.get(e.path.split("?")[0])
            return b is not None and e.size > max(b * 1.5, b + 1024)
        big = [e for e in ok if is_big(e)]
        if big:
            b = base[big[0].path.split("?")[0]]
            return ("success", f"평소 응답({_kb(b)})보다 훨씬 큰 응답 {len(big)}건 (예: {_ex(big[0])}) → 데이터가 추가로 나갔을 가능성",
                    "해당 기능이 어떤 테이블을 조회하는지 개발 담당과 확인하고, DB 접근 기록을 확인하세요. "
                    "개인정보가 포함됐다면 유출 신고 대상인지 검토가 필요합니다.")
        if ok:
            return ("check", f"200 응답 {len(ok)}건 — 응답 크기로는 데이터 노출 여부를 판단할 수 없음",
                    "해당 요청을 개발 환경에서 재현해 결과가 달라지는지 확인하세요.")
        if err:
            return ("check", f"서버 오류(500) 유발 {len(err)}건 → 입력값이 DB 쿼리에 들어갔을 가능성(취약점 단서)",
                    "이후 같은 주소로 반복 시도가 있었는지, 응답 크기가 달라진 요청이 있는지 확인하세요.")
        return fail
    if sig == "xss":
        if ok:
            return ("check", f"200 응답 {len(ok)}건 — 입력값이 화면에 그대로 나오면 다른 사용자가 피해를 볼 수 있음",
                    "같은 주소에 해당 입력을 넣었을 때 스크립트가 실행되는지 개발 담당이 확인하세요.")
        return fail
    if sig == "traversal":
        if ok_sized:
            return ("success", f"상위 폴더·시스템 파일 요청이 200으로 응답 {len(ok_sized)}건 (예: {_ex(ok_sized[0])}) → 파일 내용 유출 가능성",
                    "응답 크기가 실제 파일 크기와 비슷한지 확인하고, 해당 기능을 막으세요.")
        return fail
    if sig == "sensitive":
        if ok_sized:
            return ("success", f"민감 파일 요청이 200으로 응답 {len(ok_sized)}건 (예: {_ex(ok_sized[0])})",
                    "해당 파일을 외부에서 받을 수 없게 막고, 파일 안에 있던 비밀번호·접속키를 모두 교체하세요.")
        return fail
    if sig == "admin":
        if ok:
            return ("check", f"관리 화면이 200으로 응답 {len(ok)}건 (예: {_ex(ok[0])})",
                    "이 IP가 관리 권한이 있는 사용자인지 확인하고, 관리 화면은 사내 IP만 접근하도록 제한하세요.")
        return fail
    return ("check", "", "")


def judge_findings(ip: str, evs: List[Event], base: dict) -> List[dict]:
    """한 IP의 이벤트(시간순)에서 침해 시도와 성공 여부를 판정한다."""
    for e in evs:
        tag_event(e)
    F: List[dict] = []

    def add(typ, name, lst, res):
        if lst:
            v, why, nxt = res
            F.append({"ip": ip, "type": typ, "name": name, "verdict": v, "why": why, "next": nxt,
                      "count": len(lst), "start": lst[0].time, "end": lst[-1].time, "events": lst})

    claimed = set()
    for sid, name, rx, use_ua in SIGS:
        hits = []
        for e in evs:
            if sid in ("traversal", "sensitive") and id(e) in claimed:
                continue
            txt = (e.path + " " + _decode(e.path) + (" " + e.agent if use_ua else "")) if e.source == "access" else e.message
            if rx.search(txt):
                hits.append(e)
        if sid == "webshell":
            claimed.update(id(e) for e in hits)
        if hits:
            add(sid, name, hits, _judge(sid, [e for e in hits if e.source == "access"], hits, base))

    acc = [e for e in evs if e.source == "access"]
    posts = [e for e in acc if e.method == "POST" and LOGIN_PATH_RE.search(e.path)]
    fails = [e for e in evs if "인증실패" in e.tags]
    if len(fails) >= 3 or len(posts) >= 10:
        t0 = (fails or posts)[0].time
        acc_fail = [f for f in fails if f.source == "access"]
        log_fail = [f for f in fails if f.source != "access"]
        succ = [e for e in evs if e.time >= t0 and (
            (e.source == "access" and acc_fail and e.method == "POST" and LOGIN_PATH_RE.search(e.path) and 200 <= e.status < 400)
            or (e.source != "access" and LOGIN_OK_RE.search(e.message)))]
        users = list(dict.fromkeys(m[1] for m in (USER_RE.search(e.message) for e in evs if e.source != "access") if m))
        ok_user = next((m[1] for m in (USER_RE.search(e.message) for e in succ if e.source != "access") if m), None)
        fail_txt = ", ".join(x for x in [acc_fail and f"웹 응답 거부 {len(acc_fail)}회",
                                         log_fail and f"서버 로그 실패 기록 {len(log_fail)}줄"] if x) or f"로그인 요청 {len(posts)}회"
        tried = f" · 시도한 계정: {', '.join(users)}" if users else ""
        lst = sorted({id(e): e for e in fails + posts + succ}.values(), key=lambda e: e.time)
        if succ:
            res = ("success", f"로그인 실패({fail_txt}) 뒤 {succ[0].time:%Y-%m-%d %H:%M:%S} 로그인 성공"
                              + (f" (계정: {ok_user})" if ok_user else "") + tried,
                   "해당 계정 비밀번호를 즉시 바꾸고 접속 중인 세션을 끊으세요. 성공 이후 이 IP가 한 일을 활동 타임라인에서 확인하세요.")
        elif len(posts) >= 10 and not acc_fail:
            c = Counter(f"{e.status}/{e.size}" for e in posts)
            major = c.most_common(1)[0][0]
            odd = [e for e in posts if f"{e.status}/{e.size}" != major]
            res = ("check", (f"로그인 요청 {len(posts)}건이 상태코드로 실패를 구분할 수 없음. 응답이 다른 요청 {len(odd)}건 "
                             f"(예: {_ex(odd[0])}) → 이때 성공했을 가능성") if odd else
                   f"로그인 요청 {len(posts)}건 — 앱이 실패에도 같은 응답을 줘서 성공 여부 판단 불가",
                   "앱의 로그인 성공 기록(감사 로그)이나 해당 시각 세션 생성 기록을 확인하세요.")
        else:
            res = ("fail", f"로그인 실패({fail_txt}), 성공 기록 없음{tried}", "")
        add("brute", "로그인 무차별 대입", lst, res)

    per = Counter(e.time.replace(second=0, microsecond=0) for e in acc)
    if per and max(per.values()) >= 60:
        peak = max(per.values())
        bu = [e for e in acc if per[e.time.replace(second=0, microsecond=0)] >= 60]
        ok = [e for e in bu if 200 <= e.status < 300]
        add("burst", "대량 반복 요청", bu,
            ("check", f"분당 최대 {peak}회, 성공 응답 {len(ok)}건 (총 {_kb(sum(e.size for e in ok))}) → 자동화된 대량 수집 가능성",
             "어떤 데이터를 가져갔는지 해당 주소 기능을 확인하고, 필요하면 요청 횟수 제한을 거세요.")
            if len(ok) / len(bu) > 0.5 else ("fail", f"분당 최대 {peak}회, 대부분 실패 응답", ""))
    tools = [e for e in acc if TOOL_UA_RE.search(e.agent or "")]
    if tools:
        names = ", ".join(dict.fromkeys(TOOL_UA_RE.search(e.agent)[1] for e in tools))
        add("tool", "공격·자동화 도구 사용", tools,
            ("check", f"User-Agent에 도구 이름: {names} ({len(tools)}건)",
             "User-Agent는 조작이 쉬워 참고용입니다. 같은 IP의 다른 시도와 함께 판단하세요."))
    return F


def group_sys(sys_events: List[dict]) -> List[dict]:
    """배포 한 번에 여러 줄이 남으므로 1분 안의 같은 종류 기록은 한 건으로 묶는다."""
    out: List[dict] = []
    for d in sorted(sys_events, key=lambda x: x["time"]):
        g = out[-1] if out else None
        if g and g["cat"] == d["cat"] and d["time"] - g["end"] <= timedelta(minutes=1):
            g["end"] = d["time"]
            if d["label"] not in g["labels"]: g["labels"].append(d["label"])
            if d["target"] and d["target"] not in g["targets"]: g["targets"].append(d["target"])
        else:
            out.append({"cat": d["cat"], "time": d["time"], "end": d["time"], "labels": [d["label"]],
                        "targets": [d["target"]] if d["target"] else []})
    for g in out:
        g["label"], g["target"] = " · ".join(g["labels"]), ", ".join(g["targets"])
    return out


def correlate(findings: List[dict], sys_events: List[dict]) -> List[dict]:
    """공격 시도 뒤 24시간 안에 배포가 있으면(재시작은 성공 정황이 있을 때만) 연결한다."""
    out = []
    for d in group_sys(sys_events):
        if d["cat"] not in ("deploy", "restart"):
            continue
        by_ip: dict = {}
        for f in findings:
            if f["verdict"] == "fail" or f["type"] in ("burst", "tool") or not f["events"]:
                continue
            before = [e for e in f["events"] if e.time <= d["time"]]
            if not before or d["time"] - before[-1].time > timedelta(hours=24):
                continue
            last = before[-1].time
            cur = by_ip.get(f["ip"])
            succ = (cur["succ"] if cur else False) or f["verdict"] == "success"
            if not cur or last > cur["last"]:
                by_ip[f["ip"]] = {"last": last, "f": f, "succ": succ}
            else:
                cur["succ"] = succ
        for ip, x in by_ip.items():
            if d["cat"] == "restart" and not x["succ"]:
                continue
            out.append({"ip": ip, "type": "postdeploy", "name": "공격 시도 뒤 서버 변경",
                        "verdict": "success" if x["succ"] else "check",
                        "why": f"{d['time']:%Y-%m-%d %H:%M:%S} {d['label']}" + (f' "{d["target"]}"' if d["target"] else "")
                               + f" — 이 IP의 '{x['f']['name']}' {_dur(d['time'] - x['last'])} 뒤",
                        "next": "이 배포·재시작이 승인된 작업인지 운영 담당에게 확인하세요. 아니라면 배포 파일을 지우지 말고 보존한 뒤 "
                                "제거하고, WildFly 관리 계정 비밀번호를 바꾸세요.",
                        "count": 1, "start": d["time"], "end": d["time"], "events": []})
    return out


def scan_incidents(log_paths: List[str]) -> dict:
    """모든 IP의 침해 시도와 서버 변경 이력을 한 번에 점검한다."""
    sys_events: List[dict] = []
    by_ip: dict = defaultdict(list)
    all_events = []
    for e in read_events(find_log_files(log_paths), sys_events):
        tag_event(e)
        by_ip[e.ip].append(e)
        all_events.append(e)
    base = build_baseline(all_events)
    findings = []
    for ip, evs in by_ip.items():
        evs.sort(key=lambda e: e.time)
        findings += judge_findings(ip, evs, base)
    findings += correlate(findings, sys_events)
    findings.sort(key=lambda f: (VERDICT[f["verdict"]][1], f["start"]))
    times = [e.time for e in all_events]
    return {"findings": findings, "sys": sorted(sys_events, key=lambda d: d["time"]), "base": base,
            "period": (min(times), max(times)) if times else None}


def incident_text(findings: List[dict], sys_events: Optional[List[dict]], title: str) -> str:
    L = [f"[침해 시도 점검] {title}", "※ 로그 기반 추정입니다. 확정하려면 서버 파일·DB·네트워크 기록 확인이 필요합니다."]
    for v in ("success", "check", "fail"):
        fs = [f for f in findings if f["verdict"] == v]
        if not fs:
            continue
        L.append(f"\n■ {VERDICT[v][0]} ({len(fs)})")
        for f in fs:
            rng = f"{f['start']:%Y-%m-%d %H:%M:%S}" + (f" ~ {f['end']:%Y-%m-%d %H:%M:%S}" if f["end"] != f["start"] else "")
            L.append(f"- {rng} | {f['ip']} | {f['name']} ({f['count']}건)")
            L.append(f"    근거: {f['why']}")
            if f["next"]:
                L.append(f"    확인할 것: {f['next']}")
    if sys_events:
        L.append("\n■ 서버 변경 이력 (server.log)")
        for d in sys_events:
            L.append(f"- {d['time']:%Y-%m-%d %H:%M:%S} {d['label']}" + (f' "{d["target"]}"' if d["target"] else ""))
    return "\n".join(L)


def findings_dicts(fs: List[dict]) -> List[dict]:
    return [dict({k: (v.isoformat() if isinstance(v, datetime) else v) for k, v in f.items() if k != "events"},
                 verdict_label=VERDICT[f["verdict"]][0]) for f in fs]


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
    print(f" 액세스 요청: {r['access_requests']}건 / 서버·기타 로그: {r['server_log_lines']}건")
    print(f" 응답 코드  : {r['status_count']}")
    print(f" 분당 최대  : {r['peak_per_minute']}회 ({r['peak_minute']})")
    print(f" 위험도     : {r['risk_level']} (점수 {r['risk_score']})")
    for reason in r["reasons"]:
        print(f"   - {reason}")
    print("\n[많이 요청한 경로]")
    for p, c in r["top_paths"]:
        print(f"   {c:>5}  {p}")
    if r.get("findings_text"):
        print("\n" + r["findings_text"])
    tl = build_timeline(events)
    print("\n" + timeline_text(r["ip"], tl[:200]).replace("[IP 활동 타임라인]", "[활동 타임라인 — 시간순 정리]", 1))
    if len(tl) > 200:
        print(f"   … 전체 {len(tl)}개 구간 중 처음 200개만 표시 (--since/--until 로 기간을 나눠 보세요)")
    print(f"\n[개별 기록 — 최근 {limit}건]")
    for e in events[-limit:]:
        what = f"{e.method} {e.path} -> {e.status}" if e.source == "access" else f"{e.level} {e.message[:80]}".strip()
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
        print("\n[참고] IP가 있지만 형식·시각을 인식하지 못해 건너뛴 줄:")
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
    gcls = {"업무": "g-work", "시도": "g-try", "특이사항": "g-odd"}
    tl_rows, day = [], None
    for b in build_timeline(events):
        if b["start"].date() != day:
            day = b["start"].date()
            tl_rows.append(f'<tr class="tlday"><td colspan="5">{day} ({"월화수목금토일"[day.weekday()]})</td></tr>')
        gap = f'<div class="mut">이전 활동 후 {_dur(b["gap_before"])} 만에 접속</div>' if b["gap_before"] else ""
        tl_rows.append(
            f'<tr><td class="t">{_span(b)}<div class="mut">{len(b["events"])}건</div>{gap}</td>'
            f'<td><span class="gb {gcls[b["group"]]}">{b["group"]}</span><div class="mut">{html.escape(b["title"])}</div></td>'
            f'<td class="w">{html.escape(b["what"])}</td><td>{html.escape(b["result"])}</td>'
            f'<td>{"".join(f"<div>{html.escape(n)}</div>" for n in b["notes"]) or "-"}</td></tr>')
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
.tl td{{vertical-align:top}} .tl td.t{{white-space:nowrap}} .tlday td{{background:var(--card);font-weight:700}}
.gb{{font-size:11px;font-weight:700;border-radius:4px;padding:1px 6px;white-space:nowrap}}
.g-work{{background:rgba(var(--ok),.15);color:rgb(var(--ok))}} .g-try{{background:rgba(var(--bad),.15);color:rgb(var(--bad))}}
.g-odd{{background:rgba(217,119,6,.15);color:#d97706}}
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
<h2>활동 타임라인 (시간순 정리)</h2>
<p class="mut">같은 종류의 행동이 이어지면 한 줄로 묶었습니다. 30분 넘게 기록이 없으면 새 접속으로 나눕니다.</p>
<div class="scroll"><table class="tl"><tr><th>시간</th><th>구분</th><th>무엇을 했나</th><th>처리 결과</th><th>특이사항</th></tr>
{''.join(tl_rows)}</table></div>
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
    ap.add_argument("--incident", action="store_true",
                    help="모든 IP의 침해 시도와 성공 여부, 서버 변경(배포·재시작) 이력을 점검")
    a = ap.parse_args(argv)

    if a.incident:
        res = scan_incidents(a.logs)
        p = res["period"]
        title = f"로그 기간 {p[0]:%Y-%m-%d %H:%M} ~ {p[1]:%Y-%m-%d %H:%M}" if p else "로그 없음"
        if a.json:
            print(json.dumps({"findings": findings_dicts(res["findings"]),
                              "server_changes": [{**d, "time": d["time"].isoformat()} for d in res["sys"]]},
                             ensure_ascii=False, indent=2))
        else:
            print(incident_text(res["findings"], res["sys"], title))
            if not res["findings"]:
                print("\n알려진 공격 패턴은 발견되지 않았습니다. 이 도구가 아는 패턴만 검사하므로 '공격이 없었다'는 뜻은 아닙니다.")
            print_skipped()
        return 0

    if not a.ip:
        files = find_log_files(a.logs)
        print(f"{'IP':<40}{'요청수':>8}{'의심요청':>10}")
        for ip, cnt, bad in top_ips(files, a.top or 10):
            print(f"{ip:<40}{cnt:>8}{bad:>10}")
        print("\n자세히 보려면: --ip <IP> 를 붙여 다시 실행하세요.")
        print_skipped()
        return 0

    events = collect(a.ip, a.logs, a.since, a.until)
    if not events and "/" not in a.ip:
        rs = raw_search(a.ip, a.logs)
        if not rs["hits"]:
            print(f"[알림] 원문 전체에서도 {a.ip} 를 찾지 못했습니다. 입력값, 로그 기간, 프록시 여부를 확인하세요.")
            print_skipped()
            return 1
        print(f"[알림] 자동 인식으로는 못 찾아 원문 글자 검색으로 찾았습니다 ({rs['hits']}줄).")
        if rs["front"]:
            fr = ", ".join(f"{ip}({c}줄)" for ip, c in rs["front"].most_common(3))
            print(f"[주의] 이 줄들의 맨 앞(접속 IP 자리)에는 {fr} 가 찍혀 있습니다. 프록시·로드밸런서일 가능성이 높습니다.")
            print("       그렇다면 아래 차단 명령은 효과가 없고, 앞단 장비에서 막아야 합니다.")
        print("[원문 예시]\n   " + "\n   ".join(rs["samples"]) + "\n")
        events = rs["events"]
        if a.since or a.until:
            t0 = datetime.fromisoformat(a.since) if a.since else datetime.min
            t1 = datetime.fromisoformat(a.until) if a.until else datetime.max
            events = [e for e in events if t0 <= e.time <= t1]
    r = analyze(events, a.ip)
    # 침해 시도 판정 (평소 응답 크기 기준과 배포 기록은 전체 로그에서 계산)
    inc = scan_incidents(a.logs)
    mine = judge_findings(a.ip, sorted(events, key=lambda e: e.time), inc["base"])
    mine += [f for f in inc["findings"] if f["type"] == "postdeploy" and f["ip"] == a.ip]
    mine.sort(key=lambda f: (VERDICT[f["verdict"]][1], f["start"]))
    r["findings"] = findings_dicts(mine)
    r["findings_text"] = incident_text(mine, None, f"IP {a.ip}") if mine else \
        "[침해 시도 점검] 알려진 공격 패턴은 발견되지 않았습니다 (도구가 모르는 방식일 수 있음)."
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
