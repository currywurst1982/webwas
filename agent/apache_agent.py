#!/usr/bin/env python3
"""
Apache 2.4 monitoring agent — Reports to WAS Agent Controller.
Monitors access/error logs, detects anomalies, sends stats via heartbeat.

Usage:
  python apache_agent.py --config /etc/apache-agent/config.yaml
  python apache_agent.py --config config_apache.yaml --simulate
"""
from __future__ import annotations

import json, logging, os, random, re, socket, subprocess, sys, time, uuid
from collections import defaultdict, deque
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import requests
import yaml

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("apache_agent")

VERSION = "1.0.0"

# ─── Log format parsers ───────────────────────────────────────────────────────

# Apache Combined Log Format
# 127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /index.html HTTP/1.0" 200 2326 "http://ref" "UA"
ACCESS_LOG_RE = re.compile(
    r'(?P<host>\S+)\s+\S+\s+\S+\s+'
    r'\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<method>\S+)\s+(?P<path>\S+)\s+(?P<proto>\S+)"\s+'
    r'(?P<status>\d{3})\s+(?P<size>\S+)'
    r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<ua>[^"]*)")?'
)

# Apache Error Log (Apache 2.4+)
# [Thu Oct 10 14:32:52.123456 2024] [core:notice] [pid 1234] AH00094: ...
ERROR_LOG_RE = re.compile(
    r'\[(?P<dt>[^\]]+)\]\s+'
    r'\[(?:(?P<module>[^:\]]+):)?(?P<level>\w+)\]\s+'
    r'(?:\[pid\s+\d+(?::\s*tid\s+\d+)?\]\s+)?'
    r'(?:\[client\s+(?P<client>[^\]]+)\]\s+)?'
    r'(?P<message>.+)'
)

# ─── Simulation data ──────────────────────────────────────────────────────────

_SIM_PATHS = [
    "/", "/index.html", "/api/v1/health", "/static/app.js",
    "/api/v1/users", "/api/v1/data", "/login", "/dashboard",
    "/images/logo.png", "/favicon.ico",
]
_SIM_IPS = [
    "192.168.1.1", "10.0.0.5", "203.0.113.1",
    "198.51.100.5", "172.16.0.1", "1.2.3.4",
]
_SIM_STATUS = [200]*70 + [304]*10 + [404]*8 + [301]*5 + [302]*3 + [500]*2 + [403]*1 + [503]*1


# ─── Data classes ─────────────────────────────────────────────────────────────

class AccessEntry:
    __slots__ = ("host", "method", "path", "status", "size", "raw")

    def __init__(self, host, method, path, status, size, raw):
        self.host   = host
        self.method = method
        self.path   = path
        self.status = int(status)
        self.size   = size
        self.raw    = raw

    def to_dict(self) -> dict:
        return {
            "host": self.host, "method": self.method, "path": self.path,
            "status": self.status, "size": self.size,
            "message": f"{self.method} {self.path} → {self.status}",
        }


class ErrorEntry:
    __slots__ = ("level", "client", "message", "raw")

    def __init__(self, level, client, message, raw):
        self.level   = (level or "error").lower()
        self.client  = client
        self.message = message
        self.raw     = raw

    def to_dict(self) -> dict:
        return {"level": self.level, "client": self.client or "",
                "message": self.message}


class ApacheAnomaly:
    def __init__(self, rule_name, severity, description, entry, remedy=None):
        self.id          = str(uuid.uuid4())[:8]
        self.rule_name   = rule_name
        self.severity    = severity
        self.description = description
        self.entry       = entry
        self.remedy      = remedy or []
        self.detected_at = datetime.now()

    def to_dict(self) -> dict:
        return {
            "id":          self.id,
            "rule_name":   self.rule_name,
            "severity":    self.severity,
            "description": self.description,
            "remedy":      self.remedy,
            "detected_at": self.detected_at.isoformat(),
            "log_entry":   self.entry.to_dict() if self.entry else {},
        }


# ─── Log parser ───────────────────────────────────────────────────────────────

class ApacheLogParser:
    def __init__(self, access_log: str, error_log: Optional[str] = None):
        self._access = Path(access_log)
        self._error  = Path(error_log) if error_log else None
        self._apos   = 0
        self._epos   = 0

    def open(self) -> bool:
        if not self._access.exists():
            logger.warning("Access log not found: %s", self._access)
            return False
        self._apos = self._access.stat().st_size
        if self._error and self._error.exists():
            self._epos = self._error.stat().st_size
        return True

    def read_new(self) -> Tuple[List[AccessEntry], List[ErrorEntry]]:
        return self._read_access(), self._read_errors()

    def _read_access(self) -> List[AccessEntry]:
        entries = []
        try:
            sz = self._access.stat().st_size
            if sz < self._apos:          # log rotated
                self._apos = 0
            with open(self._access, "r", errors="replace") as f:
                f.seek(self._apos)
                for line in f:
                    line = line.rstrip()
                    m = ACCESS_LOG_RE.match(line)
                    if m:
                        entries.append(AccessEntry(
                            host=m.group("host"), method=m.group("method"),
                            path=m.group("path"),  status=m.group("status"),
                            size=m.group("size"),  raw=line,
                        ))
                self._apos = f.tell()
        except Exception as e:
            logger.error("access log read error: %s", e)
        return entries

    def _read_errors(self) -> List[ErrorEntry]:
        if not self._error or not self._error.exists():
            return []
        entries = []
        try:
            sz = self._error.stat().st_size
            if sz < self._epos:
                self._epos = 0
            with open(self._error, "r", errors="replace") as f:
                f.seek(self._epos)
                for line in f:
                    line = line.rstrip()
                    m = ERROR_LOG_RE.match(line)
                    if m:
                        entries.append(ErrorEntry(
                            level=m.group("level"), client=m.group("client"),
                            message=m.group("message"), raw=line,
                        ))
                    elif line:
                        entries.append(ErrorEntry("error", None, line, line))
                self._epos = f.tell()
        except Exception as e:
            logger.error("error log read error: %s", e)
        return entries


# ─── Anomaly detector ─────────────────────────────────────────────────────────

class ApacheAnomalyDetector:
    def __init__(self,
                 err5xx_threshold: int = 5,
                 err5xx_window:    int = 60,
                 err4xx_threshold: int = 30,
                 err4xx_window:    int = 60,
                 ip_threshold:     int = 100,
                 ip_window:        int = 60):
        self._5xx:  deque = deque()
        self._4xx:  deque = deque()
        self._403:  deque = deque()
        self._ips:  Dict[str, deque] = defaultdict(deque)
        self.t5xx = err5xx_threshold;  self.w5xx = err5xx_window
        self.t4xx = err4xx_threshold;  self.w4xx = err4xx_window
        self.tip  = ip_threshold;      self.wip  = ip_window

    def analyze_access(self, entries: List[AccessEntry]) -> List[ApacheAnomaly]:
        anomalies: List[ApacheAnomaly] = []
        now = time.time()

        for e in entries:
            if e.status >= 500:
                anomalies.append(ApacheAnomaly(
                    "HTTP5xxError", "CRITICAL",
                    f"HTTP {e.status} 오류: {e.method} {e.path} (클라이언트: {e.host})",
                    e,
                    ["애플리케이션 로그를 확인하세요", "error.log에서 상세 원인을 확인하세요"],
                ))
                self._5xx.append(now)
            if e.status == 403:
                self._403.append(now)
            if 400 <= e.status < 500:
                self._4xx.append(now)
            self._ips[e.host].append(now)

        # 5xx storm
        self._5xx = deque(t for t in self._5xx if now - t < self.w5xx)
        if len(self._5xx) >= self.t5xx:
            anomalies.append(ApacheAnomaly(
                "HTTP5xxStorm", "CRITICAL",
                f"{self.w5xx}초 내 HTTP 5xx 오류 {len(self._5xx)}건 집중 발생",
                entries[-1] if entries else ErrorEntry("crit", None, "5xx storm", ""),
                ["서버 부하 및 애플리케이션 상태를 확인하세요", "apachectl graceful 재시작을 고려하세요"],
            ))
            self._5xx.clear()

        # 403 storm (potential attack)
        self._403 = deque(t for t in self._403 if now - t < self.w4xx)
        if len(self._403) >= 20:
            anomalies.append(ApacheAnomaly(
                "HTTP403Storm", "HIGH",
                f"{self.w4xx}초 내 403 Forbidden {len(self._403)}건 — 무단 접근 시도 가능성",
                entries[-1] if entries else ErrorEntry("warn", None, "403 storm", ""),
                ["mod_security 또는 fail2ban 설정을 검토하세요", "해당 IP 대역을 차단하세요"],
            ))
            self._403.clear()

        # 4xx storm
        self._4xx = deque(t for t in self._4xx if now - t < self.w4xx)
        if len(self._4xx) >= self.t4xx:
            anomalies.append(ApacheAnomaly(
                "HTTP4xxStorm", "MEDIUM",
                f"{self.w4xx}초 내 HTTP 4xx 오류 {len(self._4xx)}건 발생",
                entries[-1] if entries else ErrorEntry("warn", None, "4xx storm", ""),
                ["요청 경로 패턴을 분석하세요", "누락된 리소스를 확인하세요"],
            ))
            self._4xx.clear()

        # IP flood
        for ip, times in list(self._ips.items()):
            self._ips[ip] = deque(t for t in times if now - t < self.wip)
            if len(self._ips[ip]) >= self.tip:
                anomalies.append(ApacheAnomaly(
                    "IPFlood", "HIGH",
                    f"IP {ip}에서 {self.wip}초 내 {len(self._ips[ip])}건 과도한 요청",
                    ErrorEntry("warn", ip, f"IP flood from {ip}", ""),
                    [f"iptables -A INPUT -s {ip} -j DROP", "fail2ban 또는 mod_evasive 활성화를 고려하세요"],
                ))
                self._ips[ip].clear()

        return anomalies

    def analyze_errors(self, entries: List[ErrorEntry]) -> List[ApacheAnomaly]:
        anomalies: List[ApacheAnomaly] = []
        for e in entries:
            lvl = e.level
            if lvl in ("emerg", "alert", "crit"):
                anomalies.append(ApacheAnomaly(
                    "ApacheErrorCritical", "CRITICAL",
                    f"Apache 심각 오류 [{e.level.upper()}]: {e.message[:120]}",
                    e, ["error.log를 즉시 점검하세요", "서비스 재시작을 고려하세요"],
                ))
            elif lvl == "error":
                anomalies.append(ApacheAnomaly(
                    "ApacheError", "HIGH",
                    f"Apache 오류: {e.message[:120]}",
                    e, ["error.log를 점검하세요"],
                ))
        return anomalies


# ─── mod_status ───────────────────────────────────────────────────────────────

class ApacheModStatus:
    """Reads Apache runtime metrics from mod_status (machine-readable)."""

    def __init__(self, url: str = "http://localhost/server-status?auto", timeout: int = 5):
        self.url     = url
        self.timeout = timeout

    def fetch(self) -> dict:
        try:
            r = requests.get(self.url, timeout=self.timeout)
            r.raise_for_status()
            m: dict = {}
            for line in r.text.splitlines():
                if ":" in line:
                    k, _, v = line.partition(":")
                    k, v = k.strip(), v.strip()
                    try:
                        m[k] = float(v) if "." in v else int(v)
                    except ValueError:
                        m[k] = v
            return m
        except Exception as e:
            logger.debug("mod_status fetch failed: %s", e)
            return {}


# ─── Simulator ────────────────────────────────────────────────────────────────

class ApacheSimulator:
    def __init__(self, anomaly_rate: float = 0.05):
        self.anomaly_rate = anomaly_rate
        self._count = 0

    def next_entries(self, n: int = 5) -> Tuple[List[AccessEntry], List[ErrorEntry]]:
        access, errors = [], []
        for _ in range(n):
            self._count += 1
            status = random.choice(_SIM_STATUS)
            if random.random() < self.anomaly_rate:
                status = random.choice([500, 502, 503, 403, 503])
            path = random.choice(_SIM_PATHS)
            ip   = random.choice(_SIM_IPS)
            ts   = datetime.now().strftime("%d/%b/%Y:%H:%M:%S +0000")
            size = random.randint(200, 50000)
            raw  = f'{ip} - - [{ts}] "GET {path} HTTP/1.1" {status} {size}'
            access.append(AccessEntry(ip, "GET", path, status, str(size), raw))
            if status >= 500:
                errors.append(ErrorEntry(
                    "error", f"{ip}:12345",
                    f"[sim] Error serving {path}: Internal Server Error", "",
                ))
        return access, errors


# ─── System metrics ───────────────────────────────────────────────────────────

def _collect_system_metrics() -> dict:
    m: dict = {}
    if HAS_PSUTIL:
        try:
            m["cpu_percent"]  = psutil.cpu_percent(interval=0.2)
            vm = psutil.virtual_memory()
            m["mem_total_mb"] = int(vm.total / 1048576)
            m["mem_used_mb"]  = int(vm.used  / 1048576)
            m["mem_percent"]  = vm.percent
            du = psutil.disk_usage("/")
            m["disk_total_gb"] = round(du.total / 1073741824, 1)
            m["disk_used_gb"]  = round(du.used  / 1073741824, 1)
            m["disk_percent"]  = du.percent
            return m
        except Exception:
            pass
    # /proc fallback (Linux)
    try:
        with open("/proc/stat") as f:
            tok = f.readline().split()[1:]
        i1 = sum(int(x) for x in tok)
        time.sleep(0.2)
        with open("/proc/stat") as f:
            tok = f.readline().split()[1:]
        i2 = sum(int(x) for x in tok)
        idle2 = int(tok[3])
        dt = (i2 - i1) or 1
        m["cpu_percent"] = round(max(0, 100 - idle2 / dt * 100), 1)
    except Exception:
        m["cpu_percent"] = 0
    try:
        with open("/proc/meminfo") as f:
            info = {k.strip(): int(v.split()[0])
                    for k, v in (l.split(":", 1) for l in f if ":" in l)}
        total = info.get("MemTotal", 0)
        avail = info.get("MemAvailable", info.get("MemFree", 0))
        used  = total - avail
        m["mem_total_mb"] = int(total / 1024)
        m["mem_used_mb"]  = int(used  / 1024)
        m["mem_percent"]  = round(used / total * 100, 1) if total else 0
    except Exception:
        pass
    try:
        import shutil
        total, used, _ = shutil.disk_usage("/")
        m["disk_total_gb"] = round(total / 1073741824, 1)
        m["disk_used_gb"]  = round(used  / 1073741824, 1)
        m["disk_percent"]  = round(used / total * 100, 1) if total else 0
    except Exception:
        pass
    return m


# ─── Config ───────────────────────────────────────────────────────────────────

_DEFAULTS = {
    ("server",  "id"):               os.environ.get("AGENT_ID"),
    ("server",  "host"):              socket.gethostname(),
    ("controller", "url"):            os.environ.get("CONTROLLER_URL", "http://localhost:8380"),
    ("controller", "api_key"):        os.environ.get("CONTROLLER_API_KEY", ""),
    ("apache",  "access_log"):        "/var/log/apache2/access.log",
    ("apache",  "error_log"):         "/var/log/apache2/error.log",
    ("apache",  "mod_status_url"):    "http://localhost/server-status?auto",
    ("apache",  "version"):           "2.4",
    ("monitoring", "poll_interval"):  5,
    ("monitoring", "report_interval"): 30,
}


def _load_config(path: str) -> dict:
    with open(path) as f:
        cfg = yaml.safe_load(f) or {}
    for (sec, key), default in _DEFAULTS.items():
        if default is not None:
            cfg.setdefault(sec, {})
            cfg[sec].setdefault(key, default)
    return cfg


def _validate_config(cfg: dict):
    required = [("server", "id"), ("controller", "url"), ("apache", "access_log")]
    missing  = [(s, k) for s, k in required if not cfg.get(s, {}).get(k)]
    if missing:
        logger.error("Missing required config fields: %s", missing)
        sys.exit(1)


# ─── Agent ────────────────────────────────────────────────────────────────────

class ApacheAgent:
    def __init__(self, config_path: str, simulate: bool = False):
        if not Path(config_path).exists():
            logger.error("Config not found: %s", config_path)
            sys.exit(1)

        self.cfg            = _load_config(config_path)
        _validate_config(self.cfg)
        self.server_id      = self.cfg["server"]["id"]
        self.host           = self.cfg["server"].get("host", "") or socket.gethostname()
        self.controller_url = self.cfg["controller"]["url"].rstrip("/")
        self.api_key        = self.cfg["controller"].get("api_key", "")
        self.poll_interval  = int(self.cfg["monitoring"].get("poll_interval", 5))
        self.report_interval = int(self.cfg["monitoring"].get("report_interval", 30))
        self.simulate       = simulate

        ap = self.cfg.get("apache", {})
        self.apache_version       = ap.get("version", "2.4")
        self.apache_root          = ap.get("apache_root", "")   # e.g. /opt/apache-2.4.63
        # {date} 플레이스홀더 지원 — 오늘 날짜(YYYY-MM-DD)로 자동 치환
        self.access_log_template  = ap.get("access_log", "")
        self.error_log_template   = ap.get("error_log", "")
        self.access_log_path      = self._resolve_log_path(self.access_log_template)
        self.error_log_path       = self._resolve_log_path(self.error_log_template)
        self.mod_status_url       = ap.get("mod_status_url", "http://localhost/server-status?auto")
        self.mod_status           = ApacheModStatus(url=self.mod_status_url)

        # 포트 및 도메인 — 설정 우선, 없으면 Apache 설정 파일에서 자동 감지
        self.listen_ports = ap.get("listen_ports", "") or self._detect_listen_ports()
        self.domain       = ap.get("domain", "")       or self._detect_domain()
        if self.listen_ports or self.domain:
            logger.info("WEB info — listen: %s  domain: %s",
                        self.listen_ports or "—", self.domain or "—")

        # WEB-WAS 연동 체크 설정 (다중 WAS 지원)
        wc = self.cfg.get("was", {})
        connections_cfg = wc.get("connections", [])
        if not connections_cfg and wc.get("server_id"):
            # 레거시 단일 WAS 설정 호환
            connections_cfg = [{"server_id": wc["server_id"], "check_url": wc.get("check_url", "")}]
        self._was_connections_cfg = [
            {"server_id": c.get("server_id", ""), "check_url": c.get("check_url", "")}
            for c in connections_cfg if c.get("server_id")
        ]
        self.was_check_interval = int(wc.get("check_interval", 30))
        self.was_check_timeout  = int(wc.get("check_timeout", 5))
        # 연결 상태 딕셔너리: server_id → {check_url, connected, check_status, last_check}
        self._was_states: Dict[str, dict] = {
            c["server_id"]: {"check_url": c["check_url"], "connected": None, "check_status": 0, "last_check": 0.0}
            for c in self._was_connections_cfg
        }
        # 레거시 단일 속성 (외부 참조 호환용 — 첫 번째 WAS 기준)
        _first = self._was_connections_cfg[0] if self._was_connections_cfg else {}
        self.was_server_id = _first.get("server_id", "")
        self.was_check_url = _first.get("check_url", "")

        acfg = self.cfg.get("anomaly", {})
        self.detector = ApacheAnomalyDetector(
            err5xx_threshold = acfg.get("err5xx_threshold", 5),
            err5xx_window    = acfg.get("err5xx_window",    60),
            err4xx_threshold = acfg.get("err4xx_threshold", 30),
            err4xx_window    = acfg.get("err4xx_window",    60),
            ip_threshold     = acfg.get("ip_threshold",    100),
            ip_window        = acfg.get("ip_window",        60),
        )

        if simulate:
            self.simulator = ApacheSimulator(
                anomaly_rate=acfg.get("simulation_anomaly_rate", 0.05)
            )
            self.parser = None
            logger.info("Mode: SIMULATION (anomaly_rate=%.0f%%)",
                        acfg.get("simulation_anomaly_rate", 0.05) * 100)
        else:
            self.parser = ApacheLogParser(
                access_log=self.access_log_path,
                error_log=self.error_log_path or None,
            )
            self.simulator = None

        self._stats: Dict = defaultdict(int)
        self._pending: List[dict] = []

    # ── HTTP helpers ──────────────────────────────────────────────────────────

    def _headers(self) -> dict:
        h = {"Content-Type": "application/json"}
        if self.api_key:
            h["X-API-Key"] = self.api_key
        return h

    def _post(self, path: str, payload: dict, timeout: int = 10) -> bool:
        try:
            r = requests.post(
                self.controller_url + path, json=payload,
                headers=self._headers(), timeout=timeout,
            )
            r.raise_for_status()
            return True
        except Exception as e:
            logger.warning("POST %s failed: %s", path, e)
            return False

    def _get(self, path: str, timeout: int = 10):
        try:
            r = requests.get(
                self.controller_url + path,
                headers=self._headers(), timeout=timeout,
            )
            r.raise_for_status()
            return r.json()
        except Exception:
            return None

    # ── Registration ──────────────────────────────────────────────────────────

    def _register(self):
        logger.info("Registering Apache agent [%s]…", self.server_id)
        ok = self._post("/api/agents/register", {
            "server_id":      self.server_id,
            "host":           self.host,
            "server_type":    "apache",
            "wildfly_version": f"Apache/{self.apache_version}",
            "log_path":       self.cfg.get("apache", {}).get("access_log", ""),
            "simulate":       self.simulate,
            "registered_at":  datetime.now().isoformat(),
        })
        logger.info("Registration %s", "OK" if ok else "FAILED — will retry")

    # ── Log path resolution ───────────────────────────────────────────────────

    def _resolve_log_path(self, template: str) -> str:
        """{date} 플레이스홀더를 오늘 날짜(YYYY-MM-DD)로 치환합니다.
        플레이스홀더가 없으면 그대로 반환합니다.
        """
        if not template or '{date}' not in template:
            return template
        return template.replace('{date}', datetime.now().strftime('%Y-%m-%d'))

    # ── Port detection ────────────────────────────────────────────────────────

    def _detect_listen_ports(self) -> str:
        """Apache Listen 디렉티브에서 서비스 포트를 감지합니다.
        설정된 listen_ports가 없을 때만 호출됩니다.
        """
        conf_candidates = []
        if self.apache_root:
            conf_candidates += [
                f"{self.apache_root}/conf/httpd.conf",
                f"{self.apache_root}/conf/extra/httpd-ssl.conf",
            ]
        conf_candidates += [
            "/etc/apache2/ports.conf",
            "/etc/httpd/conf/httpd.conf",
        ]
        ports: list = []
        for cp in conf_candidates:
            if not os.path.exists(cp):
                continue
            try:
                with open(cp, errors="replace") as f:
                    for line in f:
                        line = line.strip()
                        if line.startswith("Listen ") and not line.startswith("#"):
                            val = line.split()[1]
                            port = val.split(":")[-1]   # handle "0.0.0.0:443" form
                            if port.isdigit() and port not in ports:
                                ports.append(port)
            except Exception as e:
                logger.debug("listen port detection error (%s): %s", cp, e)
        return ",".join(ports)

    def _detect_domain(self) -> str:
        """Apache 설정 파일에서 ServerName(서비스 도메인)을 감지합니다.
        설정된 domain이 없을 때만 호출됩니다.
        """
        conf_dirs = []
        if self.apache_root:
            conf_dirs += [
                f"{self.apache_root}/conf",
                f"{self.apache_root}/conf/extra",
            ]
        conf_dirs += [
            "/etc/apache2/sites-enabled",
            "/etc/apache2",
            "/etc/httpd/conf.d",
            "/etc/httpd/conf",
        ]
        for d in conf_dirs:
            if not os.path.exists(d):
                continue
            try:
                result = subprocess.run(
                    f"grep -rhi 'ServerName' \"{d}/\" 2>/dev/null",
                    shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5,
                )
                for line in result.stdout.decode("utf-8", errors="replace").splitlines():
                    line = line.strip()
                    if line.lower().startswith("servername") and not line.startswith("#"):
                        parts = line.split()
                        if len(parts) >= 2:
                            return parts[1]
            except Exception as e:
                logger.debug("domain detection error (%s): %s", d, e)
        return ""

    # ── WAS connectivity check ────────────────────────────────────────────────

    def _check_was_connection(self):
        """각 WAS check_url에 HTTP GET을 수행하여 WEB-WAS 연동 상태를 확인합니다.
        HTTP 200 응답이면 connected=True, 그 외 또는 오류면 False.
        was.check_interval 주기마다 실행됩니다.
        """
        now = time.time()
        for sid, state in self._was_states.items():
            if now - state["last_check"] < self.was_check_interval:
                continue
            state["last_check"] = now
            if not state["check_url"]:
                state["error"] = "check_url 미설정"
                continue
            try:
                r = requests.get(
                    state["check_url"],
                    timeout=self.was_check_timeout,
                    allow_redirects=True,
                )
                state["check_status"] = r.status_code
                state["connected"]    = (r.status_code == 200)
                state["error"]        = "" if r.status_code == 200 else f"HTTP {r.status_code}"
                logger.info("WAS check [%s] %s → HTTP %d  connected=%s",
                            sid, state["check_url"], r.status_code, state["connected"])
            except Exception as e:
                state["check_status"] = 0
                state["connected"]    = False
                state["error"]        = str(e)
                logger.warning("WAS check [%s] %s → 실패: %s", sid, state["check_url"], e)

    # ── Heartbeat ─────────────────────────────────────────────────────────────

    def _heartbeat(self):
        stats = dict(self._stats)
        stats.update(_collect_system_metrics())

        # Always include installation paths so the dashboard can build correct commands
        stats["apache_root"]      = self.apache_root
        stats["access_log_path"]  = self.access_log_path
        stats["error_log_path"]   = self.error_log_path
        stats["mod_status_url"]   = self.mod_status_url
        stats["listen_ports"]     = self.listen_ports
        stats["domain"]           = self.domain

        # WEB-WAS 연동 상태 (다중 WAS 지원)
        if self._was_states:
            conn_list = []
            for sid, state in self._was_states.items():
                entry = {
                    "server_id":    sid,
                    "check_url":    state["check_url"],
                    "connected":    state["connected"],
                    "check_status": state["check_status"],
                }
                if state.get("error"):
                    entry["error"] = state["error"]
                if state["last_check"]:
                    entry["last_check"] = datetime.fromtimestamp(state["last_check"]).isoformat()
                conn_list.append(entry)
            stats["was_connections"] = conn_list
            # 레거시 단일 필드 (첫 번째 WAS 기준 — UI 하위 호환성 유지)
            if conn_list:
                first = conn_list[0]
                stats["was_server_id"]    = first["server_id"]
                stats["was_check_url"]    = first["check_url"]
                stats["was_connected"]    = first["connected"]
                stats["was_check_status"] = first["check_status"]
                if "last_check" in first:
                    stats["was_last_check"] = first["last_check"]

        ms = self.mod_status.fetch()
        if ms:
            stats["busy_workers"]     = ms.get("BusyWorkers", ms.get("BusyW", 0))
            stats["idle_workers"]     = ms.get("IdleWorkers",  ms.get("IdleW", 0))
            stats["requests_per_sec"] = ms.get("ReqPerSec",   0)
            stats["bytes_per_sec"]    = ms.get("BytesPerSec", 0)
            stats["total_accesses"]   = ms.get("Total Accesses", ms.get("TotalAccesses", 0))

        self._post("/api/agents/heartbeat", {
            "server_id": self.server_id,
            "timestamp": datetime.now().isoformat(),
            "stats":     stats,
        }, timeout=5)

    # ── Anomaly reporting ─────────────────────────────────────────────────────

    def _send_anomalies(self, anomalies: List[dict]):
        if not anomalies:
            return
        self._post("/api/anomalies", {
            "server_id": self.server_id,
            "host":      self.host,
            "anomalies": anomalies,
            "timestamp": datetime.now().isoformat(),
        })
        logger.info("Reported %d anomaly/anomalies", len(anomalies))

    # ── Task execution (remediation / analysis commands) ──────────────────────

    def _poll_tasks(self):
        tasks = self._get(f"/api/agents/{self.server_id}/tasks")
        if not tasks:
            return
        for task in (tasks if isinstance(tasks, list) else [tasks]):
            self._execute_task(task)

    def _execute_task(self, task: dict):
        task_id   = task.get("task_id", "")
        rule_name = task.get("rule_name", "unknown")
        # Both os_commands and cli_commands are run as shell commands for Apache
        cmds = task.get("os_commands") or task.get("cli_commands") or []
        if not cmds:
            result = {"success": False, "output": "", "error": "실행할 명령이 없습니다"}
        else:
            # Analysis tasks: collect all output even if a command exits non-zero
            # (e.g. permission denied on log file — still useful to show partial output)
            is_analysis = rule_name.startswith("analysis_")
            result = self._run_os_commands(cmds, ignore_errors=is_analysis)
        logger.info("Task %s [%s] → %s", task_id, rule_name,
                    "OK" if result["success"] else "FAIL")
        self._post(f"/api/tasks/{task_id}/result", {
            "task_id":    task_id,
            "server_id":  self.server_id,
            "result": {
                "success": result["success"],
                "output":  result["output"][:65536],
                "error":   result["error"][:2048],
            },
            "executed_at": datetime.now().isoformat(),
        })

    def _run_os_commands(self, commands: List[str], ignore_errors: bool = False) -> dict:
        """Run shell commands sequentially.

        Args:
            commands: List of shell command strings.
            ignore_errors: When True, continue running subsequent commands even if
                one exits non-zero and accumulate all output (used for analysis tasks).
                The final success flag will be False if any command failed.
        """
        outputs = []
        errors  = []
        any_failed = False
        for cmd in commands:
            try:
                proc = subprocess.run(
                    cmd, shell=True, stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE, timeout=120,
                )
                stdout = proc.stdout.decode("utf-8", errors="replace")
                stderr = proc.stderr.decode("utf-8", errors="replace")
                if stdout:
                    outputs.append(stdout)
                if proc.returncode != 0:
                    err_msg = stderr.strip() or f"종료코드 {proc.returncode}"
                    errors.append(err_msg)
                    # Append stderr to output so the dashboard can show it
                    if stderr.strip():
                        outputs.append(f"[stderr] {stderr.strip()}")
                    any_failed = True
                    if not ignore_errors:
                        return {
                            "success": False,
                            "output":  "\n".join(outputs),
                            "error":   err_msg,
                        }
            except subprocess.TimeoutExpired:
                errors.append("명령 타임아웃 (120s)")
                any_failed = True
                if not ignore_errors:
                    return {"success": False, "output": "\n".join(outputs),
                            "error": "명령 타임아웃 (120s)"}
            except Exception as e:
                errors.append(str(e))
                any_failed = True
                if not ignore_errors:
                    return {"success": False, "output": "\n".join(outputs), "error": str(e)}
        return {
            "success": not any_failed,
            "output":  "\n".join(outputs),
            "error":   "; ".join(errors),
        }

    # ── Main loop ─────────────────────────────────────────────────────────────

    def _get_entries(self) -> Tuple[List[AccessEntry], List[ErrorEntry]]:
        time.sleep(self.poll_interval)
        if self.simulate:
            return self.simulator.next_entries(random.randint(2, 8))

        # {date} 플레이스홀더가 있는 경우 오늘 날짜로 재해석 — 자정 날짜 변경 자동 대응
        new_access = self._resolve_log_path(self.access_log_template)
        new_error  = self._resolve_log_path(self.error_log_template)
        if new_access != self.access_log_path or new_error != self.error_log_path:
            logger.info("날짜 변경 감지: %s → %s", self.access_log_path, new_access)
            self.access_log_path = new_access
            self.error_log_path  = new_error
            self.parser = ApacheLogParser(
                access_log=self.access_log_path,
                error_log=self.error_log_path or None,
            )
            if not self.parser.open():
                logger.warning("새 로그 파일 없음 — 다음 폴링에 재시도: %s", new_access)

        return self.parser.read_new()

    def run(self):
        logger.info("Apache Agent v%s  server_id=%s  host=%s  simulate=%s",
                    VERSION, self.server_id, self.host, self.simulate)
        if not self.simulate:
            if not self.parser.open():
                logger.warning("Log files not found yet — will retry each cycle")

        self._register()

        last_report = time.time()
        last_hb     = 0.0

        while True:
            try:
                access_entries, error_entries = self._get_entries()

                anomalies  = self.detector.analyze_access(access_entries)
                anomalies += self.detector.analyze_errors(error_entries)

                self._stats["entries_processed"] += len(access_entries)
                self._stats["anomalies_detected"] += len(anomalies)
                self._stats["requests_5xx"] += sum(1 for e in access_entries if e.status >= 500)
                self._stats["requests_4xx"] += sum(1 for e in access_entries if 400 <= e.status < 500)
                self._stats["requests_total"] += len(access_entries)

                if anomalies:
                    self._pending.extend(a.to_dict() for a in anomalies)
                    critical = [a for a in anomalies if a.severity == "CRITICAL"]
                    if critical:
                        self._send_anomalies([a.to_dict() for a in critical])
                        sent_ids = {a.id for a in critical}
                        self._pending = [p for p in self._pending if p["id"] not in sent_ids]

                now = time.time()
                self._check_was_connection()
                if now - last_hb >= 10:
                    self._heartbeat()
                    last_hb = now

                if now - last_report >= self.report_interval:
                    if self._pending:
                        self._send_anomalies(self._pending)
                        self._pending = []
                    last_report = now

                self._poll_tasks()

                if int(now) % 60 < self.poll_interval:
                    logger.info("Stats: %s", dict(self._stats))

            except KeyboardInterrupt:
                logger.info("Agent stopped.")
                break
            except Exception as e:
                logger.error("Unexpected error: %s", e, exc_info=True)
                time.sleep(5)


# ─── Entry point ─────────────────────────────────────────────────────────────

def main():
    import argparse
    ap = argparse.ArgumentParser(description="Apache 2.4 monitoring agent")
    ap.add_argument("--config",   default="config_apache.yaml",
                    help="Config YAML path")
    ap.add_argument("--simulate", action="store_true",
                    help="Simulate log entries (no real logs needed)")
    args = ap.parse_args()
    ApacheAgent(args.config, simulate=args.simulate).run()


if __name__ == "__main__":
    main()
