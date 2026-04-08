#!/usr/bin/env python3
"""
WildFly 26 Log Monitoring Agent
================================
Monitors WildFly server.log, detects anomalies, and reports to a central controller.

Usage:
    python wildfly_agent.py [config.yaml]
    python wildfly_agent.py [config.yaml] --simulate     # demo mode with fake log entries
"""

import argparse
import json
import logging
import os
import random
import socket
import sys
import time
import uuid
from collections import deque, defaultdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Tuple

try:
    import requests
    import yaml
except ImportError:
    print("[ERROR] Missing dependencies. Run: pip install requests pyyaml")
    sys.exit(1)

# ─── Logging ──────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)-8s] %(name)s - %(message)s",
    handlers=[logging.StreamHandler()],
)
logger = logging.getLogger("wildfly-agent")

# ─── WildFly 26 log line pattern ──────────────────────────────────────────────
# Format:  YYYY-MM-DD HH:MM:SS,mmm  LEVEL  [logger]  (thread)  message
import re

LOG_RE = re.compile(
    r"^(?P<date>\d{4}-\d{2}-\d{2})\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2},\d{3})\s+"
    r"(?P<level>TRACE|DEBUG|INFO|WARN|ERROR|FATAL)\s+"
    r"\[(?P<logger>[^\]]*)\]\s+"
    r"\((?P<thread>[^)]*)\)\s*"
    r"(?P<message>.*)"
)

# ─── Anomaly detection rules ──────────────────────────────────────────────────
ANOMALY_RULES: List[Dict] = [
    {
        "name": "OutOfMemoryError",
        "pattern": re.compile(r"OutOfMemoryError|java\.lang\.OutOfMemory", re.I),
        "severity": "CRITICAL",
        "description": "JVM out-of-memory error",
    },
    {
        "name": "GCOverheadLimit",
        "pattern": re.compile(r"GC overhead limit exceeded", re.I),
        "severity": "CRITICAL",
        "description": "Garbage collection overhead limit exceeded",
    },
    {
        "name": "Deadlock",
        "pattern": re.compile(r"deadlock|ARJUNA016051", re.I),
        "severity": "CRITICAL",
        "description": "Thread or transaction deadlock detected",
    },
    {
        "name": "StackOverflow",
        "pattern": re.compile(r"StackOverflowError", re.I),
        "severity": "HIGH",
        "description": "Stack overflow error",
    },
    {
        "name": "DeploymentFailure",
        "pattern": re.compile(
            r"WFLYSRV\d+.*[Ff]ailed|deployment.*failed|[Ff]ailed.*deploy", re.I
        ),
        "severity": "HIGH",
        "description": "Application deployment failure",
    },
    {
        "name": "ConnectionPoolExhausted",
        "pattern": re.compile(
            r"IJ000604|connection pool.*full|no connection available|pool.*exhaust",
            re.I,
        ),
        "severity": "HIGH",
        "description": "Database connection pool exhausted",
    },
    {
        "name": "TransactionTimeout",
        "pattern": re.compile(
            r"transaction.*timed out|ARJUNA016|TransactionRolledback", re.I
        ),
        "severity": "HIGH",
        "description": "Transaction timeout or rollback",
    },
    {
        "name": "JDBCError",
        "pattern": re.compile(r"SQLException|JDBC.*[Ee]rror|could not execute", re.I),
        "severity": "HIGH",
        "description": "JDBC/SQL database error",
    },
    {
        "name": "NetworkError",
        "pattern": re.compile(
            r"SocketTimeoutException|Connection refused|Connection reset|UnknownHostException",
            re.I,
        ),
        "severity": "MEDIUM",
        "description": "Network connectivity error",
    },
    {
        "name": "NullPointerException",
        "pattern": re.compile(r"NullPointerException", re.I),
        "severity": "MEDIUM",
        "description": "Null pointer exception",
    },
    {
        "name": "ClassLoadingError",
        "pattern": re.compile(
            r"ClassNotFoundException|NoClassDefFoundError|ClassCastException", re.I
        ),
        "severity": "MEDIUM",
        "description": "Class loading or casting error",
    },
    {
        "name": "SecurityViolation",
        "pattern": re.compile(
            r"SecurityException|AccessControlException|WFLYSEC\d+", re.I
        ),
        "severity": "HIGH",
        "description": "Security violation or access denied",
    },
    {
        "name": "EJBError",
        "pattern": re.compile(
            r"EJBException|EJBTransactionRolled|WFLYEJB\d+.*[Ee]rror", re.I
        ),
        "severity": "MEDIUM",
        "description": "Enterprise JavaBeans error",
    },
    {
        "name": "FileDescriptorLimit",
        "pattern": re.compile(r"Too many open files", re.I),
        "severity": "HIGH",
        "description": "OS file descriptor limit reached",
    },
    {
        "name": "MessagingError",
        "pattern": re.compile(
            r"JMSException|ActiveMQException|WFLYMSG\d+.*[Ee]rror", re.I
        ),
        "severity": "MEDIUM",
        "description": "JMS/ActiveMQ messaging error",
    },
]

# ─── Simulation data ───────────────────────────────────────────────────────────
_SIM_NORMAL = [
    ("INFO",  "org.jboss.as",                   "WFLYSRV0025: WildFly Full 26.1.3.Final started in {ms}ms - Started {s1} of {s2} services"),
    ("INFO",  "org.wildfly.extension.undertow",  "WFLYUT0006: Undertow HTTP listener default listening on 0.0.0.0:8080"),
    ("INFO",  "org.jboss.as.server",             "WFLYSRV0010: Deployed \"myapp.war\" (runtime-name : \"myapp.war\")"),
    ("INFO",  "org.hibernate.dialect",           "HHH000400: Using dialect: org.hibernate.dialect.MySQL8Dialect"),
    ("DEBUG", "org.jboss.as.ejb3",              "WFLYEJB0022: EJB method MyService.process() completed in {ms}ms"),
    ("INFO",  "org.jboss.as.connector",          "WFLYJCA0001: Bound data source [java:jboss/datasources/MyDS]"),
    ("INFO",  "io.undertow.request",             "GET /api/health HTTP/1.1  200  {ms}ms"),
    ("INFO",  "io.undertow.request",             "POST /api/users HTTP/1.1  201  {ms}ms"),
    ("INFO",  "org.jboss.as.ejb3",              "Started message driven bean MyMDB"),
    ("DEBUG", "org.hibernate",                   "Hibernate: select u from User u where u.id = ?"),
]

_SIM_ANOMALY = [
    ("ERROR", "org.jboss.as.server",         "java.lang.OutOfMemoryError: Java heap space"),
    ("ERROR", "org.jboss.as.server",         "WFLYSRV0020: Failed to deploy \"myapp.war\": java.lang.Exception: Deployment failed"),
    ("ERROR", "org.wildfly.transaction",     "ARJUNA016051: thread is already associated with a transaction! Deadlock detected"),
    ("WARN",  "org.jboss.as.connector",      "IJ000604: Timed out waiting for a connection, pool: MyDS connection pool is full"),
    ("ERROR", "org.hibernate",               "WFLYJPA0007: Internal Exception: java.sql.SQLException: Connection reset"),
    ("ERROR", "org.wildfly.security",        "WFLYSEC0047: SecurityException: Access denied for resource [/admin/delete]"),
    ("ERROR", "io.undertow",                 "java.lang.NullPointerException at com.example.UserService.findById(UserService.java:142)"),
    ("WARN",  "org.jboss.as.ejb3",          "WFLYEJB0136: Transaction rolled back. XA transaction could not commit"),
    ("ERROR", "org.jboss.as",               "GC overhead limit exceeded"),
    ("WARN",  "io.undertow.request",         "UT005023: Exception handling request /api/orders: java.net.SocketTimeoutException: Read timed out"),
    ("ERROR", "org.wildfly.transaction",     "Transaction timed out after 60 seconds and has been rolled back"),
    ("FATAL", "org.jboss.as.server",         "WFLYSRV0024: WildFly Full 26.1.3.Final stopped"),
    ("ERROR", "org.jboss.as.naming",         "java.lang.ClassNotFoundException: com.example.MissingService"),
    ("ERROR", "org.jboss.as.server",         "java.io.IOException: Too many open files"),
    ("ERROR", "org.wildfly.messaging",       "ActiveMQException[errorType=CONNECTION_TIMEDOUT]: Connection timed out to server"),
    ("ERROR", "org.jboss.as.ejb3",          "EJBException: javax.ejb.EJBTransactionRolledbackException: Transaction rolled back"),
    ("ERROR", "org.jboss.as.server",         "java.lang.StackOverflowError at com.example.RecursiveProcessor.process"),
]


# ─── Data models ──────────────────────────────────────────────────────────────
class LogEntry:
    __slots__ = ("timestamp", "level", "logger", "thread", "message")

    def __init__(
        self,
        timestamp: datetime,
        level: str,
        logger: str,
        thread: str,
        message: str,
    ):
        self.timestamp = timestamp
        self.level = level
        self.logger = logger
        self.thread = thread
        self.message = message

    def to_dict(self) -> Dict:
        return {
            "timestamp": self.timestamp.isoformat(),
            "level": self.level,
            "logger": self.logger,
            "thread": self.thread,
            "message": self.message[:1024],
        }


class AnomalyEvent:
    def __init__(self, rule_name: str, severity: str, description: str, entry: LogEntry):
        self.id = str(uuid.uuid4())[:8]
        self.rule_name = rule_name
        self.severity = severity
        self.description = description
        self.entry = entry
        self.detected_at = datetime.now()

    def to_dict(self) -> Dict:
        return {
            "id": self.id,
            "rule_name": self.rule_name,
            "severity": self.severity,
            "description": self.description,
            "detected_at": self.detected_at.isoformat(),
            "log_entry": self.entry.to_dict(),
        }


# ─── Error storm detector ──────────────────────────────────────────────────────
class ErrorStormDetector:
    """Detects burst of ERROR/FATAL messages within a sliding time window."""

    def __init__(self, threshold: int = 10, window_seconds: int = 60):
        self.threshold = threshold
        self.window_seconds = window_seconds
        self._queue: deque = deque()
        self._active = False

    def feed(self, level: str) -> bool:
        """Feed a log level. Returns True when a new storm is first detected."""
        if level not in ("ERROR", "FATAL"):
            return False

        now = datetime.now()
        self._queue.append(now)
        cutoff = now - timedelta(seconds=self.window_seconds)
        while self._queue and self._queue[0] < cutoff:
            self._queue.popleft()

        if len(self._queue) >= self.threshold:
            if not self._active:
                self._active = True
                return True  # storm just started
        else:
            self._active = False
        return False


# ─── Log file parser ───────────────────────────────────────────────────────────
class WildflyLogParser:
    """Tails WildFly 26 server.log and yields LogEntry objects."""

    def __init__(self, log_path: str):
        self.log_path = Path(log_path)
        self._fd = None
        self._pos = 0
        self._buf: List[str] = []

    def open(self) -> bool:
        if not self.log_path.exists():
            logger.warning("Log file not found: %s  (retrying…)", self.log_path)
            return False
        self._fd = open(self.log_path, "r", encoding="utf-8", errors="replace")
        self._fd.seek(0, 2)  # start from end
        self._pos = self._fd.tell()
        logger.info("Monitoring log: %s", self.log_path)
        return True

    def _handle_rotation(self):
        try:
            if self.log_path.stat().st_size < self._pos:
                logger.info("Log rotation detected — reopening")
                self._fd.close()
                self._fd = open(self.log_path, "r", encoding="utf-8", errors="replace")
                self._pos = 0
        except FileNotFoundError:
            pass

    def read_new_entries(self) -> List[LogEntry]:
        if not self._fd:
            if not self.open():
                return []

        self._handle_rotation()
        self._fd.seek(self._pos)
        lines = self._fd.readlines()
        self._pos = self._fd.tell()

        entries: List[LogEntry] = []
        for line in lines:
            line = line.rstrip("\n")
            m = LOG_RE.match(line)
            if m:
                if self._buf:
                    e = self._flush()
                    if e:
                        entries.append(e)
                self._buf = [line]
            elif self._buf:
                self._buf.append(line)

        return entries

    def _flush(self) -> Optional[LogEntry]:
        if not self._buf:
            return None
        first = self._buf[0]
        extra = "\n".join(self._buf[1:]) if len(self._buf) > 1 else ""
        self._buf = []

        m = LOG_RE.match(first)
        if not m:
            return None
        try:
            ts = datetime.strptime(
                f"{m.group('date')} {m.group('time')}", "%Y-%m-%d %H:%M:%S,%f"
            )
        except ValueError:
            ts = datetime.now()

        msg = m.group("message")
        if extra:
            msg += "\n" + extra

        return LogEntry(ts, m.group("level"), m.group("logger"), m.group("thread"), msg)

    def close(self):
        if self._fd:
            self._fd.close()
            self._fd = None


# ─── Anomaly detector ──────────────────────────────────────────────────────────
class AnomalyDetector:
    def __init__(self, storm_threshold: int = 10, storm_window: int = 60):
        self._storm = ErrorStormDetector(storm_threshold, storm_window)

    def analyze(self, entries: List[LogEntry]) -> List[AnomalyEvent]:
        results: List[AnomalyEvent] = []
        for entry in entries:
            # Error storm check
            if self._storm.feed(entry.level):
                results.append(
                    AnomalyEvent(
                        "ErrorStorm",
                        "CRITICAL",
                        f"Error storm: ≥{self._storm.threshold} errors in {self._storm.window_seconds}s",
                        entry,
                    )
                )

            if entry.level == "FATAL":
                results.append(
                    AnomalyEvent("FatalError", "CRITICAL", "FATAL level log message", entry)
                )
                continue

            if entry.level in ("ERROR", "WARN"):
                matched = False
                for rule in ANOMALY_RULES:
                    if rule["pattern"].search(entry.message):
                        results.append(
                            AnomalyEvent(
                                rule["name"], rule["severity"], rule["description"], entry
                            )
                        )
                        matched = True
                        break
                if not matched and entry.level == "ERROR":
                    results.append(
                        AnomalyEvent("GenericError", "LOW", "Unclassified application error", entry)
                    )

        return results


# ─── Log simulator ──────────────────────────────────────────────────────────────
class WildflyLogSimulator:
    """Generates realistic WildFly 26 log entries for demo/testing."""

    def __init__(self, anomaly_rate: float = 0.08):
        self.anomaly_rate = anomaly_rate

    def next_entries(self, count: int = 1) -> List[LogEntry]:
        entries = []
        for _ in range(count):
            now = datetime.now()
            if random.random() < self.anomaly_rate:
                level, log_name, msg = random.choice(_SIM_ANOMALY)
            else:
                level, log_name, tmpl = random.choice(_SIM_NORMAL)
                msg = tmpl.format(
                    ms=random.randint(1, 5000),
                    s1=random.randint(100, 999),
                    s2=random.randint(1000, 1200),
                )
            thread = f"ServerService Thread Pool -- {random.randint(1, 64)}"
            entries.append(LogEntry(now, level, log_name, thread, msg))
        return entries


# ─── Config loader ─────────────────────────────────────────────────────────────
def _load_config(path: str) -> Dict:
    """Load YAML config with environment variable overrides."""
    with open(path) as f:
        cfg = yaml.safe_load(f)

    # Environment overrides (useful for Docker deployments)
    env_map: Dict[Tuple, str] = {
        ("server", "id"):          os.environ.get("AGENT_ID"),
        ("server", "host"):        os.environ.get("AGENT_HOST"),
        ("controller", "url"):     os.environ.get("CONTROLLER_URL"),
        ("controller", "api_key"): os.environ.get("API_KEY"),
        ("wildfly", "log_path"):   os.environ.get("WILDFLY_LOG_PATH"),
    }
    for keys, val in env_map.items():
        if val is not None:
            d = cfg
            for k in keys[:-1]:
                d = d.setdefault(k, {})
            d[keys[-1]] = val

    return cfg


# ─── Agent ────────────────────────────────────────────────────────────────────
class WildflyAgent:
    def __init__(self, config_path: str, simulate: bool = False):
        cfg_file = Path(config_path)
        if not cfg_file.exists():
            logger.error("Config not found: %s", config_path)
            sys.exit(1)

        self.cfg = _load_config(config_path)
        self.server_id: str = self.cfg["server"]["id"]
        self.host: str = self.cfg["server"].get("host", socket.gethostname())
        self.controller_url: str = self.cfg["controller"]["url"].rstrip("/")
        self.api_key: str = self.cfg["controller"].get("api_key", "")
        self.poll_interval: int = self.cfg["monitoring"].get("poll_interval", 5)
        self.report_interval: int = self.cfg["monitoring"].get("report_interval", 30)
        self.simulate: bool = simulate

        anomaly_cfg = self.cfg.get("anomaly", {})
        self.detector = AnomalyDetector(
            storm_threshold=anomaly_cfg.get("error_storm_threshold", 10),
            storm_window=anomaly_cfg.get("error_storm_window", 60),
        )

        if simulate:
            logger.info("Mode: SIMULATION (anomaly_rate=%.0f%%)", anomaly_cfg.get("simulation_anomaly_rate", 0.08) * 100)
            self.simulator = WildflyLogSimulator(
                anomaly_rate=anomaly_cfg.get("simulation_anomaly_rate", 0.08)
            )
            self.parser = None
        else:
            self.parser = WildflyLogParser(self.cfg["wildfly"]["log_path"])
            self.simulator = None

        self._pending: List[Dict] = []
        self._stats: Dict = defaultdict(int)
        self._last_report = datetime.now()
        self._running = False

    @property
    def _headers(self) -> Dict:
        return {
            "Content-Type": "application/json",
            "X-API-Key": self.api_key,
            "X-Agent-ID": self.server_id,
        }

    def _post(self, path: str, payload: Dict, timeout: int = 10) -> bool:
        try:
            r = requests.post(
                f"{self.controller_url}{path}",
                json=payload,
                headers=self._headers,
                timeout=timeout,
            )
            r.raise_for_status()
            return True
        except requests.exceptions.ConnectionError:
            logger.warning("Controller unreachable: %s", self.controller_url)
        except requests.exceptions.Timeout:
            logger.warning("Request timed out: %s", path)
        except Exception as e:
            logger.warning("POST %s failed: %s", path, e)
        return False

    def _register(self):
        logger.info("Registering [%s] with controller…", self.server_id)
        ok = self._post(
            "/api/agents/register",
            {
                "server_id": self.server_id,
                "host": self.host,
                "wildfly_version": "26",
                "log_path": self.cfg["wildfly"]["log_path"],
                "simulate": self.simulate,
                "registered_at": datetime.now().isoformat(),
            },
        )
        if ok:
            logger.info("Registration OK")
        else:
            logger.warning("Registration failed — will retry on next heartbeat")

    def _heartbeat(self):
        self._post(
            "/api/agents/heartbeat",
            {
                "server_id": self.server_id,
                "timestamp": datetime.now().isoformat(),
                "stats": dict(self._stats),
            },
            timeout=5,
        )

    def _send_anomalies(self, anomalies: List[Dict]):
        if not anomalies:
            return
        ok = self._post(
            "/api/anomalies",
            {
                "server_id": self.server_id,
                "host": self.host,
                "anomalies": anomalies,
                "timestamp": datetime.now().isoformat(),
            },
        )
        if ok:
            logger.info("Reported %d anomaly/anomalies to controller", len(anomalies))

    def _get_entries(self) -> List[LogEntry]:
        time.sleep(self.poll_interval)
        if self.simulate:
            return self.simulator.next_entries(random.randint(1, 6))
        return self.parser.read_new_entries()

    def run(self):
        logger.info(
            "=== WildFly Agent starting === id=%s  host=%s  controller=%s",
            self.server_id, self.host, self.controller_url,
        )
        self._running = True

        if self.parser:
            self.parser.open()

        self._register()

        while self._running:
            try:
                entries = self._get_entries()
                if entries:
                    anomalies = self.detector.analyze(entries)
                    self._stats["entries_processed"] += len(entries)
                    self._stats["anomalies_detected"] += len(anomalies)

                    if anomalies:
                        self._pending.extend(a.to_dict() for a in anomalies)

                        # Send CRITICAL immediately without waiting for next report cycle
                        critical = [a for a in anomalies if a.severity == "CRITICAL"]
                        if critical:
                            self._send_anomalies([a.to_dict() for a in critical])
                            sent_ids = {c.id for c in critical}
                            self._pending = [p for p in self._pending if p["id"] not in sent_ids]

                # Periodic report
                elapsed = (datetime.now() - self._last_report).total_seconds()
                if elapsed >= self.report_interval:
                    self._heartbeat()
                    if self._pending:
                        self._send_anomalies(self._pending)
                        self._pending.clear()
                    self._last_report = datetime.now()
                    logger.info("Stats: %s", dict(self._stats))

            except KeyboardInterrupt:
                logger.info("Shutdown requested")
                self._running = False
            except Exception as e:
                logger.exception("Unexpected error: %s", e)

        if self.parser:
            self.parser.close()
        logger.info("Agent stopped")


# ─── Entry point ───────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="WildFly 26 Log Monitoring Agent")
    parser.add_argument(
        "config",
        nargs="?",
        default="config.yaml",
        help="Path to config file (default: config.yaml)",
    )
    parser.add_argument(
        "--simulate",
        action="store_true",
        help="Simulation mode — generate synthetic WildFly log entries for demo",
    )
    args = parser.parse_args()

    agent = WildflyAgent(args.config, simulate=args.simulate)
    try:
        agent.run()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
