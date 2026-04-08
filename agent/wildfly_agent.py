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
import subprocess
import sys
import tempfile
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

# ─── Anomaly detection rules (description + remedy + cli_commands) ────────────
ANOMALY_RULES: List[Dict] = [
    {
        "name": "OutOfMemoryError",
        "pattern": re.compile(r"OutOfMemoryError|java\.lang\.OutOfMemory", re.I),
        "severity": "CRITICAL",
        "description": "JVM 힙 메모리 부족으로 OutOfMemoryError 발생",
        "remedy": [
            "standalone.conf의 -Xmx 값을 증가시켜 힙 메모리를 늘립니다 (예: -Xmx2g → -Xmx4g)",
            "jmap -dump:format=b,file=heap.hprof <pid> 로 힙 덤프를 수집해 메모리 누수를 분석합니다",
            "불필요한 캐시, static 컬렉션, 세션 데이터를 점검합니다",
            "WildFly 재시작 후 메모리 사용량 추세를 모니터링합니다",
        ],
        "cli_commands": [
            "/core-service=platform-mbean/type=memory:read-attribute(name=heap-memory-usage)",
            "/core-service=platform-mbean/type=memory:read-attribute(name=non-heap-memory-usage)",
            "/core-service=platform-mbean/type=garbage-collector=*:read-resource(include-runtime=true)",
            "/core-service=platform-mbean/type=memory-pool=*:read-resource(include-runtime=true)",
        ],
    },
    {
        "name": "GCOverheadLimit",
        "pattern": re.compile(r"GC overhead limit exceeded", re.I),
        "severity": "CRITICAL",
        "description": "GC가 전체 시간의 98% 이상 점유 — 힙 메모리 거의 고갈 상태",
        "remedy": [
            "힙 크기를 증가합니다: standalone.conf에서 -Xmx 값 상향",
            "GC 알고리즘을 G1GC로 변경합니다: -XX:+UseG1GC",
            "메모리 누수 여부를 힙 덤프로 확인합니다",
            "단기 처방으로 -XX:-UseGCOverheadLimit 추가하여 즉시 크래시 방지 후 근본 원인 분석",
        ],
        "cli_commands": [
            "/core-service=platform-mbean/type=memory:read-attribute(name=heap-memory-usage)",
            "/core-service=platform-mbean/type=garbage-collector=*:read-resource(include-runtime=true)",
            "/core-service=platform-mbean/type=runtime:read-attribute(name=input-arguments)",
        ],
    },
    {
        "name": "Deadlock",
        "pattern": re.compile(r"deadlock|ARJUNA016051", re.I),
        "severity": "CRITICAL",
        "description": "스레드 또는 트랜잭션 데드락 감지",
        "remedy": [
            "jstack <pid> 로 스레드 덤프를 수집해 데드락 발생 위치를 확인합니다",
            "트랜잭션 타임아웃을 설정합니다: standalone.xml의 <coordinator-environment default-timeout=\"300\"/>",
            "락 획득 순서를 코드 전체에서 일관되게 유지하도록 리팩터링합니다",
            "데드락 발생 시 WildFly 재시작이 필요할 수 있습니다",
        ],
        "cli_commands": [
            "/core-service=platform-mbean/type=threading:find-deadlocked-threads()",
            "/core-service=platform-mbean/type=threading:dump-all-threads(locked-monitors=true,locked-synchronizers=true)",
            "/subsystem=transactions:read-attribute(name=default-timeout)",
        ],
    },
    {
        "name": "StackOverflow",
        "pattern": re.compile(r"StackOverflowError", re.I),
        "severity": "HIGH",
        "description": "재귀 호출 과다 또는 스택 크기 부족으로 스택 오버플로우 발생",
        "remedy": [
            "스택트레이스에서 반복 호출되는 메서드를 찾아 재귀 종료 조건을 점검합니다",
            "스택 크기를 늘립니다: standalone.conf에 -Xss512k → -Xss1m",
            "재귀 로직을 반복문(iterative)으로 변환하는 것을 검토합니다",
        ],
        "cli_commands": [
            "/core-service=platform-mbean/type=threading:read-attribute(name=thread-count)",
            "/core-service=platform-mbean/type=threading:dump-all-threads(locked-monitors=true,locked-synchronizers=true)",
            "/core-service=platform-mbean/type=runtime:read-attribute(name=input-arguments)",
        ],
    },
    {
        "name": "DeploymentFailure",
        "pattern": re.compile(
            r"WFLYSRV\d+.*[Ff]ailed|deployment.*failed|[Ff]ailed.*deploy", re.I
        ),
        "severity": "HIGH",
        "description": "애플리케이션 WAR/EAR 배포 실패",
        "remedy": [
            "server.log 전체에서 'Caused by:' 라인을 찾아 근본 원인을 확인합니다",
            "WEB-INF/lib 내 jar 파일 중복 또는 버전 충돌을 점검합니다",
            "jboss-deployment-structure.xml에서 모듈 의존성 설정을 확인합니다",
            "standalone/deployments/ 디렉토리의 .failed 마커 파일 내용을 확인합니다",
            "datasource, queue 등 외부 리소스 바인딩이 정상인지 확인합니다",
        ],
        "cli_commands": [
            "deployment-info",
            ":read-children-resources(child-type=deployment,include-runtime=true)",
            "/subsystem=datasources/data-source=*:read-resource(include-runtime=true)",
            "/subsystem=naming/binding=*:read-resource(include-runtime=true)",
        ],
    },
    {
        "name": "ConnectionPoolExhausted",
        "pattern": re.compile(
            r"IJ000604|connection pool.*full|no connection available|pool.*exhaust",
            re.I,
        ),
        "severity": "HIGH",
        "description": "데이터베이스 커넥션 풀 고갈",
        "remedy": [
            "standalone.xml의 datasource max-pool-size 값을 증가시킵니다 (기본값 20)",
            "커넥션을 반환하지 않는 코드(finally 블록 누락)를 점검합니다",
            "슬로우 쿼리를 최적화해 커넥션 점유 시간을 줄입니다",
            "idle-timeout-minutes, blocking-timeout-wait-millis 설정을 조정합니다",
            "DB 서버의 max_connections 설정도 함께 확인합니다",
        ],
        "cli_commands": [
            "/subsystem=datasources/data-source=*/statistics=pool:read-resource(include-runtime=true)",
            "/subsystem=datasources/data-source=*/statistics=jdbc:read-resource(include-runtime=true)",
            "/subsystem=datasources/data-source=*:flush-idle-connection-in-pool()",
            "/subsystem=datasources/data-source=*:test-connection-in-pool()",
        ],
    },
    {
        "name": "TransactionTimeout",
        "pattern": re.compile(
            r"transaction.*timed out|ARJUNA016|TransactionRolledback", re.I
        ),
        "severity": "HIGH",
        "description": "트랜잭션 시간 초과 또는 롤백 발생",
        "remedy": [
            "standalone.xml에서 트랜잭션 타임아웃을 늘립니다: default-timeout 값 조정",
            "슬로우 쿼리 또는 외부 서비스 호출이 트랜잭션 내에 있는지 점검합니다",
            "장시간 실행 로직은 트랜잭션 범위 밖으로 분리합니다",
            "DB 락 경합 여부를 확인합니다 (SHOW PROCESSLIST, pg_stat_activity)",
        ],
        "cli_commands": [
            "/subsystem=transactions:read-attribute(name=default-timeout)",
            "/subsystem=transactions:read-resource(include-runtime=true)",
            "/subsystem=transactions:write-attribute(name=default-timeout,value=300)",
        ],
    },
    {
        "name": "JDBCError",
        "pattern": re.compile(r"SQLException|JDBC.*[Ee]rror|could not execute", re.I),
        "severity": "HIGH",
        "description": "JDBC 데이터베이스 연결 또는 SQL 실행 오류",
        "remedy": [
            "DB 서버가 정상 동작 중인지 확인합니다",
            "커넥션 풀 설정(host, port, 인증정보)이 올바른지 확인합니다",
            "오류 SQL 구문을 로그에서 추출해 직접 실행하여 원인을 파악합니다",
            "valid-connection-checker, check-valid-connection-sql 설정으로 끊어진 커넥션을 자동 제거합니다",
        ],
        "cli_commands": [
            "/subsystem=datasources/data-source=*/statistics=pool:read-resource(include-runtime=true)",
            "/subsystem=datasources/data-source=*:test-connection-in-pool()",
            "/subsystem=datasources/data-source=*:flush-invalid-connection-in-pool()",
        ],
    },
    {
        "name": "NetworkError",
        "pattern": re.compile(
            r"SocketTimeoutException|Connection refused|Connection reset|UnknownHostException",
            re.I,
        ),
        "severity": "MEDIUM",
        "description": "외부 서비스 또는 DB 네트워크 연결 오류",
        "remedy": [
            "원격 호스트 (DB, API, MQ 등)의 상태를 확인합니다",
            "방화벽 규칙 및 보안 그룹 설정을 점검합니다",
            "DNS 해석이 정상인지 확인합니다 (nslookup, dig)",
            "소켓 타임아웃 값을 적절히 설정해 스레드 점유를 방지합니다",
            "재시도(retry) 로직 및 서킷 브레이커 패턴 적용을 검토합니다",
        ],
        "cli_commands": [
            "/subsystem=io/worker=default:read-resource(include-runtime=true)",
            "/core-service=platform-mbean/type=operating-system:read-resource(include-runtime=true)",
            "/subsystem=undertow/server=default-server:read-resource(include-runtime=true)",
        ],
    },
    {
        "name": "NullPointerException",
        "pattern": re.compile(r"NullPointerException", re.I),
        "severity": "MEDIUM",
        "description": "null 객체 참조로 NullPointerException 발생",
        "remedy": [
            "스택트레이스에서 'at com.example...' 라인을 찾아 해당 코드를 점검합니다",
            "해당 변수에 null 체크(Objects.requireNonNull, Optional 등)를 추가합니다",
            "의존성 주입(DI) 실패 여부를 확인합니다 (빈 초기화 순서 문제)",
            "외부 API 응답값에 대한 null 방어 코드를 추가합니다",
        ],
        "cli_commands": [
            "/core-service=platform-mbean/type=threading:dump-all-threads(locked-monitors=true,locked-synchronizers=true)",
            "/core-service=platform-mbean/type=threading:read-attribute(name=thread-count)",
        ],
    },
    {
        "name": "ClassLoadingError",
        "pattern": re.compile(
            r"ClassNotFoundException|NoClassDefFoundError|ClassCastException", re.I
        ),
        "severity": "MEDIUM",
        "description": "클래스 로딩 실패 또는 타입 캐스팅 오류",
        "remedy": [
            "WEB-INF/lib에 필요한 jar 파일이 있는지 확인합니다",
            "동일 클래스가 여러 jar에 중복 포함된 경우 제거합니다",
            "jboss-deployment-structure.xml에서 모듈 격리 설정을 점검합니다",
            "클래스로더 계층 문제인 경우 parent-first / child-first 설정을 검토합니다",
        ],
        "cli_commands": [
            "/core-service=platform-mbean/type=class-loading:read-resource(include-runtime=true)",
            ":read-children-names(child-type=deployment)",
            ":read-children-resources(child-type=deployment,include-runtime=true)",
        ],
    },
    {
        "name": "SecurityViolation",
        "pattern": re.compile(
            r"SecurityException|AccessControlException|WFLYSEC\d+", re.I
        ),
        "severity": "HIGH",
        "description": "보안 정책 위반 또는 접근 권한 오류",
        "remedy": [
            "해당 사용자/역할의 권한 설정을 standalone.xml security-domain에서 확인합니다",
            "접근 시도한 리소스의 보안 어노테이션(@RolesAllowed 등)을 점검합니다",
            "비정상 접근 시도인 경우 해당 IP를 방화벽에서 차단합니다",
            "보안 감사 로그를 활성화해 접근 이력을 추적합니다",
        ],
        "cli_commands": [
            "/subsystem=elytron:read-resource(recursive=false,include-runtime=true)",
            "/subsystem=undertow/application-security-domain=*:read-resource(include-runtime=true)",
            "/subsystem=elytron/security-domain=*:read-resource(include-runtime=true)",
        ],
    },
    {
        "name": "EJBError",
        "pattern": re.compile(
            r"EJBException|EJBTransactionRolled|WFLYEJB\d+.*[Ee]rror", re.I
        ),
        "severity": "MEDIUM",
        "description": "Enterprise JavaBeans 호출 또는 트랜잭션 오류",
        "remedy": [
            "Caused by 예외를 추적해 근본 원인을 파악합니다",
            "EJB 트랜잭션 속성(@TransactionAttribute)이 올바른지 확인합니다",
            "의존하는 외부 서비스(DB, MQ)의 상태를 확인합니다",
            "EJB 타임아웃 설정을 조정합니다: @AccessTimeout, transaction-timeout",
        ],
        "cli_commands": [
            "/subsystem=ejb3:read-resource(include-runtime=true)",
            "/subsystem=ejb3/thread-pool=default:read-resource(include-runtime=true)",
            "/subsystem=ejb3/strict-max-bean-instance-pool=*:read-resource(include-runtime=true)",
            "/subsystem=transactions:read-attribute(name=default-timeout)",
        ],
    },
    {
        "name": "FileDescriptorLimit",
        "pattern": re.compile(r"Too many open files", re.I),
        "severity": "HIGH",
        "description": "OS 파일 디스크립터 한도 초과",
        "remedy": [
            "현재 한도 확인: ulimit -n (보통 1024)",
            "/etc/security/limits.conf에서 한도를 증가시킵니다: wildfly soft nofile 65536",
            "파일/소켓을 닫지 않는 누수 코드를 점검합니다 (lsof -p <pid> | wc -l)",
            "WildFly 프로세스가 사용 중인 파일 목록: lsof -p <pid>",
            "systemd 환경이면 /etc/systemd/system/wildfly.service에 LimitNOFILE=65536 추가",
        ],
        "cli_commands": [
            "/core-service=platform-mbean/type=operating-system:read-attribute(name=open-file-descriptor-count)",
            "/core-service=platform-mbean/type=operating-system:read-attribute(name=max-file-descriptor-count)",
            "/core-service=platform-mbean/type=operating-system:read-resource(include-runtime=true)",
        ],
    },
    {
        "name": "MessagingError",
        "pattern": re.compile(
            r"JMSException|ActiveMQException|WFLYMSG\d+.*[Ee]rror", re.I
        ),
        "severity": "MEDIUM",
        "description": "JMS/ActiveMQ 메시지 처리 오류",
        "remedy": [
            "WildFly 내장 메시징 브로커 상태를 확인합니다 (management console)",
            "Dead Letter Queue(DLQ)에 쌓인 메시지를 확인합니다",
            "큐 컨슈머(MDB)가 정상 동작 중인지 확인합니다",
            "메시지 재전송 횟수(redelivery-delay, max-delivery-attempts) 설정을 점검합니다",
            "브로커 연결 설정(host, port, 인증)이 올바른지 확인합니다",
        ],
        "cli_commands": [
            "/subsystem=messaging-activemq/server=default:read-resource(include-runtime=true)",
            "/subsystem=messaging-activemq/server=default/jms-queue=*:read-resource(include-runtime=true)",
            "/subsystem=messaging-activemq/server=default/jms-topic=*:read-resource(include-runtime=true)",
            "/subsystem=messaging-activemq/server=default/address-setting=#:read-resource(include-runtime=true)",
        ],
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
    def __init__(self, rule_name: str, severity: str, description: str, entry: LogEntry,
                 remedy: Optional[List[str]] = None,
                 cli_commands: Optional[List[str]] = None):
        self.id = str(uuid.uuid4())[:8]
        self.rule_name = rule_name
        self.severity = severity
        self.description = description
        self.remedy = remedy or []
        self.cli_commands = cli_commands or []
        self.entry = entry
        self.detected_at = datetime.now()

    def to_dict(self) -> Dict:
        return {
            "id": self.id,
            "rule_name": self.rule_name,
            "severity": self.severity,
            "description": self.description,
            "remedy": self.remedy,
            "cli_commands": self.cli_commands,
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


# ─── jboss-cli.sh executor ────────────────────────────────────────────────────
class JbossCliExecutor:
    """Executes jboss-cli.sh commands against the local WildFly instance."""

    def __init__(self, cfg: dict):
        self.cli_path = cfg.get("path", "/opt/wildfly/bin/jboss-cli.sh")
        self.host     = cfg.get("host", "localhost")
        self.port     = int(cfg.get("port", 9990))
        self.user     = cfg.get("user", "")
        self.password = cfg.get("password", "")
        self.timeout  = int(cfg.get("timeout", 60))
        self.enabled  = cfg.get("enabled", True)

    def available(self) -> bool:
        return self.enabled and Path(self.cli_path).exists()

    def run(self, commands: List[str]) -> Dict:
        if not self.enabled:
            return {"success": False, "output": "", "error": "jboss-cli 비활성화됨 (config: jboss_cli.enabled=false)"}
        if not Path(self.cli_path).exists():
            return {"success": False, "output": "", "error": f"jboss-cli.sh 미발견: {self.cli_path}"}
        if not commands:
            return {"success": False, "output": "", "error": "실행할 명령이 없습니다"}

        tmp = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".cli", delete=False, dir="/tmp"
            ) as f:
                f.write("\n".join(commands))
                tmp = f.name

            args = [
                self.cli_path,
                "--connect",
                f"--controller={self.host}:{self.port}",
            ]
            if self.user:
                args += [f"--user={self.user}", f"--password={self.password}"]
            args.append(f"--file={tmp}")

            logger.info("jboss-cli: %s %d commands → %s:%d", self.cli_path, len(commands), self.host, self.port)
            proc = subprocess.run(
                args,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=self.timeout,
            )
            stdout = proc.stdout.decode("utf-8", errors="replace")
            stderr = proc.stderr.decode("utf-8", errors="replace")
            return {
                "success": proc.returncode == 0,
                "returncode": proc.returncode,
                "output": stdout[:8192],
                "error": stderr[:2048],
            }
        except subprocess.TimeoutExpired:
            return {"success": False, "output": "", "error": f"CLI 실행 타임아웃 ({self.timeout}s)"}
        except Exception as e:
            return {"success": False, "output": "", "error": str(e)}
        finally:
            if tmp:
                try:
                    os.unlink(tmp)
                except OSError:
                    pass


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
                    AnomalyEvent(
                        "FatalError", "CRITICAL", "WildFly FATAL 레벨 오류 — 즉시 서버 상태 확인 필요", entry,
                        remedy=[
                            "즉시 서버 프로세스 상태를 확인합니다: ps aux | grep wildfly",
                            "전체 server.log를 수집해 원인을 분석합니다",
                            "필요 시 WildFly를 재시작합니다: systemctl restart wildfly",
                            "재발 방지를 위해 heap dump 및 thread dump를 확보합니다",
                        ],
                        cli_commands=[
                            ":read-attribute(name=server-state)",
                            "/core-service=platform-mbean/type=runtime:read-attribute(name=uptime)",
                            "/core-service=platform-mbean/type=memory:read-attribute(name=heap-memory-usage)",
                        ],
                    )
                )
                continue

            if entry.level in ("ERROR", "WARN"):
                matched = False
                for rule in ANOMALY_RULES:
                    if rule["pattern"].search(entry.message):
                        results.append(
                            AnomalyEvent(
                                rule["name"], rule["severity"], rule["description"], entry,
                                remedy=rule.get("remedy", []),
                                cli_commands=rule.get("cli_commands", []),
                            )
                        )
                        matched = True
                        break
                if not matched and entry.level == "ERROR":
                    results.append(
                        AnomalyEvent(
                            "GenericError", "LOW", "분류되지 않은 애플리케이션 오류", entry,
                            remedy=[
                                "스택트레이스 전문을 확인해 발생 위치를 파악합니다",
                                "동일 오류가 반복되는지 빈도를 확인합니다",
                                "개발팀에 해당 로그를 공유하여 코드 수준 점검을 요청합니다",
                            ],
                            cli_commands=[
                                ":read-attribute(name=server-state)",
                                "/core-service=platform-mbean/type=threading:read-attribute(name=thread-count)",
                                "/core-service=platform-mbean/type=memory:read-attribute(name=heap-memory-usage)",
                            ],
                        )
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

        # jboss-cli executor
        cli_cfg = self.cfg.get("jboss_cli", {})
        self.cli = JbossCliExecutor(cli_cfg)
        if self.cli.available():
            logger.info("jboss-cli enabled: %s → %s:%d", self.cli.cli_path, self.cli.host, self.cli.port)
        else:
            logger.info("jboss-cli disabled or not found — auto-remediation unavailable")

        self._pending: List[Dict] = []
        self._stats: Dict = defaultdict(int)
        self._last_report = datetime.now()
        self._last_task_poll = datetime.min
        self._task_poll_interval: int = self.cfg.get("monitoring", {}).get("task_poll_interval", 15)
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

    # ── Task polling (controller → agent remediation) ──────────────────────────
    def _poll_tasks(self):
        """Poll controller for pending remediation tasks and execute them."""
        try:
            r = requests.get(
                f"{self.controller_url}/api/agents/{self.server_id}/tasks",
                headers=self._headers,
                timeout=10,
            )
            r.raise_for_status()
            tasks = r.json()
            for task in tasks:
                self._execute_task(task)
        except requests.exceptions.ConnectionError:
            logger.debug("Task poll skipped: controller unreachable")
        except Exception as e:
            logger.debug("Task poll failed: %s", e)

    def _execute_task(self, task: Dict):
        task_id = task.get("task_id", "?")
        rule_name = task.get("rule_name", "unknown")
        commands: List[str] = task.get("cli_commands", [])

        logger.info("Executing remediation task %s [%s] — %d commands", task_id, rule_name, len(commands))

        if self.cli and self.cli.available() and commands:
            result = self.cli.run(commands)
        elif not commands:
            result = {"success": False, "output": "", "error": "실행할 CLI 명령이 없습니다"}
        else:
            result = {
                "success": False,
                "output": "",
                "error": f"jboss-cli.sh를 찾을 수 없습니다: {self.cli.cli_path}" if self.cli
                         else "jboss_cli 설정이 없습니다",
            }

        if result.get("success"):
            logger.info("Task %s 완료 ✓", task_id)
        else:
            logger.warning("Task %s 실패: %s", task_id, result.get("error"))

        self._post(
            f"/api/tasks/{task_id}/result",
            {
                "task_id": task_id,
                "server_id": self.server_id,
                "result": result,
                "executed_at": datetime.now().isoformat(),
            },
        )

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

                # Task polling (controller → agent auto-remediation)
                task_elapsed = (datetime.now() - self._last_task_poll).total_seconds()
                if task_elapsed >= self._task_poll_interval:
                    self._poll_tasks()
                    self._last_task_poll = datetime.now()

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
