from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

from .config import Thresholds

SEVERITY_ORDER = {"INFO": 0, "WARN": 1, "CRITICAL": 2}


@dataclass
class Finding:
    severity: str  # INFO | WARN | CRITICAL
    category: str  # OOM_RISK | SLOW_RESPONSE | HANG_SERVICE | HIGH_ERROR_RATE | OBJECT_DOWN | NATIVE_ALERT
    obj_name: str
    message: str
    detail: dict = field(default_factory=dict)
    ts: float = field(default_factory=time.time)

    @property
    def key(self) -> tuple:
        return (self.obj_name, self.category)


def _num(v: Any, default: float = 0.0) -> float:
    try:
        return float(v)
    except (TypeError, ValueError):
        return default


def evaluate_objects(object_list: list[dict]) -> list[Finding]:
    findings = []
    for obj in object_list:
        name = obj.get("objName") or obj.get("name") or str(obj.get("objHash"))
        alive = obj.get("alive")
        if alive is False:
            findings.append(Finding(
                severity="CRITICAL",
                category="OBJECT_DOWN",
                obj_name=name,
                message=f"[{name}] 오브젝트가 비활성(다운) 상태입니다.",
                detail=obj,
            ))
    return findings


def evaluate_counters(counters_by_obj: dict[str, dict[str, Any]], thresholds: Thresholds) -> list[Finding]:
    """counters_by_obj: {obj_name: {counter_key: value, ...}}"""
    findings = []
    for name, values in counters_by_obj.items():
        heap_pct = _num(values.get("HeapTotUsage"))
        if heap_pct >= thresholds.heap_usage_pct:
            findings.append(Finding(
                severity="CRITICAL",
                category="OOM_RISK",
                obj_name=name,
                message=(
                    f"[{name}] 힙 사용률 {heap_pct:.1f}% (임계값 {thresholds.heap_usage_pct}%) "
                    f"- OOM 위험"
                ),
                detail={"HeapTotUsage": heap_pct},
            ))

        perm_pct = _num(values.get("PermPercent"))
        if perm_pct >= thresholds.perm_usage_pct:
            findings.append(Finding(
                severity="WARN",
                category="OOM_RISK",
                obj_name=name,
                message=(
                    f"[{name}] Perm/Metaspace 사용률 {perm_pct:.1f}% "
                    f"(임계값 {thresholds.perm_usage_pct}%)"
                ),
                detail={"PermPercent": perm_pct},
            ))

        gc_time = _num(values.get("GcTime"))
        if gc_time >= thresholds.gc_time_ms:
            findings.append(Finding(
                severity="WARN",
                category="OOM_RISK",
                obj_name=name,
                message=(
                    f"[{name}] GC 누적 시간 {gc_time:.0f}ms (임계값 {thresholds.gc_time_ms}ms) "
                    f"- GC 스래싱 의심"
                ),
                detail={"GcTime": gc_time},
            ))

        elapsed_avg = _num(values.get("ElapsedTime"))
        if elapsed_avg >= thresholds.elapsed_avg_ms:
            findings.append(Finding(
                severity="WARN",
                category="SLOW_RESPONSE",
                obj_name=name,
                message=(
                    f"[{name}] 평균 응답시간 {elapsed_avg:.0f}ms (임계값 {thresholds.elapsed_avg_ms}ms)"
                ),
                detail={"ElapsedTime": elapsed_avg},
            ))

        elapsed_90 = _num(values.get("Elapsed90%"))
        if elapsed_90 >= thresholds.elapsed_90pct_ms:
            findings.append(Finding(
                severity="CRITICAL",
                category="SLOW_RESPONSE",
                obj_name=name,
                message=(
                    f"[{name}] 응답시간 90퍼센타일 {elapsed_90:.0f}ms "
                    f"(임계값 {thresholds.elapsed_90pct_ms}ms)"
                ),
                detail={"Elapsed90%": elapsed_90},
            ))

        error_rate = _num(values.get("ErrorRate"))
        if error_rate >= thresholds.error_rate_pct:
            findings.append(Finding(
                severity="CRITICAL",
                category="HIGH_ERROR_RATE",
                obj_name=name,
                message=(
                    f"[{name}] 에러율 {error_rate:.1f}% (임계값 {thresholds.error_rate_pct}%)"
                ),
                detail={"ErrorRate": error_rate},
            ))

        active_service = _num(values.get("ActiveService"))
        if active_service >= thresholds.active_service_count:
            findings.append(Finding(
                severity="WARN",
                category="SLOW_RESPONSE",
                obj_name=name,
                message=(
                    f"[{name}] 동시 실행 서비스 수 {active_service:.0f}건 "
                    f"(임계값 {thresholds.active_service_count}) - 처리 지연/큐잉 의심"
                ),
                detail={"ActiveService": active_service},
            ))

    return findings


def evaluate_active_services(active_services_by_obj: dict[str, list[dict]], thresholds: Thresholds) -> list[Finding]:
    """Detect individual long-running (hung) transactions."""
    findings = []
    now_ms = time.time() * 1000
    for name, services in active_services_by_obj.items():
        for svc in services:
            start = svc.get("startTime") or svc.get("start_time")
            if start is None:
                continue
            elapsed = now_ms - _num(start)
            if elapsed >= thresholds.hang_elapsed_ms:
                service_name = svc.get("service") or svc.get("txidName") or svc.get("threadId")
                findings.append(Finding(
                    severity="CRITICAL",
                    category="HANG_SERVICE",
                    obj_name=name,
                    message=(
                        f"[{name}] 서비스 '{service_name}' 가 {elapsed/1000:.1f}초째 실행중 "
                        f"(임계값 {thresholds.hang_elapsed_ms/1000:.0f}초) - 행(hang) 의심, 즉시 확인 필요"
                    ),
                    detail=svc,
                ))
    return findings


def evaluate_native_alerts(alerts: list[dict]) -> list[Finding]:
    """Surface Scouter's own server-side alerts (ext_alert_* scripts)."""
    level_map = {"FATAL": "CRITICAL", "ERROR": "CRITICAL", "WARN": "WARN", "INFO": "INFO"}
    findings = []
    for alert in alerts:
        name = alert.get("objName") or alert.get("obj_name") or str(alert.get("objHash", "-"))
        level = str(alert.get("level", "WARN")).upper()
        title = alert.get("title", "ALERT")
        message = alert.get("message", "")
        findings.append(Finding(
            severity=level_map.get(level, "WARN"),
            category="NATIVE_ALERT",
            obj_name=name,
            message=f"[{name}] ({title}) {message}",
            detail=alert,
        ))
    return findings


def sort_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 0), reverse=True)
