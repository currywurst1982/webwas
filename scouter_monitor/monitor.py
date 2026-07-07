from __future__ import annotations

import logging
import time
from typing import Any

from .client import ScouterApiError, ScouterClient
from .config import AppConfig
from .notifier import Notifier, print_summary_table
from .rules import (
    evaluate_active_services,
    evaluate_counters,
    evaluate_native_alerts,
    evaluate_objects,
    sort_findings,
)

log = logging.getLogger("scouter_monitor")

COUNTERS = [
    "HeapTotUsage", "PermPercent", "GcTime", "GcCount",
    "ElapsedTime", "Elapsed90%", "ErrorRate", "ActiveService", "TPS",
]


def _obj_hash_to_name(object_list: list[dict]) -> dict[str, str]:
    mapping = {}
    for obj in object_list:
        h = obj.get("objHash")
        name = obj.get("objName") or obj.get("name")
        if h is not None and name:
            mapping[str(h)] = name
    return mapping


def normalize_counters(raw: Any, hash_to_name: dict[str, str]) -> dict[str, dict[str, Any]]:
    """Best-effort normalization of the counter/realTime API response into
    {obj_name: {counter_key: value}}, tolerant of a couple of plausible
    response shapes (dict-of-dict keyed by objHash, or a flat list of
    per-counter records)."""
    result: dict[str, dict[str, Any]] = {}
    if raw is None:
        return result

    if isinstance(raw, dict):
        for obj_hash, payload in raw.items():
            name = hash_to_name.get(str(obj_hash), str(obj_hash))
            if isinstance(payload, dict):
                result.setdefault(name, {}).update(payload)
            elif isinstance(payload, list):
                for rec in payload:
                    if isinstance(rec, dict) and "counter" in rec:
                        result.setdefault(name, {})[rec["counter"]] = rec.get("value")
        return result

    if isinstance(raw, list):
        for rec in raw:
            if not isinstance(rec, dict):
                continue
            obj_hash = rec.get("objHash")
            name = hash_to_name.get(str(obj_hash), rec.get("objName") or str(obj_hash))
            counter = rec.get("counter") or rec.get("key")
            value = rec.get("value")
            if counter is not None:
                result.setdefault(name, {})[counter] = value
        return result

    return result


def normalize_active_services(raw: Any, hash_to_name: dict[str, str]) -> dict[str, list[dict]]:
    result: dict[str, list[dict]] = {}
    if raw is None:
        return result

    records = []
    if isinstance(raw, list):
        records = raw
    elif isinstance(raw, dict):
        for v in raw.values():
            if isinstance(v, list):
                records.extend(v)

    for rec in records:
        if not isinstance(rec, dict):
            continue
        obj_hash = rec.get("objHash")
        name = hash_to_name.get(str(obj_hash), rec.get("objName") or str(obj_hash))
        result.setdefault(name, []).append(rec)
    return result


class ScouterMonitor:
    def __init__(self, cfg: AppConfig, client: ScouterClient | None = None):
        self.cfg = cfg
        self.client = client or ScouterClient(cfg.scouter)
        self.notifier = Notifier(cfg.notify)
        self._alert_offsets: dict[str, tuple[int, int]] = {}

    def poll_once(self) -> list:
        object_list = self.client.object_list()
        hash_to_name = _obj_hash_to_name(object_list)

        counters_by_obj: dict[str, dict[str, Any]] = {}
        active_services_by_obj: dict[str, list[dict]] = {}
        native_alerts: list[dict] = []

        for obj_type in self.cfg.scouter.object_types:
            try:
                raw_counters = self.client.realtime_counters(COUNTERS, obj_type)
                counters_by_obj.update(normalize_counters(raw_counters, hash_to_name))
            except ScouterApiError as e:
                log.warning("counter 조회 실패 (objType=%s): %s", obj_type, e)

            try:
                raw_services = self.client.active_service_list(obj_type)
                active_services_by_obj.update(normalize_active_services(raw_services, hash_to_name))
            except ScouterApiError as e:
                log.warning("activeService 조회 실패 (objType=%s): %s", obj_type, e)

            try:
                o1, o2 = self._alert_offsets.get(obj_type, (0, 0))
                alert_resp = self.client.alerts_realtime(obj_type, o1, o2)
                if isinstance(alert_resp, dict):
                    native_alerts.extend(alert_resp.get("list", alert_resp.get("alerts", [])))
                    if "offset1" in alert_resp and "offset2" in alert_resp:
                        self._alert_offsets[obj_type] = (alert_resp["offset1"], alert_resp["offset2"])
                elif isinstance(alert_resp, list):
                    native_alerts.extend(alert_resp)
            except ScouterApiError as e:
                log.warning("alert 조회 실패 (objType=%s): %s", obj_type, e)

        findings = []
        findings += evaluate_objects(object_list)
        findings += evaluate_counters(counters_by_obj, self.cfg.thresholds)
        findings += evaluate_active_services(active_services_by_obj, self.cfg.thresholds)
        findings += evaluate_native_alerts(native_alerts)
        findings = sort_findings(findings)

        if self.cfg.notify.console:
            print_summary_table(object_list, counters_by_obj)

        sent = self.notifier.notify_all(findings)
        if not sent:
            print("즉시 확인이 필요한 이상 징후가 없습니다.\n")
        return sent

    def run_forever(self) -> None:
        interval = self.cfg.scouter.poll_interval_sec
        log.info("ScouterAPM 모니터링을 시작합니다 (host=%s, interval=%ss)",
                  self.cfg.scouter.host, interval)
        while True:
            try:
                self.poll_once()
            except Exception as e:  # keep the daemon alive across transient errors
                log.error("모니터링 주기 실행 중 오류: %s", e, exc_info=True)
            time.sleep(interval)
