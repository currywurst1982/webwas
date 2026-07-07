import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scouter_monitor.config import Thresholds
from scouter_monitor.rules import (
    evaluate_active_services,
    evaluate_counters,
    evaluate_native_alerts,
    evaluate_objects,
)

THRESHOLDS = Thresholds()


def test_object_down_detected():
    findings = evaluate_objects([{"objHash": 1, "objName": "WAS-1", "alive": False}])
    assert len(findings) == 1
    assert findings[0].category == "OBJECT_DOWN"


def test_object_up_no_finding():
    findings = evaluate_objects([{"objHash": 1, "objName": "WAS-1", "alive": True}])
    assert findings == []


def test_heap_over_threshold_is_oom_risk():
    findings = evaluate_counters({"WAS-1": {"HeapTotUsage": 95}}, THRESHOLDS)
    categories = {f.category for f in findings}
    assert "OOM_RISK" in categories


def test_heap_under_threshold_no_finding():
    findings = evaluate_counters({"WAS-1": {"HeapTotUsage": 40}}, THRESHOLDS)
    assert findings == []


def test_slow_response_detected():
    findings = evaluate_counters({"WAS-1": {"Elapsed90%": 9000}}, THRESHOLDS)
    assert any(f.category == "SLOW_RESPONSE" and f.severity == "CRITICAL" for f in findings)


def test_hang_service_detected():
    import time
    now_ms = time.time() * 1000
    findings = evaluate_active_services(
        {"WAS-1": [{"service": "/slow", "startTime": now_ms - 20000}]}, THRESHOLDS
    )
    assert len(findings) == 1
    assert findings[0].category == "HANG_SERVICE"


def test_hang_service_below_threshold_ignored():
    import time
    now_ms = time.time() * 1000
    findings = evaluate_active_services(
        {"WAS-1": [{"service": "/fast", "startTime": now_ms - 500}]}, THRESHOLDS
    )
    assert findings == []


def test_native_alert_level_mapping():
    findings = evaluate_native_alerts([
        {"objName": "WAS-1", "level": "FATAL", "title": "GcTime", "message": "..."},
    ])
    assert findings[0].severity == "CRITICAL"
