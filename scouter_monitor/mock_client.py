from __future__ import annotations

import random
import time

from .config import ScouterConfig


class MockScouterClient:
    """Fake ScouterClient used for --demo runs, so the monitoring pipeline
    (rules + notifier + summary table) can be exercised without a real
    ScouterAPM server available."""

    def __init__(self, cfg: ScouterConfig):
        self.cfg = cfg
        self._tick = 0

    def object_list(self) -> list[dict]:
        return [
            {"objHash": 1001, "objName": "WAS-ORDER-01", "objType": "was", "alive": True},
            {"objHash": 1002, "objName": "WAS-ORDER-02", "objType": "was", "alive": True},
            {"objHash": 1003, "objName": "WAS-PAYMENT-01", "objType": "was", "alive": self._tick % 5 != 4},
        ]

    def realtime_counters(self, counters, obj_type: str):
        self._tick += 1
        return {
            "1001": {
                "HeapTotUsage": 55 + random.uniform(-5, 5),
                "PermPercent": 40,
                "GcTime": 200,
                "ElapsedTime": 300,
                "Elapsed90%": 600,
                "ErrorRate": 0.5,
                "ActiveService": 12,
            },
            "1002": {
                "HeapTotUsage": 91 + random.uniform(-2, 2),   # OOM risk
                "PermPercent": 60,
                "GcTime": 4200,                                # GC thrashing
                "ElapsedTime": 4200,                            # slow
                "Elapsed90%": 7200,
                "ErrorRate": 7.5,                               # high error rate
                "ActiveService": 130,
            },
            "1003": {
                "HeapTotUsage": 60,
                "PermPercent": 45,
                "GcTime": 150,
                "ElapsedTime": 250,
                "Elapsed90%": 400,
                "ErrorRate": 0.1,
                "ActiveService": 8,
            },
        }

    def active_service_list(self, obj_type: str):
        now_ms = time.time() * 1000
        return [
            {"objHash": 1002, "service": "/api/order/checkout", "startTime": now_ms - 15000, "threadId": 42},
            {"objHash": 1002, "service": "/api/order/list", "startTime": now_ms - 500, "threadId": 7},
        ]

    def alerts_realtime(self, obj_type: str, offset1: int = 0, offset2: int = 0):
        if self._tick != 1:
            return {"list": [], "offset1": offset1, "offset2": offset2}
        return {
            "list": [
                {
                    "objHash": 1002,
                    "objName": "WAS-ORDER-02",
                    "level": "FATAL",
                    "title": "GcTime",
                    "message": "GcTime 이 2초 임계값을 초과했습니다 (4.2s)",
                },
            ],
            "offset1": offset1 + 1,
            "offset2": offset2 + 1,
        }
