from __future__ import annotations

import logging
import time
from datetime import datetime

import requests

from .config import NotifyConfig
from .rules import Finding

log = logging.getLogger("scouter_monitor.notifier")

_COLOR = {"CRITICAL": "\033[91m", "WARN": "\033[93m", "INFO": "\033[94m"}
_RESET = "\033[0m"

_ICON = {"CRITICAL": "🚨", "WARN": "⚠️", "INFO": "ℹ️"}


class Notifier:
    def __init__(self, cfg: NotifyConfig):
        self.cfg = cfg
        self._last_sent: dict[tuple, float] = {}

    def _in_cooldown(self, finding: Finding) -> bool:
        last = self._last_sent.get(finding.key)
        if last is None:
            return False
        return (time.time() - last) < self.cfg.cooldown_sec

    def notify_all(self, findings: list[Finding]) -> list[Finding]:
        """Send findings that are not currently in cooldown; returns the ones actually sent."""
        sent = []
        for f in findings:
            if self._in_cooldown(f):
                continue
            self._send(f)
            self._last_sent[f.key] = time.time()
            sent.append(f)
        return sent

    def _send(self, finding: Finding) -> None:
        if self.cfg.console:
            self._print_console(finding)
        if self.cfg.slack_webhook_url:
            self._send_slack(finding)

    @staticmethod
    def _print_console(finding: Finding) -> None:
        color = _COLOR.get(finding.severity, "")
        icon = _ICON.get(finding.severity, "")
        ts = datetime.fromtimestamp(finding.ts).strftime("%Y-%m-%d %H:%M:%S")
        print(f"{color}{icon} [{ts}] [{finding.severity}] [{finding.category}] {finding.message}{_RESET}")

    def _send_slack(self, finding: Finding) -> None:
        icon = _ICON.get(finding.severity, "")
        text = f"{icon} *{finding.severity}* `{finding.category}`\n{finding.message}"
        try:
            requests.post(self.cfg.slack_webhook_url, json={"text": text}, timeout=5)
        except requests.RequestException as e:
            log.warning("Slack 알림 전송 실패: %s", e)


def print_summary_table(object_list: list[dict], counters_by_obj: dict[str, dict]) -> None:
    print("\n" + "=" * 78)
    print(f"ScouterAPM 모니터링 현황  ({datetime.now().strftime('%Y-%m-%d %H:%M:%S')})")
    print("=" * 78)
    header = f"{'OBJECT':<24}{'STATUS':<8}{'HEAP%':<8}{'GC(ms)':<10}{'RESP(ms)':<10}{'ERR%':<8}{'ACTIVE':<8}"
    print(header)
    print("-" * 78)
    for obj in object_list:
        name = obj.get("objName") or obj.get("name") or str(obj.get("objHash"))
        alive = "UP" if obj.get("alive") else "DOWN"
        v = counters_by_obj.get(name, {})
        print(
            f"{name:<24}{alive:<8}"
            f"{_fmt(v.get('HeapTotUsage')):<8}"
            f"{_fmt(v.get('GcTime')):<10}"
            f"{_fmt(v.get('ElapsedTime')):<10}"
            f"{_fmt(v.get('ErrorRate')):<8}"
            f"{_fmt(v.get('ActiveService')):<8}"
        )
    print("=" * 78 + "\n")


def _fmt(v) -> str:
    if v is None:
        return "-"
    try:
        return f"{float(v):.1f}"
    except (TypeError, ValueError):
        return str(v)
