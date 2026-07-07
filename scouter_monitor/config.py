from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml


@dataclass
class AuthConfig:
    mode: str = "ip"  # ip | session | bearer | none
    id: str = ""
    password: str = ""
    token: str = ""


@dataclass
class ScouterConfig:
    host: str = "127.0.0.1"
    http_port: int = 6188
    use_https: bool = False
    timeout_sec: int = 5
    auth: AuthConfig = field(default_factory=AuthConfig)
    object_types: list[str] = field(default_factory=lambda: ["was"])
    poll_interval_sec: int = 30

    @property
    def base_url(self) -> str:
        scheme = "https" if self.use_https else "http"
        return f"{scheme}://{self.host}:{self.http_port}/scouter"


@dataclass
class Thresholds:
    heap_usage_pct: float = 85
    perm_usage_pct: float = 85
    gc_time_ms: float = 3000
    elapsed_avg_ms: float = 3000
    elapsed_90pct_ms: float = 5000
    error_rate_pct: float = 5
    active_service_count: int = 100
    hang_elapsed_ms: float = 10000


@dataclass
class NotifyConfig:
    console: bool = True
    slack_webhook_url: str = ""
    cooldown_sec: int = 300


@dataclass
class AppConfig:
    scouter: ScouterConfig = field(default_factory=ScouterConfig)
    thresholds: Thresholds = field(default_factory=Thresholds)
    notify: NotifyConfig = field(default_factory=NotifyConfig)


def load_config(path: str | Path) -> AppConfig:
    raw = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}

    scouter_raw = raw.get("scouter", {}) or {}
    auth_raw = scouter_raw.get("auth", {}) or {}
    scouter = ScouterConfig(
        host=scouter_raw.get("host", ScouterConfig.host),
        http_port=int(scouter_raw.get("http_port", ScouterConfig.http_port)),
        use_https=bool(scouter_raw.get("use_https", False)),
        timeout_sec=int(scouter_raw.get("timeout_sec", 5)),
        auth=AuthConfig(
            mode=auth_raw.get("mode", "ip"),
            id=auth_raw.get("id", ""),
            password=auth_raw.get("password", ""),
            token=auth_raw.get("token", ""),
        ),
        object_types=list(scouter_raw.get("object_types", ["was"])),
        poll_interval_sec=int(scouter_raw.get("poll_interval_sec", 30)),
    )

    thresholds_raw = raw.get("thresholds", {}) or {}
    thresholds = Thresholds(**{
        k: thresholds_raw[k] for k in Thresholds.__dataclass_fields__ if k in thresholds_raw
    })

    notify_raw = raw.get("notify", {}) or {}
    notify = NotifyConfig(
        console=bool(notify_raw.get("console", True)),
        slack_webhook_url=notify_raw.get("slack_webhook_url", ""),
        cooldown_sec=int(notify_raw.get("cooldown_sec", 300)),
    )

    return AppConfig(scouter=scouter, thresholds=thresholds, notify=notify)
