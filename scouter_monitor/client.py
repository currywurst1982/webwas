from __future__ import annotations

import logging
from typing import Any, Iterable

import requests

from .config import ScouterConfig

log = logging.getLogger("scouter_monitor.client")


class ScouterApiError(RuntimeError):
    pass


class ScouterClient:
    """Thin wrapper around Scouter's official HTTP Web API (v1).

    See: scouter.document/tech/Web-API-Guide.md in scouter-project/scouter.
    Requires the collector's HTTP module to be reachable (net_http_port,
    default 6180 embedded / 6188 standalone) -- this is a different port
    from the raw TCP collector port (6100) used by agents.
    """

    def __init__(self, cfg: ScouterConfig):
        self.cfg = cfg
        self.session = requests.Session()
        self._logged_in = False

    def _url(self, path: str) -> str:
        return f"{self.cfg.base_url}{path}"

    def _ensure_auth(self) -> None:
        mode = self.cfg.auth.mode
        if mode in ("ip", "none") or self._logged_in:
            return
        if mode == "bearer":
            if self.cfg.auth.token:
                self.session.headers["Authorization"] = f"Bearer {self.cfg.auth.token}"
                self._logged_in = True
                return
            data = self._post("/v1/user/loginGetToken", json_body={
                "user": {"id": self.cfg.auth.id, "password": self.cfg.auth.password},
            })
            token = _find_token(data)
            if not token:
                raise ScouterApiError(
                    "bearer 모드 로그인 응답에서 토큰을 찾지 못했습니다. "
                    "config.yaml 의 auth.token 에 미리 발급받은 토큰을 직접 입력하세요."
                )
            self.session.headers["Authorization"] = f"Bearer {token}"
            self._logged_in = True
        elif mode == "session":
            self._post("/v1/user/login", json_body={
                "user": {"id": self.cfg.auth.id, "password": self.cfg.auth.password},
            })
            self._logged_in = True
        else:
            raise ScouterApiError(f"알 수 없는 auth.mode: {mode}")

    def _get(self, path: str, params: dict | None = None) -> Any:
        self._ensure_auth()
        resp = self.session.get(self._url(path), params=params, timeout=self.cfg.timeout_sec)
        return self._unwrap(resp)

    def _post(self, path: str, json_body: dict) -> Any:
        resp = self.session.post(self._url(path), json=json_body, timeout=self.cfg.timeout_sec)
        return self._unwrap(resp)

    @staticmethod
    def _unwrap(resp: requests.Response) -> Any:
        resp.raise_for_status()
        body = resp.json()
        if isinstance(body, dict) and body.get("resultCode") not in (0, None):
            raise ScouterApiError(f"scouter api error: {body}")
        return body.get("result") if isinstance(body, dict) else body

    # -- public API -----------------------------------------------------

    def server_info(self) -> Any:
        return self._get("/v1/info/server")

    def object_list(self) -> list[dict]:
        return self._get("/v1/object") or []

    def realtime_counters(self, counters: Iterable[str], obj_type: str) -> Any:
        counter_path = ",".join(counters)
        return self._get(f"/v1/counter/realTime/{counter_path}/ofType/{obj_type}")

    def active_service_list(self, obj_type: str) -> Any:
        return self._get(f"/v1/activeService/ofType/{obj_type}")

    def alerts_realtime(self, obj_type: str, offset1: int = 0, offset2: int = 0) -> Any:
        return self._get(f"/v1/alert/realTime/{offset1}/{offset2}", params={"objType": obj_type})


def _find_token(data: Any) -> str | None:
    """Best-effort extraction of a bearer token from a login response,
    since the exact response schema isn't guaranteed across versions."""
    if isinstance(data, str):
        return data
    if isinstance(data, dict):
        for key in ("token", "accessToken", "access_token", "jwt"):
            if key in data and isinstance(data[key], str):
                return data[key]
        for value in data.values():
            found = _find_token(value)
            if found:
                return found
    return None
