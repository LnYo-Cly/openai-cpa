"""Minimal Grok2API SSO importer used immediately after Grok signup."""

import base64
import json
import threading
import time
from typing import Any, Dict, Optional, Tuple

from curl_cffi import requests as cffi_requests

from utils import config as cfg

_TOKEN_CACHE: Dict[Tuple[str, str], Tuple[str, float]] = {}
_TOKEN_LOCK = threading.Lock()


def _jwt_exp(token: str) -> Optional[float]:
    parts = str(token or "").split(".")
    if len(parts) != 3:
        return None
    try:
        payload = parts[1] + ("=" * (-len(parts[1]) % 4))
        data = json.loads(base64.urlsafe_b64decode(payload).decode("utf-8"))
        exp = float(data.get("exp"))
        return exp if exp > time.time() else None
    except (ValueError, TypeError, KeyError, json.JSONDecodeError, UnicodeDecodeError):
        return None


def _parse_sse_result(body: str) -> Optional[Dict[str, Any]]:
    """Return the final import summary from JSON or an SSE response."""
    candidates = []
    try:
        candidates.append(json.loads(body))
    except (TypeError, ValueError, json.JSONDecodeError):
        pass

    event_data = []
    for line in str(body or "").splitlines():
        if line.startswith("data:"):
            event_data.append(line[5:].strip())
    for raw in event_data:
        try:
            candidates.append(json.loads(raw))
        except (TypeError, ValueError, json.JSONDecodeError):
            continue

    for item in reversed(candidates):
        if not isinstance(item, dict):
            continue
        nested = item.get("data")
        if isinstance(nested, dict) and any(key in nested for key in ("created", "updated", "synced", "skipped")):
            return nested
        if any(key in item for key in ("created", "updated", "synced", "skipped")):
            return item
    return None


class Grok2APIClient:
    def __init__(self, api_url: str, username: str, password: str, target: str, timeout: int = 180):
        self.api_url = str(api_url or "").strip().rstrip("/")
        self.username = str(username or "").strip()
        self.password = str(password or "")
        self.target = target if target in {"grok_console", "grok_web"} else "grok_console"
        self.timeout = max(15, int(timeout or 180))

    @classmethod
    def from_config(cls) -> "Grok2APIClient":
        return cls(
            getattr(cfg, "GROK2API_URL", ""),
            getattr(cfg, "GROK2API_USERNAME", ""),
            getattr(cfg, "GROK2API_PASSWORD", ""),
            getattr(cfg, "GROK2API_TARGET", "grok_console"),
            getattr(cfg, "GROK2API_TIMEOUT", 180),
        )

    def _request_kwargs(self) -> Dict[str, Any]:
        kwargs: Dict[str, Any] = {
            "timeout": self.timeout,
            "impersonate": "chrome110",
            "proxies": {},
        }
        if bool(getattr(cfg, "GROK2API_PUSH_USE_PROXY", False)):
            proxy = str(getattr(cfg, "GROK2API_PUSH_PROXY", "") or getattr(cfg, "DEFAULT_PROXY", "")).strip()
            if proxy:
                if proxy.startswith("socks5://"):
                    proxy = proxy.replace("socks5://", "socks5h://", 1)
                kwargs["proxies"] = {"http": proxy, "https": proxy}
        return kwargs

    def _cache_key(self) -> Tuple[str, str]:
        return self.api_url, self.username

    def _clear_cached_token(self) -> None:
        with _TOKEN_LOCK:
            _TOKEN_CACHE.pop(self._cache_key(), None)

    def _login(self) -> str:
        if not self.api_url or not self.username or not self.password:
            raise ValueError("Grok2API 未配置完整的 API 地址、管理员用户名或密码")

        key = self._cache_key()
        now = time.time()
        with _TOKEN_LOCK:
            cached = _TOKEN_CACHE.get(key)
            if cached and cached[1] > now + 30:
                return cached[0]

            response = cffi_requests.post(
                f"{self.api_url}/api/admin/v1/auth/login",
                json={"username": self.username, "password": self.password},
                **self._request_kwargs(),
            )
            if response.status_code != 200:
                raise RuntimeError(f"Grok2API 登录失败 HTTP {response.status_code}: {response.text[:200]}")
            try:
                payload = response.json()
            except ValueError as exc:
                raise RuntimeError("Grok2API 登录响应不是 JSON") from exc
            token = str(((payload.get("data") or {}).get("tokens") or {}).get("accessToken") or "").strip()
            if not token:
                raise RuntimeError(f"Grok2API 登录未返回 accessToken: {str(payload)[:200]}")
            expires_at = _jwt_exp(token) or (now + 300)
            _TOKEN_CACHE[key] = (token, expires_at)
        return token

    def push_sso(self, sso: str) -> Tuple[bool, str]:
        sso = str(sso or "").strip()
        if not sso:
            return False, "SSO 为空"
        if not self.api_url:
            return False, "未配置 Grok2API 地址"

        endpoint_name = "console" if self.target == "grok_console" else "web"
        filename = f"grok-{endpoint_name}-sso-tokens.txt"
        url = f"{self.api_url}/api/admin/v1/accounts/{endpoint_name}/import"
        for attempt in range(2):
            try:
                token = self._login()
                response = cffi_requests.post(
                    url,
                    headers={"Authorization": f"Bearer {token}", "Accept": "text/event-stream"},
                    files={"files": (filename, f"{sso}\n", "text/plain")},
                    **self._request_kwargs(),
                )
                if response.status_code == 401 and attempt == 0:
                    self._clear_cached_token()
                    continue
                if response.status_code != 200:
                    return False, f"HTTP {response.status_code}: {response.text[:240]}"
                summary = _parse_sse_result(response.text)
                if not summary:
                    return False, "导入响应没有最终统计事件"
                created = summary.get("created", 0)
                updated = summary.get("updated", 0)
                synced = summary.get("synced", 0)
                skipped = summary.get("skipped", 0)
                return True, f"{endpoint_name} 导入完成 created={created}, updated={updated}, synced={synced}, skipped={skipped}"
            except Exception as exc:
                if attempt == 0 and "401" in str(exc):
                    self._clear_cached_token()
                    continue
                return False, str(exc).strip() or repr(exc)
        return False, "Grok2API 推送失败"


def push_grok_sso(sso: str) -> Tuple[bool, str]:
    return Grok2APIClient.from_config().push_sso(sso)
