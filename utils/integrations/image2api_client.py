import json
import logging
import threading
import time
from typing import Dict, Any, List, Tuple
from utils import config as cfg
from curl_cffi import requests as cffi_requests

logger = logging.getLogger(__name__)
_IMAGE2API_PUSH_SEM = threading.BoundedSemaphore(3)


def _safe_bool(value: Any, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    text = str(value).strip().lower()
    if text in {"1", "true", "yes", "on", "y"}:
        return True
    if text in {"0", "false", "no", "off", "n", ""}:
        return False
    return default


def _config_section(name: str) -> Dict[str, Any]:
    raw = getattr(cfg, "_c", {})
    if isinstance(raw, dict) and isinstance(raw.get(name), dict):
        return raw.get(name) or {}
    return {}


def _normalize_proxy_url(proxy_url: str) -> str:
    proxy = str(proxy_url or "").strip()
    if not proxy:
        return ""
    formatter = getattr(cfg, "format_docker_url", None)
    if callable(formatter):
        proxy = formatter(proxy)
    if proxy.startswith("socks5://"):
        proxy = proxy.replace("socks5://", "socks5h://", 1)
    return proxy


def _push_transport_kwargs(section_name: str) -> Dict[str, Any]:
    section = _config_section(section_name)
    # 默认直连推送，避免 Image2API 推送占用注册用的全局代理。
    if not _safe_bool(section.get("push_use_proxy"), default=False):
        return {"proxies": {}}

    proxy = _normalize_proxy_url(section.get("push_proxy") or getattr(cfg, "DEFAULT_PROXY", ""))
    if not proxy:
        return {"proxies": {}}
    return {"proxies": {"http": proxy, "https": proxy}}



class Image2APIClient:
    def __init__(self, api_url: str = None, api_key: str = None):
        self.api_url = (api_url or getattr(cfg, "IMAGE2API_URL", "")).rstrip("/")
        self.api_key = api_key or getattr(cfg, "IMAGE2API_KEY", "")

        self.headers = {
            "Accept": "application/json, text/plain, */*",
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}"
        }

        self.request_kwargs = {
            "timeout": 90,
            "impersonate": "chrome110",
            "verify": False
        }

    def _request_kwargs(self, **overrides: Any) -> Dict[str, Any]:
        kwargs = dict(self.request_kwargs)
        kwargs.update(overrides)
        kwargs.update(_push_transport_kwargs("image2api_mode"))
        return kwargs

    def _handle_response(
            self,
            response: cffi_requests.Response,
            success_codes: Tuple[int, ...] = (200, 201, 204),
    ) -> Tuple[bool, Any]:
        if response.status_code in success_codes:
            try:
                return True, response.json() if response.text else {}
            except ValueError:
                return True, response.text

        error_msg = f"HTTP {response.status_code}"
        try:
            detail = response.json()
            if isinstance(detail, dict):
                error_msg = detail.get("message", error_msg)
        except Exception:
            error_msg = f"{error_msg} - {response.text[:200]}"

        return False, error_msg

    def add_accounts(self, tokens: List[str]) -> Tuple[bool, str]:
        if not self.api_url or not self.api_key:
            return False, "Image2API 配置缺失，请检查 URL 和 Auth Key"

        if not tokens:
            return False, "没有需要上传的 Token"

        url = f"{self.api_url}/api/accounts"
        payload = {"tokens": tokens}
        last_error = None

        with _IMAGE2API_PUSH_SEM:
            for attempt in range(1, 4):
                try:
                    response = cffi_requests.post(
                        url,
                        json=payload,
                        headers=self.headers,
                        **self._request_kwargs()
                    )
                    status = response.status_code
                    response.close()
                    if status in (200, 201, 204):
                        logger.info(f"Image2API 推送成功: {len(tokens)} 个账号 (HTTP {status})")
                        return True, f"成功推送 {len(tokens)} 个账号"
                    last_error = f"推送失败，远端返回状态码: {status}"
                    logger.warning("Image2API 推送失败，第 %s/3 次，HTTP %s", attempt, status)
                except Exception as exc:
                    last_error = f"网络请求失败: {exc}"
                    logger.error("向 Image2API 推送网络请求失败，第 %s/3 次: %s", attempt, exc)
                if attempt < 3:
                    time.sleep(2 * attempt)

        return False, last_error or "推送失败"

    def get_accounts(self) -> Tuple[bool, Any]:
        if not self.api_url or not self.api_key:
            return False, "配置未填写"
        url = f"{self.api_url}/api/accounts"
        try:
            kwargs = self._request_kwargs()
            kwargs["timeout"] = 60
            response = cffi_requests.get(url, headers=self.headers, **kwargs)
            return self._handle_response(response)
        except Exception as exc:
            return False, f"获取远端账号失败: {exc}"

    def update_account_status(self, access_token: str, status: str, acc_type: str = "Free", quota: int = 25) -> \
    Tuple[bool, Any]:
        url = f"{self.api_url}/api/accounts/update"
        payload = {
            "access_token": access_token,
            "type": acc_type,
            "status": status,
            "quota": quota
        }
        try:
            response = cffi_requests.post(url, json=payload, headers=self.headers, **self._request_kwargs())
            return self._handle_response(response)
        except Exception as exc:
            return False, f"更新远端状态失败: {exc}"

    def refresh_tokens(self, access_tokens: List[str]) -> Tuple[bool, Any]:
        url = f"{self.api_url}/api/accounts/refresh"
        payload = {"access_tokens": access_tokens}
        try:
            response = cffi_requests.post(url, json=payload, headers=self.headers, **self._request_kwargs())
            return self._handle_response(response)
        except Exception as exc:
            return False, f"刷新远端凭证失败: {exc}"