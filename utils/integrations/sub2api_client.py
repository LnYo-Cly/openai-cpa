import json
import logging
import threading
import time
import uuid
from urllib.parse import urlparse
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple
from utils import config as cfg
from curl_cffi import requests as cffi_requests
from utils.integrations.sub2api_proxy import parse_sub2api_proxy

logger = logging.getLogger(__name__)


def _ai_user_log(account_name: str, stage: str, detail: str = "") -> None:
    """Emit concise Agent Identity stage lines into the web console log stream."""
    try:
        from utils.config import ts as _ts
        stamp = _ts()
    except Exception:
        stamp = "-"
    msg = f"[{stamp}] [INFO] （{account_name}）Agent Identity [{stage}]"
    if detail:
        msg = f"{msg}: {detail}"
    try:
        print(msg)
    except Exception:
        logger.info("%s", msg)

_SUB2API_PUSH_SEM = threading.BoundedSemaphore(3)


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
    # 默认直连推送，避免 Sub2API/Image2API 推送占用注册用的全局代理。
    if not _safe_bool(section.get("push_use_proxy"), default=False):
        return {"proxies": {}}

    proxy = _normalize_proxy_url(section.get("push_proxy") or getattr(cfg, "DEFAULT_PROXY", ""))
    if not proxy:
        return {"proxies": {}}
    return {"proxies": {"http": proxy, "https": proxy}}



def get_sub2api_push_settings() -> Dict[str, Any]:
    def as_int(value: Any, default: int, minimum: int) -> int:
        try:
            return max(minimum, int(value))
        except (TypeError, ValueError):
            return default

    def as_float(value: Any, default: float, minimum: float) -> float:
        try:
            return max(minimum, float(value))
        except (TypeError, ValueError):
            return default

    raw_group_ids = getattr(cfg, "SUB2API_ACCOUNT_GROUP_IDS", [])
    if isinstance(raw_group_ids, list):
        group_ids = [int(item) for item in raw_group_ids if str(item).strip().isdigit()]
    else:
        group_ids = [int(item.strip()) for item in str(raw_group_ids or "").split(",") if item.strip().isdigit()]

    push_format = str(getattr(cfg, "SUB2API_PUSH_FORMAT", "agent_identity") or "agent_identity").strip().lower()
    if push_format in {"agentidentity", "agent-identity", "identity", "auth_json", "auth-json"}:
        push_format = "agent_identity"
    elif push_format not in {"oauth", "agent_identity"}:
        push_format = "oauth"

    return {
        "concurrency": as_int(getattr(cfg, "SUB2API_ACCOUNT_CONCURRENCY", 10), 10, 1),
        "load_factor": as_int(getattr(cfg, "SUB2API_ACCOUNT_LOAD_FACTOR", 10), 10, 1),
        "priority": as_int(getattr(cfg, "SUB2API_ACCOUNT_PRIORITY", 1), 1, 1),
        "rate_multiplier": as_float(getattr(cfg, "SUB2API_ACCOUNT_RATE_MULTIPLIER", 1.0), 1.0, 0.0),
        "group_ids": group_ids,
        "enable_ws": bool(getattr(cfg, "SUB2API_ENABLE_WS_MODE", True)),
        "push_format": push_format,
        "agent_identity_fallback_oauth": _safe_bool(
            getattr(cfg, "SUB2API_AGENT_IDENTITY_FALLBACK_OAUTH", False),
            default=False,
        ),
        "agent_identity_use_reg_proxy": _safe_bool(
            getattr(cfg, "SUB2API_AGENT_IDENTITY_USE_REG_PROXY", True),
            default=True,
        ),
        # Path B 内嵌 Path C：register 被拒时从 Sub2API Runtime 池恢复
        "agent_identity_runtime_recovery": _safe_bool(
            getattr(cfg, "SUB2API_AGENT_IDENTITY_RUNTIME_RECOVERY", True),
            default=True,
        ),
        "agent_identity_recovery_cross_account": _safe_bool(
            getattr(cfg, "SUB2API_AGENT_IDENTITY_RECOVERY_CROSS_ACCOUNT", True),
            default=True,
        ),
        "update_existing": _safe_bool(
            getattr(cfg, "SUB2API_UPDATE_EXISTING", True),
            default=True,
        ),
    }



def _build_account_extra(settings: Dict[str, Any]) -> Dict[str, Any]:
    extra = {"load_factor": settings["load_factor"]}
    if settings["enable_ws"]:
        extra["openai_oauth_responses_websockets_v2_enabled"] = True
        extra["openai_oauth_responses_websockets_v2_mode"] = "passthrough"
    else:
        # Align with Sub2API admin UI default when WS mode is off.
        extra["openai_oauth_responses_websockets_v2_enabled"] = False
        extra["openai_oauth_responses_websockets_v2_mode"] = "off"
    return extra


def _build_account_item(token_data: Dict[str, Any], settings: Dict[str, Any], proxy_obj: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    email = str(token_data.get("email") or "unknown").strip() or "unknown"
    name = email[:64]
    provider = str(token_data.get("provider") or token_data.get("type") or "").lower()
    status = str(token_data.get("status") or "").lower()

    if provider in ("grok", "xai") or status.startswith("grok") or "grok_oauth" in status:
        access = str(token_data.get("access_token") or "").strip()
        refresh = str(token_data.get("refresh_token") or "").strip()
        expires_in = token_data.get("expires_in", 21600)
        try:
            expires_in = int(expires_in)
        except (TypeError, ValueError):
            expires_in = 21600
        expires_at = token_data.get("expires_at")
        if expires_at in (None, ""):
            expires_at = int(time.time()) + expires_in
        else:
            try:
                expires_at = int(expires_at)
            except (TypeError, ValueError):
                expires_at = int(time.time()) + expires_in

        credentials: Dict[str, Any] = {
            "access_token": access,
            "refresh_token": refresh,
            "token_type": str(token_data.get("token_type") or "Bearer"),
            "email": email,
            "expires_in": expires_in,
            "expires_at": expires_at,
        }
        id_token = str(token_data.get("id_token") or "").strip()
        if id_token:
            credentials["id_token"] = id_token
        base_url = str(token_data.get("base_url") or "").strip()
        if base_url:
            credentials["base_url"] = base_url
        token_endpoint = str(token_data.get("token_endpoint") or "").strip()
        if token_endpoint:
            credentials["token_endpoint"] = token_endpoint
        client_id = str(token_data.get("client_id") or "").strip()
        if client_id:
            credentials["client_id"] = client_id
        scope = str(token_data.get("scope") or "").strip()
        if scope:
            credentials["scope"] = scope
        sub = str(token_data.get("sub") or "").strip()
        if sub:
            credentials["sub"] = sub
        account_item: Dict[str, Any] = {
            "name": name,
            "platform": "grok",
            "type": "oauth",
            "credentials": credentials,
            "extra": {
                "email": email,
                "source": "openai-cpa",
            },
            "concurrency": settings["concurrency"],
            "priority": settings["priority"],
            "rate_multiplier": settings["rate_multiplier"],
            "auto_pause_on_expired": True,
        }
    else:
        account_item = {
            "name": name,
            "platform": "openai",
            "type": "oauth",
            "credentials": {
                "access_token": token_data.get("access_token", ""),
                "chatgpt_account_id": token_data.get("account_id", ""),
                "client_id": token_data.get("client_id", ""),
                "expires_at": int(time.time() + 864000),
                "expires_in": 863999,
                "model_mapping": {
                    "gpt-5.4": "gpt-5.4",
                    "gpt-5.4-mini": "gpt-5.4-mini",
                    "gpt-5.5": "gpt-5.5",
                    "gpt-5.6-sol": "gpt-5.6-sol",
                    "gpt-5.6-luna": "gpt-5.6-luna",
                    "gpt-5.6-terra": "gpt-5.6-terra"
                },
                "organization_id": token_data.get("workspace_id", ""),
                "refresh_token": token_data.get("refresh_token", ""),
            },
            "extra": _build_account_extra(settings),
            "concurrency": settings["concurrency"],
            "priority": settings["priority"],
            "rate_multiplier": settings["rate_multiplier"],
            "auto_pause_on_expired": True,
        }

    if settings.get("group_ids"):
        account_item["group_ids"] = settings["group_ids"]
    if proxy_obj and "proxy_key" in proxy_obj:
        account_item["proxy_key"] = proxy_obj["proxy_key"]
    return account_item


def build_sub2api_export_bundle(
    token_items: List[Dict[str, Any]],
    settings: Optional[Dict[str, Any]] = None,
    *,
    rotate_missing_proxy: bool = False,
) -> Dict[str, Any]:
    push_settings = settings or get_sub2api_push_settings()
    proxies_by_key: Dict[str, Dict[str, Any]] = {}
    accounts: List[Dict[str, Any]] = []

    for token_data in token_items:
        proxy_obj = token_data.get("sub2api_proxy")
        if proxy_obj is None and rotate_missing_proxy:
            proxy_obj = parse_sub2api_proxy(cfg.get_next_sub2api_proxy_url())
        if proxy_obj and proxy_obj.get("proxy_key"):
            proxies_by_key[proxy_obj["proxy_key"]] = proxy_obj
        accounts.append(_build_account_item(token_data, push_settings, proxy_obj))

    return {
        "exported_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "proxies": list(proxies_by_key.values()),
        "accounts": accounts,
    }


class Sub2APIClient:
    def __init__(self, api_url: str, api_key: str):
        self.api_url = api_url.rstrip("/")
        self.headers = {
            "Content-Type": "application/json",
            "x-api-key": api_key,
        }
        self.request_kwargs = {
            "timeout": 45,
            "impersonate": "chrome110",
        }
        self._sub2api_proxy_ids: Dict[str, int] = {}
        self._sub2api_proxy_ids_lock = threading.Lock()
        self._valid_group_ids_cache = None
        self._valid_group_ids_ts = 0.0

    def _request_kwargs(self, **overrides: Any) -> Dict[str, Any]:
        kwargs = dict(self.request_kwargs)
        kwargs.update(overrides)
        kwargs.update(_push_transport_kwargs("sub2api_mode"))
        return kwargs

    def _build_network_error(self, exc: Exception) -> str:
        msg = str(exc)
        host = (urlparse(self.api_url).hostname or "").strip()
        if "Could not resolve host" in msg and host:
            return (
                f"{msg} | 本机 DNS 无法解析 {host}，"
                "请优先检查本机或路由器 DNS，或暂时切换到公共 DNS 后重试"
            )
        return msg

    @staticmethod
    def _is_dns_resolution_error(message: Any) -> bool:
        return "Could not resolve host" in str(message or "")

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

    def _extract_group_id(self, item: Any) -> Optional[int]:
        if not isinstance(item, dict):
            return None
        for key in ("id", "group_id", "groupId", "ID"):
            raw = item.get(key)
            if raw is None:
                continue
            try:
                return int(raw)
            except (TypeError, ValueError):
                text = str(raw).strip()
                if text.isdigit():
                    return int(text)
        return None

    def _fetch_valid_group_ids(self, *, force: bool = False):
        now = time.time()
        cached = getattr(self, "_valid_group_ids_cache", None)
        ts = float(getattr(self, "_valid_group_ids_ts", 0.0) or 0.0)
        if not force and isinstance(cached, set) and (now - ts) < 60.0:
            return set(cached)

        try:
            response = cffi_requests.get(
                f"{self.api_url}/api/v1/admin/groups/all",
                headers=self.headers,
                timeout=10,
                impersonate="chrome110",
                proxies=None,
            )
            ok, result = self._handle_response(response, success_codes=(200,))
            if not ok:
                logger.warning("获取 Sub2API 分组失败，跳过分组校验: %s", result)
                return None

            raw = result.get("data", result) if isinstance(result, dict) else result
            groups = []
            if isinstance(raw, list):
                groups = raw
            elif isinstance(raw, dict):
                if isinstance(raw.get("list"), list):
                    groups = raw.get("list") or []
                elif isinstance(raw.get("data"), list):
                    groups = raw.get("data") or []
                elif isinstance(raw.get("items"), list):
                    groups = raw.get("items") or []

            valid = set()
            for item in groups:
                gid = self._extract_group_id(item)
                if gid is not None:
                    valid.add(gid)

            self._valid_group_ids_cache = set(valid)
            self._valid_group_ids_ts = now
            return set(valid)
        except Exception as exc:
            logger.warning("获取 Sub2API 分组异常，跳过分组校验: %s", exc)
            return None

    def _sanitize_group_ids(self, group_ids: List[int]) -> List[int]:
        cleaned = []
        seen = set()
        for item in group_ids or []:
            try:
                gid = int(item)
            except (TypeError, ValueError):
                continue
            if gid in seen:
                continue
            seen.add(gid)
            cleaned.append(gid)
        if not cleaned:
            return []

        valid = self._fetch_valid_group_ids(force=False)
        if valid is None:
            return cleaned

        kept = [gid for gid in cleaned if gid in valid]
        dropped = [gid for gid in cleaned if gid not in valid]
        if dropped:
            logger.warning(
                "配置中的 Sub2API 分组已在线上删除，已自动忽略: %s；有效分组: %s",
                dropped,
                kept,
            )
            try:
                print(
                    f"[Sub2API] 分组 {dropped} 已不存在，推送时自动跳过；"
                    f"请重新「获取线上分组」并保存配置"
                )
            except Exception:
                pass
        return kept

    def _get_push_settings(self) -> Dict[str, Any]:
        settings = get_sub2api_push_settings()
        settings = dict(settings)
        settings["group_ids"] = self._sanitize_group_ids(settings.get("group_ids") or [])
        return settings

    def _build_account_extra(self, settings: Dict[str, Any]) -> Dict[str, Any]:
        return _build_account_extra(settings)

    def _refresh_created_account(self, account_id: str) -> None:
        if not account_id:
            return

        refresh_urls = [
            f"{self.api_url}/api/v1/admin/accounts/{account_id}/refresh",
            f"{self.api_url}/api/v1/admin/openai/accounts/{account_id}/refresh",
        ]

        for refresh_url in refresh_urls:
            try:
                response = cffi_requests.post(
                    refresh_url,
                    json={},
                    headers=self.headers,
                    **self._request_kwargs(timeout=30),
                )
                if response.status_code in (200, 201, 204):
                    logger.info("Sub2API account refresh succeeded (ID: %s)", account_id)
                    return
            except Exception as exc:
                logger.warning("Sub2API account refresh failed via %s: %s", refresh_url, exc)

        logger.warning("Sub2API account refresh did not succeed for %s", account_id)

    def _import_account(self, token_data: Dict[str, Any], settings: Dict[str, Any]) -> Tuple[bool, str]:
        url = f"{self.api_url}/api/v1/admin/accounts/data"
        bundle = build_sub2api_export_bundle([token_data], settings, rotate_missing_proxy=True)
        payload = {
            "data": {
                "type": "sub2api-data",
                "version": 1,
                **bundle,
            },
            "skip_default_group_bind": not bool(settings["group_ids"]),
        }

        try:
            headers = self.headers.copy()
            headers["Idempotency-Key"] = f"import-{int(time.time())}"
            response = cffi_requests.post(
                url,
                json=payload,
                headers=headers,
                **self._request_kwargs(timeout=60),
            )
            ok, result = self._handle_response(response, success_codes=(200, 201))
            if ok:
                return True, "Sub2API account import succeeded"
            return False, str(result)
        except Exception as exc:
            return False, f"Network request failed: {exc}"

    def get_accounts(self, page: int = 1, page_size: int = 50) -> Tuple[bool, Any]:
        url = f"{self.api_url}/api/v1/admin/accounts"
        params = {
            "page": page,
            "page_size": page_size,
        }
        try:
            request_kwargs = self._request_kwargs()
            # 全量库存接口体积较大，分页读取时放宽超时，降低本地网络抖动造成的误判。
            request_kwargs["timeout"] = max(int(request_kwargs.get("timeout", 15)), 45)
            response = cffi_requests.get(url, headers=self.headers, params=params, **request_kwargs)
            return self._handle_response(response)
        except Exception as exc:
            logger.error("Get Sub2API accounts failed: %s", exc)
            return False, self._build_network_error(exc)

    def get_all_accounts(self, page_size: int = 100) -> Tuple[bool, Any]:
        all_items: List[dict] = []
        strategies = []
        for size in (page_size, 50, 25):
            if size not in strategies and size > 0:
                strategies.append(size)

        last_error: Any = "unknown error"
        for current_page_size in strategies:
            all_items = []
            page = 1
            page_failed = False

            while True:
                ok = False
                data: Any = None
                attempt_error: Any = None

                for attempt in range(1, 4):
                    ok, data = self.get_accounts(page=page, page_size=current_page_size)
                    if ok:
                        break
                    attempt_error = data
                    logger.warning(
                        "Sub2API page fetch failed (page=%s, page_size=%s, attempt=%s): %s",
                        page,
                        current_page_size,
                        attempt,
                        data,
                    )
                    time.sleep(min(attempt, 3))

                if not ok:
                    last_error = attempt_error
                    if self._is_dns_resolution_error(attempt_error):
                        logger.warning(
                            "Sub2API full inventory aborted because DNS resolution failed on page %s",
                            page,
                        )
                        return False, attempt_error
                    if page == 1:
                        page_failed = True
                    else:
                        logger.warning(
                            "Sub2API pagination failed on page %s; continue with %s fetched accounts",
                            page,
                            len(all_items),
                        )
                    break

                inner = data.get("data", {}) if isinstance(data, dict) else {}
                items = inner.get("items", [])
                if not items:
                    break

                all_items.extend(items)

                total = inner.get("total", 0)
                if len(all_items) >= total:
                    logger.info(
                        "Fetched %s Sub2API accounts across paginated results (page_size=%s)",
                        len(all_items),
                        current_page_size,
                    )
                    return True, all_items

                page += 1

            if not page_failed:
                logger.info(
                    "Fetched %s Sub2API accounts across paginated results (partial, page_size=%s)",
                    len(all_items),
                    current_page_size,
                )
                return True, all_items

            next_sizes = [size for size in strategies if size < current_page_size]
            if next_sizes:
                logger.warning(
                    "Retrying Sub2API full inventory with smaller page_size=%s after failure on first page",
                    next_sizes[0],
                )

        return False, last_error

    def get_total_count(self) -> Tuple[bool, Any]:
        ok, data = self.get_accounts(page=1, page_size=1)
        if not ok:
            return False, data

        inner = data.get("data", {}) if isinstance(data, dict) else {}
        total = inner.get("total")
        if total is None:
            items = inner.get("items", [])
            total = len(items) if isinstance(items, list) else 0
        try:
            return True, int(total)
        except (TypeError, ValueError):
            return False, f"Sub2API total 字段异常: {total}"

    def get_account_usage(self, account_id: str) -> Tuple[bool, Any]:
        url = f"{self.api_url}/api/v1/admin/accounts/{account_id}/usage"
        params = {"timezone": "Asia/Shanghai"}
        try:
            response = cffi_requests.get(
                url,
                headers=self.headers,
                params=params,
                **self._request_kwargs()
            )
            return self._handle_response(response)
        except Exception as exc:
            logger.error("Get Sub2API account usage %s failed: %s", account_id, exc)
            return False, str(exc)


    def _resolve_identity_reg_proxies(self, token_data: Dict[str, Any], settings: Dict[str, Any]) -> Any:
        """Proxy used when calling OpenAI auth.openai.com to register agent identity."""
        if not settings.get("agent_identity_use_reg_proxy", True):
            return None
        raw = (
            token_data.get("proxy")
            or token_data.get("reg_proxy")
            or getattr(cfg, "DEFAULT_PROXY", "")
            or ""
        )
        proxy = str(raw or "").strip()
        if not proxy:
            return None
        formatter = getattr(cfg, "format_docker_url", None)
        if callable(formatter):
            proxy = formatter(proxy)
        if proxy.startswith("socks5://"):
            proxy = proxy.replace("socks5://", "socks5h://", 1)
        return {"http": proxy, "https": proxy}

    def _export_account_data_by_ids(self, account_ids: List[Any]) -> Tuple[bool, Any]:
        """Export full account credentials (including agent_private_key when permitted)."""
        ids = []
        for item in account_ids or []:
            try:
                value = int(item)
            except (TypeError, ValueError):
                continue
            if value > 0:
                ids.append(value)
        if not ids:
            return False, "empty account ids"
        url = f"{self.api_url}/api/v1/admin/accounts/data"
        params = {
            "ids": ",".join(str(i) for i in ids[:20]),
            "include_proxies": "false",
        }
        try:
            response = cffi_requests.get(
                url,
                headers=self.headers,
                params=params,
                **self._request_kwargs(timeout=60),
            )
            return self._handle_response(response)
        except Exception as exc:
            logger.error("Export Sub2API account data failed: %s", exc)
            return False, self._build_network_error(exc)

    @staticmethod
    def _iter_exported_accounts(export_payload: Any) -> List[Dict[str, Any]]:
        """Normalize /admin/accounts/data response into a list of account dicts."""
        if not isinstance(export_payload, dict):
            return []
        candidates: List[Any] = []
        for key in ("accounts", "items", "data"):
            value = export_payload.get(key)
            if isinstance(value, list):
                candidates = value
                break
            if isinstance(value, dict):
                nested = value.get("accounts") or value.get("items")
                if isinstance(nested, list):
                    candidates = nested
                    break
                # some builds nest once more under data.data
                deeper = value.get("data")
                if isinstance(deeper, dict):
                    nested = deeper.get("accounts") or deeper.get("items")
                    if isinstance(nested, list):
                        candidates = nested
                        break
        out: List[Dict[str, Any]] = []
        for item in candidates:
            if isinstance(item, dict):
                out.append(item)
        return out

    def find_reusable_agent_identity(
        self,
        chatgpt_account_id: str,
        chatgpt_user_id: str,
        *,
        allow_cross_account: bool = True,
        max_pages: int = 20,
    ) -> Optional[Dict[str, str]]:
        """Path C pool lookup: recover runtime_id + private_key from active Agent Identity rows.

        Preference order:
        1) exact chatgpt_account_id + chatgpt_user_id match
        2) other complete active Agent Identity runtimes (if allow_cross_account)
        """
        target_account = str(chatgpt_account_id or "").strip()
        target_user = str(chatgpt_user_id or "").strip()
        if not target_account or not target_user:
            return None

        candidates: List[Tuple[int, int, str, str, str]] = []
        page = 1
        while page <= max(1, int(max_pages or 20)):
            ok, data = self.get_accounts(page=page, page_size=100)
            if not ok:
                logger.warning("Path C pool list page=%s failed: %s", page, data)
                break
            inner = data.get("data", data) if isinstance(data, dict) else {}
            if not isinstance(inner, dict):
                break
            items = inner.get("items") or []
            if not isinstance(items, list) or not items:
                break

            for item in items:
                if not isinstance(item, dict):
                    continue
                status = str(item.get("status") or "").strip().lower()
                if status and status not in {"active", "enabled", "ok"}:
                    continue
                credentials = item.get("credentials")
                if not isinstance(credentials, dict):
                    continue
                cred_status = item.get("credentials_status")
                runtime_id = str(
                    credentials.get("agent_runtime_id")
                    or credentials.get("agentRuntimeId")
                    or ""
                ).strip()
                task_id = str(credentials.get("task_id") or credentials.get("taskId") or "").strip()
                source_account = str(
                    credentials.get("chatgpt_account_id")
                    or credentials.get("account_id")
                    or ""
                ).strip()
                source_user = str(
                    credentials.get("chatgpt_user_id")
                    or credentials.get("chatgptUserId")
                    or ""
                ).strip()
                auth_mode = str(credentials.get("auth_mode") or credentials.get("authMode") or "").strip()
                has_key = True
                if isinstance(cred_status, dict) and "has_agent_private_key" in cred_status:
                    has_key = bool(cred_status.get("has_agent_private_key"))
                if (
                    auth_mode != "agentIdentity"
                    or not runtime_id
                    or not task_id
                    or not source_account
                    or not source_user
                    or not has_key
                ):
                    continue
                try:
                    account_row_id = int(item.get("id"))
                except (TypeError, ValueError):
                    continue
                if account_row_id <= 0:
                    continue
                exact = source_account == target_account and source_user == target_user
                if not exact and not allow_cross_account:
                    continue
                candidates.append(
                    (
                        0 if exact else 1,
                        account_row_id,
                        runtime_id,
                        source_account,
                        source_user,
                    )
                )

            total = inner.get("total")
            try:
                total_i = int(total) if total is not None else None
            except (TypeError, ValueError):
                total_i = None
            if total_i is not None and page * 100 >= total_i:
                break
            pages = inner.get("pages")
            try:
                pages_i = int(pages) if pages is not None else None
            except (TypeError, ValueError):
                pages_i = None
            if pages_i is not None and page >= pages_i:
                break
            page += 1

        if not candidates:
            return None

        candidates.sort(key=lambda row: (row[0], -row[1]))
        for priority, account_row_id, listed_runtime, listed_account, listed_user in candidates:
            ok, exported = self._export_account_data_by_ids([account_row_id])
            if not ok:
                err_text = str(exported or "")
                logger.warning(
                    "Path C export id=%s failed: %s",
                    account_row_id,
                    err_text[:200],
                )
                # Permission errors should fail closed quickly.
                if any(
                    marker in err_text.upper()
                    for marker in (
                        "STEP_UP",
                        "FORBIDDEN",
                        "403",
                        "UNAUTHORIZED",
                        "401",
                    )
                ):
                    raise RuntimeError(
                        f"Sub2API 拒绝导出 Agent Identity 私钥（id={account_row_id}）：{err_text[:180]}"
                    )
                continue

            for account in self._iter_exported_accounts(exported if isinstance(exported, dict) else {}):
                credentials = account.get("credentials")
                if not isinstance(credentials, dict):
                    continue
                runtime_id = str(
                    credentials.get("agent_runtime_id")
                    or credentials.get("agentRuntimeId")
                    or ""
                ).strip()
                private_key = str(
                    credentials.get("agent_private_key")
                    or credentials.get("agentPrivateKey")
                    or ""
                ).strip()
                source_account = str(
                    credentials.get("chatgpt_account_id")
                    or credentials.get("account_id")
                    or ""
                ).strip()
                source_user = str(
                    credentials.get("chatgpt_user_id")
                    or credentials.get("chatgptUserId")
                    or ""
                ).strip()
                auth_mode = str(credentials.get("auth_mode") or credentials.get("authMode") or "").strip()
                if (
                    auth_mode != "agentIdentity"
                    or runtime_id != listed_runtime
                    or source_account != listed_account
                    or source_user != listed_user
                    or not private_key
                ):
                    continue
                return {
                    "agent_runtime_id": runtime_id,
                    "agent_private_key": private_key,
                    "source_account_id": source_account,
                    "source_user_id": source_user,
                    "source_sub2api_id": str(account_row_id),
                    "exact_match": "1" if priority == 0 else "0",
                }
        return None

    def _import_codex_session(
        self,
        auth_json: Dict[str, Any],
        settings: Dict[str, Any],
        *,
        account_name: str,
    ) -> Tuple[bool, str]:
        """Push agent-identity auth.json via Sub2API codex-session import endpoint."""
        url = f"{self.api_url}/api/v1/admin/accounts/import/codex-session"
        # Match admin UI shape: content is a full auth.json string.
        payload: Dict[str, Any] = {
            "content": json.dumps(auth_json, ensure_ascii=False, indent=2),
            "name": account_name,
            "notes": None,
            "proxy_id": None,
            "concurrency": settings["concurrency"],
            "priority": settings["priority"],
            "rate_multiplier": settings["rate_multiplier"],
            "load_factor": settings["load_factor"],
            "expires_at": None,
            "auto_pause_on_expired": True,
            "extra": self._build_account_extra(settings),
            "update_existing": bool(settings.get("update_existing", True)),
            "skip_default_group_bind": not bool(settings.get("group_ids")),
        }
        if settings.get("group_ids"):
            payload["group_ids"] = settings["group_ids"]

        identity = auth_json.get("agent_identity") if isinstance(auth_json, dict) else None
        runtime_id = ""
        task_id = ""
        if isinstance(identity, dict):
            runtime_id = str(identity.get("agent_runtime_id") or "")[:24]
            task_id = str(identity.get("task_id") or "")[:24]
        logger.info(
            "Sub2API codex-session import start name=%s runtime=%s task=%s groups=%s",
            account_name,
            runtime_id or "-",
            task_id or "-",
            payload.get("group_ids") or [],
        )

        try:
            headers = self.headers.copy()
            headers["Idempotency-Key"] = f"codex-import-{int(time.time() * 1000)}"
            response = cffi_requests.post(
                url,
                json=payload,
                headers=headers,
                **self._request_kwargs(timeout=90),
            )
            status_code = int(getattr(response, "status_code", 0) or 0)
            if status_code in (404, 405):
                return False, (
                    "Sub2API 不支持 /import/codex-session（HTTP "
                    f"{status_code}）。请升级到含 Agent Identity 导入的版本后重试。"
                )
            ok, result = self._handle_response(response, success_codes=(200, 201))
            if not ok:
                logger.warning(
                    "Sub2API codex-session import HTTP fail name=%s status=%s msg=%s",
                    account_name,
                    status_code,
                    result,
                )
                return False, str(result)

            # Business-level fail-closed: HTTP 200 alone is not enough.
            if isinstance(result, dict):
                code = result.get("code", result.get("status"))
                if code not in (None, 0, 200, "0", "success", "ok", True):
                    msg = result.get("message") or result.get("msg") or result
                    return False, f"Sub2API business error: {msg}"

            data = result
            if isinstance(result, dict) and isinstance(result.get("data"), dict):
                data = result["data"]
            if not isinstance(data, dict):
                # Unexpected body: do not claim inventory success.
                preview = str(result)[:200]
                return False, f"Sub2API agent-identity import 响应异常（无统计字段）: {preview}"

            created = int(data.get("created") or 0)
            updated = int(data.get("updated") or 0)
            failed = int(data.get("failed") or 0)
            skipped = int(data.get("skipped") or 0)
            total = int(data.get("total") or 0)
            errors = data.get("errors") or []
            items = data.get("items") or []
            account_ids = [
                str(item.get("account_id"))
                for item in items
                if isinstance(item, dict) and item.get("account_id")
            ]

            def _first_error() -> str:
                if errors and isinstance(errors, list):
                    first = errors[0]
                    if isinstance(first, dict):
                        return str(first.get("message") or first)
                    return str(first)
                if items and isinstance(items, list):
                    for item in items:
                        if isinstance(item, dict) and str(item.get("action") or "").lower() == "failed":
                            return str(item.get("message") or item)
                return ""

            summary = (
                f"created={created}, updated={updated}, failed={failed}, "
                f"skipped={skipped}, total={total}"
            )
            logger.info(
                "Sub2API codex-session import result name=%s %s account_ids=%s",
                account_name,
                summary,
                account_ids[:3],
            )

            if failed > 0 and created == 0 and updated == 0:
                detail = _first_error() or "Sub2API agent-identity import failed"
                return False, f"{detail} ({summary})"

            if created == 0 and updated == 0:
                if skipped > 0:
                    return True, f"Sub2API agent-identity import skipped (already exists; {summary})"
                if account_ids:
                    return True, f"Sub2API agent-identity import ok (account_ids={','.join(account_ids[:3])}; {summary})"
                detail = _first_error()
                if detail:
                    return False, f"{detail} ({summary})"
                return False, (
                    "Sub2API agent-identity import 未新增/更新账号 "
                    f"({summary})；请检查 content 是否为完整 auth_mode=agentIdentity 的 auth.json"
                )

            return True, f"Sub2API agent-identity import ok ({summary})"
        except Exception as exc:
            return False, f"Network request failed: {exc}"

    def _add_account_agent_identity(
        self,
        token_data: Dict[str, Any],
        settings: Dict[str, Any],
    ) -> Tuple[bool, str]:
        """
        Path B: access_token only -> Agent Identity auth.json -> import.

        B1: register new Runtime + task on auth.openai.com.
        B2/Path C (embedded): if registry disabled, recover Runtime+key from
        Sub2API pool, register a fresh task, then import the same way.
        """
        from utils.integrations.agent_identity import (
            AgentIdentityError,
            create_agent_identity_auth_json,
            create_agent_identity_auth_json_from_recovered,
            is_agent_registry_not_enabled_error,
            parse_id_token_identity,
            resolve_identity_bootstrap_tokens,
        )

        account_name = str(token_data.get("email") or "unknown")[:64]
        group_ids = settings.get("group_ids") or []
        strategy = "register"
        try:
            _ai_user_log(account_name, "bootstrap", "校验 session access_token claims")
            logger.info("Agent Identity bootstrap start name=%s", account_name)
            tokens = resolve_identity_bootstrap_tokens(token_data)
            _ai_user_log(account_name, "bootstrap", "claims ok")
            logger.info("Agent Identity bootstrap token claims ok name=%s", account_name)
            proxies = self._resolve_identity_reg_proxies(token_data, settings)
            _ai_user_log(
                account_name,
                "register",
                f"Path B1 向 auth.openai.com 注册 agent 公钥/task（proxy={'yes' if proxies else 'no'}）",
            )
            logger.info(
                "Agent Identity register start name=%s proxy=%s",
                account_name,
                "yes" if proxies else "no",
            )
            try:
                auth_json = create_agent_identity_auth_json(
                    tokens["access_token"],
                    id_token=tokens.get("id_token"),
                    email=token_data.get("email"),
                    proxies=proxies,
                )
                strategy = "register"
            except AgentIdentityError as reg_exc:
                recovery_enabled = bool(settings.get("agent_identity_runtime_recovery", True))
                if not recovery_enabled or not is_agent_registry_not_enabled_error(reg_exc):
                    raise
                _ai_user_log(
                    account_name,
                    "recover",
                    f"Path C：Registry 不可用，尝试从 Sub2API Runtime 池恢复（{reg_exc}）",
                )
                logger.warning(
                    "Agent Identity B1 failed name=%s, trying Path C pool recovery: %s",
                    account_name,
                    reg_exc,
                )
                identity_claims = parse_id_token_identity(
                    tokens.get("id_token") or tokens["access_token"]
                )
                allow_cross = bool(settings.get("agent_identity_recovery_cross_account", True))
                try:
                    reusable = self.find_reusable_agent_identity(
                        identity_claims["account_id"],
                        identity_claims["chatgpt_user_id"],
                        allow_cross_account=allow_cross,
                    )
                except RuntimeError as pool_exc:
                    raise AgentIdentityError(str(pool_exc)) from pool_exc
                if not reusable:
                    raise AgentIdentityError(
                        "Agent Registry 未启用，且 Sub2API 中没有可恢复的完整 Agent Identity Runtime "
                        f"（cross_account={allow_cross}）; 原始错误: {reg_exc}"
                    ) from reg_exc
                _ai_user_log(
                    account_name,
                    "recover",
                    (
                        f"命中池 runtime={str(reusable.get('agent_runtime_id') or '')[:20]} "
                        f"exact={reusable.get('exact_match')} "
                        f"src_sub2api_id={reusable.get('source_sub2api_id')}"
                    ),
                )
                auth_json = create_agent_identity_auth_json_from_recovered(
                    tokens["access_token"],
                    agent_runtime_id=reusable["agent_runtime_id"],
                    agent_private_key_pkcs8=reusable["agent_private_key"],
                    id_token=tokens.get("id_token"),
                    email=token_data.get("email"),
                    proxies=proxies,
                    recovery_source=(
                        f"sub2api_pool:id={reusable.get('source_sub2api_id')}"
                        f":exact={reusable.get('exact_match')}"
                    ),
                )
                strategy = "recover_pool"
                # Avoid retaining exported private key in local dict longer than needed.
                reusable.clear()

            # Prefer local account email as display name
            if account_name and account_name != "unknown":
                identity = auth_json.get("agent_identity")
                if isinstance(identity, dict) and not identity.get("email"):
                    identity["email"] = account_name
            identity = auth_json.get("agent_identity") if isinstance(auth_json, dict) else None
            if isinstance(identity, dict):
                _ai_user_log(
                    account_name,
                    "auth.json",
                    (
                        f"strategy={strategy} "
                        f"runtime={str(identity.get('agent_runtime_id') or '')[:20]} "
                        f"task={str(identity.get('task_id') or '')[:20]} "
                        f"account_id={str(identity.get('account_id') or '')[:12]}"
                    ),
                )
                logger.info(
                    "Agent Identity auth ready name=%s strategy=%s runtime=%s task=%s account_id=%s",
                    account_name,
                    strategy,
                    str(identity.get("agent_runtime_id") or "")[:24],
                    str(identity.get("task_id") or "")[:24],
                    str(identity.get("account_id") or "")[:24],
                )
            _ai_user_log(account_name, "import", "POST /import/codex-session")
            ok, msg = self._import_codex_session(auth_json, settings, account_name=account_name)
            if not ok:
                _ai_user_log(account_name, "import", f"fail ({msg})")
            if ok:
                _ai_user_log(account_name, "import", f"ok strategy={strategy} ({msg})")
                # Enrich local token_data so inventory can display full Agent Identity credential.
                token_data["auth_mode"] = "agentIdentity"
                token_data["status"] = "agent_identity"
                token_data["credential_type"] = "codex_agent_identity"
                token_data["agent_identity_strategy"] = strategy
                if isinstance(identity, dict):
                    token_data["agent_identity"] = identity
                # Drop bootstrap bearer after successful conversion (matches codex-agent-identity flow).
                token_data.pop("access_token", None)
                token_data.pop("id_token", None)
                token_data.pop("accessToken", None)
                token_data.pop("idToken", None)
                self._force_bind_groups(account_name, group_ids)
                if strategy == "recover_pool" and "recover" not in str(msg).lower():
                    msg = f"{msg}; strategy=recover_pool"
            return ok, msg
        except AgentIdentityError as exc:
            _ai_user_log(account_name, "error", str(exc))
            logger.warning("Agent Identity register/push fail name=%s err=%s", account_name, exc)
            return False, f"Agent Identity 注册失败: {exc}"
        except Exception as exc:
            _ai_user_log(account_name, "error", str(exc))
            logger.exception("Agent Identity push failed for %s", account_name)
            return False, f"Agent Identity 推送异常: {exc}"

    def _proxy_signature(proxy_obj: Dict[str, Any]) -> Tuple[str, str, int, str, str]:
        return (
            str(proxy_obj.get("protocol", "")).strip().lower(),
            str(proxy_obj.get("host", "")).strip().lower(),
            int(proxy_obj.get("port", 0)),
            str(proxy_obj.get("username", "")),
            str(proxy_obj.get("password", "")),
        )

    def _ensure_sub2api_proxy(self, proxy_obj: Optional[Dict[str, Any]]) -> Optional[int]:
        if not proxy_obj or not proxy_obj.get("proxy_key"):
            return None

        proxy_key = str(proxy_obj["proxy_key"])
        with self._sub2api_proxy_ids_lock:
            cached_id = self._sub2api_proxy_ids.get(proxy_key)
        if cached_id is not None:
            return cached_id

        try:
            signature = self._proxy_signature(proxy_obj)
        except (TypeError, ValueError):
            logger.warning("Invalid Sub2API proxy definition: %s", proxy_key)
            return None

        list_url = f"{self.api_url}/api/v1/admin/proxies/all"
        try:
            response = cffi_requests.get(
                list_url,
                headers=self.headers,
                **self.request_kwargs,
            )
            ok, result = self._handle_response(response)
            if ok and isinstance(result, dict):
                proxy_items = result.get("data", [])
                if isinstance(proxy_items, list):
                    for item in proxy_items:
                        if not isinstance(item, dict):
                            continue
                        try:
                            item_signature = self._proxy_signature(item)
                            item_id = int(item.get("id", 0))
                        except (TypeError, ValueError):
                            continue
                        if item_id > 0 and item_signature == signature:
                            with self._sub2api_proxy_ids_lock:
                                self._sub2api_proxy_ids[proxy_key] = item_id
                            return item_id
            elif not ok:
                logger.warning("Failed to list Sub2API proxies: %s", result)
        except Exception as exc:
            logger.warning("Failed to resolve Sub2API proxy %s: %s", proxy_key, exc)
            return None

        create_url = f"{self.api_url}/api/v1/admin/proxies"
        create_payload = {
            "name": proxy_obj.get("name") or "openai-cpa",
            "protocol": proxy_obj.get("protocol"),
            "host": proxy_obj.get("host"),
            "port": proxy_obj.get("port"),
            "username": proxy_obj.get("username", ""),
            "password": proxy_obj.get("password", ""),
        }
        try:
            response = cffi_requests.post(
                create_url,
                json=create_payload,
                headers=self.headers,
                timeout=30,
                impersonate="chrome110",
            )
            ok, result = self._handle_response(response, success_codes=(200, 201))
            if not ok:
                logger.warning("Failed to create Sub2API proxy %s: %s", proxy_key, result)
                return None

            created = result.get("data", {}) if isinstance(result, dict) else {}
            proxy_id = int(created.get("id", 0)) if isinstance(created, dict) else 0
            if proxy_id <= 0:
                logger.warning("Sub2API proxy creation returned no usable ID: %s", proxy_key)
                return None

            with self._sub2api_proxy_ids_lock:
                self._sub2api_proxy_ids[proxy_key] = proxy_id
            return proxy_id
        except (TypeError, ValueError):
            logger.warning("Sub2API proxy creation returned an invalid ID: %s", proxy_key)
            return None
        except Exception as exc:
            logger.warning("Failed to create Sub2API proxy %s: %s", proxy_key, exc)
            return None

    def _import_grok_oauth(self, token_data: Dict[str, Any], settings: Dict[str, Any]) -> Tuple[bool, str]:
        """Push the OAuth result to Sub2API; raw SSO is handled by Grok2API."""
        url = f"{self.api_url}/api/v1/admin/accounts"

        access = str(token_data.get("access_token") or "").strip()
        refresh = str(token_data.get("refresh_token") or "").strip()
        if not access or not refresh:
            return False, "Grok OAuth 推送失败：缺少 access_token/refresh_token"

        email = str(token_data.get("email") or "unknown").strip() or "unknown"
        name = email[:64]

        proxy_obj = token_data.get("sub2api_proxy")
        proxy_id = None
        if proxy_obj:
            proxy_id = self._ensure_sub2api_proxy(proxy_obj)
            if proxy_id is None:
                return False, "Grok 账号代理同步失败：无法获取 Sub2API proxy_id"

        expires_in = token_data.get("expires_in", 21600)
        try:
            expires_in = int(expires_in)
        except (TypeError, ValueError):
            expires_in = 21600

        expires_at = token_data.get("expires_at")
        if expires_at in (None, ""):
            expires_at = int(time.time()) + expires_in
        else:
            try:
                expires_at = int(expires_at)
            except (TypeError, ValueError):
                expires_at = int(time.time()) + expires_in

        credentials: Dict[str, Any] = {
            "access_token": access,
            "refresh_token": refresh,
            "token_type": str(token_data.get("token_type") or "Bearer"),
            "email": email,
            "expires_in": expires_in,
            "expires_at": expires_at,
        }
        id_token = str(token_data.get("id_token") or "").strip()
        if id_token:
            credentials["id_token"] = id_token
        base_url = str(token_data.get("base_url") or "").strip()
        if base_url:
            credentials["base_url"] = base_url
        token_endpoint = str(token_data.get("token_endpoint") or "").strip()
        if token_endpoint:
            credentials["token_endpoint"] = token_endpoint
        client_id = str(token_data.get("client_id") or "").strip()
        if client_id:
            credentials["client_id"] = client_id
        scope = str(token_data.get("scope") or "").strip()
        if scope:
            credentials["scope"] = scope
        sub = str(token_data.get("sub") or "").strip()
        if sub:
            credentials["sub"] = sub

        payload: Dict[str, Any] = {
            "name": name,
            "platform": "grok",
            "type": "oauth",
            "credentials": credentials,
            "extra": {
                "email": email,
                "source": "openai-cpa",
            },
            "concurrency": settings["concurrency"],
            "priority": settings["priority"],
            "rate_multiplier": settings["rate_multiplier"],
            "auto_pause_on_expired": True,
        }
        group_ids = settings.get("group_ids") or []
        if group_ids:
            payload["group_ids"] = group_ids
        if proxy_id is not None:
            payload["proxy_id"] = proxy_id

        try:
            headers = self.headers.copy()
            headers["Idempotency-Key"] = f"grok-{uuid.uuid4()}"
            response = cffi_requests.post(
                url,
                json=payload,
                headers=headers,
                timeout=30,
                impersonate="chrome110",
                proxies=None,
            )
            ok, result = self._handle_response(response, success_codes=(200, 201))
            if ok:
                return True, "Sub2API Grok 账号导入成功"
            return False, f"Grok 推送失败: {result}"
        except Exception as exc:
            return False, f"Grok 网络上传请求失败: {exc}"

    def add_account(self, token_data: Dict[str, Any]) -> Tuple[bool, str]:
        with _SUB2API_PUSH_SEM:
            settings = self._get_push_settings()
            working_token_data = dict(token_data)
            account_name = str(working_token_data.get("email") or "unknown")[:64]
            group_ids = settings.get("group_ids") or []
            push_format = settings.get("push_format") or "oauth"

            # Grok/xAI path: SSO -> optional Grok2API, then OAuth -> Sub2API.
            is_grok = (
                "sso" in working_token_data
                or str(working_token_data.get("provider", "") or "").lower() == "grok"
                or str(working_token_data.get("status", "") or "").lower().startswith("grok")
                or (
                    not working_token_data.get("access_token")
                    and not working_token_data.get("refresh_token")
                    and str(getattr(cfg, "REG_PROVIDER", "openai") or "").lower() == "grok"
                )
            )
            if is_grok:
                ok, msg = self._import_grok_oauth(working_token_data, settings)
                if ok:
                    self._force_bind_groups(account_name, group_ids)
                return ok, msg

            # Token payload already declares Agent Identity bootstrap (reg Path B).
            # Force Path B even if UI/config push_format was left on oauth by mistake.
            auth_source = str(working_token_data.get("auth_source") or "").strip()
            status = str(working_token_data.get("status") or "").strip()
            is_ai_session_payload = (
                auth_source == "agent_identity_session"
                or status in {"agent_identity_pending", "agent_identity"}
                or str(working_token_data.get("auth_mode") or "") == "agentIdentity"
                or isinstance(working_token_data.get("agent_identity"), dict)
            )
            if is_ai_session_payload and push_format != "agent_identity":
                logger.warning(
                    "token is Agent Identity session payload but push_format=%s; forcing agent_identity",
                    push_format,
                )
                push_format = "agent_identity"
                settings = dict(settings)
                settings["push_format"] = "agent_identity"

            # Path B: Agent Identity (access_token bootstrap only, no refresh_token required)
            if push_format == "agent_identity":
                _ai_user_log(
                    account_name,
                    "push",
                    (
                        f"Path B 开始 groups={group_ids or []} "
                        f"runtime_recovery={bool(settings.get('agent_identity_runtime_recovery'))} "
                        f"cross_account={bool(settings.get('agent_identity_recovery_cross_account'))} "
                        f"fallback_oauth={bool(settings.get('agent_identity_fallback_oauth'))}"
                    ),
                )
                ok, msg = self._add_account_agent_identity(working_token_data, settings)
                if ok:
                    # Promote enriched credential fields back to caller token_data.
                    for key in (
                        "auth_mode",
                        "status",
                        "credential_type",
                        "agent_identity",
                        "agent_identity_strategy",
                        "access_token",
                        "id_token",
                        "accessToken",
                        "idToken",
                    ):
                        if key in working_token_data:
                            token_data[key] = working_token_data[key]
                        elif key in ("access_token", "id_token", "accessToken", "idToken"):
                            token_data.pop(key, None)
                    # Make success text unmistakable vs OAuth data-import path.
                    if "agent-identity" not in str(msg).lower() and "agent identity" not in str(msg).lower():
                        msg = f"Sub2API agent-identity import ok: {msg}; groups={group_ids or []}"
                    else:
                        msg = f"{msg}; groups={group_ids or []}"
                    return ok, msg

                # CRITICAL: never fall back to OAuth using a session JWT without refresh_token.
                # That creates type=oauth accounts with empty refresh_token (unusable) and looks
                # like "import succeeded" while Sub2API UI shows broken OAuth rows.
                has_refresh = bool(str(working_token_data.get("refresh_token") or "").strip())
                if settings.get("agent_identity_fallback_oauth") and has_refresh:
                    _ai_user_log(
                        account_name,
                        "fallback",
                        f"Agent Identity 失败，因有 refresh_token 回退 OAuth: {msg}",
                    )
                    logger.warning(
                        "Agent Identity push failed for %s, fallback to OAuth path: %s",
                        account_name,
                        msg,
                    )
                else:
                    if "agent_registry_not_enabled" in str(msg):
                        working_token_data["status"] = "agent_identity_unsupported"
                        working_token_data["agent_identity_error_code"] = "agent_registry_not_enabled"
                        working_token_data["agent_identity_error"] = str(msg)
                        token_data.update(working_token_data)
                        msg = (
                            "Agent Identity 不可用：该账号未开启 Agent Registry/Codex；"
                            "不是代理或 URL 问题。可换支持 Codex 的账号，或改用 OAuth 推送。"
                        )
                        _ai_user_log(account_name, "unsupported", msg)
                    elif settings.get("agent_identity_fallback_oauth") and not has_refresh:
                        msg = (
                            f"Agent Identity 失败且无 refresh_token，拒绝 OAuth 回退"
                            f"（否则会导入不可用 OAuth 账号）: {msg}"
                        )
                        _ai_user_log(account_name, "error", msg)
                    return False, msg

            # Path A: classic OAuth (access_token + refresh_token / data import)
            refresh_token = working_token_data.get("refresh_token", "")
            # Final hard guard: never treat AI session bearer as OAuth credentials.
            if is_ai_session_payload and not str(refresh_token or "").strip():
                return False, (
                    "拒绝把 Agent Identity 会话 access_token 当 OAuth 导入；"
                    "请保持 push_format=agent_identity 并检查 Agent Identity 注册/import 错误"
                )
            proxy_obj = working_token_data.get("sub2api_proxy")
            if proxy_obj is None:
                proxy_obj = parse_sub2api_proxy(cfg.get_next_sub2api_proxy_url())
                if proxy_obj:
                    working_token_data["sub2api_proxy"] = proxy_obj

            if not refresh_token or proxy_obj:
                ok, msg = self._import_account(working_token_data, settings)
                if ok:
                    self._force_bind_groups(account_name, group_ids)
                return ok, msg

            url = f"{self.api_url}/api/v1/admin/accounts"
            payload = {
                "name": account_name,
                "platform": "openai",
                "type": "oauth",
                "credentials": {
                    "refresh_token": refresh_token,
                    "model_mapping": {
                        "gpt-5.4": "gpt-5.4",
                        "gpt-5.4-mini": "gpt-5.4-mini",
                        "gpt-5.5": "gpt-5.5",
                        "gpt-5.6-sol": "gpt-5.6-sol",
                        "gpt-5.6-terra": "gpt-5.6-terra",
                        "gpt-5.6-luna": "gpt-5.6-luna",
                    }
                },
                "concurrency": settings["concurrency"],
                "priority": settings["priority"],
                "rate_multiplier": settings["rate_multiplier"],
                "extra": self._build_account_extra(settings),
            }
            if proxy_obj and "proxy_key" in proxy_obj:
                payload["proxy_key"] = proxy_obj["proxy_key"]

            if settings["group_ids"]:
                payload["group_ids"] = settings["group_ids"]

            try:
                response = cffi_requests.post(
                    url,
                    json=payload,
                    headers=self.headers,
                    **self._request_kwargs(timeout=60),
                )
                ok, result = self._handle_response(response, success_codes=(200, 201))
                if not ok:
                    import_ok, import_msg = self._import_account(working_token_data, settings)
                    if import_ok:
                        self._force_bind_groups(account_name, group_ids)
                    return import_ok, import_msg
                account_id = result.get("data", {}).get("id") if isinstance(result, dict) else None
                if account_id:
                    self._refresh_created_account(str(account_id))
                return True, "Sub2API account created successfully"
            except Exception as exc:
                import_ok, import_msg = self._import_account(working_token_data, settings)
                if import_ok:
                    self._force_bind_groups(account_name, group_ids)
                return import_ok, import_msg

    def _force_bind_groups(self, account_name: str, group_ids: List[int]) -> None:
        """Best-effort group bind after create/import. Scans a few pages by name."""
        if not group_ids and not account_name:
            return
        try:
            group_ids = self._sanitize_group_ids(group_ids or [])
            matched = None
            for page in range(1, 6):
                fetch_ok, accounts_resp = self.get_accounts(page=page, page_size=100)
                if not fetch_ok:
                    break
                items = []
                if isinstance(accounts_resp, dict):
                    data = accounts_resp.get("data", accounts_resp)
                    if isinstance(data, dict):
                        items = data.get("items") or data.get("accounts") or []
                    elif isinstance(data, list):
                        items = data
                for item in items if isinstance(items, list) else []:
                    if not isinstance(item, dict):
                        continue
                    if str(item.get("name") or "") == account_name:
                        matched = item
                        break
                if matched is not None:
                    break

            if matched is None:
                logger.warning("force bind groups: account not found name=%s groups=%s", account_name, group_ids)
                return

            target_id = str(matched.get("id") or "")
            if not target_id:
                return
            if group_ids:
                ok, result = self.update_account(target_id, {"group_ids": list(group_ids)})
                if ok:
                    logger.info("账号 %s 分组强制绑定成功: %s", account_name, group_ids)
                    _ai_user_log(account_name, "groups", f"bound {group_ids}")
                else:
                    logger.warning("账号 %s 分组绑定失败: %s", account_name, result)
                    _ai_user_log(account_name, "groups", f"bind fail: {result}")
            self._refresh_created_account(target_id)
        except Exception as exc:
            logger.error("推送后执行强制补丁(绑组+刷新)异常: %s", exc)

    def update_account(self, account_id: str, update_data: Dict[str, Any]) -> Tuple[bool, Any]:
        url = f"{self.api_url}/api/v1/admin/accounts/{account_id}"
        try:
            response = cffi_requests.put(url, json=update_data, headers=self.headers, **self._request_kwargs())
            return self._handle_response(response)
        except Exception as exc:
            logger.error("Update Sub2API account %s failed: %s", account_id, exc)
            return False, str(exc)

    def set_account_status(self, account_id: str, disabled: bool) -> bool:
        url = f"{self.api_url}/api/v1/admin/accounts/{account_id}"

        status_val = "inactive" if disabled else "active"
        payload = {"status": status_val}

        try:
            response = cffi_requests.patch(url, json=payload, headers=self.headers, **self._request_kwargs())
            if response.status_code in (200, 201, 204):
                return True

            response = cffi_requests.put(url, json=payload, headers=self.headers, **self._request_kwargs())
            return response.status_code in (200, 201, 204)
        except Exception as exc:
            logger.error("Set Sub2API account %s status failed: %s", account_id, exc)
            return False

    def delete_account(self, account_id: str) -> Tuple[bool, Any]:
        url = f"{self.api_url}/api/v1/admin/accounts/{account_id}"
        try:
            response = cffi_requests.delete(url, headers=self.headers, **self._request_kwargs())
            return self._handle_response(response, success_codes=(200, 204))
        except Exception as exc:
            logger.error(f"删除账号 {account_id} 失败: {exc}")
            return False, str(exc)

    def refresh_account(self, account_id: str) -> Tuple[bool, Any]:
        url = f"{self.api_url}/api/v1/admin/accounts/{account_id}/refresh"
        try:
            response = cffi_requests.post(url, headers=self.headers, json={}, **self._request_kwargs())
            return self._handle_response(response)
        except Exception as exc:

            logger.error(f"刷新账号 {account_id} 失败: {exc}")
            return False, str(exc)

    def test_account(self, account_id: int, model_id: str = None) -> Tuple[str, str]:
        url = f"{self.api_url}/api/v1/admin/accounts/{account_id}/test"
        use_model = str(model_id or getattr(cfg, "SUB2API_TEST_MODEL", "") or "gpt-5.4-mini").strip()
        try:
            response = cffi_requests.post(
                url,
                headers=self.headers,
                json={"model_id": use_model},
                **self._request_kwargs(timeout=60),
            )
            if response.status_code != 200:
                logger.warning("Sub2API test_account %s returned HTTP %s; keep current state", account_id, response.status_code)
                return "ok", f"HTTP {response.status_code}, skipped"

            for line in response.text.splitlines():
                line = line.strip()
                if not line.startswith("data:"):
                    continue

                raw = line[5:].strip()
                if not raw or raw == "[DONE]":
                    continue

                try:
                    event = json.loads(raw)
                except Exception:
                    continue

                event_type = event.get("type", "")
                if event_type == "test_complete":
                    if event.get("success"):
                        return "ok", "test completed"
                    err = str(event.get("error") or event.get("text") or "")
                    return _classify_sse_error(err)

                if event_type == "error":
                    err = str(event.get("error") or event.get("text") or "")
                    return _classify_sse_error(err)

            logger.warning("Sub2API test_account %s did not emit a terminal SSE event; keep current state", account_id)
            return "ok", "no terminal SSE event, skipped"
        except Exception as exc:
            logger.warning("Sub2API test_account %s failed: %s", account_id, exc)
            return "ok", f"test error, skipped: {str(exc)}"

    def test_connection(self) -> Tuple[bool, str]:
        url = f"{self.api_url}/api/v1/admin/accounts/data"
        try:
            kwargs = self._request_kwargs()
            kwargs["timeout"] = 10
            response = cffi_requests.get(url, headers=self.headers, **kwargs)

            if response.status_code in (200, 201, 204, 405):
                return True, "Sub2API connection test succeeded. The API key is valid."
            if response.status_code == 401:
                return False, "Connected, but the API key is invalid (401 Unauthorized)."
            if response.status_code == 403:
                return False, "Connected, but the API key does not have enough permission (403 Forbidden)."
            return False, f"Unexpected server status code: {response.status_code}"
        except cffi_requests.exceptions.ConnectionError as exc:
            return False, f"Could not connect to the Sub2API server: {exc}"
        except cffi_requests.exceptions.Timeout:
            return False, "连接超时，请检查网络配置或服务器状态"
        except Exception as exc:
            return False, f"连接测试失败: {str(exc)}"

def _classify_sse_error(err_text: str) -> Tuple[str, str]:
    text = err_text.lower()
    if any(keyword in text for keyword in ("429", "rate_limit", "rate limit", "too many request")):
        return "quota", f"quota limited: {err_text[:120]}"
    if err_text.strip():
        return "dead", f"test failed: {err_text[:120]}"
    return "ok", "empty SSE error, skipped"
