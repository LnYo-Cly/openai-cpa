import json
import logging
from typing import Dict, Any, List, Tuple
from utils import config as cfg

logger = logging.getLogger(__name__)


class NewAPIClient:
    """NewAPI 渠道管理客户端 — 支持 single（一账号一渠道）和 multi（多Key合并）两种模式"""

    CODEX_CHANNEL_TYPE = 57
    CODEX_BASE_URL = "https://chatgpt.com"
    CODEX_MODELS_API = "https://chatgpt.com/backend-api/codex/models"
    DEFAULT_CHANNEL_NAME = "cpa-codex-pool"

    def __init__(self):
        self.api_url = getattr(cfg, "NEWAPI_URL", "").rstrip("/")
        self.api_token = getattr(cfg, "NEWAPI_TOKEN", "")
        self.user_id = str(getattr(cfg, "NEWAPI_USER_ID", "1"))
        self.models = getattr(cfg, "NEWAPI_MODELS", "")
        self.group = getattr(cfg, "NEWAPI_GROUP", "default")
        self.channel_name = getattr(cfg, "NEWAPI_CHANNEL_NAME", self.DEFAULT_CHANNEL_NAME)
        self.proxy = getattr(cfg, "NEWAPI_PROXY", "") or getattr(cfg, "DEFAULT_PROXY", "")

    def _build_headers(self) -> dict:
        return {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_token}",
            "New-Api-User": self.user_id,
        }

    def _build_channel_setting(self) -> str:
        """构建渠道 setting JSON（包含代理等配置）"""
        if not self.proxy:
            return ""
        return json.dumps({"proxy": self.proxy}, ensure_ascii=False)

    def _build_codex_key(self, token_data: dict) -> str:
        key_obj = {
            "access_token": token_data.get("access_token", ""),
            "refresh_token": token_data.get("refresh_token", ""),
            "account_id": token_data.get("account_id", ""),
            "last_refresh": token_data.get("last_refresh", ""),
            "email": token_data.get("email", ""),
            "type": token_data.get("type", "codex"),
            "expired": token_data.get("expired", ""),
        }
        return json.dumps(key_obj, ensure_ascii=False)

    def _resolve_models(self, token_data: dict) -> str:
        """获取 models：配置优先，否则动态获取"""
        models = self.models
        if not models:
            models = self._fetch_account_models(
                token_data.get("access_token", ""),
                token_data.get("account_id", ""),
            )
        return models

    def _fetch_account_models(self, access_token: str, account_id: str) -> str:
        """从 ChatGPT 动态获取该账号可用的 Codex 模型列表"""
        try:
            from curl_cffi import requests as cffi_requests
            req_kwargs = {
                "timeout": 15,
                "impersonate": "chrome120",
                "verify": False,
            }
            if self.proxy:
                req_kwargs["proxies"] = {"http": self.proxy, "https": self.proxy}
            resp = cffi_requests.get(
                self.CODEX_MODELS_API,
                headers={
                    "Authorization": f"Bearer {access_token}",
                    "chatgpt-account-id": account_id,
                    "Accept": "application/json",
                },
                **req_kwargs,
            )
            if resp.status_code != 200:
                logger.warning(f"获取 Codex 模型列表失败: HTTP {resp.status_code}")
                return ""
            data = resp.json()
            model_list = data if isinstance(data, list) else data.get("models", data.get("data", []))
            slugs = []
            for m in model_list:
                if isinstance(m, dict):
                    slug = m.get("slug") or m.get("id") or m.get("name", "")
                    if slug:
                        slugs.append(slug)
                elif isinstance(m, str):
                    slugs.append(m)
            if slugs:
                models_str = ",".join(slugs)
                logger.info(f"获取到 {len(slugs)} 个 Codex 模型: {models_str[:100]}...")
                return models_str
            logger.warning(f"Codex 模型列表解析为空: {str(data)[:200]}")
            return ""
        except Exception as e:
            logger.warning(f"获取 Codex 模型列表异常: {e}")
            return ""

    def _do_request(self, method: str, path: str, **kwargs) -> Tuple[bool, Any]:
        from curl_cffi import requests as cffi_requests
        fn = getattr(cffi_requests, method)
        resp = fn(
            f"{self.api_url}{path}",
            headers=self._build_headers(),
            timeout=30,
            impersonate="chrome110",
            verify=False,
            **kwargs,
        )
        if resp.status_code in (200, 201, 204):
            try:
                data = resp.json() if resp.text else {}
                return True, data
            except ValueError:
                return False, f"响应非 JSON: {resp.text[:200]}"
        error_msg = f"HTTP {resp.status_code}"
        try:
            detail = resp.json()
            if isinstance(detail, dict):
                error_msg = detail.get("message", error_msg)
        except Exception:
            error_msg = f"{error_msg} - {resp.text[:200]}"
        return False, error_msg

    # ── 分组列表 ──────────────────────────────────────

    def fetch_groups(self) -> Tuple[bool, Any]:
        """从 NewAPI 获取所有可用分组列表"""
        if not self.api_url or not self.api_token:
            return False, "NewAPI 配置缺失"
        try:
            ok, data = self._do_request("get", "/api/group/")
            if not ok:
                return False, data
            groups = data.get("data", []) if isinstance(data, dict) else data
            return True, groups
        except Exception as exc:
            return False, f"获取分组列表失败: {exc}"

    # ── 渠道列表 ──────────────────────────────────────

    def list_codex_channels(self) -> Tuple[bool, Any]:
        """获取所有 Codex 渠道列表"""
        if not self.api_url or not self.api_token:
            return False, "NewAPI 配置缺失"
        try:
            ok, data = self._do_request("get", "/api/channel/")
            if not ok:
                return False, data
            if not isinstance(data, (dict, list)):
                return False, f"响应格式异常: {type(data).__name__}"
            channels = data if isinstance(data, list) else data.get("data", [])
            result = []
            for ch in channels:
                if ch.get("type") != self.CODEX_CHANNEL_TYPE:
                    continue
                key_str = ch.get("key", "")
                key_count = len(key_str.strip().split("\n")) if key_str else 0
                result.append({
                    "id": ch.get("id"),
                    "name": ch.get("name", ""),
                    "models": ch.get("models", ""),
                    "status": ch.get("status", 1),
                    "key_count": key_count,
                    "group": ch.get("group", "default"),
                })
            return True, result
        except Exception as exc:
            return False, f"获取渠道列表失败: {exc}"

    # ── single 模式：一账号一渠道 ─────────────────────

    def add_account_single(self, token_data: dict) -> Tuple[bool, str]:
        """为单个账号创建独立的 Codex 渠道"""
        if not self.api_url or not self.api_token:
            return False, "NewAPI 配置缺失"
        access_token = token_data.get("access_token", "")
        account_id = token_data.get("account_id", "")
        if not access_token or not account_id:
            return False, "token_data 缺少 access_token 或 account_id"

        email = token_data.get("email", "unknown")
        models = self._resolve_models(token_data)
        if not models:
            return False, "无法获取可用模型列表，请在配置中手动指定 models"

        try:
            ok, result = self._do_request("post", "/api/channel/", json={
                "mode": "single",
                "channel": {
                    "type": self.CODEX_CHANNEL_TYPE,
                    "key": self._build_codex_key(token_data),
                    "name": email,
                    "base_url": "",
                    "models": models,
                    "group": self.group,
                    "status": 1,
                    "setting": self._build_channel_setting(),
                },
            })
            if ok:
                logger.info(f"NewAPI 独立渠道创建成功: {email}")
                return True, "渠道创建成功"
            return False, str(result)
        except Exception as exc:
            return False, f"网络请求失败: {exc}"

    # ── multi 模式：追加 Key 到指定渠道 ───────────────

    def add_key_to_channel(self, channel_id: int, token_data: dict) -> Tuple[bool, str]:
        """追加 key 到指定渠道（使用 key_mode: append，服务端自动合并）"""
        if not self.api_url or not self.api_token:
            return False, "NewAPI 配置缺失"
        access_token = token_data.get("access_token", "")
        account_id = token_data.get("account_id", "")
        if not access_token or not account_id:
            return False, "token_data 缺少 access_token 或 account_id"

        email = token_data.get("email", "unknown")
        new_key = self._build_codex_key(token_data)

        try:
            ok, result = self._do_request("put", "/api/channel/", json={
                "id": channel_id,
                "type": self.CODEX_CHANNEL_TYPE,
                "key": new_key,
                "key_mode": "append",
                "name": "",
                "base_url": self.CODEX_BASE_URL,
                "models": "",
                "group": self.group,
                "status": 1,
                "setting": self._build_channel_setting(),
            })
            if ok:
                logger.info(f"NewAPI 追加 Key 到渠道 {channel_id}: {email}")
                return True, "追加成功"
            return False, str(result)
        except Exception as exc:
            return False, f"追加渠道 Key 失败: {exc}"

    # ── multi 模式：追加到默认渠道（自动创建） ─────────

    def add_account_multi(self, token_data: dict) -> Tuple[bool, str]:
        """追加 key 到默认渠道（不存在则创建）"""
        if not self.api_url or not self.api_token:
            return False, "NewAPI 配置缺失"
        access_token = token_data.get("access_token", "")
        account_id = token_data.get("account_id", "")
        if not access_token or not account_id:
            return False, "token_data 缺少 access_token 或 account_id"

        email = token_data.get("email", "unknown")
        new_key = self._build_codex_key(token_data)
        models = self._resolve_models(token_data)
        if not models:
            return False, "无法获取可用模型列表，请在配置中手动指定 models"

        # 查找已有默认渠道
        try:
            ok, data = self._do_request("get", "/api/channel/")
            existing = None
            if ok:
                channels = data if isinstance(data, list) else data.get("data", [])
                for ch in channels:
                    if ch.get("name") == self.channel_name and ch.get("type") == self.CODEX_CHANNEL_TYPE:
                        existing = ch
                        break
        except Exception:
            existing = None

        if existing:
            old_keys = existing.get("key", "")
            merged_keys = old_keys + "\n" + new_key if old_keys else new_key
            old_models = set(existing.get("models", "").split(",")) if existing.get("models") else set()
            new_models = set(models.split(","))
            merged_models = ",".join(sorted(old_models | new_models))
            try:
                ok, result = self._do_request("put", "/api/channel/", json={
                    "id": existing["id"],
                    "type": self.CODEX_CHANNEL_TYPE,
                    "key": merged_keys,
                    "name": self.channel_name,
                    "base_url": self.CODEX_BASE_URL,
                    "models": merged_models,
                    "group": self.group,
                    "status": 1,
                    "setting": existing.get("setting", "") or self._build_channel_setting(),
                })
                if ok:
                    key_count = len(merged_keys.strip().split("\n"))
                    logger.info(f"NewAPI 追加 Key 成功: {email} (渠道共 {key_count} 个Key)")
                    return True, f"Key 追加成功 (共 {key_count} 个)"
                return False, str(result)
            except Exception as exc:
                return False, f"更新渠道失败: {exc}"
        else:
            try:
                ok, result = self._do_request("post", "/api/channel/", json={
                    "mode": "multi_to_single",
                    "multi_key_mode": "random",
                    "channel": {
                        "type": self.CODEX_CHANNEL_TYPE,
                        "key": new_key,
                        "name": self.channel_name,
                        "base_url": "",
                        "models": models,
                        "group": self.group,
                        "status": 1,
                        "setting": self._build_channel_setting(),
                    },
                })
                if ok:
                    logger.info(f"NewAPI 渠道创建成功: {self.channel_name}, 首个 Key: {email}")
                    return True, "渠道创建成功"
                return False, str(result)
            except Exception as exc:
                return False, f"网络请求失败: {exc}"

    def delete_channel(self, channel_id: int) -> Tuple[bool, str]:
        if not self.api_url or not self.api_token:
            return False, "NewAPI 配置缺失"
        try:
            ok, result = self._do_request("delete", f"/api/channel/{channel_id}")
            if ok:
                return True, "渠道删除成功"
            return False, str(result)
        except Exception as exc:
            return False, f"网络请求失败: {exc}"
