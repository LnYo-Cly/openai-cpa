import json
import logging
from typing import Dict, Any, Tuple
from utils import config as cfg

logger = logging.getLogger(__name__)


class NewAPIClient:
    """NewAPI 渠道管理客户端 — 将注册账号推送为 Codex (type=57) 渠道"""

    CODEX_CHANNEL_TYPE = 57
    CODEX_BASE_URL = "https://chatgpt.com"
    CODEX_MODELS_API = "https://chatgpt.com/backend-api/codex/models"

    def __init__(self):
        self.api_url = getattr(cfg, "NEWAPI_URL", "").rstrip("/")
        self.api_token = getattr(cfg, "NEWAPI_TOKEN", "")
        self.user_id = str(getattr(cfg, "NEWAPI_USER_ID", "1"))
        self.models = getattr(cfg, "NEWAPI_MODELS", "")  # 留空则自动获取
        self.group = getattr(cfg, "NEWAPI_GROUP", "default")

    def _build_headers(self) -> dict:
        return {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_token}",
            "New-Api-User": self.user_id,
        }

    def _build_codex_key(self, token_data: dict) -> str:
        """从 token_data 构建 Codex 渠道所需的 JSON key"""
        key_obj = {
            "access_token": token_data.get("access_token", ""),
            "account_id": token_data.get("account_id", ""),
            "refresh_token": token_data.get("refresh_token", ""),
            "email": token_data.get("email", ""),
            "type": token_data.get("type", "codex"),
            "expired": token_data.get("expired", ""),
        }
        return json.dumps(key_obj, ensure_ascii=False)

    def _fetch_account_models(self, access_token: str, account_id: str) -> str:
        """从 ChatGPT 动态获取该账号可用的 Codex 模型列表"""
        try:
            from curl_cffi import requests as cffi_requests
            resp = cffi_requests.get(
                self.CODEX_MODELS_API,
                headers={
                    "Authorization": f"Bearer {access_token}",
                    "chatgpt-account-id": account_id,
                    "Accept": "application/json",
                },
                timeout=15,
                impersonate="chrome120",
                verify=False,
            )
            if resp.status_code != 200:
                logger.warning(f"获取 Codex 模型列表失败: HTTP {resp.status_code}")
                return ""

            data = resp.json()
            # 响应可能是 {"models": [{"slug": "gpt-5.5", ...}]} 或直接是列表
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

    def add_account(self, token_data: dict) -> Tuple[bool, str]:
        """注册成功后调用：在 NewAPI 创建一个 Codex 渠道"""
        if not self.api_url or not self.api_token:
            return False, "NewAPI 配置缺失，请检查 api_url 和 api_token"

        access_token = token_data.get("access_token", "")
        account_id = token_data.get("account_id", "")
        if not access_token or not account_id:
            return False, "token_data 缺少 access_token 或 account_id"

        email = token_data.get("email", "unknown")
        channel_name = f"cpa-{email}"

        # 确定 models：优先用配置的，否则动态获取
        models = self.models
        if not models:
            models = self._fetch_account_models(access_token, account_id)
        if not models:
            return False, "无法获取可用模型列表，请在配置中手动指定 models"

        channel = {
            "type": self.CODEX_CHANNEL_TYPE,
            "key": self._build_codex_key(token_data),
            "name": channel_name,
            "base_url": self.CODEX_BASE_URL,
            "models": models,
            "group": self.group,
            "status": 1,
        }

        url = f"{self.api_url}/api/channel/"
        try:
            from curl_cffi import requests as cffi_requests
            response = cffi_requests.post(
                url,
                json=channel,
                headers=self._build_headers(),
                timeout=30,
                impersonate="chrome110",
                verify=False,
            )

            if response.status_code in (200, 201):
                logger.info(f"NewAPI 渠道创建成功: {email}")
                return True, "渠道创建成功"

            error_msg = f"HTTP {response.status_code}"
            try:
                detail = response.json()
                if isinstance(detail, dict):
                    error_msg = detail.get("message", error_msg)
            except Exception:
                error_msg = f"{error_msg} - {response.text[:200]}"

            logger.warning(f"NewAPI 渠道创建失败: {error_msg}")
            return False, str(error_msg)

        except Exception as exc:
            logger.error(f"NewAPI 网络请求失败: {exc}")
            return False, f"网络请求失败: {exc}"

    def delete_channel(self, channel_id: int) -> Tuple[bool, str]:
        """删除指定渠道"""
        if not self.api_url or not self.api_token:
            return False, "NewAPI 配置缺失"

        url = f"{self.api_url}/api/channel/{channel_id}"
        try:
            from curl_cffi import requests as cffi_requests
            response = cffi_requests.delete(
                url,
                headers=self._build_headers(),
                timeout=30,
                impersonate="chrome110",
                verify=False,
            )
            if response.status_code in (200, 204):
                return True, "渠道删除成功"
            return False, f"HTTP {response.status_code}"
        except Exception as exc:
            return False, f"网络请求失败: {exc}"
