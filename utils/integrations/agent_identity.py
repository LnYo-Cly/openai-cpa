"""Codex Agent Identity registration helpers for Sub2API push.

Minimal port of the standalone codex-agent-identity protocol used to convert a
one-time OpenAI/ChatGPT bearer token into auth_mode=agentIdentity auth.json.
"""

from __future__ import annotations

import base64
import json
import logging
import time
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from nacl.bindings import (
    crypto_box_seal_open,
    crypto_sign_ed25519_pk_to_curve25519,
    crypto_sign_ed25519_sk_to_curve25519,
    crypto_sign_seed_keypair,
)
from nacl.signing import SigningKey

logger = logging.getLogger(__name__)

CERTIFICATE_VERSION = 1
DEFAULT_AUTH_API_BASE_URL = "https://auth.openai.com/api/accounts"
DEFAULT_CODEX_BASE_URL = "https://chatgpt.com/backend-api/codex"
USER_AGENT = "openai-cpa-agent-identity/1"
ED25519_PKCS8_PREFIX = bytes.fromhex("302e020100300506032b657004220420")


class AgentIdentityError(RuntimeError):
    """Raised when agent identity registration or conversion fails."""


def b64url_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def decode_jwt_payload(jwt: str) -> Dict[str, Any]:
    parts = jwt.split(".")
    if len(parts) != 3 or not all(parts):
        raise AgentIdentityError("token 不是三段式 JWT")
    try:
        value = json.loads(b64url_decode(parts[1]))
    except (ValueError, json.JSONDecodeError) as exc:
        raise AgentIdentityError("token payload 无效") from exc
    if not isinstance(value, dict):
        raise AgentIdentityError("token payload 必须是对象")
    return value


def parse_id_token_identity(id_token: str) -> Dict[str, Any]:
    claims = decode_jwt_payload(id_token)
    auth = claims.get("https://api.openai.com/auth")
    if not isinstance(auth, dict):
        raise AgentIdentityError("token 缺少 OpenAI auth claims")
    account_id = auth.get("chatgpt_account_id")
    user_id = auth.get("chatgpt_user_id") or auth.get("user_id")
    if not isinstance(account_id, str) or not account_id:
        raise AgentIdentityError("token 缺少 chatgpt_account_id")
    if not isinstance(user_id, str) or not user_id:
        raise AgentIdentityError("token 缺少 chatgpt_user_id")
    email = claims.get("email")
    profile = claims.get("https://api.openai.com/profile")
    if not isinstance(email, str) and isinstance(profile, dict):
        email = profile.get("email")
    plan_type = auth.get("chatgpt_plan_type")
    return {
        "account_id": account_id,
        "chatgpt_user_id": user_id,
        "email": email if isinstance(email, str) else None,
        "plan_type": plan_type if isinstance(plan_type, str) else "unknown",
        "chatgpt_account_is_fedramp": bool(auth.get("chatgpt_account_is_fedramp", False)),
    }


def utc_timestamp() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def signing_key_pkcs8_base64(signing_key: SigningKey) -> str:
    private_key_der = ED25519_PKCS8_PREFIX + signing_key.encode()
    return base64.b64encode(private_key_der).decode("ascii")


def certificate_to_codex_auth_json(certificate: Dict[str, Any]) -> Dict[str, Any]:
    signing_key = SigningKey(base64.b64decode(certificate["private_key_seed"], validate=True))
    return {
        "auth_mode": "agentIdentity",
        "OPENAI_API_KEY": None,
        "tokens": None,
        "last_refresh": None,
        "agent_identity": {
            "agent_runtime_id": certificate["agent_runtime_id"],
            "agent_private_key": signing_key_pkcs8_base64(signing_key),
            "account_id": certificate["account_id"],
            "chatgpt_user_id": certificate["chatgpt_user_id"],
            "email": certificate.get("email"),
            "plan_type": certificate.get("plan_type") or "unknown",
            "chatgpt_account_is_fedramp": bool(certificate.get("chatgpt_account_is_fedramp", False)),
            "task_id": certificate["task_id"],
        },
        "personal_access_token": None,
        "bedrock_api_key": None,
    }


def ssh_ed25519_public_key(signing_key: SigningKey) -> str:
    algorithm = b"ssh-ed25519"
    public_key = signing_key.verify_key.encode()
    blob = (
        len(algorithm).to_bytes(4, "big")
        + algorithm
        + len(public_key).to_bytes(4, "big")
        + public_key
    )
    return "ssh-ed25519 " + base64.b64encode(blob).decode("ascii")


def sign_task_registration(signing_key: SigningKey, agent_runtime_id: str, timestamp: str) -> str:
    payload = f"{agent_runtime_id}:{timestamp}".encode("utf-8")
    return base64.b64encode(signing_key.sign(payload).signature).decode("ascii")


def decrypt_task_id(signing_key: SigningKey, encrypted_task_id: str) -> str:
    seed = signing_key.encode()
    ed_public_key, ed_secret_key = crypto_sign_seed_keypair(seed)
    curve_public_key = crypto_sign_ed25519_pk_to_curve25519(ed_public_key)
    curve_secret_key = crypto_sign_ed25519_sk_to_curve25519(ed_secret_key)
    try:
        ciphertext = base64.b64decode(encrypted_task_id, validate=True)
        plaintext = crypto_box_seal_open(ciphertext, curve_public_key, curve_secret_key)
        task_id = plaintext.decode("utf-8")
    except (ValueError, UnicodeDecodeError) as exc:
        raise AgentIdentityError("无法解密 task 注册响应") from exc
    if not task_id:
        raise AgentIdentityError("解密后的 task ID 为空")
    return task_id


def _normalize_proxies(proxies: Any) -> Optional[Dict[str, str]]:
    if not proxies:
        return None
    if isinstance(proxies, dict):
        http = str(proxies.get("http") or proxies.get("https") or "").strip()
        https = str(proxies.get("https") or proxies.get("http") or "").strip()
        if not http and not https:
            return None
        return {"http": http or https, "https": https or http}
    text = str(proxies).strip()
    if not text:
        return None
    return {"http": text, "https": text}


def _http_json(
    method: str,
    url: str,
    *,
    headers: Optional[Dict[str, str]] = None,
    json_body: Optional[Dict[str, Any]] = None,
    proxies: Any = None,
    timeout: int = 45,
) -> Dict[str, Any]:
    from curl_cffi import requests as cffi_requests

    request_headers = {"User-Agent": USER_AGENT, **(headers or {})}
    kwargs: Dict[str, Any] = {
        "headers": request_headers,
        "timeout": timeout,
        "impersonate": "chrome110",
    }
    proxy_map = _normalize_proxies(proxies)
    if proxy_map is not None:
        kwargs["proxies"] = proxy_map

    try:
        response = cffi_requests.request(method.upper(), url, json=json_body, **kwargs)
    except Exception as exc:
        raise AgentIdentityError(f"{method} {url} 网络失败：{exc}") from exc

    body_text = (response.text or "").strip()
    if response.status_code < 200 or response.status_code >= 300:
        detail = body_text[:1000]
        raise AgentIdentityError(f"{method} {url} 返回 HTTP {response.status_code}：{detail}")
    try:
        value = response.json() if body_text else {}
    except ValueError as exc:
        raise AgentIdentityError(f"{method} {url} 返回的内容不是 JSON") from exc
    if not isinstance(value, dict):
        raise AgentIdentityError(f"{method} {url} 返回的 JSON 不是对象")
    return value


def register_agent_identity_certificate(
    access_token: str,
    *,
    id_token: Optional[str] = None,
    email: Optional[str] = None,
    proxies: Any = None,
    auth_api_base_url: str = DEFAULT_AUTH_API_BASE_URL,
    codex_base_url: str = DEFAULT_CODEX_BASE_URL,
) -> Dict[str, Any]:
    """Register a new agent runtime and return the internal certificate dict."""
    token = str(access_token or "").strip()
    if not token:
        raise AgentIdentityError("缺少 access_token，无法注册 Agent Identity")

    claim_token = str(id_token or "").strip() or token
    identity = parse_id_token_identity(claim_token)
    if email and not identity.get("email"):
        identity["email"] = email

    signing_key = SigningKey.generate()
    registration_headers = {"Authorization": f"Bearer {token}"}
    if identity["chatgpt_account_is_fedramp"]:
        registration_headers["X-OpenAI-Fedramp"] = "true"

    base = auth_api_base_url.rstrip("/")
    registration = _http_json(
        "POST",
        f"{base}/v1/agent/register",
        headers=registration_headers,
        json_body={
            "abom": {
                "agent_version": "openai-cpa-1",
                "agent_harness_id": "codex-cli",
                "running_location": "openai-cpa",
            },
            "agent_public_key": ssh_ed25519_public_key(signing_key),
            "capabilities": ["responsesapi"],
            "ttl": None,
        },
        proxies=proxies,
    )
    runtime_id = registration.get("agent_runtime_id")
    if not isinstance(runtime_id, str) or not runtime_id:
        raise AgentIdentityError("Agent 注册响应缺少 agent_runtime_id")

    timestamp = utc_timestamp()
    task = _http_json(
        "POST",
        f"{base}/v1/agent/{runtime_id}/task/register",
        json_body={
            "timestamp": timestamp,
            "signature": sign_task_registration(signing_key, runtime_id, timestamp),
        },
        proxies=proxies,
    )
    task_id = task.get("task_id") or task.get("taskId")
    if not isinstance(task_id, str) or not task_id:
        encrypted = task.get("encrypted_task_id") or task.get("encryptedTaskId")
        if not isinstance(encrypted, str) or not encrypted:
            raise AgentIdentityError("task 注册响应缺少 task_id")
        task_id = decrypt_task_id(signing_key, encrypted)

    return {
        "version": CERTIFICATE_VERSION,
        "credential_type": "codex_agent_identity",
        "capabilities": ["responsesapi"],
        "created_at": utc_timestamp(),
        "agent_runtime_id": runtime_id,
        "private_key_seed": base64.b64encode(signing_key.encode()).decode("ascii"),
        "task_id": task_id,
        "account_id": identity["account_id"],
        "chatgpt_user_id": identity["chatgpt_user_id"],
        "email": identity.get("email") or email,
        "plan_type": identity["plan_type"],
        "chatgpt_account_is_fedramp": identity["chatgpt_account_is_fedramp"],
        "codex_base_url": codex_base_url.rstrip("/"),
        "auth_api_base_url": base,
    }


def create_agent_identity_auth_json(
    access_token: str,
    *,
    id_token: Optional[str] = None,
    email: Optional[str] = None,
    proxies: Any = None,
) -> Dict[str, Any]:
    """Create Codex-compatible auth.json (auth_mode=agentIdentity)."""
    certificate = register_agent_identity_certificate(
        access_token,
        id_token=id_token,
        email=email,
        proxies=proxies,
    )
    auth_json = certificate_to_codex_auth_json(certificate)
    # Prefer caller email when claims omit it.
    if email and isinstance(auth_json.get("agent_identity"), dict):
        auth_json["agent_identity"]["email"] = email
    return auth_json


def resolve_identity_bootstrap_tokens(token_data: Dict[str, Any]) -> Dict[str, str]:
    """Extract bootstrap access/id tokens from openai-cpa token_data."""
    access_token = str(
        token_data.get("access_token")
        or token_data.get("accessToken")
        or ""
    ).strip()
    id_token = str(
        token_data.get("id_token")
        or token_data.get("idToken")
        or ""
    ).strip()
    if not access_token and id_token:
        access_token = id_token
    if not id_token and access_token:
        # Session JWT / some OAuth access tokens already embed auth claims.
        id_token = access_token
    if not access_token:
        raise AgentIdentityError("token_data 缺少 access_token/id_token")
    return {"access_token": access_token, "id_token": id_token}
