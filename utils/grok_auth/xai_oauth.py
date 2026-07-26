# -*- coding: utf-8 -*-
"""Grok OAuth：SSO 走 device-flow，组装管仓 JSON。"""
from __future__ import annotations

import base64
import json
import time
from dataclasses import dataclass
from typing import Any, Dict, Optional

CLIPROXYAPI_GROK_BASE_URL = "https://cli-chat-proxy.grok.com/v1"
CLIPROXYAPI_GROK_HEADERS = {
    "X-XAI-Token-Auth": "xai-grok-cli",
    "x-grok-client-version": "0.2.93",
    "x-grok-client-identifier": "grok-shell",
}


def parse_jwt_payload(jwt_token: str) -> Optional[Dict[str, Any]]:
    try:
        parts = jwt_token.split(".")
        if len(parts) < 2:
            return None
        payload = parts[1] + "=" * (-len(parts[1]) % 4)
        return json.loads(base64.urlsafe_b64decode(payload))
    except Exception:
        return None


@dataclass
class OAuthLoginResult:
    token: Dict[str, Any]
    userinfo: Dict[str, Any]
    id_token_payload: Optional[Dict[str, Any]]
    path: Optional[Any] = None
    cliproxyapi_path: Optional[Any] = None
    redirect_uri: str = ""

    @property
    def access_token(self) -> str:
        return str(self.token.get("access_token") or "")

    @property
    def refresh_token(self) -> str:
        return str(self.token.get("refresh_token") or "")

    @property
    def email(self) -> str:
        return str(self.userinfo.get("email") or "")


def build_cliproxyapi_auth_record(
    token: Dict[str, Any],
    *,
    userinfo: Optional[Dict[str, Any]] = None,
    redirect_uri: str = "",
    disabled: bool = False,
    base_url: str = CLIPROXYAPI_GROK_BASE_URL,
    headers: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    id_payload = parse_jwt_payload(str(token.get("id_token") or "")) or {}
    email = ""
    if userinfo:
        email = str(userinfo.get("email") or "")
    if not email:
        email = str(id_payload.get("email") or "")
    expires_at = token.get("expires_at")
    if expires_at is None and token.get("expires_in") is not None:
        try:
            expires_at = int(time.time()) + int(token["expires_in"])
        except Exception:
            expires_at = None
    merged_headers = dict(CLIPROXYAPI_GROK_HEADERS)
    if headers:
        merged_headers.update({str(k): str(v) for k, v in headers.items()})
    return {
        "email": email,
        "access_token": str(token.get("access_token") or ""),
        "refresh_token": str(token.get("refresh_token") or ""),
        "id_token": str(token.get("id_token") or ""),
        "expires_in": token.get("expires_in"),
        "expires_at": expires_at,
        "token_type": str(token.get("token_type") or "Bearer"),
        "base_url": base_url,
        "headers": merged_headers,
        "disabled": bool(disabled),
        "redirect_uri": redirect_uri or "http://127.0.0.1:56121/callback",
        "type": "xai",
    }


def complete_build_oauth(
    email: str,
    password: str = "",
    *,
    proxy: str = "",
    session_cookies: Optional[Dict[str, Any]] = None,
    **_ignored,
) -> OAuthLoginResult:
    sso_cookie = ""
    try:
        sso_cookie = str((session_cookies or {}).get("sso") or "").strip()
    except Exception:
        sso_cookie = ""
    if not sso_cookie:
        raise RuntimeError("OAuth失败: 缺少 sso")

    from utils.grok_auth import sso_to_auth_json as sso_mod

    token = sso_mod.sso_to_token(sso_cookie, proxy=proxy or "", quiet=True)
    if not token or not token.get("access_token"):
        raise RuntimeError("未拿到 access_token")

    userinfo: Dict[str, Any] = {"email": email or str(token.get("email") or "")}
    try:
        for jwt_key in ("id_token", "access_token"):
            payload = parse_jwt_payload(str(token.get(jwt_key) or "")) or {}
            if payload.get("email"):
                userinfo["email"] = str(payload.get("email"))
                break
            if payload.get("sub") and not userinfo.get("sub"):
                userinfo["sub"] = str(payload.get("sub"))
    except Exception:
        pass

    return OAuthLoginResult(
        token=dict(token),
        userinfo=userinfo,
        id_token_payload=parse_jwt_payload(str(token.get("id_token") or "")),
        redirect_uri="http://127.0.0.1:56121/callback",
    )
