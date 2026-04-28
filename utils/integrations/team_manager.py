"""
ChatGPT Team API 客户端 — 纯 HTTP 调用，无需浏览器自动化
接口来源: codex-console auto_team 模块
"""
import json
import time
import traceback
from typing import Optional

import httpx
from curl_cffi import requests as cffi_requests

import utils.config as cfg

# ── ChatGPT API 基础 URL ──
CHATGPT_API = "https://chatgpt.com/backend-api"
ACCOUNTS_CHECK_URL = f"{CHATGPT_API}/accounts/check/v4-2023-04-27"

# ── 请求头模板 ──
_BASE_HEADERS = {
    "Accept": "application/json",
    "Origin": "https://chatgpt.com",
    "Referer": "https://chatgpt.com/",
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
}


def _get_proxy():
    """获取默认代理"""
    return getattr(cfg, 'DEFAULT_PROXY', None) or None


def _make_session(proxy=None):
    """创建 curl_cffi session"""
    p = proxy or _get_proxy()
    kwargs = {"impersonate": "chrome120", "timeout": 35}
    if p:
        kwargs["proxy"] = p
    return cffi_requests.Session(**kwargs)


def _request_with_fallback(method: str, url: str, session=None, proxy=None, **kwargs):
    """
    发起请求，遇到 TLS/连接错误时自动 fallback：
    1. 代理 + impersonate
    2. 直连 + impersonate
    3. 代理 + 无 impersonate
    4. httpx（不同 SSL 库，终极 fallback）
    """
    errors = []
    proxy_url = proxy or _get_proxy()
    headers = kwargs.pop("headers", {})
    json_body = kwargs.pop("json", None)
    params = kwargs.pop("params", None)

    # 策略1: 代理 + impersonate (默认)
    if proxy_url:
        try:
            with _make_session(proxy=proxy_url) as s:
                resp = getattr(s, method)(url, headers=headers, json=json_body, params=params, **kwargs)
            return resp
        except Exception as e:
            errors.append(f"代理+impersonate: {e}")

    # 策略2: 直连 + impersonate
    try:
        with _make_session(proxy="") as s:
            resp = getattr(s, method)(url, headers=headers, json=json_body, params=params, **kwargs)
        return resp
    except Exception as e:
        errors.append(f"直连+impersonate: {e}")

    # 策略3: 代理 + 无 impersonate
    if proxy_url:
        try:
            with cffi_requests.Session(timeout=35, proxy=proxy_url) as s:
                resp = getattr(s, method)(url, headers=headers, json=json_body, params=params, **kwargs)
            return resp
        except Exception as e:
            errors.append(f"代理+无impersonate: {e}")

    # 策略4: httpx fallback（不同 SSL 库）
    try:
        httpx_kwargs = {"timeout": 30, "headers": headers, "verify": False}
        if proxy_url:
            httpx_kwargs["proxy"] = proxy_url
        if json_body:
            httpx_kwargs["json"] = json_body
        if params:
            httpx_kwargs["params"] = params
        with httpx.Client(**httpx_kwargs) as c:
            resp = getattr(c, method)(url)
        return _HttpxResponseWrapper(resp)
    except Exception as e:
        errors.append(f"httpx: {e}")

    raise Exception(f"所有请求策略均失败: {'; '.join(errors)}")


class _HttpxResponseWrapper:
    """将 httpx.Response 包装成类似 curl_cffi.Response 的接口"""
    def __init__(self, resp):
        self._resp = resp
        self.status_code = resp.status_code
        self.text = resp.text

    def json(self):
        return self._resp.json()


def _auth_headers(access_token: str, workspace_id: str = "") -> dict:
    """构建认证请求头"""
    h = dict(_BASE_HEADERS)
    h["Authorization"] = f"Bearer {access_token}"
    if workspace_id:
        h["chatgpt-account-id"] = workspace_id
    return h


def _refresh_token_of(email: str, token_data: dict) -> Optional[str]:
    """尝试刷新 access_token，成功则返回新 token_data JSON 字符串"""
    from utils.auth_pipeline.oauth import refresh_oauth_token
    refresh_token = token_data.get("refresh_token", "")
    if not refresh_token:
        return None
    proxy = _get_proxy()
    proxies = {"https": proxy, "http": proxy} if proxy else None
    ok, result = refresh_oauth_token(refresh_token, proxies)
    if ok and result.get("access_token"):
        token_data.update({
            "access_token": result["access_token"],
            "refresh_token": result.get("refresh_token", refresh_token),
        })
        return json.dumps(token_data, ensure_ascii=False)
    return None


# ══════════════════════════════════════════════════════
#  公开接口
# ══════════════════════════════════════════════════════

def discover_workspaces(access_token: str, proxy=None) -> list:
    """
    发现 access_token 对应的所有工作区。
    返回: [{"workspace_id", "plan_type", "role", "name", "current_members", "max_members"}]
    """
    resp = _request_with_fallback("get", ACCOUNTS_CHECK_URL, proxy=proxy,
                                  headers=_auth_headers(access_token))
    if resp.status_code != 200:
        raise Exception(f"工作区发现失败: HTTP {resp.status_code} - {resp.text[:300]}")

        data = resp.json()
        accounts = data.get("accounts", {})
        results = []
        for ws_id, ws_data in accounts.items():
            acct = ws_data.get("account", {})
            plan_type = (acct.get("plan_type") or "").lower()
            role = (acct.get("account_user_role") or "").lower()

            # 提取成员信息
            current = acct.get("total_current_members", 0)
            max_m = acct.get("total_max_members", 0)

            results.append({
                "workspace_id": ws_id,
                "plan_type": plan_type,
                "role": role,
                "name": acct.get("name", ""),
                "is_default": acct.get("is_default", False),
                "current_members": current,
                "max_members": max_m,
            })
        return results


def send_invite(access_token: str, workspace_id: str, target_email: str,
                proxy=None, max_retries: int = 3) -> dict:
    """
    发送 Team 邀请，带重试和 429 退避。
    返回: {"success": bool, "message": str, "status": str}
    status: "invited" | "already_member" | "already_invited" | "failed"
    """
    headers = _auth_headers(access_token, workspace_id)
    payload = {
        "email_addresses": [target_email],
        "role": "standard-user",
        "resend_emails": True,
    }
    url = f"{CHATGPT_API}/accounts/{workspace_id}/invites"

    last_err = ""
    for attempt in range(max_retries):
        try:
            resp = _request_with_fallback("post", url, proxy=proxy,
                                          headers=headers, json=payload)

            if resp.status_code in (200, 201):
                return {"success": True, "message": "邀请已发送", "status": "invited"}

            # 409 / 422 — 已是成员或已邀请
            if resp.status_code in (409, 422):
                body = resp.text.lower()
                if "already" in body or "exist" in body or "member" in body:
                    status = "already_member" if "member" in body or "workspace" in body else "already_invited"
                    return {"success": True, "message": "该邮箱已是成员或已有邀请", "status": status}

            # 429 限流
            if resp.status_code == 429:
                wait = min(18.0, 2 ** attempt)
                print(f"[Team] 429 限流，等待 {wait}s 后重试 ({attempt+1}/{max_retries})")
                time.sleep(wait)
                continue

            # 401/403 — 可能 token 过期
            if resp.status_code in (401, 403):
                return {"success": False, "message": f"认证失败 HTTP {resp.status_code}", "status": "auth_failed"}

            last_err = f"HTTP {resp.status_code}: {resp.text[:300]}"
        except Exception as e:
            last_err = str(e)

        if attempt < max_retries - 1:
            time.sleep(min(10.0, 2 ** attempt))

    return {"success": False, "message": f"邀请失败: {last_err}", "status": "failed"}


def list_members(access_token: str, workspace_id: str, proxy=None) -> list:
    """
    列出工作区所有成员（分页）。
    返回: [{"user_id", "email", "name", "role", "created_at"}]
    """
    headers = _auth_headers(access_token, workspace_id)
    url = f"{CHATGPT_API}/accounts/{workspace_id}/users"
    all_members = []
    offset = 0
    limit = 50

    while True:
        resp = _request_with_fallback("get", url, proxy=proxy, headers=headers,
                                      params={"limit": limit, "offset": offset})
        if resp.status_code != 200:
            raise Exception(f"获取成员列表失败: HTTP {resp.status_code}")

        data = resp.json()
        items = data.get("items", []) if isinstance(data, dict) else data
        if not items:
            break

        for u in items:
            all_members.append({
                "user_id": u.get("id", ""),
                "email": (u.get("email") or "").lower(),
                "name": u.get("name", ""),
                "role": u.get("role", ""),
                "created_at": u.get("created_at", ""),
            })

        if len(items) < limit:
            break
        offset += limit

    return all_members


def list_invites(access_token: str, workspace_id: str, proxy=None) -> list:
    """
    列出工作区所有待处理邀请。
    返回: [{"id", "email", "role", "state", "created_at"}]
    """
    headers = _auth_headers(access_token, workspace_id)
    url = f"{CHATGPT_API}/accounts/{workspace_id}/invites"

    resp = _request_with_fallback("get", url, proxy=proxy, headers=headers)
    if resp.status_code != 200:
        raise Exception(f"获取邀请列表失败: HTTP {resp.status_code}")

        data = resp.json()
        items = data.get("items", data) if isinstance(data, dict) else data
        results = []
        for inv in (items or []):
            results.append({
                "id": inv.get("id", ""),
                "email": (inv.get("email_address") or inv.get("email") or "").lower(),
                "role": inv.get("role", ""),
                "state": inv.get("state", ""),
                "created_at": inv.get("created_at", ""),
            })
        return results


def revoke_invite(access_token: str, workspace_id: str, target_email: str,
                  proxy=None) -> bool:
    """撤回邀请"""
    headers = _auth_headers(access_token, workspace_id)
    headers["Content-Type"] = "application/json"
    url = f"{CHATGPT_API}/accounts/{workspace_id}/invites"

    resp = _request_with_fallback("delete", url, proxy=proxy, headers=headers,
                                  json={"email_address": target_email})
    return resp.status_code in (200, 204, 404)


def remove_member(access_token: str, workspace_id: str, user_id: str,
                  proxy=None) -> bool:
    """移除成员"""
    headers = _auth_headers(access_token, workspace_id)
    url = f"{CHATGPT_API}/accounts/{workspace_id}/users/{user_id}"

    resp = _request_with_fallback("delete", url, proxy=proxy, headers=headers)
    return resp.status_code in (200, 204, 404)


# ══════════════════════════════════════════════════════
#  带 token 刷新的高级封装
# ══════════════════════════════════════════════════════

def _get_account_token(email: str) -> tuple:
    """
    从 DB 获取账号 token_data，返回 (access_token, token_data_dict) 或抛异常。
    """
    from utils import db_manager
    token_data = db_manager.get_token_by_email(email)
    if not token_data:
        raise Exception(f"账号 {email} 无 token 数据")
    access_token = token_data.get("access_token", "")
    if not access_token:
        raise Exception(f"账号 {email} access_token 为空")
    return access_token, token_data


def _get_or_refresh_token(email: str) -> tuple:
    """
    获取 access_token，401 时自动刷新。
    返回 (access_token, token_data_dict, was_refreshed)
    """
    access_token, token_data = _get_account_token(email)
    return access_token, token_data, False


def discover_with_refresh(email: str, proxy=None) -> dict:
    """发现工作区，token 过期自动刷新"""
    access_token, token_data, _ = _get_or_refresh_token(email)
    try:
        workspaces = discover_workspaces(access_token, proxy)
        return {"success": True, "data": workspaces}
    except Exception as e:
        err_msg = str(e)
        # 尝试刷新 token
        if "401" in err_msg or "403" in err_msg:
            new_json = _refresh_token_of(email, token_data)
            if new_json:
                from utils import db_manager
                db_manager.update_account_token_only(email, new_json)
                new_data = json.loads(new_json)
                workspaces = discover_workspaces(new_data["access_token"], proxy)
                return {"success": True, "data": workspaces}
        raise


def invite_with_refresh(email: str, workspace_id: str, target_email: str,
                        proxy=None) -> dict:
    """发送邀请，token 过期自动刷新"""
    access_token, token_data, _ = _get_or_refresh_token(email)
    result = send_invite(access_token, workspace_id, target_email, proxy)

    # 如果认证失败，尝试刷新 token
    if result["status"] == "auth_failed":
        new_json = _refresh_token_of(email, token_data)
        if new_json:
            from utils import db_manager
            db_manager.update_account_token_only(email, new_json)
            new_data = json.loads(new_json)
            result = send_invite(new_data["access_token"], workspace_id, target_email, proxy)

    return result


def members_with_refresh(email: str, workspace_id: str, proxy=None) -> dict:
    """获取成员列表，token 过期自动刷新"""
    access_token, token_data, _ = _get_or_refresh_token(email)
    try:
        members = list_members(access_token, workspace_id, proxy)
        invites = list_invites(access_token, workspace_id, proxy)
        return {"success": True, "members": members, "invites": invites}
    except Exception as e:
        err_msg = str(e)
        if "401" in err_msg or "403" in err_msg:
            new_json = _refresh_token_of(email, token_data)
            if new_json:
                from utils import db_manager
                db_manager.update_account_token_only(email, new_json)
                new_data = json.loads(new_json)
                members = list_members(new_data["access_token"], workspace_id, proxy)
                invites = list_invites(new_data["access_token"], workspace_id, proxy)
                return {"success": True, "members": members, "invites": invites}
        raise
