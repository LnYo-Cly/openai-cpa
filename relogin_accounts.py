"""
批量重登录脚本：用邮箱+密码重新走 OAuth 流程获取新 token。
只处理 refresh_token 已被消耗（reused）的账号。
"""

import os
import sys
import io

# 修复 Windows GBK 编码问题
if sys.platform == "win32":
    os.environ.setdefault("PYTHONIOENCODING", "utf-8")
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

import json
import sys
import time
import uuid
import random
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, Optional, Tuple

from curl_cffi import requests

from utils import db_manager
from utils import config as cfg
from utils.config import reload_all_configs, ts
from utils.auth_core import generate_payload
from utils.browser_fingerprint import get_random_fingerprint
from utils.integrations.sub2api_client import Sub2APIClient

# ── OAuth 常量 ──
AUTH_URL = "https://auth.openai.com/oauth/authorize"
TOKEN_URL = "https://auth.openai.com/oauth/token"
CLIENT_ID = "app_EMoamEEZ73f0CkXaXp7hrann"
DEFAULT_REDIRECT_URI = "http://localhost:1455/auth/callback"
DEFAULT_SCOPE = "openid email profile offline_access"
PROXY = "http://127.0.0.1:10809"
PROXIES = {"http": PROXY, "https": PROXY}


def _ssl_verify() -> bool:
    import os
    return os.getenv("OPENAI_SSL_VERIFY", "1").strip().lower() not in {"0", "false", "no", "off"}


def _b64url_no_pad(raw: bytes) -> str:
    import base64
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _sha256_b64url_no_pad(s: str) -> str:
    import hashlib
    return _b64url_no_pad(hashlib.sha256(s.encode("ascii")).digest())


def _random_state(nbytes: int = 16) -> str:
    import secrets
    return secrets.token_urlsafe(nbytes)


def _pkce_verifier() -> str:
    import secrets
    return secrets.token_urlsafe(64)


def _oai_headers(did: str, extra: dict = None, fp: dict = None) -> dict:
    _fp = fp or get_random_fingerprint()
    h = {
        "accept": "application/json",
        "user-agent": _fp["user_agent"],
        "sec-ch-ua": _fp["sec_ch_ua"],
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": _fp["sec_ch_ua_platform"],
        "oai-device-id": did,
    }
    if extra:
        h.update(extra)
    return h


def _generate_oauth_url() -> Dict[str, str]:
    state = _random_state()
    code_verifier = _pkce_verifier()
    code_challenge = _sha256_b64url_no_pad(code_verifier)
    params = {
        "client_id": CLIENT_ID,
        "response_type": "code",
        "redirect_uri": DEFAULT_REDIRECT_URI,
        "scope": DEFAULT_SCOPE,
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
        "prompt": "login",
        "id_token_add_organizations": "true",
        "codex_cli_simplified_flow": "true",
    }
    return {
        "auth_url": f"{AUTH_URL}?{urllib.parse.urlencode(params)}",
        "state": state,
        "code_verifier": code_verifier,
        "redirect_uri": DEFAULT_REDIRECT_URI,
    }


def _follow_redirects(session, start_url, proxies, max_redirects=12):
    current_url = start_url
    response = None
    for _ in range(max_redirects):
        try:
            response = session.get(
                current_url, allow_redirects=False,
                proxies=proxies, verify=_ssl_verify(), timeout=15,
            )
            if response.status_code not in (301, 302, 303, 307, 308):
                return response, current_url
            loc = response.headers.get("Location", "")
            if not loc:
                return response, current_url
            current_url = urllib.parse.urljoin(current_url, loc)
            if "code=" in current_url and "state=" in current_url:
                return None, current_url
        except Exception:
            return None, current_url
    return response, current_url


def _post_form(url, data, proxies=None, timeout=30):
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json",
    }
    resp = requests.post(
        url, data=data, headers=headers,
        proxies=proxies, verify=_ssl_verify(),
        timeout=timeout, impersonate=get_random_fingerprint()["impersonate"],
    )
    if resp.status_code != 200:
        raise RuntimeError(f"token exchange failed: {resp.status_code}: {resp.text[:200]}")
    return resp.json()


def _extract_next_url(data):
    continue_url = str(data.get("continue_url") or "").strip()
    if continue_url:
        return continue_url
    return ""


def _parse_callback_url(callback_url):
    candidate = callback_url.strip()
    if not candidate:
        return {"code": "", "state": "", "error": "", "error_description": ""}
    if "://" not in candidate:
        if candidate.startswith("?"):
            candidate = f"http://localhost{candidate}"
        elif "=" in candidate:
            candidate = f"http://localhost/?{candidate}"
    parsed = urllib.parse.urlparse(candidate)
    query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    fragment = urllib.parse.parse_qs(parsed.fragment, keep_blank_values=True)
    for k, v in fragment.items():
        if k not in query or not query[k]:
            query[k] = v
    return {
        "code": (query.get("code", [""])[0] or "").strip(),
        "state": (query.get("state", [""])[0] or "").strip(),
        "error": (query.get("error", [""])[0] or "").strip(),
        "error_description": (query.get("error_description", [""])[0] or "").strip(),
    }


def _jwt_claims(token_str):
    import base64
    parts = token_str.split(".")
    if len(parts) < 2:
        return {}
    seg = parts[1] + "=" * (4 - len(parts[1]) % 4)
    try:
        return json.loads(base64.b64decode(seg))
    except Exception:
        return {}


def submit_callback(callback_url, expected_state, code_verifier, redirect_uri, proxies):
    cb = _parse_callback_url(callback_url)
    if cb["error"]:
        return None, f"oauth error: {cb['error']}: {cb['error_description']}"
    if not cb["code"]:
        return None, "callback url missing code"
    if cb["state"] != expected_state:
        return None, f"state mismatch"

    token_resp = _post_form(TOKEN_URL, {
        "grant_type": "authorization_code",
        "client_id": CLIENT_ID,
        "code": cb["code"],
        "redirect_uri": redirect_uri,
        "code_verifier": code_verifier,
    }, proxies=proxies)

    access_token = (token_resp.get("access_token") or "").strip()
    refresh_token = (token_resp.get("refresh_token") or "").strip()
    id_token = (token_resp.get("id_token") or "").strip()
    expires_in = int(token_resp.get("expires_in", 3600) or 3600)

    claims = _jwt_claims(id_token)
    email = str(claims.get("email") or "").strip()
    auth_claims = claims.get("https://api.openai.com/auth") or {}
    account_id = str(auth_claims.get("chatgpt_account_id") or "").strip()

    now = int(time.time())
    token_data = {
        "id_token": id_token,
        "access_token": access_token,
        "refresh_token": refresh_token,
        "account_id": account_id,
        "last_refresh": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now)),
        "email": email,
        "type": "codex",
        "expired": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now + expires_in)),
    }
    return token_data, None


def relogin_one(email: str, password: str) -> Tuple[Optional[dict], str]:
    """用邮箱密码重新走 OAuth 登录流程，返回 (token_data 或 None, 状态消息)"""
    s = requests.Session(proxies=PROXIES, impersonate=get_random_fingerprint()["impersonate"])
    s.timeout = 30

    oauth = _generate_oauth_url()

    try:
        # 1. 访问 OAuth URL 获取 oai-did
        s.get(oauth["auth_url"], proxies=PROXIES, verify=_ssl_verify(), timeout=15)
        did = s.cookies.get("oai-did") or ""
        if not did:
            return None, "未获取到 oai-did"

        current_ua = s.headers.get("User-Agent")
        ctx = {"session_id": str(uuid.uuid4())}

        # 2. 算力挑战 - authorize_continue
        sentinel1 = generate_payload(
            did=did, flow="authorize_continue", proxy=PROXY,
            user_agent=current_ua, impersonate=get_random_fingerprint()["impersonate"], ctx=ctx
        )
        h1 = _oai_headers(did, {"Referer": "https://auth.openai.com/", "content-type": "application/json"})
        if sentinel1:
            h1["openai-sentinel-token"] = sentinel1

        resp1 = s.post(
            "https://auth.openai.com/api/accounts/authorize/continue",
            headers=h1, json={"username": {"value": email, "kind": "email"}},
            proxies=PROXIES, verify=_ssl_verify(), timeout=30, allow_redirects=False,
        )
        if resp1.status_code != 200:
            return None, f"authorize/continue HTTP {resp1.status_code}"

        next_url = str(resp1.json().get("continue_url") or "").strip()
        if next_url:
            _, current_url = _follow_redirects(s, next_url, PROXIES)
        else:
            current_url = "https://auth.openai.com/"

        # 3. 算力挑战 - password_verify
        sentinel2 = generate_payload(
            did=did, flow="password_verify", proxy=PROXY,
            user_agent=current_ua, impersonate=get_random_fingerprint()["impersonate"], ctx=ctx
        )
        h2 = _oai_headers(did, {"Referer": current_url, "content-type": "application/json"})
        if sentinel2:
            h2["openai-sentinel-token"] = sentinel2

        resp2 = s.post(
            "https://auth.openai.com/api/accounts/password/verify",
            headers=h2, json={"password": password},
            proxies=PROXIES, verify=_ssl_verify(), timeout=30,
        )
        if resp2.status_code != 200:
            return None, f"password/verify HTTP {resp2.status_code}"

        pwd_json = resp2.json()
        next_url = _extract_next_url(pwd_json)
        _, current_url = _follow_redirects(s, next_url, PROXIES)

        # 4. 检查是否直接拿到 code
        if "code=" in current_url and "state=" in current_url:
            token_data, err = submit_callback(
                current_url, oauth["state"], oauth["code_verifier"],
                oauth["redirect_uri"], PROXIES
            )
            if token_data:
                return token_data, "ok"
            return None, f"callback failed: {err}"

        # 5. 处理 consent/workspace 页面
        if "consent" in current_url or "workspace" in current_url:
            auth_cookie = s.cookies.get("oai-client-auth-session") or ""
            # 尝试从 cookie 解析 workspace
            if "." in auth_cookie:
                import base64
                parts = auth_cookie.split(".")
                ws_claims = {}
                for p in parts[:2]:
                    try:
                        ws_claims = json.loads(base64.b64decode(p + "==" ))
                        break
                    except Exception:
                        pass
                workspaces = ws_claims.get("workspaces") or []
                if workspaces:
                    ws_id = str(workspaces[0].get("id") or "")
                    if ws_id:
                        sel_resp = s.post(
                            "https://auth.openai.com/api/accounts/workspace/select",
                            headers=_oai_headers(did, {"Referer": current_url, "content-type": "application/json"}),
                            json={"workspace_id": ws_id},
                            proxies=PROXIES, verify=_ssl_verify(), timeout=15,
                        )
                        if sel_resp.status_code == 200:
                            sel_next = _extract_next_url(sel_resp.json())
                            _, final_url = _follow_redirects(s, sel_next, PROXIES)
                            if "code=" in final_url and "state=" in final_url:
                                token_data, err = submit_callback(
                                    final_url, oauth["state"], oauth["code_verifier"],
                                    oauth["redirect_uri"], PROXIES
                                )
                                if token_data:
                                    return token_data, "ok"
                                return None, f"callback after workspace failed: {err}"

            return None, f"stuck at: {current_url}"

        # 6. 处理 email-verification（需要验证码）
        if "email-verification" in current_url:
            # 先获取邮箱中已有的旧验证码，用于排除
            old_codes = _get_existing_codes(email)
            if old_codes:
                print(f"  发现旧验证码: {old_codes}")

            # 发送 OTP
            try:
                sentinel_send = generate_payload(
                    did=did, flow="authorize_continue", proxy=PROXY,
                    user_agent=current_ua, impersonate=get_random_fingerprint()["impersonate"], ctx=ctx
                )
                send_h = _oai_headers(did, {
                    "Referer": current_url, "content-type": "application/json"
                })
                if sentinel_send:
                    send_h["openai-sentinel-token"] = sentinel_send
                s.post(
                    "https://auth.openai.com/api/accounts/email-otp/send",
                    headers=send_h, json={},
                    proxies=PROXIES, verify=_ssl_verify(), timeout=30,
                )
            except Exception as e:
                pass

            # 收取验证码（排除旧码）
            code = _get_oai_code(email, exclude_codes=old_codes)
            if not code:
                return None, "email-verification: 未收到验证码"

            # 验证 OTP
            sentinel_val = generate_payload(
                did=did, flow="authorize_continue", proxy=PROXY,
                user_agent=current_ua, impersonate=get_random_fingerprint()["impersonate"], ctx=ctx
            )
            val_h = _oai_headers(did, {
                "Referer": current_url, "content-type": "application/json"
            })
            if sentinel_val:
                val_h["openai-sentinel-token"] = sentinel_val

            val_resp = s.post(
                "https://auth.openai.com/api/accounts/email-otp/validate",
                headers=val_h, json={"code": code},
                proxies=PROXIES, verify=_ssl_verify(), timeout=30,
            )
            if val_resp.status_code != 200:
                return None, f"OTP validate HTTP {val_resp.status_code}"

            val_next = _extract_next_url(val_resp.json())
            _, current_url = _follow_redirects(s, val_next, PROXIES)

            # 再次检查
            if "code=" in current_url and "state=" in current_url:
                token_data, err = submit_callback(
                    current_url, oauth["state"], oauth["code_verifier"],
                    oauth["redirect_uri"], PROXIES
                )
                if token_data:
                    return token_data, "ok"
                return None, f"callback after OTP failed: {err}"

            # consent / workspace
            if "consent" in current_url or "workspace" in current_url:
                auth_cookie = s.cookies.get("oai-client-auth-session") or ""
                if "." in auth_cookie:
                    import base64
                    for p in auth_cookie.split(".")[:2]:
                        try:
                            ws_claims = json.loads(base64.b64decode(p + "=="))
                            workspaces = ws_claims.get("workspaces") or []
                            if workspaces:
                                ws_id = str(workspaces[0].get("id") or "")
                                if ws_id:
                                    sel_resp = s.post(
                                        "https://auth.openai.com/api/accounts/workspace/select",
                                        headers=_oai_headers(did, {"Referer": current_url, "content-type": "application/json"}),
                                        json={"workspace_id": ws_id},
                                        proxies=PROXIES, verify=_ssl_verify(), timeout=15,
                                    )
                                    if sel_resp.status_code == 200:
                                        sel_next = _extract_next_url(sel_resp.json())
                                        _, final_url = _follow_redirects(s, sel_next, PROXIES)
                                        if "code=" in final_url and "state=" in final_url:
                                            token_data, err = submit_callback(
                                                final_url, oauth["state"], oauth["code_verifier"],
                                                oauth["redirect_uri"], PROXIES
                                            )
                                            if token_data:
                                                return token_data, "ok"
                                break
                        except Exception:
                            pass

            return None, f"stuck after OTP at: {current_url}"

        # 7. 其他情况
        return None, f"stuck at: {current_url}"

    except Exception as e:
        return None, str(e)[:120]


def _get_oai_code(email: str, exclude_codes: set = None) -> str:
    """收取 OpenAI 验证码 - 支持 generator_email 模式
    exclude_codes: 需要排除的旧验证码集合，确保只取新的
    """
    import re as _re
    mail_proxies = PROXIES if getattr(cfg, "USE_PROXY_FOR_EMAIL", True) else None
    mode = getattr(cfg, "EMAIL_API_MODE", "")
    if exclude_codes is None:
        exclude_codes = set()

    # generator_email 模式 - 用 domain/user 构造 surl 收信
    if mode == "generator_email":
        from utils.email_providers.generator_email_service import GeneratorEmailService
        ge = GeneratorEmailService(proxies=mail_proxies)
        surl = ge._build_surl(email)
        if not surl:
            return ""
        for attempt in range(20):
            time.sleep(3)
            code = ge.get_verification_code(surl)
            if code and code not in exclude_codes:
                print(f"  验证码获取成功: {code}")
                return code
            if code and code in exclude_codes:
                if attempt % 5 == 0:
                    print(f"  等待新验证码... (跳过旧码: {code}, 尝试 {attempt+1}/20)")
        return ""

    # freemail 模式
    if mode == "freemail":
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {cfg.FREEMAIL_API_TOKEN}",
        }
        processed = set()
        for attempt in range(20):
            time.sleep(3)
            try:
                res = requests.get(
                    f"{cfg.FREEMAIL_API_URL}/api/emails",
                    params={"mailbox": email, "limit": 20},
                    headers=headers, proxies=mail_proxies,
                    verify=_ssl_verify(), timeout=15,
                )
                if res.status_code != 200:
                    continue
                raw_data = res.json()
                emails_list = (
                    raw_data.get("data") or raw_data.get("emails") or
                    raw_data.get("messages") or raw_data.get("results") or []
                    if isinstance(raw_data, dict) else raw_data
                )
                if not isinstance(emails_list, list):
                    emails_list = []
                for mail in emails_list:
                    mail_id = str(mail.get("id") or mail.get("timestamp") or "")
                    if not mail_id or mail_id in processed:
                        continue
                    subject = str(mail.get("subject") or mail.get("title") or "")
                    m = _re.search(r"(?<!\d)(\d{6})(?!\d)", subject)
                    if m:
                        code = m.group(1)
                        if code not in exclude_codes:
                            return code
                    code = str(mail.get("code") or mail.get("verification_code") or "")
                    if code and code not in exclude_codes:
                        return code
                    try:
                        dr = requests.get(
                            f"{cfg.FREEMAIL_API_URL}/api/email/{mail_id}",
                            headers=headers, proxies=mail_proxies,
                            verify=_ssl_verify(), timeout=15,
                        )
                        if dr.status_code == 200:
                            d = dr.json()
                            from utils.email_providers.mail_service import _extract_otp_code
                            content = "\n".join(filter(None, [
                                str(d.get("subject") or ""),
                                str(d.get("content") or ""),
                                str(d.get("html_content") or ""),
                            ]))
                            code = _extract_otp_code(content)
                            if code and code not in exclude_codes:
                                return code
                    except Exception:
                        pass
                    processed.add(mail_id)
            except Exception:
                pass

    # 其他模式
    try:
        from utils.email_providers.mail_service import get_oai_code
        return get_oai_code(email, jwt="", proxies=mail_proxies)
    except Exception:
        pass

    return ""


def _get_existing_codes(email: str) -> set:
    """获取邮箱中已有的 OTP 验证码（用于后续排除）"""
    mail_proxies = PROXIES if getattr(cfg, "USE_PROXY_FOR_EMAIL", True) else None
    mode = getattr(cfg, "EMAIL_API_MODE", "")
    codes = set()

    if mode == "generator_email":
        from utils.email_providers.generator_email_service import GeneratorEmailService
        import re as _re
        ge = GeneratorEmailService(proxies=mail_proxies)
        surl = ge._build_surl(email)
        if not surl:
            return codes
        try:
            mailbox_url = f"{ge.base_url}/{surl}"
            cookies = {"surl": surl}
            resp = requests.get(
                mailbox_url, headers=ge.headers, cookies=cookies,
                proxies=mail_proxies, timeout=ge.timeout, impersonate=get_random_fingerprint()["impersonate"]
            )
            if resp.status_code == 200:
                html = resp.text or ""
                # 提取所有 6 位数验证码
                all_codes = _re.findall(r"Your ChatGPT code is (\d{6})", html, _re.IGNORECASE)
                if not all_codes:
                    all_codes = _re.findall(r"(?:openai|chatgpt)[\s\S]{0,200}?(\d{6})", html, _re.IGNORECASE)
                if not all_codes and ("openai" in html.lower() or "chatgpt" in html.lower()):
                    all_codes = _re.findall(r"\b(\d{6})\b", html)
                codes = set(all_codes)
        except Exception:
            pass

    return codes


def _is_dead(msg: str) -> bool:
    """判断是否为确认死亡的账号（需要直接删除）"""
    msg_lower = msg.lower()
    # add-phone = 要求绑手机号，确认死亡
    if "add-phone" in msg_lower:
        return True
    # password/verify 返回 401 = 密码错误/账号停用
    if "password/verify http 401" in msg_lower:
        return True
    # authorize/continue 返回 401
    if "authorize/continue http 401" in msg_lower:
        return True
    return False


def _delete_account(email: str, client: Sub2APIClient, cloud_by_email: dict):
    """从云端和本地删除账号"""
    email_lower = email.strip().lower()
    # 删除云端
    if email_lower in cloud_by_email:
        account_id = cloud_by_email[email_lower].get("id")
        if account_id:
            client.delete_account(str(account_id))
    # 删除本地
    try:
        db_manager.delete_accounts_by_emails([email])
    except Exception:
        pass


def main():
    reload_all_configs()
    db_manager.init_db()

    accounts = db_manager.get_all_accounts_with_token(10000)
    print(f"[{ts()}] 本地总账号: {len(accounts)}")

    to_relogin = []
    for acc in accounts:
        email = acc.get("email", "")
        password = acc.get("password", "")
        td_str = acc.get("token_data", "") or acc.get("token_json", "") or ""
        if not email or not password or not td_str:
            continue
        to_relogin.append({"email": email, "password": password})

    print(f"[{ts()}] 需要重登录: {len(to_relogin)}")
    if not to_relogin:
        print("没有需要重登录的账号")
        return

    # Sub2API 客户端
    client = Sub2APIClient(api_url=cfg.SUB2API_URL, api_key=cfg.SUB2API_KEY)
    ok, cloud_accounts = client.get_all_accounts(page_size=200)
    cloud_by_email = {}
    if ok:
        for acc in cloud_accounts:
            cloud_by_email[acc.get("name", "").strip().lower()] = acc
    print(f"[{ts()}] 云端账号: {len(cloud_by_email)}")
    print()

    success_count = 0
    dead_deleted = 0
    other_fail = 0
    updated_cloud = 0

    # 串行处理（每个需要收验证码，并发会冲突）
    # 支持 --limit N 参数限制处理数量
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--limit", type=int, default=0, help="限制处理数量，0=全部")
    parser.add_argument("--offset", type=int, default=0, help="从第几个开始")
    args_cli = parser.parse_args()

    if args_cli.limit > 0:
        to_relogin = to_relogin[args_cli.offset:args_cli.offset + args_cli.limit]

    total = len(to_relogin)
    print(f"[{ts()}] 本次处理: {total} 个 (offset={args_cli.offset}, limit={args_cli.limit or 'all'})")
    print()

    for i, acc in enumerate(to_relogin):
        email = acc["email"]
        password = acc["password"]
        print(f"[{ts()}] [{i+1}/{total}] 重登录: {email} ...")

        token_data, msg = relogin_one(email, password)

        if token_data:
            success_count += 1
            # 更新本地数据库
            td_str = json.dumps(token_data, ensure_ascii=False)
            db_manager.save_account_to_db(email, password, td_str)

            # 更新 Sub2API
            email_lower = email.strip().lower()
            if email_lower in cloud_by_email:
                account_id = cloud_by_email[email_lower].get("id")
                if account_id:
                    update_data = {
                        "credentials": {
                            "access_token": token_data.get("access_token", ""),
                            "refresh_token": token_data.get("refresh_token", ""),
                        }
                    }
                    ok, _ = client.update_account(str(account_id), update_data)
                    if ok:
                        updated_cloud += 1
            print(f"[{ts()}] [OK] {email} (本地+云端已更新)")
        elif _is_dead(msg):
            dead_deleted += 1
            _delete_account(email, client, cloud_by_email)
            print(f"[{ts()}] [DEAD] {email} -> {msg} (已删除)")
        else:
            other_fail += 1
            print(f"[{ts()}] [FAIL] {email} -> {msg}")

        # 进度汇总
        done = i + 1
        if done % 10 == 0 or done == total:
            pct = round(done / total * 100, 1)
            print(f"[{ts()}] === 进度: {done}/{total} ({pct}%) "
                  f"成功={success_count} 删除={dead_deleted} 失败={other_fail} ===")
            sys.stdout.flush()

        # 间隔
        time.sleep(1)

    print(f"\n[{ts()}] ========== 全部完成 ==========")
    print(f"总处理: {total}")
    print(f"重登录成功: {success_count}")
    print(f"确认死亡已删除: {dead_deleted}")
    print(f"其他失败: {other_fail}")
    print(f"云端更新: {updated_cloud}")


if __name__ == "__main__":
    main()
