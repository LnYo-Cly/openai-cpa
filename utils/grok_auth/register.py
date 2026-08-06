# -*- coding: utf-8 -*-
"""Grok 注册入口：邮箱 -> Camoufox 注册 -> device-flow。"""
from __future__ import annotations

import json
import os
import time
from typing import Optional, Tuple

from utils import config as cfg
from utils.email_providers.mail_service import (
    get_email_and_token,
    get_oai_code,
    mask_email,
    set_last_email,
)

from .browser_signup import signup_with_camoufox
from .embedded_turnstile import ensure_camoufox
from .xai_oauth import (
    CLIPROXYAPI_GROK_BASE_URL,
    build_cliproxyapi_auth_record,
    complete_build_oauth,
)


def _ts() -> str:
    try:
        return cfg.ts()
    except Exception:
        return time.strftime("%H:%M:%S")


def _log(msg: str, email: str = "") -> None:
    text = str(msg or "").strip()
    if not text:
        return
    label = ""
    if email:
        try:
            label = mask_email(email)
        except Exception:
            label = str(email)
    if label and label not in text:
        text = f"{text}: {label}"
    print(f"[{_ts()}] [Grok] {text}")


def _log_success(msg: str, email: str = "") -> None:
    text = str(msg or "").strip()
    if not text:
        return
    label = ""
    if email:
        try:
            label = mask_email(email)
        except Exception:
            label = str(email)
    if label and label not in text:
        text = f"{text}: {label}"
    print(f"[{_ts()}] [SUCCESS] {text}")


def _format_proxy(proxy: Optional[str]) -> Optional[str]:
    if not proxy:
        return None
    try:
        proxy = cfg.format_docker_url(proxy)
    except Exception:
        pass
    proxy = str(proxy).strip()
    if proxy.startswith("socks5://"):
        proxy = proxy.replace("socks5://", "socks5h://", 1)
    return proxy or None


def _generate_password() -> str:
    return f"Pw{os.urandom(6).hex()}!a#A"


def _get_proxy_env(proxy: Optional[str]) -> str:
    if proxy:
        return proxy
    return (
        os.environ.get("HTTPS_PROXY")
        or os.environ.get("HTTP_PROXY")
        or os.environ.get("https_proxy")
        or os.environ.get("http_proxy")
        or ""
    )


def _short_err(text: str) -> str:
    short = str(text or "").split(" url=")[0].split(" at ")[0].strip()
    if len(short) > 120:
        short = short[:117] + "..."
    return short


def run(
    proxy: Optional[str] = None,
    run_ctx: Optional[dict] = None,
    assigned_domain: Optional[str] = None,
    batch_id: Optional[int] = None,
    worker_index: Optional[int] = None,
) -> Tuple[Optional[str], Optional[str]]:
    if run_ctx is None:
        run_ctx = {}

    ok_c, msg_c = ensure_camoufox(force=False)
    if not ok_c:
        _log(msg_c or "Camoufox 未就绪")
        return None, None

    proxy = _format_proxy(proxy)
    proxies = {"http": proxy, "https": proxy} if proxy else None

    email = ""
    password = ""

    try:
        email, email_jwt = get_email_and_token(
            proxies,
            assigned_domain=assigned_domain,
            batch_id=batch_id,
            worker_index=worker_index,
        )
        if not email:
            _log("获取邮箱失败")
            return None, None
        set_last_email(email)
        password = _generate_password()
        _log("邮箱就绪", email)

        def _fetch_code() -> str:
            return str(
                get_oai_code(
                    email,
                    jwt=email_jwt or "",
                    proxies=proxies,
                )
                or ""
            ).strip()

        def _blog(msg: str) -> None:
            # browser_signup 内部已带邮箱；这里只做透传兜底
            _log(msg, email)

        headless_raw = str(os.environ.get("GROK_BROWSER_SIGNUP_HEADLESS", "1") or "1").strip().lower()
        browser_headless = headless_raw not in {"0", "false", "no", "off"}
        _blog("已进入浏览器注册队列")
        browser_res = signup_with_camoufox(
            email,
            password,
            fetch_code=_fetch_code,
            proxy=proxy or "",
            headless=browser_headless,
            given_name="Alex",
            family_name="Chen",
            timeout=float(getattr(cfg, "GROK_OAUTH_TIMEOUT", 180.0) or 180.0),
            log=_blog,
        )

        if not (isinstance(browser_res, dict) and browser_res.get("ok") and browser_res.get("sso")):
            err = ""
            if isinstance(browser_res, dict):
                err = str(browser_res.get("error") or "")
            err_text = err or "未知错误"
            low = err_text.lower()
            if ("cf人机" in low) or ("turnstile" in low) or ("captcha" in low):
                _log("CF人机校验失败（常见原因: 代理不通/过慢、目标打开失败）", email)
            elif ("sso" in low) and ("fail" in low or "提取失败" in err_text or "missing" in low):
                _log("SSO 提取失败", email)
            else:
                _log(f"注册失败: {_short_err(err_text)}", email)
            return None, None

        sso = str(browser_res.get("sso") or "")
        session_cookies = dict(browser_res.get("cookies") or {})
        session_cookies.setdefault("sso", sso)
        session_cookies.setdefault("sso-rw", sso)
        _log("SSO 提取成功", email)

        if bool(getattr(cfg, "GROK2API_ENABLE", False)):
            try:
                from utils.integrations.grok2api_client import push_grok_sso

                pushed, push_message = push_grok_sso(sso)
                if pushed:
                    _log_success(f"Grok2API 推送成功: {push_message}", email)
            except Exception:
                pass

        _log("开始执行原有 OAuth 换取 access_token（SSO 阶段完成后）", email)
        try:
            oauth = complete_build_oauth(
                email,
                password,
                proxy=_get_proxy_env(proxy),
                session_cookies=session_cookies,
            )
        except Exception as oauth_exc:
            detail = str(oauth_exc).strip() or repr(oauth_exc)
            if "Access denied" in detail or "invalid_grant" in detail:
                _log("OAuth失败: 账号被拒绝发 token", email)
            else:
                _log(f"OAuth失败: {_short_err(detail)}", email)
            return None, None

        token = getattr(oauth, "token", None) or {}
        userinfo = getattr(oauth, "userinfo", None) or {}
        if not token.get("access_token"):
            _log("OAuth失败: 未拿到 access_token", email)
            return None, None

        _log("OAuth access_token 获取成功，生成 Sub2API OAuth 凭证", email)
        record = build_cliproxyapi_auth_record(
            token,
            userinfo=userinfo,
            base_url=CLIPROXYAPI_GROK_BASE_URL,
        )
        if not record.get("email"):
            record["email"] = email
        record["password"] = password
        if sso:
            record["sso"] = sso
        record["status"] = "grok_oauth"
        record["provider"] = "grok"

        token_json_str = json.dumps(record, ensure_ascii=False)
        _log_success("注册完成", email)
        return token_json_str, password

    except Exception as exc:
        detail = str(exc).strip() or repr(exc)
        low = detail.lower()
        if "geoip" in low:
            _log("Camoufox geoip 依赖问题（当前已不强制 geoip）", email)
        elif ("turnstile" in low) or ("人机" in detail):
            _log("CF人机校验失败（常见原因: 代理不通/过慢、目标打开失败）", email)
        else:
            _log(f"异常: {_short_err(detail)}", email)
        if email:
            set_last_email(email)
        return None, None
