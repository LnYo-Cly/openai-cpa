"""Pure-Python registration session bootstrap for Agent Identity path.

Agent Identity Path B needs a registration-session ChatGPT bearer (session JWT).
This module extracts it from the live reg session:

  continue_url -> cookie scan -> chatgpt.com /api/auth/session
  (and if needed) NextAuth csrf/signin/openai bridge

It intentionally does NOT call image2api_data / OAuth silent-token.
"""

from __future__ import annotations

import base64
import json
import logging
import time
import uuid
from typing import Any, Dict, Iterable, Optional
from urllib.parse import urljoin

logger = logging.getLogger(__name__)

CG_BASE = "https://chatgpt.com"
CG_CSRF = f"{CG_BASE}/api/auth/csrf"
CG_SIGNIN = f"{CG_BASE}/api/auth/signin/openai"
CG_SESSION = f"{CG_BASE}/api/auth/session"
AUTH_ORIGIN = "https://auth.openai.com"
OPENAI_AUTH_CLAIM = "https://api.openai.com/auth"


def _ssl_verify() -> bool:
    import os

    flag = os.getenv("OPENAI_SSL_VERIFY", "1").strip().lower()
    return flag not in {"0", "false", "no", "off"}


def _jwt_claims_no_verify(token: str) -> Dict[str, Any]:
    if not token or str(token).count(".") < 2:
        return {}
    payload_b64 = str(token).split(".")[1]
    pad = "=" * ((4 - (len(payload_b64) % 4)) % 4)
    try:
        return json.loads(
            base64.urlsafe_b64decode((payload_b64 + pad).encode("ascii")).decode("utf-8")
        )
    except Exception:
        return {}


def _follow_redirect_chain_local(
    session: Any,
    start_url: str,
    proxies: Any = None,
    max_redirects: int = 12,
):
    """Local copy to avoid importing auth_pipeline.http_utils (and auth_core)."""
    current_url = start_url
    response = None
    for _ in range(max_redirects):
        response = session.get(
            current_url,
            allow_redirects=False,
            proxies=proxies,
            verify=_ssl_verify(),
            timeout=15,
        )
        status = int(getattr(response, "status_code", 0) or 0)
        if status in (301, 302, 303, 307, 308):
            loc = ""
            try:
                loc = str(response.headers.get("Location") or response.headers.get("location") or "")
            except Exception:
                loc = ""
            if not loc:
                break
            current_url = urljoin(current_url, loc)
            continue
        break
    return response, current_url


def _looks_like_jwt(value: str) -> bool:
    text = str(value or "").strip()
    if text.count(".") != 2:
        return False
    parts = text.split(".")
    return all(parts) and len(parts[0]) >= 8 and len(parts[1]) >= 8


def jwt_has_openai_auth_claims(token: str) -> bool:
    """True when JWT embeds OpenAI auth claims needed by Agent Identity."""
    if not _looks_like_jwt(token):
        return False
    claims = _jwt_claims_no_verify(token)
    auth = claims.get(OPENAI_AUTH_CLAIM)
    if not isinstance(auth, dict):
        return False
    account_id = auth.get("chatgpt_account_id")
    user_id = auth.get("chatgpt_user_id") or auth.get("user_id")
    return bool(isinstance(account_id, str) and account_id and isinstance(user_id, str) and user_id)


def pick_session_access_token(*candidates: Any) -> str:
    """Return the first non-empty candidate that looks like an OpenAI session JWT."""
    for raw in candidates:
        token = str(raw or "").strip()
        if token and jwt_has_openai_auth_claims(token):
            return token
    for raw in candidates:
        token = str(raw or "").strip()
        if token and _looks_like_jwt(token):
            return token
    return ""


def _iter_cookie_pairs(session: Any) -> Iterable[tuple[str, str]]:
    cookies = getattr(session, "cookies", None)
    if cookies is None:
        return []
    pairs = []
    try:
        jar = getattr(cookies, "jar", None)
        if jar is not None:
            for cookie in list(jar):
                name = str(getattr(cookie, "name", "") or "")
                value = str(getattr(cookie, "value", "") or "")
                if name and value:
                    pairs.append((name, value))
            if pairs:
                return pairs
    except Exception:
        pass
    try:
        mapping = cookies.get_dict() if hasattr(cookies, "get_dict") else dict(cookies)
        for name, value in mapping.items():
            pairs.append((str(name), str(value)))
    except Exception:
        pass
    return pairs


def scan_session_jwt_from_cookies(session: Any) -> str:
    """Scan cookie jar for a JWT that carries OpenAI auth claims."""
    preferred_names = {
        "__secure-next-auth.session-token",
        "next-auth.session-token",
        "oai-client-auth-session",
        "__secure-next-auth.session-token.0",
    }
    candidates = []
    for name, value in _iter_cookie_pairs(session):
        lname = name.lower()
        if lname in preferred_names or "session" in lname or "auth" in lname:
            candidates.append(value)
        elif _looks_like_jwt(value):
            candidates.append(value)
    return pick_session_access_token(*candidates)


def _ensure_oai_did_cookie(session: Any, device_id: str) -> None:
    did = str(device_id or "").strip()
    if not did:
        return
    try:
        session.cookies.set("oai-did", did, domain=".chatgpt.com")
    except Exception:
        try:
            session.cookies.set("oai-did", did)
        except Exception:
            pass


def _normalize_continue_url(continue_url: str) -> str:
    raw = str(continue_url or "").strip()
    if not raw:
        return ""
    if raw.startswith("http://") or raw.startswith("https://"):
        return raw
    if raw.startswith("/"):
        return urljoin(AUTH_ORIGIN + "/", raw.lstrip("/"))
    return f"{AUTH_ORIGIN}/{raw.lstrip('/')}"


def follow_reg_continue_url(session: Any, continue_url: str, proxies: Any = None) -> str:
    """Follow post-create continue_url to settle auth cookies. Returns final URL."""
    start = _normalize_continue_url(continue_url)
    if not start:
        return ""
    try:
        _, final_url = _follow_redirect_chain_local(session, start, proxies)
        return str(final_url or start)
    except Exception as exc:
        logger.debug("follow continue_url failed: %s", exc)
        try:
            resp = session.get(
                start,
                allow_redirects=True,
                proxies=proxies,
                verify=_ssl_verify(),
                timeout=30,
            )
            return str(getattr(resp, "url", start) or start)
        except Exception:
            return start


def _extract_access_token_from_session_json(payload: Any) -> str:
    if not isinstance(payload, dict):
        return ""
    return pick_session_access_token(
        payload.get("accessToken"),
        payload.get("access_token"),
        payload.get("idToken"),
        payload.get("id_token"),
    )


def fetch_chatgpt_session_json(
    session: Any,
    *,
    proxies: Any = None,
    user_agent: str = "",
    timeout: int = 30,
) -> Dict[str, Any]:
    headers = {
        "accept": "application/json",
        "referer": f"{CG_BASE}/",
    }
    if user_agent:
        headers["user-agent"] = user_agent
    resp = session.get(
        CG_SESSION,
        headers=headers,
        proxies=proxies,
        verify=_ssl_verify(),
        timeout=timeout,
        allow_redirects=True,
    )
    try:
        data = resp.json()
    except Exception:
        return {}
    return data if isinstance(data, dict) else {}


def bridge_chatgpt_nextauth_session(
    session: Any,
    *,
    proxies: Any = None,
    device_id: str = "",
    user_agent: str = "",
    login_hint: str = "",
    timeout: int = 30,
) -> str:
    """
    Establish chatgpt.com NextAuth session from an auth.openai.com-authenticated jar.

    CSRF -> signin/openai -> follow authorize URL -> GET /api/auth/session.
    """
    _ensure_oai_did_cookie(session, device_id)
    headers_base = {
        "accept": "application/json",
        "referer": f"{CG_BASE}/",
        "origin": CG_BASE,
    }
    if user_agent:
        headers_base["user-agent"] = user_agent

    try:
        csrf_resp = session.get(
            CG_CSRF,
            headers=headers_base,
            proxies=proxies,
            verify=_ssl_verify(),
            timeout=timeout,
        )
        csrf_data = csrf_resp.json() if csrf_resp is not None else {}
    except Exception as exc:
        logger.debug("chatgpt csrf failed: %s", exc)
        csrf_data = {}
    csrf_token = ""
    if isinstance(csrf_data, dict):
        csrf_token = str(csrf_data.get("csrfToken") or csrf_data.get("csrf_token") or "").strip()
    if not csrf_token:
        token = _extract_access_token_from_session_json(
            fetch_chatgpt_session_json(session, proxies=proxies, user_agent=user_agent, timeout=timeout)
        )
        return token

    session_logging_id = str(uuid.uuid4())
    form = {
        "prompt": "login",
        "screen_hint": "login_or_signup",
        "login_hint": str(login_hint or "").strip(),
        "callbackUrl": f"{CG_BASE}/",
        "csrfToken": csrf_token,
        "json": "true",
        "ext-oai-did": str(device_id or "").strip(),
        "auth_session_logging_id": session_logging_id,
        "ext-passkey-client-capabilities": "1111",
    }
    form = {k: v for k, v in form.items() if v not in ("", None)}

    signin_headers = {
        **headers_base,
        "content-type": "application/x-www-form-urlencoded",
    }
    auth_url = ""
    try:
        signin_resp = session.post(
            CG_SIGNIN,
            data=form,
            headers=signin_headers,
            proxies=proxies,
            verify=_ssl_verify(),
            timeout=timeout,
            allow_redirects=False,
        )
        try:
            body = signin_resp.json()
        except Exception:
            body = {}
        if isinstance(body, dict):
            auth_url = str(body.get("url") or body.get("redirect") or "").strip()
        if not auth_url:
            loc = ""
            try:
                loc = str(signin_resp.headers.get("Location") or signin_resp.headers.get("location") or "")
            except Exception:
                loc = ""
            if loc:
                auth_url = urljoin(CG_BASE + "/", loc)
    except Exception as exc:
        logger.debug("chatgpt signin failed: %s", exc)
        auth_url = ""

    if auth_url:
        try:
            _follow_redirect_chain_local(session, auth_url, proxies, max_redirects=16)
        except Exception as exc:
            logger.debug("follow auth_url failed: %s", exc)
            try:
                session.get(
                    auth_url,
                    headers={**headers_base, "accept": "text/html,application/xhtml+xml"},
                    proxies=proxies,
                    verify=_ssl_verify(),
                    timeout=timeout,
                    allow_redirects=True,
                )
            except Exception:
                pass

    token = _extract_access_token_from_session_json(
        fetch_chatgpt_session_json(session, proxies=proxies, user_agent=user_agent, timeout=timeout)
    )
    if token:
        return token
    return scan_session_jwt_from_cookies(session)


def extract_reg_session_access_token(
    session: Any,
    *,
    continue_url: str = "",
    proxies: Any = None,
    device_id: str = "",
    user_agent: str = "",
    email: str = "",
    settle_seconds: float = 0.0,
) -> str:
    """
    Best-effort pure-Python extractor for registration-session ChatGPT bearer.

    Order:
      1) optional settle sleep
      2) follow continue_url (auth.openai.com post-create)
      3) cookie JWT scan
      4) ChatGPT /api/auth/session
      5) NextAuth csrf/signin/session bridge
      6) cookie JWT scan again
    """
    if session is None:
        return ""

    if settle_seconds and settle_seconds > 0:
        try:
            time.sleep(float(settle_seconds))
        except Exception:
            pass

    if continue_url:
        follow_reg_continue_url(session, continue_url, proxies)

    token = scan_session_jwt_from_cookies(session)
    if token:
        return token

    try:
        token = _extract_access_token_from_session_json(
            fetch_chatgpt_session_json(session, proxies=proxies, user_agent=user_agent)
        )
        if token:
            return token
    except Exception as exc:
        logger.debug("direct chatgpt session failed: %s", exc)

    try:
        token = bridge_chatgpt_nextauth_session(
            session,
            proxies=proxies,
            device_id=device_id,
            user_agent=user_agent,
            login_hint=email,
        )
        if token:
            return token
    except Exception as exc:
        logger.debug("nextauth bridge failed: %s", exc)

    return scan_session_jwt_from_cookies(session)


def describe_token_source(token: str) -> str:
    """Short non-sensitive label for logs."""
    if not token:
        return "empty"
    if jwt_has_openai_auth_claims(token):
        claims = _jwt_claims_no_verify(token)
        auth = claims.get(OPENAI_AUTH_CLAIM) if isinstance(claims, dict) else {}
        plan = ""
        if isinstance(auth, dict):
            plan = str(auth.get("chatgpt_plan_type") or "")
        return f"openai_session_jwt(plan={plan or 'unknown'})"
    if _looks_like_jwt(token):
        return "jwt_without_openai_auth_claims"
    return "non_jwt"
