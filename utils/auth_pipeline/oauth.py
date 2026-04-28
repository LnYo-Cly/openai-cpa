import json
import time
import urllib.parse
from dataclasses import dataclass
from typing import Any, Tuple

from curl_cffi import requests

from .constants import AUTH_URL, TOKEN_URL, CLIENT_ID, DEFAULT_REDIRECT_URI, DEFAULT_SCOPE
from .common import _random_state, _pkce_verifier, _sha256_b64url_no_pad, _parse_callback_url, _jwt_claims_no_verify
from .http_utils import _post_form, _to_int, _ssl_verify


@dataclass(frozen=True)
class OAuthStart:
    auth_url: str
    state: str
    code_verifier: str
    redirect_uri: str


def generate_oauth_url(
        *,
        redirect_uri: str = DEFAULT_REDIRECT_URI,
        scope: str = DEFAULT_SCOPE,
) -> OAuthStart:
    state = _random_state()
    code_verifier = _pkce_verifier()
    code_challenge = _sha256_b64url_no_pad(code_verifier)
    params = {
        "client_id": CLIENT_ID,
        "response_type": "code",
        "redirect_uri": redirect_uri,
        "scope": scope,
        "state": state,
        # "prompt": "login",
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
        "id_token_add_organizations": "true",
        "codex_cli_simplified_flow": "true",
    }
    return OAuthStart(
        auth_url=f"{AUTH_URL}?{urllib.parse.urlencode(params)}",
        state=state,
        code_verifier=code_verifier,
        redirect_uri=redirect_uri,
    )


def submit_callback_url(
        *,
        callback_url: str,
        expected_state: str,
        code_verifier: str,
        redirect_uri: str = DEFAULT_REDIRECT_URI,
        proxies: Any = None,
) -> str:
    cb = _parse_callback_url(callback_url)
    if cb["error"]:
        raise RuntimeError(f"oauth error: {cb['error']}: {cb['error_description']}".strip())
    if not cb["code"]:
        raise ValueError("callback url missing ?code=")
    if not cb["state"]:
        raise ValueError("callback url missing ?state=")
    if cb["state"] != expected_state:
        raise ValueError("state mismatch")

    token_resp = _post_form(
        TOKEN_URL,
        {
            "grant_type": "authorization_code",
            "client_id": CLIENT_ID,
            "code": cb["code"],
            "redirect_uri": redirect_uri,
            "code_verifier": code_verifier,
        },
        proxies=proxies,
    )

    access_token = (token_resp.get("access_token") or "").strip()
    refresh_token = (token_resp.get("refresh_token") or "").strip()
    id_token = (token_resp.get("id_token") or "").strip()
    expires_in = _to_int(token_resp.get("expires_in"))

    claims = _jwt_claims_no_verify(id_token)
    email = str(claims.get("email") or "").strip()
    auth_claims = claims.get("https://api.openai.com/auth") or {}
    account_id = str(auth_claims.get("chatgpt_account_id") or "").strip()
    plan_type = str(auth_claims.get("chatgpt_plan_type") or "").strip()

    now = int(time.time())
    now_rfc = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now))
    expired_rfc = time.strftime("%Y-%m-%dT%H:%M:%SZ",
                                time.gmtime(now + max(expires_in, 0)))

    config_obj = {
        "id_token": id_token,
        "client_id": CLIENT_ID,
        "access_token": access_token,
        "refresh_token": refresh_token,
        "account_id": account_id,
        "plan_type": plan_type,
        "last_refresh": now_rfc,
        "email": email,
        "type": "codex",
        "expired": expired_rfc,
    }
    return json.dumps(config_obj, ensure_ascii=False, separators=(",", ":"))


def refresh_oauth_token(refresh_token: str, proxies: Any = None) -> Tuple[bool, dict]:
    """刷新 OAuth Token，在子进程中执行以隔离 curl_cffi 的 OpenSSL 污染"""
    import subprocess
    import sys

    if not refresh_token:
        return False, {"error": "无 refresh_token"}

    proxy_url = ""
    if proxies:
        proxy_url = proxies.get("https") or proxies.get("http") or ""

    script = (
        "import sys,json,httpx,time\n"
        "refresh_token,proxy_url,TOKEN_URL,CLIENT_ID,REDIRECT_URI=sys.argv[1:6]\n"
        "try:\n"
        "    with httpx.Client(proxy=proxy_url or None,verify=False,timeout=30) as c:\n"
        "        r=c.post(TOKEN_URL,data={'client_id':CLIENT_ID,'grant_type':'refresh_token',"
        "'refresh_token':refresh_token,'redirect_uri':REDIRECT_URI},"
        "headers={'Content-Type':'application/x-www-form-urlencoded','Accept':'application/json',"
        "'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/131.0.0.0'})\n"
        "    if r.status_code==200:\n"
        "        d=r.json();now=int(time.time());ei=int(d.get('expires_in',3600))\n"
        "        print(json.dumps({'ok':True,'access_token':d.get('access_token',''),"
        "'refresh_token':d.get('refresh_token',refresh_token),"
        "'id_token':d.get('id_token',''),"
        "'last_refresh':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime(now)),"
        "'expired':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime(now+max(ei,0)))}))\n"
        "    else:\n"
        "        print(json.dumps({'ok':False,'error':f'HTTP {r.status_code}'}))\n"
        "except Exception as e:\n"
        "    print(json.dumps({'ok':False,'error':str(e)}))\n"
    )

    try:
        result = subprocess.run(
            [sys.executable, "-c", script, refresh_token, proxy_url, TOKEN_URL, CLIENT_ID,
             DEFAULT_REDIRECT_URI],
            capture_output=True, text=True, timeout=35
        )
        data = json.loads(result.stdout.strip())
        if data.get("ok"):
            return True, {k: v for k, v in data.items() if k != "ok"}
        return False, {"error": data.get("error", "未知")}
    except subprocess.TimeoutExpired:
        return False, {"error": "子进程超时"}
    except Exception as e:
        return False, {"error": str(e)}