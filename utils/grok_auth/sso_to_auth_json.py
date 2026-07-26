# -*- coding: utf-8 -*-
"""SSO 通过 device-flow 换 access_token。"""
from __future__ import annotations

import base64
import json
import os
import re
import time
import urllib.parse
from pathlib import Path
from typing import Any

from curl_cffi import requests
try:
    from register_lite_config import AUTH_FILE, GROK_CLI_CLIENT_ID, OIDC_ISSUER, OIDC_SCOPES
except Exception:
    AUTH_FILE = Path(os.getenv('GROK2API_AUTH_FILE', str(Path.home() / '.grok' / 'auth.json')))
    GROK_CLI_CLIENT_ID = os.getenv('GROK2API_OIDC_CLIENT_ID', 'b1a00492-073a-47ea-816f-4c329264a828')
    OIDC_ISSUER = os.getenv('GROK2API_OIDC_ISSUER', 'https://auth.x.ai')
    OIDC_SCOPES = os.getenv('GROK2API_OIDC_SCOPES', 'openid profile email offline_access grok-cli:access api:access conversations:read conversations:write')
AUTH_KEY = f'{OIDC_ISSUER}::{GROK_CLI_CLIENT_ID}'
GROK_DEVICE_REFERRER = (os.getenv('GROK2API_DEVICE_REFERRER') or os.getenv('GROK_DEVICE_REFERRER') or 'grok-build').strip() or 'grok-build'
SSO_COOKIE_DOMAINS = ('.x.ai', 'accounts.x.ai', 'auth.x.ai', '.accounts.x.ai', '.auth.x.ai')
ACCOUNTS_ORIGIN = 'https://accounts.x.ai'
GROK_REFERRER = (os.getenv('GROK2API_DEVICE_REFERRER') or os.getenv('GROK_DEVICE_REFERRER') or GROK_DEVICE_REFERRER or 'grok-build').strip() or 'grok-build'
GROK_PLAN = (os.getenv('GROK2API_OAUTH_PLAN') or 'generic').strip() or 'generic'
REDIRECT_URI = (os.getenv('GROK2API_CPA_REDIRECT_URI') or 'http://127.0.0.1:56121/callback').strip()
CLIENT_ID = GROK_CLI_CLIENT_ID
SCOPES = OIDC_SCOPES
GROK_VERSION = (os.getenv('GROK2API_CLI_VERSION') or '0.2.93').strip() or '0.2.93'
GROK_TOKEN_UA = f'grok-shell/{GROK_VERSION} (linux; x86_64)'
import threading as _threading
_DEVICE_FLOW_LOCK = _threading.RLock()
_DEVICE_FLOW_LAST_TS = 0.0

def _device_flow_gap_sec() -> float:
    try:
        return max(0.0, float(os.getenv('GROK2API_SSO_DEVICE_GAP_SEC', '1.2') or 1.2))
    except (TypeError, ValueError):
        return 1.2

def _device_flow_retries() -> int:
    try:
        return max(1, min(6, int(os.getenv('GROK2API_SSO_DEVICE_RETRIES', '3') or 3)))
    except (TypeError, ValueError):
        return 3

def _device_flow_backoff_sec(attempt: int) -> float:
    base = 2.0 * attempt
    try:
        base = float(os.getenv('GROK2API_SSO_DEVICE_BACKOFF_SEC', str(base)) or base)
    except (TypeError, ValueError):
        pass
    return max(1.0, min(20.0, base))

def _wait_device_flow_slot() -> None:
    global _DEVICE_FLOW_LAST_TS
    gap = _device_flow_gap_sec()
    with _DEVICE_FLOW_LOCK:
        now = time.time()
        wait = _DEVICE_FLOW_LAST_TS + gap - now
        if wait > 0:
            time.sleep(wait)
        _DEVICE_FLOW_LAST_TS = time.time()

def _is_rate_limited_payload(text: str | None=None, url: str | None=None, status: int | None=None) -> bool:
    blob = f"{status or ''} {url or ''} {text or ''}".lower()
    return any((k in blob for k in ('slow_down', 'rate_limited', 'rate limit', 'too many', '429')))

def _proxy_kwargs(fixed: str | None=None) -> dict:
    """Return curl_cffi compatible proxy kwargs.

    Prefer a sticky fixed URL for an entire device-flow.
    """
    proxy = (fixed or '').strip()
    if not proxy:
        try:
            from proxy_pool import resolve_proxy_for_request, curl_proxies_arg
            url = resolve_proxy_for_request(fallback_env=True)
            proxies = curl_proxies_arg(url)
            if proxies:
                return {'proxies': proxies}
        except Exception:
            pass
        proxy = (os.getenv('GROK2API_XAI_PROXY') or os.getenv('GROK2API_PROXY') or os.getenv('GROK_CLI_PROXY') or '').strip()
        if '\n' in proxy or '\r' in proxy:
            proxy = next((ln.strip() for ln in proxy.replace('\r', '\n').split('\n') if ln.strip() and (not ln.strip().startswith('#'))), '')
    if proxy:
        return {'proxies': {'http': proxy, 'https': proxy}}
    return {}

def _resolve_sticky_proxy(explicit: str='') -> str:
    """Pick one proxy URL and keep it for the whole device-flow."""
    pxy = (explicit or '').strip()
    if not pxy:
        try:
            from proxy_pool import resolve_proxy_for_request
            url = resolve_proxy_for_request(fallback_env=True)
            if url:
                pxy = str(url).strip()
        except Exception:
            pxy = ''
    if not pxy:
        kw = _proxy_kwargs()
        proxies = kw.get('proxies') or {}
        pxy = str(proxies.get('https') or proxies.get('http') or '').strip()
    if '\n' in pxy or '\r' in pxy:
        pxy = next((ln.strip() for ln in pxy.replace('\r', '\n').split('\n') if ln.strip() and (not ln.strip().startswith('#'))), '')
    return pxy

def _set_sso_cookies(session: Any, sso_cookie: str) -> None:
    """Write sso + sso-rw across auth domains used by device verify/approve."""
    sso = str(sso_cookie or '').strip()
    if not sso:
        return
    for domain in SSO_COOKIE_DOMAINS:
        try:
            session.cookies.set('sso', sso, domain=domain)
            session.cookies.set('sso-rw', sso, domain=domain)
        except Exception:
            try:
                session.cookies.set('sso', sso, domain=domain.lstrip('.'))
                session.cookies.set('sso-rw', sso, domain=domain.lstrip('.'))
            except Exception:
                pass

def fetch_userinfo(access_token: str, *, session: Any | None=None) -> dict:
    """OIDC userinfo for email when device-flow token has no email claim."""
    token = str(access_token or '').strip()
    if not token:
        return {}
    headers = {'Authorization': f'Bearer {token}', 'Accept': 'application/json'}
    timeout = _http_timeout()
    proxy_kw = _proxy_kwargs()
    if session is not None:
        try:
            r = session.get(f'{OIDC_ISSUER}/oauth2/userinfo', headers=headers, impersonate='chrome', timeout=timeout, **proxy_kw)
            if int(getattr(r, 'status_code', 0) or 0) < 400:
                data = r.json()
                return data if isinstance(data, dict) else {}
        except Exception:
            return {}
        return {}
    req = urllib.request.Request(f'{OIDC_ISSUER}/oauth2/userinfo', headers=headers, method='GET')
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read())
            return data if isinstance(data, dict) else {}
    except Exception:
        return {}

def enrich_token_with_userinfo(token: dict, *, session: Any | None=None) -> dict:
    if not isinstance(token, dict) or not token:
        return token
    if token.get('_email') or token.get('email'):
        return token
    access = token.get('access_token') or token.get('key') or ''
    info = fetch_userinfo(str(access or ''), session=session)
    if info.get('email'):
        token['_email'] = info.get('email')
        token['email'] = info.get('email')
        token['_email_verified'] = bool(info.get('email_verified'))
        token['_name'] = info.get('name') or ''
    return token

def b64url_decode(seg: str) -> bytes:
    seg += '=' * (-len(seg) % 4)
    return base64.urlsafe_b64decode(seg)

def decode_jwt_payload(token: str) -> dict:
    try:
        return json.loads(b64url_decode(token.split('.')[1]))
    except Exception:
        return {}

def _http_timeout() -> float:
    try:
        return max(8.0, float(os.getenv('GROK2API_SSO_HTTP_TIMEOUT', '30') or 30))
    except (TypeError, ValueError):
        return 30.0

def _poll_interval_sec(raw: Any=None) -> float:
    """Device-code poll interval after approve.

    Upstream often advertises interval=5, but once the user_code is already
    approved we can poll immediately / more aggressively. Override with
    GROK2API_SSO_POLL_INTERVAL (seconds).
    """
    env = (os.getenv('GROK2API_SSO_POLL_INTERVAL') or '').strip()
    if env:
        try:
            return max(0.2, min(10.0, float(env)))
        except ValueError:
            pass
    try:
        hinted = float(raw if raw is not None else 1)
    except (TypeError, ValueError):
        hinted = 1.0
    return max(0.4, min(hinted, 1.5))

def request_device_code(session: Any | None=None, *, proxy_kw: dict | None=None) -> dict | None:
    """Request OIDC device code. Prefer shared curl_cffi session when given.

    Retries on xAI rate limits (HTTP 429 / slow_down) — common when several
    registration workers enter device-flow together.
    """
    form = {'client_id': GROK_CLI_CLIENT_ID, 'scope': OIDC_SCOPES}
    timeout = _http_timeout()
    retries = _device_flow_retries()
    pkw = proxy_kw if proxy_kw is not None else _proxy_kwargs()
    last_err = ''
    for attempt in range(1, retries + 1):
        _wait_device_flow_slot()
        if session is not None:
            try:
                r = session.post(f'{OIDC_ISSUER}/oauth2/device/code', data=form, headers={'Content-Type': 'application/x-www-form-urlencoded', 'Accept': 'application/json'}, impersonate='chrome', timeout=timeout, **pkw)
                code = int(getattr(r, 'status_code', 0) or 0)
                body = (getattr(r, 'text', None) or '')[:300]
                if code >= 400:
                    last_err = f'HTTP {code}: {body[:200]}'
                    print(f'   device/code {last_err}')
                    if _is_rate_limited_payload(body, status=code) and attempt < retries:
                        time.sleep(_device_flow_backoff_sec(attempt))
                        continue
                    return None
                data = r.json()
                return data if isinstance(data, dict) else None
            except Exception as e:
                last_err = str(e)
                print(f'   device/code: {e}')
                if attempt < retries and _is_rate_limited_payload(str(e)):
                    time.sleep(_device_flow_backoff_sec(attempt))
                    continue
                return None
        data = urllib.parse.urlencode(form).encode()
        req = urllib.request.Request(f'{OIDC_ISSUER}/oauth2/device/code', data=data, method='POST', headers={'Content-Type': 'application/x-www-form-urlencoded'})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return json.loads(resp.read())
        except urllib.error.HTTPError as e:
            body = e.read().decode()[:300]
            last_err = f'HTTP {e.code}: {body[:200]}'
            print(f'   device/code {last_err}')
            if _is_rate_limited_payload(body, status=e.code) and attempt < retries:
                time.sleep(_device_flow_backoff_sec(attempt))
                continue
            return None
        except Exception as e:
            last_err = str(e)
            print(f'   device/code: {e}')
            if attempt < retries:
                time.sleep(_device_flow_backoff_sec(attempt))
                continue
            return None
    if last_err:
        print(f'   device/code exhausted retries: {last_err}')
    return None

def poll_token(device_code: str, interval: int | float=1, expires_in: int=1800, timeout: int | float=45, *, session: Any | None=None, proxy_kw: dict | None=None, immediate: bool=True) -> dict | None:
    """Exchange an approved device_code for tokens.

    Performance notes:
    - Poll **immediately** after approve (do not sleep first).
    - Use a short interval (default ~1s) instead of the upstream 5s hint.
    - Prefer curl_cffi session when provided (same TLS fingerprint path).
    """
    interval_f = _poll_interval_sec(interval)
    deadline = time.time() + min(float(expires_in or 1800), float(timeout or 45))
    form = {'grant_type': 'urn:ietf:params:oauth:grant-type:device_code', 'client_id': GROK_CLI_CLIENT_ID, 'device_code': device_code}
    http_timeout = _http_timeout()
    pkw = proxy_kw if proxy_kw is not None else _proxy_kwargs()
    first = True
    while time.time() < deadline:
        if not (first and immediate):
            time.sleep(interval_f)
        first = False
        if session is not None:
            try:
                r = session.post(f'{OIDC_ISSUER}/oauth2/token', data=form, headers={'Content-Type': 'application/x-www-form-urlencoded'}, impersonate='chrome', timeout=http_timeout, **pkw)
                code = int(getattr(r, 'status_code', 0) or 0)
                if code < 400:
                    data = r.json()
                    return data if isinstance(data, dict) else None
                try:
                    err = r.json() if r.content else {}
                except Exception:
                    err = {}
                error = str((err or {}).get('error') or '')
                desc = str((err or {}).get('error_description') or '')[:240]
                if error == 'invalid_grant':
                   # print('   token: invalid_grant' + (f' ({desc})' if desc else '') + f" raw={(getattr(r, 'text', '') or '')[:160]!r}")
                    return None
                if error == 'authorization_pending':
                    continue
                if error == 'slow_down':
                    interval_f = min(10.0, interval_f + 1.0)
                    continue
                print(f"   token: {error or f'HTTP {code}'}")
                return None
            except Exception as e:
                if time.time() >= deadline:
                    print(f'   token network: {e}')
                    return None
                continue
        data = urllib.parse.urlencode(form).encode()
        req = urllib.request.Request(f'{OIDC_ISSUER}/oauth2/token', data=data, method='POST', headers={'Content-Type': 'application/x-www-form-urlencoded'})
        try:
            with urllib.request.urlopen(req, timeout=http_timeout) as resp:
                return json.loads(resp.read())
        except urllib.error.HTTPError as e:
            try:
                err = json.loads(e.read())
            except Exception:
                err = {}
            error = err.get('error', '')
            if error == 'invalid_grant':
                print('  token: invalid_grant')
                return None
            if error == 'authorization_pending':
                continue
            if error == 'slow_down':
                interval_f = min(10.0, interval_f + 1.0)
                continue
            print(f'   token: {error}')
            return None
        except Exception as e:
            if time.time() >= deadline:
                print(f'   token network: {e}')
                return None
            continue
    print('   轮询超时')
    return None

def _principal_id_from_sso(sso_cookie: str) -> str:
    """Extract OAuth principal id from SSO session JWT.

    SSO cookies are often HS256 session JWTs with session_id only — do not
    treat bare session_id / id as principal_id (wrong id -> Access denied).
    """
    pl = decode_jwt_payload(str(sso_cookie or ''))
    if not pl:
        return ''
    for key in ('sub', 'principal_id', 'principalId', 'user_id', 'userId', 'uid'):
        val = pl.get(key)
        if val is not None and str(val).strip():
            return str(val).strip()
    for nest in ('user', 'account', 'identity', 'profile'):
        sub = pl.get(nest)
        if not isinstance(sub, dict):
            continue
        for key in ('sub', 'principal_id', 'user_id', 'userId', 'uid'):
            val = sub.get(key)
            if val is not None and str(val).strip():
                return str(val).strip()
    return ''

def _url_path(url: str) -> str:
    try:
        return urllib.parse.urlparse(url or '').path or ''
    except Exception:
        return url or ''

def _is_sign_in_url(url: str) -> bool:
    low = (url or '').lower()
    path = _url_path(url).lower()
    return 'sign-in' in low or 'sign-up' in low or path.endswith('/sign-in') or path.endswith('/sign-up')

def _location_error(url: str):
    if not url:
        return None
    try:
        q = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)
        err = (q.get('error') or [''])[0].strip()
        return err or None
    except Exception:
        return None

def _is_redirect_status(code: int) -> bool:
    return code in (301, 302, 303, 307, 308)

def _abs_url(base_host: str, loc: str) -> str:
    loc = (loc or '').strip()
    if not loc:
        return ''
    if loc.startswith('http://') or loc.startswith('https://'):
        return loc
    if loc.startswith('/'):
        return str(base_host).rstrip('/') + loc
    return loc

def _is_device_done_url(url: str) -> bool:
    if not url:
        return False
    if _location_error(url):
        return False
    path = _url_path(url).lower()
    low = (url or '').lower()
    return '/oauth2/device/done' in path or path.endswith('/device/done') or 'device/done' in low or ('device_authorized' in low)

def _authorized_body(body: str='') -> bool:
    low = (body or '').lower()
    if '设备已授权' in (body or ''):
        return True
    if 'device authorized' in low or 'device is authorized' in low:
        return True
    if 'you have authorized' in low or 'authorization complete' in low:
        return True
    return False

def _is_consent_ish(url: str, body: str='') -> bool:
    blob = f"{url or ''}\n{body or ''}".lower()
    path = _url_path(url).lower()
    if 'consent' in blob or 'consent' in path:
        return True
    if 'device/verify' in path or 'device/approve' in path:
        return True
    if 'authorize grok' in blob or '请求访问' in (body or '') or 'wants to access' in blob:
        return True
    return False

def _is_bare_account_url(url: str) -> bool:
    if not url:
        return False
    path = _url_path(url).rstrip('/').lower()
    if path in ('/account', '/accounts') or path.endswith('/account'):
        low = (url or '').lower()
        if 'device' in low or 'consent' in low or 'oauth2' in low:
            return False
        return True
    return False

def _is_approve_ok(url: str, body: str='', *, location: str='') -> bool:
    if _location_error(url) or _location_error(location):
        return False
    if _is_device_done_url(location) or _is_device_done_url(url):
        return True
    if _authorized_body(body):
        return True
    return False

def _parse_html_form_fields(html: str) -> dict:
    out = {}
    if not html:
        return out
    try:
        for m in re.finditer('<input[^>]+>', html, flags=re.I):
            tag = m.group(0)
            name_m = re.search('name=["\\\']([^"\\\']+)["\\\']', tag, flags=re.I)
            if not name_m:
                continue
            name = name_m.group(1)
            val_m = re.search('value=["\\\']([^"\\\']*)["\\\']', tag, flags=re.I)
            out[name] = val_m.group(1) if val_m else ''
    except Exception:
        return out
    return out

def _device_form_headers(referer: str='') -> dict:
    origin = globals().get('ACCOUNTS_ORIGIN') or 'https://accounts.x.ai'
    return {'Content-Type': 'application/x-www-form-urlencoded', 'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8', 'Accept-Language': 'en-US,en;q=0.9', 'Origin': origin, 'Referer': referer or str(origin).rstrip('/') + '/', 'Sec-Fetch-Site': 'same-site', 'Sec-Fetch-Mode': 'navigate', 'Sec-Fetch-Dest': 'document', 'Sec-Fetch-User': '?1', 'Upgrade-Insecure-Requests': '1'}

def sso_to_token_device_flow(sso_cookie: str, *, quiet: bool=False, proxy: str='') -> dict | None:
    """SSO cookie -> token（device-flow）。"""
    log = (lambda *a, **k: None) if quiet else print
    sso_cookie = (sso_cookie or '').strip()
    if sso_cookie.lower().startswith('sso='):
        sso_cookie = sso_cookie.split('=', 1)[1].strip()
    sso_cookie = sso_cookie.strip().strip('"').strip("'")
    if not sso_cookie:
        log('  empty sso cookie')
        return None
    sticky = _resolve_sticky_proxy(proxy)
    proxy_kw = _proxy_kwargs(sticky)
    if sticky:
        host = sticky.split('@')[-1] if '@' in sticky else sticky
        log(f'  device-flow proxy sticky={host[:80]}')
    accounts = globals().get('ACCOUNTS_ORIGIN') or 'https://accounts.x.ai'
    user = requests.Session()
    _set_sso_cookies(user, sso_cookie)
    device = requests.Session()
    timeout = _http_timeout()
    try:
        r = user.get(str(accounts).rstrip('/') + '/', impersonate='chrome', timeout=timeout, allow_redirects=True, **proxy_kw)
    except Exception as e:
        log(f'  network error: {e}')
        return None
    final_url = getattr(r, 'url', '') or ''
    if _is_sign_in_url(final_url):
        log(f'  sso invalid (landed {final_url[:120]})')
        return None
    log('  sso ok')
    principal_id = _principal_id_from_sso(sso_cookie)
    if principal_id:
        log(f'  principal_id={principal_id[:48]}')
    else:
        log('  sso jwt=session-only (normal); approve without principal_id field')
    verify_urls = [f'{OIDC_ISSUER}/oauth2/device/verify', f'{accounts}/oauth2/device/verify']
    approve_urls = [f'{OIDC_ISSUER}/oauth2/device/approve', f'{accounts}/oauth2/device/approve']
    retries = _device_flow_retries()
    for attempt in range(1, retries + 1):
        log(f'  Device Flow (referrer={GROK_REFERRER})... (try {attempt}/{retries})')
        dc = request_device_code(session=device, proxy_kw=proxy_kw)
        if not dc:
            if attempt < retries:
                time.sleep(_device_flow_backoff_sec(attempt))
                continue
            return None
        user_code = str(dc.get('user_code') or '').strip()
        device_code = str(dc.get('device_code') or '').strip()
        if not user_code or not device_code:
            log(f'  device/code missing fields: {list(dc.keys())}')
            if attempt < retries:
                time.sleep(_device_flow_backoff_sec(attempt))
                continue
            return None
        log(f'  user_code: {user_code}')
        verification = str(dc.get('verification_uri_complete') or dc.get('verification_uri') or f'{accounts}/oauth2/device?user_code={user_code}').strip()
        if 'user_code=' not in verification and user_code:
            sep = '&' if '?' in verification else '?'
            verification = f'{verification}{sep}user_code={urllib.parse.quote(user_code)}'
        rate_limited = False
        consent_ref = f'{accounts}/oauth2/device/consent?user_code={urllib.parse.quote(user_code)}'
        already_done = False
        verified = False
        try:
            user.get(verification, impersonate='chrome', timeout=timeout, allow_redirects=True, **proxy_kw)
            for v_url in verify_urls:
                r = user.post(v_url, data={'user_code': user_code}, headers=_device_form_headers(referer=verification), impersonate='chrome', timeout=timeout, allow_redirects=False, **proxy_kw)
                body_snip = ''
                try:
                    body_snip = (r.text or '')[:800]
                except Exception:
                    body_snip = ''
                status = int(getattr(r, 'status_code', 0) or 0)
                loc = ''
                try:
                    loc = r.headers.get('Location') or r.headers.get('location') or ''
                except Exception:
                    loc = ''
                loc_abs = _abs_url(accounts, loc) or _abs_url(OIDC_ISSUER, loc)
                err = _location_error(loc_abs)
                if err == 'rate_limited' or _is_rate_limited_payload(body_snip, loc_abs, status):
                    log(f'  verify rate_limited loc={loc_abs[:120]}')
                    rate_limited = True
                    break
                if err:
                    log(f'  verify error={err} loc={loc_abs[:140]}')
                    continue
                if _is_sign_in_url(loc_abs):
                    log(f'  verify->sign-in: {loc_abs[:140]}')
                    return None
                if _is_device_done_url(loc_abs) or _authorized_body(body_snip):
                    log(f'  verify already done loc={loc_abs[:120]}')
                    already_done = True
                    verified = True
                    break
                if _is_redirect_status(status) and loc_abs:
                    if 'consent' in loc_abs.lower() or _is_consent_ish(loc_abs, body_snip):
                        consent_ref = loc_abs
                        log(f'  verify ok -> consent {loc_abs[:120]}')
                        verified = True
                        break
                    if _is_bare_account_url(loc_abs):
                        log(f'  verify bare /account: {loc_abs[:140]}')
                        continue
                    consent_ref = loc_abs
                    log(f'  verify redirect status={status} loc={loc_abs[:120]}')
                    verified = True
                    break
                if status < 400 and (_is_consent_ish('', body_snip) or status == 200):
                    log(f'  verify soft-ok status={status}')
                    verified = True
                    break
            if rate_limited:
                if attempt < retries:
                    time.sleep(_device_flow_backoff_sec(attempt))
                    continue
                return None
            if not verified and (not already_done):
                log('  verify failed — retry device flow')
                if attempt < retries:
                    time.sleep(_device_flow_backoff_sec(attempt))
                    continue
                return None
        except Exception as e:
            log(f'  verify exception: {e}')
            if attempt < retries:
                time.sleep(_device_flow_backoff_sec(attempt))
                continue
            return None
        if already_done:
            approve_ok = True
        else:
            approve_ok = False
            overlay = {'user_code': user_code, 'action': 'allow', 'principal_type': 'User', 'referrer': GROK_REFERRER, 'plan': GROK_PLAN}
            if principal_id:
                overlay['principal_id'] = principal_id
            try:
                cr = user.get(consent_ref, impersonate='chrome', timeout=timeout, allow_redirects=True, **proxy_kw)
                fields = _parse_html_form_fields(getattr(cr, 'text', '') or '')
                if fields:
                    for (k, v) in fields.items():
                        if k.lower() in ('submit',):
                            continue
                        if v:
                            overlay[k] = v
                    overlay['action'] = 'allow'
                    overlay['user_code'] = user_code
                    overlay['referrer'] = GROK_REFERRER
                    overlay['plan'] = GROK_PLAN
                    if principal_id and (not str(overlay.get('principal_id') or '').strip()):
                        overlay['principal_id'] = principal_id
            except Exception as e:
                log(f'  consent form load: {e}')
            go_minimal = {'user_code': user_code, 'action': 'allow'}
            with_referrer = {'user_code': user_code, 'action': 'allow', 'referrer': GROK_REFERRER, 'plan': GROK_PLAN, 'principal_type': 'User'}
            if principal_id:
                with_referrer['principal_id'] = principal_id
            form_variants = [('referrer', with_referrer), ('overlay', overlay), ('go_minimal', go_minimal)]
            try:
                for a_url in approve_urls:
                    for (form_name, form) in form_variants:
                        r = user.post(a_url, data=form, headers=_device_form_headers(referer=consent_ref), impersonate='chrome', timeout=timeout, allow_redirects=False, **proxy_kw)
                        body_snip = ''
                        try:
                            body_snip = (r.text or '')[:1200]
                        except Exception:
                            body_snip = ''
                        status = int(getattr(r, 'status_code', 0) or 0)
                        loc = ''
                        try:
                            loc = r.headers.get('Location') or r.headers.get('location') or ''
                        except Exception:
                            loc = ''
                        loc_abs = _abs_url(OIDC_ISSUER, loc) or _abs_url(accounts, loc)
                        err = _location_error(loc_abs)
                        if err == 'rate_limited' or _is_rate_limited_payload(body_snip, loc_abs, status):
                            log(f'  approve rate_limited loc={loc_abs[:120]}')
                            rate_limited = True
                            break
                        if err:
                            log(f'  approve error={err} form={form_name} loc={loc_abs[:120]}')
                            continue
                        if _is_sign_in_url(loc_abs):
                            log(f'  approve->sign-in: {loc_abs[:140]}')
                            return None
                        if _is_approve_ok(loc_abs, body_snip, location=loc_abs):
                            log(f'  approve ok form={form_name} status={status} Location={loc_abs[:140]}')
                            approve_ok = True
                            break
                        if _is_redirect_status(status) and loc_abs:
                            try:
                                gr = user.get(loc_abs, impersonate='chrome', timeout=timeout, allow_redirects=False, **proxy_kw)
                                gbody = (gr.text or '')[:800]
                                gloc = gr.headers.get('Location') or gr.headers.get('location') or ''
                                gloc_abs = _abs_url(accounts, gloc) or loc_abs
                                if _is_approve_ok(gloc_abs, gbody, location=gloc_abs) or _authorized_body(gbody):
                                    log(f'  approve ok(follow) form={form_name} Location={gloc_abs[:120]}')
                                    approve_ok = True
                                    break
                            except Exception as fe:
                                log(f'  approve follow: {fe}')
                        log(f"  approve incomplete form={form_name} status={status} loc={loc_abs[:120] or '(none)'}")
                    if approve_ok or rate_limited:
                        break
            except Exception as e:
                log(f'  approve exception: {e}')
                if attempt < retries:
                    time.sleep(_device_flow_backoff_sec(attempt))
                    continue
                return None
            if rate_limited:
                if attempt < retries:
                    time.sleep(_device_flow_backoff_sec(attempt))
                    continue
                return None
            if not approve_ok:
                log('  approve missing Location=/device/done — retry')
                if attempt < retries:
                    time.sleep(_device_flow_backoff_sec(attempt))
                    continue
                return None
        time.sleep(1.0)
        token = poll_token(device_code, dc.get('interval', 1), dc.get('expires_in', 1800), timeout=float(os.getenv('GROK2API_SSO_POLL_TIMEOUT', '60') or 60), session=device, proxy_kw=proxy_kw, immediate=True)
        if not token or not token.get('access_token'):
            if attempt < retries:
                log('  token poll empty/invalid_grant — retry device flow')
                time.sleep(_device_flow_backoff_sec(attempt))
                continue
            return None
        token = enrich_token_with_userinfo(token, session=user)
        ref = ''
        try:
            ref = str(decode_jwt_payload(str(token.get('access_token') or '')).get('referrer') or '')
        except Exception:
            ref = ''
        email_hint = token.get('email') or token.get('_email') or ''
        log(f"  access_token (expires_in={token.get('expires_in')}s)" + (' + refresh_token' if token.get('refresh_token') else '') + (f' referrer={ref}' if ref else '') + (f' email={email_hint}' if email_hint else ''))
        return token
    return None

def sso_to_token(sso_cookie: str, *, quiet: bool=False, proxy: str='') -> dict | None:
    """仅 device-flow。"""
    log = (lambda *a, **k: None) if quiet else print
    proxy = (proxy or '').strip()
    log('   OAuth device-flow only...')
    token = sso_to_token_device_flow(sso_cookie, quiet=quiet, proxy=proxy)
    if token and token.get('access_token'):
        token = enrich_token_with_userinfo(token)
        token['_oauth_path'] = 'device_flow'
        return token
    return None
