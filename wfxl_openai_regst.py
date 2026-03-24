import json
import os
import re
import time
import random
import string
import secrets
import hashlib
import base64
import argparse
import asyncio
from datetime import datetime
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple
import urllib.parse
from urllib.parse import urlparse, parse_qs, quote
from html import unescape

import imaplib
import socks
import socket
from email import message_from_string
from email.header import decode_header, make_header
from email.message import Message
from email.policy import default as email_policy
import email as email_lib

from curl_cffi import requests
from curl_cffi import CurlMime

# ================= 配置区开始 =================
# 可选值: "imap" / "freemail" / "cloudflare_temp_email"
EMAIL_API_MODE = "cloudflare_temp_email"

# [公共配置: cloudflare_temp_email / imap 共享]
MAIL_DOMAINS = "domain1.com,domain2.xyz,domain3.net" # 你的域名 (支持逗号分隔多域名随机轮换) 如果只有一个域名就只填一个域名
GPTMAIL_BASE = "https://your-domain.com"     # 你的临时邮箱 后端API 基础地址 结尾不要/，注意：用浏览器打开后端api验证是否可访问

# [模式 "imap" 专属配置] (CF Catch-all 转发接收端)
IMAP_SERVER = "imap.gmail.com"           # 默认为gmail IMAP 服务器地址,QQ为imap.qq.com。不建议用QQ
IMAP_PORT = 993                          # IMAP 端口
IMAP_USER = "" # 接收转发的真实邮箱账号
IMAP_PASS = ""          # 16位应用专用密码，谷歌邮箱要去https://myaccount.google.com/apppasswords这里创建专属应用密码

# [模式 "freemail" 专属]
FREEMAIL_API_URL = "https://your-domain.com"
FREEMAIL_API_TOKEN = ""

# [模式 "cloudflare_temp_email" 专属配置]
ADMIN_AUTH = "" # 你的临时邮箱管理员密码



# [验证码重发配置]
MAX_OTP_RETRIES = 5  # 验证码重试次数

DEFAULT_PROXY = "" #openai注册时代理地址，例子：http://127.0.0.1:7897。如果是国外服务器此项可以不填
# [邮箱代理专项配置]
USE_PROXY_FOR_EMAIL = False  # 【开关】True 表示获取邮箱（谷歌）也用代理，False 表示直连（推荐先试 False）如果是国外服务器此项可以保持False
TOKEN_OUTPUT_DIR = os.getenv("TOKEN_OUTPUT_DIR", "").strip() #目录 默认存放跟脚本一个目录
# ================= 这里不要动 =================
AUTH_URL = "https://auth.openai.com/oauth/authorize"
TOKEN_URL = "https://auth.openai.com/oauth/token"
CLIENT_ID = "app_EMoamEEZ73f0CkXaXp7hrann"
DEFAULT_REDIRECT_URI = f"http://localhost:1455/auth/callback"
DEFAULT_SCOPE = "openid email profile offline_access"
# ================= 这里不要动 =================

# ================= CPA 模式专属配置 =================
ENABLE_CPA_MODE = False  # 【开关】True 开启巡检补货上传，False 则只进行常规无限注册
CPA_API_URL = "http://your-domain.com:8317"   # CPA的api地址
CPA_API_TOKEN = "xxxx"  # CPA登陆密码
MIN_ACCOUNTS_THRESHOLD = 30  # 仓库存量低于此值时触发补货
BATCH_REG_COUNT = 1          # 每次触发补货注册的数量

# 周限额剔除阈值设置 (0-100)
# 设为 80 代表额度剩余低于 80% 就当作死号剔除，设为 0 代表完全耗尽才剔除。
MIN_REMAINING_WEEKLY_PERCENT = 80 
CHECK_INTERVAL_MINUTES = 60  #CPA 仓库巡检的间隔时间，默认每60分钟巡检一次
# ================= CPA 模式专属配置 =================

DEFAULT_CLIPROXY_UA = "codex_cli_rs/0.76.0 (Debian 13.0.0; x86_64) WindowsTerminal"
KNOWN_CLIPROXY_ERROR_LABELS = {
    "usage_limit_reached": "周限额已耗尽",
    "account_deactivated": "账号已停用",
    "insufficient_quota": "额度不足",
    "invalid_api_key": "凭证无效",
    "unsupported_region": "地区不支持",
}
OTP_CODE_PATTERN = r"(?<!\d)(\d{6})(?!\d)"
# ================= 配置区结束 =================

def _load_dotenv(path: str = ".env") -> None:
    if not os.path.exists(path): return
    try:
        with open(path, "r", encoding="utf-8") as handle:
            for raw in handle:
                line = raw.strip()
                if not line or line.startswith("#") or "=" not in line: continue
                key, value = line.split("=", 1)
                key = key.strip()
                if not key or key in os.environ: continue
                value = value.strip()
                if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
                    value = value[1:-1]
                os.environ[key] = value
    except Exception: pass

_load_dotenv()

def ts() -> str:
    """获取当前时间戳字符串"""
    return datetime.now().strftime("%H:%M:%S")

def _ssl_verify() -> bool:
    flag = os.getenv("OPENAI_SSL_VERIFY", "1").strip().lower()
    return flag not in {"0", "false", "no", "off"}

def _skip_net_check() -> bool:
    flag = os.getenv("SKIP_NET_CHECK", "0").strip().lower()
    return flag in {"1", "true", "yes", "on"}

def get_email_and_token(proxies: Any = None) -> tuple:
    """兼容三模式的邮箱获取逻辑 (支持多域名随机轮换)"""
    mail_proxies = proxies if USE_PROXY_FOR_EMAIL else None
    letters = ''.join(random.choices(string.ascii_lowercase, k=5))
    digits = ''.join(random.choices(string.digits, k=random.randint(1, 3)))
    suffix = ''.join(random.choices(string.ascii_lowercase, k=random.randint(1, 3)))
    prefix = letters + digits + suffix
    
    if EMAIL_API_MODE == "freemail":
        headers = {"Authorization": f"Bearer {FREEMAIL_API_TOKEN}", "Content-Type": "application/json"}
        api_params = {}

        try:
            domain_res = requests.get(
                f"{FREEMAIL_API_URL.rstrip('/')}/api/domains",
                headers=headers, 
                proxies=mail_proxies, 
                verify=_ssl_verify(), 
                timeout=15
            )
            raw_text = domain_res.text.strip()
            
            if raw_text.upper() == "OK" or not raw_text.startswith("["):
                api_params["domainIndex"] = 0
            else:
                domains_list = domain_res.json()
                if isinstance(domains_list, list) and len(domains_list) > 0:
                    random_domain_index = random.randint(0, len(domains_list) - 1)
                    api_params["domainIndex"] = random_domain_index
        except Exception as e:
            print(f"[{ts()}] [WARNING] 探测 Freemail 域名列表时出现小插曲: {e}。将直接使用默认参数生成。")
            
        for attempt in range(5):
            try:
                res = requests.get(
                    f"{FREEMAIL_API_URL.rstrip('/')}/api/generate",
                    params=api_params,
                    headers=headers, proxies=mail_proxies, verify=_ssl_verify(), timeout=15
                )
                res.raise_for_status()
                data = res.json()
                if data and data.get("email"):
                    email = data["email"].strip()
                    print(f"[{ts()}] [INFO] 成功通过 Freemail 生成临时邮箱: {email}")
                    return email, ""
                else:
                    print(f"[{ts()}] [WARNING] Freemail 邮箱生成失败 (尝试 {attempt + 1}/5): {res.text}")
                    time.sleep(1)
            except Exception as e:
                print(f"[{ts()}] [ERROR] Freemail 邮箱注册异常，准备重试: {e}")
                time.sleep(2)
        return None, None

    domain_list = [d.strip() for d in MAIL_DOMAINS.split(",") if d.strip()]
    if not domain_list:
        print(f"[{ts()}] [ERROR] MAIL_DOMAINS 配置为空，无法生成邮箱！")
        return None, None
        
    selected_domain = random.choice(domain_list)
    email_str = f"{prefix}@{selected_domain}"
    
    if EMAIL_API_MODE in ["imap"]:
        print(f"[{ts()}] [INFO] 成功生成临时域名邮箱: {email_str}")
        return email_str, ""

    headers = {"x-admin-auth": ADMIN_AUTH, "Content-Type": "application/json"}
    body = {"enablePrefix": False, "name": prefix, "domain": selected_domain}
    
    for attempt in range(5):
        try:
            res = requests.post(
                f"{GPTMAIL_BASE}/admin/new_address", headers=headers, json=body,
                proxies=mail_proxies, verify=_ssl_verify(), timeout=15
            )
            res.raise_for_status()
            data = res.json()
            if data and data.get("address"):
                email = data["address"].strip()
                jwt = data.get("jwt", "").strip()
                print(f"[{ts()}] [INFO] 成功获取临时邮箱: {email}")
                return email, jwt
            else:
                print(f"[{ts()}] [WARNING] 邮箱申请失败 (尝试 {attempt + 1}/5): {res.text}")
                time.sleep(1)
        except Exception as e:
            print(f"[{ts()}] [ERROR] 邮箱注册网络异常，准备重试: {e}")
            time.sleep(2)
            
    return None, None

def _decode_mime_header(value: str) -> str:
    if not value: return ""
    try: return str(make_header(decode_header(value)))
    except Exception: return value

def _extract_body_from_message(message: Message) -> str:
    parts = []
    if message.is_multipart():
        for part in message.walk():
            if part.get_content_maintype() == "multipart": continue
            content_type = (part.get_content_type() or "").lower()
            if content_type not in ("text/plain", "text/html"): continue
            try:
                payload = part.get_payload(decode=True)
                charset = part.get_content_charset() or "utf-8"
                text = payload.decode(charset, errors="replace") if payload else ""
            except Exception:
                try: text = part.get_content()
                except Exception: text = ""
            if content_type == "text/html": text = re.sub(r"<[^>]+>", " ", text)
            parts.append(text)
    else:
        try:
            payload = message.get_payload(decode=True)
            charset = message.get_content_charset() or "utf-8"
            body = payload.decode(charset, errors="replace") if payload else ""
        except Exception:
            try: body = message.get_content()
            except Exception: body = str(message.get_payload() or "")
        if "html" in (message.get_content_type() or "").lower():
            body = re.sub(r"<[^>]+>", " ", body)
        parts.append(body)
    return unescape("\n".join(part for part in parts if part).strip())

def _extract_mail_fields(mail: dict) -> dict:
    sender = str(mail.get("source") or mail.get("from") or mail.get("from_address") or mail.get("fromAddress") or "").strip()
    subject = str(mail.get("subject") or mail.get("title") or "").strip()
    body_text = str(mail.get("text") or mail.get("body") or mail.get("content") or mail.get("html") or "").strip()
    raw = str(mail.get("raw") or "").strip()
    if raw:
        try:
            message = message_from_string(raw, policy=email_policy)
            sender = sender or _decode_mime_header(message.get("From", ""))
            subject = subject or _decode_mime_header(message.get("Subject", ""))
            parsed_body = _extract_body_from_message(message)
            if parsed_body: body_text = f"{body_text}\n{parsed_body}".strip() if body_text else parsed_body
        except Exception:
            body_text = f"{body_text}\n{raw}".strip() if body_text else raw

    body_text = unescape(re.sub(r"<[^>]+>", " ", body_text))
    return {"sender": sender, "subject": subject, "body": body_text, "raw": raw}


def _extract_otp_code(content: str) -> str:
    """提取验证码的增强正则"""
    if not content: return ""
    patterns = [
        r"(?i)Your ChatGPT code is\s*(\d{6})",
        r"(?i)ChatGPT code is\s*(\d{6})",
        r"(?i)verification code to continue:\s*(\d{6})",
        r"(?i)Subject:.*?(\d{6})",
    ]
    for pattern in patterns:
        match = re.search(pattern, content)
        if match:
            return match.group(1)
    fallback = re.search(r"(?<!\d)(\d{6})(?!\d)", content)
    return fallback.group(1) if fallback else ""

class ProxiedIMAP4_SSL(imaplib.IMAP4_SSL):
    def __init__(self, host, port, proxy_host, proxy_port, proxy_type, **kwargs):
        self.proxy_host = proxy_host
        self.proxy_port = proxy_port
        self.proxy_type = proxy_type
        self.timeout_val = kwargs.pop('timeout', 60)
        super().__init__(host, port, **kwargs)

    def _create_socket(self, timeout):
        sock = socks.socksocket()
        sock.set_proxy(self.proxy_type, self.proxy_host, self.proxy_port)
        sock.settimeout(self.timeout_val)
        sock.connect((self.host, self.port))
        return sock

def get_oai_code(email: str, jwt: str = "", proxies: Any = None, processed_mail_ids: set = None, pattern: str = OTP_CODE_PATTERN) -> str:
    """基于 Mail ID 过滤的验证码提取 (支持 JWT 或 Admin 双重鉴权)"""
    mail_proxies = proxies if USE_PROXY_FOR_EMAIL else None
    base_url = GPTMAIL_BASE.rstrip('/')
    print(f"[{ts()}] [INFO] 等待接收验证码 ({email}) ", end="", flush=True)

    if processed_mail_ids is None:
        processed_mail_ids = set()
    def create_imap_conn():
        if USE_PROXY_FOR_EMAIL and DEFAULT_PROXY and IMAP_SERVER.lower() == "imap.gmail.com":
            try:
                import socks
                import socket
            except ImportError:
                print(f"\n[{ts()}] [WARNING] 未安装 pysocks，回退到直连。")
                return imaplib.IMAP4_SSL(IMAP_SERVER, IMAP_PORT, timeout=60)
            
            print(f"\n[{ts()}] [INFO] 正在为 IMAP 注入底层代理穿透...")
            try:
                parsed = urlparse(DEFAULT_PROXY)
                proxy_host = parsed.hostname
                proxy_port = parsed.port or 80
                proxy_type = socks.HTTP if parsed.scheme.lower() in ['http', 'https'] else socks.SOCKS5
                
                original_socket = socket.socket
                
                try:
                    socks.set_default_proxy(proxy_type, proxy_host, proxy_port)
                    socket.socket = socks.socksocket
                    conn = imaplib.IMAP4_SSL(IMAP_SERVER, IMAP_PORT, timeout=20)
                    return conn
                finally:
                    socket.socket = original_socket
                    
            except Exception as e:
                print(f"\n[{ts()}] [ERROR] IMAP 代理注入失败: {e}，尝试回退到直连。")
                return imaplib.IMAP4_SSL(IMAP_SERVER, IMAP_PORT, timeout=15)
        else:
            return imaplib.IMAP4_SSL(IMAP_SERVER, IMAP_PORT, timeout=15)
    mail_conn = None
    if EMAIL_API_MODE == "imap":
        try:
            mail_conn = create_imap_conn()
            clean_pass = IMAP_PASS.replace(" ", "")
            mail_conn.login(IMAP_USER, clean_pass)
        except Exception as e:
            print(f"\n[{ts()}] [ERROR] IMAP 初始登录失败: {e}")
            mail_conn = None
    start_time = time.time()
    for attempt in range(20):
        try:
            if EMAIL_API_MODE == "imap":
                if not mail_conn:
                    try:
                        mail_conn = imaplib.IMAP4_SSL(IMAP_SERVER, IMAP_PORT, timeout=15)
                        mail_conn.login(IMAP_USER, IMAP_PASS.replace(" ", ""))
                    except Exception as e:
                        time.sleep(5)
                        continue

                folders_to_check = ['INBOX', 'Junk', '"Junk Email"', 'Spam', '"[Gmail]/Spam"', '"垃圾邮件"']
                found_in_loop = False
                
                for folder in folders_to_check:
                    try:
                        mail_conn.noop()
                        status, _ = mail_conn.select(folder, readonly=True)
                        if status != 'OK': continue
                        
                        search_query = f'(UNSEEN FROM "openai.com" TO "{email}")'
                        status, messages = mail_conn.search(None, search_query)
                        
                        if status == 'OK' and messages[0]:
                            mail_ids = messages[0].split()
                            
                            for mail_id in reversed(mail_ids):
                                if mail_id in processed_mail_ids:
                                    continue
                                
                                res, data = mail_conn.fetch(mail_id, '(RFC822)')
                                for response_part in data:
                                    if isinstance(response_part, tuple):
                                        msg = email_lib.message_from_bytes(response_part[1])
                                        
                                        subject = str(msg.get("Subject", ""))
                                        if "=?UTF-8?" in subject:
                                            from email.header import decode_header
                                            dh = decode_header(subject)
                                            subject = "".join([str(t[0].decode(t[1] or 'utf-8') if isinstance(t[0], bytes) else t[0]) for t in dh])

                                        content = ""
                                        if msg.is_multipart():
                                            for part in msg.walk():
                                                if part.get_content_type() == "text/plain":
                                                    try: content += part.get_payload(decode=True).decode('utf-8', 'ignore')
                                                    except: pass
                                        else:
                                            content = msg.get_payload(decode=True).decode('utf-8', 'ignore')

                                        to_header = str(msg.get("To", "")).lower()
                                        delivered_to = str(msg.get("Delivered-To", "")).lower()
                                        target_email = email.lower()
                                        
                                        if target_email not in to_header and target_email not in delivered_to and target_email not in content.lower():
                                            processed_mail_ids.add(mail_id) 
                                            continue 
                                        
                                        code = _extract_otp_code(f"{subject}\n{content}")
                                        if code:
                                            processed_mail_ids.add(mail_id)
                                            print(f"\n[{ts()}] [SUCCESS] 验证码: {code}")
                                            try:
                                                mail_conn.logout()
                                            except Exception:
                                                pass
                                            return code
                                        else:
                                            processed_mail_ids.add(mail_id)
                            
                            found_in_loop = True
                            break
                    except imaplib.IMAP4.abort as e:
                        print(f"\n[{ts()}] [WARNING] IMAP 连接断开，将在下次循环重连...")
                        mail_conn = None
                        break
                    except Exception as e:
                        if "Spam" in folder:
                            print(f"\n[{ts()}] [DEBUG] 访问垃圾箱失败: {e}")
                
                if not found_in_loop:
                    print(".", end="", flush=True)
            elif EMAIL_API_MODE == "freemail":
                headers = {"Authorization": f"Bearer {FREEMAIL_API_TOKEN}", "Content-Type": "application/json"}
                res = requests.get(
                    f"{FREEMAIL_API_URL.rstrip('/')}/api/emails",
                    params={"mailbox": email, "limit": 20},
                    headers=headers,
                    proxies=mail_proxies, verify=_ssl_verify(), timeout=15,
                )

                if res.status_code == 200:
                    raw_data = res.json()
                    
                    if isinstance(raw_data, dict):
                        emails_list = raw_data.get("data") or raw_data.get("emails") or raw_data.get("messages") or raw_data.get("results") or []
                    else:
                        emails_list = raw_data
                        
                    if not isinstance(emails_list, list):
                        emails_list = []

                    for mail in emails_list:
                        mail_id = str(mail.get("id") or mail.get("timestamp") or mail.get("subject") or "")
                        if not mail_id or mail_id in processed_mail_ids:
                            continue
                        
                        subject_text = str(mail.get("subject") or mail.get("title") or "")
                        code = ""
                        
                        code_match = re.search(r'(?<!\d)(\d{6})(?!\d)', subject_text)
                        if code_match:
                            code = code_match.group(1)
                        
                        if not code:
                            code = str(mail.get("code") or mail.get("verification_code") or "")
                        
                        if not code:
                            try:
                                detail_res = requests.get(
                                    f"{FREEMAIL_API_URL.rstrip('/')}/api/email/{mail_id}",
                                    headers=headers,
                                    proxies=mail_proxies, verify=_ssl_verify(), timeout=15,
                                )
                                if detail_res.status_code == 200:
                                    detail = detail_res.json()
                                    content = "\n".join(filter(None, [
                                        str(detail.get("subject") or ""),
                                        str(detail.get("content") or ""),
                                        str(detail.get("html_content") or ""),
                                    ]))
                                    code = _extract_otp_code(content)
                            except Exception:
                                pass
                        
                        if code:
                            processed_mail_ids.add(mail_id)
                            print(f" 提取成功: {code}")
                            return code
            else:
                if jwt:
                    res = requests.get(
                        f"{base_url}/api/mails",
                        params={"limit": 20, "offset": 0},
                        headers={"Authorization": "Bearer " + jwt, "Content-Type": "application/json", "Accept": "application/json"},
                        proxies=mail_proxies, verify=_ssl_verify(), timeout=15,
                    )
                else:
                    res = requests.get(
                        f"{base_url}/admin/mails",
                        params={"limit": 20, "offset": 0, "address": email},
                        headers={"x-admin-auth": ADMIN_AUTH},
                        proxies=mail_proxies, verify=_ssl_verify(), timeout=15,
                    )
                
                if res.status_code != 200:
                    print(f"\n[{ts()}] [ERROR] 邮箱接口请求失败 (HTTP {res.status_code}): {res.text}")
                    time.sleep(3)
                    continue

                results = res.json().get("results")
                if results and len(results) > 0:
                    for mail in results:
                        mail_id = mail.get("id")
                        if not mail_id or mail_id in processed_mail_ids:
                            continue

                        parsed = _extract_mail_fields(mail)
                        content = f"{parsed['subject']}\n{parsed['body']}".strip()

                        if "openai" not in parsed["sender"].lower() and "openai" not in content.lower():
                            continue

                        match = re.search(pattern, content)
                        if match:
                            code = match.group(1)
                            processed_mail_ids.add(mail_id)
                            print(f" 提取成功: {code}")
                            return code
                    print(".", end="", flush=True)
                else:
                    print(".", end="", flush=True)
        except Exception as e:
            print(".", end="", flush=True)

        time.sleep(3)

    print(f"\n[{ts()}] [ERROR] 接收验证码超时")
    return ""

def _b64url_no_pad(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")

def _sha256_b64url_no_pad(s: str) -> str:
    return _b64url_no_pad(hashlib.sha256(s.encode("ascii")).digest())

def _random_state(nbytes: int = 16) -> str:
    return secrets.token_urlsafe(nbytes)

def _pkce_verifier() -> str:
    return secrets.token_urlsafe(64)

def _parse_callback_url(callback_url: str) -> Dict[str, Any]:
    candidate = callback_url.strip()
    if not candidate: return {"code": "", "state": "", "error": "", "error_description": ""}
    if "://" not in candidate:
        if candidate.startswith("?"): candidate = f"http://localhost{candidate}"
        elif any(ch in candidate for ch in "/?#") or ":" in candidate: candidate = f"http://{candidate}"
        elif "=" in candidate: candidate = f"http://localhost/?{candidate}"
    parsed = urllib.parse.urlparse(candidate)
    query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    fragment = urllib.parse.parse_qs(parsed.fragment, keep_blank_values=True)
    for key, values in fragment.items():
        if key not in query or not query[key] or not (query[key][0] or "").strip(): query[key] = values
    def get1(k: str) -> str:
        v = query.get(k, [""]); return (v[0] or "").strip()
    code = get1("code"); state = get1("state"); error = get1("error"); error_description = get1("error_description")
    if code and not state and "#" in code: code, state = code.split("#", 1)
    if not error and error_description: error, error_description = error_description, ""
    return {"code": code, "state": state, "error": error, "error_description": error_description}

def _jwt_claims_no_verify(id_token: str) -> Dict[str, Any]:
    if not id_token or id_token.count(".") < 2: return {}
    payload_b64 = id_token.split(".")[1]
    pad = "=" * ((4 - (len(payload_b64) % 4)) % 4)
    try:
        payload = base64.urlsafe_b64decode((payload_b64 + pad).encode("ascii"))
        return json.loads(payload.decode("utf-8"))
    except Exception: return {}

def _decode_jwt_segment(seg: str) -> Dict[str, Any]:
    raw = (seg or "").strip()
    if not raw: return {}
    pad = "=" * ((4 - (len(raw) % 4)) % 4)
    try:
        decoded = base64.urlsafe_b64decode((raw + pad).encode("ascii"))
        return json.loads(decoded.decode("utf-8"))
    except Exception: return {}

def _to_int(v: Any) -> int:
    try: return int(v)
    except (TypeError, ValueError): return 0

def _post_form(url: str, data: Dict[str, str], proxies: Any = None, timeout: int = 30, retries: int = 3) -> Dict[str, Any]:
    """带有自动重试机制的表单提交 (用于对抗 TLS 闪断和代理掉线)"""
    last_error: Optional[Exception] = None
    for attempt in range(retries + 1):
        try:
            resp = requests.post(
                url, 
                data=data, 
                headers={"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"},
                proxies=proxies,
                verify=_ssl_verify(),
                timeout=timeout,
                impersonate="chrome110"
            )
            if resp.status_code != 200: 
                raise RuntimeError(f"token exchange failed: {resp.status_code}: {resp.text}")
            return resp.json()
        except Exception as exc:
            last_error = exc
            if attempt < retries:
                print(f"\n[{ts()}] [WARNING] 换取 Token 时遇到网络异常: {exc}。")
                print(f"[{ts()}] [INFO] 正在给代理缓冲时间，准备第 {attempt + 1}/{retries} 次重试...")
                time.sleep(2 * (attempt + 1))
            else:
                break
                
    raise RuntimeError(f"token exchange request failed after {retries} retries: {last_error}") from last_error

def _post_with_retry(
    session: requests.Session, url: str, *, headers: Dict[str, Any], data: Any = None,
    json_body: Any = None, proxies: Any = None, timeout: int = 30, retries: int = 2
) -> Any:
    last_error: Optional[Exception] = None
    for attempt in range(retries + 1):
        try:
            if json_body is not None:
                return session.post(url, headers=headers, json=json_body, proxies=proxies, verify=_ssl_verify(), timeout=timeout)
            return session.post(url, headers=headers, data=data, proxies=proxies, verify=_ssl_verify(), timeout=timeout)
        except Exception as e:
            last_error = e
            if attempt >= retries: break
            time.sleep(2 * (attempt + 1))
    if last_error: raise last_error
    raise RuntimeError("Request failed without exception")

@dataclass(frozen=True)
class OAuthStart:
    auth_url: str; state: str; code_verifier: str; redirect_uri: str

def generate_oauth_url(*, redirect_uri: str = DEFAULT_REDIRECT_URI, scope: str = DEFAULT_SCOPE) -> OAuthStart:
    state = _random_state(); code_verifier = _pkce_verifier()
    code_challenge = _sha256_b64url_no_pad(code_verifier)
    params = {"client_id": CLIENT_ID, "response_type": "code", "redirect_uri": redirect_uri, "scope": scope, "state": state, "code_challenge": code_challenge, "code_challenge_method": "S256", "prompt": "login", "id_token_add_organizations": "true", "codex_cli_simplified_flow": "true"}
    auth_url = f"{AUTH_URL}?{urllib.parse.urlencode(params)}"
    return OAuthStart(auth_url=auth_url, state=state, code_verifier=code_verifier, redirect_uri=redirect_uri)

def submit_callback_url(*, callback_url: str, expected_state: str, code_verifier: str, redirect_uri: str = DEFAULT_REDIRECT_URI, proxies: Any = None) -> str:
    cb = _parse_callback_url(callback_url)
    if cb["error"]: raise RuntimeError(f"oauth error: {cb['error']}: {cb['error_description']}".strip())
    if not cb["code"]: raise ValueError("callback url missing ?code=")
    if not cb["state"]: raise ValueError("callback url missing ?state=")
    if cb["state"] != expected_state: raise ValueError("state mismatch")
    
    token_resp = _post_form(
        TOKEN_URL, 
        {"grant_type": "authorization_code", "client_id": CLIENT_ID, "code": cb["code"], "redirect_uri": redirect_uri, "code_verifier": code_verifier}, 
        proxies=proxies
    )

    access_token = (token_resp.get("access_token") or "").strip()
    refresh_token = (token_resp.get("refresh_token") or "").strip()
    id_token = (token_resp.get("id_token") or "").strip()
    expires_in = _to_int(token_resp.get("expires_in"))

    claims = _jwt_claims_no_verify(id_token)
    email = str(claims.get("email") or "").strip()
    auth_claims = claims.get("https://api.openai.com/auth") or {}
    account_id = str(auth_claims.get("chatgpt_account_id") or "").strip()

    now = int(time.time())
    expired_rfc3339 = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now + max(expires_in, 0)))
    now_rfc3339 = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now))

    config = {
        "id_token": id_token, "access_token": access_token, "refresh_token": refresh_token,
        "account_id": account_id, "last_refresh": now_rfc3339, "email": email,
        "type": "codex", "expired": expired_rfc3339,
    }
    return json.dumps(config, ensure_ascii=False, separators=(",", ":"))

def _generate_password(length: int = 16) -> str:
    upper = random.choices(string.ascii_uppercase, k=2)
    lower = random.choices(string.ascii_lowercase, k=2)
    digits = random.choices(string.digits, k=2)
    specials = random.choices("!@#$%&*", k=2)
    rest_len = length - 8
    pool = string.ascii_letters + string.digits + "!@#$%&*"
    rest = random.choices(pool, k=rest_len)
    chars = upper + lower + digits + specials + rest
    random.shuffle(chars)
    return "".join(chars)

FIRST_NAMES = [
    "James", "John", "Robert", "Michael", "William", "David", "Richard", "Joseph", "Thomas", "Charles",
    "Emma", "Olivia", "Ava", "Isabella", "Sophia", "Mia", "Charlotte", "Amelia", "Harper", "Evelyn",
    "Alex", "Jordan", "Taylor", "Morgan", "Casey", "Riley", "Jamie", "Avery", "Quinn", "Skyler",
    "Liam", "Noah", "Ethan", "Lucas", "Mason", "Oliver", "Elijah", "Aiden", "Henry", "Sebastian",
    "Grace", "Lily", "Chloe", "Zoey", "Nora", "Aria", "Hazel", "Aurora", "Stella", "Ivy"
]

def generate_random_user_info() -> dict:
    """生成随机用户信息 (18-45岁)"""
    name = random.choice(FIRST_NAMES)
    current_year = datetime.now().year
    birth_year = random.randint(current_year - 45, current_year - 18)
    birth_month = random.randint(1, 12)
    
    if birth_month in [1, 3, 5, 7, 8, 10, 12]:
        birth_day = random.randint(1, 31)
    elif birth_month in [4, 6, 9, 11]:
        birth_day = random.randint(1, 30)
    else:
        birth_day = random.randint(1, 28)

    birthdate = f"{birth_year}-{birth_month:02d}-{birth_day:02d}"

    return {
        "name": name,
        "birthdate": birthdate
    }

def run(proxy: Optional[str]) -> tuple:
    processed_mails = set()
    proxies = {"http": proxy, "https": proxy} if proxy else None
    s = requests.Session(proxies=proxies, impersonate="chrome110")

    if not _skip_net_check():
        try:
            trace = s.get("https://cloudflare.com/cdn-cgi/trace", proxies=proxies, verify=_ssl_verify(), timeout=10).text
            loc = (re.search(r"^loc=(.+)$", trace, re.MULTILINE) or [None, None])[1]
            if loc in ("CN", "HK"): raise RuntimeError("当前代理所在地不支持 OpenAI 服务 (CN/HK)")
            print(f"[{ts()}] [INFO] 代理节点检测通过 (所在地: {loc})")
        except Exception as e:
            print(f"[{ts()}] [ERROR] 代理网络检查失败: {e}")
            return None, None

    email, email_jwt = get_email_and_token(proxies)
    if not email: return None, None

    oauth = generate_oauth_url()
    try:
        s.get(oauth.auth_url, proxies=proxies, verify=True, timeout=15)
        did = s.cookies.get("oai-did")

        sen_resp = requests.post(
            "https://sentinel.openai.com/backend-api/sentinel/req",
            headers={"origin": "https://sentinel.openai.com", "content-type": "text/plain;charset=UTF-8"},
            data=f'{{"p":"","id":"{did}","flow":"authorize_continue"}}',
            proxies=proxies, impersonate="chrome110", verify=_ssl_verify(), timeout=15
        )
        if sen_resp.status_code != 200:
            print(f"[{ts()}] [ERROR] Sentinel 风控校验失败 (HTTP {sen_resp.status_code})")
            return None, None

        sentinel = f'{{"p": "", "t": "", "c": "{sen_resp.json()["token"]}", "id": "{did}", "flow": "authorize_continue"}}'

        signup_resp = s.post(
            "https://auth.openai.com/api/accounts/authorize/continue",
            headers={"openai-sentinel-token": sentinel, "content-type": "application/json"},
            data=f'{{"username":{{"value":"{email}","kind":"email"}},"screen_hint":"signup"}}',
            proxies=proxies, verify=_ssl_verify()
        )
        if signup_resp.status_code == 403:
            print(f"[{ts()}] [WARNING] 注册请求触发 403 拦截，稍作等待后重试...")
            return "retry_403", None
        elif signup_resp.status_code != 200:
            print(f"[{ts()}] [ERROR] 注册表单提交失败，中断当前流程")
            return None, None

        password = _generate_password()
        print(f"[{ts()}] [INFO] 提交注册信息 (密码: {password[:4]}****)")
        pwd_resp = s.post(
            "https://auth.openai.com/api/accounts/user/register",
            headers={"openai-sentinel-token": sentinel, "content-type": "application/json"},
            json={"password": password, "username": email},
            proxies=proxies, verify=_ssl_verify()
        )
        if pwd_resp.status_code != 200:
            print(f"[{ts()}] [ERROR] 密码注册环节异常: {pwd_resp.text}")
            return None, None

        try:
            reg_json = pwd_resp.json()
            need_otp = "verify" in reg_json.get("continue_url", "") or "otp" in (reg_json.get("page") or {}).get("type", "")
        except Exception:
            need_otp = False

        if need_otp:
            otp_url = pwd_resp.json().get("continue_url", "")
            if otp_url:
                _post_with_retry(s, otp_url if otp_url.startswith("http") else f"https://auth.openai.com{otp_url}", headers={"openai-sentinel-token": sentinel, "content-type": "application/json"}, json_body={}, proxies=proxies, timeout=30)
            
            code = ""
            for resend_attempt in range(max(1, MAX_OTP_RETRIES)):
                if resend_attempt > 0:
                    print(f"\n[{ts()}] [INFO] 正在重试 {resend_attempt}/5...")
                    try:
                        _post_with_retry(s, "https://auth.openai.com/api/accounts/email-otp/resend", headers={"openai-sentinel-token": sentinel, "content-type": "application/json"}, json_body={}, proxies=proxies, timeout=15)
                        time.sleep(2)  
                    except Exception as e:
                        print(f"[{ts()}] [WARNING] 重新发送请求异常: {e}")
                
                code = get_oai_code(email, jwt=email_jwt, proxies=proxies, processed_mail_ids=processed_mails)
                
                if code:
                    break

            if not code:
                print(f"[{ts()}] [ERROR] 重试次数上限，丢弃当前邮箱。")
                return None, None
            
            code_resp = _post_with_retry(s, "https://auth.openai.com/api/accounts/email-otp/validate", headers={"openai-sentinel-token": sentinel, "content-type": "application/json"}, json_body={"code": code}, proxies=proxies)
            if code_resp.status_code != 200:
                print(f"[{ts()}] [ERROR] 验证码校验未通过: {code_resp.text}")
                return None, None

        user_info = generate_random_user_info()
        print(f"[{ts()}] [INFO] 初始化账户基础信息 (昵称: {user_info['name']}, 生日: {user_info['birthdate']})...")
        create_account_resp = _post_with_retry(s, "https://auth.openai.com/api/accounts/create_account", headers={"content-type": "application/json"}, data=json.dumps(user_info), proxies=proxies)
        
        if create_account_resp.status_code != 200:
            print(f"[{ts()}] [ERROR] 账户创建受阻: {create_account_resp.text}")
            return None, None

        print(f"[{ts()}] [INFO] 基础信息建立完毕，执行静默风控重登录...")
        s.cookies.clear()
        
        oauth = generate_oauth_url()
        try:
            s.get(oauth.auth_url, proxies=proxies, verify=True, timeout=15)
            new_did = s.cookies.get("oai-did")
            sen_token2 = requests.post("https://sentinel.openai.com/backend-api/sentinel/req", headers={"origin": "https://sentinel.openai.com", "content-type": "text/plain;charset=UTF-8"}, data=f'{{"p":"","id":"{new_did}","flow":"authorize_continue"}}', proxies=proxies, impersonate="chrome110", verify=_ssl_verify(), timeout=15).json().get("token", "")
            sentinel2 = f'{{"p": "", "t": "", "c": "{sen_token2}", "id": "{new_did}", "flow": "authorize_continue"}}'

            s.post("https://auth.openai.com/api/accounts/authorize/continue", headers={"openai-sentinel-token": sentinel2, "content-type": "application/json"}, data=f'{{"username":{{"value":"{email}","kind":"email"}},"screen_hint":"login"}}', proxies=proxies, verify=_ssl_verify())
            pwd_login_resp = s.post("https://auth.openai.com/api/accounts/password/verify", headers={"openai-sentinel-token": sentinel2, "content-type": "application/json"}, json={"password": password}, proxies=proxies, verify=_ssl_verify())

            pwd_json = pwd_login_resp.json() if pwd_login_resp.status_code == 200 else {}
            if pwd_json.get("page", {}).get("type", "") == "email_otp_verification" or "verify" in str(pwd_json.get("continue_url", "")):
                code2 = ""
                for resend_attempt in range(max(1, MAX_OTP_RETRIES)):
                    if resend_attempt > 0:
                        print(f"\n[{ts()}] [INFO] 正在重试 {resend_attempt}/5...")
                        try:
                            _post_with_retry(s, "https://auth.openai.com/api/accounts/email-otp/resend", headers={"openai-sentinel-token": sentinel2, "content-type": "application/json"}, json_body={}, proxies=proxies, timeout=15)
                            time.sleep(2)
                        except Exception as e:
                            print(f"[{ts()}] [WARNING] 重新发送请求异常: {e}")
                    
                    code2 = get_oai_code(email, jwt=email_jwt, proxies=proxies, processed_mail_ids=processed_mails)
                    
                    if code2:
                        break 
                if not code2:
                    print(f"[{ts()}] [ERROR] 重新发送后依然未收到验证码，彻底放弃。")
                    return None, None
                    
                code2_resp = _post_with_retry(s, "https://auth.openai.com/api/accounts/email-otp/validate", headers={"openai-sentinel-token": sentinel2, "content-type": "application/json"}, json_body={"code": code2}, proxies=proxies)
                if code2_resp.status_code != 200:
                    print(f"[{ts()}] [ERROR] 二次安全验证 OTP 校验失败: {code2_resp.text}")
                    return None, None
        except Exception as e:
            print(f"[{ts()}] [ERROR] 风控重登录流程发生异常: {e}")
            return None, None

        auth_cookie = s.cookies.get("oai-client-auth-session")
        if not auth_cookie:
            print(f"[{ts()}] [ERROR] 授权 Token 获取失败")
            return None, None

        segments = auth_cookie.split(".")
        auth_json = _decode_jwt_segment(segments[1]) if len(segments) >= 2 else {}
        if not auth_json.get("workspaces"): auth_json = _decode_jwt_segment(segments[0])
        
        workspace_id = str((auth_json.get("workspaces") or [{}])[0].get("id", "")).strip()
        select_resp = _post_with_retry(s, "https://auth.openai.com/api/accounts/workspace/select", headers={"content-type": "application/json"}, data=f'{{"workspace_id":"{workspace_id}"}}', proxies=proxies)

        if select_resp.status_code != 200:
            print(f"[{ts()}] [ERROR] 工作区(Workspace)绑定失败 (HTTP {select_resp.status_code})。可能触发了最后一步的 IP 风控！")
            return None, None
        try:
            select_data = select_resp.json()
        except Exception:
            print(f"[{ts()}] [ERROR] 遭到了非预期拦截！服务器返回了空数据或 HTML，而不是 JSON。")
            return None, None
            
        current_url = str((select_data or {}).get("continue_url", "")).strip()
        for _ in range(15):
            f_resp = s.get(current_url, allow_redirects=False, proxies=proxies, verify=_ssl_verify(), timeout=15)
            if f_resp.status_code in [301, 302, 303, 307, 308]:
                next_url = urllib.parse.urljoin(current_url, f_resp.headers.get("Location") or "")
            elif f_resp.status_code == 200:
                meta_match = re.search(r'content=["\']\d+;\s*url=([^"\']+)["\']', f_resp.text, re.IGNORECASE)
                next_url = urllib.parse.urljoin(current_url, meta_match.group(1)) if meta_match else ""
                if not next_url: break
            else: break

            if "code=" in next_url and "state=" in next_url:
                return submit_callback_url(callback_url=next_url, code_verifier=oauth.code_verifier, redirect_uri=oauth.redirect_uri, expected_state=oauth.state, proxies=proxies), password
                
            current_url = next_url
            time.sleep(0.5)

        print(f"[{ts()}] [ERROR] OAuth 授权链路追踪失败")
        return None, None

    except Exception as e:
        import traceback
        print(f"[{ts()}] [ERROR] 注册主流程发生严重异常: {e}")
        print(f"[{ts()}] [DEBUG] 追踪定位:\n{traceback.format_exc()}")
        return None, None

def _normalize_cpa_auth_files_url(api_url: str) -> str:
    normalized = (api_url or "").strip().rstrip("/")
    lower_url = normalized.lower()
    if not normalized: return ""
    if lower_url.endswith("/auth-files"): return normalized
    if lower_url.endswith("/v0/management") or lower_url.endswith("/management"): return f"{normalized}/auth-files"
    if lower_url.endswith("/v0"): return f"{normalized}/management/auth-files"
    return f"{normalized}/v0/management/auth-files"

def upload_to_cpa_integrated(token_data: dict, api_url: str, api_token: str) -> Tuple[bool, str]:
    upload_url = _normalize_cpa_auth_files_url(api_url)
    filename = f"{token_data['email']}.json"
    file_content = json.dumps(token_data, ensure_ascii=False, indent=2).encode("utf-8")
    try:
        mime = CurlMime()
        mime.addpart(name="file", data=file_content, filename=filename, content_type="application/json")
        response = requests.post(upload_url, multipart=mime, headers={"Authorization": f"Bearer {api_token}"}, timeout=30, impersonate="chrome110")
        if response.status_code in (200, 201): return True, "上传成功"
        
        if response.status_code in (404, 405, 415):
            raw_upload_url = f"{upload_url}?name={urllib.parse.quote(filename)}"
            fallback_res = requests.post(raw_upload_url, data=file_content, headers={"Authorization": f"Bearer {api_token}", "Content-Type": "application/json"}, timeout=30, impersonate="chrome110")
            if fallback_res.status_code in (200, 201): return True, "上传成功"
            response = fallback_res
        return False, f"HTTP {response.status_code}"
    except Exception as e: return False, str(e)

def _decode_possible_json_payload(payload: Any) -> Any:
    if isinstance(payload, str):
        text = payload.strip()
        if not text: return payload
        try: return json.loads(text)
        except Exception: return payload
    return payload

def _extract_remaining_percent(window_info: Any) -> Optional[float]:
    if not isinstance(window_info, dict): return None
    remaining_percent = window_info.get("remaining_percent")
    if isinstance(remaining_percent, (int, float)): return max(0.0, min(100.0, float(remaining_percent)))
    used_percent = window_info.get("used_percent")
    if isinstance(used_percent, (int, float)): return max(0.0, min(100.0, 100.0 - float(used_percent)))
    return None

def _format_percent(value: float) -> str:
    normalized = round(float(value), 2)
    if normalized.is_integer(): return str(int(normalized))
    return f"{normalized:.2f}".rstrip("0").rstrip(".")

def _format_known_cliproxy_error(error_type: str) -> str:
    label = KNOWN_CLIPROXY_ERROR_LABELS.get(error_type)
    if label: return f"{label} ({error_type})"
    return f"错误类型: {error_type}"

def _extract_rate_limit_reason(rate_info: Any, key: str, min_remaining_weekly_percent: int = 0) -> Optional[str]:
    if not isinstance(rate_info, dict): return None
    allowed = rate_info.get("allowed")
    limit_reached = rate_info.get("limit_reached")
    if allowed is False or limit_reached is True:
        label_map = {"rate_limit": "周限额已耗尽", "code_review_rate_limit": "代码审查周限额已耗尽"}
        label = label_map.get(key, f"{key} 已耗尽")
        return f"{label}（allowed={allowed}, limit_reached={limit_reached}）"

    if key == "rate_limit" and min_remaining_weekly_percent > 0:
        remaining_percent = _extract_remaining_percent(rate_info.get("primary_window"))
        if remaining_percent is not None and remaining_percent < min_remaining_weekly_percent:
            return f"周限额剩余 {_format_percent(remaining_percent)}%，低于阈值 {min_remaining_weekly_percent}%"
    return None

def _extract_cliproxy_failure_reason(payload: Any, min_remaining_weekly_percent: int = 0) -> Optional[str]:
    data = _decode_possible_json_payload(payload)

    if isinstance(data, str):
        for keyword in ("usage_limit_reached", "account_deactivated", "insufficient_quota", "invalid_api_key", "unsupported_region"):
            if keyword in data: return _format_known_cliproxy_error(keyword)
        return None

    if not isinstance(data, dict): return None

    error = data.get("error")
    if isinstance(error, dict):
        err_type = error.get("type")
        if err_type: return _format_known_cliproxy_error(err_type)
        message = error.get("message")
        if message: return str(message)

    for key in ("rate_limit", "code_review_rate_limit"):
        min_remaining_percent = min_remaining_weekly_percent if key == "rate_limit" else 0
        reason = _extract_rate_limit_reason(data.get(key), key, min_remaining_percent)
        if reason: return reason

    additional_rate_limits = data.get("additional_rate_limits")
    if isinstance(additional_rate_limits, list):
        for index, rate_info in enumerate(additional_rate_limits):
            reason = _extract_rate_limit_reason(rate_info, f"additional_rate_limits[{index}]", 0)
            if reason: return reason
    elif isinstance(additional_rate_limits, dict):
        for key, rate_info in additional_rate_limits.items():
            reason = _extract_rate_limit_reason(rate_info, f"additional_rate_limits.{key}", 0)
            if reason: return reason

    for key in ("data", "body", "response", "text", "content", "status_message"):
        reason = _extract_cliproxy_failure_reason(data.get(key), min_remaining_weekly_percent)
        if reason: return reason

    data_str = json.dumps(data, ensure_ascii=False)
    for keyword in ("usage_limit_reached", "account_deactivated", "insufficient_quota", "invalid_api_key", "unsupported_region"):
        if keyword in data_str: return _format_known_cliproxy_error(keyword)

    return None
# ----------------------------------------

def test_cliproxy_auth_file(item: dict, api_url: str, api_token: str) -> Tuple[bool, str]:
    auth_index = item.get("auth_index")
    base_url = api_url.strip().rstrip("/")
    call_url = base_url.replace("/auth-files", "/api-call") if "/auth-files" in base_url else f"{base_url}/v0/management/api-call"
    payload = {
        "authIndex": auth_index, 
        "method": "GET", 
        "url": "https://chatgpt.com/backend-api/wham/usage", 
        "header": {
            "Authorization": "Bearer $TOKEN$", 
            "Content-Type": "application/json", 
            "User-Agent": DEFAULT_CLIPROXY_UA, 
            "Chatgpt-Account-Id": str(item.get("account_id") or "")
        }
    }
    try:
        resp = requests.post(call_url, headers={"Authorization": f"Bearer {api_token}"}, json=payload, timeout=60, impersonate="chrome110")
        if resp.status_code != 200:
            return False, f"HTTP {resp.status_code}"
            
        data = resp.json()
        status_code = data.get("status_code", 0)
        
        failure_reason = _extract_cliproxy_failure_reason(data, MIN_REMAINING_WEEKLY_PERCENT)
        
        if status_code >= 400 or failure_reason:
            return False, failure_reason or f"HTTP {status_code}"
            
        return True, "正常"
    except Exception: 
        return False, "测活超时"

async def cpa_main_loop(args):
    """CPA 智能仓管模式 (测活、清理、补货、上传一体化)"""
    print("=" * 60)
    print(f"   目标库存阈值: {MIN_ACCOUNTS_THRESHOLD} | 单次补发量: {BATCH_REG_COUNT}")
    print(f"   周限额剔除规则: 剩余低于 {MIN_REMAINING_WEEKLY_PERCENT}%" if MIN_REMAINING_WEEKLY_PERCENT > 0 else "  ⚖️  周限额剔除规则: 完全耗尽才剔除")
    print("=" * 60)
    
    loop = asyncio.get_running_loop()

    while True:
        print(f"\n[{ts()}] [INFO] 开始执行仓库例行巡检与测活...")
        try:
            res = requests.get(
                _normalize_cpa_auth_files_url(CPA_API_URL), 
                headers={"Authorization": f"Bearer {CPA_API_TOKEN}"}, 
                timeout=20
            )
            all_files = res.json().get("files", [])
            codex_files = [f for f in all_files if "codex" in str(f.get("type","")).lower() or "codex" in str(f.get("provider","")).lower()]
            
            valid_count = 0
            for i, item in enumerate(codex_files, 1):
                name = item.get("name")
                is_ok, msg = test_cliproxy_auth_file(item, CPA_API_URL, CPA_API_TOKEN)
                if is_ok:
                    valid_count += 1
                    print(f"[{ts()}] [INFO] 测活 [{i}/{len(codex_files)}]: {name} 状态健康")
                else:
                    print(f"[{ts()}] [WARNING] 测活 [{i}/{len(codex_files)}]: 凭证 {name} 失效({msg})，正在物理剔除...")
                    requests.delete(
                        _normalize_cpa_auth_files_url(CPA_API_URL), 
                        headers={"Authorization": f"Bearer {CPA_API_TOKEN}"}, 
                        params={"name": name}
                    )

            print(f"[{ts()}] [INFO] 巡检结束，当前仓库有效数: {valid_count}")

            if valid_count < MIN_ACCOUNTS_THRESHOLD:
                print(f"[{ts()}] [INFO] 侦测到库存不足 (当前 {valid_count} < 阈值 {MIN_ACCOUNTS_THRESHOLD})，启动注册补货...")
                for _ in range(BATCH_REG_COUNT):
                    result = await loop.run_in_executor(None, run, args.proxy)
                    if not result:
                        continue
                    
                    token_json_str, password = result
                    if token_json_str == "retry_403":
                        print(f"[{ts()}] [WARNING] 检测到 403 频率限制，任务挂起 10 秒后重试...")
                        await asyncio.sleep(10)
                        continue
                    
                    if token_json_str:
                        token_data = json.loads(token_json_str)
                        account_email = token_data.get('email', 'unknown')
                        fname_email = account_email.replace("@", "_")
                        
                        base_dir = TOKEN_OUTPUT_DIR or "."
                        if base_dir != ".": os.makedirs(base_dir, exist_ok=True)

                        json_file_name = f"token_{fname_email}_{int(time.time())}.json"
                        json_path = os.path.join(base_dir, json_file_name)
                        with open(json_path, "w", encoding="utf-8") as f:
                            f.write(token_json_str)
                        print(f"[{ts()}] [SUCCESS] 本地 JSON 备份成功: {json_file_name}")

                        if account_email:
                            accounts_file = os.path.join(base_dir, "accounts.txt")
                            with open(accounts_file, "a", encoding="utf-8") as af:
                                af.write(f"{account_email}----{password}\n")
                            print(f"[{ts()}] [SUCCESS] 账号密码已追加至本地 accounts.txt")
                        
                        # CPA 上传
                        success, up_msg = upload_to_cpa_integrated(token_data, CPA_API_URL, CPA_API_TOKEN)
                        if success:
                            print(f"[{ts()}] [SUCCESS] 补货凭证 {account_email} 云端上传成功！")
                        else:
                            print(f"[{ts()}] [ERROR] 云端上传失败: {up_msg}")
                    
                    await asyncio.sleep(5)
            else:
                print(f"[{ts()}] [INFO] 仓库存量充足，无需补发。")
            
            print(f"[{ts()}] [INFO] 维护周期结束，{CHECK_INTERVAL_MINUTES} 分钟后进行下一次巡检...")
            await asyncio.sleep(CHECK_INTERVAL_MINUTES * 60)

        except Exception as e:
            print(f"[{ts()}] [ERROR] 主循环异常: {e}")
            await asyncio.sleep(60)

def normal_main_loop(args):
    """常规模式 (纯量产注册，存本地)"""
    sleep_min = max(1, args.sleep_min)
    sleep_max = max(sleep_min, args.sleep_max)
    count = 0

    while True:
        count += 1
        print(f"\n[{ts()}] >>> 开始第 {count} 次量产注册任务 <<<")

        try:
            result = run(args.proxy)
            if not result:
                print(f"[{ts()}] [ERROR] ❌ 本次注册任务执行失败")
            else:
                token_json_str, password = result
                if token_json_str == "retry_403":
                    print(f"[{ts()}] [WARNING] 检测到 403 频率限制，任务挂起 10 秒后重试...")
                    time.sleep(10)
                    continue

                if token_json_str:
                    token_data = json.loads(token_json_str)
                    account_email = token_data.get("email", "unknown")
                    fname_email = account_email.replace("@", "_")

                    base_dir = TOKEN_OUTPUT_DIR or "."
                    if base_dir != ".": os.makedirs(base_dir, exist_ok=True)
                    
                    file_name = os.path.join(base_dir, f"token_{fname_email}_{int(time.time())}.json")
                    with open(file_name, "w", encoding="utf-8") as f:
                        f.write(token_json_str)
                    print(f"[{ts()}] [SUCCESS] Token 凭证已生成: {file_name}")

                    if account_email and password:
                        accounts_file = os.path.join(base_dir, "accounts.txt")
                        with open(accounts_file, "a", encoding="utf-8") as af:
                            af.write(f"{account_email}----{password}\n")
                        print(f"[{ts()}] [SUCCESS] 账户明文信息已归档: {accounts_file}")
                else:
                    print(f"[{ts()}] [ERROR] ❌ 本次注册任务执行失败")

        except Exception as e:
            print(f"[{ts()}] [ERROR] 发生未捕获全局异常: {e}")

        if args.once:
            break

        wait_time = random.randint(sleep_min, sleep_max)
        print(f"[{ts()}] [INFO] 任务进入休眠，等待 {wait_time} 秒后继续...")
        time.sleep(wait_time)

def main() -> None:
    parser = argparse.ArgumentParser(description="OpenAI 自动注册 & CPA 检测一体")
    parser.add_argument("--proxy", default=None, help="代理地址，如 http://127.0.0.1:7890")
    parser.add_argument("--once", action="store_true", help="只运行一次 (常规模式下有效)")
    parser.add_argument("--sleep-min", type=int, default=5, help="循环模式最短等待秒数")
    parser.add_argument("--sleep-max", type=int, default=30, help="循环模式最长等待秒数")
    args = parser.parse_args()
    args.proxy = DEFAULT_PROXY if DEFAULT_PROXY.strip() else None
    print("=" * 65)
    print("   OpenAI 无限注册 & CPA 智能仓管")
    print("   Author: (wenfxl)轩灵")
    print("   特性: 支持纯协议无限注册、周限额低于设定值|死号智能剔除、低于存货数自动补货")
    print("-" * 65)
    if ENABLE_CPA_MODE:
        print("   当前状态: [ CPA 智能仓管模式 ] 已开启")
        print("   行为逻辑: 自动巡检测活 -> 剔除死号 -> 补货注册 -> 云端上传")
    else:
        print("   当前状态: [ 常规量产模式 ] 已开启")
        print("   行为逻辑: 纯净无限注册 -> 本地保存 (CPA 上传已关闭)")
    print("=" * 65)

    if ENABLE_CPA_MODE:
        try:
            asyncio.run(cpa_main_loop(args))
        except KeyboardInterrupt:
            print(f"\n[{ts()}] [INFO] 用户终止了系统运行。")
    else:
        try:
            normal_main_loop(args)
        except KeyboardInterrupt:
            print(f"\n[{ts()}] [INFO] 用户终止了系统运行。")

if __name__ == "__main__":
    main()