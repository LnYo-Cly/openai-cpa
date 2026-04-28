import re
import random
import string
import httpx
from utils import config as cfg


class YopmailService:
    """yopmail.com 临时邮箱对接（网页抓取方式，使用 httpx 避免 curl_cffi SOCKS5 TLS 冲突）"""

    DOMAINS = [
        "yopmail.com",
        "yopmail.fr",
        "yopmail.net",
        "cool.fr.nf",
        "jetable.fr.nf",
        "nospam.ze.tc",
        "nomail.xl.cx",
        "mega.zik.dj",
    ]

    def __init__(self, proxies=None):
        proxy_url = None
        if proxies:
            if isinstance(proxies, dict):
                proxy_url = proxies.get("https") or proxies.get("http")
            else:
                proxy_url = str(proxies)
        self.client = httpx.Client(
            proxy=proxy_url,
            verify=False,
            timeout=20,
            follow_redirects=True,
            headers={
                "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36",
                "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "referer": "https://yopmail.com/en/",
            },
        )
        self._yp = None
        self._yj = None
        self._version = None

    def _init_session(self):
        """首次访问 yopmail 获取 yp、yj、version 动态参数"""
        if self._yp and self._yj:
            return True
        try:
            r = self.client.get("https://yopmail.com/en/")
            if r.status_code != 200:
                return False

            # 提取 yp: <input type="hidden" name="yp" id="yp" value="XXX" />
            yp_match = re.search(r'name="yp"[^>]*value="([^"]+)"', r.text)
            if not yp_match:
                yp_match = re.search(r'value="([^"]+)"[^>]*name="yp"', r.text)
            if yp_match:
                self._yp = yp_match.group(1)

            # 提取 version: /ver/X.X/style.css 或 /ver/X.X/webmail.js
            ver_match = re.search(r'/ver/([0-9.]+)/(?:webmail\.js|style\.css)', r.text)
            if ver_match:
                self._version = ver_match.group(1)
            else:
                self._version = "9.2"

            # 提取 yj: 从 webmail.js 中找 value+'&yj=XXXXX&v='
            if self._version:
                try:
                    js_url = f"https://yopmail.com/ver/{self._version}/webmail.js"
                    js_r = self.client.get(js_url)
                    if js_r.status_code == 200:
                        yj_match = re.search(r"value\+'\\&yj=([0-9a-zA-Z]+)\\&v='", js_r.text)
                        if yj_match:
                            self._yj = yj_match.group(1)
                except Exception:
                    pass

            return bool(self._yp)
        except Exception as e:
            print(f"[{cfg.ts()}] [ERROR] YOPmail 初始化会话失败: {e}")
            return False

    def create_email(self):
        """生成随机邮箱地址，返回 (email, email)"""
        username = "".join(random.choices(string.ascii_lowercase + string.digits, k=12))
        domain = random.choice(self.DOMAINS)
        email = f"{username}@{domain}"

        if not self._init_session():
            print(f"[{cfg.ts()}] [ERROR] YOPmail 会话初始化失败")
            return None, None

        print(f"[{cfg.ts()}] [INFO] YOPmail 分配邮箱: {email}")
        return email, email

    def get_inbox(self, email):
        """抓取收件箱，返回 [{id, subject, sender}, ...]"""
        if not self._init_session():
            return []

        username = email.split("@")[0]
        try:
            params = {
                "login": username,
                "p": "1",
                "d": "",
                "ctrl": "",
                "yp": self._yp or "",
                "yj": self._yj or "",
                "v": self._version or "9.2",
                "r_c": "",
                "id": "",
                "ad": "0",
            }
            r = self.client.get("https://yopmail.com/en/inbox", params=params)
            if r.status_code != 200:
                return []

            return self._parse_inbox(r.text)
        except Exception as e:
            print(f"[{cfg.ts()}] [ERROR] YOPmail 获取收件箱异常: {e}")
            return []

    def _parse_inbox(self, html):
        """从收件箱 HTML 解析邮件列表"""
        messages = []
        for m_div in re.finditer(r'<div[^>]*class="m"[^>]*id="([^"]+)"[^>]*>(.*?)</div>', html, re.DOTALL):
            mail_id = m_div.group(1)
            content = m_div.group(2)

            subject_match = re.search(r'<div[^>]*class="[^"]*"[^>]*>(.*?)</div>', content, re.DOTALL)
            subject = re.sub(r"<[^>]+>", "", subject_match.group(1)).strip() if subject_match else ""

            sender_match = re.search(r'<span[^>]*>(.*?)</span>', content, re.DOTALL)
            sender = re.sub(r"<[^>]+>", "", sender_match.group(1)).strip() if sender_match else ""

            if mail_id:
                messages.append({"id": mail_id, "subject": subject, "sender": sender})

        return messages

    def get_mail_body(self, mail_id, email):
        """获取单封邮件正文"""
        if not self._init_session():
            return ""

        username = email.split("@")[0]
        try:
            params = {
                "b": username,
                "id": f"m{mail_id}",
                "yp": self._yp or "",
                "yj": self._yj or "",
                "v": self._version or "9.2",
            }
            r = self.client.get("https://yopmail.com/en/mail", params=params)
            if r.status_code != 200:
                return ""

            mail_match = re.search(r'<div[^>]*id="mail"[^>]*>(.*?)</div>', r.text, re.DOTALL)
            if mail_match:
                body = re.sub(r"<[^>]+>", " ", mail_match.group(1))
                return re.sub(r"\s+", " ", body).strip()
            return re.sub(r"<[^>]+>", " ", r.text)
        except Exception:
            return ""

    def get_verification_code(self, email):
        """从收件箱提取 OpenAI 验证码"""
        messages = self.get_inbox(email)
        for mail in messages:
            subject = mail.get("subject", "")
            sender = mail.get("sender", "").lower()

            if "openai" not in sender and "openai" not in subject.lower() and "chatgpt" not in subject.lower():
                continue

            code = self._extract_code(subject)
            if code:
                return code

            body = self.get_mail_body(mail.get("id", ""), email)
            code = self._extract_code(f"{subject}\n{body}")
            if code:
                return code

        return ""

    @staticmethod
    def _extract_code(text):
        m = re.search(r"Your ChatGPT code is (\d{6})", text, re.I)
        if m:
            return m.group(1)
        m = re.search(r"(?:enter|verification)\s+(?:this\s+)?code:?\s*(\d{6})", text, re.I)
        if m:
            return m.group(1)
        m = re.search(r"(?:openai|chatgpt)[\s\S]{0,200}?(\d{6})", text, re.I)
        if m:
            return m.group(1)
        if "openai" in text.lower() or "chatgpt" in text.lower():
            codes = re.findall(r"\b(\d{6})\b", text)
            if codes:
                return codes[-1]
        return ""
