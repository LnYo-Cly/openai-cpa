import json
import random
import string
import time
import uuid
from typing import List, Optional, Dict, Any
from curl_cffi import requests as cffi_requests
from utils import config as cfg
from utils import db_manager


class LocalMicrosoftService:
    def __init__(self, proxies: Optional[Dict[str, str]] = None):
        self.proxies = proxies
        self.token_url = "https://login.microsoftonline.com/common/oauth2/v2.0/token"
        self.graph_base_url = "https://graph.microsoft.com/v1.0/me"

    def generate_suffix_v2(self):
        return uuid.uuid4().hex[:8]

    def get_unused_mailbox(self) -> Optional[dict]:
        if getattr(cfg, "LOCAL_MS_ENABLE_FISSION", False):
            master_email = getattr(cfg, "LOCAL_MS_MASTER_EMAIL", "").strip()
            if not master_email or "@" not in master_email:
                return None
            random_suffix = self.generate_suffix_v2()
            user_part, domain_part = master_email.split("@", 1)
            fission_email = f"{user_part}+{random_suffix}@{domain_part}"

            return {
                "id": "fission",
                "email": fission_email,
                "master_email": master_email,
                "client_id": getattr(cfg, "LOCAL_MS_CLIENT_ID", ""),
                "refresh_token": getattr(cfg, "LOCAL_MS_REFRESH_TOKEN", ""),
                "assigned_at": time.time()
            }
        mailbox = db_manager.get_one_unused_local_mailbox()
        if mailbox:
            db_manager.update_local_mailbox_status(mailbox["email"], 1)
            res = dict(mailbox)
            res["assigned_at"] = time.time()
            return res

        return None

    def _exchange_refresh_token(self, mailbox: dict) -> str:
        refresh_token = mailbox.get("refresh_token")
        client_id = str(mailbox.get("client_id") or getattr(cfg, "LOCAL_MS_CLIENT_ID", "")).strip()

        if not refresh_token or not client_id:
            raise ValueError("缺失 refresh_token 或 client_id，请先在面板完成授权")

        payload = {
            "client_id": client_id,
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "scope": "offline_access https://graph.microsoft.com/Mail.Read"
        }

        resp = cffi_requests.post(self.token_url, data=payload, proxies=self.proxies, timeout=15,
                                  impersonate="chrome110")
        data = resp.json()

        if resp.status_code == 200 and "access_token" in data:
            new_rt = data.get("refresh_token")
            if new_rt and new_rt != refresh_token and mailbox.get("id") != "fission":
                try:
                    db_manager.update_local_mailbox_refresh_token(mailbox["email"], new_rt)
                except:
                    pass
            return data["access_token"]
        else:
            raise RuntimeError(f"Token 续期失败: {data.get('error_description', data)}")

    def fetch_openai_messages(self, mailbox: dict) -> List[Dict[str, Any]]:
        all_msgs = []
        try:
            access_token = self._exchange_refresh_token(mailbox)
            target_folders = ["inbox", "junkemail", "INBOX", "Junk", '"Junk Email"']

            for folder in target_folders:
                url = f"{self.graph_base_url}/mailFolders/{folder}/messages"
                params = {
                    "$select": "subject,body,from,toRecipients,receivedDateTime",
                    "$orderby": "receivedDateTime desc",
                    "$top": 3
                }

                headers = {
                    "Authorization": f"Bearer {access_token}",
                    "Content-Type": "application/json"
                }

                resp = cffi_requests.get(url, params=params, headers=headers, proxies=self.proxies, timeout=15,
                                         impersonate="chrome110")

                if resp.status_code == 200:
                    raw_msgs = resp.json().get("value", [])

                    for m in raw_msgs:
                        sender = str(m.get('from', {}).get('emailAddress', {}).get('address', '')).lower()

                        if "openai.com" in sender:
                            all_msgs.append(m)
                else:
                    pass

        except Exception as e:
            print(f"[{cfg.ts()}] [DEBUG-GRAPH] 严重错误: {e}", flush=True)
        return all_msgs