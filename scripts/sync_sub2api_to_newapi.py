"""
Sub2API → NewAPI 账号同步脚本
只同步 status=active 和 rate-limited 的账号到 NewAPI 作为 Codex 渠道
"""

import json
import sys
import time
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from curl_cffi import requests as cffi_requests

# ── 配置 ──
SUB2API_URL = "http://154.219.99.9:26843"
SUB2API_KEY = "admin-4c237bfb1dfd01e70fd697b992be2bb6c2390fd18e70b460085b7dc79d07f7a9"

NEWAPI_URL = "https://api.trovebox.online"
NEWAPI_TOKEN = "rxbTIhKjMGOtb26zW02JahSi5/B+Dg=="
NEWAPI_USER_ID = "1"
NEWAPI_PROXY = ""  # 留空或填代理如 http://127.0.0.1:7897
NEWAPI_GROUP = "default"
NEWAPI_MODELS = "gpt-5.3-codex,gpt-5.3-codex-spark,gpt-5.4,gpt-5.4-mini,gpt-5.5"

CODEX_CHANNEL_TYPE = 57
CODEX_BASE_URL = "https://chatgpt.com"

# 日志文件
LOG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sync_log.txt")


def log(msg):
    line = msg
    print(line, flush=True)
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(line + "\n")


def sub2api_get(path, params=None, retries=3):
    for attempt in range(retries):
        try:
            resp = cffi_requests.get(
                f"{SUB2API_URL.rstrip('/')}{path}",
                headers={"Content-Type": "application/json", "x-api-key": SUB2API_KEY},
                params=params,
                timeout=30,
                impersonate="chrome110",
                verify=False,
            )
            if resp.status_code == 200:
                return resp.json()
            log(f"  [ERROR] Sub2API {path} -> HTTP {resp.status_code}: {resp.text[:200]}")
            return None
        except Exception as e:
            if attempt < retries - 1:
                log(f"  [RETRY {attempt+1}] Sub2API {path} 连接失败，3秒后重试...")
                time.sleep(3)
            else:
                log(f"  [ERROR] Sub2API {path} -> 连接失败: {e}")
                return None


def newapi_request(method, path, json_data=None, retries=3):
    for attempt in range(retries):
        try:
            resp = getattr(cffi_requests, method)(
                f"{NEWAPI_URL.rstrip('/')}{path}",
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {NEWAPI_TOKEN}",
                    "New-Api-User": NEWAPI_USER_ID,
                },
                json=json_data,
                timeout=30,
                impersonate="chrome110",
                verify=False,
            )
            return resp.status_code in (200, 201, 204), resp.json() if resp.text else {}
        except Exception as e:
            if attempt < retries - 1:
                log(f"\n  [RETRY {attempt+1}] NewAPI {path} 连接失败，3秒后重试...")
                time.sleep(3)
            else:
                return False, str(e)


def get_sub2api_accounts():
    """获取所有 Sub2API 账号"""
    all_items = []
    page = 1
    while True:
        data = sub2api_get("/api/v1/admin/accounts", {"page": page, "page_size": 100})
        if not data:
            break
        inner = data.get("data", {}) if isinstance(data, dict) else {}
        items = inner.get("items", [])
        if not items:
            break
        all_items.extend(items)
        total = inner.get("total", 0)
        if len(all_items) >= total:
            break
        page += 1
    return all_items


def build_channel_setting():
    if not NEWAPI_PROXY:
        return ""
    return json.dumps({"proxy": NEWAPI_PROXY}, ensure_ascii=False)


def build_codex_key(creds, email):
    key_obj = {
        "access_token": creds.get("access_token", ""),
        "refresh_token": creds.get("refresh_token", ""),
        "account_id": creds.get("chatgpt_account_id", ""),
        "last_refresh": creds.get("last_refresh", ""),
        "email": email,
        "type": "codex",
        "expired": creds.get("expired", ""),
    }
    return json.dumps(key_obj, ensure_ascii=False)


def push_to_newapi(email, creds):
    """推送单个账号到 NewAPI"""
    if isinstance(creds, str):
        try:
            creds = json.loads(creds)
        except:
            creds = {}
    access_token = creds.get("access_token", "")
    account_id = creds.get("chatgpt_account_id", "")
    refresh_token = creds.get("refresh_token", "")

    if not access_token:
        return False, "缺少 access_token"

    key = build_codex_key(creds, email)
    models = NEWAPI_MODELS
    if not models:
        models = get_codex_models(access_token, account_id)
    if not models:
        return False, "无法获取模型列表，请设置 NEWAPI_MODELS"

    ok, result = newapi_request("post", "/api/channel/", {
        "mode": "single",
        "channel": {
            "type": CODEX_CHANNEL_TYPE,
            "key": key,
            "name": email,
            "base_url": "",
            "models": models,
            "group": NEWAPI_GROUP,
            "status": 1,
            "setting": build_channel_setting(),
        }
    })

    if ok:
        return True, "创建成功"
    err_msg = str(result) if isinstance(result, str) else result.get("message", str(result))
    return False, err_msg


def main():
    # 清空旧日志
    with open(LOG_FILE, "w", encoding="utf-8") as f:
        f.write("")

    log("=" * 60)
    log("Sub2API → NewAPI 账号同步")
    log("=" * 60)

    # 1. 获取 Sub2API 账号
    log("\n[1/3] 正在从 Sub2API 获取账号...")
    accounts = get_sub2api_accounts()
    log(f"  共获取到 {len(accounts)} 个账号")

    # 2. 过滤：只保留 active 和有凭据的
    filtered = []
    for acc in accounts:
        status = acc.get("status", "")
        name = acc.get("name", "unknown")
        if status in ("active", "rate_limited") and acc.get("credentials"):
            filtered.append(acc)

    log(f"  其中 active/rate_limited 且有凭据: {len(filtered)} 个")

    # 只要有 access_token 就推（不再要求 chatgpt_account_id）
    valid = []
    for acc in filtered:
        creds = acc.get("credentials", {})
        if isinstance(creds, str):
            try:
                creds = json.loads(creds)
            except:
                creds = {}
        acc["credentials"] = creds
        if creds.get("access_token"):
            valid.append(acc)

    log(f"  其中有 access_token: {len(valid)} 个")

    if not valid:
        log("\n没有可同步的账号，退出。")
        return

    # 3. 推送到 NewAPI
    log(f"\n[2/3] 开始推送到 NewAPI ({NEWAPI_URL})...")

    success = 0
    fail = 0
    skip = 0

    # 先检查 NewAPI 已有哪些渠道（按名称去重）
    ok, existing_data = newapi_request("get", "/api/channel/?p=0&page_size=10000")
    existing_names = set()
    if ok:
        channels = existing_data.get("data", {})
        if isinstance(channels, dict):
            channels = channels.get("items", [])
        elif not isinstance(channels, list):
            channels = []
        for ch in channels:
            if not isinstance(ch, dict):
                continue
            if ch.get("type") == CODEX_CHANNEL_TYPE:
                existing_names.add(ch.get("name", ""))
    log(f"  NewAPI 已有 {len(existing_names)} 个 Codex 渠道")

    for i, acc in enumerate(valid, 1):
        name = acc.get("name", "unknown")
        creds = acc.get("credentials", {})

        if name in existing_names:
            skip += 1
            if i % 100 == 0:
                log(f"  [{i}/{len(valid)}] 已跳过 {skip} 个已存在")
            continue

        ok, msg = push_to_newapi(name, creds)
        if ok:
            success += 1
            if success <= 5 or success % 50 == 0:
                log(f"  [{i}/{len(valid)}] {name} -> OK")
        else:
            fail += 1
            if fail <= 10:
                log(f"  [{i}/{len(valid)}] {name} -> FAIL: {msg}")

        # 避免请求过快
        time.sleep(0.3)

    log(f"\n[3/3] 同步完成！")
    log(f"  成功: {success}")
    log(f"  跳过(已存在): {skip}")
    log(f"  失败: {fail}")
    log(f"  总计: {len(valid)}")


if __name__ == "__main__":
    main()
