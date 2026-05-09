"""快速统计 Sub2API 唯一 active 数 vs NewAPI 数"""
import json, sys, os, time
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from curl_cffi import requests as cffi_requests

S2_URL = "http://154.219.99.9:26843"
S2_KEY = "admin-4c237bfb1dfd01e70fd697b992be2bb6c2390fd18e70b460085b7dc79d07f7a9"
NA_URL = "https://api.trovebox.online"
NA_TOKEN = "rxbTIhKjMGOtb26zW02JahSi5/B+Dg=="

print("NewAPI Codex 渠道...", flush=True)
na_names = set()
page = 0
while True:
    resp = cffi_requests.get(f"{NA_URL}/api/channel/",
        headers={"Authorization": f"Bearer {NA_TOKEN}", "New-Api-User": "1"},
        params={"p": page, "page_size": 100},
        timeout=30, impersonate="chrome110", verify=False)
    inner = resp.json().get("data", {})
    items = inner.get("items", []) if isinstance(inner, dict) else []
    if not items: break
    for ch in items:
        if ch.get("type") == 57:
            na_names.add(ch.get("name", ""))
    page += 1
print(f"  NewAPI: {len(na_names)}", flush=True)

# Sub2API 每页拉大一点，快速遍历
print("Sub2API 全量...", flush=True)
seen = set()
pg = 1
while True:
    resp = cffi_requests.get(f"{S2_URL}/api/v1/admin/accounts",
        headers={"x-api-key": S2_KEY},
        params={"page": pg, "page_size": 500},
        timeout=30, impersonate="chrome110", verify=False)
    inner = resp.json().get("data", {})
    items = inner.get("items", [])
    if not items: break
    for acc in items:
        if acc.get("status") in ("active", "rate_limited"):
            creds = acc.get("credentials", {})
            if isinstance(creds, str):
                try: creds = json.loads(creds)
                except: creds = {}
            if creds.get("access_token"):
                seen.add(acc.get("name", ""))
    total = inner.get("total", 0)
    if pg * 500 >= total: break
    pg += 1

print(f"  Sub2API 唯一: {len(seen)}", flush=True)
missing = seen - na_names
print(f"  缺失: {len(missing)}", flush=True)
if missing:
    for m in sorted(missing)[:20]:
        print(f"    {m}", flush=True)
