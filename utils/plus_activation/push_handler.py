"""推送逻辑 — 复用现有 upload_to_cpa / Sub2APIClient / shop"""

import json
import re
import time
import base64
from curl_cffi import requests

from utils import config as cfg
from utils import db_manager
from utils.db_manager import get_db_conn, get_cursor, execute_sql


def _acw_sc_v2(arg1: str) -> str:
    """计算阿里云 WAF acw_sc__v2 挑战 cookie (unsbox + hexXor，算法固定)。"""
    box = [15, 35, 29, 24, 33, 16, 1, 38, 10, 9, 19, 31, 40, 27, 22,
           23, 25, 13, 6, 11, 39, 18, 20, 8, 14, 21, 32, 26, 2, 30,
           7, 4, 17, 5, 3, 28, 34, 37, 12, 36]
    unsboxed = [""] * 40
    for i in range(len(arg1)):
        for k in range(40):
            if box[k] == i + 1:
                unsboxed[k] = arg1[i]
    s = "".join(unsboxed)
    mask = "3000176000856006061501533003690027800375"
    out = ""
    for i in range(0, 40, 2):
        out += format(int(s[i:i + 2], 16) ^ int(mask[i:i + 2], 16), "02x")
    return out


def _jwt_payload(access_token: str) -> dict:
    """无验签解析 access_token(JWT) payload，仅取 org/exp/iat 等明文字段。"""
    try:
        parts = access_token.split(".")
        if len(parts) < 2:
            return {}
        seg = parts[1] + "=" * (-len(parts[1]) % 4)
        return json.loads(base64.urlsafe_b64decode(seg))
    except Exception:
        return {}


def _clean_bundle_for_sale(bundle: dict) -> dict:
    """售卖用 bundle 清洗：去卖家私有 group_ids；从 JWT 补真实 organization_id 与过期时间。"""
    now = int(time.time())
    for acc in bundle.get("accounts", []):
        acc.pop("group_ids", None)  # 卖家面板组号，买家面板无关
        creds = acc.get("credentials") or {}
        pl = _jwt_payload(creds.get("access_token") or "")
        if not pl:
            continue
        auth = pl.get("https://api.openai.com/auth") or {}
        org = auth.get("pid") or auth.get("organization_id") or ""
        if org:
            creds["organization_id"] = org
        exp = pl.get("exp")
        iat = pl.get("iat")
        if isinstance(exp, (int, float)):
            creds["expires_at"] = int(exp)
            if isinstance(iat, (int, float)):
                creds["expires_in"] = max(0, int(exp) - int(iat))
            else:
                creds["expires_in"] = max(0, int(exp) - now)
    return bundle


def push_activated_account(token_data: dict, targets: list) -> dict:
    results = {}

    if not token_data:
        return results

    email = token_data.get("email", "")
    if email:
        try:
            content = json.dumps(token_data, ensure_ascii=False)
            # UPDATE only — preserve existing password from registration
            with get_db_conn(is_write=True) as conn:
                c = get_cursor(conn)
                execute_sql(c, "UPDATE accounts SET token_data = ? WHERE email = ?", (content, email))
        except Exception:
            pass

    if "sub2api" in targets:
        try:
            from utils.integrations.sub2api_client import Sub2APIClient
            client = Sub2APIClient(
                api_url=cfg.SUB2API_URL,
                api_key=cfg.SUB2API_KEY,
            )
            ok, msg = client.add_account(token_data)
            results["sub2api"] = {"success": ok, "message": msg}
        except Exception as e:
            results["sub2api"] = {"success": False, "message": str(e)}

    if "cpa" in targets:
        try:
            from utils.core_engine import upload_to_cpa_integrated
            ok, msg = upload_to_cpa_integrated(
                token_data, cfg.CPA_API_URL, cfg.CPA_API_TOKEN
            )
            results["cpa"] = {"success": ok, "message": msg}
        except Exception as e:
            results["cpa"] = {"success": False, "message": str(e)}

    if "shop" in targets:
        try:
            results["shop"] = _push_to_shop(token_data)
        except Exception as e:
            results["shop"] = {"success": False, "message": str(e)}

    return results


def _build_shop_content(token_data: dict):
    """按 shop_format 构建卡密内容，返回 (ok, content_or_error_msg)。"""
    fmt = getattr(cfg, "PLUS_ACT_SHOP_FORMAT", "cpa")
    if fmt == "sub2api":
        try:
            from utils.integrations.sub2api_client import (
                build_sub2api_export_bundle, get_sub2api_push_settings,
            )
            bundle = build_sub2api_export_bundle([token_data], get_sub2api_push_settings())
            _clean_bundle_for_sale(bundle)
            return True, json.dumps(bundle, ensure_ascii=False)
        except Exception as e:
            return False, f"构建 sub2api 格式失败: {e}"
    return True, json.dumps(token_data, ensure_ascii=False)


def _deliver_ldxp(content: str) -> dict:
    """投递到联动小铺 pay.ldxp.cn (含阿里云 WAF acw_sc__v2 反爬自动解题)。"""
    merchant_token = getattr(cfg, "PLUS_ACT_SHOP_MERCHANT_TOKEN", "")
    goods_id = getattr(cfg, "PLUS_ACT_SHOP_GOODS_ID", 0)
    if not merchant_token:
        return {"success": False, "message": "未配置联动小铺 Merchant Token"}
    if not goods_id:
        return {"success": False, "message": "未配置联动小铺 商品 ID"}

    shop_proxy = getattr(cfg, "PLUS_ACT_SHOP_PROXY", "")
    url = "https://pay.ldxp.cn/merchantApi/GoodsCardStorage/add"
    base_headers = {"content-type": "application/json", "merchant-token": merchant_token}
    req_kwargs = {
        "headers": base_headers,
        "json": {"goods_id": goods_id, "content": content, "first": 0, "remove_repeat": 0},
        "timeout": 15,
        "impersonate": "chrome110",
    }
    if shop_proxy:
        req_kwargs["proxies"] = {"http": shop_proxy, "https": shop_proxy}

    resp = requests.post(url, **req_kwargs)

    # 阿里云 WAF acw_sc__v2 反爬挑战页：返回 <html><script>var arg1=... → 解出 cookie 重试一次
    raw = resp.text or ""
    if resp.ok and ("<script>var arg1" in raw or "acw_sc__v2" in raw):
        m = re.search(r"var arg1='([0-9A-Fa-f]+)'", raw)
        if m:
            acw_tc = ""
            try:
                acw_tc = resp.cookies.get("acw_tc", "") or ""
            except Exception:
                pass
            retry_kwargs = dict(req_kwargs)
            retry_kwargs["headers"] = dict(base_headers)
            retry_kwargs["headers"]["cookie"] = f"acw_tc={acw_tc}; acw_sc__v2={_acw_sc_v2(m.group(1))}"
            resp = requests.post(url, **retry_kwargs)
            raw = resp.text or ""

    if not resp.ok:
        return {"success": False, "message": f"HTTP {resp.status_code}: {raw[:200]}"}
    if "<script>var arg1" in raw or "acw_sc__v2" in raw:
        return {"success": False, "message": "反爬挑战未通过，可尝试配置 shop_proxy 走干净代理"}

    data = {}
    if raw:
        try:
            data = resp.json()
        except Exception:
            return {"success": False, "message": f"响应非JSON(HTTP {resp.status_code}): {raw[:200]}"}
    if not isinstance(data, dict):
        return {"success": False, "message": f"响应格式异常(HTTP {resp.status_code}): {str(data)[:200]}"}
    code = data.get("code", 0)
    if isinstance(code, int) and (code < 0 or code >= 300):
        return {"success": False, "message": data.get("message") or data.get("msg") or "推送失败"}
    return {"success": True, "message": "联动小铺推送成功"}


def _deliver_dujiao(content: str) -> dict:
    """投递到独角兽发卡网 (admin JWT, /admin/card-secrets/batch)。"""
    base = getattr(cfg, "PLUS_ACT_SHOP_DUJIAO_URL", "").rstrip("/")
    token = getattr(cfg, "PLUS_ACT_SHOP_DUJIAO_TOKEN", "")
    pid = getattr(cfg, "PLUS_ACT_SHOP_DUJIAO_PRODUCT_ID", 0)
    sid = getattr(cfg, "PLUS_ACT_SHOP_DUJIAO_SKU_ID", 0)
    if not token:
        return {"success": False, "message": "未配置独角兽 Token"}
    if not base:
        return {"success": False, "message": "未配置独角兽 Base URL"}
    if not pid:
        return {"success": False, "message": "未配置独角兽 product_id"}

    try:
        resp = requests.post(
            f"{base}/admin/card-secrets/batch",
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
            json={"product_id": pid, "sku_id": sid, "secrets": [content], "deduplicate": True},
            timeout=15,
            impersonate="chrome110",
        )
    except Exception as e:
        return {"success": False, "message": f"独角兽请求异常: {e}"}

    if not resp.ok:
        return {"success": False, "message": f"HTTP {resp.status_code}: {(resp.text or '')[:200]}"}
    raw = resp.text or ""
    try:
        data = resp.json()
    except Exception:
        return {"success": False, "message": f"响应非JSON: {raw[:200]}"}
    sc = data.get("status_code")
    if sc != 0:
        return {"success": False, "message": data.get("msg") or f"独角兽返回 status_code={sc}"}
    created = (data.get("data") or {}).get("created", 0)
    return {"success": True, "message": f"独角兽导入成功({created}张)"}


def _push_to_shop(token_data: dict) -> dict:
    ok, content = _build_shop_content(token_data)
    if not ok:
        return {"success": False, "message": content}
    if getattr(cfg, "PLUS_ACT_SHOP_PLATFORM", "ldxp") == "dujiao":
        return _deliver_dujiao(content)
    return _deliver_ldxp(content)
