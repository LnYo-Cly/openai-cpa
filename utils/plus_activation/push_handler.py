"""推送逻辑 — 复用现有 upload_to_cpa / Sub2APIClient / shop"""

import json
from curl_cffi import requests

from utils import config as cfg
from utils import db_manager
from utils.db_manager import get_db_conn, get_cursor, execute_sql


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


def _push_to_shop(token_data: dict) -> dict:
    merchant_token = getattr(cfg, "PLUS_ACT_SHOP_MERCHANT_TOKEN", "")
    goods_id = getattr(cfg, "PLUS_ACT_SHOP_GOODS_ID", 0)

    if not merchant_token:
        return {"success": False, "message": "未配置 Shop Merchant Token"}
    if goods_id is None:
        return {"success": False, "message": "未配置 Shop 商品 ID"}

    fmt = getattr(cfg, "PLUS_ACT_SHOP_FORMAT", "cpa")
    if fmt == "sub2api":
        try:
            from utils.integrations.sub2api_client import (
                build_sub2api_export_bundle, get_sub2api_push_settings,
            )
            bundle = build_sub2api_export_bundle([token_data], get_sub2api_push_settings())
            content = json.dumps(bundle, ensure_ascii=False)
        except Exception as e:
            return {"success": False, "message": f"构建 sub2api 格式失败: {e}"}
    else:
        content = json.dumps(token_data, ensure_ascii=False)
    resp = requests.post(
        "https://pay.ldxp.cn/merchantApi/GoodsCardStorage/add",
        headers={
            "content-type": "application/json",
            "merchant-token": merchant_token,
        },
        json={"goods_id": goods_id, "content": content, "first": 0, "remove_repeat": 0},
        timeout=15,
        impersonate="chrome110",
    )

    if not resp.ok:
        return {"success": False, "message": f"HTTP {resp.status_code}: {resp.text[:200]}"}

    data = resp.json() if resp.text else {}
    code = data.get("code", 0)
    if isinstance(code, int) and (code < 0 or code >= 300):
        return {"success": False, "message": data.get("message") or data.get("msg") or "推送失败"}

    return {"success": True, "message": "推送成功"}
