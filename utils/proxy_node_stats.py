import hashlib
import json
import os
import re
import threading
import time
import urllib.parse
from typing import Any, Optional

import requests
import yaml

from utils.clash_group_utils import resolve_group_name


BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, "data")
STATS_PATH = os.path.join(DATA_DIR, "proxy_node_stats.json")
CONFIG_PATH = os.path.join(DATA_DIR, "config.yaml")

_lock = threading.Lock()
_selected_nodes: dict[str, dict[str, Any]] = {}


def _now() -> float:
    return time.time()


def _read_yaml_config() -> dict:
    if not os.path.exists(CONFIG_PATH):
        return {}
    try:
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _write_yaml_config(data: dict) -> None:
    os.makedirs(DATA_DIR, exist_ok=True)
    with open(CONFIG_PATH, "w", encoding="utf-8") as f:
        yaml.safe_dump(data or {}, f, allow_unicode=True, sort_keys=False)


def _read_stats_unlocked() -> dict:
    if not os.path.exists(STATS_PATH):
        return {"version": 1, "items": {}}
    try:
        with open(STATS_PATH, "r", encoding="utf-8") as f:
            data = json.load(f) or {}
        if not isinstance(data, dict):
            return {"version": 1, "items": {}}
        if not isinstance(data.get("items"), dict):
            data["items"] = {}
        data.setdefault("version", 1)
        return data
    except Exception:
        return {"version": 1, "items": {}}


def _write_stats_unlocked(data: dict) -> None:
    os.makedirs(DATA_DIR, exist_ok=True)
    tmp = STATS_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    os.replace(tmp, STATS_PATH)


def _normalize_proxy_url(proxy_url: Optional[str]) -> str:
    text = str(proxy_url or "").strip()
    if not text:
        return ""
    try:
        from utils import config as cfg
        text = cfg.format_docker_url(text)
    except Exception:
        pass
    return text


def _proxy_fingerprint(proxy_url: str) -> str:
    return hashlib.sha256(str(proxy_url or "").encode("utf-8")).hexdigest()[:16]


def _mask_proxy_url(proxy_url: str) -> str:
    text = str(proxy_url or "").strip()
    if not text:
        return ""
    try:
        parsed = urllib.parse.urlparse(text if "://" in text else f"http://{text}")
        scheme = parsed.scheme or "http"
        host = parsed.hostname or ""
        port = f":{parsed.port}" if parsed.port else ""
        if parsed.username:
            return f"{scheme}://***:***@{host}{port}"
        return f"{scheme}://{host}{port}"
    except Exception:
        return re.sub(r"//([^:/@]+):([^@]+)@", "//***:***@", text)


def _proxy_label(proxy_url: str) -> str:
    try:
        parsed = urllib.parse.urlparse(proxy_url if "://" in proxy_url else f"http://{proxy_url}")
        host = parsed.hostname or "unknown"
        port = parsed.port
        if port:
            return f"{host}:{port}"
        return host
    except Exception:
        return _mask_proxy_url(proxy_url) or "default"


def _parse_host_port(url: str) -> tuple[str, Optional[int], str]:
    text = str(url or "").strip()
    if not text:
        return "", None, ""
    if "://" not in text:
        text = f"http://{text}"
    try:
        parsed = urllib.parse.urlparse(text)
        return parsed.hostname or "", parsed.port, parsed.scheme or "http"
    except Exception:
        return "", None, ""


def _controller_candidates(config_data: dict, proxy_url: str = "") -> list[tuple[str, str]]:
    raw_conf = config_data.get("raw_proxy_pool", {}) if isinstance(config_data.get("raw_proxy_pool"), dict) else {}
    clash_conf = config_data.get("clash_proxy_pool", {}) if isinstance(config_data.get("clash_proxy_pool"), dict) else {}
    candidates: list[tuple[str, str]] = []

    for key in ("api_url", "controller_url", "external_controller"):
        value = str(raw_conf.get(key) or "").strip()
        if value:
            candidates.append((value, "raw_proxy_pool"))

    # 兼容旧配置：很多部署把 15559 的控制口暂存在 clash_proxy_pool.api_url。
    value = str(clash_conf.get("api_url") or "").strip()
    if value:
        candidates.append((value, "clash_proxy_pool"))

    host, port, _ = _parse_host_port(proxy_url or str(config_data.get("default_proxy") or ""))
    if host and port:
        guessed_ports = []
        if 15000 <= port < 20000:
            guessed_ports.append(port + 27000)  # 15559 -> 42559
        if 7800 <= port < 8000:
            guessed_ports.append(port + 1200)   # 7897 -> 9097
        if 41000 < port <= 41050:
            guessed_ports.append(port + 1000)
        for guessed in guessed_ports:
            candidates.append((f"http://{host}:{guessed}", "guessed"))

    seen = set()
    uniq = []
    for url, source in candidates:
        if not url:
            continue
        if "://" not in url:
            url = f"http://{url}"
        key = url.rstrip("/")
        if key in seen:
            continue
        seen.add(key)
        uniq.append((key, source))
    return uniq


def _controller_headers(config_data: dict) -> dict:
    raw_conf = config_data.get("raw_proxy_pool", {}) if isinstance(config_data.get("raw_proxy_pool"), dict) else {}
    clash_conf = config_data.get("clash_proxy_pool", {}) if isinstance(config_data.get("clash_proxy_pool"), dict) else {}
    secret = str(raw_conf.get("secret") or clash_conf.get("secret") or "").strip()
    return {"Authorization": f"Bearer {secret}"} if secret else {}


def _resolve_leaf_node(proxy_map: dict, group_name: str) -> tuple[str, str, Optional[int]]:
    """Return (runtime group, current leaf node, last delay)."""
    current_group = resolve_group_name(proxy_map, group_name) or group_name
    node = ""
    delay = None
    visited = set()
    for _ in range(8):
        if not current_group or current_group in visited:
            break
        visited.add(current_group)
        runtime = proxy_map.get(current_group)
        if not isinstance(runtime, dict):
            node = current_group
            break
        now_name = str(runtime.get("now") or "").strip()
        if not now_name:
            node = current_group
            break
        node = now_name
        if now_name in proxy_map and isinstance(proxy_map.get(now_name), dict) and "all" in proxy_map[now_name]:
            current_group = now_name
            continue
        history = proxy_map.get(now_name, {}).get("history", []) if isinstance(proxy_map.get(now_name), dict) else []
        if history:
            last_delay = history[-1].get("delay")
            if isinstance(last_delay, (int, float)):
                delay = int(last_delay)
        break
    return current_group, node, delay


def _fetch_runtime_snapshot(proxy_url: str = "") -> dict:
    config_data = _read_yaml_config()
    raw_conf = config_data.get("raw_proxy_pool", {}) if isinstance(config_data.get("raw_proxy_pool"), dict) else {}
    clash_conf = config_data.get("clash_proxy_pool", {}) if isinstance(config_data.get("clash_proxy_pool"), dict) else {}
    group_hint = str(raw_conf.get("group_name") or clash_conf.get("group_name") or "GLOBAL").strip()

    selected = _selected_nodes.get(_proxy_fingerprint(proxy_url))
    if selected and (_now() - float(selected.get("selected_at") or 0)) < 900:
        return dict(selected)

    for base_url, source in _controller_candidates(config_data, proxy_url):
        try:
            resp = requests.get(f"{base_url.rstrip('/')}/proxies", headers=_controller_headers(config_data), timeout=2.0)
            if resp.status_code not in {200, 204}:
                continue
            proxy_map = (resp.json() or {}).get("proxies", {})
            if not isinstance(proxy_map, dict):
                continue
            group_name, node_name, delay = _resolve_leaf_node(proxy_map, group_hint)
            return {
                "controller_url": base_url,
                "controller_source": source,
                "group_name": group_name or group_hint,
                "node_name": node_name or "",
                "delay_ms": delay,
            }
        except Exception:
            continue
    return {"group_name": group_hint, "node_name": "", "delay_ms": None}


def remember_selected_node(proxy_url: Optional[str], node_name: str, group_name: str = "", delay_ms: Optional[int] = None) -> None:
    proxy_url = _normalize_proxy_url(proxy_url)
    if not proxy_url or not node_name:
        return
    _selected_nodes[_proxy_fingerprint(proxy_url)] = {
        "group_name": str(group_name or "").strip(),
        "node_name": str(node_name or "").strip(),
        "delay_ms": delay_ms,
        "selected_at": _now(),
    }


def classify_error_type(status: str, run_ctx: Optional[dict] = None) -> str:
    ctx = run_ctx or {}
    explicit = str(ctx.get("proxy_error") or ctx.get("proxy_error_type") or "").strip()
    if explicit:
        return explicit
    if status == "success":
        return ""
    if status == "retry_403":
        return "rate_limited_403"
    if ctx.get("phone_verify"):
        return "phone_verify"
    if ctx.get("pwd_blocked"):
        return "password_blocked"
    if ctx.get("signup_blocked"):
        return "signup_blocked"
    return "registration_failed"


def record_registration_result(proxy_url: Optional[str], status: str, run_ctx: Optional[dict] = None) -> None:
    proxy_url = _normalize_proxy_url(proxy_url or (run_ctx or {}).get("proxy"))
    if not proxy_url:
        proxy_url = "DIRECT"
    status = str(status or "failed").strip() or "failed"
    ctx = run_ctx or {}
    runtime = _fetch_runtime_snapshot(proxy_url)
    node_name = str(ctx.get("proxy_node") or runtime.get("node_name") or "").strip()
    error_type = classify_error_type(status, ctx)
    detail = str(ctx.get("proxy_error_detail") or ctx.get("proxy_error_message") or "").strip()[:240]
    region = str(ctx.get("proxy_region") or "").strip()

    key_material = f"{_proxy_fingerprint(proxy_url)}|{node_name or runtime.get('group_name') or 'endpoint'}"
    key = hashlib.sha256(key_material.encode("utf-8")).hexdigest()[:24]
    now_ts = _now()

    with _lock:
        data = _read_stats_unlocked()
        items = data.setdefault("items", {})
        item = items.setdefault(
            key,
            {
                "key": key,
                "proxy_hash": _proxy_fingerprint(proxy_url),
                "proxy_label": _proxy_label(proxy_url),
                "proxy_url_masked": _mask_proxy_url(proxy_url),
                "node_name": node_name,
                "group_name": str(runtime.get("group_name") or ""),
                "controller_url": str(runtime.get("controller_url") or ""),
                "subscription": str(runtime.get("controller_source") or ""),
                "region": region,
                "total": 0,
                "success": 0,
                "failed": 0,
                "retry_403": 0,
                "errors": {},
                "first_seen": now_ts,
                "last_seen": now_ts,
                "last_error": "",
                "last_detail": "",
                "last_delay_ms": runtime.get("delay_ms"),
            },
        )
        item["proxy_label"] = _proxy_label(proxy_url)
        item["proxy_url_masked"] = _mask_proxy_url(proxy_url)
        item["node_name"] = node_name or item.get("node_name", "")
        item["group_name"] = str(runtime.get("group_name") or item.get("group_name") or "")
        item["controller_url"] = str(runtime.get("controller_url") or item.get("controller_url") or "")
        item["subscription"] = str(runtime.get("controller_source") or item.get("subscription") or "")
        item["last_delay_ms"] = runtime.get("delay_ms", item.get("last_delay_ms"))
        if region:
            item["region"] = region
        item["total"] = int(item.get("total") or 0) + 1
        item["last_seen"] = now_ts
        if status == "success":
            item["success"] = int(item.get("success") or 0) + 1
        else:
            item["failed"] = int(item.get("failed") or 0) + 1
            if status == "retry_403":
                item["retry_403"] = int(item.get("retry_403") or 0) + 1
            if error_type:
                errors = item.setdefault("errors", {})
                errors[error_type] = int(errors.get(error_type) or 0) + 1
                item["last_error"] = error_type
                item["last_detail"] = detail
        item["fail_rate"] = round((int(item.get("failed") or 0) / max(1, int(item.get("total") or 0))) * 100, 2)
        items[key] = item
        _write_stats_unlocked(data)


def list_node_stats() -> list[dict]:
    with _lock:
        data = _read_stats_unlocked()
        rows = list((data.get("items") or {}).values())
    rows.sort(key=lambda row: (float(row.get("fail_rate") or 0), int(row.get("total") or 0)), reverse=True)
    return rows


def clear_node_stats() -> None:
    with _lock:
        _write_stats_unlocked({"version": 1, "items": {}})


def blacklist_node(node_name: str) -> tuple[bool, str]:
    value = str(node_name or "").strip()
    if not value:
        return False, "节点名称不能为空。"
    config_data = _read_yaml_config()
    raw_conf = config_data.get("raw_proxy_pool", {}) if isinstance(config_data.get("raw_proxy_pool"), dict) else {}
    raw_conf.setdefault("enable", False)
    raw_conf.setdefault("proxy_list", [])
    blacklist = raw_conf.get("blacklist", [])
    if not isinstance(blacklist, list):
        blacklist = []
    if value not in blacklist:
        blacklist.append(value)
    raw_conf["blacklist"] = blacklist
    config_data["raw_proxy_pool"] = raw_conf
    _write_yaml_config(config_data)
    try:
        from utils import config as cfg
        cfg.reload_all_configs(new_config_dict=config_data)
    except Exception:
        pass
    return True, f"已加入 raw_proxy_pool 黑名单：{value}"


def _group_rows_from_proxy_map(proxy_map: dict, group_hint: str, blacklist: list[str]) -> list[dict]:
    groups = []
    for name, value in proxy_map.items():
        if not isinstance(value, dict) or "all" not in value:
            continue
        nodes = list(value.get("all") or [])
        visible_nodes = []
        for node in nodes:
            node_text = str(node or "")
            visible_nodes.append(
                {
                    "name": node_text,
                    "blacklisted": any(str(kw).upper() in node_text.upper() for kw in blacklist if str(kw).strip()),
                }
            )
        runtime_name, current_node, delay = _resolve_leaf_node(proxy_map, name)
        groups.append(
            {
                "name": name,
                "runtime_name": runtime_name,
                "type": value.get("type") or "",
                "count": len(nodes),
                "current": value.get("now") or "",
                "leaf_current": current_node,
                "leaf_delay_ms": delay,
                "nodes": visible_nodes[:200],
                "nodes_truncated": len(visible_nodes) > 200,
                "is_target": bool(resolve_group_name({name: value}, group_hint)),
            }
        )
    groups.sort(key=lambda row: (not row.get("is_target"), row.get("name", "")))
    return groups


def get_raw_pool_status() -> dict:
    config_data = _read_yaml_config()
    raw_conf = config_data.get("raw_proxy_pool", {}) if isinstance(config_data.get("raw_proxy_pool"), dict) else {}
    clash_conf = config_data.get("clash_proxy_pool", {}) if isinstance(config_data.get("clash_proxy_pool"), dict) else {}
    raw_list = raw_conf.get("proxy_list", [])
    if not isinstance(raw_list, list):
        raw_list = []
    blacklist = raw_conf.get("blacklist", [])
    if not isinstance(blacklist, list):
        blacklist = []
    group_hint = str(raw_conf.get("group_name") or clash_conf.get("group_name") or "GLOBAL").strip()
    default_proxy = str(config_data.get("default_proxy") or "").strip()
    raw_enabled = bool(raw_conf.get("enable", False))
    probe_proxy = raw_list[0] if raw_enabled and raw_list else default_proxy

    status = {
        "enabled": raw_enabled,
        "default_proxy_masked": _mask_proxy_url(default_proxy),
        "proxy_count": len(raw_list),
        "proxies": [
            {
                "label": _proxy_label(_normalize_proxy_url(p)),
                "url_masked": _mask_proxy_url(_normalize_proxy_url(p)),
                "hash": _proxy_fingerprint(_normalize_proxy_url(p)),
            }
            for p in raw_list
        ],
        "controller_url": "",
        "controller_source": "",
        "controller_ok": False,
        "group_name": group_hint,
        "groups": [],
        "blacklist": blacklist,
        "message": "raw_proxy_pool 只按代理 URL 轮换；配置控制口后可读取 15559/Mihomo 当前组和节点。",
    }

    for base_url, source in _controller_candidates(config_data, _normalize_proxy_url(probe_proxy)):
        try:
            resp = requests.get(f"{base_url.rstrip('/')}/proxies", headers=_controller_headers(config_data), timeout=2.5)
            if resp.status_code != 200:
                continue
            proxy_map = (resp.json() or {}).get("proxies", {})
            if not isinstance(proxy_map, dict):
                continue
            status.update(
                {
                    "controller_url": base_url,
                    "controller_source": source,
                    "controller_ok": True,
                    "groups": _group_rows_from_proxy_map(proxy_map, group_hint, blacklist),
                    "message": f"已连接外部 Mihomo 控制口 ({source})，可读取当前策略组和节点。",
                }
            )
            break
        except Exception as exc:
            status["message"] = f"raw_proxy_pool 已启用，但暂未连上控制口：{exc}"
    return status
