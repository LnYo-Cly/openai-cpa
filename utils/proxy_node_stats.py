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
_GROUP_MARKERS = {"DIRECT", "REJECT", "GLOBAL", "COMPATIBLE", "PASS", "REJECT-DROP"}
_PSEUDO_PREFIXES = ("LB-", "AUTO", "URL-TEST", "FALLBACK", "LOADBALANCE", "SELECT")
UNCAPTURED_NODE = "uncaptured"


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


def _is_group_entry(proxy_map: Optional[dict], name: str) -> bool:
    if not proxy_map or not name:
        return False
    value = proxy_map.get(name)
    return isinstance(value, dict) and "all" in value


def is_real_exit_node(name: Any, group_hint: str = "", proxy_map: Optional[dict] = None) -> bool:
    """True only for leaf exit nodes; DIRECT/GLOBAL/LB-* strategy groups are excluded."""
    text = str(name or "").strip()
    if not text:
        return False
    if text.lower() in {UNCAPTURED_NODE, "unknown", "endpoint"}:
        return False
    upper = text.upper()
    if upper in _GROUP_MARKERS:
        return False
    if upper.startswith(_PSEUDO_PREFIXES):
        return False
    hint = str(group_hint or "").strip()
    if hint and (text == hint or upper == hint.upper()):
        return False
    if _is_group_entry(proxy_map, text):
        return False
    return True


def _sanitize_node_name(name: Any, group_hint: str = "", proxy_map: Optional[dict] = None) -> str:
    text = str(name or "").strip()
    if is_real_exit_node(text, group_hint=group_hint, proxy_map=proxy_map):
        return text
    return ""


def _real_member_count(proxy_map: dict, group_name: str) -> int:
    runtime = proxy_map.get(group_name) if isinstance(proxy_map, dict) else None
    if not isinstance(runtime, dict):
        return 0
    nodes = runtime.get("all") or []
    return sum(1 for node in nodes if is_real_exit_node(node, group_hint=group_name, proxy_map=proxy_map))


def select_target_node_pool_group(proxy_map: dict, group_hint: str = "GLOBAL") -> tuple[str, int]:
    """
    Pick the Mihomo group used for 15559 node-pool counting.
    When group_hint is GLOBAL (or a pure selector), prefer the biggest non-DIRECT/non-REJECT
    real proxy group such as LB-GLOBAL-REFINED.
    """
    proxy_map = proxy_map if isinstance(proxy_map, dict) else {}
    hint = str(group_hint or "GLOBAL").strip() or "GLOBAL"
    resolved = resolve_group_name(proxy_map, hint) or hint

    def _candidate_score(name: str) -> int:
        return _real_member_count(proxy_map, name)

    prefer_biggest = (not resolved) or (str(resolved).strip().upper() in {"GLOBAL", "PROXY", "SELECT", "NODE", "节点选择"})
    if prefer_biggest:
        best_name = ""
        best_count = -1
        for name, value in proxy_map.items():
            if not isinstance(value, dict) or "all" not in value:
                continue
            upper = str(name or "").upper()
            if upper in _GROUP_MARKERS:
                continue
            count = _candidate_score(name)
            if count > best_count:
                best_count = count
                best_name = name
        if best_name and best_count > 0:
            return best_name, best_count

    if resolved and isinstance(proxy_map.get(resolved), dict) and "all" in proxy_map[resolved]:
        return resolved, _candidate_score(resolved)
    return resolved or hint, 0


def _resolve_leaf_node(proxy_map: dict, group_name: str) -> tuple[str, str, Optional[int]]:
    """Return (runtime group, current leaf node, last delay). Leaf is never DIRECT/GLOBAL/LB-*."""
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
            node = current_group if is_real_exit_node(current_group, group_hint=group_name, proxy_map=proxy_map) else ""
            break
        now_name = str(runtime.get("now") or "").strip()
        if not now_name:
            # Load-balance / empty selector: no single leaf from /proxies.
            node = ""
            break
        if now_name in proxy_map and isinstance(proxy_map.get(now_name), dict) and "all" in proxy_map[now_name]:
            current_group = now_name
            node = ""
            continue
        if not is_real_exit_node(now_name, group_hint=group_name, proxy_map=proxy_map):
            node = ""
            break
        node = now_name
        history = proxy_map.get(now_name, {}).get("history", []) if isinstance(proxy_map.get(now_name), dict) else []
        if history:
            last_delay = history[-1].get("delay")
            if isinstance(last_delay, (int, float)):
                delay = int(last_delay)
        break
    return current_group, node, delay


def _node_from_chains(chains: Any, group_hint: str = "") -> str:
    for item in chains or []:
        name = _sanitize_node_name(item, group_hint=group_hint)
        if name:
            return name
    return ""


def _active_connection_snapshot(proxy_url: str = "", host_hint: str = "") -> dict:
    config_data = _read_yaml_config()
    _, port, _ = _parse_host_port(proxy_url or str(config_data.get("default_proxy") or ""))
    raw_conf = config_data.get("raw_proxy_pool", {}) if isinstance(config_data.get("raw_proxy_pool"), dict) else {}
    clash_conf = config_data.get("clash_proxy_pool", {}) if isinstance(config_data.get("clash_proxy_pool"), dict) else {}
    group_hint = str(raw_conf.get("group_name") or clash_conf.get("group_name") or "LB-GLOBAL-REFINED").strip()
    host_hint = str(host_hint or "").strip().lower()
    for base_url, source in _controller_candidates(config_data, proxy_url):
        try:
            resp = requests.get(f"{base_url.rstrip('/')}/connections", headers=_controller_headers(config_data), timeout=1.5)
            if resp.status_code != 200:
                continue
            connections = resp.json().get("connections") or []
            # Prefer host_hint matches (auth.openai.com), then any inboundPort match.
            ranked = []
            for conn in connections:
                meta = conn.get("metadata") or {}
                if port and str(meta.get("inboundPort") or "") != str(port):
                    continue
                host = str(meta.get("host") or "").lower()
                prefer = 0 if (host_hint and host_hint in host) else 1
                ranked.append((prefer, conn))
            ranked.sort(key=lambda item: item[0])
            for _, conn in ranked:
                node = _node_from_chains(conn.get("chains"), group_hint)
                if node:
                    # Prefer reporting the actual load-balance pool when chain exposes it.
                    chain_groups = [
                        str(x or "").strip()
                        for x in (conn.get("chains") or [])
                        if str(x or "").strip().upper().startswith("LB-")
                    ]
                    report_group = chain_groups[0] if chain_groups else group_hint
                    return {
                        "controller_url": base_url,
                        "controller_source": source,
                        "group_name": report_group,
                        "node_name": node,
                        "delay_ms": None,
                    }
        except Exception:
            continue
    return {}


def remember_active_proxy_node(proxy_url: Optional[str], run_ctx: Optional[dict] = None, host_hint: str = "auth.openai.com") -> None:
    proxy_url = _normalize_proxy_url(proxy_url or (run_ctx or {}).get("proxy"))
    snap = _active_connection_snapshot(proxy_url, host_hint=host_hint)
    node = _sanitize_node_name(snap.get("node_name"), group_hint=str(snap.get("group_name") or ""))
    if not node:
        return
    remember_selected_node(proxy_url, node, str(snap.get("group_name") or ""), snap.get("delay_ms"))
    if run_ctx is not None:
        run_ctx["proxy_node"] = node
        run_ctx["proxy_group"] = snap.get("group_name") or ""


def start_proxy_node_watcher(
    proxy_url: Optional[str],
    run_ctx: Optional[dict] = None,
    host_hint: str = "auth.openai.com",
    interval: float = 0.4,
    max_seconds: float = 90.0,
) -> dict:
    """
    Bounded daemon that polls Mihomo /connections during an active registration.
    Stop with stop_proxy_node_watcher(handle) in finally.
    """
    handle = {"stop": threading.Event(), "thread": None}
    if run_ctx is None:
        return handle
    proxy_url = _normalize_proxy_url(proxy_url or run_ctx.get("proxy"))
    if not proxy_url:
        return handle
    stop_event: threading.Event = handle["stop"]

    def _loop() -> None:
        deadline = _now() + max(5.0, float(max_seconds or 90.0))
        sleep_s = max(0.2, float(interval or 0.4))
        while not stop_event.is_set() and _now() < deadline:
            try:
                remember_active_proxy_node(proxy_url, run_ctx, host_hint=host_hint)
            except Exception:
                pass
            stop_event.wait(sleep_s)

    thread = threading.Thread(target=_loop, name="proxy-node-watcher", daemon=True)
    handle["thread"] = thread
    thread.start()
    return handle


def stop_proxy_node_watcher(handle: Optional[dict], join_timeout: float = 1.0) -> None:
    if not isinstance(handle, dict):
        return
    stop_event = handle.get("stop")
    if isinstance(stop_event, threading.Event):
        stop_event.set()
    thread = handle.get("thread")
    if thread is not None and getattr(thread, "is_alive", lambda: False)():
        try:
            thread.join(timeout=max(0.1, float(join_timeout or 1.0)))
        except Exception:
            pass


def _fetch_runtime_snapshot(proxy_url: str = "") -> dict:
    config_data = _read_yaml_config()
    raw_conf = config_data.get("raw_proxy_pool", {}) if isinstance(config_data.get("raw_proxy_pool"), dict) else {}
    clash_conf = config_data.get("clash_proxy_pool", {}) if isinstance(config_data.get("clash_proxy_pool"), dict) else {}
    group_hint = str(raw_conf.get("group_name") or clash_conf.get("group_name") or "GLOBAL").strip()

    selected = _selected_nodes.get(_proxy_fingerprint(proxy_url))
    if selected and (_now() - float(selected.get("selected_at") or 0)) < 900:
        snap = dict(selected)
        snap["node_name"] = _sanitize_node_name(snap.get("node_name"), group_hint=str(snap.get("group_name") or group_hint))
        return snap
    active = _active_connection_snapshot(proxy_url)
    if active:
        active["node_name"] = _sanitize_node_name(active.get("node_name"), group_hint=str(active.get("group_name") or group_hint))
        if active.get("node_name"):
            return active

    for base_url, source in _controller_candidates(config_data, proxy_url):
        try:
            resp = requests.get(f"{base_url.rstrip('/')}/proxies", headers=_controller_headers(config_data), timeout=2.0)
            if resp.status_code not in {200, 204}:
                continue
            proxy_map = (resp.json() or {}).get("proxies", {})
            if not isinstance(proxy_map, dict):
                continue
            pool_group, _ = select_target_node_pool_group(proxy_map, group_hint)
            group_name, node_name, delay = _resolve_leaf_node(proxy_map, pool_group or group_hint)
            return {
                "controller_url": base_url,
                "controller_source": source,
                "group_name": group_name or pool_group or group_hint,
                "node_name": _sanitize_node_name(node_name, group_hint=group_name or pool_group or group_hint, proxy_map=proxy_map),
                "delay_ms": delay,
            }
        except Exception:
            continue
    return {"group_name": group_hint, "node_name": "", "delay_ms": None}


def remember_selected_node(proxy_url: Optional[str], node_name: str, group_name: str = "", delay_ms: Optional[int] = None) -> None:
    proxy_url = _normalize_proxy_url(proxy_url)
    node_name = _sanitize_node_name(node_name, group_hint=group_name)
    if not proxy_url or not node_name:
        return
    _selected_nodes[_proxy_fingerprint(proxy_url)] = {
        "group_name": str(group_name or "").strip(),
        "node_name": node_name,
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
        # Endpoint-less local direct traffic; never treat this as a Mihomo leaf node name.
        proxy_url = "local-direct"
    status = str(status or "failed").strip() or "failed"
    ctx = run_ctx or {}
    runtime = _fetch_runtime_snapshot(proxy_url)
    group_name = str(ctx.get("proxy_group") or runtime.get("group_name") or "").strip()
    node_name = _sanitize_node_name(ctx.get("proxy_node") or runtime.get("node_name"), group_hint=group_name)
    if not node_name:
        node_name = UNCAPTURED_NODE
    error_type = classify_error_type(status, ctx)
    detail = str(ctx.get("proxy_error_detail") or ctx.get("proxy_error_message") or "").strip()[:240]
    region = str(ctx.get("proxy_region") or "").strip()

    key_material = f"{_proxy_fingerprint(proxy_url)}|{node_name}"
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
                "group_name": group_name,
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
        item["node_name"] = node_name
        item["group_name"] = group_name or str(item.get("group_name") or "")
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


def _merge_exclude_filter(existing: str, node_name: str) -> str:
    escaped = re.escape(str(node_name or "").strip())
    if not escaped:
        return str(existing or "")
    current = str(existing or "").strip()
    if escaped in current:
        return current
    return f"{current}|{escaped}" if current else escaped


def _apply_mihomo_blacklist(config_data: dict, node_name: str) -> str:
    path = os.path.join(DATA_DIR, "mihomo-dukadi-15559", "config.yaml")
    if not os.path.exists(path):
        return "未找到 15559 Mihomo 配置，已仅写入 Wenfxl 黑名单。"
    try:
        with open(path, "r", encoding="utf-8") as f:
            mihomo_cfg = yaml.safe_load(f) or {}
        providers = mihomo_cfg.get("proxy-providers") or {}
        for provider in providers.values():
            if isinstance(provider, dict):
                provider["exclude-filter"] = _merge_exclude_filter(provider.get("exclude-filter", ""), node_name)
        with open(path, "w", encoding="utf-8") as f:
            yaml.safe_dump(mihomo_cfg, f, allow_unicode=True, sort_keys=False)
    except Exception as exc:
        return f"写入 15559 Mihomo 黑名单失败：{exc}"

    for base_url, _ in _controller_candidates(config_data, str(config_data.get("default_proxy") or "")):
        try:
            resp = requests.put(
                f"{base_url.rstrip('/')}/configs?force=true",
                headers=_controller_headers(config_data),
                json={"path": "/root/.config/mihomo/config.yaml"},
                timeout=3,
            )
            if resp.status_code in {200, 204}:
                return "已写入 15559 Mihomo exclude-filter 并热重载。"
        except Exception:
            continue
    return "已写入 15559 Mihomo exclude-filter；控制口热重载失败，请重启 mihomo-dukadi-15559。"


def blacklist_node(node_name: str) -> tuple[bool, str]:
    value = str(node_name or "").strip()
    if not value:
        return False, "节点名称不能为空。"
    if not is_real_exit_node(value):
        return False, f"不能拉黑非真实出口节点：{value}"
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
    mihomo_msg = _apply_mihomo_blacklist(config_data, value)
    try:
        from utils import config as cfg
        cfg.reload_all_configs(new_config_dict=config_data)
    except Exception:
        pass
    return True, f"已加入 15559 节点池黑名单：{value}；{mihomo_msg}"


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
    # Always prefer default_proxy (e.g. 15559) for controller probe; raw list is secondary.
    probe_proxy = default_proxy or (raw_list[0] if raw_enabled and raw_list else "")

    status = {
        "enabled": raw_enabled,
        "pool_mode": "default_proxy_mihomo" if default_proxy else ("raw_proxy_pool" if raw_enabled else "none"),
        "pool_label": "15559 全局代理节点池",
        "default_proxy_masked": _mask_proxy_url(default_proxy),
        "proxy_count": 0,
        "raw_proxy_list_count": len(raw_list),
        "node_pool_count": 0,
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
        "target_group": group_hint,
        "groups": [],
        "blacklist": blacklist,
        "message": "统计目标是 default_proxy（如 15559）背后的 Mihomo 全局节点池；raw_proxy_pool 开关不影响下方状态。",
    }

    for base_url, source in _controller_candidates(config_data, _normalize_proxy_url(probe_proxy)):
        try:
            resp = requests.get(f"{base_url.rstrip('/')}/proxies", headers=_controller_headers(config_data), timeout=2.5)
            if resp.status_code != 200:
                continue
            proxy_map = (resp.json() or {}).get("proxies", {})
            if not isinstance(proxy_map, dict):
                continue
            target_group, node_pool_count = select_target_node_pool_group(proxy_map, group_hint)
            status.update(
                {
                    "controller_url": base_url,
                    "controller_source": source,
                    "controller_ok": True,
                    "group_name": target_group or group_hint,
                    "target_group": target_group or group_hint,
                    "proxy_count": int(node_pool_count or 0),
                    "node_pool_count": int(node_pool_count or 0),
                    "groups": _group_rows_from_proxy_map(proxy_map, target_group or group_hint, blacklist),
                    "message": (
                        f"已连接 15559 Mihomo 控制口 ({source})，"
                        f"目标节点池 {target_group or group_hint} 共 {int(node_pool_count or 0)} 个真实出口节点。"
                    ),
                }
            )
            break
        except Exception as exc:
            status["message"] = f"15559 Mihomo 控制口暂未连上：{exc}"
    if not status["controller_ok"] and raw_enabled and raw_list:
        # Fallback only when controller is down and raw list is actually used.
        status["proxy_count"] = len(raw_list)
        status["message"] = (
            status.get("message")
            or "未连上 15559 Mihomo 控制口；临时显示 raw_proxy_pool.proxy_list 数量。"
        )
    return status
