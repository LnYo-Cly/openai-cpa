"""SMS 接码池 — 加载、轮询选择、失败追踪"""

import os
import re
import time
import threading
from curl_cffi import requests
from dataclasses import dataclass, field
from typing import Optional

from utils import config as cfg

_pool_lock = threading.RLock()
_entries: list = []
_loaded_at: float = 0

DISABLE_THRESHOLD = 2


@dataclass
class SMSPoolEntry:
    phone: str
    verify_url: str
    use_count: int = 0
    consecutive_failures: int = 0
    disabled: bool = False


def _parse_pool_file(path: str) -> list:
    entries = []
    if not os.path.isfile(path):
        return entries
    with open(path, "r", encoding="utf-8") as f:
        lines = [line.strip() for line in f if line.strip() and not line.strip().startswith("#")]
    i = 0
    while i < len(lines):
        line = lines[i]
        if "----" in line:
            parts = line.split("----", 1)
            phone = parts[0].strip()
            url = parts[1].strip()
            if phone and url:
                entries.append(SMSPoolEntry(phone=phone, verify_url=url))
            i += 1
        else:
            phone = line
            url = lines[i + 1].strip() if i + 1 < len(lines) else ""
            if phone and url and url.startswith("http"):
                entries.append(SMSPoolEntry(phone=phone, verify_url=url))
                i += 2
            else:
                i += 1
    return entries


def reload_pool():
    global _entries, _loaded_at
    pool_file = getattr(cfg, "PLUS_ACT_SMS_POOL_FILE", "")
    if not pool_file:
        return
    if not os.path.isabs(pool_file):
        pool_file = os.path.join(cfg.BASE_DIR, pool_file)
    new_entries = _parse_pool_file(pool_file)
    with _pool_lock:
        old_map = {e.phone + e.verify_url: e for e in _entries}
        merged = []
        for ne in new_entries:
            key = ne.phone + ne.verify_url
            if key in old_map:
                old = old_map[key]
                ne.use_count = old.use_count
                ne.consecutive_failures = old.consecutive_failures
                ne.disabled = old.disabled
            merged.append(ne)
        _entries = merged
        _loaded_at = time.time()


def get_entries() -> list:
    with _pool_lock:
        if not _entries:
            reload_pool()
        return list(_entries)


def choose_entry() -> Optional[SMSPoolEntry]:
    with _pool_lock:
        if not _entries:
            reload_pool()
        if not _entries:
            return None
        available = [e for e in _entries if not e.disabled]
        if not available:
            return None
        available.sort(key=lambda e: (e.use_count, e.consecutive_failures))
        entry = available[0]
        entry.use_count += 1
        return entry


def report_failure(entry: SMSPoolEntry):
    with _pool_lock:
        for e in _entries:
            if e.phone == entry.phone and e.verify_url == entry.verify_url:
                e.consecutive_failures += 1
                if e.consecutive_failures >= DISABLE_THRESHOLD:
                    e.disabled = True
                break


def report_success(entry: SMSPoolEntry):
    with _pool_lock:
        for e in _entries:
            if e.phone == entry.phone and e.verify_url == entry.verify_url:
                e.consecutive_failures = 0
                break


def poll_sms_code(verify_url: str, timeout: int = 120, interval: int = 3) -> str:
    start = time.time()
    while time.time() - start < timeout:
        try:
            resp = requests.get(verify_url, timeout=10,
                                headers={"Accept": "application/json", "Cache-Control": "no-cache"},
                                impersonate="chrome110")
            code = _extract_code(resp.text)
            if code:
                return code
        except Exception:
            pass
        time.sleep(interval)
    raise TimeoutError(f"SMS 验证码在 {timeout}s 内未收到")


_CODE_RE = re.compile(r'(?:verification|code|verify|验证码)[^\d]*(\d{6})', re.IGNORECASE)
_DIGIT_RE = re.compile(r'\b(\d{6})\b')


def _extract_code(text: str) -> str:
    m = _CODE_RE.search(text)
    if m:
        return m.group(1)
    m = _DIGIT_RE.search(text)
    if m:
        return m.group(1)
    return ""


def get_pool_status() -> dict:
    entries = get_entries()
    return {
        "total": len(entries),
        "available": sum(1 for e in entries if not e.disabled),
        "disabled": sum(1 for e in entries if e.disabled),
        "entries": [
            {
                "phone": e.phone,
                "use_count": e.use_count,
                "failures": e.consecutive_failures,
                "disabled": e.disabled,
            }
            for e in entries
        ],
    }
