# -*- coding: utf-8 -*-
"""Grok 打码准备：只检查 Camoufox。"""
from __future__ import annotations

from typing import Tuple

from .embedded_turnstile import ensure_camoufox


def captcha_provider() -> str:
    return "local"


def ensure_captcha_ready() -> Tuple[bool, str]:
    try:
        ok, msg = ensure_camoufox(force=False)
        return bool(ok), str(msg or "")
    except Exception as exc:
        return False, f"Camoufox 准备失败: {exc}"
