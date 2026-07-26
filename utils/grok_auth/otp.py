# -*- coding: utf-8 -*-
"""从邮件正文提取 xAI 验证码。"""
from __future__ import annotations

import re
from typing import Optional

_XAI_CODE_PATTERNS = (
    re.compile(r"(?<![A-Z0-9])([A-Z0-9]{3}-[A-Z0-9]{3})(?![A-Z0-9])"),
    re.compile(
        r"(?i)(?:code|otp|验证码|verification code|verify code|code is|your code)"
        r"\s*[:：]?\s*([A-Z0-9]{3}-[A-Z0-9]{3})"
    ),
    re.compile(
        r"(?i)(?:code|otp|验证码|verification code|verify code|code is|your code)"
        r"\s*[:：]?\s*([A-Z0-9]{6,8})"
    ),
    re.compile(r"(?i)\b[A-Z0-9]{6}\b"),
    re.compile(r"(?i)\b[A-Z0-9]{8}\b"),
    re.compile(
        r"(?i)(?:code|otp|验证码|verification|verify|code is|your code)"
        r"[^A-Za-z0-9]{0,40}([A-Z0-9]{4,8})"
    ),
)


def _is_pure_digits(s: str) -> bool:
    return bool(s) and s.isdigit()


def _looks_like_xai_code(raw: str) -> bool:
    s = (raw or "").strip().upper()
    if not s:
        return False
    if re.fullmatch(r"[A-Z0-9]{3}-[A-Z0-9]{3}", s):
        return True
    compact = re.sub(r"[\s\-]+", "", s)
    if len(compact) not in (6, 8):
        return False
    if not re.fullmatch(r"[A-Z0-9]+", compact):
        return False
    if _is_pure_digits(compact):
        return False
    return True


def extract_xai_code(text: str) -> Optional[str]:
    body = text or ""
    if not body.strip():
        return None
    for pat in _XAI_CODE_PATTERNS:
        m = pat.search(body)
        if not m:
            continue
        raw = (m.group(1) if m.lastindex else m.group(0) or "").strip()
        if _looks_like_xai_code(raw):
            return raw.upper()
    return None
