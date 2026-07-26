# -*- coding: utf-8 -*-
"""兼容主程序停止接口（HTTP 打码旁路已不用）。"""
from __future__ import annotations

from typing import Optional, Tuple

def captcha_provider() -> str:
    return "local"


def auto_start_enabled() -> bool:
    return False


def is_solver_running(url: Optional[str] = None) -> bool:
    return False


def start_local_solver_if_needed(*, force: bool = False, wait_sec: float = 45.0) -> Tuple[bool, str]:
    return True, "skip http solver"


def stop_local_solver_if_owned(timeout: float = 5.0) -> None:
    return None
