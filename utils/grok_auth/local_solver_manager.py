# -*- coding: utf-8 -*-
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
    try:
        from .browser_pool import shutdown_browser_pool
        shutdown_browser_pool(timeout=timeout)
    except Exception:
        pass
