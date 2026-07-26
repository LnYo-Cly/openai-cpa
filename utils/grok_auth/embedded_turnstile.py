# -*- coding: utf-8 -*-
"""检查本地 Camoufox 浏览器是否可用。"""
from __future__ import annotations

import os
import sys
import time
from pathlib import Path
from typing import Tuple


def _project_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _camoufox_binary_ready() -> Tuple[bool, str]:
    try:
        from camoufox.pkgman import INSTALL_DIR, LAUNCH_FILE, OS_NAME  # type: ignore
    except Exception as exc:
        return False, f"camoufox 包异常: {exc}"

    install_dir = Path(str(INSTALL_DIR))
    launch_name = LAUNCH_FILE.get(OS_NAME) if isinstance(LAUNCH_FILE, dict) else None
    if not launch_name:
        return False, f"未知系统，无法定位 Camoufox 可执行文件: {OS_NAME}"

    candidates = [
        install_dir / launch_name,
        install_dir / "camoufox.exe",
        install_dir / "camoufox-bin",
    ]
    for c in candidates:
        try:
            if c.is_file() and c.stat().st_size > 0:
                return True, f"camoufox binary ready: {c}"
        except Exception:
            continue

    if install_dir.is_dir():
        try:
            names = sorted(os.listdir(install_dir))[:12]
        except Exception:
            names = []
        return (
            False,
            "Camoufox 浏览器本体未安装完整。"
            f"目录={install_dir} 内容={names or '空'}。"
            "请本机开代理后执行: python -m camoufox fetch",
        )
    return (
        False,
        "Camoufox 浏览器本体未下载。"
        f"期望目录={install_dir}。"
        "注意: pip install camoufox 只装 Python 包，还要执行: python -m camoufox fetch",
    )


def ensure_camoufox(*, force: bool = False, timeout_sec: float = 900.0) -> Tuple[bool, str]:
    try:
        import camoufox  # noqa: F401
    except Exception as exc:
        return (
            False,
            f"未安装 camoufox Python 包: {exc}. 请执行: pip install camoufox",
        )

    ok, msg = _camoufox_binary_ready()
    if ok:
        return True, msg + (" (skip fetch)" if force else "")

    if not force:
        return False, msg

    import subprocess

    cmd = [sys.executable, "-m", "camoufox", "fetch"]
    last_err = ""
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_sec,
            env=os.environ.copy(),
            cwd=str(_project_root()),
        )
        out = ((proc.stdout or "") + "\n" + (proc.stderr or "")).strip()
        ok2, msg2 = _camoufox_binary_ready()
        if proc.returncode == 0 and ok2:
            return True, f"camoufox fetch ok: {msg2}"
        last_err = out[-800:] if out else f"exit={proc.returncode}"
        if not ok2:
            last_err = f"{last_err} | after-check: {msg2}"
    except subprocess.TimeoutExpired:
        last_err = "timeout"
    except Exception as exc:
        last_err = str(exc)
    return (
        False,
        "camoufox fetch 失败（常见原因: GitHub API 限流 403 / 代理不通）。"
        f" 详情: {last_err}。"
        "请开本地代理后手动执行: python -m camoufox fetch",
    )


def ensure_embedded_ready(*, force: bool = False, wait_sec: float = 60.0) -> Tuple[bool, str]:
    return ensure_camoufox(force=force)


def stop_embedded_solver(timeout: float = 8.0) -> None:
    return None
