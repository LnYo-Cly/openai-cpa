# -*- coding: utf-8 -*-
"""检查本地 Camoufox 浏览器是否可用。"""
from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import List, Optional, Tuple


def _project_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _is_exec_file(path: Path) -> bool:
    try:
        return path.is_file() and path.stat().st_size > 0
    except Exception:
        return False


def _collect_binary_candidates(install_dir: Path, launch_name: Optional[str]) -> List[Path]:
    names = []
    if launch_name:
        names.append(Path(launch_name).name)
    names.extend(["camoufox-bin", "camoufox.exe", "camoufox"])
    # 去重保序
    seen = set()
    uniq_names: List[str] = []
    for n in names:
        if n and n not in seen:
            seen.add(n)
            uniq_names.append(n)

    candidates: List[Path] = []
    for n in uniq_names:
        candidates.append(install_dir / n)

    # 兼容：二进制落在 browsers/official/<ver>/ 等子目录
    if install_dir.is_dir():
        for n in uniq_names:
            try:
                for hit in install_dir.rglob(n):
                    if _is_exec_file(hit):
                        candidates.append(hit)
            except Exception:
                pass
        # 常见新布局
        for sub in (
            install_dir / "browsers",
            install_dir / "browsers" / "official",
        ):
            if not sub.is_dir():
                continue
            for n in uniq_names:
                try:
                    for hit in sub.rglob(n):
                        if _is_exec_file(hit):
                            candidates.append(hit)
                except Exception:
                    pass

    out: List[Path] = []
    seen_path = set()
    for c in candidates:
        key = str(c)
        if key in seen_path:
            continue
        seen_path.add(key)
        out.append(c)
    return out


def _ensure_root_launch_link(install_dir: Path, real_bin: Path, launch_name: Optional[str]) -> Path:
    """
    camoufox 启动只认 INSTALL_DIR 下的 camoufox-bin/camoufox.exe。
    若实际文件在版本子目录，补根目录符号链接（失败则复制）。
    """
    target_name = Path(launch_name).name if launch_name else real_bin.name
    if not target_name:
        target_name = "camoufox-bin"
    root_link = install_dir / target_name

    try:
        if root_link.resolve() == real_bin.resolve() and _is_exec_file(root_link):
            return root_link
    except Exception:
        if _is_exec_file(root_link):
            return root_link

    if _is_exec_file(root_link):
        return root_link

    try:
        install_dir.mkdir(parents=True, exist_ok=True)
    except Exception:
        pass

    # 相对链接更稳（容器迁移时不易断）
    try:
        if root_link.exists() or root_link.is_symlink():
            root_link.unlink()
    except Exception:
        pass

    try:
        rel = os.path.relpath(str(real_bin), str(install_dir))
        os.symlink(rel, str(root_link))
        if _is_exec_file(root_link) or root_link.is_symlink():
            return root_link
    except Exception:
        pass

    try:
        import shutil

        shutil.copy2(str(real_bin), str(root_link))
        try:
            os.chmod(str(root_link), 0o755)
        except Exception:
            pass
        if _is_exec_file(root_link):
            return root_link
    except Exception:
        pass

    return real_bin


def find_camoufox_binary() -> Tuple[bool, str]:
    """定位 Camoufox 可执行文件；必要时在 INSTALL_DIR 根目录建立启动链接。"""
    try:
        from camoufox.pkgman import INSTALL_DIR, LAUNCH_FILE, OS_NAME  # type: ignore
    except Exception as exc:
        return False, f"camoufox 包异常: {exc}"

    install_dir = Path(str(INSTALL_DIR))
    launch_name = LAUNCH_FILE.get(OS_NAME) if isinstance(LAUNCH_FILE, dict) else None
    if not launch_name:
        return False, f"未知系统，无法定位 Camoufox 可执行文件: {OS_NAME}"

    for c in _collect_binary_candidates(install_dir, launch_name):
        if not _is_exec_file(c):
            continue
        final = c
        try:
            # 不在根目录时，补链接供 launch_path() 使用
            if c.parent.resolve() != install_dir.resolve():
                final = _ensure_root_launch_link(install_dir, c, launch_name)
        except Exception:
            final = c
        return True, f"camoufox binary ready: {final}"

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


def _camoufox_binary_ready() -> Tuple[bool, str]:
    return find_camoufox_binary()


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
    try:
        from .browser_pool import shutdown_browser_pool
        shutdown_browser_pool(timeout=timeout)
    except Exception:
        pass