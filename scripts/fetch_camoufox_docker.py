# -*- coding: utf-8 -*-
"""Docker/CI: install Camoufox browser with optional GitHub token (secret file)."""
from __future__ import annotations

import os
import sys
import time
from pathlib import Path


def _load_token() -> str:
    for p in (
        os.environ.get("GITHUB_TOKEN_FILE") or "",
        "/run/secrets/github_token",
        "/run/secrets/GITHUB_TOKEN",
    ):
        p = str(p or "").strip()
        if not p:
            continue
        try:
            fp = Path(p)
            if fp.is_file():
                tok = fp.read_text(encoding="utf-8", errors="ignore").strip()
                if tok:
                    return tok
        except Exception:
            pass
    return (
        os.environ.get("GITHUB_TOKEN")
        or os.environ.get("GH_TOKEN")
        or os.environ.get("CAMOUFOX_GITHUB_TOKEN")
        or ""
    ).strip()


def _patch_requests(token: str) -> str:
    import requests

    orig_get = requests.get

    def _get(url, *args, **kwargs):
        headers = dict(kwargs.pop("headers", None) or {})
        headers.setdefault("User-Agent", "openai-cpa-docker-camoufox-fetch")
        headers.setdefault("Accept", "application/vnd.github+json")
        if token and "api.github.com" in str(url):
            headers["Authorization"] = f"Bearer {token}"
        kwargs["headers"] = headers
        if kwargs.get("timeout") is None:
            kwargs["timeout"] = 120 if "api.github.com" in str(url) else 600
        return orig_get(url, *args, **kwargs)

    requests.get = _get  # type: ignore[assignment]
    return "with-token" if token else "no-token"


def _binary_ready() -> tuple[bool, str]:
    # 与运行时同一套逻辑：支持子目录 + 自动补根目录启动链接
    try:
        from utils.grok_auth.embedded_turnstile import find_camoufox_binary

        return find_camoufox_binary()
    except Exception:
        pass

    # 构建早期只有 /tmp 脚本、还没有项目代码时的兜底
    from camoufox.pkgman import INSTALL_DIR, LAUNCH_FILE, OS_NAME

    install_dir = Path(str(INSTALL_DIR))
    launch_name = LAUNCH_FILE.get(OS_NAME) if isinstance(LAUNCH_FILE, dict) else None
    names = []
    if launch_name:
        names.append(Path(launch_name).name)
    names.extend(["camoufox-bin", "camoufox.exe", "camoufox"])

    found = None
    for n in names:
        direct = install_dir / n
        if direct.is_file() and direct.stat().st_size > 0:
            found = direct
            break
        if install_dir.is_dir():
            try:
                for hit in install_dir.rglob(n):
                    if hit.is_file() and hit.stat().st_size > 0:
                        found = hit
                        break
            except Exception:
                pass
        if found:
            break

    if not found:
        sample = []
        if install_dir.is_dir():
            try:
                sample = sorted(p.name for p in install_dir.iterdir())[:20]
            except Exception:
                sample = []
        return False, f"dir={install_dir} sample={sample}"

    # 补根目录链接，供 camoufox.launch_path() 使用
    target_name = Path(launch_name).name if launch_name else found.name
    root = install_dir / target_name
    if not (root.is_file() and root.stat().st_size > 0):
        try:
            if root.exists() or root.is_symlink():
                root.unlink()
        except Exception:
            pass
        try:
            rel = os.path.relpath(str(found), str(install_dir))
            os.symlink(rel, str(root))
        except Exception:
            try:
                import shutil

                shutil.copy2(str(found), str(root))
                os.chmod(str(root), 0o755)
            except Exception:
                pass
    return True, str(root if root.exists() else found)


def main() -> int:
    token = _load_token()
    mode = _patch_requests(token)
    print(f"[camoufox-fetch] auth={mode}", flush=True)

    last_err = ""
    for attempt in range(1, 4):
        print(f"[camoufox-fetch] attempt {attempt}/3", flush=True)
        try:
            from camoufox.__main__ import CamoufoxUpdate

            CamoufoxUpdate().update()
            ok, info = _binary_ready()
            if ok:
                print(f"[camoufox-fetch] browser ready: {info}", flush=True)
                try:
                    from camoufox.addons import DefaultAddons, maybe_download_addons

                    maybe_download_addons(list(DefaultAddons))
                    print("[camoufox-fetch] addons ok", flush=True)
                except Exception as exc:
                    print(f"[camoufox-fetch] addons skipped: {exc}", flush=True)
                return 0
            last_err = f"binary missing after update: {info}"
            print(f"[camoufox-fetch] {last_err}", flush=True)
        except Exception as exc:
            last_err = f"{type(exc).__name__}: {exc}"
            print(f"[camoufox-fetch] failed: {last_err}", flush=True)
        if attempt < 3:
            time.sleep(8 * attempt)

    print(f"[camoufox-fetch] giving up: {last_err}", flush=True)
    return 1


if __name__ == "__main__":
    sys.exit(main())