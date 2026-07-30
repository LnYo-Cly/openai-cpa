# -*- coding: utf-8 -*-
from __future__ import annotations

import queue
import os
import shutil
import threading
import time
from concurrent.futures import Future
from typing import Any, Callable, Dict, List, Optional


_lock = threading.RLock()
_job_q: Optional["queue.Queue[Optional[_PoolJob]]"] = None
_workers: List[threading.Thread] = []
_worker_count = 0
_headless = True
_started = False
_shutting_down = False


class _PoolJob:
    __slots__ = ("fn", "kwargs", "future")

    def __init__(self, fn: Callable[..., Any], kwargs: Dict[str, Any], future: Future):
        self.fn = fn
        self.kwargs = kwargs
        self.future = future


def _desired_size() -> int:
    try:
        from utils import config as cfg

        multi = bool(getattr(cfg, "ENABLE_MULTI_THREAD_REG", False))
        threads = int(getattr(cfg, "REG_THREADS", 1) or 1)
        if multi:
            return max(1, threads)
        return 1
    except Exception:
        return 1


def _launch_browser(headless: bool):
    configured_engine = str(os.environ.get("GROK_BROWSER_ENGINE", "") or "").strip().lower()
    engine = configured_engine or ("chromium" if shutil.which("chromium") else "camoufox")
    if engine in {
        "chromium",
        "chrome",
    }:
        from playwright.sync_api import sync_playwright

        manager = sync_playwright()
        playwright = manager.start()
        try:
            executable = shutil.which("chromium") or shutil.which("chromium-browser")
            if not executable:
                raise RuntimeError("GROK_BROWSER_ENGINE=chromium but chromium is not installed")
            browser = playwright.chromium.launch(
                executable_path=executable,
                headless=bool(headless),
                args=["--no-sandbox", "--disable-dev-shm-usage"],
            )
            return manager, browser
        except Exception:
            manager.stop()
            raise

    from camoufox.sync_api import Camoufox

    # 代理放在 Context 上，浏览器进程本身长期复用
    cm = Camoufox(headless=bool(headless))
    browser = cm.__enter__()
    return cm, browser


def _close_browser(cm, browser) -> None:
    try:
        if browser is not None:
            try:
                browser.close()
            except Exception:
                pass
    finally:
        if cm is not None:
            try:
                if hasattr(cm, "stop"):
                    cm.stop()
                else:
                    cm.__exit__(None, None, None)
            except Exception:
                pass


def _browser_alive(browser) -> bool:
    if browser is None:
        return False
    try:
        return bool(browser.is_connected())
    except Exception:
        return False


def _worker_loop(worker_id: int, headless: bool) -> None:
    global _shutting_down
    cm = None
    browser = None
    try:
        while True:
            with _lock:
                if _shutting_down and (_job_q is None or _job_q.empty()):
                    break
            try:
                job = _job_q.get(timeout=0.4) if _job_q is not None else None
            except queue.Empty:
                continue
            if job is None:
                # 毒丸：退出
                try:
                    if _job_q is not None:
                        _job_q.task_done()
                except Exception:
                    pass
                break

            if not _browser_alive(browser):
                _close_browser(cm, browser)
                cm, browser = None, None
                try:
                    cm, browser = _launch_browser(headless)
                except Exception as exc:
                    try:
                        job.future.set_exception(exc)
                    except Exception:
                        pass
                    try:
                        if _job_q is not None:
                            _job_q.task_done()
                    except Exception:
                        pass
                    continue

            try:
                result = job.fn(browser, **job.kwargs)
                if not job.future.done():
                    job.future.set_result(result)
            except Exception as exc:
                # 浏览器可能已坏，下次任务重建
                try:
                    if not _browser_alive(browser):
                        _close_browser(cm, browser)
                        cm, browser = None, None
                except Exception:
                    cm, browser = None, None
                if not job.future.done():
                    try:
                        job.future.set_exception(exc)
                    except Exception:
                        pass
            finally:
                try:
                    if _job_q is not None:
                        _job_q.task_done()
                except Exception:
                    pass
    finally:
        _close_browser(cm, browser)


def ensure_browser_pool(*, headless: bool = True, size: Optional[int] = None) -> int:
    """按当前多线程配置启动/扩容浏览器池，返回实际 worker 数。"""
    global _job_q, _workers, _worker_count, _headless, _started, _shutting_down

    want = max(1, int(size if size is not None else _desired_size()))
    with _lock:
        if _shutting_down:
            # 停止后允许再次启动
            _shutting_down = False
            _started = False
            _workers = []
            _worker_count = 0
            _job_q = None

        if not _started or _job_q is None:
            _job_q = queue.Queue()
            _headless = bool(headless)
            _workers = []
            _worker_count = 0
            _started = True

        # 只扩容不缩容（缩容在 shutdown）
        while _worker_count < want:
            wid = _worker_count + 1
            t = threading.Thread(
                target=_worker_loop,
                args=(wid, _headless),
                name=f"grok-browser-pool-{wid}",
                daemon=True,
            )
            t.start()
            _workers.append(t)
            _worker_count += 1

        return _worker_count


def run_with_browser(
    fn: Callable[..., Any],
    *,
    headless: bool = True,
    timeout: Optional[float] = None,
    **kwargs: Any,
) -> Any:
    """
    在池内某个 worker 线程执行 fn(browser, **kwargs)。
    Playwright 同步 API 非线程安全：browser 只在所属 worker 线程使用。
    """
    if not callable(fn):
        raise TypeError("fn must be callable")

    ensure_browser_pool(headless=headless)
    fut: Future = Future()
    job = _PoolJob(fn=fn, kwargs=dict(kwargs), future=fut)

    with _lock:
        if _job_q is None or _shutting_down:
            raise RuntimeError("browser pool is not available")
        _job_q.put(job)

    wait_s = None if timeout is None else max(30.0, float(timeout))
    try:
        return fut.result(timeout=wait_s)
    except Exception:
        # 超时/取消时 future 可能仍被 worker 写回，忽略即可
        raise


def shutdown_browser_pool(timeout: float = 8.0) -> None:
    """停止所有浏览器 worker 并关闭进程。"""
    global _job_q, _workers, _worker_count, _started, _shutting_down

    with _lock:
        if not _started and not _workers:
            return
        _shutting_down = True
        q = _job_q
        workers = list(_workers)
        n = len(workers)

    if q is not None:
        for _ in range(n):
            try:
                q.put(None)
            except Exception:
                pass

    deadline = time.time() + max(1.0, float(timeout or 8.0))
    for t in workers:
        remain = deadline - time.time()
        if remain <= 0:
            break
        try:
            t.join(timeout=remain)
        except Exception:
            pass

    with _lock:
        _workers = []
        _worker_count = 0
        _job_q = None
        _started = False
        _shutting_down = False


def browser_pool_status() -> Dict[str, Any]:
    with _lock:
        return {
            "started": _started,
            "workers": _worker_count,
            "headless": _headless,
            "desired": _desired_size(),
            "queue": (0 if _job_q is None else _job_q.qsize()),
        }
