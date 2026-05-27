"""Plus 激活 Worker — 主循环、线程管理、浏览器生命周期"""

import json
import time
import threading
import asyncio
from typing import Optional

from utils import config as cfg

_log_prefix = "[Plus激活]"


def _log(msg: str, level: str = "INFO"):
    ts = time.strftime("%H:%M:%S")
    print(f"[{ts}] [{_log_prefix}] [{level}] {msg}")


class PlusActivationWorker:
    def __init__(self):
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self.current_account: str = ""

    def start(self):
        if self.is_running():
            _log("Worker 已在运行")
            return
        if not getattr(cfg, "PLUS_ACT_ENABLE", False):
            _log("Plus 激活未启用，跳过启动")
            return
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run_wrapper, daemon=True)
        self._thread.start()
        _log("Worker 已启动")

    def stop(self):
        self._stop_event.set()
        _log("Worker 收到停止信号")

    def is_running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def _run_wrapper(self):
        try:
            asyncio.run(self._run_loop())
        except Exception as e:
            _log(f"Worker 异常退出: {e}", "ERROR")

    async def _run_loop(self):
        from playwright.async_api import async_playwright
        from utils.plus_activation.browser import launch_browser, activate_plus
        from utils.plus_activation import queue_manager, sms_pool
        from utils.auth_pipeline.oauth import refresh_oauth_token

        pw = await async_playwright().start()
        browser_instance = None

        try:
            browser_instance, context_opts, page_timeout = await launch_browser(pw)
            _log("Chromium 实例已启动")

            queue_manager.recover_stuck()
            _log("已恢复卡住的 processing 任务")

            while not self._stop_event.is_set():
                try:
                    item = queue_manager.dequeue()
                except Exception as e:
                    _log(f"出队失败: {e}", "ERROR")
                    await asyncio.sleep(5)
                    continue

                if not item:
                    await asyncio.sleep(5)
                    continue

                email = item.get("email", "unknown")
                self.current_account = email
                item_id = item.get("id")

                try:
                    token_data = json.loads(item.get("token_data", "{}"))
                except Exception:
                    _log(f"账号 {email} token 数据无效", "ERROR")
                    queue_manager.mark_failed(item_id, "token 数据无效",
                                              max_retries=getattr(cfg, "PLUS_ACT_RETRY_LIMIT", 3))
                    self.current_account = ""
                    continue

                _log(f"开始处理账号: {email}")

                try:
                    # Step 1: Refresh RT (sync call, run in executor)
                    rt = token_data.get("refresh_token", "")
                    if not rt:
                        raise ValueError("缺少 refresh_token")

                    _log(f"正在刷新令牌: {email}")
                    proxy = getattr(cfg, "PLUS_ACT_PROXY", "")
                    proxies = {"http": proxy, "https": proxy} if proxy else None

                    loop = asyncio.get_event_loop()
                    ok, new_tokens = await loop.run_in_executor(
                        None, refresh_oauth_token, rt, proxies
                    )
                    if not ok:
                        raise ValueError(f"RT 刷新失败: {new_tokens}")

                    access_token = new_tokens.get("access_token", "")
                    new_rt = new_tokens.get("refresh_token", rt)
                    id_token = new_tokens.get("id_token", "")

                    token_data.update({
                        "access_token": access_token,
                        "refresh_token": new_rt,
                        "id_token": id_token,
                    })
                    _log(f"令牌刷新成功: {email}")

                    # Step 2: Checkout + PayPal automation
                    _log(f"开始 Plus 激活流程: {email}")

                    # Reload SMS pool before each activation
                    sms_pool.reload_pool()

                    browser_creds = await activate_plus(
                        browser_instance, context_opts, page_timeout, access_token
                    )

                    if browser_creds.get("activation_success"):
                        _log(f"Plus 激活成功: {email}", "SUCCESS")

                        # Step 3: Refresh RT again to get final credentials
                        try:
                            ok2, final_tokens = await loop.run_in_executor(
                                None, refresh_oauth_token, new_rt, proxies
                            )
                            if ok2:
                                token_data.update({
                                    "access_token": final_tokens.get("access_token", access_token),
                                    "refresh_token": final_tokens.get("refresh_token", new_rt),
                                    "id_token": final_tokens.get("id_token", id_token),
                                })
                        except Exception:
                            _log(f"最终令牌刷新失败，使用当前令牌: {email}", "WARN")

                        # Step 4: Build codex format credentials
                        from utils.plus_activation.browser import build_codex_credentials
                        codex = build_codex_credentials(token_data, browser_creds, email)
                        _log(f"凭证构建完成: account_id={codex.get('chatgpt_account_id', '')}, plan={codex.get('chatgpt_plan_type', '')}")

                        # Step 5: Push to targets
                        from utils.plus_activation.push_handler import push_activated_account
                        push_targets = getattr(cfg, "PLUS_ACT_PUSH_TARGETS", [])
                        if push_targets:
                            _log(f"正在推送至 {push_targets}: {email}")
                            results = await loop.run_in_executor(
                                None, push_activated_account, codex, push_targets
                            )
                            for target, result in results.items():
                                status = "成功" if result.get("success") else f"失败: {result.get('message')}"
                                _log(f"推送 {target}: {status}")

                        queue_manager.mark_done(item_id)
                    else:
                        raise ValueError("激活流程未返回成功")

                except Exception as e:
                    err_msg = str(e)
                    _log(f"账号 {email} 激活失败: {err_msg}", "ERROR")
                    queue_manager.mark_failed(
                        item_id, err_msg,
                        max_retries=getattr(cfg, "PLUS_ACT_RETRY_LIMIT", 3)
                    )

                    # Browser might be in bad state, restart
                    try:
                        await browser_instance.close()
                    except Exception:
                        pass
                    try:
                        browser_instance, context_opts, page_timeout = await launch_browser(pw)
                        _log("Chromium 实例已重启")
                    except Exception as restart_err:
                        _log(f"Chromium 重启失败: {restart_err}", "ERROR")
                        break

                finally:
                    self.current_account = ""

                # Delay between accounts
                retry_delay = getattr(cfg, "PLUS_ACT_RETRY_DELAY", 30)
                await asyncio.sleep(retry_delay)

        except Exception as e:
            _log(f"Worker 主循环异常: {e}", "ERROR")
        finally:
            if browser_instance:
                try:
                    await browser_instance.close()
                except Exception:
                    pass
            await pw.stop()
            _log("Worker 已停止，Chromium 已关闭")
