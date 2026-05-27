"""Playwright 自动化 — Stripe checkout + PayPal guest checkout"""

import os
import time
import asyncio
from typing import Optional

from utils import config as cfg

PAYPAL_URL_PATTERNS = ["paypal.com", "paypalobjects.com"]


async def launch_browser(playwright_instance):
    headless = getattr(cfg, "PLUS_ACT_HEADLESS", True)
    proxy = getattr(cfg, "PLUS_ACT_PROXY", "")
    timeout = getattr(cfg, "PLUS_ACT_BROWSER_TIMEOUT", 120) * 1000

    launch_args = [
        "--disable-blink-features=AutomationControlled",
        "--no-sandbox",
        "--disable-dev-shm-usage",
    ]

    context_opts = {
        "viewport": {"width": 1280, "height": 800},
        "user_agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/125.0.0.0 Safari/537.36"
        ),
    }
    if proxy:
        if "://" in proxy:
            parsed = proxy.split("://", 1)
            context_opts["proxy"] = {"server": f"{parsed[0]}://{parsed[1]}"}
            if "@" in parsed[1]:
                auth_part, server_part = parsed[1].rsplit("@", 1)
                if ":" in auth_part:
                    u, p = auth_part.split(":", 1)
                    context_opts["proxy"]["username"] = u
                    context_opts["proxy"]["password"] = p
        else:
            context_opts["proxy"] = {"server": f"http://{proxy}"}

    browser_instance = await playwright_instance.chromium.launch(
        headless=headless,
        args=launch_args,
    )
    return browser_instance, context_opts, timeout


async def activate_plus(browser_instance, context_opts: dict, page_timeout: int,
                        access_token: str) -> bool:
    context = await browser_instance.new_context(**context_opts)
    page = await context.new_page()

    try:
        return await _run_checkout_flow(page, page_timeout, access_token)
    except Exception as e:
        try:
            screenshot_path = os.path.join(cfg.BASE_DIR, "data", "plus_error_screenshots")
            os.makedirs(screenshot_path, exist_ok=True)
            ts = int(time.time())
            await page.screenshot(path=os.path.join(screenshot_path, f"error_{ts}.png"))
        except Exception:
            pass
        raise
    finally:
        try:
            await context.close()
        except Exception:
            pass


async def _run_checkout_flow(page, timeout: int, access_token: str) -> bool:
    from utils.plus_activation.checkout_api import create_checkout

    # Step 1: Create checkout session (sync HTTP call — run in executor)
    loop = asyncio.get_event_loop()
    checkout_result = await loop.run_in_executor(None, create_checkout, access_token)
    checkout_url = checkout_result["checkout_url"]

    # Step 2: Navigate to Stripe checkout
    await page.goto(checkout_url, timeout=timeout, wait_until="networkidle")
    await page.wait_for_timeout(2000)

    # Resolve the checkout frame — Stripe may embed in an iframe on chatgpt.com
    checkout_root = await _resolve_checkout_root(page)

    # Step 3: Select PayPal payment method
    await _select_paypal(checkout_root)

    # Step 4: Fill billing address
    from utils.plus_activation.checkout_api import fetch_us_address
    address = await loop.run_in_executor(None, fetch_us_address)
    await _fill_billing_address(checkout_root, address)

    # Step 5: Click Subscribe
    await _click_subscribe(checkout_root)

    # Step 6: Wait for PayPal redirect
    await _wait_for_paypal(page, timeout)

    # Step 7: PayPal guest checkout
    await _paypal_guest_checkout(page, timeout)

    # Step 8: Wait for success redirect
    return await _wait_for_success(page, timeout)


async def _resolve_checkout_root(page):
    """Return the root locator for checkout form — page itself or a Stripe iframe."""
    if "checkout.stripe.com" in page.url:
        return page

    # On chatgpt.com / other sites, Stripe embeds in an iframe
    for sel in [
        'iframe[src*="checkout.stripe.com"]',
        'iframe[src*="js.stripe.com"]',
        'iframe[title*="Stripe"]',
        'iframe[name*="__stripe"]',
        'iframe[src*="stripe.com"]',
    ]:
        try:
            frame_loc = page.locator(sel).first
            if await frame_loc.count() > 0:
                return frame_loc.content_frame
        except Exception:
            continue

    return page


async def _select_paypal(root):
    for sel in [
        'text=PayPal',
        '[data-testid="paypal-radio"]',
        '[aria-label*="PayPal"]',
        'input[value="paypal"]',
        'label:has-text("PayPal")',
    ]:
        try:
            loc = root.locator(sel).first
            if await loc.count() > 0:
                await loc.click(timeout=5000)
                await root.wait_for_timeout(500)
                return
        except Exception:
            continue
    raise ValueError("未找到 PayPal 支付选项")


async def _fill_billing_address(root, address: dict):
    fill_fields = {
        "name": address.get("name", ""),
        "address": address.get("address", ""),
        "city": address.get("city", ""),
        "state": address.get("state", ""),
        "zip": address.get("zip", ""),
    }

    for field_name, value in fill_fields.items():
        if not value:
            continue
        selectors = [
            f'input[name*="{field_name}"]',
            f'input[id*="{field_name}"]',
            f'input[placeholder*="{field_name}"]',
            f'input[data-testid*="{field_name}"]',
        ]
        for selector in selectors:
            try:
                loc = root.locator(selector).first
                if await loc.count() > 0:
                    await loc.fill(value, timeout=3000)
                    break
            except Exception:
                continue

    # Country dropdown
    try:
        country_select = root.locator('select[name*="country"], select[data-testid*="country"]').first
        if await country_select.count() > 0:
            await country_select.select_option(value="US", timeout=3000)
    except Exception:
        pass

    await root.wait_for_timeout(500)


async def _click_subscribe(root):
    for text in ["Subscribe", "订阅", "Confirm", "确认", "Pay"]:
        try:
            btn = root.locator(f'button:has-text("{text}")').first
            if await btn.count() > 0:
                await btn.click(timeout=5000)
                return
        except Exception:
            continue

    try:
        btn = root.locator('button[type="submit"]').first
        if await btn.count() > 0:
            await btn.click(timeout=5000)
            return
    except Exception:
        pass

    raise ValueError("未找到 Subscribe/确认按钮")


async def _wait_for_paypal(page, timeout: int):
    timeout_sec = timeout / 1000
    start = time.time()
    while time.time() - start < timeout_sec:
        url = page.url
        if any(p in url.lower() for p in PAYPAL_URL_PATTERNS):
            return
        if "redirect_status=pending" in url or "payments/success" in url:
            return
        await page.wait_for_timeout(1000)
    raise TimeoutError("等待 PayPal 页面超时")


async def _paypal_guest_checkout(page, timeout: int):
    url = page.url
    if not any(p in url.lower() for p in PAYPAL_URL_PATTERNS):
        return

    from utils.plus_activation.checkout_api import (
        generate_random_email, generate_visa_card,
        generate_card_expiry, generate_card_cvv, fetch_us_address,
    )
    from utils.plus_activation import sms_pool

    # Click "Pay with Debit or Credit Card" if present
    for text in ["Debit or Credit Card", "pay with card", "guest"]:
        try:
            guest_btn = page.locator(f'text="{text}"').first
            if await guest_btn.count() > 0:
                await guest_btn.click(timeout=5000)
                await page.wait_for_timeout(1500)
                break
        except Exception:
            continue

    # Generate fake identity
    email = generate_random_email()
    card_number = generate_visa_card()
    expiry = generate_card_expiry()
    cvv = generate_card_cvv()
    address = fetch_us_address()
    sms_entry = sms_pool.choose_entry()
    phone = sms_entry.phone if sms_entry else ""

    # Fill PayPal form fields
    fields = {
        "email": email,
        "card_number": card_number.replace(" ", ""),
        "expiry": expiry,
        "cvv": cvv,
        "firstName": address.get("name", "John").split()[0] if address.get("name") else "John",
        "lastName": address.get("name", "Doe").split()[-1] if address.get("name") else "Doe",
        "address1": address.get("address", ""),
        "city": address.get("city", ""),
        "state": address.get("state", ""),
    }

    for field_name, value in fields.items():
        if not value:
            continue
        selectors = [
            f'input[name*="{field_name}"]',
            f'input[id*="{field_name}"]',
            f'input[data-testid*="{field_name}"]',
            f'input[autocomplete*="{field_name}"]',
        ]
        for selector in selectors:
            try:
                loc = page.locator(selector).first
                if await loc.count() > 0:
                    await loc.fill(value, timeout=3000)
                    break
            except Exception:
                continue

    # Phone field
    if phone:
        for sel in ['input[name*="phone"]', 'input[id*="phone"]', 'input[type="tel"]']:
            try:
                loc = page.locator(sel).first
                if await loc.count() > 0:
                    await loc.fill(phone, timeout=3000)
                    break
            except Exception:
                continue

    await page.wait_for_timeout(1000)

    # Submit payment form
    for text in ["Pay Now", "Pay", "Submit", "Continue"]:
        try:
            btn = page.locator(f'button:has-text("{text}")').first
            if await btn.count() > 0:
                await btn.click(timeout=5000)
                break
        except Exception:
            continue

    await page.wait_for_timeout(3000)

    # Handle SMS verification
    await _handle_sms_verification(page, sms_entry, timeout)


async def _handle_sms_verification(page, sms_entry, timeout: int):
    from utils.plus_activation import sms_pool

    if not sms_entry:
        return

    timeout_sec = timeout / 1000
    start = time.time()

    while time.time() - start < timeout_sec:
        # Check if verification form is visible
        has_verify = False
        for sel in ['input[name*="code"]', 'input[name*="otp"]', 'input[placeholder*="code"]',
                     'input[placeholder*="verification"]', 'input[maxlength="6"]']:
            try:
                loc = page.locator(sel).first
                if await loc.count() > 0 and await loc.is_visible():
                    has_verify = True
                    break
            except Exception:
                continue

        if not has_verify:
            url = page.url
            if any(p in url.lower() for p in ["chatgpt.com", "payments/success", "redirect_status"]):
                sms_pool.report_success(sms_entry)
                return
            await page.wait_for_timeout(2000)
            continue

        # Poll for SMS code (sync, run in executor)
        loop = asyncio.get_event_loop()
        try:
            code = await loop.run_in_executor(
                None, sms_pool.poll_sms_code, sms_entry.verify_url, 60, 3
            )
        except TimeoutError:
            sms_pool.report_failure(sms_entry)
            raise TimeoutError("PayPal SMS 验证码未收到")

        # Enter code
        for sel in ['input[name*="code"]', 'input[name*="otp"]', 'input[placeholder*="code"]',
                     'input[maxlength="6"]']:
            try:
                loc = page.locator(sel).first
                if await loc.count() > 0:
                    await loc.fill(code, timeout=3000)
                    break
            except Exception:
                continue

        await page.wait_for_timeout(500)

        # Submit code
        for text in ["Submit", "Verify", "Confirm", "Continue"]:
            try:
                btn = page.locator(f'button:has-text("{text}")').first
                if await btn.count() > 0:
                    await btn.click(timeout=3000)
                    break
            except Exception:
                continue

        await page.wait_for_timeout(3000)

        # Check if verification passed (URL changed or error appeared)
        url = page.url
        if any(p in url.lower() for p in ["chatgpt.com", "payments/success"]):
            sms_pool.report_success(sms_entry)
            return

        # If still on verification page, the code was wrong
        error_visible = False
        for text in ["incorrect", "invalid", "wrong", "try again", "错误"]:
            try:
                err_loc = page.locator(f'text="{text}"').first
                if await err_loc.count() > 0:
                    error_visible = True
                    break
            except Exception:
                continue

        if error_visible:
            sms_pool.report_failure(sms_entry)
            raise ValueError("PayPal SMS 验证码错误")

    raise TimeoutError("PayPal SMS 验证超时")


async def _wait_for_success(page, timeout: int) -> bool:
    timeout_sec = timeout / 1000
    start = time.time()
    while time.time() - start < timeout_sec:
        url = page.url
        if "chatgpt.com" in url and ("payments/success" in url or "redirect_status=pending" in url):
            return True
        await page.wait_for_timeout(2000)
    raise TimeoutError("等待支付成功跳转超时")
