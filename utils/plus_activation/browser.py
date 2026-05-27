"""Playwright 自动化 — Stripe checkout + PayPal guest checkout"""

import os
import time
import asyncio
import json
import base64
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

    launch_opts = {
        "headless": headless,
        "args": launch_args,
    }

    context_opts = {
        "viewport": {"width": 1280, "height": 800},
        "user_agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/125.0.0.0 Safari/537.36"
        ),
    }

    if proxy:
        scheme, server, username, password = _parse_proxy(proxy)
        # Browser launch proxy enables context-level proxy override
        launch_opts["proxy"] = {"server": f"{scheme}://{server}"}
        # Context-level proxy with optional auth
        ctx_proxy = {"server": f"{scheme}://{server}"}
        if username:
            ctx_proxy["username"] = username
            ctx_proxy["password"] = password
        context_opts["proxy"] = ctx_proxy

    browser_instance = await playwright_instance.chromium.launch(**launch_opts)
    return browser_instance, context_opts, timeout


def _parse_proxy(proxy: str):
    """Parse proxy string into (scheme, server, username, password)."""
    scheme = "http"
    rest = proxy
    if "://" in proxy:
        scheme, rest = proxy.split("://", 1)
    username, password = "", ""
    if "@" in rest:
        auth_part, server = rest.rsplit("@", 1)
        if ":" in auth_part:
            username, password = auth_part.split(":", 1)
        rest = server
    return scheme, rest, username, password


async def activate_plus(browser_instance, context_opts: dict, page_timeout: int,
                        access_token: str) -> dict:
    """Run full Plus activation flow. Returns credential data dict on success."""
    context = await browser_instance.new_context(**context_opts)
    page = await context.new_page()

    try:
        result = await _run_checkout_flow(page, page_timeout, access_token)

        # Extract session data after successful payment
        credentials = await _extract_credentials(page, context, access_token)
        credentials["activation_success"] = True
        return credentials
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
    """Return the root frame for checkout form — page itself or a Stripe iframe frame."""
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
            frame_el = page.locator(sel).first
            if await frame_el.count() > 0:
                # Get the Frame object (not FrameLocator) — supports evaluate/wait_for_timeout
                src = await frame_el.get_attribute("src")
                if src:
                    frame = page.frame(url=src)
                    if frame:
                        return frame
        except Exception:
            continue

    return page


async def _remove_captcha(root):
    """Remove captcha overlays."""
    for sel in ['#captcha-standalone', '.captcha-overlay', '.captcha-container']:
        try:
            await root.evaluate(f"""
                document.querySelectorAll('{sel}').forEach(n => {{
                    try {{ n.remove(); }} catch(e) {{}}
                }});
            """)
        except Exception:
            pass


async def _select_paypal(root):
    # Stripe hosted checkout uses accordion button
    for sel in [
        '[data-testid="paypal-accordion-item-button"]',
        '.paypal-accordion-item button',
    ]:
        try:
            loc = root.locator(sel).first
            if await loc.count() > 0:
                await loc.click(timeout=5000)
                await root.wait_for_timeout(500)
                # Click again for activation
                await loc.click(timeout=3000)
                await root.wait_for_timeout(500)
                return
        except Exception:
            continue

    # Fallback: generic PayPal selectors
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
    # Use precise Stripe/OpenAI hosted checkout IDs first
    precise_fields = {
        "#billingAddressLine1": address.get("address", ""),
        "#billingLocality": address.get("city", ""),
        "#billingPostalCode": address.get("zip", ""),
    }
    for sel, value in precise_fields.items():
        if not value:
            continue
        try:
            loc = root.locator(sel).first
            if await loc.count() > 0:
                await loc.fill(value, timeout=3000)
                continue
        except Exception:
            pass
        # Fallback to generic selectors
        field_name = sel.split("-")[-1].replace("AddressLine1", "address").replace("Locality", "city").replace("PostalCode", "zip").lstrip("#")
        for fallback in [f'input[name*="{field_name}"]', f'input[id*="{field_name}"]']:
            try:
                loc = root.locator(fallback).first
                if await loc.count() > 0:
                    await loc.fill(value, timeout=3000)
                    break
            except Exception:
                continue

    # State/region dropdown — precise ID then fallback
    state = address.get("state", address.get("region", ""))
    if state:
        try:
            region_select = root.locator('#billingAdministrativeArea').first
            if await region_select.count() > 0:
                await region_select.select_option(label=state, timeout=3000)
            else:
                region_select = root.locator('select[name*="state"], select[name*="region"], select[id*="state"], select[id*="AdministrativeArea"]').first
                if await region_select.count() > 0:
                    await region_select.select_option(label=state, timeout=3000)
        except Exception:
            pass

    # Country dropdown
    try:
        country_select = root.locator('#billingCountry').first
        if await country_select.count() > 0:
            await country_select.select_option(value="US", timeout=3000)
        else:
            country_select = root.locator('select[name*="country"], select[data-testid*="country"]').first
            if await country_select.count() > 0:
                await country_select.select_option(value="US", timeout=3000)
    except Exception:
        pass

    # Terms of service checkbox
    try:
        checkbox = root.locator('#termsOfServiceConsentCheckbox').first
        if await checkbox.count() > 0:
            checked = await checkbox.is_checked()
            if not checked:
                await checkbox.click(timeout=3000)
    except Exception:
        pass

    await root.wait_for_timeout(500)


async def _click_subscribe(root):
    # Remove captcha before clicking
    await _remove_captcha(root)

    # Precise data-testid selectors
    for sel in [
        'button[data-testid="submit-button"]',
        'button[data-testid="hosted-payment-submit-button"]',
        'button.SubmitButton--complete',
    ]:
        try:
            loc = root.locator(sel).first
            if await loc.count() > 0:
                await loc.click(timeout=5000)
                return
        except Exception:
            continue

    # Fallback: text-based search
    for text in ["Subscribe", "订阅", "Confirm", "确认", "Pay", "Continue", "Next"]:
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
        generate_random_email, generate_random_password, generate_visa_card,
        generate_card_expiry, generate_card_cvv, fetch_us_address,
    )
    from utils.plus_activation import sms_pool

    # Remove captcha overlays
    await _remove_captcha(page)

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

    await page.wait_for_timeout(2000)

    # Generate fake identity
    email = generate_random_email()
    password = generate_random_password()
    card_number = generate_visa_card()
    expiry = generate_card_expiry()
    cvv = generate_card_cvv()
    loop = asyncio.get_event_loop()
    address = await loop.run_in_executor(None, fetch_us_address)
    sms_entry = sms_pool.choose_entry()
    phone = sms_entry.phone if sms_entry else "1234567890"

    first_name = address.get("firstName", address.get("name", "John").split()[0] if address.get("name") else "John")
    last_name = address.get("lastName", address.get("name", "Doe").split()[-1] if address.get("name") else "Doe")

    # Set country to US first (triggers form reload)
    try:
        country_el = page.locator('#country').first
        if await country_el.count() > 0:
            current_val = await country_el.input_value()
            if current_val.upper() != "US":
                await country_el.select_option(value="US", timeout=3000)
                await page.wait_for_timeout(3000)
    except Exception:
        pass

    # Fill PayPal form — precise IDs matching extension
    paypal_fields = {
        "#email": email,
        "#phone": phone,
        "#cardNumber": card_number.replace(" ", ""),
        "#cardExpiry": expiry,
        "#cardCvv": cvv,
        "#password": password,
        "#firstName": first_name,
        "#lastName": last_name,
        "#billingLine1": address.get("address", ""),
        "#billingCity": address.get("city", ""),
        "#billingPostalCode": address.get("zip", ""),
    }

    for sel, value in paypal_fields.items():
        if not value:
            continue
        try:
            loc = page.locator(sel).first
            if await loc.count() > 0:
                await loc.fill(value, timeout=3000)
                continue
        except Exception:
            pass
        # Fallback to generic name/id selectors
        field_name = sel.lstrip("#")
        for fallback in [f'input[name*="{field_name}"]', f'input[id*="{field_name}"]', f'input[autocomplete*="{field_name}"]']:
            try:
                loc = page.locator(fallback).first
                if await loc.count() > 0:
                    await loc.fill(value, timeout=3000)
                    break
            except Exception:
                continue

    # Billing state dropdown
    state = address.get("state", address.get("region", ""))
    if state:
        try:
            state_el = page.locator('#billingState').first
            if await state_el.count() > 0:
                await state_el.select_option(label=state, timeout=3000)
        except Exception:
            pass

    # Remove captcha again after filling
    await _remove_captcha(page)
    await page.wait_for_timeout(1000)

    # Submit — precise data-testid selectors first
    submitted = False
    for sel in [
        'button[data-testid="submit-button"]',
        'button[data-testid="hosted-payment-submit-button"]',
        'button.SubmitButton--complete',
    ]:
        try:
            loc = page.locator(sel).first
            if await loc.count() > 0:
                await loc.click(timeout=5000)
                submitted = True
                break
        except Exception:
            continue

    if not submitted:
        for text in ["Pay Now", "Pay", "Submit", "Continue", "Agree", "Next"]:
            try:
                btn = page.locator(f'button:has-text("{text}")').first
                if await btn.count() > 0:
                    await btn.click(timeout=5000)
                    submitted = True
                    break
            except Exception:
                continue

    await page.wait_for_timeout(3000)

    # Handle SMS verification
    await _handle_sms_verification(page, sms_entry, timeout)

    # Handle Hermes review page (PayPal consent)
    await _handle_hermes_review(page, timeout)


async def _handle_sms_verification(page, sms_entry, timeout: int):
    from utils.plus_activation import sms_pool

    if not sms_entry:
        return

    timeout_sec = timeout / 1000
    start = time.time()

    while time.time() - start < timeout_sec:
        # Check for PayPal hosted verification (6 individual inputs)
        has_hosted_verify = False
        try:
            first_input = page.locator('#ci-ciBasic-0').first
            if await first_input.count() > 0 and await first_input.is_visible():
                has_hosted_verify = True
        except Exception:
            pass

        # Check for generic verification inputs
        has_generic_verify = False
        if not has_hosted_verify:
            for sel in ['input[name*="code"]', 'input[name*="otp"]', 'input[placeholder*="code"]',
                         'input[placeholder*="verification"]', 'input[maxlength="6"]']:
                try:
                    loc = page.locator(sel).first
                    if await loc.count() > 0 and await loc.is_visible():
                        has_generic_verify = True
                        break
                except Exception:
                    continue

        if not has_hosted_verify and not has_generic_verify:
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

        if has_hosted_verify:
            # PayPal hosted: fill 6 individual digit inputs ci-ciBasic-0..5
            for i in range(6):
                try:
                    digit_input = page.locator(f'#ci-ciBasic-{i}').first
                    if await digit_input.count() > 0:
                        await digit_input.fill(code[i] if i < len(code) else "", timeout=3000)
                except Exception:
                    continue
        else:
            # Generic: fill single input
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

        # Submit code — precise data-testid first
        submitted = False
        for sel in [
            'button[data-testid="submit-button"]',
            'button[data-testid="hosted-payment-submit-button"]',
            'button.SubmitButton--complete',
        ]:
            try:
                loc = page.locator(sel).first
                if await loc.count() > 0:
                    await loc.click(timeout=3000)
                    submitted = True
                    break
            except Exception:
                continue

        if not submitted:
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


async def _handle_hermes_review(page, timeout: int):
    """Handle PayPal Hermes review consent page after SMS verification."""
    timeout_sec = timeout / 1000
    start = time.time()

    while time.time() - start < timeout_sec:
        url = page.url
        # Already past PayPal
        if "chatgpt.com" in url:
            return
        if not any(p in url.lower() for p in PAYPAL_URL_PATTERNS):
            return

        # Look for "Set up once. Pay faster next time" consent button
        consent_clicked = False
        for sel in [
            '#consentButton',
            'button[name="consent"]',
            'button:has-text("Continue")',
            'button:has-text("Agree")',
        ]:
            try:
                loc = page.locator(sel).first
                if await loc.count() > 0 and await loc.is_visible():
                    await loc.click(timeout=5000)
                    consent_clicked = True
                    await page.wait_for_timeout(1500)
                    break
            except Exception:
                continue

        if not consent_clicked:
            # Check for "Agree and Continue" button
            for sel in [
                'button:has-text("Agree and Continue")',
                'input[value="Agree and Continue"]',
                'button[name="continue"]',
                '#confirmButton',
            ]:
                try:
                    loc = page.locator(sel).first
                    if await loc.count() > 0 and await loc.is_visible():
                        await loc.click(timeout=5000)
                        await page.wait_for_timeout(1500)
                        break
                except Exception:
                    continue

        await page.wait_for_timeout(2000)

        # Check if we've left PayPal
        url = page.url
        if "chatgpt.com" in url:
            return

    # Timeout is ok — may have already passed this page


async def _extract_credentials(page, context, access_token: str) -> dict:
    """Extract session cookies and session data after successful payment."""
    result = {"cookies": {}, "session_data": {}}

    # Navigate to chatgpt.com if not already there
    try:
        if "chatgpt.com" not in page.url:
            await page.goto("https://chatgpt.com", timeout=30000, wait_until="networkidle")
            await page.wait_for_timeout(3000)
    except Exception as e:
        print(f"[Plus激活] 导航到 chatgpt.com 失败: {e}")

    # Extract cookies from browser context
    try:
        cookies = await context.cookies()
        for c in cookies:
            if c.get("domain", "").endswith("chatgpt.com"):
                result["cookies"][c["name"]] = c["value"]
    except Exception:
        pass

    # Get session token from cookies
    session_token = result["cookies"].get("__Secure-next-auth.session-token", "")

    # Call /api/auth/session to get session data
    session_data = {}
    try:
        session_resp = await page.evaluate("""
            async () => {
                try {
                    const resp = await fetch('/api/auth/session', {
                        credentials: 'include'
                    });
                    return await resp.json();
                } catch(e) { return {}; }
            }
        """)
        if isinstance(session_resp, dict):
            session_data = session_resp
    except Exception:
        pass

    result["session_data"] = session_data
    result["session_token"] = session_token
    result["access_token"] = session_data.get("accessToken", access_token)
    result["id_token_from_session"] = session_data.get("idToken", "")

    return result


def parse_jwt_payload(token: str) -> dict:
    """Decode JWT payload without verifying signature."""
    try:
        parts = token.split(".")
        if len(parts) < 2:
            return {}
        payload = parts[1]
        # Add padding
        padding = 4 - len(payload) % 4
        if padding != 4:
            payload += "=" * padding
        decoded = base64.urlsafe_b64decode(payload)
        return json.loads(decoded)
    except Exception:
        return {}


def build_codex_credentials(token_data: dict, browser_credentials: dict,
                            email: str) -> dict:
    """Build full codex-format credential dict from token data + browser extracted data."""
    access_token = browser_credentials.get("access_token") or token_data.get("access_token", "")
    refresh_token = token_data.get("refresh_token", "")
    session_token = browser_credentials.get("session_token", "")
    id_token_real = browser_credentials.get("id_token_from_session") or token_data.get("id_token", "")

    # Parse JWT to extract account info
    jwt_payload = parse_jwt_payload(access_token)
    auth_section = jwt_payload.get("https://api.openai.com/auth", {})
    profile_section = jwt_payload.get("https://api.openai.com/profile", {})
    account_id = auth_section.get("chatgpt_account_id", "")
    user_id = auth_section.get("chatgpt_user_id", "")
    plan_type = auth_section.get("chatgpt_plan_type", "chatgptplusplan")
    jwt_email = profile_section.get("email", email)
    exp = jwt_payload.get("exp", 0)

    # Build id_token — use real if available, otherwise synthetic
    id_token_synthetic = False
    if id_token_real:
        id_token = id_token_real
    else:
        id_token_synthetic = True
        synthetic_header = base64.urlsafe_b64encode(
            json.dumps({"alg": "none", "typ": "JWT", "cpa_synthetic": True}).encode()
        ).decode().rstrip("=")
        synthetic_payload = base64.urlsafe_b64encode(json.dumps({
            "https://api.openai.com/auth": {
                "chatgpt_account_id": account_id,
                "chatgpt_user_id": user_id,
                "chatgpt_plan_type": plan_type,
            },
            "https://api.openai.com/profile": {"email": jwt_email},
            "sub": user_id,
            "email": jwt_email,
            "iat": int(time.time()),
            "exp": exp or int(time.time()) + 3600,
        }).encode()).decode().rstrip("=")
        id_token = f"{synthetic_header}.{synthetic_payload}."

    from datetime import datetime, timezone
    now_iso = datetime.now(timezone.utc).isoformat()
    exp_iso = ""
    if exp:
        exp_iso = datetime.fromtimestamp(exp, tz=timezone.utc).isoformat()

    return {
        "type": "codex",
        "account_id": account_id,
        "chatgpt_account_id": account_id,
        "chatgpt_user_id": user_id,
        "email": jwt_email,
        "name": jwt_email,
        "plan_type": "plus",
        "chatgpt_plan_type": plan_type,
        "id_token": id_token,
        "id_token_synthetic": id_token_synthetic,
        "access_token": access_token,
        "refresh_token": refresh_token,
        "session_token": session_token,
        "last_refresh": now_iso,
        "expired": exp_iso,
    }
