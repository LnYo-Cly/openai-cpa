"""Checkout API + 地址 API 调用"""

import random
import string
from curl_cffi import requests

from utils import config as cfg


def create_checkout(accessToken: str) -> dict:
    api_url = getattr(cfg, "PLUS_ACT_CHECKOUT_API_URL", "")
    if not api_url:
        raise ValueError("未配置 Checkout API URL")
    country = getattr(cfg, "PLUS_ACT_COUNTRY", "US")
    method = getattr(cfg, "PLUS_ACT_PAYMENT_METHOD", "paypal")
    proxy = getattr(cfg, "PLUS_ACT_PROXY", "")

    proxies = None
    if proxy:
        proxies = {"http": proxy, "https": proxy}

    resp = requests.post(api_url, json={
        "accessToken": accessToken,
        "paymentMethod": method,
        "country": country,
    }, headers={"Content-Type": "application/json"}, timeout=30, proxies=proxies,
        impersonate="chrome110")

    if resp.status_code != 200:
        raise ValueError(f"Checkout API 返回 HTTP {resp.status_code}: {resp.text[:200]}")

    data = resp.json()
    checkout_url = data.get("url") or data.get("checkoutUrl") or data.get("checkout_url")
    if not checkout_url:
        raise ValueError(f"Checkout API 未返回 checkout URL: {data}")

    return {"checkout_url": checkout_url, "raw": data}


def fetch_us_address() -> dict:
    api_url = getattr(cfg, "PLUS_ACT_ADDRESS_API_URL", "")
    proxy = getattr(cfg, "PLUS_ACT_PROXY", "")

    proxies = None
    if proxy:
        proxies = {"http": proxy, "https": proxy}

    if api_url:
        try:
            resp = requests.post(api_url, json={"path": "/", "method": "address"},
                                 timeout=10, proxies=proxies, impersonate="chrome110")
            if resp.ok:
                return resp.json()
        except Exception:
            pass

    try:
        resp = requests.get("https://randomuser.me/api/?nat=us&inc=location&noinfo",
                            timeout=10, proxies=proxies, impersonate="chrome110")
        if resp.ok:
            loc = resp.json()["results"][0]["location"]
            return {
                "name": f"{loc['street']['name']} {loc['street']['number']}",
                "address": f"{loc['street']['number']} {loc['street']['name']}",
                "city": loc["city"],
                "state": loc["state"],
                "zip": str(loc["postcode"]),
                "country": "US",
            }
    except Exception:
        pass

    return {
        "name": "123 Main St",
        "address": "123 Main St",
        "city": "New York",
        "state": "NY",
        "zip": "10001",
        "country": "US",
    }


def generate_random_email() -> str:
    prefix = "".join(random.choices(string.ascii_lowercase + string.digits, k=10))
    domains = ["gmail.com", "yahoo.com", "outlook.com", "hotmail.com"]
    return f"{prefix}@{random.choice(domains)}"


def generate_random_password() -> str:
    chars = string.ascii_letters + string.digits + "!@#$%"
    return "".join(random.choices(chars, k=16))


def generate_visa_card() -> str:
    prefix = random.choice(["4147", "4100"])
    digits = [int(d) for d in prefix]
    while len(digits) < 15:
        digits.append(random.randint(0, 9))
    total = 0
    for i, d in enumerate(digits):
        if i % 2 == 0:
            total += d * 2
            if d * 2 > 9:
                total -= 9
        else:
            total += d
    check = (10 - total % 10) % 10
    digits.append(check)
    return "".join(str(d) for d in digits)


def generate_card_expiry() -> str:
    month = random.randint(1, 12)
    year = random.randint(2027, 2030)
    return f"{month:02d}/{year}"


def generate_card_cvv() -> str:
    return f"{random.randint(100, 999)}"
