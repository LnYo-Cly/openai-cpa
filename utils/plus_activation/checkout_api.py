"""Checkout API + 地址 API 调用"""

import random
import string
import time
from curl_cffi import requests

from utils import config as cfg

FIRST_NAMES = [
    "James", "John", "Robert", "Michael", "William", "David", "Richard",
    "Joseph", "Thomas", "Christopher", "Mary", "Patricia", "Jennifer",
    "Linda", "Barbara", "Elizabeth", "Susan", "Jessica", "Sarah", "Karen",
    "Daniel", "Matthew", "Anthony", "Mark", "Donald", "Steven", "Andrew",
    "Paul", "Joshua", "Kenneth", "Emma", "Olivia", "Ava", "Isabella",
    "Sophia", "Mia", "Charlotte", "Amelia", "Harper", "Evelyn",
]

LAST_NAMES = [
    "Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller",
    "Davis", "Rodriguez", "Martinez", "Hernandez", "Lopez", "Gonzalez",
    "Wilson", "Anderson", "Thomas", "Taylor", "Moore", "Jackson", "Martin",
    "Lee", "Perez", "Thompson", "White", "Harris", "Sanchez", "Clark",
    "Ramirez", "Lewis", "Robinson",
]

SEED_ADDRESSES = {
    "US": [
        {"address1": "Broadway", "city": "New York", "region": "New York", "postalCode": "10007"},
        {"address1": "Market St", "city": "San Francisco", "region": "California", "postalCode": "94105"},
        {"address1": "Michigan Ave", "city": "Chicago", "region": "Illinois", "postalCode": "60601"},
    ],
    "AU": [
        {"address1": "George St", "city": "Sydney", "region": "NSW", "postalCode": "2000"},
        {"address1": "Collins St", "city": "Melbourne", "region": "VIC", "postalCode": "3000"},
    ],
    "DE": [
        {"address1": "Friedrichstrasse", "city": "Berlin", "region": "Berlin", "postalCode": "10117"},
        {"address1": "Marienplatz", "city": "Munich", "region": "Bavaria", "postalCode": "80331"},
    ],
    "FR": [
        {"address1": "Rue de Rivoli", "city": "Paris", "region": "Ile-de-France", "postalCode": "75001"},
        {"address1": "Rue de la Republique", "city": "Lyon", "region": "Auvergne-Rhone-Alpes", "postalCode": "69002"},
    ],
    "ID": [
        {"address1": "Jl. Sudirman", "city": "Jakarta", "region": "DKI Jakarta", "postalCode": "10220"},
        {"address1": "Jl. Gatot Subroto", "city": "Jakarta", "region": "DKI Jakarta", "postalCode": "10270"},
    ],
    "JP": [
        {"address1": "Ginza", "city": "Tokyo", "region": "Tokyo", "postalCode": "1040061"},
        {"address1": "Shinsaibashi", "city": "Osaka", "region": "Osaka", "postalCode": "5420085"},
    ],
    "KR": [
        {"address1": "Gangnam-daero", "city": "Seoul", "region": "Seoul", "postalCode": "06123"},
        {"address1": "Sejong-daero", "city": "Seoul", "region": "Seoul", "postalCode": "04521"},
    ],
}


def create_checkout(accessToken: str) -> dict:
    """Create checkout session via ChatGPT backend API (same as extension)."""
    # If external Checkout API is configured, use it (with optional API key)
    ext_api_url = getattr(cfg, "PLUS_ACT_CHECKOUT_API_URL", "")
    if ext_api_url:
        return _create_checkout_external(accessToken, ext_api_url)

    # Default: call ChatGPT backend API directly (no extra key needed)
    return _create_checkout_chatgpt(accessToken)


def _create_checkout_chatgpt(accessToken: str) -> dict:
    """Call ChatGPT's own /backend-api/payments/checkout — matches extension flow."""
    country = getattr(cfg, "PLUS_ACT_COUNTRY", "US")
    method = getattr(cfg, "PLUS_ACT_PAYMENT_METHOD", "paypal")
    proxy = getattr(cfg, "PLUS_ACT_PROXY", "")

    proxies = {"http": proxy, "https": proxy} if proxy else None

    currency_map = {
        "US": "USD", "AU": "AUD", "DE": "EUR", "FR": "EUR",
        "ID": "IDR", "JP": "JPY", "KR": "KRW", "GB": "GBP",
    }
    currency = currency_map.get(country, "USD")

    payload = {
        "entry_point": "all_plans_pricing_modal",
        "plan_name": "chatgptplusplan",
        "checkout_ui_mode": "hosted" if method == "paypal" else "custom",
        "billing_details": {
            "country": country,
            "currency": currency,
        },
        "promo_campaign": {
            "promo_campaign_id": "plus-1-month-free",
            "is_coupon_from_query_param": False,
        },
    }

    resp = requests.post(
        "https://chatgpt.com/backend-api/payments/checkout",
        json=payload,
        headers={
            "Authorization": f"Bearer {accessToken}",
            "Content-Type": "application/json",
        },
        timeout=30,
        proxies=proxies,
        impersonate="chrome110",
    )

    if resp.status_code != 200:
        raise ValueError(f"ChatGPT Checkout API 返回 HTTP {resp.status_code}: {resp.text[:300]}")

    data = resp.json()
    session_id = data.get("checkout_session_id")
    if not session_id:
        raise ValueError(f"ChatGPT Checkout API 未返回 session ID: {data}")

    checkout_url = f"https://chatgpt.com/checkout/openai_llc/{session_id}"
    return {"checkout_url": checkout_url, "raw": data}


def _create_checkout_external(accessToken: str, api_url: str) -> dict:
    """Call external Checkout API (fallback, requires API key)."""
    api_key = getattr(cfg, "PLUS_ACT_CHECKOUT_API_KEY", "")
    country = getattr(cfg, "PLUS_ACT_COUNTRY", "US")
    method = getattr(cfg, "PLUS_ACT_PAYMENT_METHOD", "paypal")
    proxy = getattr(cfg, "PLUS_ACT_PROXY", "")

    proxies = {"http": proxy, "https": proxy} if proxy else None

    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["X-API-Key"] = api_key

    resp = requests.post(api_url, json={
        "accessToken": accessToken,
        "paymentMethod": method,
        "country": country,
    }, headers=headers, timeout=30, proxies=proxies,
        impersonate="chrome110")

    if resp.status_code != 200:
        raise ValueError(f"Checkout API 返回 HTTP {resp.status_code}: {resp.text[:200]}")

    data = resp.json()
    checkout_url = data.get("url") or data.get("checkoutUrl") or data.get("checkout_url")
    if not checkout_url:
        raise ValueError(f"Checkout API 未返回 checkout URL: {data}")

    return {"checkout_url": checkout_url, "raw": data}


def fetch_us_address() -> dict:
    """Generate a random identity with address. Prefers local seed, falls back to API."""
    country = getattr(cfg, "PLUS_ACT_COUNTRY", "US")
    proxy = getattr(cfg, "PLUS_ACT_PROXY", "")
    first = random.choice(FIRST_NAMES)
    last = random.choice(LAST_NAMES)

    proxies = None
    if proxy:
        proxies = {"http": proxy, "https": proxy}

    # Try address API first
    api_url = getattr(cfg, "PLUS_ACT_ADDRESS_API_URL", "")
    if api_url:
        try:
            resp = requests.post(api_url, json={"path": "/", "method": "address"},
                                 timeout=10, proxies=proxies, impersonate="chrome110")
            if resp.ok:
                addr = resp.json()
                addr.setdefault("name", f"{first} {last}")
                addr.setdefault("firstName", first)
                addr.setdefault("lastName", last)
                return addr
        except Exception:
            pass

    # Use local seed addresses
    country_addrs = SEED_ADDRESSES.get(country, SEED_ADDRESSES["US"])
    seed = random.choice(country_addrs)
    return {
        "name": f"{first} {last}",
        "firstName": first,
        "lastName": last,
        "address": seed["address1"],
        "address1": seed["address1"],
        "city": seed["city"],
        "state": seed["region"],
        "region": seed["region"],
        "zip": seed["postalCode"],
        "postalCode": seed["postalCode"],
        "country": country,
    }


def generate_random_birthday() -> dict:
    """Generate random birthday for age 19-25."""
    year = time.localtime().tm_year - random.randint(19, 25)
    month = random.randint(1, 12)
    day = random.randint(1, 28)
    return {"year": str(year), "month": str(month), "day": str(day)}


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
    """Generate card expiry in MM / YY format (matching PayPal expected format)."""
    import time as _time
    month = random.randint(1, 12)
    current_year_2digit = _time.localtime().tm_year % 100
    year = current_year_2digit + random.randint(2, 5)
    return f"{month:02d} / {year}"


def generate_card_cvv() -> str:
    return f"{random.randint(100, 999)}"
