import unittest

from utils.grok_auth.browser_signup import _build_proxy_config


class BrowserProxyConfigTests(unittest.TestCase):
    def test_socks5_omits_unsupported_browser_auth(self):
        self.assertEqual(
            _build_proxy_config("socks5://user:pass@127.0.0.1:1080"),
            {"server": "socks5://127.0.0.1:1080"},
        )

    def test_http_keeps_browser_auth(self):
        self.assertEqual(
            _build_proxy_config("http://user:pass@127.0.0.1:8080"),
            {"server": "http://127.0.0.1:8080", "username": "user", "password": "pass"},
        )


if __name__ == "__main__":
    unittest.main()
