import unittest
from unittest.mock import patch

from utils.grok_auth import browser_signup


class _Page:
    url = browser_signup.SIGNUP_URL

    def __init__(self):
        self.gotos = []

    def set_default_timeout(self, _timeout):
        pass

    def goto(self, url, **kwargs):
        self.gotos.append((url, kwargs))


class GrokBrowserSignupTests(unittest.TestCase):
    def test_signup_page_uses_single_domcontentloaded_navigation(self):
        page = _Page()
        logs = []
        with patch.object(browser_signup, "_click_email_signup", return_value=False), patch.object(
            browser_signup, "_dump_debug"
        ), patch.object(browser_signup.time, "sleep"):
            result = browser_signup._signup_on_page(
                page,
                email="user@example.test",
                password="password",
                fetch_code=lambda: "",
                log=logs.append,
            )

        self.assertEqual(result["error"], "未提交邮箱")
        self.assertEqual(len(page.gotos), 1)
        self.assertEqual(page.gotos[0][0], browser_signup.SIGNUP_URL)
        self.assertEqual(page.gotos[0][1]["wait_until"], "domcontentloaded")
        self.assertIn("正在打开注册页", logs)
        self.assertIn("注册页已加载", logs)


if __name__ == "__main__":
    unittest.main()
