import os
import unittest
from unittest.mock import patch

from utils.grok_auth import register


class GrokProxyEnvironmentTests(unittest.TestCase):
    def test_explicit_registration_proxy_does_not_mutate_process_proxy_environment(self):
        baseline_http = "http://baseline.invalid:8080"
        baseline_https = "http://baseline.invalid:8443"

        def signup(_email, _password, **_kwargs):
            self.assertEqual(os.environ.get("HTTP_PROXY"), baseline_http)
            self.assertEqual(os.environ.get("HTTPS_PROXY"), baseline_https)
            return {"ok": False, "error": "test stop"}

        with patch.dict(
            os.environ,
            {"HTTP_PROXY": baseline_http, "HTTPS_PROXY": baseline_https},
            clear=False,
        ), patch.object(register, "ensure_camoufox", return_value=(True, "")), patch.object(
            register, "get_email_and_token", return_value=("user@example.test", "jwt")
        ), patch.object(register, "signup_with_camoufox", side_effect=signup):
            self.assertEqual(register.run(proxy="socks5://proxy.example:1080"), (None, None))


if __name__ == "__main__":
    unittest.main()
