import json
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from utils.grok_auth import register


class GrokRegisterFlowTests(unittest.TestCase):
    def test_sso_push_precedes_oauth_and_returns_oauth_record(self):
        events = []

        def push_sso(sso):
            events.append(("grok2api", sso))
            return True, "console imported"

        def complete_oauth(email, password, **kwargs):
            self.assertEqual(kwargs["session_cookies"]["sso"], "sso-token")
            events.append(("oauth", email))
            return SimpleNamespace(
                token={
                    "access_token": "access-token",
                    "refresh_token": "refresh-token",
                    "expires_in": 3600,
                },
                userinfo={"email": email},
            )

        with patch.object(register, "ensure_camoufox", return_value=(True, "")), patch.object(
            register, "get_email_and_token", return_value=("user@example.test", "jwt")
        ), patch.object(
            register,
            "signup_with_camoufox",
            return_value={"ok": True, "sso": "sso-token", "cookies": {}},
        ), patch("utils.integrations.grok2api_client.push_grok_sso", push_sso), patch.object(
            register, "complete_build_oauth", side_effect=complete_oauth
        ), patch.object(register.cfg, "GROK2API_ENABLE", True), patch.object(
            register, "set_last_email"
        ):
            token_json, password = register.run()

        self.assertTrue(password)
        self.assertEqual([event[0] for event in events], ["grok2api", "oauth"])
        record = json.loads(token_json)
        self.assertEqual(record["access_token"], "access-token")
        self.assertEqual(record["refresh_token"], "refresh-token")
        self.assertEqual(record["sso"], "sso-token")
        self.assertEqual(record["provider"], "grok")


if __name__ == "__main__":
    unittest.main()
