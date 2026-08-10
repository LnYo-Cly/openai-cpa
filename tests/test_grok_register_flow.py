import json
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from utils.grok_auth import register


class GrokRegisterFlowTests(unittest.TestCase):
    def test_sub2api_keeps_original_grok_oauth_endpoint(self):
        from utils.integrations import sub2api_client

        client = sub2api_client.Sub2APIClient("http://sub2api.test", "api-key")
        response = SimpleNamespace(
            status_code=200,
            text="{}",
            json=lambda: {},
        )
        settings = {
            "concurrency": 10,
            "priority": 1,
            "rate_multiplier": 1.0,
            "group_ids": [26],
        }

        with patch.object(sub2api_client.cffi_requests, "post", return_value=response) as post:
            ok, message = client._import_grok_oauth(
                {
                    "email": "user@example.test",
                    "access_token": "access-token",
                    "refresh_token": "refresh-token",
                },
                settings,
            )

        self.assertTrue(ok)
        self.assertEqual(message, "Sub2API Grok 账号导入成功")
        self.assertEqual(post.call_args.args[0], "http://sub2api.test/api/v1/admin/accounts")
        self.assertEqual(post.call_args.kwargs["json"]["platform"], "grok")
        self.assertEqual(post.call_args.kwargs["json"]["type"], "oauth")
        self.assertEqual(post.call_args.kwargs["json"]["credentials"]["access_token"], "access-token")


if __name__ == "__main__":
    unittest.main()
