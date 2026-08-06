import unittest
from unittest.mock import patch

from utils.integrations import grok2api_client as client_module


class _Response:
    def __init__(self, status_code, text, payload=None):
        self.status_code = status_code
        self.text = text
        self._payload = payload

    def json(self):
        if self._payload is not None:
            return self._payload
        raise ValueError("not json")


class Grok2APIClientTests(unittest.TestCase):
    def setUp(self):
        client_module._TOKEN_CACHE.clear()

    def test_parse_sse_result_returns_import_summary(self):
        body = 'data: {"stage":"sync"}\n\ndata: {"created":1,"updated":0,"synced":1,"skipped":0}\n\n'
        self.assertEqual(
            client_module._parse_sse_result(body),
            {"created": 1, "updated": 0, "synced": 1, "skipped": 0},
        )

    def test_console_import_uses_console_route_and_reuses_login_token(self):
        client = client_module.Grok2APIClient(
            "http://grok2api.test", "admin", "secret", "grok_console", timeout=30
        )
        login = _Response(
            200,
            "{}",
            {"data": {"tokens": {"accessToken": "cached-token"}}},
        )
        imported = _Response(200, 'data: {"created":1,"updated":0,"synced":1,"skipped":0}\n\n')

        with patch.object(client_module.cffi_requests, "post", side_effect=[login, imported, imported]) as post:
            self.assertEqual(client.push_sso("sso-console"), (True, "console 导入完成 created=1, updated=0, synced=1, skipped=0"))
            self.assertEqual(client.push_sso("sso-console-2"), (True, "console 导入完成 created=1, updated=0, synced=1, skipped=0"))

        self.assertEqual(post.call_count, 3)
        self.assertEqual(post.call_args_list[1].args[0], "http://grok2api.test/api/admin/v1/accounts/console/import")
        self.assertEqual(post.call_args_list[1].kwargs["files"]["files"][0], "grok-console-sso-tokens.txt")
        self.assertEqual(post.call_args_list[2].args[0], "http://grok2api.test/api/admin/v1/accounts/console/import")

    def test_web_import_uses_web_route(self):
        client = client_module.Grok2APIClient(
            "http://grok2api.test", "web-admin", "secret", "grok_web", timeout=30
        )
        with patch.object(
            client_module.cffi_requests,
            "post",
            side_effect=[
                _Response(200, "{}", {"data": {"tokens": {"accessToken": "web-token"}}}),
                _Response(200, 'data: {"created":0,"updated":1,"synced":1,"skipped":0}\n\n'),
            ],
        ) as post:
            ok, message = client.push_sso("sso-web")

        self.assertTrue(ok)
        self.assertIn("updated=1", message)
        self.assertEqual(post.call_args_list[1].args[0], "http://grok2api.test/api/admin/v1/accounts/web/import")
        self.assertEqual(post.call_args_list[1].kwargs["files"]["files"][0], "grok-web-sso-tokens.txt")


if __name__ == "__main__":
    unittest.main()
