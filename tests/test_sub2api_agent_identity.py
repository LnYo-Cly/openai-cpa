import importlib
import json
import sys
import types
import unittest
from unittest.mock import patch


_yaml_module = types.SimpleNamespace(
    safe_load=lambda *args, **kwargs: {},
    dump=lambda *args, **kwargs: None,
)


class _FakeResponse:
    def __init__(self, status_code, payload, text=""):
        self.status_code = status_code
        self._payload = payload
        self.text = text or (json.dumps(payload) if payload is not None else "")

    def json(self):
        return self._payload


class Sub2APIAgentIdentityTests(unittest.TestCase):
    repo_module_names = [
        "utils.config",
        "utils.proxy_manager",
        "utils.integrations.sub2api_client",
        "utils.integrations.sub2api_proxy",
        "utils.integrations.agent_identity",
    ]

    def setUp(self):
        fake_requests_module = types.SimpleNamespace(
            post=None,
            get=None,
            put=None,
            patch=None,
            delete=None,
            request=None,
            Response=object,
            exceptions=types.SimpleNamespace(ConnectionError=Exception, Timeout=TimeoutError),
        )

        self.original_modules = {}
        for module_name in ["curl_cffi", "requests", "yaml", *self.repo_module_names]:
            if module_name in sys.modules:
                self.original_modules[module_name] = sys.modules[module_name]
            sys.modules.pop(module_name, None)

        sys.modules["curl_cffi"] = types.SimpleNamespace(requests=fake_requests_module)
        sys.modules["requests"] = types.SimpleNamespace(get=None, put=None)
        sys.modules["yaml"] = _yaml_module

        self.cfg = importlib.import_module("utils.config")
        self.client_module = importlib.import_module("utils.integrations.sub2api_client")
        self.identity_module = importlib.import_module("utils.integrations.agent_identity")
        self.Sub2APIClient = self.client_module.Sub2APIClient
        self.get_sub2api_push_settings = self.client_module.get_sub2api_push_settings

        self.cfg_patches = [
            patch.object(self.cfg, "SUB2API_DEFAULT_PROXY", ""),
            patch.object(self.cfg, "SUB2API_ACCOUNT_CONCURRENCY", 10),
            patch.object(self.cfg, "SUB2API_ACCOUNT_LOAD_FACTOR", 10),
            patch.object(self.cfg, "SUB2API_ACCOUNT_PRIORITY", 1),
            patch.object(self.cfg, "SUB2API_ACCOUNT_RATE_MULTIPLIER", 1.0),
            patch.object(self.cfg, "SUB2API_ACCOUNT_GROUP_IDS", [7]),
            patch.object(self.cfg, "SUB2API_ENABLE_WS_MODE", True),
            patch.object(self.cfg, "SUB2API_PUSH_FORMAT", "agent_identity"),
            patch.object(self.cfg, "SUB2API_AGENT_IDENTITY_FALLBACK_OAUTH", False),
            patch.object(self.cfg, "SUB2API_AGENT_IDENTITY_USE_REG_PROXY", True),
            patch.object(self.cfg, "SUB2API_UPDATE_EXISTING", True),
        ]
        for item in self.cfg_patches:
            item.start()

    def tearDown(self):
        for item in reversed(self.cfg_patches):
            item.stop()
        for module_name in ["curl_cffi", "requests", "yaml", *self.repo_module_names]:
            sys.modules.pop(module_name, None)
        sys.modules.update(self.original_modules)

    def test_push_settings_normalize_agent_identity_aliases(self):
        with patch.object(self.cfg, "SUB2API_PUSH_FORMAT", "agent-identity"):
            settings = self.get_sub2api_push_settings()
        self.assertEqual(settings["push_format"], "agent_identity")
        self.assertFalse(settings["agent_identity_fallback_oauth"])
        self.assertTrue(settings["agent_identity_use_reg_proxy"])
        self.assertTrue(settings["update_existing"])
        self.assertEqual(settings["group_ids"], [7])

    def test_add_account_agent_identity_uses_codex_session_endpoint(self):
        captured = []

        def fake_post(url, json=None, headers=None, **kwargs):
            captured.append({"url": url, "json": json, "headers": headers})
            if url.endswith("/api/v1/admin/accounts/import/codex-session"):
                return _FakeResponse(200, {"data": {"created": 1, "updated": 0, "failed": 0, "skipped": 0}})
            if "/api/v1/admin/accounts" in url and "group" in url:
                return _FakeResponse(200, {"data": {}})
            # group bind lookups may call GET-like paths via post in some flows; keep permissive
            return _FakeResponse(200, {"data": []})

        auth_json = {
            "auth_mode": "agentIdentity",
            "tokens": None,
            "agent_identity": {
                "account_id": "acct-1",
                "agent_private_key": "MC4CAQAwBQYDK2VwBCIEAAAA",
                "agent_runtime_id": "agent-1",
                "chatgpt_account_is_fedramp": False,
                "chatgpt_user_id": "user-1",
                "email": "agent@example.com",
                "plan_type": "free",
                "task_id": "task-1",
            },
        }

        with patch.object(self.client_module.cffi_requests, "post", side_effect=fake_post), patch.object(
            self.identity_module,
            "create_agent_identity_auth_json",
            return_value=auth_json,
        ), patch.object(
            self.identity_module,
            "resolve_identity_bootstrap_tokens",
            return_value={"access_token": "at-demo", "id_token": "at-demo"},
        ), patch.object(self.Sub2APIClient, "_force_bind_groups") as bind_mock:
            # ensure import path uses the same module object
            with patch.dict(
                sys.modules,
                {"utils.integrations.agent_identity": self.identity_module},
            ):
                client = self.Sub2APIClient(api_url="https://sub2api.example", api_key="demo-key")
                ok, msg = client.add_account(
                    {
                        "email": "agent@example.com",
                        "access_token": "at-demo",
                        # intentionally no refresh_token
                    }
                )

        self.assertTrue(ok, msg)
        self.assertTrue(any(item["url"].endswith("/import/codex-session") for item in captured), captured)
        payload = next(item["json"] for item in captured if item["url"].endswith("/import/codex-session"))
        content = json.loads(payload["content"])
        self.assertEqual(content["auth_mode"], "agentIdentity")
        self.assertEqual(payload["name"], "agent@example.com")
        self.assertEqual(payload["group_ids"], [7])
        self.assertTrue(payload["update_existing"])
        bind_mock.assert_called_once()

    def test_add_account_agent_identity_reports_missing_endpoint(self):
        def fake_post(url, json=None, headers=None, **kwargs):
            if url.endswith("/import/codex-session"):
                return _FakeResponse(404, {"error": "not found"}, text="not found")
            raise AssertionError(url)

        auth_json = {
            "auth_mode": "agentIdentity",
            "agent_identity": {
                "account_id": "acct-1",
                "agent_private_key": "k",
                "agent_runtime_id": "agent-1",
                "chatgpt_user_id": "user-1",
                "task_id": "task-1",
            },
        }

        with patch.object(self.client_module.cffi_requests, "post", side_effect=fake_post), patch.object(
            self.identity_module,
            "create_agent_identity_auth_json",
            return_value=auth_json,
        ), patch.object(
            self.identity_module,
            "resolve_identity_bootstrap_tokens",
            return_value={"access_token": "at-demo", "id_token": "at-demo"},
        ), patch.dict(sys.modules, {"utils.integrations.agent_identity": self.identity_module}):
            client = self.Sub2APIClient(api_url="https://sub2api.example", api_key="demo-key")
            ok, msg = client.add_account({"email": "agent@example.com", "access_token": "at-demo"})

        self.assertFalse(ok)
        self.assertIn("codex-session", msg)
        self.assertIn("升级", msg)

    def test_oauth_path_still_used_when_push_format_oauth(self):
        with patch.object(self.cfg, "SUB2API_PUSH_FORMAT", "oauth"):
            settings = self.get_sub2api_push_settings()
        self.assertEqual(settings["push_format"], "oauth")

        captured = []

        def fake_post(url, json=None, headers=None, **kwargs):
            captured.append(url)
            if url.endswith("/api/v1/admin/accounts"):
                return _FakeResponse(201, {"data": {}})
            raise AssertionError(url)

        with patch.object(self.cfg, "SUB2API_PUSH_FORMAT", "oauth"), patch.object(
            self.client_module.cffi_requests, "post", side_effect=fake_post
        ), patch.object(self.Sub2APIClient, "_force_bind_groups"):
            client = self.Sub2APIClient(api_url="https://sub2api.example", api_key="demo-key")
            ok, msg = client.add_account(
                {"email": "oauth@example.com", "refresh_token": "rt-1", "access_token": "at-1"}
            )

        self.assertTrue(ok, msg)
        self.assertTrue(any(u.endswith("/api/v1/admin/accounts") for u in captured))
        self.assertFalse(any("codex-session" in u for u in captured))


if __name__ == "__main__":
    unittest.main()
