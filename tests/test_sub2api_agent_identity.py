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




    def test_import_created_zero_is_failure(self):
        captured = []

        def fake_post(url, json=None, headers=None, **kwargs):
            captured.append({"url": url, "json": json})
            if url.endswith("/import/codex-session"):
                return _FakeResponse(
                    200,
                    {"data": {"created": 0, "updated": 0, "failed": 0, "skipped": 0, "total": 1, "errors": [{"message": "invalid agent identity"}]}},
                )
            return _FakeResponse(200, {"data": {}})

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
        self.assertTrue(any("created=0" in msg or "未新增" in msg or "invalid" in msg.lower() for _ in [0]) or ("created=0" in msg or "invalid" in msg.lower() or "未新增" in msg), msg)
        payload = next(item["json"] for item in captured if item["url"].endswith("/import/codex-session"))
        self.assertIn("content", payload)
        self.assertEqual(payload.get("name"), "agent@example.com")
        content = json.loads(payload["content"])
        self.assertEqual(content["auth_mode"], "agentIdentity")
        # Admin UI shape: notes/proxy_id/update_existing/extra present
        self.assertIn("update_existing", payload)
        self.assertIn("extra", payload)

    def test_import_payload_matches_admin_ui_shape(self):
        captured = []

        def fake_post(url, json=None, headers=None, **kwargs):
            captured.append({"url": url, "json": json})
            if url.endswith("/import/codex-session"):
                return _FakeResponse(200, {"data": {"created": 1, "updated": 0, "failed": 0, "skipped": 0, "total": 1}})
            if "/api/v1/admin/accounts" in url:
                return _FakeResponse(200, {"data": {}})
            return _FakeResponse(200, {"data": []})

        auth_json = {
            "auth_mode": "agentIdentity",
            "OPENAI_API_KEY": None,
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
            "bedrock_api_key": None,
            "last_refresh": None,
            "personal_access_token": None,
        }

        with patch.object(self.cfg, "SUB2API_ENABLE_WS_MODE", False), patch.object(
            self.client_module.cffi_requests, "post", side_effect=fake_post
        ), patch.object(
            self.identity_module, "create_agent_identity_auth_json", return_value=auth_json
        ), patch.object(
            self.identity_module,
            "resolve_identity_bootstrap_tokens",
            return_value={"access_token": "at", "id_token": "at"},
        ), patch.object(self.Sub2APIClient, "_force_bind_groups"), patch.dict(
            sys.modules, {"utils.integrations.agent_identity": self.identity_module}
        ):
            client = self.Sub2APIClient(api_url="https://sub2api.example", api_key="demo-key")
            ok, msg = client.add_account({"email": "agent@example.com", "access_token": "at"})
        self.assertTrue(ok, msg)
        payload = next(item["json"] for item in captured if item["url"].endswith("/import/codex-session"))
        for key in ("content", "name", "group_ids", "update_existing", "extra", "concurrency", "priority"):
            self.assertIn(key, payload)
        self.assertEqual(payload["extra"].get("openai_oauth_responses_websockets_v2_mode"), "off")
        self.assertFalse(payload["extra"].get("openai_oauth_responses_websockets_v2_enabled"))


class AgentIdentityRegSkipTests(unittest.TestCase):
    """Registration path must skip OAuth when push_format=agent_identity."""

    def setUp(self):
        # agent_identity only needs PyNaCl for crypto helpers; pure helpers need none.
        for name in ["utils.integrations.agent_identity"]:
            sys.modules.pop(name, None)
        self.mod = importlib.import_module("utils.integrations.agent_identity")

    def test_should_use_agent_identity_reg_path(self):
        self.assertTrue(self.mod.should_use_agent_identity_reg_path(True, "agent_identity"))
        self.assertTrue(self.mod.should_use_agent_identity_reg_path(True, "agent_identity "))
        self.assertFalse(self.mod.should_use_agent_identity_reg_path(False, "agent_identity"))
        self.assertFalse(self.mod.should_use_agent_identity_reg_path(True, "oauth"))
        self.assertFalse(self.mod.should_use_agent_identity_reg_path(True, "OAuth"))

    def test_build_agent_identity_session_payload_shape(self):
        raw = self.mod.build_agent_identity_session_payload(
            "sess-jwt-token",
            "user@example.com",
            device_id="did-1",
            user_agent="ua-1",
        )
        data = json.loads(raw)
        self.assertEqual(data["access_token"], "sess-jwt-token")
        self.assertEqual(data["id_token"], "sess-jwt-token")
        self.assertEqual(data["email"], "user@example.com")
        self.assertEqual(data["type"], "codex")
        self.assertEqual(data["auth_source"], "agent_identity_session")
        self.assertEqual(data["device_id"], "did-1")
        self.assertEqual(data["user_agent"], "ua-1")
        # Must not look like half-finished statuses that skip Sub2API push.
        self.assertNotIn(data.get("status"), ["image2api", "仅注册成功"])
        self.assertNotIn("refresh_token", data)

    def test_resolve_bootstrap_accepts_session_payload(self):
        import base64

        def _b64url(obj):
            raw = json.dumps(obj, separators=(",", ":")).encode("utf-8")
            return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")

        good = f"{_b64url({'alg': 'none'})}.{_b64url({'https://api.openai.com/auth': {'chatgpt_account_id': 'acct-1', 'chatgpt_user_id': 'user-1'}})}.sig"
        raw = self.mod.build_agent_identity_session_payload(good, "a@b.com")
        tokens = self.mod.resolve_identity_bootstrap_tokens(json.loads(raw))
        self.assertEqual(tokens["access_token"], good)
        self.assertEqual(tokens["id_token"], good)

    def test_resolve_bootstrap_rejects_jwt_without_claims(self):
        import base64

        def _b64url(obj):
            raw = json.dumps(obj, separators=(",", ":")).encode("utf-8")
            return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")

        junk = f"{_b64url({'alg': 'none'})}.{_b64url({'sub': 'x'})}.sig"
        with self.assertRaises(self.mod.AgentIdentityError):
            self.mod.resolve_identity_bootstrap_tokens({"access_token": junk, "email": "a@b.com"})


if __name__ == "__main__":
    unittest.main()
