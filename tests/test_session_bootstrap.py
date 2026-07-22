# -*- coding: utf-8 -*-
import base64
import json
import sys
import types
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def _b64url(obj: dict) -> str:
    raw = json.dumps(obj, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def make_jwt(payload: dict) -> str:
    return f"{_b64url({'alg': 'none'})}.{_b64url(payload)}.sig"


class SessionBootstrapTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Avoid importing heavy/native modules transitively.
        sys.modules.setdefault("curl_cffi", types.ModuleType("curl_cffi"))
        req = types.ModuleType("curl_cffi.requests")
        req.Session = object
        sys.modules.setdefault("curl_cffi.requests", req)
        cfg = types.ModuleType("utils.config")
        cfg.ts = lambda: "ts"
        sys.modules.setdefault("utils.config", cfg)
        for name in [
            "utils.auth_pipeline.session_bootstrap",
            "utils.auth_pipeline.common",
            "utils.auth_pipeline.http_utils",
        ]:
            sys.modules.pop(name, None)
        import importlib

        cls.mod = importlib.import_module("utils.auth_pipeline.session_bootstrap")

    def test_jwt_has_openai_auth_claims(self):
        good = make_jwt(
            {
                "https://api.openai.com/auth": {
                    "chatgpt_account_id": "acct-1",
                    "chatgpt_user_id": "user-1",
                    "chatgpt_plan_type": "free",
                }
            }
        )
        bad = make_jwt({"sub": "x"})
        self.assertTrue(self.mod.jwt_has_openai_auth_claims(good))
        self.assertFalse(self.mod.jwt_has_openai_auth_claims(bad))
        self.assertEqual(self.mod.pick_session_access_token(bad, good), good)

    def test_scan_session_jwt_from_cookies(self):
        good = make_jwt(
            {
                "https://api.openai.com/auth": {
                    "chatgpt_account_id": "acct-1",
                    "chatgpt_user_id": "user-1",
                }
            }
        )
        session = MagicMock()
        session.cookies.jar = [
            types.SimpleNamespace(name="noise", value="abc"),
            types.SimpleNamespace(name="__Secure-next-auth.session-token", value=good),
        ]
        self.assertEqual(self.mod.scan_session_jwt_from_cookies(session), good)

    def test_extract_uses_continue_then_session_endpoint(self):
        good = make_jwt(
            {
                "https://api.openai.com/auth": {
                    "chatgpt_account_id": "acct-9",
                    "chatgpt_user_id": "user-9",
                    "chatgpt_plan_type": "plus",
                }
            }
        )
        session = MagicMock()
        session.cookies.jar = []
        session.cookies.get_dict.return_value = {}

        with patch.object(self.mod, "follow_reg_continue_url", return_value="https://chatgpt.com/") as follow, patch.object(
            self.mod, "scan_session_jwt_from_cookies", side_effect=["", good]
        ), patch.object(
            self.mod,
            "fetch_chatgpt_session_json",
            return_value={"accessToken": good},
        ), patch.object(
            self.mod,
            "bridge_chatgpt_nextauth_session",
            side_effect=AssertionError("bridge should not run when session JSON works"),
        ):
            token = self.mod.extract_reg_session_access_token(
                session,
                continue_url="/continue",
                proxies=None,
                device_id="did",
                user_agent="ua",
                email="a@b.com",
            )
        self.assertEqual(token, good)
        follow.assert_called_once()

    def test_extract_falls_back_to_nextauth_bridge(self):
        good = make_jwt(
            {
                "https://api.openai.com/auth": {
                    "chatgpt_account_id": "acct-2",
                    "chatgpt_user_id": "user-2",
                }
            }
        )
        session = MagicMock()
        with patch.object(self.mod, "follow_reg_continue_url", return_value=""), patch.object(
            self.mod, "scan_session_jwt_from_cookies", return_value=""
        ), patch.object(self.mod, "fetch_chatgpt_session_json", return_value={}), patch.object(
            self.mod, "bridge_chatgpt_nextauth_session", return_value=good
        ) as bridge:
            token = self.mod.extract_reg_session_access_token(
                session,
                continue_url="https://auth.openai.com/continue",
                email="x@y.com",
            )
        self.assertEqual(token, good)
        bridge.assert_called_once()

    def test_bridge_reads_access_token_from_session_json(self):
        good = make_jwt(
            {
                "https://api.openai.com/auth": {
                    "chatgpt_account_id": "acct-3",
                    "chatgpt_user_id": "user-3",
                }
            }
        )
        session = MagicMock()

        class _Resp:
            def __init__(self, payload, headers=None):
                self._payload = payload
                self.headers = headers or {}

            def json(self):
                return self._payload

        def fake_get(url, **kwargs):
            if url.endswith("/api/auth/csrf"):
                return _Resp({"csrfToken": "csrf-1"})
            if url.endswith("/api/auth/session"):
                return _Resp({"accessToken": good})
            return _Resp({})

        def fake_post(url, **kwargs):
            self.assertIn("/api/auth/signin/openai", url)
            return _Resp({"url": "https://auth.openai.com/api/accounts/authorize?x=1"})

        session.get.side_effect = fake_get
        session.post.side_effect = fake_post

        with patch.object(self.mod, "_follow_redirect_chain_local", return_value=(None, "https://chatgpt.com/")):
            token = self.mod.bridge_chatgpt_nextauth_session(
                session,
                device_id="did-1",
                user_agent="ua",
                login_hint="a@b.com",
            )
        self.assertEqual(token, good)


    def test_pick_rejects_jwt_without_claims(self):
        junk = make_jwt({"sub": "no-auth-claims"})
        self.assertEqual(self.mod.pick_session_access_token(junk), "")
        self.assertEqual(self.mod.pick_session_access_token(junk, require_claims=False), junk)

    def test_extract_never_returns_non_claim_cookie_jwt(self):
        junk = make_jwt({"sub": "cookie-only"})
        session = MagicMock()
        session.cookies.jar = [
            types.SimpleNamespace(name="oai-client-auth-session", value=junk),
        ]
        with patch.object(self.mod, "follow_reg_continue_url", return_value=""), patch.object(
            self.mod, "fetch_chatgpt_session_json", return_value={}
        ), patch.object(self.mod, "bridge_chatgpt_nextauth_session", return_value=""):
            token = self.mod.extract_reg_session_access_token(session, continue_url="", email="a@b.com")
        self.assertEqual(token, "")


class AgentIdentityNoImage2ApiSemantics(unittest.TestCase):
    def test_should_use_path_independent_of_image2api(self):
        for name in ["utils.integrations.agent_identity"]:
            sys.modules.pop(name, None)
        import importlib

        mod = importlib.import_module("utils.integrations.agent_identity")
        self.assertTrue(mod.should_use_agent_identity_reg_path(True, "agent_identity"))
        self.assertFalse(mod.should_use_agent_identity_reg_path(True, "oauth"))


if __name__ == "__main__":
    unittest.main()
