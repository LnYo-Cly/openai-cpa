import sys
import types
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

# register imports browser modules that are unavailable in the minimal test image.
sys.modules.setdefault("camoufox", types.SimpleNamespace(Camoufox=object))

from utils.grok_auth import register


class _OAuth:
    token = {"access_token": "build-access", "refresh_token": "build-refresh"}
    userinfo = {"email": "test@example.com"}


def _run(monkeypatch, events, *, enabled=True, web_ok=True, account_state=None):
    monkeypatch.setattr(register.cfg, "GROK2API_IMPORT_SSO_AS_GROK_WEB", enabled, raising=False)
    monkeypatch.setattr(register, "ensure_camoufox", lambda force=False: (True, ""))
    monkeypatch.setattr(register, "get_email_and_token", lambda *a, **k: ("test@example.com", "mail-token"))
    monkeypatch.setattr(register, "set_last_email", lambda email: None)
    monkeypatch.setattr(register, "signup_with_camoufox", lambda *a, **k: {
        "ok": True,
        "sso": "sso-secret",
        "cookies": {"sso": "sso-secret"},
    })
    account_state = account_state or {
        "found": True,
        "bot_flag_source": 0,
        "risk": 0.01,
        "denied": False,
        "error": "",
    }
    monkeypatch.setattr(register, "inspect_sso_account_state", lambda *a, **k: account_state)

    def complete(*args, **kwargs):
        events.append("build_oauth")
        return _OAuth()

    monkeypatch.setattr(register, "complete_build_oauth", complete)
    monkeypatch.setattr(register, "build_cliproxyapi_auth_record", lambda *a, **k: {"email": "test@example.com"})

    core_engine = types.SimpleNamespace(grok2api_admin_login=lambda: (True, "admin-token", "ok"))
    monkeypatch.setitem(sys.modules, "utils.core_engine", core_engine)

    def import_web(sso, token):
        events.append("grok_web")
        assert sso == "sso-secret"
        assert token == "admin-token"
        return web_ok, "web result"

    core_engine._grok2api_import_web_sso = import_web
    ctx = {}
    result = register.run(run_ctx=ctx)
    return result, ctx


def test_enabled_imports_grok_web_before_build_oauth(monkeypatch):
    events = []
    result, ctx = _run(monkeypatch, events, enabled=True, web_ok=True)
    assert result[0]
    assert events == ["grok_web", "build_oauth"]
    assert ctx["grok_web_import_ok"] is True


def test_grok_web_failure_does_not_block_build_oauth(monkeypatch):
    events = []
    result, ctx = _run(monkeypatch, events, enabled=True, web_ok=False)
    assert result[0]
    assert events == ["grok_web", "build_oauth"]
    assert ctx["grok_web_import_ok"] is False


def test_disabled_skips_grok_web_and_keeps_build_oauth(monkeypatch):
    events = []
    result, ctx = _run(monkeypatch, events, enabled=False)
    assert result[0]
    assert events == ["build_oauth"]
    assert "grok_web_import_ok" not in ctx


def test_grok_account_state_parser_reads_risk_and_denial():
    result = register._parse_grok_account_state(
        r'{\"botFlagSource\":2,\"botFlagDetails\":\"policy=deny,event=$registration,risk=0.87\"}'
    )
    assert result["found"] is True
    assert result["bot_flag_source"] == 2
    assert result["risk"] == 0.87
    assert result["denied"] is True


def test_downgraded_account_is_discarded_before_oauth(monkeypatch):
    events = []
    monkeypatch.setattr(register.cfg, "DISCARD_ON_DOWNGRADE", True, raising=False)
    result, _ = _run(monkeypatch, events, enabled=False, account_state={
        "found": True,
        "bot_flag_source": 2,
        "risk": 0.7,
        "denied": False,
        "error": "",
    })
    assert result == (None, None)
    assert events == []


def test_detection_failure_does_not_block_oauth(monkeypatch):
    events = []
    result, _ = _run(monkeypatch, events, enabled=False, account_state={
        "found": False,
        "bot_flag_source": None,
        "risk": None,
        "denied": False,
        "error": "被 CF 拦截",
    })
    assert result[0]
    assert events == ["build_oauth"]


def test_downgraded_account_continues_when_discard_is_disabled(monkeypatch):
    events = []
    monkeypatch.setattr(register.cfg, "DISCARD_ON_DOWNGRADE", False, raising=False)
    result, _ = _run(monkeypatch, events, enabled=False, account_state={
        "found": True,
        "bot_flag_source": 2,
        "risk": 0.7,
        "denied": False,
        "error": "",
    })
    assert result[0]
    assert events == ["build_oauth"]
