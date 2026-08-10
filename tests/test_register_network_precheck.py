import importlib
import sys
import types

from utils.auth_pipeline.http_utils import _preflight_proxy


class _Response:
    text = "loc=US\n"


class _Session:
    def __init__(self):
        self.calls = 0

    def get(self, *_args, **_kwargs):
        self.calls += 1
        if self.calls == 1:
            raise RuntimeError("SSL_ERROR_SYSCALL")
        return _Response()


def test_preflight_retries_one_transient_tls_disconnect(monkeypatch):
    monkeypatch.setattr("utils.auth_pipeline.http_utils.time.sleep", lambda _: None)
    session = _Session()

    ok, loc, elapsed, error = _preflight_proxy(session, {"https": "http://proxy"})

    assert ok is True
    assert loc == "US"
    assert elapsed >= 0
    assert error == ""
    assert session.calls == 2


def test_register_continues_after_transient_preflight_failure(monkeypatch):
    auth_core = types.ModuleType("utils.auth_core")
    for name in (
        "generate_payload",
        "init_auth",
        "image2api_data",
        "sys_node_allocate",
        "sys_node_release",
        "code_pool",
        "sys_team_domain_verify",
    ):
        setattr(auth_core, name, lambda *args, **kwargs: None)
    monkeypatch.setitem(sys.modules, "utils.auth_core", auth_core)

    register = importlib.import_module("utils.auth_pipeline.register")

    class _Session:
        def __init__(self, *_args, **_kwargs):
            self.headers = {}

        def close(self):
            pass

    email_calls = []
    monkeypatch.setattr(register.requests, "Session", _Session)
    monkeypatch.setattr(register, "_skip_net_check", lambda: False)
    monkeypatch.setattr(
        register,
        "_preflight_proxy",
        lambda *_args, **_kwargs: (False, None, 0.0, "SSL_ERROR_SYSCALL"),
    )
    monkeypatch.setattr(
        register,
        "get_email_and_token",
        lambda *_args, **_kwargs: (email_calls.append(True) or (None, None)),
    )
    monkeypatch.setattr(register.cfg, "format_docker_url", lambda proxy: proxy)
    monkeypatch.setattr(register.cfg, "TEAM_MODE_OVERSPEED", False)

    assert register.run("http://proxy") == (None, None)
    assert email_calls == [True]
