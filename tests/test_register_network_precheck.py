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
