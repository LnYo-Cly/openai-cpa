"""Plus 激活模块 — 公开 API"""

_worker = None


def _get_worker():
    global _worker
    if _worker is None:
        from utils.plus_activation.worker import PlusActivationWorker
        _worker = PlusActivationWorker()
    return _worker


def enqueue(email: str, password: str, token_data: str) -> int:
    from utils.plus_activation.queue_manager import enqueue as _enqueue
    return _enqueue(email, password, token_data)


def start():
    _get_worker().start()


def stop():
    _get_worker().stop()


def is_running() -> bool:
    return _get_worker().is_running()


def get_status() -> dict:
    from utils.plus_activation.queue_manager import get_queue_stats
    from utils.plus_activation.sms_pool import get_pool_status
    return {
        "is_running": _get_worker().is_running(),
        "queue_stats": get_queue_stats(),
        "sms_pool": get_pool_status(),
        "current_account": _get_worker().current_account,
    }
