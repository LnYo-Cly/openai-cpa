"""Plus 激活控制接口"""

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from typing import List, Optional

from global_state import verify_token
from utils.plus_activation import (
    start as plus_start,
    stop as plus_stop,
    is_running as plus_is_running,
    get_status as plus_get_status,
)
from utils.plus_activation import queue_manager, sms_pool

router = APIRouter(prefix="/api/plus", tags=["plus"])


@router.post("/start", dependencies=[Depends(verify_token)])
def api_plus_start():
    plus_start()
    return {"ok": True, "message": "Plus 激活 Worker 已启动"}


@router.post("/stop", dependencies=[Depends(verify_token)])
def api_plus_stop():
    plus_stop()
    return {"ok": True, "message": "Plus 激活 Worker 已停止"}


@router.get("/status", dependencies=[Depends(verify_token)])
def api_plus_status():
    return plus_get_status()


@router.get("/queue", dependencies=[Depends(verify_token)])
def api_plus_queue(status: str = None, limit: int = 50, offset: int = 0):
    items = queue_manager.get_queue_items(status=status, limit=limit, offset=offset)
    stats = queue_manager.get_queue_stats()
    return {"ok": True, "items": items, "stats": stats}


@router.post("/queue/retry", dependencies=[Depends(verify_token)])
def api_plus_queue_retry():
    queue_manager.reset_failed()
    return {"ok": True, "message": "已重置所有失败任务为待处理"}


@router.post("/queue/clear", dependencies=[Depends(verify_token)])
def api_plus_queue_clear(days: int = 7):
    queue_manager.cleanup_done(days=days)
    return {"ok": True, "message": f"已清理 {days} 天前的已完成任务"}


@router.get("/sms_pool", dependencies=[Depends(verify_token)])
def api_plus_sms_pool():
    return sms_pool.get_pool_status()


@router.post("/sms_pool/reload", dependencies=[Depends(verify_token)])
def api_plus_sms_pool_reload():
    sms_pool.reload_pool()
    return {"ok": True, "message": "SMS 池已重新加载"}


class SmsImportRequest(BaseModel):
    text: str


class SmsDeleteRequest(BaseModel):
    indices: List[int]


@router.post("/sms_pool/import", dependencies=[Depends(verify_token)])
def api_plus_sms_pool_import(req: SmsImportRequest):
    count = sms_pool.import_entries(req.text)
    return {"ok": True, "message": f"已导入 {count} 条接码池条目", "count": count}


@router.post("/sms_pool/delete", dependencies=[Depends(verify_token)])
def api_plus_sms_pool_delete(req: SmsDeleteRequest):
    count = sms_pool.delete_entries(req.indices)
    return {"ok": True, "message": f"已删除 {count} 条", "count": count}


@router.post("/sms_pool/clear", dependencies=[Depends(verify_token)])
def api_plus_sms_pool_clear():
    count = sms_pool.clear_all()
    return {"ok": True, "message": f"已清空 {count} 条接码池条目", "count": count}
