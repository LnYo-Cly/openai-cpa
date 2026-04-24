from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from global_state import verify_token
from utils import core_engine

router = APIRouter()

class SMSPriceReq(BaseModel):
    service: str = "openai"

@router.get('/api/sms/balance')
def api_get_sms_balance(token: str = Depends(verify_token)):
    from utils.integrations.hero_sms import hero_sms_get_balance
    proxy_url = core_engine.cfg.DEFAULT_PROXY
    balance, err = hero_sms_get_balance(proxies={"http": proxy_url, "https": proxy_url} if proxy_url else None)
    return {"status": "success", "balance": f"{balance:.2f}"} if balance >= 0 else {"status": "error", "message": err}

@router.post('/api/sms/prices')
def api_get_sms_prices(req: SMSPriceReq, token: str = Depends(verify_token)):
    from utils.integrations.hero_sms import _hero_sms_prices_by_service
    proxy_url = core_engine.cfg.DEFAULT_PROXY
    rows = _hero_sms_prices_by_service(req.service,
                                       proxies={"http": proxy_url, "https": proxy_url} if proxy_url else None)
    return {"status": "success", "prices": rows} if rows else {"status": "error", "message": "无法获取价格或当前服务无库存"}

@router.get('/api/smsbower/balance')
def api_get_smsbower_balance(api_key: str = Query(None), token: str = Depends(verify_token)):
    from utils.integrations.smsbower_sms import smsbower_get_balance
    proxy_url = getattr(core_engine.cfg, 'DEFAULT_PROXY', None)
    balance, err = smsbower_get_balance(proxies={"http": proxy_url, "https": proxy_url} if proxy_url else None)
    return {"status": "success", "balance": f"{balance:.2f}"} if balance >= 0 else {"status": "error", "message": err}

@router.post('/api/smsbower/prices')
def api_get_smsbower_prices(req: SMSPriceReq, token: str = Depends(verify_token)):
    from utils.integrations.smsbower_sms import _smsbower_prices_by_service
    proxy_url = getattr(core_engine.cfg, 'DEFAULT_PROXY', None)
    rows = _smsbower_prices_by_service(req.service, proxies={"http": proxy_url, "https": proxy_url} if proxy_url else None, force_refresh=False)
    return {"status": "success", "prices": rows} if rows else {"status": "error", "message": "无法获取价格或当前服务无库存"}