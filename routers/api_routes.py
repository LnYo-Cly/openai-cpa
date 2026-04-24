from fastapi import APIRouter
from . import system_routes
from . import account_routes
from . import service_routes
from . import sms_routes

router = APIRouter()

router.include_router(system_routes.router)
router.include_router(account_routes.router)
router.include_router(service_routes.router)
router.include_router(sms_routes.router)
