import time
from fastapi import APIRouter, Depends
from pydantic import BaseModel

from global_state import verify_token
from utils import db_manager
from utils.integrations import team_manager
import utils.config as cfg

router = APIRouter()


# ── 请求模型 ──

class TeamDiscoverReq(BaseModel):
    email: str

class TeamMembersReq(BaseModel):
    email: str
    workspace_id: str

class TeamInviteReq(BaseModel):
    email: str
    workspace_id: str
    target_emails: list[str]

class TeamActionReq(BaseModel):
    email: str
    workspace_id: str
    target_email: str = ""
    user_id: str = ""


# ── 端点 ──

@router.get("/api/team/accounts")
def get_team_accounts(token: str = Depends(verify_token)):
    """列出有 token 的账号，供选择 Team 管理者"""
    try:
        accounts = db_manager.get_accounts_with_token()
        return {"status": "success", "data": accounts}
    except Exception as e:
        return {"status": "error", "message": str(e)}


@router.post("/api/team/discover")
def discover_team_workspaces(req: TeamDiscoverReq, token: str = Depends(verify_token)):
    """发现指定账号的 Team 工作区"""
    try:
        result = team_manager.discover_with_refresh(req.email)
        workspaces = result.get("data", [])
        # 过滤出 team 类型的
        team_ws = [ws for ws in workspaces if "team" in ws.get("plan_type", "")]
        return {"status": "success", "data": team_ws, "all_workspaces": workspaces}
    except Exception as e:
        return {"status": "error", "message": str(e)}


@router.post("/api/team/members")
def get_team_members(req: TeamMembersReq, token: str = Depends(verify_token)):
    """获取工作区成员和待处理邀请"""
    try:
        result = team_manager.members_with_refresh(req.email, req.workspace_id)
        return {"status": "success", "data": result}
    except Exception as e:
        return {"status": "error", "message": str(e)}


@router.post("/api/team/invite")
def invite_team_member(req: TeamInviteReq, token: str = Depends(verify_token)):
    """批量发送 Team 邀请"""
    if not req.target_emails:
        return {"status": "error", "message": "目标邮箱列表为空"}

    results = []
    success_count = 0
    for target in req.target_emails:
        target = target.strip()
        if not target:
            continue
        try:
            # 先记录 pending
            db_manager.save_team_invite_record(req.email, target, req.workspace_id, "pending")
            # 发送邀请
            res = team_manager.invite_with_refresh(req.email, req.workspace_id, target)
            state = res.get("status", "failed")
            msg = res.get("message", "")

            # 更新记录
            if res.get("success"):
                db_manager.save_team_invite_record(req.email, target, req.workspace_id, state)
                success_count += 1
            else:
                db_manager.save_team_invite_record(req.email, target, req.workspace_id, "failed", msg)

            results.append({"email": target, **res})
        except Exception as e:
            db_manager.save_team_invite_record(req.email, target, req.workspace_id, "failed", str(e))
            results.append({"email": target, "success": False, "message": str(e), "status": "failed"})

        # 邀请间隔 1.2s 防限流
        if len(req.target_emails) > 1:
            time.sleep(1.2)

    return {
        "status": "success",
        "message": f"邀请完成: {success_count}/{len(req.target_emails)} 成功",
        "data": results
    }


@router.post("/api/team/revoke")
def revoke_team_invite(req: TeamActionReq, token: str = Depends(verify_token)):
    """撤回邀请"""
    if not req.target_email:
        return {"status": "error", "message": "目标邮箱不能为空"}
    try:
        access_token, token_data, _ = team_manager._get_or_refresh_token(req.email)
        ok = team_manager.revoke_invite(access_token, req.workspace_id, req.target_email)
        if ok:
            db_manager.save_team_invite_record(req.email, req.target_email, req.workspace_id, "revoked")
            return {"status": "success", "message": "邀请已撤回"}
        return {"status": "error", "message": "撤回失败"}
    except Exception as e:
        return {"status": "error", "message": str(e)}


@router.post("/api/team/remove")
def remove_team_member(req: TeamActionReq, token: str = Depends(verify_token)):
    """移除成员"""
    if not req.user_id:
        return {"status": "error", "message": "成员 ID 不能为空"}
    try:
        access_token, token_data, _ = team_manager._get_or_refresh_token(req.email)
        ok = team_manager.remove_member(access_token, req.workspace_id, req.user_id)
        if ok:
            return {"status": "success", "message": "成员已移除"}
        return {"status": "error", "message": "移除失败"}
    except Exception as e:
        return {"status": "error", "message": str(e)}


@router.get("/api/team/invite-records")
def get_team_invite_records(manager_email: str = "", workspace_id: str = "",
                            token: str = Depends(verify_token)):
    """获取邀请记录"""
    try:
        records = db_manager.get_team_invite_records(
            manager_email=manager_email or None,
            workspace_id=workspace_id or None
        )
        return {"status": "success", "data": records}
    except Exception as e:
        return {"status": "error", "message": str(e)}


@router.post("/api/team/invite-records/clear")
def clear_team_invite_records(token: str = Depends(verify_token)):
    """清空邀请记录"""
    try:
        db_manager.clear_team_invite_records()
        return {"status": "success", "message": "邀请记录已清空"}
    except Exception as e:
        return {"status": "error", "message": str(e)}
