import time
import json
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


class SysAllocateReq(BaseModel):
    access_token: str
    did: str
    proxy: str = ""
    cookies: str = ""


# ── 端点 ──

@router.get("/api/team/accounts")
def get_team_accounts(token: str = Depends(verify_token)):
    """列出有 token 的账号 + team_accounts 表的账号，供选择 Team 管理者"""
    try:
        accounts = db_manager.get_accounts_with_token()
        # 也从 team_accounts 表读取已导入的 Team 管理员
        team_imported = db_manager.get_all_team_accounts()
        # 用 email 去重，team_accounts 的优先
        seen = set()
        merged = []
        for t in team_imported:
            email = (t.get('email') or '').strip().lower()
            if email and email not in seen:
                merged.append({"email": t.get('email', ''), "plan_type": "team", "source": "team_accounts"})
                seen.add(email)
        for a in accounts:
            email = (a.get('email') or '').strip().lower()
            if email and email not in seen:
                merged.append({"email": a.get('email', ''), "plan_type": a.get('plan_type', ''), "source": "accounts"})
                seen.add(email)
        return {"status": "success", "data": merged}
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


@router.post("/api/team/sys-allocate")
def sys_allocate_team(req: SysAllocateReq, token: str = Depends(verify_token)):
    """用浏览器 cookies 走 PKCE OAuth 获取 refresh_token（不走 sys_node_allocate）"""
    from curl_cffi import requests as cffi_requests
    from utils.auth_pipeline.oauth import generate_oauth_url, submit_callback_url
    from utils.auth_pipeline.http_utils import _follow_redirect_chain_local, _oai_headers
    from utils.auth_pipeline.common import _parse_workspace_from_auth_cookie

    did = req.did.strip()
    proxy = cfg.format_docker_url(req.proxy.strip()) if req.proxy else ""
    if proxy and proxy.startswith("socks5://"):
        proxy = proxy.replace("socks5://", "socks5h://")
    proxies = {"http": proxy, "https": proxy} if proxy else None

    if not did:
        return {"status": "error", "message": "did 不能为空"}
    if not req.cookies.strip():
        return {"status": "error", "message": "cookies 不能为空，需要浏览器端的 auth.openai.com cookies"}

    session = None
    try:
        session = cffi_requests.Session(proxies=proxies, impersonate="chrome110")
        session.headers.update({"Connection": "close"})
        session.timeout = 30

        # 1. 注入浏览器 cookies
        raw_cookies = req.cookies.strip()
        for pair in raw_cookies.split(";"):
            pair = pair.strip()
            if "=" not in pair:
                continue
            name, _, value = pair.partition("=")
            name = name.strip()
            value = value.strip()
            if name and value:
                session.cookies.set(name, value, domain="auth.openai.com")
                session.cookies.set(name, value, domain=".openai.com")
                session.cookies.set(name, value, domain="chatgpt.com")
                session.cookies.set(name, value, domain=".chatgpt.com")

        # 2. 生成 PKCE 参数
        oauth = generate_oauth_url()

        # 3. 用 session 走 OAuth redirect chain
        _, callback_url = _follow_redirect_chain_local(session, oauth.auth_url, proxies)

        # 4. 如果没拿到 code，走 workspace select 兜底
        if "code=" not in callback_url or "state=" not in callback_url:
            auth_cookie = session.cookies.get("oai-client-auth-session") or ""
            workspaces = _parse_workspace_from_auth_cookie(auth_cookie)

            if workspaces:
                target_ws_id = ""
                for ws in workspaces:
                    ws_title = str(ws.get("title", ws.get("name", "Unknown")))
                    if "Personal" in ws_title or "个人" in ws_title or ws.get("is_personal"):
                        target_ws_id = str(ws.get("id", ""))
                        break
                if not target_ws_id and workspaces:
                    target_ws_id = str(workspaces[-1].get("id", ""))

                if target_ws_id:
                    select_resp = session.post(
                        "https://auth.openai.com/api/accounts/workspace/select",
                        headers=_oai_headers(did, {"Content-Type": "application/json"}),
                        json={"workspace_id": target_ws_id},
                        proxies=proxies,
                        timeout=15,
                    )
                    if select_resp.status_code == 200:
                        next_url = str(select_resp.json().get("continue_url") or "").strip()
                        if next_url:
                            _, callback_url = _follow_redirect_chain_local(session, next_url, proxies)

        # 5. 检查是否拿到 code
        if "code=" not in callback_url or "state=" not in callback_url:
            return {"status": "error", "message": f"OAuth redirect chain 未获取到 code，最终 URL: {callback_url[:200]}"}

        # 6. 换 token
        token_json_str = submit_callback_url(
            callback_url=callback_url,
            expected_state=oauth.state,
            code_verifier=oauth.code_verifier,
            proxies=proxies,
        )
        tokens = json.loads(token_json_str)

        return {
            "status": "success",
            "data": {
                "access_token": tokens.get("access_token", ""),
                "refresh_token": tokens.get("refresh_token", ""),
                "id_token": tokens.get("id_token", ""),
                "email": tokens.get("email", ""),
                "account_id": tokens.get("account_id", ""),
            },
        }

    except Exception as e:
        return {"status": "error", "message": f"OAuth 异常: {str(e)}"}
    finally:
        if session:
            try:
                session.close()
            except Exception:
                pass


# ── 批量拉人相关 ──

class TeamBatchInviteReq(BaseModel):
    manager_email: str
    workspace_id: str
    target_emails: list[str]
    seat_type: str = "chatgpt"
    auto_kick: bool = False
    kick_delay: int = 0


class TeamAutoKickReq(BaseModel):
    manager_email: str
    workspace_id: str
    target_emails: list[str]
    delay_seconds: int = 0


@router.get("/api/team/config")
def get_team_invite_config(token: str = Depends(verify_token)):
    """获取当前 TEAM拉人 配置状态"""
    return {
        "status": "success",
        "data": {
            "team_invite_enable": getattr(cfg, 'TEAM_INVITE_ENABLE', False),
            "team_invite_auto_kick": getattr(cfg, 'TEAM_INVITE_AUTO_KICK', False),
            "team_invite_seat_type": getattr(cfg, 'TEAM_INVITE_SEAT_TYPE', "chatgpt"),
            "team_invite_kick_delay": getattr(cfg, 'TEAM_INVITE_KICK_DELAY', 0),
            "team_mode_enable": getattr(cfg, 'TEAM_MODE_ENABLE', False),
            "manager_email": getattr(cfg, 'TEAM_INVITE_MANAGER_EMAIL', ""),
            "workspace_id": getattr(cfg, 'TEAM_INVITE_WORKSPACE_ID', ""),
        },
    }


@router.post("/api/team/batch_invite")
def batch_invite_to_team(req: TeamBatchInviteReq, token: str = Depends(verify_token)):
    """批量邀请账号进入 Team 工作区"""
    if not getattr(cfg, 'TEAM_INVITE_ENABLE', False):
        return {"status": "error", "message": "TEAM拉人 未启用，请先在设置中开启"}

    if getattr(cfg, 'TEAM_MODE_ENABLE', False):
        return {"status": "error", "message": "原版 TEAM 模式已开启，请先关闭后再使用 TEAM拉人"}

    if not req.target_emails:
        return {"status": "error", "message": "目标邮箱列表为空"}

    results = []
    success_count = 0
    fail_count = 0

    for target in req.target_emails:
        target = target.strip()
        if not target:
            continue
        try:
            db_manager.save_team_invite_record(req.manager_email, target, req.workspace_id, "pending")
            res = team_manager.invite_with_refresh(req.manager_email, req.workspace_id, target)
            state = res.get("status", "failed")

            if res.get("success"):
                db_manager.save_team_invite_record(req.manager_email, target, req.workspace_id, state)
                success_count += 1
            else:
                db_manager.save_team_invite_record(req.manager_email, target, req.workspace_id, "failed", res.get("message", ""))
                fail_count += 1

            results.append({"email": target, **res})
        except Exception as e:
            db_manager.save_team_invite_record(req.manager_email, target, req.workspace_id, "failed", str(e))
            fail_count += 1
            results.append({"email": target, "success": False, "message": str(e), "status": "failed"})

        # 邀请间隔 1.2s 防限流
        if len(req.target_emails) > 1:
            time.sleep(1.2)

    # 自动踢人
    kicked_count = 0
    if req.auto_kick and success_count > 0:
        if req.kick_delay > 0:
            time.sleep(req.kick_delay)
        kicked_count = _auto_kick_members(req.manager_email, req.workspace_id, req.target_emails)

    return {
        "status": "success",
        "message": f"邀请完成: {success_count}/{len(req.target_emails)} 成功" + (f"，已踢出 {kicked_count} 人" if req.auto_kick else ""),
        "data": {
            "success_count": success_count,
            "fail_count": fail_count,
            "total": len(req.target_emails),
            "results": results,
            "kicked_count": kicked_count,
        },
    }


def _auto_kick_members(manager_email: str, workspace_id: str, target_emails: list[str]) -> int:
    """批量移除工作区成员，返回踢出人数"""
    kicked = 0
    try:
        members_data = team_manager.members_with_refresh(manager_email, workspace_id)
        members = members_data.get("members", [])
        target_set = {e.strip().lower() for e in target_emails if e.strip()}

        for member in members:
            member_email = (member.get("email") or "").lower()
            user_id = member.get("user_id", "")
            if member_email in target_set and user_id:
                try:
                    access_token, token_data, _ = team_manager._get_or_refresh_token(manager_email)
                    ok = team_manager.remove_member(access_token, workspace_id, user_id)
                    if ok:
                        kicked += 1
                        print(f"[team_invite] 🦶 已踢出成员: {member_email}")
                except Exception as e:
                    print(f"[team_invite] 踢出 {member_email} 失败: {e}")
    except Exception as e:
        print(f"[team_invite] 自动踢人异常: {e}")
    return kicked


@router.post("/api/team/auto_kick")
def auto_kick_members(req: TeamAutoKickReq, token: str = Depends(verify_token)):
    """手动触发批量踢人"""
    kicked = _auto_kick_members(req.manager_email, req.workspace_id, req.target_emails)
    return {"status": "success", "message": f"已踢出 {kicked} 个成员", "kicked_count": kicked}
