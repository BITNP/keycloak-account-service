from fastapi import Depends, APIRouter
from starlette.requests import Request
import datatypes

from modauthlib import BITNPSessionFastAPIApp
from .profile import sp_profile_json
from .sessions import sp_sessions_json

router = APIRouter()

@router.get("/", include_in_schema=False)
async def sp_landing(request: Request,
        session_data: datatypes.SessionData = Depends(BITNPSessionFastAPIApp.deps_requires_session)
    ):
    tdata = {
        "request": request,
        "name": session_data.username,
        "is_admin": "admin" in session_data.client_roles,
        "signed_in": True,
        "keycloak_admin_url": request.app.state.config.keycloak_admin_url,
        "permission": await sp_permission(request=request, session_data=session_data),
        "profile": await sp_profile_json(request=request, session_data=session_data, load_session_only=True),
    }

    # Remote
    try:
        tdata["sessions"] = (await sp_sessions_json(request=request, session_data=session_data))
        tdata['sessions_count'] = len(tdata['sessions'])
    except Exception as e:
        tdata["sessions"] = None
        tdata['sessions_count'] = 0

    if tdata['sessions_count'] > 1:
        latest_session: datatypes.KeycloakSessionItem = tdata['sessions'][1]
        device: str = latest_session.os + ' ' + latest_session.browser
        if latest_session.device:
            device = latest_session.device + ' ' + latest_session.browser
        tdata['sessions_desc'] = '你在其它位置的最后一次登录是 {time} ({browser})。'.format(
            time=local_timestring(latest_session.lastAccess),
            browser=device)
    elif tdata['sessions_count'] > 0:
        tdata['sessions_desc'] = '你目前没有在其它位置登录。'
    else:
        tdata['sessions_desc'] = '查看你在其它设备的登录情况并远程下线。'
    return request.app.state.templates.TemplateResponse("sp.html.jinja2", tdata)

@router.get("/permission", include_in_schema=True, response_model=datatypes.PermissionInfo)
async def sp_permission(
    request: Request,
    session_data: datatypes.SessionData = Depends(BITNPSessionFastAPIApp.deps_requires_session)
    ) -> datatypes.PermissionInfo:
    pub_memberof = session_data.memberof.copy()
    for item in pub_memberof:
        item.internal_note = None
    permission_dict = session_data.dict()
    permission_dict['active_groups'], permission_dict['memberof'] \
        = request.app.state.config.group_config.filter_active_groups(pub_memberof)
    permission_dict['has_active_role'] = request.app.state.config.role_active_name in session_data.realm_roles
    return datatypes.PermissionInfo(**permission_dict)

@router.get("/applications", include_in_schema=True)
async def sp_applications(
        session_data: datatypes.SessionData = Depends(BITNPSessionFastAPIApp.deps_requires_session)
    ):
    return {}