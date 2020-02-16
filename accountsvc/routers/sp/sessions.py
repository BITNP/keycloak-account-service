from fastapi import Depends, APIRouter, Query, HTTPException
from starlette.requests import Request
from starlette.responses import Response, RedirectResponse
from accountsvc import datatypes
from typing import Union

from accountsvc.modauthlib import (BITNPSessions, SessionData,
    deps_get_csrf_field, deps_requires_csrf_posttoken, deps_requires_session)


router = APIRouter()

@router.get("/", include_in_schema=True, response_model=datatypes.KeycloakSessionInfo,
    responses={
        200: {"content": {"text/html": {}}}
    })
async def sp_sessions(
        request: Request,
        csrf_field: tuple = Depends(deps_get_csrf_field),
        session_data: SessionData = Depends(deps_requires_session),
        order_by: str = 'default',
    ) -> Union[datatypes.KeycloakSessionInfo, Response]:
    """
    The order of KeycloakSessionItem will be:
    - Current session
    - Order from the latest to the oldest of `lastAccess`

    There should always be at least one session, since current user should own one session to access this data.
    """
    updated = request.query_params.get('updated', False)

    sessions = await sp_sessions_json(request=request, session_data=session_data, order_by=order_by)
    if request.state.response_type.is_json():
        return sessions
    else:
        return request.app.state.templates.TemplateResponse("sp-sessions.html.jinja2", {
            "request": request,
            "sessions": sessions,
            "name": session_data.username,
            "signed_in": True,
            "csrf_field": csrf_field,
            "updated": updated,
        })

async def sp_sessions_json(
        request: Request,
        session_data: SessionData = Depends(deps_requires_session),
        order_by: str = 'default',
        timeout: int = 5,
    ) -> datatypes.KeycloakSessionInfo:
    resp = await request.app.state.app_session.oauth_client.get(
        request.app.state.config.keycloak_accountapi_url+'sessions/devices',
        token=session_data.to_tokens(),
        headers={'Accept': 'application/json'},
        timeout=timeout,
    )
    devices: list = resp.json()
    sessions: list = []

    # extract devices to sessions
    for device in devices:
        for session in device['sessions']:
            for k in ['os', 'osVersion', 'device']:
                session[k] = device.get(k)
            if session['device'] == 'Other':
                session['device'] = None
            sessions.append(session)

    # sort
    ret: list = []
    if order_by == 'default':
        current_index = next(i for i, e in enumerate(sessions) if e.get('current', False))
        ret.append(sessions.pop(current_index))
        ret.extend(
            sorted(sessions, key=lambda session: session['lastAccess'], reverse=True)
        )
    sessions = ret

    return [datatypes.KeycloakSessionItem.parse_obj(r) for r in sessions]

@router.post("/logout", include_in_schema=True, status_code=200, responses={
        303: {"description": "Successful response (for end users)", "content": {"text/html": {}}},
        200: {"content": {"application/json": {}}}
    })
async def sp_sessions_logout(
        request: Request,
        session_data: SessionData = Depends(deps_requires_session),
        id: str = Query(None, regex="^[A-Za-z0-9-_]+$"),
        current: bool = False,
        csrf_valid: bool = Depends(deps_requires_csrf_posttoken)
    ) -> Response:
    result = await sp_sessions_logout_json(request=request, session_data=session_data, id=id, current=current)
    if result is not True:
        raise HTTPException(status_code=500, detail=str(result))
    # success
    if request.state.response_type.is_json():
        return Response(status_code=200)
    else:
        return RedirectResponse(request.url_for('sp_sessions')+"?updated=1", status_code=303)
        # 303 to force POST to convert to GET

async def sp_sessions_logout_json(
        request: Request,
        session_data: SessionData = Depends(deps_requires_session),
        id: str = Query(None, regex="^[A-Za-z0-9-_]+$"),
        current: bool = False
    ) -> Union[bool, str]:
    resp = await request.app.state.app_session.oauth_client.delete(
        request.app.state.config.keycloak_accountapi_url+'sessions/'+(id if id else ''),
        token=session_data.to_tokens(),
        headers={'Accept': 'application/json'},
        params={'current': current}
    )
    result = resp.text
    if resp.status_code == 204:
        # success
        return True
    else:
        return result
