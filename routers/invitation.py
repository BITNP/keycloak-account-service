from fastapi import Depends, APIRouter, HTTPException
from starlette.requests import Request
from starlette.responses import RedirectResponse

import datatypes
import invitation
from modauthlib import BITNPSessionFastAPIApp
from utils import TemplateService

router = APIRouter()

async def validate_token(request: Request, token: str) -> datatypes.GroupItem:
    path, nonce = invitation.parse_invitation_token(token=token, config=request.app.state.config)
    if not path:
        raise HTTPException(404)
    # we assume this is legimitate data because it's signed with our secret

    async with request.app.state.app_session.get_service_account_oauth_client() as client:
        resp = await client.get(request.app.state.config.keycloak_adminapi_url+'group-by-path/'+path,
            headers={'Accept': 'application/json'})
        if resp.status_code == 200:
            current_group : datatypes.GroupItem = datatypes.GroupItem.parse_obj(resp.json())
        else:
            print(resp.text)
            raise HTTPException(500)

    if invitation.get_invitation_token(group=current_group, config=request.app.state.config) != token:
        # nonce or expiry does not match
        print((path, nonce, ))
        raise HTTPException(404, detail="This link has expired.")

    # parse group
    parsed_group = request.app.state.config.group_config.get(path)
    if parsed_group:
        current_group.name = parsed_group.name

    return current_group

@router.get("/i/{token}", include_in_schema=False)
async def invitation_landing(
        request: Request, token: str,
        session_data: datatypes.SessionData = Depends(BITNPSessionFastAPIApp.deps_session_data),
        csrf_field: tuple = Depends(BITNPSessionFastAPIApp.deps_get_csrf_field),
    ):
    current_group = await validate_token(request, token)

    in_group = False
    if session_data:
        for g in session_data.memberof:
            if g.path == current_group.path:
                in_group = True

    return request.app.state.templates.TemplateResponse("invitation-landing.html.jinja2", {
                "request": request,
                "group": current_group,
                "in_group": in_group,
                "session_data": session_data,
                "csrf_field": csrf_field,
                "token": token,
            })
    return current_group.name

@router.post("/i/{token}", include_in_schema=False)
async def invitation_join(
        request: Request, token: str,
        session_data: datatypes.SessionData = Depends(BITNPSessionFastAPIApp.deps_requires_session),
        # deps_requires_session will redirect users as needed (and later convert POST to GET to show the confirmation page)
        csrf_valid: bool = Depends(BITNPSessionFastAPIApp.deps_requires_csrf_posttoken),
    ):
    current_group = await validate_token(request, token)

    for g in session_data.memberof:
        if g.path == current_group.path:
            # in_group
            raise HTTPException(status_code=403)

