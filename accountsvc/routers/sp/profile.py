from typing import Union, Optional
from pydantic import ValidationError

from fastapi import Depends, APIRouter, Form
from fastapi.exceptions import RequestValidationError
from starlette.requests import Request
from starlette.responses import Response, RedirectResponse

from accountsvc.datatypes import ProfileInfo, ProfileUpdateInfo
from accountsvc.modauthlib import (SessionData, deps_requires_session,
                                   deps_get_csrf_field, deps_requires_csrf_posttoken)
from accountsvc.utils import request_accountapi_json_expect_200

router = APIRouter()

@router.get("/", include_in_schema=True, response_model=ProfileInfo,
            responses={
                200: {"content": {"text/html": {}}}
            })
async def sp_profile(
        request: Request,
        csrf_field: tuple = Depends(deps_get_csrf_field),
        session_data: SessionData = Depends(deps_requires_session),
    ) -> Union[ProfileInfo, Response]:
    # prefer_onename is used if user has firstName+lastName and they initiated oneName setup process
    prefer_onename = request.query_params.get('prefer_onename', False)
    updated = request.query_params.get('updated', False)
    profile = await sp_profile_json(request=request, session_data=session_data)
    if request.state.response_type.is_json():
        return profile
    else:
        return request.app.state.templates.TemplateResponse("sp-profile.html.jinja2", {
            "request": request,
            "profile": profile,
            "name": session_data.username,
            "signed_in": True,
            "csrf_field": csrf_field,
            "prefer_onename": prefer_onename,
            "updated": updated,
            "assistance_url": request.app.state.config.assistance_url,
        })

async def sp_profile_json(
        request: Request,
        session_data: SessionData = Depends(deps_requires_session),
        load_session_only: bool = False
    ) -> ProfileInfo:
    if not load_session_only:
        resp = await request.app.state.app_session.oauth_client.get(
            request.app.state.config.keycloak_accountapi_url,
            token=session_data.to_tokens(),
            headers={'Accept': 'application/json'}
        )
        profile = resp.json()
        profile['name'] = session_data.name
        profile['id'] = session_data.id
    else:
        profile = session_data.dict()
    return ProfileInfo.parse_obj(profile)

@router.post("/", include_in_schema=True, status_code=200, response_model=ProfileUpdateInfo, responses={
        303: {"description": "Successful response (for end users)", "content": {"text/html": {}}},
        200: {"content": {"application/json": {}}},
        409: {"description": "Failed response (Conflict)"},
    })
async def sp_profile_update(
        request: Request,
        # profile: Optional[ProfileUpdateInfo] = Body(None),
        name: Optional[str] = Form(None),
        firstName: Optional[str] = Form(None),
        lastName: Optional[str] = Form(None),
        email: str = Form(...),
        session_data: SessionData = Depends(deps_requires_session),
        csrf_valid: bool = Depends(deps_requires_csrf_posttoken),
    ) -> Union[ProfileUpdateInfo, Response]:
    # if not profile:
    try:
        profile = ProfileUpdateInfo(name=name, firstName=firstName, lastName=lastName, email=email)
    except ValidationError as e:
        raise RequestValidationError(errors=e.raw_errors)

    _ = await sp_profile_update_json(request=request, profile=profile, session_data=session_data)
    if request.state.response_type.is_json():
        return profile
    else:
        return RedirectResponse(request.url_for('sp_profile')+"?updated=1", status_code=303)

async def sp_profile_update_json(
        request: Request,
        profile: ProfileUpdateInfo,
        session_data: SessionData
    ) -> bool:
    data: str = profile.json(exclude={'name',})
    await request_accountapi_json_expect_200(request=request, session_data=session_data, data=data)
    return True

@router.post("/emailverify", include_in_schema=False, status_code=204, responses={
        303: {"description": "Successful response (for end users)", "content": {"text/html": {}}},
        204: {"content": {"application/json": {}}},
        429: {"description": "Failed response (try again later to request a new verification)"},
    })
async def sp_profile_emailverify() -> Response:
    """
    Won't implement for now
    """
    return Response(status_code=404)
    # /{realm}/users/{id}/send-verify-email?client_id=
    # return Response(status_code=204)