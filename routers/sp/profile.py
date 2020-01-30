from fastapi import Depends, APIRouter, Form
from starlette.requests import Request
from starlette.responses import RedirectResponse
from starlette.exceptions import HTTPException as StarletteHTTPException
import datatypes

from modauthlib import BITNPSessionFastAPIApp

router = APIRouter()

@router.get("/", include_in_schema=True, response_model=datatypes.ProfileInfo,
    responses={
        200: {"content": {"text/html": {}}}
    })
async def sp_profile(
        request: Request,
        csrf_field: tuple = Depends(BITNPSessionFastAPIApp.deps_get_csrf_field),
        session_data: datatypes.SessionData = Depends(BITNPSessionFastAPIApp.deps_requires_session),
    ):
    # prefer_onename is used if user has firstName+lastName and they initiated oneName setup process
    prefer_onename = request.query_params.get('prefer_onename', False)
    updated = request.query_params.get('updated', False)
    profile = await sp_profile_json(request=request, session_data=session_data)
    if 'application/json' in request.headers['accept']:
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
        })

async def sp_profile_json(
        request: Request,
        session_data: datatypes.SessionData = Depends(BITNPSessionFastAPIApp.deps_requires_session),
        load_session_only: bool= False
    ) -> datatypes.ProfileInfo:
    if not load_session_only:
        resp = await request.app.state.app_session.oauth_client.get(
            request.app.state.config.keycloak_accountapi_url,
            token=session_data.to_tokens(),
            headers={'Accept': 'application/json'}
        )
        profile = resp.json()
        profile['name'] = session_data.name
        profile['subject'] = session_data.subject
    else:
        profile = session_data
    return datatypes.ProfileInfo.parse_obj(profile)

@router.post("/", include_in_schema=True, status_code=200, responses={
        303: {"description": "Successful response (for end users)", "content": {"text/html": {}}},
        200: {"content": {"application/json": {}}}
    })
async def sp_profile_update(
        request: Request,
        profile: datatypes.ProfileInfo = None,
        name: str = Form(None),
        firstName: str = Form(None),
        lastName: str = Form(None),
        email: str = Form(None),
        session_data: datatypes.SessionData = Depends(BITNPSessionFastAPIApp.deps_requires_session),
        csrf_valid: bool = Depends(BITNPSessionFastAPIApp.deps_requires_csrf_posttoken),
    ):
    return profile
    if 'application/json' in request.headers['accept']:
        return {'status':'ok'}
    else:
        return RedirectResponse(request.url_for('sp_profile')+"?updated=1", status_code=303)