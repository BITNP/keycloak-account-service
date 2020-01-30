from fastapi import Depends, APIRouter
from starlette.requests import Request
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
    profile = await sp_profile_json(session_data=session_data)
    if 'application/json' in request.headers['accept']:
        return profile
    else:
        return request.app.state.templates.TemplateResponse("sp-profile.html.jinja2", {
            "request": request,
            "sessions": [],
            "profile": profile,
            "name": session_data.username,
            "signed_in": True,
            "csrf_field": csrf_field,
        })

async def sp_profile_json(
        session_data: datatypes.SessionData = Depends(BITNPSessionFastAPIApp.deps_requires_session)
    ) -> datatypes.ProfileInfo:
    return datatypes.ProfileInfo.parse_obj(session_data)
