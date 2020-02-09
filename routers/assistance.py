from fastapi import Depends, APIRouter
from starlette.requests import Request

import datatypes
from modauthlib import BITNPSessions
from utils import TemplateService

router = APIRouter()


@router.get("/assistance/", include_in_schema=False)
async def assistance_landing(request: Request, templates: TemplateService = Depends()):
    return templates.TemplateResponse("assistance.html.jinja2", {
        "keycloak_forgotpw_url": request.app.state.config.keycloak_forgotpw_url,
        "assistance_url": request.app.state.config.assistance_url,
    })
