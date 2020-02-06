from fastapi import Depends, APIRouter
from starlette.requests import Request

import datatypes
from modauthlib import BITNPSessionFastAPIApp
from utils import TemplateService

router = APIRouter()

@router.get("/register/", include_in_schema=False)
async def register_landing(
        request: Request,
        csrf_field: tuple = Depends(BITNPSessionFastAPIApp.deps_get_csrf_field),
    ):
    return request.app.state.templates.TemplateResponse("register-landing.html.jinja2", {
        "request": request,
        "csrf_field": csrf_field,
    })
