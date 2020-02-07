from fastapi import Depends, APIRouter
from starlette.requests import Request
from starlette.responses import Response

import datatypes
from modauthlib import BITNPSessionFastAPIApp
from utils import TemplateService

router = APIRouter()

@router.get("/migrate-phpcas/", include_in_schema=False)
async def phpcas_migrate_landing(
        request: Request,
        csrf_field: tuple = Depends(BITNPSessionFastAPIApp.deps_get_csrf_field),
    ):
    return request.app.state.templates.TemplateResponse("migrate-phpcas-landing.html.jinja2", {
        "request": request,
        "csrf_field": csrf_field,
    })

@router.post("/migrate-phpcas/", include_in_schema=False)
async def phpcas_migrate_process(request: Request):
    return None

@router.get("/migrate-phpcas/is-required", include_in_schema=False)
async def phpcas_migrate_is_required(request: Request, username: str, email: str=None):
    if True:
        return Response(status_code=204)
    else:
        return Response(content="yes", status_code=409)