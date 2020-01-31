from fastapi import Depends, APIRouter
from starlette.requests import Request

import datatypes
from modauthlib import BITNPSessionFastAPIApp
from utils import TemplateService

router = APIRouter()

@router.get("/migrate-phpcas/", include_in_schema=False)
async def phpcas_migrate_landing(request: Request):
    return request.app.state.templates.TemplateResponse("index.html.jinja2", {"request": request})
