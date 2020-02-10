from fastapi import Depends, APIRouter
from starlette.requests import Request
from starlette.responses import RedirectResponse

import datatypes
from utils import TemplateService

router = APIRouter()


@router.get("/assistance/", include_in_schema=False)
async def assistance_landing(request: Request, templates: TemplateService = Depends()):
    if request.query_params.get('forgotpw'):
        return RedirectResponse(url=request.app.state.config.keycloak_forgotpw_url)

    return templates.TemplateResponse("assistance.html.jinja2", {
        "keycloak_forgotpw_url": "?forgotpw=1",
        "assistance_url": request.app.state.config.assistance_url,
    })
