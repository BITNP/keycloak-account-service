from fastapi import APIRouter
from starlette.requests import Request
from starlette.responses import RedirectResponse, Response

router = APIRouter()

@router.get("/", include_in_schema=False)
async def admin_landing(request: Request) -> Response:
    return RedirectResponse(url=request.url_for("sp_landing"))

@router.get("/keycloak", include_in_schema=False)
async def admin_keycloak_redirect(request: Request) -> Response:
    return RedirectResponse(url=request.app.state.config.keycloak_admin_console_url)
