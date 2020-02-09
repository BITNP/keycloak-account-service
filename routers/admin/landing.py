from fastapi import APIRouter
from starlette.requests import Request
from starlette.responses import RedirectResponse

router = APIRouter()

@router.get("/", include_in_schema=False)
async def admin_landing(request: Request):
    return RedirectResponse(url=request.url_for("sp_landing"))
