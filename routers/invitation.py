from fastapi import Depends, APIRouter
from starlette.requests import Request
from starlette.responses import RedirectResponse

import datatypes
import invitation
from utils import TemplateService

router = APIRouter()


@router.get("/i/{token}", include_in_schema=False)
async def invitation_landing(request: Request, token: str):
    return invitation.parse_invitation_token(token=token, config=request.app.state.config)