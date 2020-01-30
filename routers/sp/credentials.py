from fastapi import Depends, APIRouter, Form, HTTPException
from fastapi.exceptions import RequestValidationError
from starlette.requests import Request
from starlette.responses import RedirectResponse
import datatypes
from pydantic import ValidationError

from modauthlib import BITNPSessionFastAPIApp

router = APIRouter()

@router.get("/password", include_in_schema=True)
async def sp_password(
        request: Request,
        session_data: datatypes.SessionData = Depends(BITNPSessionFastAPIApp.deps_requires_session)
    ):
    resp = await request.app.state.app_session.oauth_client.get(
        request.app.state.config.keycloak_accountapi_url+'credentials/password',
        token=session_data.to_tokens(),
        headers={'Accept': 'application/json'}
    )
    return resp.json()

async def sp_password_update():
    pass

async def sp_password_update_json():
    # {currentPassword, newPassword, confirmation}
    pass