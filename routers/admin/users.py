from fastapi import Depends, APIRouter, Path
from starlette.requests import Request

import datatypes
from modauthlib import BITNPSessionFastAPIApp
from utils import TemplateService

router = APIRouter()


@router.get("/users", include_in_schema=True)
async def admin_groups(
        request: Request,
        session_data: datatypes.SessionData = Depends(BITNPSessionFastAPIApp.deps_requires_admin_session)
    ):
    client: AsyncOAuth2Client
    async with request.app.state.app_session.get_service_account_oauth_client() as client:
        resp = await client.get(request.app.state.config.keycloak_adminapi_url+'users?briefRepresentation=true',
            headers={'Accept': 'application/json'})
        return resp.json()