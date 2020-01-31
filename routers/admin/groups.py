from fastapi import Depends, APIRouter, Path
from starlette.requests import Request

import datatypes
from modauthlib import BITNPSessionFastAPIApp
from utils import TemplateService

router = APIRouter()


@router.get("/groups", include_in_schema=True)
async def admin_groups(
        request: Request,
        session_data: datatypes.SessionData = Depends(BITNPSessionFastAPIApp.deps_requires_admin_session)
    ):
    client: AsyncOAuth2Client
    async with request.app.state.app_session.get_service_account_oauth_client() as client:
        resp = await client.get(request.app.state.config.keycloak_adminapi_url+'groups',
            headers={'Accept': 'application/json'})
        return resp.json()

@router.get("/roles/{role_name}/groups", include_in_schema=True)
async def admin_groups(
        request: Request,
        role_name: str = Path(..., regex="^[A-Za-z0-9-_]+$"),
        session_data: datatypes.SessionData = Depends(BITNPSessionFastAPIApp.deps_requires_admin_session)
    ):
    resp = await request.app.state.app_session.oauth_client.get(
        request.app.state.config.keycloak_adminapi_url+'roles/'+role_name+'/groups',
        token=session_data.to_tokens(),
        headers={'Accept': 'application/json'}
    )
    return resp.json()

@router.get("/client-roles/{role_name}/groups", include_in_schema=True)
async def admin_groups(
        request: Request,
        role_name: str = Path(..., regex="^[A-Za-z0-9-_]+$"),
        session_data: datatypes.SessionData = Depends(BITNPSessionFastAPIApp.deps_requires_admin_session)
    ):
    resp = await request.app.state.app_session.oauth_client.get(
        request.app.state.config.keycloak_adminapi_url+'clients/3513512c-c67b-4fc4-a540-939d1d29c12c/roles/'+role_name+'/groups',
        token=session_data.to_tokens(),
        headers={'Accept': 'application/json'}
    )
    return resp.json()