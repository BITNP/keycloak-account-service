from fastapi import Depends, APIRouter, Path, HTTPException
from starlette.requests import Request
from typing import List

import datatypes
from modauthlib import BITNPSessions
from utils import TemplateService
from urllib.parse import quote

router = APIRouter()


@router.get("/users", include_in_schema=True)
async def admin_groups(
        request: Request,
        session_data: datatypes.SessionData = Depends(BITNPSessions.deps_requires_master_session)
    ):
    client: AsyncOAuth2Client
    async with request.app.state.app_session.oauth_client as client:
        resp = await client.get(request.app.state.config.keycloak_adminapi_url+'users?briefRepresentation=true',
            headers={'Accept': 'application/json'})
        return resp.json()

async def _admin_search_users(
        request: Request,
        search: str
    ) -> List[datatypes.ProfileInfo]:
    """
    search: A String contained in username, first or last name, or email
    """
    client: AsyncOAuth2Client
    async with request.app.state.app_session.get_service_account_oauth_client() as client:
        resp = await client.get(request.app.state.config.keycloak_adminapi_url+'users?briefRepresentation=true&search='+quote(search),
            headers={'Accept': 'application/json'})
        if resp.status_code == 200:
            return list(datatypes.ProfileInfo.parse_obj(p) for p in resp.json())
        else:
            raise HTTPException(resp.status_code, detail=resp.json())

async def _admin_search_users_by_username(
        request: Request,
        username: str
    ) -> List[datatypes.ProfileInfo]:
    """
    This is supposed to return exact match of username
    """
    client: AsyncOAuth2Client
    async with request.app.state.app_session.get_service_account_oauth_client() as client:
        resp = await client.get(
            request.app.state.config.keycloak_adminapi_url+'users?briefRepresentation=true&username='+quote(username),
            headers={'Accept': 'application/json'})
        if resp.status_code == 200:
            return list(datatypes.ProfileInfo.parse_obj(p) for p in resp.json() if p["username"] == username)
        else:
            raise HTTPException(resp.status_code, detail=resp.json())
