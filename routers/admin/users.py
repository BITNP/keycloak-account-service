from fastapi import Depends, APIRouter, Path, HTTPException
from starlette.requests import Request
from typing import List, Optional
from pydantic import constr
import ldap3

import datatypes
from modauthlib import BITNPSessions, SessionData
from utils import TemplateService
from urllib.parse import quote

router = APIRouter()


@router.get("/users/", include_in_schema=True, response_model=List[datatypes.ProfileInfo], responses={
    200: {"content": {"text/html": {}}},
})
async def admin_users(
        request: Request,
        session_data: SessionData = Depends(BITNPSessions.deps_requires_master_session),
        search: str = '',
        first: int = 0,
    ):
    users = await admin_users_json(
        request=request, session_data=session_data,
        search=search, first=first, sort_by='createdTimestamp',
    )
    if request.state.response_type.is_json():
        return users
    else:
        return request.app.state.templates.TemplateResponse("admin-users-list.html.jinja2", {
                "request": request,
                "users": users,
                "name": session_data.username,
                "is_admin": session_data.is_admin(),
                "is_master": session_data.is_master(),
                "signed_in": True,
                "search": search,
                "first": first,
            })

async def admin_users_json(
        request: Request,
        session_data: SessionData,
        search: str = '',
        first: int = 0,
        sort_by: str = 'createdTimestamp',
    ):
    client: AsyncOAuth2Client = request.app.state.app_session.oauth_client
    resp = await client.get(
        request.app.state.config.keycloak_adminapi_url+'users?briefRepresentation=true&max=100&first='+str(first)+'&search='+quote(search),
        headers={'Accept': 'application/json'},
        token=session_data.to_tokens()
    )
    if resp.status_code == 200:
        users = list(datatypes.ProfileInfo.parse_obj(p) for p in resp.json())
        if sort_by == 'createdTimestamp':
            users.sort(key=lambda item: item.createdTimestamp, reverse=True)
        return users
    else:
        raise HTTPException(resp.status_code, detail=resp.json())


async def _admin_search_users(
        request: Request,
        search: str = '',
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

@router.get("/users/{user_id}", include_in_schema=True, responses={
    200: {"content": {"text/html": {}}},
}, response_model=datatypes.UserInfoMaster)
async def admin_user_detail(
        request: Request,
        user_id: constr(regex="^[A-Za-z0-9-_]+$"),
        session_data: SessionData = Depends(BITNPSessions.deps_requires_master_session),
    ):
    user = await admin_user_detail_json(request=request, user_id=user_id, session_data=session_data)
    if request.state.response_type.is_json():
        return user
    else:
        return request.app.state.templates.TemplateResponse("admin-users-detail.html.jinja2", {
                "request": request,
                "user": user,
                "name": session_data.username,
                "is_admin": session_data.is_admin(),
                "is_master": session_data.is_master(),
                "signed_in": True,
            })

async def admin_user_detail_json(
        request: Request,
        user_id: constr(regex="^[A-Za-z0-9-_]+$"),
        session_data: SessionData,
    ):
    config: datatypes.Settings = request.app.state.config

    client: AsyncOAuth2Client = request.app.state.app_session.oauth_client
    resp = await client.get(
        request.app.state.config.keycloak_adminapi_url+'users/'+quote(user_id),
        headers={'Accept': 'application/json'},
        token=session_data.to_tokens()
    )
    if resp.status_code == 200:
        user: datatypes.UserInfoMaster = datatypes.UserInfoMaster.parse_obj(resp.json())
    else:
        raise HTTPException(resp.status_code, detail=resp.json())

    # Groups
    groups_resp = await client.get(
        request.app.state.config.keycloak_adminapi_url+'users/'+quote(user_id)+'/groups',
        headers={'Accept': 'application/json'},
        token=session_data.to_tokens()
    )
    if groups_resp.status_code == 200:
        user.memberof = [config.group_config.get(g['path']) for g in groups_resp.json()]

    # LDAP
    conn = ldap3.Connection(ldap3.Server(config.ldap_host, get_info=ldap3.ALL),
        config.ldap_user_dn, config.ldap_password, auto_bind=True)
    ldape: Optional[datatypes.UserLdapEntry]
    if conn.search('uid='+user.username+','+config.ldap_base_dn_users, '(objectclass=*)',
        attributes=(ldap3.ALL_ATTRIBUTES, ldap3.ALL_OPERATIONAL_ATTRIBUTES, )):
        ldape = datatypes.UserLdapEntry.parse_obj(conn.response[0])
    else:
        # not found in ldap
        ldape = None

    user.ldapEntry = ldape
    return user
    # "LDAP_ENTRY_DN":["uid=test,ou=users,dc=bitnp,dc=net"],"phpCAS_id":["117"],"createTimestamp":["20200209070105Z"],"modifyTimestamp":["20200209071945Z"],"LDAP_ID":["af4c35ce-df55-1039-8b50-c9497b22642b"]
