from fastapi import Depends, APIRouter, Path, HTTPException, Form
from starlette.requests import Request
from starlette.responses import RedirectResponse
from typing import List, Optional
from pydantic import constr
import ldap3
import traceback

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
                "jira_user_search_url_f": request.app.state.config.jira_user_search_url_f,
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
    config: datatypes.Settings = request.app.state.config
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
                "ldap_kc_fedlink_id": config.ldap_kc_fedlink_id,
                "ldap_base_dn_groups": config.ldap_base_dn_groups,
                "jira_user_search_url_f": request.app.state.config.jira_user_search_url_f,
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
    try:
        ldape = None
        conn = ldap3.Connection(ldap3.Server(config.ldap_host, get_info=ldap3.ALL),
            config.ldap_user_dn, config.ldap_password, auto_bind=True)
        ldape: Optional[datatypes.UserLdapEntry]
        if conn.search('uid='+user.username+','+config.ldap_base_dn_users, '(objectclass=*)',
            attributes=(ldap3.ALL_ATTRIBUTES, ldap3.ALL_OPERATIONAL_ATTRIBUTES, )):
            ldape = datatypes.UserLdapEntry.parse_obj(conn.response[0])

            # mask userPassword if needed
            if not ldape.attributes.get('userPassword', [b'{'])[0].decode().startswith('{'):
                ldape.attributes['userPassword'] = ['{MASKED}']
            if not ldape.raw_attributes.get('userPassword', ['{'])[0].startswith('{'):
                ldape.raw_attributes['userPassword'] = ['{MASKED}']

            # LDAP groups
            user.ldapMemberof = []
            if conn.search(config.ldap_base_dn_groups, '(&(objectClass=groupOfNames)(member='+ldape.dn+'))',
                attributes=None):
                user.ldapMemberof = [g['dn'] for g in conn.response]
        else:
            # not found in ldap
            pass
    except Exception as e:
        traceback.print_exc()

    user.ldapEntry = ldape
    return user

@router.get("/users/{user_id}/ldapSetup", include_in_schema=False, responses={
    200: {"content": {"text/html": {}}},
})
async def admin_user_ldapsetup_landing(
        request: Request,
        user_id: constr(regex="^[A-Za-z0-9-_]+$"),
        session_data: SessionData = Depends(BITNPSessions.deps_requires_master_session),
        csrf_field: tuple = Depends(BITNPSessions.deps_get_csrf_field),
    ):
    config: datatypes.Settings = request.app.state.config
    user = await admin_user_detail_json(request=request, user_id=user_id, session_data=session_data)

    ldap_data = admin_user_ldapsetup_generate(user=user, config=config)

    return request.app.state.templates.TemplateResponse("admin-users-ldapsetup.html.jinja2", {
        "request": request,
        "user": user,
        "ldap_new_attributes": ldap_data['ldap_new_attributes'],
        "ldap_kc_attributes": ldap_data['ldap_kc_attributes'],
        "ldap_groups_add": ldap_data['ldap_groups_add'],
        "ldap_groups_remove": ldap_data['ldap_groups_remove'],
        "name": session_data.username,
        "is_admin": session_data.is_admin(),
        "is_master": session_data.is_master(),
        "signed_in": True,
        "ldap_kc_fedlink_id": config.ldap_kc_fedlink_id,
        "csrf_field": csrf_field,
        "updated": bool(request.query_params.get("updated", False)),
    })


def admin_user_ldapsetup_generate(
        user: datatypes.UserInfoMaster,
        config: datatypes.Settings,
    ):
    """
    This is where we manually do attribute mappings in accountsvc for a manual sync.
    If any rules change please change here accordingly.
    In Keycloak they do this by using ldap-mappers.
    """
    ldap_new_object_class = ['inetOrgPerson', 'organizationalPerson']
    ldap_new_attributes = {
        'uid': user.username,
        # 'userPassword': '',
        'mail': user.email or '',
        'sn': user.lastName or ' ',
        'givenName': user.firstName or ' ',
        'cn': ' '.join([part for part in [user.firstName, user.lastName] if part.strip()]),
    }

    if user.ldapEntry:
        ldap_kc_attributes_new = {
            'LDAP_ENTRY_DN': [user.ldapEntry.dn],
            'LDAP_ID': user.ldapEntry.raw_attributes['entryUUID'],
            'modifyTimestamp': user.ldapEntry.raw_attributes['modifyTimestamp'],
            'createTimestamp': user.ldapEntry.raw_attributes['createTimestamp'],
        }
        ldap_kc_attributes = user.attributes.copy()
        ldap_kc_attributes.update(**ldap_kc_attributes_new)

        ldap_groups = ['cn='+g.path.split('/')[-1]+','+config.ldap_base_dn_groups for g in user.memberof]
        current_ldap_groups = user.ldapMemberof
        ldap_groups_add = []
        ldap_groups_remove = []
        for g in ldap_groups:
            if g not in current_ldap_groups:
                ldap_groups_add.append(g)
        for g in current_ldap_groups:
            if g not in ldap_groups:
                ldap_groups_remove.append(g)
    else:
        ldap_kc_attributes = None
        ldap_groups = None
        ldap_groups_add = None
        ldap_groups_remove = None


    return {
        "ldap_new_object_class": ldap_new_object_class,
        "ldap_new_attributes": ldap_new_attributes,
        "ldap_kc_attributes": ldap_kc_attributes,
        "ldap_groups_add": ldap_groups_add,
        "ldap_groups_remove": ldap_groups_remove,
    }

@router.post("/users/{user_id}/ldapSetup", include_in_schema=False, responses={
    200: {"content": {"text/html": {}}},
})
async def admin_user_ldapsetup_post(
        request: Request,
        user_id: constr(regex="^[A-Za-z0-9-_]+$"),
        type: str = Form(...),
        session_data: SessionData = Depends(BITNPSessions.deps_requires_master_session),
        csrf_valid: bool = Depends(BITNPSessions.deps_requires_csrf_posttoken),
    ):
    updated: bool = False
    config: datatypes.Settings = request.app.state.config
    user = await admin_user_detail_json(request=request, user_id=user_id, session_data=session_data)
    ldap_data = admin_user_ldapsetup_generate(user=user, config=config)

    if type == 'user':
        conn = ldap3.Connection(ldap3.Server(config.ldap_host, get_info=ldap3.ALL),
            config.ldap_user_dn, config.ldap_password, auto_bind=True)
        dn = 'uid='+user.username+','+config.ldap_base_dn_users
        if not user.ldapEntry:
            if conn.add(dn, object_class=ldap_data["ldap_new_object_class"], attributes=ldap_data["ldap_new_attributes"], controls=None):
                updated = True
            else:
                raise HTTPException(500, detail=conn.result)
        else:
            changes = {}
            for key, value in ldap_data["ldap_new_attributes"].items():
                changes[key] = [(ldap3.MODIFY_REPLACE, value)]

            if conn.modify(dn, changes=changes):
                updated = True
            else:
                raise HTTPException(500, detail=conn.result)

    if type == 'groups':
        conn = ldap3.Connection(ldap3.Server(config.ldap_host, get_info=ldap3.ALL),
            config.ldap_user_dn, config.ldap_password, auto_bind=True)
        user_dn = 'uid='+user.username+','+config.ldap_base_dn_users

        for add in ldap_data["ldap_groups_add"]:
            if not conn.modify(add, changes={"member": [(ldap3.MODIFY_ADD, [user_dn])]}):
                raise HTTPException(500, detail=conn.result)

        for removal in ldap_data["ldap_groups_remove"]:
            if not conn.modify(removal, changes={"member": [(ldap3.MODIFY_DELETE, [user_dn])]}):
                raise HTTPException(500, detail=conn.result)

        updated = True

    if type == 'kc':
        client: AsyncOAuth2Client = request.app.state.app_session.oauth_client
        resp = await client.put(
            request.app.state.config.keycloak_adminapi_url+'users/'+quote(user.id),
            headers={'Accept': 'application/json'},
            token=session_data.to_tokens(),
            json={
                "attributes": ldap_data["ldap_kc_attributes"],
                "federationLink": config.ldap_kc_fedlink_id,
            }
        )
        if resp.status_code != 204:
            raise HTTPException(resp.status_code, detail=resp.json())
        updated = True

    if updated:
        return RedirectResponse(request.url_for('admin_user_ldapsetup_landing', user_id=user_id)+"?updated=1", status_code=303)
    else:
        raise HTTPException(422, detail="type incorrect")
