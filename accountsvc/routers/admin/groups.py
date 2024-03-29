from typing import List, Tuple, Optional, Generator, Union
from operator import attrgetter
from urllib.parse import quote
from datetime import datetime, timedelta, timezone

from fastapi import Depends, APIRouter, HTTPException, Form, Query
from starlette.requests import Request
from starlette.responses import Response, RedirectResponse
from pydantic import constr

from accountsvc import invitation
from accountsvc.datatypes import GroupItem, KCGroupItem, ProfileInfo, GroupConfig, Settings
from accountsvc.modauthlib import (SessionData, deps_requires_admin_session, deps_requires_master_session,
                                   deps_get_csrf_field, deps_requires_csrf_posttoken)
from accountsvc.utils import TemplateService
from .users import _admin_search_users, _admin_search_users_by_username, admin_users_json

router: APIRouter = APIRouter()


@router.get("/delegated-groups/", include_in_schema=True, response_model=List[GroupItem])
async def admin_delegated_groups_get(
        request: Request,
        path: Optional[str] = Query(None, example="/bitnp/active"),
        session_data: SessionData = Depends(deps_requires_admin_session),
        first: int = Query(0, example="0"),
        csrf_field: tuple = Depends(deps_get_csrf_field),
    ) -> Union[List[GroupItem], Response]:
    grouplist = admin_delegated_groups_list_json(request=request, session_data=session_data)
    if path is None:
        if request.state.response_type.is_json():
            return grouplist
        else:
            return request.app.state.templates.TemplateResponse("admin-delegatedgroup-list.html.jinja2", {
                "request": request,
                "groups": grouplist,
                "name": session_data.username,
                "is_admin": session_data.is_admin(),
                "is_master": session_data.is_master(),
                "signed_in": True,
            })
    else:
        # detail page
        current_group = await admin_delegated_groups_detail_json(request, grouplist, path, session_data, first)
        if request.state.response_type.is_json():
            return [current_group]
        else:
            updated = request.query_params.get('updated', False)
            return request.app.state.templates.TemplateResponse("admin-delegatedgroup-detail.html.jinja2", {
                "request": request,
                "group": current_group,
                "name": session_data.username,
                "new_nonce": invitation.generate_random_nonce(),
                "first": first,
                "path": path,
                "is_admin": session_data.is_admin(),
                "is_master": session_data.is_master(),
                "signed_in": True,
                "updated": updated,
                "csrf_field": csrf_field,
            })

@router.get("/delegated-groups/all", include_in_schema=True, response_model=List[GroupItem])
async def admin_delegated_groups_master_list(
        request: Request,
        session_data: SessionData = Depends(deps_requires_admin_session),
    ) -> Union[List[GroupItem], Response]:
    if not session_data.is_master():
        return await admin_delegated_groups_get(request=request, path=None, session_data=session_data)
    grouplist = await admin_delegated_groups_master_list_json(request=request, session_data=session_data)

    if request.state.response_type.is_json():
        return grouplist
    else:
        return request.app.state.templates.TemplateResponse("admin-delegatedgroup-masterlist.html.jinja2", {
            "request": request,
            "groups": grouplist,
            "name": session_data.username,
            "is_admin": session_data.is_admin(),
            "is_master": session_data.is_master(),
            "signed_in": True,
        })

async def _admin_delegated_groups_path_to_group(
        request: Request,
        session_data: SessionData,
        grouplist: List[GroupItem],
        path: str,
    ) -> KCGroupItem:
    group_config = request.app.state.config.group_config
    # check if path is inside allowed grouplist - some ACL control
    current_groups = list(filter(lambda g: g.path == path, grouplist))
    if len(current_groups) != 1:
        if not session_data.is_master():
            raise HTTPException(status_code=403, detail="The path is not in the group list that you are allowed to access")
        # master exception
        current_group: GroupItem = group_config.get(path, None)
        if current_group:
            current_group = current_group.copy(deep=True)
        else:
            current_group = GroupItem(path=path)
    else:
        current_group = current_groups[0]

    # @managerof- parsing
    if current_group.path.startswith("@managerof-"):
        role_name = current_group.path[1:]
        try:
            async with request.app.state.app_session.get_service_account_oauth_client() as client:
                resp = await client.get(
                    (request.app.state.config.keycloak_adminapi_url+'clients/'+
                     request.app.state.config.keycloak_client_uuid+'/roles/'+role_name),
                    headers={'Accept': 'application/json'})
                groupNS = resp.json().get('attributes').get('groupNS')[0]
            # Merge from group_config
            # it's possible that this groupNS is not in group_config
            # this case we should proceed and reuse the previous group_config
            group_info = group_config.get(groupNS)
            if group_info:
                current_group = group_info
            else:
                current_group.path = groupNS
        except Exception as e:
            print(e)
            raise HTTPException(status_code=404, detail="Cannot get group information based on your role")

    # lookup group id from path
    # or, we need attributes for invitation nonce
    if not current_group.id or current_group.attributes is None:
        try:
            async with request.app.state.app_session.get_service_account_oauth_client() as client:
                resp = await client.get(
                    request.app.state.config.keycloak_adminapi_url+'group-by-path/'+current_group.path,
                    headers={'Accept': 'application/json'})
                group_info = resp.json()
                current_group.id = group_info['id']
                current_group.attributes = group_info.get('attributes', dict())
        except Exception as e:
            print(e)
            raise HTTPException(status_code=404, detail="Cannot get group information by path")

    return KCGroupItem.parse_obj(current_group)

async def admin_delegated_groups_detail_json(
        request: Request,
        grouplist: List[GroupItem],
        path: str,
        session_data: SessionData = Depends(deps_requires_admin_session),
        first: int = 0,
    ) -> GroupItem:
    current_group = await _admin_delegated_groups_path_to_group(request, session_data, grouplist, path)

    # get group invitation link
    # May be None if no nonce is set up
    current_group.invitation_link = invitation.get_invitation_link(group=current_group, request=request)
    expires = invitation.get_invitation_expires(group=current_group)
    current_group.invitation_expires = datetime.utcfromtimestamp(expires) if expires else None

    # get group direct users - first 100
    current_group.members = await _admin_groups_members_json(request, current_group.id, first)

    return current_group

async def _admin_groups_members_json(
        request: Request,
        group_id: str,
        first: int = 0,
        briefRepresentation: bool = True
    ) -> List[ProfileInfo]:
    # This method DOES NOT authenticate at all; use with caution
    async with request.app.state.app_session.get_service_account_oauth_client() as client:
        resp = await client.get(
            request.app.state.config.keycloak_adminapi_url+'groups/'+group_id+'/members',
            headers={'Accept': 'application/json'},
            params={
                'briefRepresentation': briefRepresentation,
                'first': first,
            },
        )
        ret = resp.json()
        return list(ProfileInfo.parse_obj(u) for u in ret)

@router.post("/delegated-groups/member-add", include_in_schema=True, response_model=ProfileInfo)
async def admin_delegated_groups_member_add(
        request: Request,
        path: str = Form(...),
        username: Optional[str] = Form(None),
        user_id: Optional[constr(regex="^[A-Za-z0-9-_]+$")] = Form(None), # type: ignore # constr
        session_data: SessionData = Depends(deps_requires_admin_session),
        csrf_valid: bool = Depends(deps_requires_csrf_posttoken),
    ) -> Union[ProfileInfo, Response]:
    grouplist = admin_delegated_groups_list_json(request=request, session_data=session_data)
    current_group = await _admin_delegated_groups_path_to_group(request, session_data, grouplist, path)

    user = await _delegated_groups_member_add_json(
        request, current_group, username, user_id
    )
    # success
    if request.state.response_type.is_json():
        return user
    else:
        return RedirectResponse(request.url_for('admin_delegated_groups_get')+"?path="+quote(path)+"&updated=1", status_code=303)

async def _delegated_groups_member_add_json(
        request: Request,
        current_group: KCGroupItem,
        username: Optional[str] = None,
        user_id: Optional[str] = None,
    ) -> ProfileInfo:
    """
    This function is also used on client-faced invitation join i.e. no permission check against session_data.

    Another logic of this is located at register.register_process
    """
    if not username and not user_id:
        raise HTTPException(status_code=422, detail="username or user_id required")

    parsed_user = None
    if not user_id and username:
        parsed_user = await admin_users_json(request=request, session_data=None, search=username)
        user_id = parsed_user[0].id

    assert user_id is not None, "Cannot find a valid user_id"

    async with request.app.state.app_session.get_service_account_oauth_client() as client:
        resp = await client.put(
            request.app.state.config.keycloak_adminapi_url+'users/'+quote(user_id)+'/groups/'+quote(current_group.id),
            # user id is always returned from Keycloak so it should be fine to use it without encoding
            headers={'Accept': 'application/json'})
        if resp.status_code == 204:
            return parsed_user[0] if parsed_user else ProfileInfo(id=user_id)
        else:
            raise HTTPException(resp.status_code, detail=resp.json())

@router.post("/delegated-groups/member-remove", include_in_schema=True, status_code=204)
async def admin_delegated_groups_member_remove(
        request: Request,
        path: str = Form(...),
        username: str = Form(None),
        user_id: Optional[constr(regex="^[A-Za-z0-9-_]+$")] = Form(None), # type: ignore # constr
        session_data: SessionData = Depends(deps_requires_admin_session),
        csrf_valid: bool = Depends(deps_requires_csrf_posttoken),
    ) -> Response:
    grouplist = admin_delegated_groups_list_json(request=request, session_data=session_data)
    current_group = await _admin_delegated_groups_path_to_group(request, session_data, grouplist, path)

    await admin_delegated_groups_member_remove_json(request, current_group, username, user_id)
    # success
    if request.state.response_type.is_json():
        return Response(status_code=204)
    else:
        return RedirectResponse(request.url_for('admin_delegated_groups_get')+"?path="+quote(path)+"&updated=1", status_code=303)

async def admin_delegated_groups_member_remove_json(
        request: Request,
        current_group: KCGroupItem,
        username: Optional[str] = None,
        user_id: Optional[str] = None,
    ) -> None:
    if not user_id and not username:
        raise HTTPException(status_code=422, detail="username or user_id required")

    parsed_user = None
    if not user_id and username:
        parsed_user = await admin_users_json(request=request, session_data=None, search=username)
        user_id = parsed_user[0].id

    assert user_id is not None, "Cannot find a valid user_id"

    async with request.app.state.app_session.get_service_account_oauth_client() as client:
        resp = await client.delete(
            request.app.state.config.keycloak_adminapi_url+'users/'+quote(user_id)+'/groups/'+quote(current_group.id),
            headers={'Accept': 'application/json'})
        if resp.status_code == 204:
            pass
        else:
            raise HTTPException(resp.status_code, detail=resp.json())

@router.post("/delegated-groups/update-invitation-link", include_in_schema=True,
             responses={
                 200: {"content": {"application/json": {"example": {"invitationNonce": ["rAnD"], "invitationExpires": [123456789]}}}},
                 303: {"description": "Successful response (for end users)", "content": {"text/html": {}}},
             })
async def admin_delegated_groups_update_invitation_link(
        request: Request,
        path: str = Form(..., example="/bitnp/active"),
        days_from_now: int = Form(...),
        expires: Optional[datetime] = Form(None),
        session_data: SessionData = Depends(deps_requires_admin_session),
        csrf_valid: bool = Depends(deps_requires_csrf_posttoken),
    ) -> Union[Response, dict]:
    """
    - days_from_now < 0: nonce = None
    - days_from_now == 0: nonce = new
    - days_from_now > 0: expires = now + days_from_now, nonce = new if not nonce else nonce
    """
    grouplist = admin_delegated_groups_list_json(request=request, session_data=session_data)
    current_group = await _admin_delegated_groups_path_to_group(request, session_data, grouplist, path)

    attributes: dict = current_group.attributes or {}

    if days_from_now > 0:
        if not attributes.get('invitationNonce'):
            attributes['invitationNonce'] = [invitation.generate_random_nonce()]
    elif days_from_now == 0:
        # reset nonce
        attributes['invitationNonce'] = [invitation.generate_random_nonce()]
    else:
        # remove nonce
        attributes['invitationNonce'] = []

    if days_from_now > 0 or expires:
        if not expires:
            expires = datetime.utcnow() + timedelta(days=days_from_now)
        attributes['invitationExpires'] = [int(expires.replace(tzinfo=timezone.utc).timestamp())]

    async with request.app.state.app_session.get_service_account_oauth_client() as client:
        resp = await client.put(
            request.app.state.config.keycloak_adminapi_url+'groups/'+quote(current_group.id),
            json={"attributes": attributes})
        if resp.status_code == 204:
            if request.state.response_type.is_json():
                return attributes
            else:
                return RedirectResponse(request.url_for('admin_delegated_groups_get')+"?path="+quote(path)+"&updated=1", status_code=303)
        else:
            raise HTTPException(resp.status_code, detail=resp.json())


def guess_active_ns(session_data: SessionData, group_config: GroupConfig) -> Tuple[Optional[str], Optional[str]]:
    """
    Guess active_ns by checking the last available year in status groups.
    Since session_data is usually admin, we assume that they have latest affiliation.

    e.g. I have `/bitnp/active-2018/2018-master, /bitnp/active-2019/2019-alumni`,
    then 2019 is the guessed active_ns.

    First return value will only include ns; you may want ret[0]+ret[1]+'-'
    """
    pub_memberof = session_data.memberof
    active_groups, _ = group_config.filter_active_groups(pub_memberof)
    active_groups.sort(key=attrgetter('path'), reverse=True)
    if len(active_groups) < 1:
        return (None, None)
    path = active_groups[0].path
    year = path[len(group_config.settings.group_status_prefix):].split('/', 1)[0]
    return (group_config.settings.group_status_prefix + year + '/', year)

def guess_group_item(name: str, group_config: GroupConfig) -> Optional[GroupItem]:
    """
    Guess group item from name, by comparing the suffix.

    e.g. group_config=[`/bitnp/iam-admin`], name=`iam-admin`, then match.

    If there are multiple results, see if we could match one but only one @active/, or return None.
    """
    ret = list()
    item: GroupItem
    for item in group_config.values():
        if item.path.endswith(name):
            ret.append(item)
    if len(ret) == 0:
        return None
    if len(ret) == 1:
        return ret[0]
    status = list(item for item in ret if item.path.startswith(group_config.settings.group_status_prefix))
    if len(status) == 1:
        return status[0]
    return None # not sure, don't guess

def admin_delegated_groups_list_json(
        request: Request,
        session_data: SessionData,
    ) -> List[GroupItem]:
    if session_data.is_master():
        ret = list()
        active_ns, year = guess_active_ns(session_data, request.app.state.config.group_config)
        item: GroupItem
        for item in request.app.state.config.group_config.values():
            copied = item.copy(deep=True)
            if copied.path.startswith(GroupConfig.active_ns_placeholder):
                if active_ns and year:
                    copied.path = copied.path.replace(
                        GroupConfig.active_ns_placeholder, active_ns+year+'-')
                    copied.name = copied.name + ' ' + year
                else:
                    # we cannot guess any active_ns; ignore this to prevent error
                    continue
            ret.append(copied)
        return ret
    else:
        names = list(r[10:] for r in session_data.client_roles if r.startswith('managerof-'))
        ret = list()
        for n in names:
            guess = guess_group_item(n, request.app.state.config.group_config)
            if guess:
                copied = guess.copy(deep=True)
                copied.path = "@managerof-"+n
                ret.append(copied)
            else:
                ret.append(GroupItem(path="@managerof-"+n, name=n))
        return ret

def loop_grouptree(grouptree: Optional[list], config: GroupConfig) -> Generator[GroupItem, None, None]:
    if isinstance(grouptree, list):
        for g in grouptree:
            item: GroupItem = config.get(g['path'], None)
            if item:
                item = item.copy(deep=True)
                item.id = g['id']
            else:
                item = GroupItem.parse_obj(g)
            yield item

            yield from loop_grouptree(g['subGroups'], config)


async def admin_delegated_groups_master_list_json(
        request: Request,
        session_data: SessionData,
    ) -> List[GroupItem]:
    if session_data.is_master():
        resp = await request.app.state.app_session.oauth_client.get(
            request.app.state.config.keycloak_adminapi_url+'groups',
            token=session_data.to_tokens(),
            headers={'Accept': 'application/json'}
        )
        if resp.status_code != 200:
            raise HTTPException(status_code=resp.status_code, detail=resp.json())

        grouptree: list = resp.json()

        return list(loop_grouptree(grouptree, request.app.state.config.group_config))
    else:
        return []

@router.get("/group-config/", include_in_schema=True, response_model=List[GroupItem])
async def admin_group_config(
        request: Request,
        session_data: SessionData = Depends(deps_requires_master_session),
        templates: TemplateService = Depends(),
    ) -> Union[List[GroupItem], Response]:
    config: Settings = request.app.state.config
    guessed_ns = guess_active_ns(session_data, config.group_config)
    incorrect: Optional[str] = None
    active_role_groups: list = []
    managerof_roles: list = []
    group_config: list = list(config.group_config.values())
    try:
        active_role_groups_resp = await request.app.state.app_session.oauth_client.get(
            request.app.state.config.keycloak_adminapi_url+'roles/'+config.role_active_name+'/groups',
            token=session_data.to_tokens(),
            headers={'Accept': 'application/json'}
        )
        active_role_groups = active_role_groups_resp.json()
        managerof_roles = await admin_group_config_get_managerof(request, session_data, config)
    except Exception as e: # pylint: disable=broad-except
        print(e)
        incorrect = '{}: {}'.format(e.__class__.__name__, str(e))

    return templates.TemplateResponse('admin-group-config.html.jinja2', {
        'client_uuid': config.keycloak_client_uuid,
        'guess_active_ns': guessed_ns,
        'group_config': group_config,
        'active_role_groups': active_role_groups,
        'managerof_roles': managerof_roles,
        'incorrect': incorrect,
    })

async def admin_group_config_get_managerof(request: Request, session_data: SessionData, config: Settings) -> list:
    managerof_roles_resp = await request.app.state.app_session.oauth_client.get(
        request.app.state.config.keycloak_adminapi_url+'clients/'+config.keycloak_client_uuid+'/roles',
        token=session_data.to_tokens(),
        headers={'Accept': 'application/json'}
    )
    managerof_roles = []
    for r in managerof_roles_resp.json():
        if not r['name'].startswith("managerof-"):
            continue

        attr_resp = await request.app.state.app_session.oauth_client.get(
            request.app.state.config.keycloak_adminapi_url+'roles-by-id/'+r['id'],
            token=session_data.to_tokens(),
            headers={'Accept': 'application/json'}
        )
        r['attributes'] = attr_resp.json()['attributes']

        group_resp = await request.app.state.app_session.oauth_client.get(
            request.app.state.config.keycloak_adminapi_url+'clients/'+config.keycloak_client_uuid+'/roles/'+r['name']+'/groups',
            token=session_data.to_tokens(),
            headers={'Accept': 'application/json'}
        )
        r['groups'] = group_resp.json()

        managerof_roles.append(r)
    return managerof_roles

@router.get("/delegated-groups/batch-users", include_in_schema=False)
async def admin_delagated_group_batchuser(
        request: Request,
        path: Optional[str] = Query(None),
        session_data: SessionData = Depends(deps_requires_admin_session),
        templates: TemplateService = Depends(),
    ) -> Response:
    # Verify that they have permission with the path, and preload grouplist
    if session_data.is_master():
        grouplist = await admin_delegated_groups_master_list_json(request=request, session_data=session_data)
    else:
        grouplist = admin_delegated_groups_list_json(request=request, session_data=session_data)
    current_group: Optional[KCGroupItem]
    if path:
        current_group = await _admin_delegated_groups_path_to_group(request, session_data, grouplist, path)
    else:
        current_group = None

    # This is a single page app
    return templates.TemplateResponse('admin-delegatedgroup-batchusers.html.jinja2', {
        'path': path,
        'group': current_group,
        'grouplist': grouplist,
    })