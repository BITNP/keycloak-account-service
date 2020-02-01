from fastapi import Depends, APIRouter, Path
from starlette.requests import Request

import datatypes
from modauthlib import BITNPSessionFastAPIApp
from utils import TemplateService
from typing import List, Tuple
from operator import attrgetter

router = APIRouter()


@router.get("/delegated-groups", include_in_schema=True)
async def admin_delegated_groups_get(
        request: Request,
        path: str = None,
        session_data: datatypes.SessionData = Depends(BITNPSessionFastAPIApp.deps_requires_admin_session),
    ):
    return ''

def guess_active_ns(session_data: datatypes.SessionData, group_config: datatypes.GroupConfig) -> Tuple[str, str]:
    pub_memberof = session_data.memberof
    active_groups, _ = group_config.filter_active_groups(pub_memberof)
    active_groups.sort(key=attrgetter('path'), reverse=True)
    if len(active_groups) < 1:
        return None
    path = active_groups[0].path
    year = path[len(group_config.settings.group_status_prefix):].split('/', 1)[0]
    return (group_config.settings.group_status_prefix
        + year + '/', year)

def guess_group_item(name: str, group_config: datatypes.GroupConfig) -> datatypes.GroupItem:
    ret = list()
    item: datatypes.GroupItem
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
        session_data: datatypes.SessionData = Depends(BITNPSessionFastAPIApp.deps_requires_admin_session),
    ) -> List[datatypes.GroupItem]:
    if session_data.is_master():
        ret = list()
        active_ns, year = guess_active_ns(session_data, request.app.state.config.group_config)
        item: datatypes.GroupItem
        for item in request.app.state.config.group_config.values():
            copied = item.copy(deep=True)
            if copied.path.startswith(datatypes.GroupConfig.active_ns_placeholder):
                copied.path = copied.path.replace(datatypes.GroupConfig.active_ns_placeholder, active_ns)
                copied.name = copied.name + year
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
                ret.append(datatypes.GroupItem(path="@managerof-"+n, name=n))
        return ret

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