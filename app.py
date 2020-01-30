from fastapi import FastAPI, Depends, APIRouter, Query, Path
from starlette.middleware.sessions import SessionMiddleware
from starlette.requests import Request
from starlette.responses import Response, PlainTextResponse, JSONResponse, RedirectResponse
from starlette.staticfiles import StaticFiles
from starlette.templating import Jinja2Templates
from starlette.exceptions import HTTPException as StarletteHTTPException
from fastapi.exception_handlers import http_exception_handler
import datatypes
from utils import TemplateService

from authlib.integrations.starlette_client import OAuth
from authlib.integrations.httpx_client import OAuthError, AsyncOAuth2Client
from modauthlib import BITNPOAuthRemoteApp, BITNPSessionFastAPIApp
from aiocache import Cache

from urllib.parse import urlencode
from datetime import tzinfo, datetime
import json

app = FastAPI(
    title="网协通行证账户服务",
    version="0.1"
)

router = APIRouter()

app.state.config = datatypes.Settings() # from .env
with open('group_config.json', 'r') as f:
    data = json.load(f)
    app.state.config.group_config = datatypes.GroupConfig.from_dict(data, settings=app.state.config)

app.state.oauth = OAuth()
app.state.oauth.remote_app_class = BITNPOAuthRemoteApp
app.state.oauth.register(
    name='bitnp',
    client_id=app.state.config.client_id,
    client_secret=app.state.config.client_secret,
    server_metadata_url=app.state.config.server_metadata_url,
    client_kwargs = {
        'scope': 'openid'
    },
)

app.add_middleware(SessionMiddleware, secret_key=app.state.config.session_secret)
app_session = BITNPSessionFastAPIApp(
    app=app, oauth_client=app.state.oauth.bitnp, group_config=app.state.config.group_config,
    csrf_token=app.state.config.session_secret,
    cache_type=Cache.MEMORY
)
app.state.app_session = app_session
app.mount("/static", StaticFiles(directory="static"), name="static")

def local_timestring(dt, format='%Y-%m-%d %H:%M'):
    return dt.astimezone(app.state.config.local_timezone).strftime(format)

app.state.templates = Jinja2Templates(directory="templates")
app.state.templates.env.globals["app_title"] = app.title
app.state.templates.env.filters["local_timestring"] = local_timestring


@app.exception_handler(StarletteHTTPException)
async def http_exception_accept_handler(request, exc):
    if 'application/json' in request.headers['accept']:
        return await http_exception_handler(request, exc)
    else:
        return PlainTextResponse(f"{exc.status_code} {exc.detail}", status_code=exc.status_code)

@app.exception_handler(OAuthError)
async def oauth_exception_handler(request, exc):
    if 'application/json' in request.headers['accept']:
        return JSONResponse(
            {"detail": exc.description}, status_code=500
        )
    else:
        return PlainTextResponse(f"{exc.error}: {exc.description}", status_code=500)


@router.get("/", include_in_schema=False)
async def index(request: Request,
    session_data: datatypes.SessionData = Depends(app_session.deps_session_data)):
    tdata = {
        "request": request,
        "name": None,
        "is_admin": False,
        "signed_in": False
    }
    if session_data:
        return RedirectResponse(request.url_for("sp_landing"))
        tdata['name'] = session_data.username
        tdata['is_admin'] = "admin" in session_data.client_roles
        tdata['signed_in'] = True
    return request.app.state.templates.TemplateResponse("index.html.jinja2", tdata)


@router.get("/activate-phpcas/", include_in_schema=False)
async def activate_phpcas_landing(request: Request):
    return request.app.state.templates.TemplateResponse("index.html.jinja2", {"request": request})


@router.get("/assistance/", include_in_schema=False)
async def assistance_landing(request: Request):
    return request.app.state.templates.TemplateResponse("index.html.jinja2", {"request": request})


@router.get("/sp/", include_in_schema=False)
async def sp_landing(request: Request,
        session_data: datatypes.SessionData = Depends(app_session.deps_requires_session_gen())
    ):
    tdata = {
        "request": request,
        "name": session_data.username,
        "is_admin": "admin" in session_data.client_roles,
        "signed_in": True,
        "keycloak_admin_url": request.app.state.config.keycloak_admin_url,
        "permission": await sp_permission(request=request, session_data=session_data),
        "profile": await sp_profile(session_data=session_data),
    }

    # Remote
    try:
        tdata["sessions"] = (await sp_sessions_json(session_data=session_data))
        tdata['sessions_count'] = len(tdata['sessions'])
    except Exception as e:
        tdata["sessions"] = None
        tdata['sessions_count'] = 0

    if tdata['sessions_count'] > 1:
        latest_session: datatypes.KeycloakSessionItem = tdata['sessions'][1]
        device: str = latest_session.os + ' ' + latest_session.browser
        if latest_session.device:
            device = latest_session.device + ' ' + latest_session.browser
        tdata['sessions_desc'] = '你在其它位置的最后一次登录是 {time} ({browser})。'.format(
            time=local_timestring(latest_session.lastAccess),
            browser=device)
    elif tdata['sessions_count'] > 0:
        tdata['sessions_desc'] = '你目前没有在其它位置登录。'
    else:
        tdata['sessions_desc'] = '查看你在其它设备的登录情况并远程下线。'
    return request.app.state.templates.TemplateResponse("sp.html.jinja2", tdata)

@router.get("/sp/permission", include_in_schema=True, response_model=datatypes.PermissionInfo)
async def sp_permission(
    request: Request,
    session_data: datatypes.SessionData = Depends(app_session.deps_requires_session_gen())
    ) -> datatypes.PermissionInfo:
    pub_memberof = session_data.memberof.copy()
    for item in pub_memberof:
        item.internal_note = None
    permission_dict = session_data.dict()
    permission_dict['active_groups'], permission_dict['memberof'] \
        = request.app.state.config.group_config.filter_active_groups(pub_memberof)
    permission_dict['has_active_role'] = request.app.state.config.role_active_name in session_data.realm_roles
    return datatypes.PermissionInfo(**permission_dict)

@router.get("/sp/profile", include_in_schema=True, response_model=datatypes.ProfileInfo)
async def sp_profile(
        session_data: datatypes.SessionData = Depends(app_session.deps_requires_session_gen())
    ) -> datatypes.ProfileInfo:
    return datatypes.ProfileInfo.parse_obj(session_data)

@router.get("/sp/sessions/", include_in_schema=True, response_model=datatypes.KeycloakSessionInfo,
    responses={
        200: {"content": {"text/html": {}}}
    })
async def sp_sessions(
        request: Request,
        csrf_field: tuple = Depends(app_session.deps_get_csrf_field_gen()),
        session_data: datatypes.SessionData = Depends(app_session.deps_requires_session_gen()),
        order_by: str = 'default',
    ):
    """
    TODO: https://github.com/tiangolo/fastapi/issues/911

    The order of KeycloakSessionItem will be:
    - Current session
    - Order from the latest to the oldest of `lastAccess`
    """
    sessions = await sp_sessions_json(session_data, order_by)
    if 'application/json' in request.headers['accept']:
        return sessions
    else:
        return request.app.state.templates.TemplateResponse("sp-sessions.html.jinja2", {
            "request": request,
            "sessions": sessions,
            "name": session_data.username,
            "signed_in": True,
            "csrf_field": csrf_field,
        })

async def sp_sessions_json(
        request: Request,
        session_data: datatypes.SessionData = Depends(app_session.deps_requires_session_gen()),
        order_by: str = 'default',
    ) -> datatypes.KeycloakSessionInfo:
    resp = await app_session.oauth_client.get(request.app.state.config.keycloak_accountapi_url+'sessions/devices',
        token=session_data.to_tokens(), headers={'Accept': 'application/json'})
    devices: list = resp.json()
    sessions: list = []

    # extract devices to sessions
    for device in devices:
        for session in device['sessions']:
            for k in ['os', 'osVersion', 'device']:
                session[k] = device.get(k)
            if session['device'] == 'Other':
                session['device'] = None
            sessions.append(session)

    # sort
    ret: list = []
    if order_by == 'default':
        current_index = next(i for i, e in enumerate(sessions) if e.get('current', False))
        ret.append(sessions.pop(current_index))
        ret.extend(
            sorted(sessions, key=lambda session: session['lastAccess'], reverse=True)
        )
    sessions = ret

    return [datatypes.KeycloakSessionItem.parse_obj(r) for r in sessions]

@router.post("/sp/sessions/logout", include_in_schema=True, status_code=204, responses={
        303: {"description": "Successful response (for end users)", "content": {"text/html": {}}},
        204: {"content": {"application/json": {}}}
    })
async def sp_sessions_logout(
        request: Request,
        session_data: datatypes.SessionData = Depends(app_session.deps_requires_session_gen()),
        id: str = Query(None, regex="^[A-Za-z0-9-_]+$"),
        current: bool = False,
        csrf_valid: bool = Depends(app_session.deps_requires_csrf_posttoken_gen())
    ) -> Response:
    result = await sp_sessions_logout_json(session_data=session_data, id=id, current=current)
    if result is not True:
        raise StarletteHTTPException(status_code=500, detail=str(result))
    # success
    if 'application/json' in request.headers['accept']:
        return Response(status_code=204)
    else:
        return RedirectResponse(request.url_for('sp_sessions'), status_code=303)
        # 303 to force POST to convert to GET

async def sp_sessions_logout_json(
        request: Request,
        session_data: datatypes.SessionData = Depends(app_session.deps_requires_session_gen()),
        id: str = Query(None, regex="^[A-Za-z0-9-_]+$"),
        current: bool = False
    ):
    resp = await app_session.oauth_client.delete(request.app.state.config.keycloak_accountapi_url+'sessions/'+(id if id else ''),
        token=session_data.to_tokens(), headers={'Accept': 'application/json'}, params={'current': current})
    result = resp.text
    if resp.status_code == 204:
        # success
        return True
    else:
        return result


@router.get("/sp/credentials/password", include_in_schema=True)
async def sp_password(
        request: Request,
        session_data: datatypes.SessionData = Depends(app_session.deps_requires_session_gen())
    ):
    resp = await app_session.oauth_client.get(request.app.state.config.keycloak_accountapi_url+'credentials/password',
        token=session_data.to_tokens(), headers={'Accept': 'application/json'})
    return resp.json()

@router.get("/sp/applications", include_in_schema=True)
async def sp_applications(
        session_data: datatypes.SessionData = Depends(app_session.deps_requires_session_gen())
    ):
    return {}


@router.get("/admin/", include_in_schema=False)
async def admin_landing(
        request: Request,
        session_data: datatypes.SessionData = Depends(app_session.deps_requires_admin_session_gen())
    ):
    return request.app.state.templates.TemplateResponse("index.html.jinja2", {"request": request})


@router.get("/admin/groups", include_in_schema=True)
async def admin_groups(
        request: Request,
        session_data: datatypes.SessionData = Depends(app_session.deps_requires_admin_session_gen())
    ):
    client: AsyncOAuth2Client
    async with app_session.get_service_account_oauth_client() as client:
        resp = await client.get(request.app.state.config.keycloak_adminapi_url+'groups',
            headers={'Accept': 'application/json'})
        return resp.json()

@router.get("/admin/roles/{role_name}/groups", include_in_schema=True)
async def admin_groups(
        request: Request,
        role_name: str = Path(..., regex="^[A-Za-z0-9-_]+$"),
        session_data: datatypes.SessionData = Depends(app_session.deps_requires_admin_session_gen())
    ):
    resp = await app_session.oauth_client.get(request.app.state.config.keycloak_adminapi_url+'roles/'+role_name+'/groups',
        token=session_data.to_tokens(), headers={'Accept': 'application/json'})
    return resp.json()

@router.get("/admin/users", include_in_schema=True)
async def admin_groups(
        request: Request,
        session_data: datatypes.SessionData = Depends(app_session.deps_requires_admin_session_gen())
    ):
    client: AsyncOAuth2Client
    async with request.app.state.app_session.get_service_account_oauth_client() as client:
        resp = await client.get(request.app.state.config.keycloak_adminapi_url+'users?briefRepresentation=true',
            headers={'Accept': 'application/json'})
        return resp.json()

@router.get("/register/", include_in_schema=False)
async def register_landing(request: Request):
    return request.app.state.templates.TemplateResponse("index.html.jinja2", {"request": request})


@router.get("/logout", include_in_schema=True)
async def logout(request: Request):
    access_token = await app_session.end_session(request)
    if not access_token:
        access_token = ''

    url = await app_session.oauth_client.get_metadata_value('end_session_endpoint')
    if not url:
        return RedirectResponse(request.url_for('index'))
    else:
        return RedirectResponse(url+"?"+urlencode({"post_logout_redirect_uri": request.url_for('index')}))


@router.get("/tos/", response_model=datatypes.TOSData, responses={
        200: {"content": {"text/html": {}}}
    })
async def tos(request: Request, templates: TemplateService = Depends()):
    if 'application/json' in request.headers['accept']:
        return datatypes.TOSData(html=
            templates.TemplateResponse("tos-content.html.jinja2").body
        )
    else:
        return templates.TemplateResponse("tos.html.jinja2")

app.include_router(router, dependencies=[Depends(app_session.deps_session_data)])

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="127.0.0.1", port=80, log_level="info", reload=True)
