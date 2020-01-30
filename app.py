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
from routers import sp

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
app.state.app_session = BITNPSessionFastAPIApp(
    app=app, oauth_client=app.state.oauth.bitnp, group_config=app.state.config.group_config,
    csrf_token=app.state.config.session_secret,
    cache_type=Cache.MEMORY
)
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
    session_data: datatypes.SessionData = Depends(BITNPSessionFastAPIApp.deps_session_data)):
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


@router.get("/admin/", include_in_schema=False)
async def admin_landing(
        request: Request,
        session_data: datatypes.SessionData = Depends(BITNPSessionFastAPIApp.deps_requires_admin_session)
    ):
    return request.app.state.templates.TemplateResponse("index.html.jinja2", {"request": request})


@router.get("/admin/groups", include_in_schema=True)
async def admin_groups(
        request: Request,
        session_data: datatypes.SessionData = Depends(BITNPSessionFastAPIApp.deps_requires_admin_session)
    ):
    client: AsyncOAuth2Client
    async with request.app.state.app_session.get_service_account_oauth_client() as client:
        resp = await client.get(request.app.state.config.keycloak_adminapi_url+'groups',
            headers={'Accept': 'application/json'})
        return resp.json()

@router.get("/admin/roles/{role_name}/groups", include_in_schema=True)
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

@router.get("/admin/users", include_in_schema=True)
async def admin_groups(
        request: Request,
        session_data: datatypes.SessionData = Depends(BITNPSessionFastAPIApp.deps_requires_admin_session)
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
    access_token = await request.app.state.app_session.end_session(request)
    if not access_token:
        access_token = ''

    url = await request.app.state.app_session.oauth_client.get_metadata_value('end_session_endpoint')
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

app.include_router(router, dependencies=[Depends(BITNPSessionFastAPIApp.deps_session_data)])
app.include_router(sp.landing.router, prefix='/sp', dependencies=[Depends(BITNPSessionFastAPIApp.deps_session_data)])
app.include_router(sp.profile.router, prefix='/sp/profile', dependencies=[Depends(BITNPSessionFastAPIApp.deps_session_data)])
app.include_router(sp.credentials.router, prefix='/sp/credentials', dependencies=[Depends(BITNPSessionFastAPIApp.deps_session_data)])
app.include_router(sp.sessions.router, prefix='/sp/sessions', dependencies=[Depends(BITNPSessionFastAPIApp.deps_session_data)])

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="127.0.0.1", port=80, log_level="info", reload=True)
