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
from routers import sp, admin
from routers import publicsvc, assistance, invitation, migrate_phpcas

from authlib.integrations.starlette_client import OAuth
from authlib.integrations.httpx_client import OAuthError, AsyncOAuth2Client
from modauthlib import BITNPOAuthRemoteApp, BITNPSessionFastAPIApp
from aiocache import Cache

from urllib.parse import urlencode
from utils import local_timestring
import json

import sys
MIN_PYTHON = (3, 5)
if sys.version_info < MIN_PYTHON:
    sys.exit("At least Python {}.{} or later is required.\n".format(*MIN_PYTHON))

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
        'scope': 'openid iam-admin'
    },
)

app.add_middleware(SessionMiddleware, secret_key=app.state.config.session_secret)
app.state.app_session = BITNPSessionFastAPIApp(
    app=app, oauth_client=app.state.oauth.bitnp, group_config=app.state.config.group_config,
    csrf_token=app.state.config.session_secret,
    cache_type=Cache.MEMORY
)
app.mount("/static", StaticFiles(directory="static"), name="static")

app.state.templates = Jinja2Templates(directory="templates")
app.state.templates.env.globals["app_title"] = app.title
app.state.templates.env.filters["local_timestring"] = (
    lambda dt, format='%Y-%m-%d %H:%M': local_timestring(app.state.config.local_timezone, dt, format)
)

@app.exception_handler(StarletteHTTPException)
async def http_exception_accept_handler(request, exc):
    if request.state.response_type.is_json():
        return await http_exception_handler(request, exc)
    else:
        return PlainTextResponse(f"{exc.status_code} {exc.detail}", status_code=exc.status_code)

@app.exception_handler(OAuthError)
async def oauth_exception_handler(request, exc):
    if request.state.response_type.is_json():
        return JSONResponse(
            {"detail": exc.description}, status_code=500
        )
    else:
        return PlainTextResponse(f"{exc.error}: {exc.description}", status_code=500)

@app.middleware("http")
async def add_response_type_hint(request: Request, call_next):
    request.state.response_type = datatypes.BITNPResponseType.from_request(request)
    return await call_next(request)


app.include_router(router)
app.include_router(publicsvc.router)
app.include_router(assistance.router)
app.include_router(invitation.router)
app.include_router(migrate_phpcas.router)
app.include_router(sp.landing.router, prefix='/sp', dependencies=[Depends(BITNPSessionFastAPIApp.deps_session_data)])
app.include_router(sp.profile.router, prefix='/sp/profile', dependencies=[Depends(BITNPSessionFastAPIApp.deps_session_data)])
app.include_router(sp.credentials.router, prefix='/sp/credentials', dependencies=[Depends(BITNPSessionFastAPIApp.deps_session_data)])
app.include_router(sp.sessions.router, prefix='/sp/sessions', dependencies=[Depends(BITNPSessionFastAPIApp.deps_session_data)])
app.include_router(admin.groups.router, prefix='/admin', dependencies=[Depends(BITNPSessionFastAPIApp.deps_requires_admin_session)])
app.include_router(admin.users.router, prefix='/admin', dependencies=[Depends(BITNPSessionFastAPIApp.deps_requires_admin_session)])


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="127.0.0.1", port=80, log_level="info", reload=True)
