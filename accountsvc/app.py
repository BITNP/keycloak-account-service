from typing import Callable
import traceback
import sys

from fastapi import FastAPI, Depends
from fastapi.exception_handlers import http_exception_handler
from starlette.middleware.sessions import SessionMiddleware
from starlette.requests import Request
from starlette.responses import Response, PlainTextResponse, JSONResponse
from starlette.staticfiles import StaticFiles
from starlette.templating import Jinja2Templates
from starlette.exceptions import HTTPException as StarletteHTTPException
from authlib.integrations.starlette_client import OAuth
from authlib.integrations.httpx_client import OAuthError
from aiocache import Cache

from . import datatypes
from .config import MIN_PYTHON, APP_TITLE, APP_VERSION, CONFIG
from .utils import local_timestring
from .phpcas_adaptor import FakePHPCASAdaptor, MySQLPHPCASAdaptor # pylint: disable=unused-import
from .auth import BITNPOAuthRemoteApp, BITNPSessions
from .modauthlib import deps_requires_session, deps_requires_admin_session
from .routers import sp, admin
from .routers import publicsvc, assistance, invitation, migrate_phpcas


if sys.version_info < MIN_PYTHON:
    sys.exit("At least Python {}.{} or later is required.\n".format(*MIN_PYTHON))

app: FastAPI = FastAPI(
    title=APP_TITLE,
    version=APP_VERSION,
)

app.state.config = CONFIG

app.state.oauth = OAuth()
app.state.oauth.framework_client_cls = BITNPOAuthRemoteApp
app.state.oauth.register(
    name='bitnp',
    client_id=app.state.config.client_id,
    client_secret=app.state.config.client_secret,
    server_metadata_url=app.state.config.server_metadata_url,
    client_kwargs={
        'scope': 'openid iam-admin'
    },
)

app.add_middleware(SessionMiddleware, secret_key=app.state.config.session_secret)
app.state.app_session = BITNPSessions(
    app=app, oauth_client=app.state.oauth.bitnp, group_config=app.state.config.group_config,
    csrf_token=app.state.config.session_secret,
    cache_type=Cache.MEMORY
)
app.mount("/static", StaticFiles(directory="static"), name="static")

app.state.templates = Jinja2Templates(directory="templates")
app.state.templates.env.globals["app_title"] = app.title
app.state.templates.env.filters["local_timestring"] = (
    lambda dt, format='%Y-%m-%d %H:%M': local_timestring(CONFIG.local_timezone, dt, format)
)

@app.on_event("startup")
async def init_phpcas_adaptor() -> None:
    app.state.phpcas_adaptor = await MySQLPHPCASAdaptor.create(app.state.config)

@app.exception_handler(StarletteHTTPException)
async def http_exception_accept_handler(request: Request, exc: StarletteHTTPException) -> Response:
    if exc.status_code > 499:
        # Only log server error
        traceback.print_exc()
    if request.state.response_type.is_json():
        return await http_exception_handler(request, exc)
    else:
        return PlainTextResponse(f"{exc.status_code} {exc.detail}", status_code=exc.status_code)

@app.exception_handler(OAuthError)
async def oauth_exception_handler(request: Request, exc: OAuthError) -> Response:
    traceback.print_exc()
    if request.state.response_type.is_json():
        return JSONResponse(
            {"error": exc.error, "detail": exc.description}, status_code=403
        )
    else:
        return request.app.state.templates.TemplateResponse("oauth-error.html.jinja2", {
            "request": request,
            "error": f"{exc.error}: {exc.description}",
            "retry_url": BITNPOAuthRemoteApp.get_cleaned_redirect_url_str(request.url),
        }, status_code=500)

@app.middleware("http")
async def add_response_type_hint(request: Request, call_next: Callable) -> Response:
    request.state.response_type = datatypes.BITNPResponseType.from_request(request)
    return await call_next(request)


app.include_router(publicsvc.router)
app.include_router(assistance.router)
app.include_router(invitation.router)
app.include_router(migrate_phpcas.router)
app.include_router(sp.landing.router, prefix='/sp', dependencies=[Depends(deps_requires_session)])
app.include_router(sp.profile.router, prefix='/sp/profile', dependencies=[Depends(deps_requires_session)])
app.include_router(sp.credentials.router, prefix='/sp/credentials', dependencies=[Depends(deps_requires_session)])
app.include_router(sp.sessions.router, prefix='/sp/sessions', dependencies=[Depends(deps_requires_session)])
app.include_router(admin.landing.router, prefix='/admin', dependencies=[Depends(deps_requires_admin_session)])
app.include_router(admin.groups.router, prefix='/admin', dependencies=[Depends(deps_requires_admin_session)])
app.include_router(admin.users.router, prefix='/admin', dependencies=[Depends(deps_requires_admin_session)])
