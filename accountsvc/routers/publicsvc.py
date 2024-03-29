from typing import Union, Optional
from urllib.parse import urlencode
from fastapi import Depends, APIRouter
from starlette.requests import Request
from starlette.responses import RedirectResponse, Response, FileResponse

from accountsvc import datatypes
from accountsvc.modauthlib import (SessionData, deps_get_session)
from accountsvc.utils import TemplateService

router: APIRouter = APIRouter()


@router.get("/", include_in_schema=False)
async def index(request: Request,
                session_data: SessionData = Depends(deps_get_session)) -> Response:
    tdata: dict = {
        "request": request,
        "name": None,
        "is_admin": False,
        "signed_in": False
    }
    if session_data:
        tdata['name'] = session_data.username
        tdata['is_admin'] = session_data.is_admin()
        tdata['signed_in'] = True
    return request.app.state.templates.TemplateResponse("index.html.jinja2", tdata)

@router.get("/favicon.ico", include_in_schema=False)
async def favicon(request: Request) -> Response:
    return FileResponse('static/favicon.ico')

@router.get("/tos", response_model=datatypes.TOSData, responses={
        200: {"content": {"text/html": {}}}
    })
async def tos(request: Request, templates: TemplateService = Depends()) -> Union[Response, datatypes.TOSData]:
    if request.state.response_type.is_json():
        return datatypes.TOSData(html=templates.TemplateResponse("tos-content.html.jinja2").body)
    else:
        return templates.TemplateResponse("tos.html.jinja2")

@router.get("/register", include_in_schema=False)
async def register_landing(
        request: Request,
        redirect_uri: Optional[str] = None,
    ) -> Response:
    if redirect_uri:
        if not redirect_uri.startswith('/'):
            redirect_uri = None
        else:
            base_url = request.url.replace(path="", query="")
            redirect_uri = str(base_url) + redirect_uri
    if not redirect_uri:
        redirect_uri = request.url_for('sp_landing')

    return await request.app.state.app_session.oauth_client.register_redirect(request, redirect_uri)

@router.get("/logout", include_in_schema=False)
async def logout(request: Request) -> Response:
    access_token = await request.app.state.app_session.end_session(request)
    if not access_token:
        access_token = ''

    url = await request.app.state.app_session.oauth_client.get_metadata_value('end_session_endpoint')
    if not url:
        return RedirectResponse(request.url_for('index'))
    else:
        redirect_uri = request.url_for('index')
        input_redirect_uri: str = request.query_params.get("redirect_uri", "")
        if input_redirect_uri.startswith("/"):
            base_url = request.url.replace(path="", query="")
            redirect_uri = str(base_url) + input_redirect_uri
        return RedirectResponse(url+"?"+urlencode({"post_logout_redirect_uri": redirect_uri}))


@router.get("/login-action/{action}/", include_in_schema=False)
async def kc_login_action(
        request: Request,
        action: str,
        redirect_uri: Optional[str] = None,
    ) -> Response:
    if redirect_uri:
        if not redirect_uri.startswith('/'):
            redirect_uri = None
        else:
            base_url = request.url.replace(path="", query="")
            redirect_uri = str(base_url) + redirect_uri
    if not redirect_uri:
        redirect_uri = request.url_for('sp_landing')
    return await request.app.state.app_session.oauth_client.authorize_redirect(request, redirect_uri, kc_action=action)