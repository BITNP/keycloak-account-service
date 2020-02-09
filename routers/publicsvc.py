from fastapi import Depends, APIRouter
from starlette.requests import Request
from starlette.responses import RedirectResponse

import datatypes
from modauthlib import BITNPSessionFastAPIApp
from utils import TemplateService
from urllib.parse import urlencode

router = APIRouter()


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
        tdata['name'] = session_data.username
        tdata['is_admin'] = session_data.is_admin()
        tdata['signed_in'] = True
    return request.app.state.templates.TemplateResponse("index.html.jinja2", tdata)

@router.get("/tos", response_model=datatypes.TOSData, responses={
        200: {"content": {"text/html": {}}}
    })
async def tos(request: Request, templates: TemplateService = Depends()):
    if request.state.response_type.is_json():
        return datatypes.TOSData(html=
            templates.TemplateResponse("tos-content.html.jinja2").body
        )
    else:
        return templates.TemplateResponse("tos.html.jinja2")

@router.get("/register", include_in_schema=False)
async def register_landing(
        request: Request,
        redirect_uri: str = None,
    ):
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
async def logout(request: Request):
    access_token = await request.app.state.app_session.end_session(request)
    if not access_token:
        access_token = ''

    url = await request.app.state.app_session.oauth_client.get_metadata_value('end_session_endpoint')
    if not url:
        return RedirectResponse(request.url_for('index'))
    else:
        redirect_uri = request.url_for('index')
        input_redirect_uri : str = request.query_params.get("redirect_uri", "")
        if input_redirect_uri.startswith("/"):
            base_url = request.url.replace(path="", query="")
            redirect_uri = str(base_url) + input_redirect_uri
        return RedirectResponse(url+"?"+urlencode({"post_logout_redirect_uri": redirect_uri}))