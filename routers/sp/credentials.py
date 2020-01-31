from fastapi import Depends, APIRouter, Form, HTTPException
from fastapi.exceptions import RequestValidationError
from starlette.requests import Request
from starlette.responses import Response, RedirectResponse
import datatypes
from pydantic import ValidationError

from modauthlib import BITNPSessionFastAPIApp

router = APIRouter()

@router.get("/password", include_in_schema=True, response_model=datatypes.PasswordInfo)
async def sp_password(
        request: Request,
        csrf_field: tuple = Depends(BITNPSessionFastAPIApp.deps_get_csrf_field),
        session_data: datatypes.SessionData = Depends(BITNPSessionFastAPIApp.deps_requires_session),
    ):
    resp = await request.app.state.app_session.oauth_client.get(
        request.app.state.config.keycloak_accountapi_url+'credentials/password',
        token=session_data.to_tokens(),
        headers={'Accept': 'application/json'}
    )
    data = datatypes.PasswordInfo.parse_obj(resp.json())
    if 'application/json' in request.headers['accept']:
        return data
    else:
        updated = request.query_params.get('updated')
        incorrect = request.query_params.get('incorrect')
        if data.registered is False:
            # Redirect to assistance page since they don't have a current password
            # which accountapi requires
            return RedirectResponse(request.url_for('assistance_landing'))
        return request.app.state.templates.TemplateResponse("sp-password.html.jinja2", {
            "request": request,
            "name": session_data.username,
            "signed_in": True,
            "csrf_field": csrf_field,
            "updated": updated,
            "incorrect": incorrect,
        })
    return

@router.post("/password", include_in_schema=True, status_code=200, responses={
        303: {"description": "Successful response (for end users)", "content": {"text/html": {}}},
        200: {"content": {"application/json": {}}},
        400: {"description": "Failed response"},
    })
async def sp_password_update(
        request: Request,
        pwupdate: datatypes.PasswordUpdateRequest = None,
        currentPassword: str = Form(...),
        newPassword: str = Form(...),
        confirmation: str = Form(...),
        session_data: datatypes.SessionData = Depends(BITNPSessionFastAPIApp.deps_requires_session),
        csrf_valid: bool = Depends(BITNPSessionFastAPIApp.deps_requires_csrf_posttoken),
        csrf_field: tuple = Depends(BITNPSessionFastAPIApp.deps_get_csrf_field),
    ):
    if not pwupdate:
        try:
            pwupdate = datatypes.PasswordUpdateRequest(
                currentPassword=currentPassword,
                newPassword=newPassword,
                confirmation=confirmation,
            )
        except ValidationError as e:
            raise RequestValidationError(errors=e.raw_errors)


    try:
        result = await sp_password_update_json(request=request, pwupdate=pwupdate, session_data=session_data)
    except HTTPException as e:
        if ('application/json' not in request.headers['accept']):
            if e.detail.get('errorMessage') == 'invalidPasswordExistingMessage':
                incorrect = "旧密码错误，请重试，如忘记旧密码请点击下方重设密码。"
            else:
                incorrect = "请重新选择新密码，错误信息："+str(e.detail)
            return request.app.state.templates.TemplateResponse("sp-password.html.jinja2", {
                "request": request,
                "name": session_data.username,
                "signed_in": True,
                "csrf_field": csrf_field,
                "updated": False,
                "incorrect": incorrect,
            }, status_code=400)
        raise

    if 'application/json' in request.headers['accept']:
        return Response(status_code=200)
    else:
        return RedirectResponse(request.url_for('sp_password')+"?updated=1", status_code=303)

async def sp_password_update_json(
        request: Request,
        pwupdate: datatypes.PasswordUpdateRequest,
        session_data: datatypes.SessionData
    ):
    resp = await request.app.state.app_session.oauth_client.post(
        request.app.state.config.keycloak_accountapi_url+'credentials/password',
        token=session_data.to_tokens(),
        data=pwupdate.json(),
        headers={'Accept': 'application/json', 'Content-Type': 'application/json'}
    )
    if resp.status_code == 200:
        # success
        return True
    else:
        detail = resp.json()
        raise HTTPException(status_code=resp.status_code, detail=detail)
