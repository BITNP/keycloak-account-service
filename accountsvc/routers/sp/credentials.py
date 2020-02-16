from typing import Union, Optional
from pydantic import ValidationError

from fastapi import Depends, APIRouter, Form, HTTPException
from fastapi.exceptions import RequestValidationError
from starlette.requests import Request
from starlette.responses import Response, RedirectResponse

from accountsvc import datatypes
from accountsvc.modauthlib import (SessionData, deps_requires_session,
                                   deps_get_csrf_field, deps_requires_csrf_posttoken)

router: APIRouter = APIRouter()

@router.get("/password", include_in_schema=True, response_model=datatypes.PasswordInfo)
async def sp_password(
        request: Request,
        csrf_field: tuple = Depends(deps_get_csrf_field),
        session_data: SessionData = Depends(deps_requires_session),
    ) -> Union[datatypes.PasswordInfo, Response]:
    resp = await request.app.state.app_session.oauth_client.get(
        request.app.state.config.keycloak_accountapi_url+'credentials/password',
        token=session_data.to_tokens(),
        headers={'Accept': 'application/json'}
    )
    data = datatypes.PasswordInfo.parse_obj(resp.json())
    if request.state.response_type.is_json():
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

@router.post("/password", include_in_schema=True, status_code=200, responses={
        303: {"description": "Successful response (for end users)", "content": {"text/html": {}}},
        200: {"content": {"application/json": {}}},
        400: {"description": "Failed response"},
    })
async def sp_password_update(
        request: Request,
        pwupdate: Optional[datatypes.PasswordUpdateRequest] = None,
        currentPassword: str = Form(...),
        newPassword: str = Form(...),
        confirmation: str = Form(...),
        session_data: SessionData = Depends(deps_requires_session),
        csrf_valid: bool = Depends(deps_requires_csrf_posttoken),
        csrf_field: tuple = Depends(deps_get_csrf_field),
    ) -> Response:
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
        _ = await sp_password_update_json(request=request, pwupdate=pwupdate, session_data=session_data)
    except HTTPException as e:
        if not request.state.response_type.is_json():
            if e.detail.find('invalidPasswordExistingMessage') > 0:
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

    if request.state.response_type.is_json():
        return Response(status_code=200)
    else:
        return RedirectResponse(request.url_for('sp_password')+"?updated=1", status_code=303)

async def sp_password_update_json(
        request: Request,
        pwupdate: datatypes.PasswordUpdateRequest,
        session_data: SessionData
    ) -> bool:
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
        raise HTTPException(status_code=resp.status_code, detail=resp.body)
