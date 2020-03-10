from typing import Union, Dict, List
from pydantic import ValidationError

from fastapi import Depends, APIRouter, Form, HTTPException
from fastapi.exceptions import RequestValidationError
from starlette.requests import Request
from starlette.responses import Response, RedirectResponse

from accountsvc.datatypes import PasswordInfo, PasswordUpdateRequest, CredentialType
from accountsvc.modauthlib import (SessionData, deps_requires_session,
                                   deps_get_csrf_field, deps_requires_csrf_posttoken)
from accountsvc.utils import request_accountapi_json_expect_200

MFA_ADD_REQ_ACTIONS: Dict[str, str] = {
    '': '',
}

router = APIRouter()

@router.get("/password", include_in_schema=True, response_model=PasswordInfo)
async def sp_password(
        request: Request,
        csrf_field: tuple = Depends(deps_get_csrf_field),
        session_data: SessionData = Depends(deps_requires_session),
    ) -> Union[PasswordInfo, Response]:
    resp = await request.app.state.app_session.oauth_client.get(
        request.app.state.config.keycloak_accountapi_url+'credentials/password',
        token=session_data.to_tokens(),
        headers={'Accept': 'application/json'}
    )
    data = PasswordInfo.parse_obj(resp.json())
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
        # pwupdate: Optional[PasswordUpdateRequest] = Body(None, embed=True),
        currentPassword: str = Form(...),
        newPassword: str = Form(...),
        confirmation: str = Form(...),
        session_data: SessionData = Depends(deps_requires_session),
        csrf_valid: bool = Depends(deps_requires_csrf_posttoken),
        csrf_field: tuple = Depends(deps_get_csrf_field),
    ) -> Response:
    #if not pwupdate:
    try:
        pwupdate = PasswordUpdateRequest(
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
        pwupdate: PasswordUpdateRequest,
        session_data: SessionData
    ) -> bool:
    await request_accountapi_json_expect_200(request=request, session_data=session_data,
                                             data=pwupdate.json(), uri='credentials/password')
    return True

@router.get("/mfa/", include_in_schema=True, response_model=List[CredentialType])
async def sp_mfa_list(
        request: Request,
        csrf_field: tuple = Depends(deps_get_csrf_field),
        session_data: SessionData = Depends(deps_requires_session),
    ) -> Union[List[CredentialType], Response]:
    creds: List[CredentialType] = await sp_mfa_list_json(request=request, session_data=session_data)
    if request.state.response_type.is_json():
        return creds
    else:
        updated = request.query_params.get('updated')
        if request.query_params.get('kc_action_status') == 'success':
            updated = True
        return request.app.state.templates.TemplateResponse("sp-mfa.html.jinja2", {
            "request": request,
            "name": session_data.username,
            "signed_in": True,
            "csrf_field": csrf_field,
            "updated": updated,
            "creds": creds,
        })

async def sp_mfa_list_json(
        request: Request,
        session_data: SessionData,
    ) -> List[CredentialType]:
    resp = await request.app.state.app_session.oauth_client.get(
        request.app.state.config.keycloak_accountapi_url+'credentials',
        token=session_data.to_tokens(),
        headers={'Accept': 'application/json'},
    )
    return list(CredentialType.parse_obj(c) for c in resp.json())

@router.post("/mfa/remove", include_in_schema=True, status_code=204, responses={
        303: {"description": "Successful response (for end users)", "content": {"text/html": {}}},
        204: {"content": {"application/json": {}}},
        400: {"description": "Failed response"},
    })
async def sp_mfa_remove(
        request: Request,
        credentialId: str = Form(...),
        session_data: SessionData = Depends(deps_requires_session),
        csrf_valid: bool = Depends(deps_requires_csrf_posttoken),
    ) -> Response:
    await sp_mfa_remove_json(request=request, credentialId=credentialId, session_data=session_data)

    if request.state.response_type.is_json():
        return Response(status_code=204)
    else:
        return RedirectResponse(request.url_for('sp_mfa_list')+"?updated=1", status_code=303)

async def sp_mfa_remove_json(
        request: Request,
        credentialId: str,
        session_data: SessionData,
    ) -> None:
    resp = await request.app.state.app_session.oauth_client.delete(
        request.app.state.config.keycloak_accountapi_url+'credentials/'+credentialId,
        token=session_data.to_tokens(),
        headers={'Accept': 'application/json'},
    )
    if resp.status_code != 204:
        raise HTTPException(resp.status_code, detail=resp.json())