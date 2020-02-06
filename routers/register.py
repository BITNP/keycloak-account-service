from fastapi import Depends, APIRouter, Form, HTTPException
from fastapi.exceptions import RequestValidationError
from pydantic import ValidationError
from starlette.requests import Request
from starlette.responses import RedirectResponse

import datatypes
from modauthlib import BITNPSessionFastAPIApp
from utils import TemplateService
from .invitation import validate_token

router = APIRouter()

@router.get("/register/", include_in_schema=False)
async def register_landing(
        request: Request,
        i: str = None,
        csrf_field: tuple = Depends(BITNPSessionFastAPIApp.deps_get_csrf_field),
    ):
    incorrect = None
    i_group = None
    if i:
        try:
            i_group = await validate_token(request, i)
        except Exception as e:
            print(e)
            incorrect = "你的邀请链接不正确，如继续注册，账户将需要管理层人工激活。"

    return request.app.state.templates.TemplateResponse("register-landing.html.jinja2", {
        "request": request,
        "csrf_field": csrf_field,
        "i_name": i_group.name if i_group else None,
        "i": i,
        "incorrect": incorrect,
    })

@router.post("/register/", include_in_schema=False)
async def register_process(
        request: Request,
        username: str = Form(...),
        name: str = Form(..., max_length=64), # soft control
        email: str = Form(..., max_length=64),
        newPassword: str = Form(...),
        confirmation: str = Form(...),
        i: str = None,
        csrf_valid: bool = Depends(BITNPSessionFastAPIApp.deps_requires_csrf_posttoken),
        csrf_field: tuple = Depends(BITNPSessionFastAPIApp.deps_get_csrf_field),
    ):
    incorrect = None
    i_group = None

    if i:
        try:
            i_group = await validate_token(request, i)
        except Exception as e:
            pass

    try:
        user_url = await register_create_json(
            request=request,
            username=username,
            name=name,
            email=email,
            newPassword=newPassword,
            confirmation=confirmation,
        )
        # successful
        if i_group:
            async with request.app.state.app_session.get_service_account_oauth_client() as client:
                resp = await client.put(
                    user_url+'/groups/'+quote(i_group.id),
                    headers={'Accept': 'application/json'
                })
                if resp.status_code != 204:
                    if request.state.response_type.is_json():
                        raise HTTPException(status_code=resp.status_code, detail=resp.json())
                    # user created but not able to join
                    # Needs to log in somehow
                    return RedirectResponse(request.url_for('invitation_landing', token=i), status_code=303)

        # log in somehow
        return RedirectResponse(request.url_for('sp_landing'), status_code=303)

    except (HTTPException, RequestValidationError, ) as e:
        if not request.state.response_type.is_json():
            if isinstance(e, HTTPException):
                incorrect = "注册失败，如有疑问请联系管理员。错误信息："+str(
                    e.detail["errorMessage"] if e.detail.get and e.detail.get("errorMessage") else e.detail
                )
                # Until https://github.com/keycloak/keycloak/commit/221aad98770647ee8059b000ec4b0c32da899ba2#diff-2d5026806b9f86138813c99521f40597 is released,
                # PasswordPolicyNotMetException will always show "Could not create user"
                # You should be able to see full error message in Keycloak docker logs
            if isinstance(e, RequestValidationError):
                incorrect = "注册失败，错误信息："+(
                    ', '.join(['.'.join(field_error['loc'])+':'+field_error['msg'] for field_error in e.errors()])
                )
            return request.app.state.templates.TemplateResponse("register-landing.html.jinja2", {
                "request": request,
                "csrf_field": csrf_field,
                "i_name": i_group.name if i_group else None,
                "i": i,
                "incorrect": incorrect,
                "input_email": email,
                "input_username": username,
                "input_name": name,
            }, status_code=422)
        raise

    return request.app.state.templates.TemplateResponse("register-landing.html.jinja2", {
        "request": request,
        "csrf_field": csrf_field,
        "i_name": i_group.name if i_group else None,
        "i": i,
        "incorrect": incorrect,
        "input_email": email,
        "input_username": username,
        "input_name": name,
    })

async def register_create_json(
        request: Request,
        username: str,
        name: str,
        email: str,
        newPassword: str,
        confirmation: str,
    ) -> str:
    """
    @return URL of user resource
    """
    try:
        user_data = datatypes.UserCreationInfo(
            email=email,
            emailVerified=False,
            name=name,
            username=username,
            newPassword=newPassword,
            confirmation=confirmation,
        )
    except ValidationError as e:
        raise RequestValidationError(errors=e.raw_errors)

    async with request.app.state.app_session.get_service_account_oauth_client() as client:
        resp = await client.post(request.app.state.config.keycloak_adminapi_url+'users',
            data=user_data.request_json(),
            headers={'Accept': 'application/json', 'Content-Type': 'application/json'}
        )
        if resp.status_code == 201:
            return resp.headers.get('location')
        else:
            print(resp.text)
            raise HTTPException(status_code=resp.status_code, detail=resp.json())
