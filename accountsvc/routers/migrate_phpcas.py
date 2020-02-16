from fastapi import Depends, APIRouter, Form, HTTPException
from starlette.requests import Request
from starlette.responses import Response
from pydantic import ValidationError
import re
from typing import Tuple, Optional

from accountsvc import datatypes
from accountsvc.phpcas_adaptor import PHPCASAdaptor, PHPCASUserInfo
from accountsvc.modauthlib import BITNPSessions, deps_get_csrf_field, deps_requires_csrf_posttoken
from accountsvc.utils import TemplateService

router = APIRouter()
EMAIL_SESSION_NAME = 'mpc_email'

@router.get("/migrate-phpcas/", include_in_schema=False)
async def phpcas_migrate_landing(
        request: Request,
        csrf_field: tuple = Depends(deps_get_csrf_field),
    ) -> Response:
    return request.app.state.templates.TemplateResponse("migrate-phpcas-landing.html.jinja2", {
        "request": request,
        "csrf_field": csrf_field,
    })


@router.post("/migrate-phpcas/", include_in_schema=False)
async def phpcas_migrate_process(
        request: Request,
        email: str = Form(...),
        password: Optional[str] = Form(None),
        newPassword: Optional[str] = Form(None),
        confirmation: Optional[str] = Form(None),
        name: str = Form(...),
        csrf_field: tuple = Depends(deps_get_csrf_field),
        csrf_valid: bool = Depends(deps_requires_csrf_posttoken),
    ) -> Response:
    session_email = request.session.get(EMAIL_SESSION_NAME)
    user: Optional[PHPCASUserInfo]
    if session_email and password is None and (newPassword and confirmation):
        # we assume that their previous password has been validated
        # and they are authorized to set up a new password
        print("phpcas-migrate: Restoring session for "+session_email)
        user, resp = await _phpcas_migrate_validate_cred(
            request=request,
            email=session_email,
            password=None,
            name=name,
            csrf_field=csrf_field,
        )

        if not user:
            assert resp is not None
            return resp

        user_uri, resp = await _phpcas_migrate_create_user(
            user_id=user.id,
            request=request,
            email=user.email,
            password=newPassword,
            confirmation=confirmation,
            name=name,
            username=user.name,
            csrf_field=csrf_field,
        )

        if resp:
            return resp

        del request.session[EMAIL_SESSION_NAME]
    else:
        if not password:
            return request.app.state.templates.TemplateResponse("migrate-phpcas-landing.html.jinja2", {
                    "request": request,
                    "csrf_field": csrf_field,
                    "input_name": name,
                    "input_email": email,
                    "incorrect": "请输入密码。",
                })

        user, resp = await _phpcas_migrate_validate_cred(
            request=request,
            email=email,
            password=password,
            name=name,
            csrf_field=csrf_field,
        )

        if not user:
            assert resp is not None
            return resp

        user_uri, resp = await _phpcas_migrate_create_user(
            user_id=user.id,
            request=request,
            email=user.email,
            password=password,
            confirmation=password,
            name=name,
            username=user.name,
            csrf_field=csrf_field,
        )

        if not user_uri:
            assert resp is not None
            return resp

    # iam-master add
    if user_uri:
        IAM_MASTER_GROUP_ID = request.app.state.config.iam_master_group_id
        if user.admin is True and IAM_MASTER_GROUP_ID:
            try:
                print("phpcas-migrate: Upgrading {} to iam-master".format(user.name))
                async with request.app.state.app_session.get_service_account_oauth_client() as client:
                    resp_iam = await client.put(
                        user_uri+'/groups/'+IAM_MASTER_GROUP_ID,
                        headers={'Accept': 'application/json'}
                    )
                    if resp_iam.status_code != 204:
                        raise HTTPException(status_code=resp_iam.status_code, detail=resp_iam.body)
            except Exception as e:
                print("phpcas-migrate: Failed upgrading to iam-master {}".format(e))

    return request.app.state.templates.TemplateResponse("migrate-phpcas-completed.html.jinja2", {
        "request": request,
        "username": user.name,
    })


async def _phpcas_migrate_create_user(request: Request,
        user_id: int,
        email: str,
        password: str,
        confirmation: str,
        name: str,
        username: str,
        csrf_field: tuple,
    ) -> Tuple[Optional[str], Optional[Response]]:
    """
    temp auth - use (signed) session
    # email - use as is
    # password - if not in compliance, we need to ask for a new password
    # name - use the latest input
    # username - if not in compliance, block migration and refer to asssitance; use as is (show this to user sometime)
    """
    try:
        new_user = datatypes.UserCreationInfo(
            email=email,
            emailVerified=False,
            name=name,
            username=username,
            newPassword=password,
            confirmation=confirmation,
            attributes={'phpCAS_id': [user_id]},
        )
    except ValidationError as e:
        incorrect = "迁移失败，错误信息："+(
            ', '.join(['.'.join(field_error['loc'])+':'+field_error['msg'] for field_error in e.errors()])
        )

        for field_error in e.errors():
            if field_error['loc'][0] == 'username':
                incorrect= "你创建旧版账户时使用的用户名包含了中文，无法自动迁移，请访问此网址提交用户名修改请求，由人工处理： "+request.app.state.config.assistance_url
                break

            if field_error['loc'][0] == 'newPassword':
                # direct to setup new password
                request.session[EMAIL_SESSION_NAME] = email
                return None, request.app.state.templates.TemplateResponse("migrate-phpcas-password.html.jinja2", {
                    "request": request,
                    "csrf_field": csrf_field,
                    "input_name": name,
                    "input_email": email,
                    "incorrect": incorrect,
                })

        return None, request.app.state.templates.TemplateResponse("migrate-phpcas-landing.html.jinja2", {
                    "request": request,
                    "csrf_field": csrf_field,
                    "input_name": name,
                    "input_email": email,
                    "incorrect": incorrect,
                })

    # when creating user, make sure we don't create duplicates
    async with request.app.state.app_session.get_service_account_oauth_client() as client:
        resp = await client.post(request.app.state.config.keycloak_adminapi_url+'users',
            data=new_user.request_json(),
            headers={'Accept': 'application/json', 'Content-Type': 'application/json'}
        )
        if resp.status_code == 201:
            return resp.headers.get('location', ''), None
        else:
            incorrect = "迁移失败，如有疑问请联系管理员。错误信息："+resp.text
            print("phpcas-migrate: Error creating {}: {}".format(new_user.username, resp.text))
            try:
                resp_json = resp.json()
                if resp_json['errorMessage'].startswith('User exists with same '):
                    incorrect = "你的账户已被迁移，不能再迁移。如有疑问请联系管理员。"
            except Exception:
                pass

            return None, request.app.state.templates.TemplateResponse("migrate-phpcas-landing.html.jinja2", {
                "request": request,
                "csrf_field": csrf_field,
                "input_name": name,
                "input_email": email,
                "incorrect": incorrect,
            })


async def _phpcas_migrate_validate_cred(request: Request,
        email: str,
        password: Optional[str],
        name: str,
        csrf_field: tuple,
    ) -> Tuple[Optional[PHPCASUserInfo], Optional[Response]]:
    phpcas_adaptor: PHPCASAdaptor = request.app.state.phpcas_adaptor
    user = await phpcas_adaptor.get_user_by_email(email)
    if not user or (password and not user.check_password(password)):
        return None, request.app.state.templates.TemplateResponse("migrate-phpcas-landing.html.jinja2", {
            "request": request,
            "csrf_field": csrf_field,
            "input_name": name,
            "input_email": email,
            "incorrect": "你的邮箱与密码不正确，请确保使用正确的旧版网协通行证密码。",
        })

    if not user.enabled:
        # helpdesk
        return None, request.app.state.templates.TemplateResponse("migrate-phpcas-landing.html.jinja2", {
            "request": request,
            "csrf_field": csrf_field,
            "input_name": name,
            "input_email": email,
            "incorrect": "你的账户被禁用，无法迁移。请联系 webmaster@bitnp.net 以启用账户。",
        })

    return user, None


@router.get("/migrate-phpcas/user-lookup", include_in_schema=False)
async def phpcas_migrate_user_lookup(request: Request, username: str, email: Optional[str]=None) -> Response:
    """
    This is an internal API; include_in_schema=False

    Disabled users should also be required to migrate (and they will see a helpdesk option eventually).

    We won't check to see if an account exists in Keycloak here (so that they may have done migration)
    because this endpoint is usually used by Keycloak during register and pwreset, after no user is hit.

    Additional check should be done during the actual migration (after verifying password) to see
    if Keycloak account exists or not.
    """
    username = username.strip()
    email = email.strip() if email else None

    if email is None and username.find('@') != -1:
        # Keycloak's pwreset will send username or email as username, regardless of actaul value
        email = username

    phpcas_adaptor: PHPCASAdaptor = request.app.state.phpcas_adaptor
    user: Optional[PHPCASUserInfo] = None

    if email:
        user = await phpcas_adaptor.get_user_by_email(email)

    if not user and username:
        user = await phpcas_adaptor.get_user_by_username(username)

    if user:
        return Response(content="yes", status_code=200)
    else:
        return Response(status_code=204)
