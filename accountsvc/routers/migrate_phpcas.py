from typing import Tuple, Optional, Union
from fastapi import Depends, APIRouter, Form, HTTPException
from starlette.requests import Request
from starlette.responses import Response
from pydantic import ValidationError

from accountsvc import datatypes
from accountsvc.phpcas_adaptor import PHPCASAdaptor, PHPCASUserInfo
from accountsvc.modauthlib import (deps_get_csrf_field, deps_requires_csrf_posttoken,
                                   SessionData, deps_get_session, deps_requires_master_session)

router: APIRouter = APIRouter()
EMAIL_SESSION_NAME = 'mpc_email'

@router.get("/migrate-phpcas/", include_in_schema=False)
async def phpcas_migrate_landing(
        request: Request,
        csrf_field: tuple = Depends(deps_get_csrf_field),
        session_data: SessionData = Depends(deps_get_session),
    ) -> Response:
    return request.app.state.templates.TemplateResponse("migrate-phpcas-landing.html.jinja2", {
        "request": request,
        "csrf_field": csrf_field,
        "name": session_data.username if session_data else None,
        "is_admin": session_data.is_admin() if session_data else None,
        "is_master": session_data.is_master() if session_data else None,
        "signed_in": bool(session_data),
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
        session_data: SessionData = Depends(deps_get_session),
    ) -> Response:
    session_email = request.session.get(EMAIL_SESSION_NAME)
    user: Union[PHPCASUserInfo, Response]
    if session_email and session_email == email and password is None and (newPassword and confirmation):
        # we assume that their previous password has been validated
        # and they are authorized to set up a new password
        # so we allow password to be None which will bypass password check
        print("phpcas-migrate: Restoring session for "+session_email)
    else:
        if not password:
            return request.app.state.templates.TemplateResponse(
                "migrate-phpcas-landing.html.jinja2",
                {
                    "request": request,
                    "csrf_field": csrf_field,
                    "input_name": name,
                    "input_email": email,
                    "incorrect": "请输入密码。",
                },
            )

        # reuse the same password for the new account
        newPassword = password
        confirmation = password

    user = await _phpcas_migrate_validate_cred(
        request=request,
        email=email,
        password=password,
        name=name,
        csrf_field=csrf_field,
    )

    if not isinstance(user, PHPCASUserInfo):
        # we assume it's a Response and should stop execution now
        return user

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

    if not user_uri:
        if resp:
            return resp
        else:
            raise HTTPException(status_code=500, detail="Cannot create the new user due to unkonwn reason")

    if session_email == email:
        del request.session[EMAIL_SESSION_NAME]

    # iam-master add
    if user_uri:
        if user.admin is True and request.app.state.config.iam_master_group_id:
            try:
                print("phpcas-migrate: Upgrading {} to iam-master".format(user.name))
                async with request.app.state.app_session.get_service_account_oauth_client() as client:
                    resp_iam = await client.put(
                        user_uri+'/groups/'+request.app.state.config.iam_master_group_id,
                        headers={'Accept': 'application/json'}
                    )
                    if resp_iam.status_code != 204:
                        raise HTTPException(status_code=resp_iam.status_code, detail=resp_iam.text)
            except Exception as e: # pylint: disable=broad-except
                print("phpcas-migrate: Failed upgrading to iam-master {}".format(e))

    return request.app.state.templates.TemplateResponse("migrate-phpcas-completed.html.jinja2", {
        "request": request,
        "username": user.name,
        "user_uri": user_uri,
        "name": session_data.username if session_data else None,
        "is_admin": session_data.is_admin() if session_data else None,
        "is_master": session_data.is_master() if session_data else None,
        "signed_in": bool(session_data),
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
                incorrect = "你创建旧版账户时使用的用户名包含了中文，无法自动迁移，请访问此网址提交用户名修改请求，由人工处理： "+request.app.state.config.assistance_url
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

        return None, request.app.state.templates.TemplateResponse(
            "migrate-phpcas-landing.html.jinja2",
            {
                "request": request,
                "csrf_field": csrf_field,
                "input_name": name,
                "input_email": email,
                "incorrect": incorrect,
            })

    # when creating user, make sure we don't create duplicates
    async with request.app.state.app_session.get_service_account_oauth_client() as client:
        resp = await client.post(
            request.app.state.config.keycloak_adminapi_url+'users',
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
            except Exception: # pylint: disable=broad-except
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
                                       ) -> Union[PHPCASUserInfo, Response]:
    """
    Arguments:
    password: put it None will disable password check
    """
    phpcas_adaptor: PHPCASAdaptor = request.app.state.phpcas_adaptor
    user = await phpcas_adaptor.get_user_by_email(email)
    if not user or (password and not user.check_password(password)):
        return request.app.state.templates.TemplateResponse("migrate-phpcas-landing.html.jinja2", {
            "request": request,
            "csrf_field": csrf_field,
            "input_name": name,
            "input_email": email,
            "incorrect": "你的邮箱与密码不正确，请确保使用正确的旧版网协通行证密码。",
        })

    if not user.enabled:
        # helpdesk
        return request.app.state.templates.TemplateResponse("migrate-phpcas-landing.html.jinja2", {
            "request": request,
            "csrf_field": csrf_field,
            "input_name": name,
            "input_email": email,
            "incorrect": "你的账户被禁用，无法迁移。请联系 webmaster@bitnp.net 以启用账户。",
        })

    return user


@router.get("/migrate-phpcas/user-lookup", include_in_schema=False)
async def phpcas_migrate_user_lookup(request: Request, username: str, email: Optional[str] = None) -> Response:
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

@router.get("/admin/migrate-phpcas/", include_in_schema=False)
async def admin_phpcas_migrate_landing(
        request: Request,
        csrf_field: tuple = Depends(deps_get_csrf_field),
        session_data: SessionData = Depends(deps_requires_master_session),
    ) -> Response:
    return request.app.state.templates.TemplateResponse("admin-migrate-phpcas-landing.html.jinja2", {
        "request": request,
        "csrf_field": csrf_field,
        "name": session_data.username if session_data else None,
        "is_admin": session_data.is_admin() if session_data else None,
        "is_master": session_data.is_master() if session_data else None,
        "signed_in": bool(session_data),
    })

@router.post("/admin/migrate-phpcas/", include_in_schema=False)
async def admin_phpcas_migrate_process(
        request: Request,
        email: str = Form(...),
        csrf_field: tuple = Depends(deps_get_csrf_field),
        csrf_valid: bool = Depends(deps_requires_csrf_posttoken),
        session_data: SessionData = Depends(deps_requires_master_session),
    ) -> Response:
    phpcas_adaptor: PHPCASAdaptor = request.app.state.phpcas_adaptor
    user = await phpcas_adaptor.get_user_by_email(email)

    if not user or not isinstance(user, PHPCASUserInfo):
        return request.app.state.templates.TemplateResponse("admin-migrate-phpcas-landing.html.jinja2", {
            "request": request,
            "csrf_field": csrf_field,
            "input_email": email,
            "incorrect": "找不到用户。",
        })

    try:
        new_user = datatypes.UserCreationInfo(
            enabled=user.enabled,
            email=email,
            emailVerified=False,
            name=user.real_name,
            username=user.name,
            credentials=[],
            attributes={'phpCAS_id': [user.id]},
        )
    except ValidationError as e:
        incorrect = "迁移失败，错误信息："+(
            ', '.join(['.'.join(field_error['loc'])+':'+field_error['msg'] for field_error in e.errors()])
        )

        return request.app.state.templates.TemplateResponse(
            "admin-migrate-phpcas-landing.html.jinja2",
            {
                "request": request,
                "csrf_field": csrf_field,
                "input_email": email,
                "incorrect": incorrect,
            })

    user_uri: str

    # when creating user, make sure we don't create duplicates
    async with request.app.state.app_session.get_service_account_oauth_client() as client:
        resp = await client.post(
            request.app.state.config.keycloak_adminapi_url+'users',
            data=new_user.request_json(),
            headers={'Accept': 'application/json', 'Content-Type': 'application/json'}
        )
        if resp.status_code != 201:
            incorrect = "迁移失败，错误信息："+resp.text
            print("phpcas-migrate: Error creating {}: {}".format(new_user.username, resp.text))

            return request.app.state.templates.TemplateResponse("admin-migrate-phpcas-landing.html.jinja2", {
                "request": request,
                "csrf_field": csrf_field,
                "input_email": email,
                "incorrect": incorrect,
            })

        user_uri = resp.headers.get('location', '')

        # send email
        resp = await client.put(
            user_uri+'/execute-actions-email',
            params={'client_id': request.app.state.config.client_id, 'redirect_uri': request.url_for("sp_landing"), 'lifespan': 60*60*24},
            json=['UPDATE_PASSWORD'],
            headers={'Accept': 'application/json'},
        )

        if resp.status_code != 200:
            incorrect = "迁移成功但无法触发邮件，如有需要请到 Keycloak 配置相应的群组："+resp.text
        else:
            incorrect = "迁移完成，如有需要请到 Keycloak 配置相应的群组。"

        return request.app.state.templates.TemplateResponse("admin-migrate-phpcas-landing.html.jinja2", {
                "request": request,
                "csrf_field": csrf_field,
                "input_email": email,
                "incorrect": incorrect,
            })
