from contextlib import asynccontextmanager
from typing import AsyncIterator, List, Union, Optional, Tuple, Any, Dict
from hashlib import sha1
from datetime import datetime, timedelta, timezone
import time
import traceback

from pydantic import BaseModel, validator
from pydantic.utils import deep_update
from starlette.responses import RedirectResponse, Response
from starlette.requests import Request
from starlette.datastructures import URL
from fastapi import FastAPI, Depends, Form, HTTPException
from fastapi.security import OAuth2
from fastapi.security.utils import get_authorization_scheme_param
from authlib.integrations.starlette_client import StarletteRemoteApp
from authlib.integrations.httpx_client import OAuthError, AsyncOAuth2Client
from authlib.common.encoding import urlsafe_b64decode, to_bytes
from authlib.common.security import generate_token
from authlib.jose.rfc7519.jwt import decode_payload as decode_jwt_payload
from aiocache import Cache
from aiocache.base import BaseCache

from .app import app  # See app.state.oauth2_scheme
from .datatypes import GroupConfig, GroupItem
from .auth import (BITNPFastAPICSRFAddon, CSRFTokenInvalidException, BITNPSessions,
                   SessionData, RemovesAuthParamsException, RequiresTokenException, UnauthorizedException)


# Usage: Depends(deps_get_session)
async def deps_get_session(request: Request,
                           oauth_bearer_token: str = Depends(app.state.oauth2_scheme),
                           _oidc_bearer_token: str = Depends(app.state.oidc_scheme),
                           ) -> Optional[SessionData]:
    """
    :param _oidc_bearer_token This dependency shows a correct OIDC entry in openapi.json
    :param oauth_bearer_token compatible OAuth2 Bearer entry
    """
    _self: BITNPSessions = request.app.state.app_session
    session_data: Optional[SessionData]

    # check code, state in query to complete auth
    if request.query_params.get('code') and request.query_params.get('state'):
        token = await _self.oauth_client.authorize_access_token(request)
        await _self.new_session(token, request=request)
        # if GET, redirect to remove code and state
        if request.method == 'GET':
            raise RemovesAuthParamsException

    # Bearer token flow
    # We will never have refersh_token, but we can still cache it in session_cache (for id_token purpose)
    if oauth_bearer_token:
        # so we are not validating access_token at this time
        access_body = await _self.oauth_client.parse_token_body(oauth_bearer_token)
        tokens = {'access_token': oauth_bearer_token, 'token_type': 'bearer'}
        if not access_body.get('jti'):
            raise OAuthError(error='invalid_claim', description='missing jti')

        # we assume that we are doing a refresh_token
        # new_session will always validate access_token
        saved_session_data = await _self.get_session(access_body.get('jti'))
        _, session_data = await _self.new_session(tokens, request=None, old_session_data=saved_session_data)
        if (not saved_session_data or not saved_session_data.id_token_expires_at
            or saved_session_data.id_token_expires_at < datetime.utcnow()):
            # get new id_token related information
            # and Keycloak will validate access_token for us
            session_data.id_token_expires_at = datetime.utcnow() + _self.bearer_grace_period # a short cache
            try:
                async with request.app.state.app_session.get_service_account_oauth_client() as client:
                    resp = await client.get(
                        request.app.state.config.keycloak_adminapi_url+'users/'+session_data.id+'/groups',
                        headers={'Accept': 'application/json'}
                    )
                    if resp.status_code != 200:
                        raise HTTPException(status_code=resp.status_code, detail=resp.text)

                    session_data.memberof = [
                        request.app.state.config.group_config.get(g['path'], GroupItem.parse_obj(g))
                            for g in resp.json()]
            except Exception as e: # pylint: disable=broad-except
                traceback.print_exc()
        else:
            pass # we reuse userinfo in saved_session_data

        if datetime.utcfromtimestamp(access_body.get('exp', 0)) < _self.not_before_policy:
            raise OAuthError(error='invalid_claim', description='your token has expired')

        print("Bearer header signed in as "+str(session_data))
        return session_data

    # login check by cookie
    jti: Optional[str] = request.session.get('bearer_jti')
    session_data = await _self.get_session(jti)

    # expiry maintainance
    if session_data and datetime.utcnow() >= session_data.access_token_expires_at:
        print(session_data.access_token_expires_at)
        # request a new access token with OIDC
        try:
            if not session_data.refresh_token:
                raise OAuthError(error='invalid_grant', description='No refresh_token exists')
            new_token = await _self.oauth_client.refresh_token(session_data)
            # update should be done in refresh_token_callback()
            # We need to manaully update session now

            # Get new jti - update session and session_data as well
            jti = await _self.get_bearer_of_refresh_token(session_data.refresh_token)
            assert jti != request.session['bearer_jti'], "Refreshed token should have different jti"

            request.session['bearer_jti'] = jti
            session_data = await _self.get_session(jti)
        except OAuthError as e:
            if e.error == 'invalid_grant':
                # Unable to refresh token (probably expired token)
                session_data = None # remove session

    # we don't use cookie if the access_token is generated by others
    # i.e. this is a header-based login
    if session_data and session_data.origin != _self.oauth_client.client_id:
        session_data = None

    if not session_data:
        # expired bearer_jti, removing
        request.session.pop('bearer_jti', None)

    return session_data

def deps_requires_session(session_data: Optional[SessionData] = Depends(deps_get_session)) -> SessionData:
    if session_data is None:
        raise RequiresTokenException
    return session_data

def deps_requires_admin_session(session_data: SessionData = Depends(deps_requires_session)) -> SessionData:
    if not session_data.is_admin():
        raise UnauthorizedException
    return session_data

def deps_requires_master_session(session_data: SessionData = Depends(deps_requires_session)) -> SessionData:
    if not session_data.is_master():
        raise UnauthorizedException
    return session_data

def deps_get_csrf_field(request: Request) -> Tuple[str, str]:
    return BITNPFastAPICSRFAddon.csrf_field_name, request.app.state.app_session.get_csrf_token(request)

def deps_requires_csrf_posttoken(
        request: Request,
        csrf_token: str = Form(None, alias=BITNPFastAPICSRFAddon.csrf_field_name, description="CSRF token (not required if Accept header include json)")
    ) -> bool:
    if not request.app.state.app_session.check_csrf_token(csrf_token, request):
        raise CSRFTokenInvalidException
    return True
