from starlette.responses import RedirectResponse, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.datastructures import URL
from fastapi import FastAPI, Depends, Form, HTTPException

from authlib.integrations.starlette_client import StarletteRemoteApp
from authlib.integrations.httpx_client import OAuthError, AsyncOAuth2Client
from authlib.common.encoding import urlsafe_b64decode, to_bytes
from authlib.jose.rfc7519.jwt import decode_payload as decode_jwt_payload
from aiocache import Cache
from aiocache.base import BaseCache

from .datatypes import GroupConfig, GroupItem
from datetime import datetime, timedelta, timezone
from pydantic import BaseModel, validator
from pydantic.utils import deep_update
from contextlib import asynccontextmanager
from typing import AsyncIterator, List, Union, Optional, Tuple, Any
from hashlib import sha1
from authlib.common.security import generate_token
import time


class RequiresTokenException(Exception):
    pass

class UnauthorizedException(HTTPException):
    def __init__(self):
        super().__init__(status_code=403, detail="You don't have the privilege to access this endpoint")

class RemovesAuthParamsException(Exception):
    pass

class CSRFTokenInvalidException(HTTPException):
    def __init__(self):
        super().__init__(status_code=403, detail="post token invalid; this request may be unauthorized")


class SessionData(BaseModel):
    access_token_issued_at: datetime
    access_token_expires_at: datetime
    access_token: str
    refresh_token: str = ''
    token_type: str = ''
    memberof: List[GroupItem] = list()
    realm_roles: List[str] = list()
    client_roles: List[str] = list()
    id: str # Keycloak UUID
    username: str = ''
    name: Optional[str] = None
    email: str = ''
    scope: List[str] = list()
    id_token: dict = {} # temp

    def to_tokens(self) -> dict:
        return {
            'access_token': self.access_token,
            'token_type': self.token_type,
            'refresh_token': self.refresh_token,
            'expires_at': int(self.access_token_expires_at.replace(tzinfo=timezone.utc).timestamp()),
        }

    def is_admin(self) -> bool:
        return 'iam-admin' in self.scope

    def is_master(self) -> bool:
        return 'admin' in self.realm_roles

    @validator('realm_roles', 'client_roles', pre=True, always=True)
    def roles_default_list(cls, v):
        return v or list()


class SessionPointerData(BaseModel):
    target_jti: str
    expires_at: datetime


class SessionExpiringData(SessionPointerData):
    pass


class SessionRefreshData(SessionPointerData):
    # access_token_jti = target_jti
    pass

SessionItem = Union[SessionData, SessionExpiringData, SessionRefreshData]


class BITNPOAuthRemoteApp(StarletteRemoteApp):
    @staticmethod
    def get_cleaned_redirect_url_str(inferred: URL) -> str:
        return str(inferred.remove_query_params('code').remove_query_params('state')
                .remove_query_params('session_state')) # Keycloak only

    async def authorize_redirect(self, request: Request, redirect_uri: Optional[str]=None, **kwargs: Any) -> RedirectResponse:
        """Create a HTTP Redirect for Authorization Endpoint.
        :param request: Starlette Request instance.
        :param redirect_uri: Callback or redirect URI for authorization.
        :param kwargs: Extra parameters to include.
        :return: Starlette ``RedirectResponse`` instance.
        """
        state = self.framework.get_session_data(request, 'state')
        if state is not None:
            # reuse state if multiple pages in the same session needs relogin
            # relaxing this CSRF token's enforcement
            # TODO: is this safe in a CSRF context?
            kwargs['state'] = state
        rv = await self.create_authorization_url(redirect_uri, **kwargs)
        self.save_authorize_data(request, redirect_uri=redirect_uri, **rv)
        return RedirectResponse(rv['url'], status_code=303)

    async def register_redirect(self, request: Request, redirect_uri: Optional[str] = None, **kwargs: Any) -> RedirectResponse:
        """Create a HTTP Redirect for Registration Endpoint. Pribably Keycloak-only.
        :param request: Starlette Request instance.
        :param redirect_uri: Callback or redirect URI for registration completion.
        :param kwargs: Extra parameters to include.
        :return: Starlette ``RedirectResponse`` instance.
        """
        state = self.framework.get_session_data(request, 'state')
        if state is not None:
            # reuse state if multiple pages in the same session needs relogin
            # relaxing this CSRF token's enforcement
            # TODO: is this safe in a CSRF context?
            kwargs['state'] = state
        rv = await self.create_authorization_url(redirect_uri, **kwargs)
        rv['url'] = rv['url'].replace('/openid-connect/auth', '/openid-connect/registrations', 1)
        self.save_authorize_data(request, redirect_uri=redirect_uri, **rv)
        return RedirectResponse(rv['url'], status_code=303)

    async def authorize_access_token(self, request: Request, **kwargs: Any) -> dict:
        """Fetch an access token.
        :param request: Starlette Request instance.
        :return: A token dict.
        """
        params = self.retrieve_access_token_params(request)
        params.update(kwargs)
        # redirect_uri fallback
        # TODO: OIDC validates this parameter at all?
        if not params.get('redirect_uri'):
            # how to generate redirect_uri is more app-specific
            # in starlette this should be the request that triggers this function
            params['redirect_uri'] = self.get_cleaned_redirect_url_str(request.url)
        return await self.fetch_access_token(**params)

    async def parse_token_body(self, token: str) -> dict:
        """Return parsed (not-validated) JWT body from token."""
        s = to_bytes(token)
        try:
            _, payload, _ = s.split(b'.', 2)
        except ValueError:
            raise Exception("Invalid JWT segment")

        payload = urlsafe_b64decode(payload)
        payload = decode_jwt_payload(payload)

        return payload

    async def get_token_endpoint(self) -> str:
        metadata = await self.load_server_metadata()
        token_endpoint = self.access_token_url
        if not token_endpoint and not self.request_token_url:
            token_endpoint = metadata.get('token_endpoint')
        return token_endpoint

    async def refresh_token(self, token: SessionData) -> dict:
        token_endpoint = await self.get_token_endpoint()
        async with self._get_oauth_client() as client:
            return await client.refresh_token(token_endpoint, refresh_token=token.refresh_token)

    async def get_metadata_value(self, key: str) -> Any:
        try:
            return self.__getattribute__(key)
        except AttributeError:
            metadata = await self.load_server_metadata()
            return metadata.get(key)

    async def get_service_account_config(self):
        token_endpoint = await self.get_token_endpoint()
        return {
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'token_endpoint': token_endpoint,
            'token_endpoint_auth_method': 'client_secret_basic',
            'revocation_endpoint_auth_method': 'client_secret_basic',
            'scope': None,
        }


class BITNPFastAPICSRFAddon:
    csrf_token: str
    csrf_field_name: str = 'post_token'

    def get_csrf_session_id(self, request: Request) -> str:
        # Do not use jti! It will change with refresh_token
        return request.session.setdefault(self.csrf_field_name, generate_token(20))

    def get_csrf_token(self, request: Request) -> str:
        session_id = self.get_csrf_session_id(request)
        string = session_id + '&' + self.csrf_token
        token = sha1(string.encode()).hexdigest()[:20]
        # print(token)
        return token

    def check_csrf_token(self, token: str, request: Request) -> bool:
        # print(token)

        # ignore CSRF token check if Accept header is correctly set
        if request.state.response_type.is_json():
            return True
        if not token or not token == self.get_csrf_token(request):
            return False
        return True

def deps_get_csrf_field(request: Request) -> Tuple[str, str]:
    return BITNPFastAPICSRFAddon.csrf_field_name, request.app.state.app_session.get_csrf_token(request)

def deps_requires_csrf_posttoken(
        request: Request,
        csrf_token: str = Form(None, alias=BITNPFastAPICSRFAddon.csrf_field_name, description="CSRF token (not required if Accept header include json)")
    ) -> bool:
    if not request.app.state.app_session.check_csrf_token(csrf_token, request):
        raise CSRFTokenInvalidException
    return True

class BITNPSessions(BITNPFastAPICSRFAddon, object):
    group_config: GroupConfig
    oauth_client: StarletteRemoteApp
    session_cache: BaseCache
    bearer_grace_period: timedelta
    not_before_policy: datetime = datetime.utcnow()
    sa_tokens: Optional[dict] = None

    def __init__(self, app: FastAPI, oauth_client: StarletteRemoteApp, group_config: GroupConfig,
        csrf_token: str,
        bearer_grace_period: timedelta = timedelta(seconds=10),
        cache_type: BaseCache = Cache.MEMORY, cache_kwargs: dict = dict()):
        """
        bearer_grace_period: when the old token will expire, after browser receives a new token
        there might be several requests sent by browser at the same time with the same old token
        """
        self.init_app(app)

        self.oauth_client = oauth_client
        oauth_client._update_token = self.refresh_token_callback
        self.session_cache = Cache(cache_type, **cache_kwargs)
        self.bearer_grace_period = bearer_grace_period
        self.group_config = group_config
        self.csrf_token = csrf_token

    def init_app(self, app: FastAPI) -> None:
        app.exception_handler(RequiresTokenException)(self.exception_handler)
        app.exception_handler(RemovesAuthParamsException)(self.exception_handler)

    async def get_session(self, jti: str) -> Optional[SessionData]:
        if not jti:
            return None
        data = await self.session_cache.get(jti)
        if isinstance(data, SessionExpiringData):
            # check expiry
            if datetime.utcnow() > data.expires_at:
                await self.session_cache.delete(jti)
                return None
            else:
                data = await self.session_cache.get(data.target_jti)
        if data and isinstance(data, SessionData):
            # check not_before_policy
            if data.access_token_issued_at < self.not_before_policy:
                await self.session_cache.delete(jti)
                return None
            return data
        return None

    async def new_session(self, tokens: dict,
        request: Optional[Request] = None, old_session_data: Optional[SessionData] = None) -> Tuple[str, SessionData]:
        access_body = await self.oauth_client.parse_token_body(tokens['access_token'])
        access_jti = access_body['jti']
        refresh_body = None
        refresh_jti = None

        session_dict = {
            'access_token': tokens['access_token'],
            'token_type': tokens['token_type'],
            'access_token_issued_at': datetime.utcfromtimestamp(access_body['iat']),
            'access_token_expires_at': datetime.utcfromtimestamp(tokens['expires_at'])
        }

        if tokens.get('id_token'):
            id_body = None
            if request:
                id_body = await self.oauth_client.parse_id_token(request, tokens)
            elif old_session_data:
                id_body = await self.oauth_client.parse_token_body(tokens['id_token'])

            if id_body:
                session_dict['memberof'] = self.group_config.list_path_to_items(id_body.get('memberof', list()))
                session_dict['realm_roles'] = id_body.get('realm_access', {}).get('roles')
                session_dict['client_roles'] = id_body.get('roles')
                session_dict['id'] = id_body.get('sub')
                session_dict['username'] = id_body.get('preferred_username')
                session_dict['name'] = id_body.get('name')
                session_dict['email'] = id_body.get('email')
                session_dict['scope'] = access_body.get('scope', '').split(' ')

        if tokens.get('refresh_token'):
            session_dict['refresh_token'] = tokens['refresh_token']

            refresh_body = await self.oauth_client.parse_token_body(tokens['refresh_token'])
            refresh_jti = refresh_body['jti']
            refresh_data = SessionRefreshData(
                target_jti=access_jti,
                expires_at=datetime.utcfromtimestamp(refresh_body['exp'])
            )
            await self.session_cache.set(refresh_jti, refresh_data)

            if old_session_data and old_session_data.refresh_token:
                # update old refresh_token entry to the new access_token
                refresh_body = await self.oauth_client.parse_token_body(old_session_data.refresh_token)
                refresh_jti = refresh_body['jti']
                refresh_data = SessionRefreshData(
                    target_jti=access_jti,
                    expires_at=datetime.utcnow()+self.bearer_grace_period
                )
                await self.session_cache.set(refresh_jti, refresh_data)

        if old_session_data:
            session_dict = deep_update(old_session_data.dict(exclude_defaults=True), session_dict)

        session_data = SessionData(**session_dict)
        await self.session_cache.set(access_jti, session_data)

        # bearer = access_token
        # this is the actual sign_in process
        if request:
            request.session['bearer_jti'] = access_jti

        # update latest not-before-policy
        self.not_before_policy = datetime.utcfromtimestamp(tokens['not-before-policy'])

        return access_jti, session_data

    async def get_bearer_of_refresh_token(self, token: Optional[str]) -> Optional[str]:
        if not token:
            return None

        # get jti of refresh token
        refresh_body = await self.oauth_client.parse_token_body(token)
        refresh_jti = refresh_body['jti']

        # get old access token's jti before we update
        refresh_data = await self.session_cache.get(refresh_jti)
        if refresh_data:
            return refresh_data.target_jti
        else:
            return None

    async def refresh_token_callback(self, token: dict, refresh_token: Optional[str]=None,
        access_token: Optional[str]=None) -> None:
        # get old access token jti before we update
        jti = await self.get_bearer_of_refresh_token(refresh_token)
        session_data = None

        if jti:
            # old access_token before refresh
            # we need to see if this is really the old one, below
            session_data = await self.session_cache.get(jti)

            if isinstance(session_data, SessionData) and session_data.access_token == token:
                jti = None # Do not replace "old" token below because this is not the old one

        # update_token
        new_jti, new_session_data = await self.new_session(token, old_session_data=session_data)

        # replace old token
        if jti and session_data and jti != new_jti:
            # if jti == new_jti, we will have infinite loop
            session_expiring_data = SessionExpiringData(
                target_jti=new_jti,
                expires_at=session_data.access_token_expires_at+self.bearer_grace_period
            )
            await self.session_cache.set(jti, session_expiring_data)

    async def end_session(self, request: Request) -> Optional[str]:
        jti = request.session.pop('bearer_jti', None)
        if jti:
            session_data = await self.get_session(jti)
            if session_data:
                session_data.access_token_expires_at = datetime.utcnow()
                session_data.refresh_token = '' # force sign-in through OIDC flow
                await self.session_cache.set(jti, session_data)
        return session_data.access_token if (jti and session_data) else None

    async def exception_handler(self, request: Request, exc: Exception) -> Response:
        if isinstance(exc, RequiresTokenException):
            return await self.oauth_client.authorize_redirect(request, str(request.url))
        if isinstance(exc, RemovesAuthParamsException):
            clean_url = self.oauth_client.get_cleaned_redirect_url_str(request.url)
            return RedirectResponse(clean_url)
        raise exc

    async def sa_refresh_token_callback(self, token: dict, refresh_token: Optional[str] = None,
        access_token: Optional[str] = None) -> None:
        self.sa_tokens = token

    @asynccontextmanager
    async def get_service_account_oauth_client(self) -> AsyncIterator[AsyncOAuth2Client]:
        kwargs = await self.oauth_client.get_service_account_config()
        kwargs['update_token'] = self.sa_refresh_token_callback
        if self.sa_tokens:
            kwargs['token'] = self.sa_tokens

        async with AsyncOAuth2Client(**kwargs) as client:
            # we are not going to make use of refresh_token
            # every time access_token expires, we can go ahead and get a new token
            # since this is a service account and we have credentials

            # this comparison requires that token dict has a valid 'expires_at'
            if not isinstance(client.token, dict) or time.time() > client.token.get('expires_at', 0):
                await client.update_token(await client.fetch_token())
            yield client

# Usage: Depends(deps_get_session)
async def deps_get_session(request: Request) -> SessionData:
    _self = request.app.state.app_session
    # check code, state in query to complete auth
    if request.query_params.get('code') and request.query_params.get('state'):
        token = await _self.oauth_client.authorize_access_token(request)
        await _self.new_session(token, request=request)
        # if GET, redirect to remove code and state
        if request.method == 'GET':
            raise RemovesAuthParamsException

    # login check
    # TODO: direct Bearer token support
    jti = request.session.get('bearer_jti')
    session_data = await _self.get_session(jti)

    # expiry maintainance
    if session_data and datetime.utcnow() >= session_data.access_token_expires_at:
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

    if not session_data:
        # expired bearer_jti, removing
        request.session.pop('bearer_jti', None)

    return session_data

def deps_requires_session(session_data: SessionData = Depends(deps_get_session)) -> SessionData:
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
