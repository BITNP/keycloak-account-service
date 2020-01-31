from starlette.responses import RedirectResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from fastapi import FastAPI, Depends, Form, HTTPException

from authlib.integrations.starlette_client import RemoteApp
from authlib.integrations.httpx_client import OAuthError, AsyncOAuth2Client
from authlib.common.encoding import urlsafe_b64decode, to_bytes
from authlib.jose.rfc7519.jwt import decode_payload as decode_jwt_payload
from aiocache import Cache
from aiocache.base import BaseCache

from datatypes import SessionData, SessionExpiringData, SessionRefreshData, GroupConfig, GroupItem
from datetime import datetime, timedelta
from pydantic.utils import deep_update
from contextlib import asynccontextmanager
from typing import ContextManager
from hashlib import sha1
from authlib.common.security import generate_token


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


class BITNPOAuthRemoteApp(RemoteApp):
    async def authorize_redirect(self, request: Request, redirect_uri:str=None, **kwargs):
        """Create a HTTP Redirect for Authorization Endpoint.
        :param request: Starlette Request instance.
        :param redirect_uri: Callback or redirect URI for authorization.
        :param kwargs: Extra parameters to include.
        :return: Starlette ``RedirectResponse`` instance.
        """
        state = self._get_session_data(request, 'state')
        if state is not None:
            # reuse state if multiple pages in the same session needs relogin
            # relaxing this CSRF token's enforcement
            # TODO: is this safe in a CSRF context?
            kwargs['state'] = state
        rv = await self.create_authorization_url(redirect_uri, **kwargs)
        self.save_authorize_data(request, redirect_uri=redirect_uri, **rv)
        return RedirectResponse(rv['url'])

    async def authorize_access_token(self, request: Request, **kwargs):
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
            params['redirect_uri'] = str(
                request.url.remove_query_params('code').remove_query_params('state')
                .remove_query_params('session_state') # Keycloak only
            )
        return await self.fetch_access_token(**params)

    async def parse_token_body(self, token: str, claims_options=None, claims_params=None):
        """Return parsed (not-validated) JWT body from token."""
        s = to_bytes(token)
        try:
            _, payload, _ = s.split(b'.', 2)
        except ValueError:
            raise Exception("Invalid JWT segment")

        payload = urlsafe_b64decode(payload)
        payload = decode_jwt_payload(payload)

        return payload

    async def get_token_endpoint(self):
        metadata = await self._load_server_metadata()
        token_endpoint = self.access_token_url
        if not token_endpoint and not self.request_token_url:
            token_endpoint = metadata.get('token_endpoint')
        return token_endpoint

    async def refresh_token(self, token: dict):
        token_endpoint = await self.get_token_endpoint()
        async with self._get_oauth_client() as client:
            return await client.refresh_token(token_endpoint, refresh_token=token.refresh_token)

    async def get_metadata_value(self, key: str):
        try:
            return self.__getattribute__(key)
        except AttributeError:
            metadata = await self._load_server_metadata()
            return metadata.get(key)

    async def get_service_account_config(self):
        token_endpoint = await self.get_token_endpoint()
        return {
            'client_id':self.client_id,
            'client_secret':self.client_secret,
            'token_endpoint':token_endpoint,
            'token_endpoint_auth_method':'client_secret_basic',
            'revocation_endpoint_auth_method':'client_secret_basic',
            'scope':None,
        }


class BITNPFastAPICSRFAddon:
    csrf_token: str
    csrf_field_name: str = 'post_token'

    def get_csrf_session_id(self, request: Request):
        # Do not use jti! It will change with refresh_token
        return request.session.setdefault(self.csrf_field_name, generate_token(20))

    def get_csrf_token(self, request: Request):
        session_id = self.get_csrf_session_id(request)
        string = session_id + '&' + self.csrf_token
        token = sha1(string.encode()).hexdigest()[:20]
        # print(token)
        return token

    def check_csrf_token(self, token, request: Request):
        # print(token)

        # ignore CSRF token check if Accept header is correctly set
        if request.state.response_type.is_json():
            return True
        if not token or not token == self.get_csrf_token(request):
            return False
        return True

    @staticmethod
    def deps_get_csrf_field(request: Request) -> (str, str):
        return BITNPFastAPICSRFAddon.csrf_field_name, request.app.state.app_session.get_csrf_token(request)

def deps_requires_csrf_posttoken(
        request: Request,
        token: str = Form(None, alias=BITNPFastAPICSRFAddon.csrf_field_name, description="CSRF token (not required if Accept header include json)")
    ) -> bool:
    if not request.app.state.app_session.check_csrf_token(token, request):
        raise CSRFTokenInvalidException
    return True
BITNPFastAPICSRFAddon.deps_requires_csrf_posttoken = deps_requires_csrf_posttoken

class BITNPSessionFastAPIApp(BITNPFastAPICSRFAddon):
    group_config: GroupConfig
    oauth_client: RemoteApp
    session_cache: BaseCache
    bearer_grace_period: timedelta
    not_before_policy: datetime = datetime.utcnow()
    sa_tokens: dict = None

    def __init__(self, app: FastAPI, oauth_client: RemoteApp, group_config: GroupConfig,
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

    async def get_session(self, jti: str) -> SessionData:
        if not jti:
            return None
        data = await self.session_cache.get(jti)
        if isinstance(data, SessionExpiringData):
            # check expiry
            if datetime.utcnow() > data.expires_at:
                await self.session_cache.delete(jti)
                return None
            else:
                data = await self.session_cache.get(data.new_jti)
        if data and isinstance(data, SessionData):
            # check not_before_policy
            if data.access_token_issued_at < self.not_before_policy:
                await self.session_cache.delete(jti)
                return None
            return data
        return None

    async def new_session(self, tokens: dict, request: Request = None, old_session_data: SessionData = None):
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
                session_dict['subject'] = id_body.get('sub')
                session_dict['username'] = id_body.get('preferred_username')
                session_dict['name'] = id_body.get('name')
                session_dict['email'] = id_body.get('email')
                session_dict['scope'] = access_body.get('scope', '').split(' ')

        if tokens.get('refresh_token'):
            session_dict['refresh_token'] = tokens['refresh_token']

            refresh_body = await self.oauth_client.parse_token_body(tokens['refresh_token'])
            refresh_jti = refresh_body['jti']
            refresh_data = SessionRefreshData(
                access_token_jti=access_jti,
                expires_at=datetime.utcfromtimestamp(refresh_body['exp'])
            )
            await self.session_cache.set(refresh_jti, refresh_data)

            if old_session_data and old_session_data.refresh_token:
                # update old refresh_token entry to the new access_token
                refresh_body = await self.oauth_client.parse_token_body(old_session_data.refresh_token)
                refresh_jti = refresh_body['jti']
                refresh_data = SessionRefreshData(
                    access_token_jti=access_jti,
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

    async def get_bearer_of_refresh_token(self, token: str):
        if not token:
            return None

        # get jti of refresh token
        refresh_body = await self.oauth_client.parse_token_body(token)
        refresh_jti = refresh_body['jti']

        # get old access token's jti before we update
        refresh_data = await self.session_cache.get(refresh_jti)
        if refresh_data:
            return refresh_data.access_token_jti
        else:
            return None

    async def refresh_token_callback(self, token: dict, refresh_token: str=None,
        access_token: str=None) -> (str, SessionData):
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
                new_jti=new_jti,
                expires_at=session_data.access_token_expires_at+self.bearer_grace_period
            )
            await self.session_cache.set(jti, session_expiring_data)

    async def end_session(self, request: Request) -> str:
        jti = request.session.pop('bearer_jti', None)
        if jti:
            session_data = await self.get_session(jti)
            session_data.access_token_expires_at = datetime.utcnow()
            session_data.refresh_token = '' # force sign-in through OIDC flow
            await self.session_cache.set(jti, session_data)
        return session_data.access_token if jti else None

    # Usage: Depends(app_session.deps_session_data)
    @staticmethod
    async def deps_session_data(request: Request) -> SessionData:
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

    async def exception_handler(self, request: Request, exc: Exception):
        if isinstance(exc, RequiresTokenException):
            response = await self.oauth_client.authorize_redirect(request, str(request.url))
            # monkey patch to make sure GET only
            response.status_code = 303
            return response
        if isinstance(exc, RemovesAuthParamsException):
            clean_url = str(
                request.url.remove_query_params('code').remove_query_params('state')
                .remove_query_params('session_state') # Keycloak only
            )
            return RedirectResponse(clean_url)

    async def sa_refresh_token_callback(self, token: dict, refresh_token: str=None,
        access_token: str=None) -> None:
        self.sa_tokens = token

    @asynccontextmanager
    async def get_service_account_oauth_client(self) -> ContextManager[AsyncOAuth2Client]:
        kwargs = await self.oauth_client.get_service_account_config()
        kwargs['update_token'] = self.sa_refresh_token_callback
        if self.sa_tokens:
            kwargs['token'] = self.sa_tokens

        async with AsyncOAuth2Client(**kwargs) as client:
            if not client.token:
                await client.update_token(await client.fetch_token())
            yield client

def deps_requires_session(session_data: SessionData = Depends(BITNPSessionFastAPIApp.deps_session_data)):
    if session_data is None:
        raise RequiresTokenException
    return session_data

BITNPSessionFastAPIApp.deps_requires_session = deps_requires_session

def deps_requires_admin_session(session_data: SessionData = Depends(BITNPSessionFastAPIApp.deps_requires_session)):
    if not session_data.is_admin():
        raise UnauthorizedException
    return session_data

BITNPSessionFastAPIApp.deps_requires_admin_session = deps_requires_admin_session

def deps_requires_master_session(session_data: SessionData = Depends(BITNPSessionFastAPIApp.deps_requires_session)):
    if not session_data.is_master():
        raise UnauthorizedException
    return session_data

BITNPSessionFastAPIApp.deps_requires_admin_session = deps_requires_admin_session