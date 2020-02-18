from typing import Optional
from datetime import datetime, tzinfo

from fastapi import HTTPException
from starlette.requests import Request
from starlette.templating import _TemplateResponse
from starlette.background import BackgroundTask

from .auth import SessionData

class TemplateService:
    def __init__(self, request: Request):
        self._request: Request = request

    def TemplateResponse(self,
                         name: str,
                         context: Optional[dict] = None,
                         status_code: int = 200,
                         headers: Optional[dict] = None,
                         media_type: Optional[str] = None,
                         background: Optional[BackgroundTask] = None
                        ) -> _TemplateResponse:
        def_context = {'request': self._request}
        if context:
            def_context.update(**context)
        return self._request.app.state.templates.TemplateResponse(
            name=name,
            context=def_context,
            status_code=status_code,
            headers=headers,
            media_type=media_type,
            background=background
        )

def local_timestring(timezone: tzinfo, dt: datetime, dt_format: str = '%Y-%m-%d %H:%M') -> str:
    return dt.astimezone(timezone).strftime(dt_format)

async def request_accountapi_json_expect_200(request: Request, session_data: SessionData, data: str, uri: str = '') -> None:
    resp = await request.app.state.app_session.oauth_client.post(
        request.app.state.config.keycloak_accountapi_url+uri,
        token=session_data.to_tokens(),
        data=data,
        headers={'Accept': 'application/json', 'Content-Type': 'application/json'}
    )
    if resp.status_code != 200:
        raise HTTPException(status_code=resp.status_code, detail=resp.text)