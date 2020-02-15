from starlette.requests import Request
from starlette.templating import Jinja2Templates, _TemplateResponse
from starlette.background import BackgroundTask

class TemplateService:
    def __init__(self, request: Request):
        self._request: Request = request

    def TemplateResponse(
        self,
        name: str,
        context: dict = dict(),
        status_code: int = 200,
        headers: dict = None,
        media_type: str = None,
        background: BackgroundTask = None
    ) -> _TemplateResponse:
        def_context = {'request': self._request}
        def_context.update(**context)
        return self._request.app.state.templates.TemplateResponse(
            name=name,
            context=def_context,
            status_code=status_code,
            headers=headers,
            media_type=media_type,
            background=background
        )

def local_timestring(timezone, dt, format='%Y-%m-%d %H:%M'):
    return dt.astimezone(timezone).strftime(format)
