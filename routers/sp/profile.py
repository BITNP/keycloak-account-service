from fastapi import Depends, APIRouter
from starlette.requests import Request
from starlette.exceptions import HTTPException as StarletteHTTPException
import datatypes

from modauthlib import BITNPSessionFastAPIApp

router = APIRouter()

@router.get("/", include_in_schema=True, response_model=datatypes.ProfileInfo)
async def sp_profile(
        session_data: datatypes.SessionData = Depends(BITNPSessionFastAPIApp.deps_requires_session)
    ) -> datatypes.ProfileInfo:
    return datatypes.ProfileInfo.parse_obj(session_data)
