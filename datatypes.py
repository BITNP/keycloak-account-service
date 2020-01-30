from pydantic import BaseModel, BaseSettings, IPvAnyAddress, validator, conlist, Field, MissingError
from datetime import datetime, tzinfo, timezone, timedelta
from typing import Union, List, Dict, Any, Optional, ForwardRef
from collections import UserDict


class Settings(BaseSettings):
    class Config:
        env_prefix = 'acct_'
        env_file = '.env'

    keycloak_admin_url: str = 'https://login.bitnp.net/'
    keycloak_adminapi_url: str = 'https://login.bitnp.net/auth/admin/realms/master/'
    keycloak_accountapi_url: str = 'https://login.bitnp.net/auth/realms/master/account/'

    local_timezone: tzinfo = timezone(timedelta(hours=8))

    client_id: str
    client_secret: str
    session_secret: str = Field(..., description="Used for session and CSRF")
    server_metadata_url: str = 'https://login.bitnp.net/auth/realms/master/.well-known/openid-configuration'
    group_status_prefix: str = '/bitnp/active'
    group_config_path: str = '/bitnp' # Pending removal?
    role_active_name: str = 'bitnp-active'

    group_config: 'GroupConfig' = None

class GroupItem(BaseModel):
    id: str = None
    path: str
    name: str = None
    internal_note: str = None

    @validator('name', always=True)
    def default_name_as_path(cls, v, values):
        if v is None:
            return values.get('path', None)
        return v

    def set_status_name(self, year: str):
        self.name = year + ((' ' + self.name) if self.name else '')

class GroupConfig(UserDict):
    settings: Settings
    active_ns_placeholder: str = '@active/' # static

    @staticmethod
    def from_dict(obj: Dict[str, dict], settings: Settings, **kwargs) -> 'GroupConfig':
        ret = GroupConfig(settings=settings, **kwargs)
        for path, item in obj.items():
            item['path'] = path
            ret[path] = GroupItem(**item)
        return ret

    def __init__(self, settings: Settings, *args, **kwargs):
        self.settings = settings
        super().__init__(*args, **kwargs)

    def __setitem__(self, key: str, item: GroupItem):
        if key is None:
            key = item.path
        super().__setitem__(key, item)

    def __getitem__(self, key: str) -> GroupItem:
        try:
            return super().__getitem__(key)
        except KeyError:
            # status transform
            if key.startswith(self.settings.group_status_prefix):
                cutted = key[len(self.settings.group_status_prefix):]
                try:
                    year, specifics = cutted.split('/', 1)
                    item : GroupItem = super().__getitem__(self.active_ns_placeholder + specifics)
                    ret = GroupItem(**item.dict())
                    ret.path = key
                except ValueError:
                    # no specifics
                    year = cutted
                    ret = GroupItem(path=key, name='')
                finally:
                    year = year.lstrip('-')
                    ret.set_status_name(year)
                    return ret
            else:
                raise

    def filter_active_groups(self, source: List[GroupItem]) -> (List[GroupItem], List[GroupItem]):
        trues = []
        falses = []
        for item in source:
            if item.path.startswith(self.settings.group_status_prefix):
                trues.append(item)
            else:
                falses.append(item)

        return trues, falses

    def list_path_to_items(self, paths: List[str]) -> List[GroupItem]:
        ret = [self.get(path, GroupItem(path=path)) for path in paths]
        return ret


class TOSData(BaseModel):
    html: str = ''


class PermissionInfo(BaseModel):
    has_active_role: Optional[bool] = None
    memberof: List[GroupItem] = list()
    realm_roles: List[str] = list()
    client_roles: List[str] = list()
    active_groups: List[GroupItem] = list()

class ProfileInfo(BaseModel):
    subject: str = None
    username: str = ''
    name: str = None
    email: str = ''
    emailVerified: bool = None
    firstName: str = None
    lastName: str = None
    attributes: dict = None

class ProfileUpdateInfo(BaseModel):
    name: str = None
    lastName: str = None
    firstName: str
    email: str

    @validator('firstName', always=True, pre=True)
    def firstName_default(cls, v, values):
        if not v:
            if values.get('name') and not values.get('lastName'):
                return values.get('name')
            raise MissingError
        return v


class KeycloakSessionClient(BaseModel):
    clientId: str
    clientName: str = None

    @validator('clientName', always=True)
    def clientName_default(cls, v, values):
        return v or values.get('clientId')

class KeycloakSessionItem(BaseModel):
    id: str
    ipAddress: IPvAnyAddress
    started: datetime
    lastAccess: datetime
    expires: datetime
    browser: str
    current: bool = False
    os: str = None
    osVersion: str = None
    device: str = None
    clients: List[KeycloakSessionClient] = list()

#class KeycloakSessionInfo(BaseModel):
#    __root__: List[KeycloakSessionItem]

KeycloakSessionInfo = List[KeycloakSessionItem]

#class KeycloakSessionInfo(BaseModel):
#    sessions: List[KeycloakSessionItem] = []

class SessionData(BaseModel):
    access_token_issued_at: datetime
    access_token_expires_at: datetime
    access_token: str
    refresh_token: str = ''
    token_type: str = ''
    memberof: List[GroupItem] = list()
    realm_roles: List[str] = list()
    client_roles: List[str] = list()
    subject: str
    username: str = ''
    name: str = None
    email: str = ''
    id_token: dict = {} # temp

    def to_tokens(self):
        return {
            'access_token': self.access_token,
            'token_type': self.token_type,
            'refresh_token': self.refresh_token,
            'expires_at': int(self.access_token_expires_at.timestamp()),
        }

    @validator('realm_roles', 'client_roles', pre=True, always=True)
    def roles_default_list(cls, v):
        return v or list()


class SessionPointerData(BaseModel):
    target_jti: str
    expires_at: datetime


class SessionExpiringData(BaseModel):
    new_jti: str
    expires_at: datetime


class SessionRefreshData(BaseModel):
    access_token_jti: str
    expires_at: datetime

SessionItem = Union[SessionData, SessionExpiringData, SessionRefreshData]


Settings.update_forward_refs()