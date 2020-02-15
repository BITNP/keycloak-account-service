from pydantic import BaseModel, BaseSettings, IPvAnyAddress, validator, root_validator, conlist, constr, Field, MissingError
from datetime import datetime, tzinfo, timezone, timedelta
from typing import Union, List, Dict, Any, Optional, Tuple
from collections import UserDict
from enum import Enum
from starlette.requests import Request


class LoadingSettings(BaseSettings):
    class Config:
        env_prefix = 'acct_'
        env_file = '.env'

    keycloak_admin_console_url: str = 'https://login.bitnp.net/auth/admin/master/console/'
    keycloak_adminapi_url: str = 'https://login.bitnp.net/auth/admin/realms/master/'
    keycloak_accountapi_url: str = 'https://login.bitnp.net/auth/realms/master/account/'
    keycloak_forgotpw_url: str = 'https://login.bitnp.net/auth/realms/master/login-actions/reset-credentials'
    keycloak_client_uuid: str = ''
    assistance_url: str = ''

    local_timezone: tzinfo = timezone(timedelta(hours=8))

    client_id: str
    client_secret: str
    session_secret: str = Field(..., description="Used for session and CSRF")
    invitation_secret: str
    server_metadata_url: str = 'https://login.bitnp.net/auth/realms/master/.well-known/openid-configuration'
    group_status_prefix: str = '/bitnp/active-'
    group_config_path: str = '/bitnp' # Pending removal?
    role_active_name: str = 'bitnp-active'
    iam_master_group_id: Optional[str] = None

    group_config: 'Optional[GroupConfig]' = None

    phpcas_host: str = ''
    phpcas_user: str = ''
    phpcas_password: str = ''
    phpcas_db: str = ''

    ldap_host: str = ''
    ldap_user_dn: str = ''
    ldap_password: str = ''
    ldap_base_dn_users: str = 'ou=users,dc=bitnp,dc=net'
    ldap_base_dn_groups: str = 'ou=groups,dc=bitnp,dc=net'
    ldap_kc_fedlink_id: str = ''

    jira_user_search_url_f: str = 'https://jira.bitnp.net/secure/admin/user/UserBrowser.jspa?userSearchFilter={username}'

class Settings(LoadingSettings):
    group_config: 'GroupConfig'

class GroupItem(BaseModel):
    id: Optional[str] = None
    path: str
    name: str = ''
    internal_note: Optional[str] = None
    attributes: Optional[dict] = None
    members: Optional[list] = None
    invitation_link: Optional[str] = None
    invitation_expires: Optional[datetime] = None

    @validator('name', always=True)
    def default_name_as_path(cls, v, values):
        if v == '':
            return values['path']
        return v

    def set_status_name(self, year: str):
        self.name = year + ((' ' + self.name) if self.name else '')

class KCGroupItem(GroupItem):
    id: str

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
                    parsed_key = self.active_ns_placeholder + specifics.replace(year+'-', '', 1)
                    item : GroupItem = super().__getitem__(parsed_key)
                    ret = GroupItem(**item.dict())
                    ret.path = key
                except ValueError:
                    # no specifics
                    year = cutted
                    ret = GroupItem(path=key, name='')
                year = year.lstrip('-')
                ret.set_status_name(year)
                return ret
            else:
                raise

    def filter_active_groups(self, source: List[GroupItem]) -> Tuple[List[GroupItem], List[GroupItem]]:
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

class UserLdapEntry(BaseModel):
    dn: str
    attributes: Dict[str, Any]
    raw_attributes: Dict[str, Any]

    @validator('raw_attributes')
    def raw_attributes_decode(cls, v):
        new_dict = dict()
        for key, values in v.items():
            new_dict[key] = [(value.decode() if isinstance(value, bytes) else value) for value in values]
        return new_dict

class ProfileInfo(BaseModel):
    id: Optional[str] = None
    username: str = ''
    firstName: Optional[str] = None
    lastName: Optional[str] = None
    name: Optional[str] = None
    email: str = ''
    emailVerified: Optional[bool] = None
    attributes: Optional[dict] = None
    createdTimestamp: Optional[datetime] = None
    enabled: bool = True

    @validator('name', always=True)
    def name_default(cls, v, values):
        if not v:
            return (values.get('lastName') or '') + (values.get('firstName') or '')
        return v

class UserInfoMaster(ProfileInfo):
    id: str
    federationLink: Optional[str] = None
    ldapEntry: Optional[UserLdapEntry] = None
    memberof: List[GroupItem] = list()
    ldapMemberof: Optional[List[str]] = None

class ProfileUpdateInfo(BaseModel):
    name: Optional[str] = None
    lastName: Optional[str] = None
    firstName: Optional[str] = None
    email: str

    @validator('firstName', always=True, pre=True)
    def firstName_default(cls, v, values):
        if not v:
            if values.get('name') and not values.get('lastName'):
                return values.get('name')
            raise MissingError
        return v

class UserCreationInfo(ProfileUpdateInfo):
    enabled: bool = True
    emailVerified: bool = False
    username: constr(min_length=2, max_length=20, regex="^[a-zA-Z0-9_-]+$") # type: ignore # for constr
    credentials: Optional[list] = None
    newPassword: constr(min_length=6) # type: ignore # for constr
    confirmation: str
    attributes: Optional[dict] = None

    def request_json(self) -> str:
        return self.json(exclude={"name", "newPassword", "confirmation"})

    @validator('newPassword')
    def check_username_password_match(cls, v, values):
        if values.get('username') == v:
            raise ValueError('Password cannot match username')
        return v

    @root_validator
    def check_passwords_match_and_init_creds(cls, values):
        pw1, pw2 = values.get('newPassword'), values.get('confirmation')
        if pw1 is not None and pw2 is not None and pw1 != pw2:
            raise ValueError('Passwords do not match')

        # init credentials
        if not values.get('credentials'):
            values['credentials'] = [{'type': 'password', 'temporary': False, 'value': pw1}]
        return values

class PasswordInfo(BaseModel):
    registered: Optional[bool] = None
    lastUpdate: Optional[datetime] = None # created date, not updated date

class PasswordUpdateRequest(BaseModel):
    currentPassword: str
    newPassword: str
    confirmation: str

    @root_validator
    def check_passwords_match(cls, values):
        pw1, pw2 = values.get('newPassword'), values.get('confirmation')
        if pw1 is not None and pw2 is not None and pw1 != pw2:
            raise ValueError('Passwords do not match')
        return values

class KeycloakSessionClient(BaseModel):
    clientId: str
    clientName: Optional[str] = None

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
    os: Optional[str] = None
    osVersion: Optional[str] = None
    device: Optional[str] = None
    clients: List[KeycloakSessionClient] = list()

#class KeycloakSessionInfo(BaseModel):
#    __root__: List[KeycloakSessionItem]

KeycloakSessionInfo = List[KeycloakSessionItem]

#class KeycloakSessionInfo(BaseModel):
#    sessions: List[KeycloakSessionItem] = []

class BITNPResponseType(Enum):
    json = 'json'
    html = 'html'

    def is_json(self) -> bool:
        return self == self.json

    @staticmethod
    def from_request(request: Request) -> 'BITNPResponseType':
        if 'application/json' in request.headers.get('accept', ''):
            return BITNPResponseType.json
        else:
            return BITNPResponseType.html


LoadingSettings.update_forward_refs()