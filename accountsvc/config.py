import json
from fastapi.security import OAuth2PasswordBearer
from fastapi.security.open_id_connect_url import OpenIdConnect
from . import datatypes

MIN_PYTHON = (3, 6)
APP_TITLE = "网协通行证账户服务"
APP_VERSION = "1.0"

def load_config() -> datatypes.Settings:
    loading_config: datatypes.LoadingSettings = datatypes.LoadingSettings() # from .env
    with open('group_config.json', 'r') as f:
        data = json.load(f)
        loading_config.group_config = datatypes.GroupConfig.from_dict(data, settings=loading_config)
    return datatypes.Settings.parse_obj(loading_config)

CONFIG = load_config()

OAUTH2_SCHEME = OAuth2PasswordBearer(
    tokenUrl=CONFIG.oauth_token_endpoint,
    scheme_name="Compatabile BITNP OAuth Password (client_id: bitnp-accounts-public)",
    scopes={"iam-admin": "Manage users and groups"},
    auto_error=False,
)

OIDC_SCHEME = OpenIdConnect(
    openIdConnectUrl=CONFIG.server_metadata_url,
    scheme_name='BITNP OpenID Connect (client_id: bitnp-accounts-public)',
    auto_error=False,
)
