from starlette.requests import Request
import datatypes
import itsdangerous
import base64
from typing import Tuple
from authlib.common.security import generate_token

SEPARATOR = "@"

def get_invitation_token(group: datatypes.GroupItem, config: datatypes.Settings) -> str:
    assert group.path.find(SEPARATOR) == -1, "Group path should not include separator: "+group.path
    nonce = group.attributes.get('invitationNonce')
    # we actually allow separator in nonce due to how this works
    if not nonce:
        # not enabled
        return None
    if isinstance(nonce, list):
        nonce = nonce[0]
    text = SEPARATOR.join([group.path, nonce])
    signer = itsdangerous.Signer(secret_key=config.invitation_secret, sep=SEPARATOR)
    return base64.urlsafe_b64encode(signer.sign(text)).decode()

def get_invitation_link(group: datatypes.GroupItem, request: Request) -> str:
    token = get_invitation_token(group=group, config=request.app.state.config)
    if token:
        return request.url_for('invitation_landing', token=token)
    else:
        return None

def parse_invitation_token(token: str, config: datatypes.Settings) -> Tuple[str, str]:
    try:
        text = base64.urlsafe_b64decode(token)
        signer = itsdangerous.Signer(secret_key=config.invitation_secret, sep=SEPARATOR)
        path, nonce = signer.unsign(text).decode().split(SEPARATOR, 1)
        return path, nonce
    except Exception as e:
        print(e)
        return None, None

def generate_random_nonce() -> str:
    return generate_token(length=4)