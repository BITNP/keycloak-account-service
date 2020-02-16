from typing import Tuple, Optional
import base64
import time

from starlette.requests import Request
import itsdangerous
from authlib.common.security import generate_token as _generate_token
from accountsvc import datatypes

SEPARATOR = "@"

def get_invitation_expires(group: datatypes.GroupItem) -> Optional[int]:
    if not group.attributes:
        return None

    expires = group.attributes.get('invitationExpires')
    if isinstance(expires, list):
        if len(expires) > 0:
            return int(expires[0]) if expires[0] else None
        else:
            return None
    return int(expires) if expires else None

def get_invitation_token(group: datatypes.GroupItem, config: datatypes.Settings) -> Optional[str]:
    """
    This token should be consistent during different execution as long as:
    - secret did not change
    - nonce did not change
    - before expiry date

    Thus, this will be used to compare against submitted token - one more
    sign process but consistent validation logic
    """
    assert group.path.find(SEPARATOR) == -1, "Group path should not include separator: "+group.path
    if not group.attributes:
        return None

    nonce = group.attributes.get('invitationNonce')
    # we actually allow separator in nonce due to how this works
    if not nonce:
        # not enabled
        return None
    if isinstance(nonce, list):
        nonce = nonce[0]

    # expiry check - if expiry is None then we ignore the check
    expires = get_invitation_expires(group)
    if expires is not None and expires < time.time():
        return None

    text = SEPARATOR.join([group.path, nonce])
    signer = itsdangerous.Signer(secret_key=config.invitation_secret, sep=SEPARATOR)
    return base64.urlsafe_b64encode(signer.sign(text)).decode()

def get_invitation_link(group: datatypes.GroupItem, request: Request) -> Optional[str]:
    token = get_invitation_token(group=group, config=request.app.state.config)
    if token:
        return request.url_for('invitation_landing', token=token)
    else:
        return None

def parse_invitation_token(token: str, config: datatypes.Settings) -> Tuple[Optional[str], Optional[str]]:
    try:
        text = base64.urlsafe_b64decode(token)
        signer = itsdangerous.Signer(secret_key=config.invitation_secret, sep=SEPARATOR)
        path, nonce = signer.unsign(text).decode().split(SEPARATOR, 1)
        return path, nonce
    except Exception as e: # pylint: disable=broad-except
        print(e)
        return None, None

def generate_random_nonce() -> str:
    return _generate_token(length=4)