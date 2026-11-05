import os
import time

from cryptography.fernet import Fernet, InvalidToken
from dotenv import load_dotenv

load_dotenv()

SESSION_KEY = os.getenv("VERYNTH_SESSION_KEY", "")
COOKIE_NAME = "verynth_user_session"
SESSION_SECONDS = 3600


def _cipher():
    if not SESSION_KEY:
        raise RuntimeError("VERYNTH_SESSION_KEY is not configured")
    return Fernet(SESSION_KEY.encode())


def create_session(claims: dict) -> str:
    import json

    subject = claims.get("sub")
    if not subject:
        raise ValueError("Missing Cognito user ID")

    expires = min(
        int(time.time()) + SESSION_SECONDS,
        int(claims.get("exp", 0)),
    )

    if expires <= time.time():
        raise ValueError("Cognito token has expired")

    payload = {
        "sub": subject,
        "exp": expires,
    }

    return _cipher().encrypt(
        json.dumps(payload).encode()
    ).decode()


def read_session(value: str | None) -> dict | None:
    import json

    if not value:
        return None

    try:
        payload = json.loads(
            _cipher().decrypt(
                value.encode(),
                ttl=SESSION_SECONDS,
            )
        )

        if not isinstance(payload, dict):
            return None

        if not isinstance(payload.get("sub"), str):
            return None

        if payload.get("exp", 0) <= time.time():
            return None

        return payload

    except (InvalidToken, ValueError, TypeError, KeyError):
        return None
