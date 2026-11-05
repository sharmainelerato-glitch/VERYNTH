from dotenv import load_dotenv
load_dotenv()


import os
from functools import lru_cache
from urllib.parse import urlencode

import httpx
import jwt
from jwt import PyJWKClient
from jwt.exceptions import InvalidTokenError


REGION = os.getenv("AWS_REGION", "af-south-1")
USER_POOL_ID = os.getenv("COGNITO_USER_POOL_ID", "")
CLIENT_ID = os.getenv("COGNITO_CLIENT_ID", "")
DOMAIN = os.getenv("COGNITO_DOMAIN", "").rstrip("/")

ISSUER = (
    f"https://cognito-idp.{REGION}.amazonaws.com/"
    f"{USER_POOL_ID}"
)

JWKS_URL = f"{ISSUER}/.well-known/jwks.json"


@lru_cache(maxsize=1)
def jwks_client():
    return PyJWKClient(JWKS_URL)


def verify_access_token(token: str) -> dict:
    if not USER_POOL_ID or not CLIENT_ID:
        raise ValueError("Cognito is not configured")

    try:
        signing_key = jwks_client().get_signing_key_from_jwt(token)

        claims = jwt.decode(
            token,
            signing_key.key,
            algorithms=["RS256"],
            issuer=ISSUER,
            options={"verify_aud": False},
        )

        if claims.get("token_use") != "access":
            raise InvalidTokenError("Not an access token")

        if claims.get("client_id") != CLIENT_ID:
            raise InvalidTokenError("Invalid client")

        if not claims.get("sub"):
            raise InvalidTokenError("Missing subject")

        return claims

    except InvalidTokenError as exc:
        raise ValueError("Invalid Cognito access token") from exc


def authorization_url(
    redirect_uri: str,
    state: str,
    code_challenge: str,
) -> str:
    if not DOMAIN or not CLIENT_ID:
        raise ValueError("Cognito is not configured")

    query = urlencode({
        "response_type": "code",
        "client_id": CLIENT_ID,
        "redirect_uri": redirect_uri,
        "scope": "openid email profile",
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
    })

    return f"{DOMAIN}/oauth2/authorize?{query}"


async def exchange_code(
    code: str,
    redirect_uri: str,
    code_verifier: str,
) -> dict:
    if not DOMAIN or not CLIENT_ID:
        raise ValueError("Cognito is not configured")

    async with httpx.AsyncClient(timeout=15) as client:
        response = await client.post(
            f"{DOMAIN}/oauth2/token",
            data={
                "grant_type": "authorization_code",
                "client_id": CLIENT_ID,
                "code": code,
                "redirect_uri": redirect_uri,
                "code_verifier": code_verifier,
            },
            headers={
                "Content-Type": "application/x-www-form-urlencoded"
            },
        )

        response.raise_for_status()
        return response.json()

