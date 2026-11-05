
import base64
import hashlib
import os
import secrets
from urllib.parse import urlencode

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import RedirectResponse

from app.cognito_auth import (
    authorization_url,
    exchange_code,
    verify_access_token,
)

from app.user_sessions import (
    COOKIE_NAME,
    SESSION_SECONDS,
    create_session,
    read_session,
)
from app.user_profiles import get_or_create_user

router = APIRouter()

CALLBACK_URI = os.getenv("VERYNTH_COGNITO_CALLBACK_URL", "http://127.0.0.1:8000/auth/callback")
SECURE_COOKIES = CALLBACK_URI.startswith("https://")
TEMP_COOKIE = "verynth_oauth_state"
VERIFIER_COOKIE = "verynth_oauth_verifier"


def code_challenge(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode()).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


@router.get("/auth/cognito/login")
async def cognito_login():
    state = secrets.token_urlsafe(32)
    verifier = secrets.token_urlsafe(64)

    url = authorization_url(
        CALLBACK_URI,
        state,
        code_challenge(verifier),
    )

    response = RedirectResponse(url, status_code=302)

    for name, value in [
        (TEMP_COOKIE, state),
        (VERIFIER_COOKIE, verifier),
    ]:
        response.set_cookie(
            name,
            value,
            httponly=True,
            secure=SECURE_COOKIES,
            samesite="lax",
            max_age=600,
        )

    return response


@router.get("/auth/callback")
async def cognito_callback(request: Request):
    code = request.query_params.get("code")
    state = request.query_params.get("state")

    expected_state = request.cookies.get(TEMP_COOKIE)
    verifier = request.cookies.get(VERIFIER_COOKIE)


    if not code or not state or not expected_state or not verifier:
        raise HTTPException(400, "Missing OAuth callback information")

    if not secrets.compare_digest(state, expected_state):
        raise HTTPException(400, "OAuth state mismatch")

    tokens = await exchange_code(
        code,
        CALLBACK_URI,
        verifier,
    )

    claims = verify_access_token(tokens["access_token"])
    get_or_create_user(claims['sub'])
    session_token = create_session(claims)

    # Do not grant access to the existing owner-only APIs.
    # The next stage will establish a separate user session
    # and enforce ownership on all account-specific resources.
    response = RedirectResponse(
        "/auth/cognito/complete",
        status_code=303,
    )

    response.set_cookie(
        COOKIE_NAME,
        session_token,
        httponly=True,
        secure=SECURE_COOKIES,
        samesite="lax",
        max_age=SESSION_SECONDS,
        path="/",
    )
    response.delete_cookie(TEMP_COOKIE)
    response.delete_cookie(VERIFIER_COOKIE)

    return response


@router.get("/auth/cognito/complete")
async def cognito_complete(request: Request):
    session = read_session(request.cookies.get(COOKIE_NAME))

    if not session:
        return RedirectResponse("/auth/cognito/login", status_code=303)

    from fastapi.responses import HTMLResponse
    return HTMLResponse("""
    <!doctype html>
    <html lang="en">
    <head>
      <meta charset="utf-8">
      <meta name="viewport" content="width=device-width,initial-scale=1">
      <title>VERYNTH | Welcome</title>
      <style>
        body { margin:0; min-height:100vh; display:grid; place-items:center;
               background:#071c24; color:#e9f8f6; font-family:system-ui,sans-serif; }
        main { width:min(440px,90%); padding:36px; text-align:center;
               border:1px solid #24515a; border-radius:24px; background:#102b34; }
        h1 { color:#61d8cc; }
        p { line-height:1.7; color:#bdd4d5; }
        a { display:inline-block; margin-top:16px; padding:12px 24px;
            border-radius:12px; background:#168e8b; color:white; text-decoration:none; }
      </style>
    </head>
    <body>
      <main>
        <h1>✦ VERYNTH</h1>
        <h2>You're signed in</h2>
        <p>Your account is authenticated successfully.</p>
        <p>Your personal workspace is being prepared.
           Your account does not have access to the private owner workspace.</p>
        <p>Account authentication is active.</p>
        <a href="/auth/cognito/me">View account status</a>
        <form method="post" action="/auth/cognito/logout">
          <button type="submit" style="margin-top:14px;padding:12px 24px;border:0;border-radius:12px;cursor:pointer;">
            Sign out
          </button>
        </form>
      </main>
    </body>
    </html>
    """, headers={"Cache-Control": "no-store"})


@router.get("/auth/cognito/me")
async def cognito_me(request: Request):
    session = read_session(request.cookies.get(COOKIE_NAME))

    if not session:
        return {
            "authenticated": False,
            "user": None,
        }

    return {
        "authenticated": True,
        "user": {
            "id": session["sub"],
        },
    }


@router.post("/auth/cognito/logout")
async def cognito_logout(request: Request):
    from urllib.parse import urlencode
    from fastapi.responses import RedirectResponse

    origin = request.headers.get("origin")
    if origin and origin != 'null':
        from urllib.parse import urlsplit
        parsed = urlsplit(origin)
        expected_origin = os.environ["VERYNTH_COGNITO_CALLBACK_URL"]
        expected = urlsplit(expected_origin)

        if parsed.scheme != expected.scheme or parsed.netloc != expected.netloc:
            raise HTTPException(403, "Cross-origin sign-out refused")

    domain = os.environ["COGNITO_DOMAIN"].rstrip("/")
    client_id = os.environ["COGNITO_CLIENT_ID"]
    callback = os.environ["VERYNTH_COGNITO_CALLBACK_URL"]

    from urllib.parse import urlsplit
    parsed = urlsplit(callback)
    signed_out_url = f"{parsed.scheme}://{parsed.netloc}/"

    logout_url = (
        domain + "/logout?" +
        urlencode({
            "client_id": client_id,
            "logout_uri": signed_out_url,
        })
    )

    response = RedirectResponse(logout_url, status_code=303)
    response.delete_cookie(COOKIE_NAME, path="/")
    return response
