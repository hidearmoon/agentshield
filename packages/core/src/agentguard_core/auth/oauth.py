"""OAuth 2.0 authentication for the management console.

Supports Authorization Code flow with external IdPs (Okta, Auth0, Keycloak, etc.).
Issues JWT access tokens after successful OAuth callback.

Flow:
1. Frontend redirects to GET /auth/login → redirect to IdP
2. IdP authenticates user, redirects to GET /auth/callback?code=xxx
3. Backend exchanges code for IdP tokens, creates/updates local user
4. Backend issues JWT access token to frontend
5. Frontend uses JWT in Authorization: Bearer header for all API calls
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass
from urllib.parse import urlencode

import httpx
from fastapi import APIRouter, Request, HTTPException
from fastapi.responses import RedirectResponse
from jose import jwt

from agentguard_core.config import settings

router = APIRouter(prefix="/auth", tags=["auth"])


@dataclass
class OAuthConfig:
    """OAuth 2.0 provider configuration."""

    provider: str  # okta | auth0 | keycloak | google
    client_id: str
    client_secret: str
    authorization_url: str
    token_url: str
    userinfo_url: str
    redirect_uri: str
    scopes: list[str]


# Load from settings — in production these come from env vars
def _get_oauth_config() -> OAuthConfig:
    return OAuthConfig(
        provider=settings.oauth_provider if hasattr(settings, "oauth_provider") else "generic",
        client_id=settings.oauth_client_id if hasattr(settings, "oauth_client_id") else "",
        client_secret=settings.oauth_client_secret if hasattr(settings, "oauth_client_secret") else "",
        authorization_url=settings.oauth_authorization_url if hasattr(settings, "oauth_authorization_url") else "",
        token_url=settings.oauth_token_url if hasattr(settings, "oauth_token_url") else "",
        userinfo_url=settings.oauth_userinfo_url if hasattr(settings, "oauth_userinfo_url") else "",
        redirect_uri=settings.oauth_redirect_uri
        if hasattr(settings, "oauth_redirect_uri")
        else "http://localhost:8080/auth/callback",
        scopes=["openid", "email", "profile"],
    )


# In-memory state store for CSRF protection (use Redis in production)
_oauth_states: dict[str, float] = {}
_MAX_OAUTH_STATES = 1000  # Prevent memory exhaustion from unauthenticated login spam


def _cleanup_expired_states() -> None:
    """Remove expired OAuth states to prevent memory leak."""
    now = time.time()
    expired = [s for s, t in _oauth_states.items() if now - t > 600]
    for s in expired:
        del _oauth_states[s]
    # Hard cap
    while len(_oauth_states) > _MAX_OAUTH_STATES:
        oldest = min(_oauth_states, key=_oauth_states.get)  # type: ignore
        del _oauth_states[oldest]


# JWT settings
JWT_SECRET = settings.policy_signing_key or "dev-jwt-secret-change-in-production"
JWT_ALGORITHM = "HS256"
JWT_EXPIRY_SECONDS = 86400  # 24 hours


def create_access_token(user_id: str, email: str, role: str) -> str:
    """Create a JWT access token for an authenticated user."""
    now = time.time()
    payload = {
        "sub": user_id,
        "email": email,
        "role": role,
        "iat": int(now),
        "exp": int(now + JWT_EXPIRY_SECONDS),
        "iss": "agentguard",
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def verify_access_token(token: str) -> dict:
    """Verify and decode a JWT access token. Raises on invalid/expired."""
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")


@router.get("/login")
async def login(request: Request) -> RedirectResponse:
    """Initiate OAuth 2.0 Authorization Code flow."""
    config = _get_oauth_config()
    if not config.authorization_url:
        raise HTTPException(status_code=501, detail="OAuth not configured")

    _cleanup_expired_states()
    state = str(uuid.uuid4())
    _oauth_states[state] = time.time()

    params = {
        "response_type": "code",
        "client_id": config.client_id,
        "redirect_uri": config.redirect_uri,
        "scope": " ".join(config.scopes),
        "state": state,
    }
    query = urlencode(params)
    return RedirectResponse(url=f"{config.authorization_url}?{query}")


@router.get("/callback")
async def callback(code: str, state: str) -> dict:
    """Handle OAuth 2.0 callback — exchange code for tokens."""
    # Validate state (CSRF protection)
    if state not in _oauth_states:
        raise HTTPException(status_code=400, detail="Invalid OAuth state")

    state_time = _oauth_states.pop(state)
    if time.time() - state_time > 600:  # 10 minute expiry
        raise HTTPException(status_code=400, detail="OAuth state expired")

    config = _get_oauth_config()

    # Exchange authorization code for tokens
    async with httpx.AsyncClient() as client:
        token_response = await client.post(
            config.token_url,
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": config.redirect_uri,
                "client_id": config.client_id,
                "client_secret": config.client_secret,
            },
        )

    if token_response.status_code != 200:
        raise HTTPException(status_code=502, detail="Token exchange failed")

    tokens = token_response.json()
    access_token = tokens.get("access_token")

    # Fetch user info from IdP
    async with httpx.AsyncClient() as client:
        userinfo_response = await client.get(
            config.userinfo_url,
            headers={"Authorization": f"Bearer {access_token}"},
        )

    if userinfo_response.status_code != 200:
        raise HTTPException(status_code=502, detail="Failed to fetch user info")

    userinfo = userinfo_response.json()
    email = userinfo.get("email", "")
    name = userinfo.get("name", email)
    sub = userinfo.get("sub", "")

    # Create or update local user (in production, query/upsert database)
    user_id = sub or str(uuid.uuid4())
    role = "viewer"  # Default role, admin assigns higher roles

    # Issue our own JWT
    jwt_token = create_access_token(user_id=user_id, email=email, role=role)

    return {
        "access_token": jwt_token,
        "token_type": "bearer",
        "expires_in": JWT_EXPIRY_SECONDS,
        "user": {
            "id": user_id,
            "email": email,
            "name": name,
            "role": role,
        },
    }


@router.post("/token/refresh")
async def refresh_token(request: Request) -> dict:
    """Refresh an expiring JWT token."""
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Bearer token required")

    token = auth_header[7:]
    # Allow refresh of tokens that will expire within 1 hour
    try:
        payload = jwt.decode(
            token,
            JWT_SECRET,
            algorithms=[JWT_ALGORITHM],
            options={"verify_exp": False},
        )
    except jwt.JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

    exp = payload.get("exp", 0)
    if time.time() - exp > 86400:  # Don't refresh tokens expired more than 24h ago
        raise HTTPException(status_code=401, detail="Token too old to refresh")

    new_token = create_access_token(
        user_id=payload["sub"],
        email=payload["email"],
        role=payload["role"],
    )

    return {
        "access_token": new_token,
        "token_type": "bearer",
        "expires_in": JWT_EXPIRY_SECONDS,
    }
