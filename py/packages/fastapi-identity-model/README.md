# fastapi-identity-model

OIDC/OAuth2 integration for [FastAPI](https://fastapi.tiangolo.com/), built on
[`py-identity-model`](https://pypi.org/project/py-identity-model/) — an OpenID
Foundation–certified relying-party library.

It gives you two composable pieces:

| Piece | Use case |
|-------|----------|
| **`TokenValidationMiddleware`** + `Depends` helpers | Protect an **API / resource server** that receives `Authorization: Bearer <token>` |
| **`build_oidc_router`** | Add a browser **login flow** (authorization code + PKCE) to your app (relying party) |

## Install

```bash
pip install fastapi-identity-model
# with a server for the demo:
pip install "fastapi-identity-model[server]"
```

## Resource server — validate incoming Bearer tokens

```python
from fastapi import FastAPI, Depends
from fastapi_identity_model import (
    TokenValidationMiddleware, OIDCSettings, get_current_user, require_scope,
)

settings = OIDCSettings(
    discovery_url="https://op.example.com/.well-known/openid-configuration",
    client_id="<client_id>",
)
app = FastAPI()
app.add_middleware(
    TokenValidationMiddleware,
    discovery_url=settings.discovery_url,
    audience=settings.audience,
    excluded_paths=settings.excluded_paths,
)

@app.get("/api/me")
async def me(user = Depends(get_current_user)):
    return {"sub": user.identity.name, "authenticated": user.identity.is_authenticated}

@app.get("/api/data", dependencies=[Depends(require_scope("api.read"))])
async def data():
    return {"data": "protected"}
```

The middleware validates the token (signature, issuer, audience, expiry) via
`py-identity-model` and attaches a `ClaimsPrincipal` to `request.state.user`.
Invalid tokens → **401**; an unexpected server-side failure → **500** (never
masked as a 401).

## Relying party — browser login flow

```python
import os

from fastapi import FastAPI, Request
from starlette.middleware.sessions import SessionMiddleware
from fastapi_identity_model import OIDCSettings, build_oidc_router

settings = OIDCSettings(
    discovery_url="https://api.descope.com/v1/apps/<project_id>/.well-known/openid-configuration",
    client_id="<client_id>",
    redirect_uri="http://localhost:8000/auth/callback",
    scope="openid profile email",
)

app = FastAPI()
# Use a strong secret from the environment — never a committed literal, or
# anyone can forge a session cookie. same_site="lax" is required so the
# provider's redirect back to /auth/callback carries the session cookie.
app.add_middleware(
    SessionMiddleware,
    secret_key=os.environ["SESSION_SECRET"],
    same_site="lax",
    https_only=True,  # behind TLS
)
app.include_router(build_oidc_router(settings), prefix="/auth")

@app.get("/me")
async def me(request: Request):
    return request.session.get("oidc", {})   # {"sub", "claims", "userinfo"} after login
```

Routes added: `GET /auth/login` → provider, `GET /auth/callback` (code exchange,
ID-token validation, **nonce check**, UserInfo `sub` verification), `POST /auth/logout`.

### Session & security

The router uses Starlette's `SessionMiddleware`, which **signs but does not
encrypt** the cookie. Stored identity claims are tamper-proof but readable by the
client. Raw tokens are stored **only** when you pass `build_oidc_router(settings,
store_tokens=True)` — enable that only with an encrypted or server-side session
store. For production, back the session with a server-side store.

## Configuration

The package reads no environment variables. Construct `OIDCSettings` yourself,
or build it from the environment with the optional helper:

```python
from fastapi_identity_model.config_helpers import oidc_settings_from_env

settings = oidc_settings_from_env()        # OIDC_DISCOVERY_URL, OIDC_CLIENT_ID, OIDC_REDIRECT_URI, ...
settings = oidc_settings_from_env("APP_")  # APP_DISCOVERY_URL, APP_CLIENT_ID, ...
```

`DISCOVERY_URL` and `CLIENT_ID` are required. `EXCLUDED_PATHS` is a
comma-separated list. Every other variable (`REDIRECT_URI`, `CLIENT_SECRET`,
`SCOPE`, `AUDIENCE`, `POST_LOGIN_REDIRECT`, `POST_LOGOUT_REDIRECT`) falls back
to the `OIDCSettings` default when unset.

HTTP settings (timeouts, retries, CA bundle, cache TTLs) belong to the
`py-identity-model` `Config`. Build an `AsyncHTTPClient` from it and pass it
as `http_client=` to `TokenValidationMiddleware`, `build_oidc_router`,
`build_ws_authenticator` and `TokenManager`. Each provider call then uses that
client and its caches. Without it, the library default client is used.

```python
from py_identity_model import Config
from py_identity_model.aio import AsyncHTTPClient

http_client = AsyncHTTPClient(config=Config(http_timeout=10.0))
app.add_middleware(
    TokenValidationMiddleware,
    discovery_url=settings.discovery_url,
    audience=settings.audience,
    http_client=http_client,
)
app.include_router(build_oidc_router(settings, http_client=http_client), prefix="/auth")
```

Close the client on shutdown (`await http_client.close()`, e.g. in the app's
lifespan).

## Token refresh

```python
from fastapi_identity_model import TokenManager

tm = TokenManager(discovery_url=..., client_id=..., client_secret=...)
tm.set_tokens(access_token=..., refresh_token=..., expires_in=3600)
access = await tm.get_access_token()   # auto-refreshes shortly before expiry
```

## License

Apache-2.0 — see the repository `LICENSE`.
