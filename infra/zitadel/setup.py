"""Provision the Zitadel fixture and write its ``TEST_*`` profile.

Runs as the ``zitadel-setup`` compose service, authenticated with the
bootstrap machine user's PAT. Zitadel generates client IDs and secrets, so the
profile is written at provisioning time instead of being committed. The
process then idles: the service's healthcheck (profile exists) is what lets
``docker compose up --wait`` gate on provisioning.
"""

from __future__ import annotations

import base64
from http import HTTPStatus
import json
import os
from pathlib import Path
import signal
import sys
import threading
import time
from typing import Any
from urllib import error, parse, request


PROJECT_NAME = "py-identity-model"
SERVICE_USER = "py-identity-model-client"
AUTH_CODE_APP = "test-auth-code"
PKCE_PUBLIC_APP = "test-pkce-public"
DEVICE_APP = "test-device"
TEST_USER = "test-user"
TEST_USER_PASSWORD = "test"  # local fixture only; AuthCodeFlowConfig default
SCOPE = "openid"

APPLICATION_CREATE = "/zitadel.application.v2.ApplicationService/CreateApplication"

HTTP_TIMEOUT_SECONDS = 10
TOKEN_READY_ATTEMPTS = 30
TOKEN_READY_INTERVAL_SECONDS = 1


class SetupError(Exception):
    """Provisioning failed."""


class ApiError(SetupError):
    """The Zitadel API rejected a request."""

    def __init__(self, path: str, status: int, body: str) -> None:
        super().__init__(f"{path}: HTTP {status}: {body}")
        self.status = status


class Zitadel:
    """Minimal JSON client; ``Host`` is pinned so the instance resolves."""

    def __init__(self, api_url: str, issuer: str, pat: str) -> None:
        self._api_url = api_url.rstrip("/")
        self._host = parse.urlsplit(issuer).netloc
        self._pat = pat

    def _send(self, req: request.Request, path: str) -> dict[str, Any]:
        req.add_header("Host", self._host)
        try:
            with request.urlopen(req, timeout=HTTP_TIMEOUT_SECONDS) as resp:
                return json.loads(resp.read() or b"{}")
        except error.HTTPError as exc:
            raise ApiError(path, exc.code, exc.read().decode(errors="replace")) from exc
        except error.URLError as exc:
            raise SetupError(f"{path}: {exc.reason}") from exc

    def call(self, path: str, body: dict[str, Any]) -> dict[str, Any]:
        req = request.Request(
            f"{self._api_url}{path}",
            data=json.dumps(body).encode(),
            headers={
                "Authorization": f"Bearer {self._pat}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        return self._send(req, path)

    def client_credentials_token(self, client_id: str, client_secret: str) -> str:
        path = "/oauth/v2/token"
        basic = base64.b64encode(f"{client_id}:{client_secret}".encode()).decode()
        req = request.Request(
            f"{self._api_url}{path}",
            data=parse.urlencode(
                {"grant_type": "client_credentials", "scope": SCOPE}
            ).encode(),
            headers={"Authorization": f"Basic {basic}"},
            method="POST",
        )
        return self._send(req, path)["access_token"]


def _oidc_app(
    zitadel: Zitadel, project_id: str, name: str, redirect_uri: str, *, public: bool
) -> dict[str, Any]:
    created = zitadel.call(
        APPLICATION_CREATE,
        {
            "projectId": project_id,
            "name": name,
            "oidcConfiguration": {
                "redirectUris": [redirect_uri],
                "postLogoutRedirectUris": [redirect_uri],
                "responseTypes": ["OIDC_RESPONSE_TYPE_CODE"],
                "grantTypes": [
                    "OIDC_GRANT_TYPE_AUTHORIZATION_CODE",
                    "OIDC_GRANT_TYPE_REFRESH_TOKEN",
                ],
                "applicationType": (
                    "OIDC_APP_TYPE_USER_AGENT" if public else "OIDC_APP_TYPE_WEB"
                ),
                "authMethodType": (
                    "OIDC_AUTH_METHOD_TYPE_NONE"
                    if public
                    else "OIDC_AUTH_METHOD_TYPE_BASIC"
                ),
                # Allows the plain-http redirect URI.
                "developmentMode": True,
                "accessTokenType": "OIDC_TOKEN_TYPE_JWT",
            },
        },
    )
    return created["oidcConfiguration"]


def provision(zitadel: Zitadel, issuer: str) -> dict[str, str]:
    orgs = zitadel.call("/v2/organizations/_search", {})["result"]
    if len(orgs) != 1:
        raise SetupError(f"expected the single first-instance org, found {len(orgs)}")
    (org,) = orgs
    org_id = org["id"]

    project_id = zitadel.call(
        "/zitadel.project.v2.ProjectService/CreateProject",
        {"organizationId": org_id, "name": PROJECT_NAME},
    )["projectId"]
    # On the issuer's own port, so a followed redirect lands on a live listener.
    redirect_uri = f"{issuer}/callback"
    auth_code = _oidc_app(
        zitadel, project_id, AUTH_CODE_APP, redirect_uri, public=False
    )
    pkce_public = _oidc_app(
        zitadel, project_id, PKCE_PUBLIC_APP, redirect_uri, public=True
    )
    device = zitadel.call(
        APPLICATION_CREATE,
        {
            "projectId": project_id,
            "name": DEVICE_APP,
            "oidcConfiguration": {
                "responseTypes": ["OIDC_RESPONSE_TYPE_CODE"],
                "grantTypes": ["OIDC_GRANT_TYPE_DEVICE_CODE"],
                "applicationType": "OIDC_APP_TYPE_NATIVE",
                "authMethodType": "OIDC_AUTH_METHOD_TYPE_NONE",
                "accessTokenType": "OIDC_TOKEN_TYPE_JWT",
            },
        },
    )["oidcConfiguration"]

    service_user_id = zitadel.call(
        "/v2/users/new",
        {
            "organizationId": org_id,
            "username": SERVICE_USER,
            "machine": {
                "name": SERVICE_USER,
                "accessTokenType": "ACCESS_TOKEN_TYPE_JWT",
            },
        },
    )["id"]
    service_secret = zitadel.call(f"/v2/users/{service_user_id}/secret", {})[
        "clientSecret"
    ]

    test_user_id = zitadel.call(
        "/v2/users/new",
        {
            "organizationId": org_id,
            "username": TEST_USER,
            "human": {
                "profile": {"givenName": "Test", "familyName": "User"},
                "email": {"email": "test@example.com", "isVerified": True},
                "password": {"password": TEST_USER_PASSWORD, "changeRequired": False},
            },
        },
    )["id"]
    # Suppresses the login UI's 2-factor setup prompt.
    zitadel.call(f"/v2/users/{test_user_id}/mfa_init_skipped", {})

    return {
        "TEST_DISCO_ADDRESS": f"{issuer}/.well-known/openid-configuration",
        "TEST_JWKS_ADDRESS": f"{issuer}/oauth/v2/keys",
        "TEST_CLIENT_ID": SERVICE_USER,
        "TEST_CLIENT_SECRET": service_secret,
        "TEST_SCOPE": SCOPE,
        "TEST_AUDIENCE": "",
        "TEST_REQUIRE_HTTPS": "false",
        "TEST_AUTH_CODE_CLIENT_ID": auth_code["clientId"],
        "TEST_AUTH_CODE_CLIENT_SECRET": auth_code["clientSecret"],
        "TEST_AUTH_CODE_REDIRECT_URI": redirect_uri,
        "TEST_PKCE_PUBLIC_CLIENT_ID": pkce_public["clientId"],
        "TEST_PKCE_PUBLIC_REDIRECT_URI": redirect_uri,
        "TEST_DEVICE_CLIENT_ID": device["clientId"],
        "TEST_REDIRECT_URI": redirect_uri,
    }


def mints_token(zitadel: Zitadel, profile: dict[str, str]) -> bool:
    try:
        zitadel.client_credentials_token(
            profile["TEST_CLIENT_ID"], profile["TEST_CLIENT_SECRET"]
        )
    except ApiError as exc:
        if exc.status in (HTTPStatus.BAD_REQUEST, HTTPStatus.UNAUTHORIZED):
            return False
        raise
    return True


def wait_until_mintable(zitadel: Zitadel, profile: dict[str, str]) -> None:
    """Block until the new service user is visible to the token endpoint."""
    for _ in range(TOKEN_READY_ATTEMPTS):
        if mints_token(zitadel, profile):
            return
        time.sleep(TOKEN_READY_INTERVAL_SECONDS)
    raise SetupError("service user cannot mint a client_credentials token")


def read_profile(path: Path) -> dict[str, str]:
    if not path.is_file():
        return {}
    pairs = (
        line.split("=", 1) for line in path.read_text().splitlines() if "=" in line
    )
    return dict(pairs)


def write_profile(path: Path, profile: dict[str, str]) -> None:
    tmp = path.with_name(f"{path.name}.tmp")
    tmp.write_text("".join(f"{key}={value}\n" for key, value in profile.items()))
    tmp.replace(path)


def idle_until_stopped() -> None:
    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    stop.wait()


def main() -> None:
    issuer = os.environ["ZITADEL_ISSUER"].rstrip("/")
    out = Path(os.environ["ZITADEL_ENV_OUT"])
    pat = Path(os.environ["ZITADEL_PAT_FILE"]).read_text().strip()
    zitadel = Zitadel(os.environ["ZITADEL_API_URL"], issuer, pat)

    existing = read_profile(out)
    if existing.get("TEST_CLIENT_SECRET") and mints_token(zitadel, existing):
        print(f"already provisioned; keeping {out}", flush=True)
    else:
        out.unlink(missing_ok=True)
        profile = provision(zitadel, issuer)
        wait_until_mintable(zitadel, profile)
        write_profile(out, profile)
        print(f"provisioned; wrote {out}", flush=True)
    idle_until_stopped()


if __name__ == "__main__":
    try:
        main()
    except SetupError as exc:
        sys.exit(f"zitadel-setup: {exc}")
