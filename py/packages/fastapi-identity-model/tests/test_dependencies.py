from types import SimpleNamespace

from fastapi import HTTPException
import pytest

from fastapi_identity_model import (
    get_claim_value,
    get_claim_values,
    get_claims,
    get_current_user,
    get_token,
    require_claim,
    require_scope,
)
from fastapi_identity_model.middleware import AuthChallenge
from py_identity_model import (
    AuthorizationScheme,
    ConfigurationException,
    to_principal,
)


pytestmark = pytest.mark.unit


def _request(**state) -> SimpleNamespace:
    return SimpleNamespace(state=SimpleNamespace(**state))


def _principal(**claims):
    return to_principal({"sub": "user-1", **claims})


# --- state-reading dependencies ---------------------------------------------


def test_get_current_user_returns_principal():
    principal = _principal()
    assert get_current_user(_request(user=principal)) is principal


def test_get_current_user_missing_raises_401():
    with pytest.raises(HTTPException) as exc:
        get_current_user(_request())
    assert (exc.value.status_code, exc.value.headers) == (
        401,
        {"WWW-Authenticate": 'Bearer realm="api"'},
    )


def test_missing_user_uses_the_middleware_challenge():
    challenge = AuthChallenge(realm="files")
    with pytest.raises(HTTPException) as exc:
        get_current_user(_request(auth_challenge=challenge))
    assert (exc.value.status_code, exc.value.headers) == (
        401,
        {"WWW-Authenticate": 'Bearer realm="files"'},
    )


def test_get_claims_and_token():
    assert get_claims(_request(claims={"sub": "x"})) == {"sub": "x"}
    assert get_token(_request(token="jwt")) == "jwt"


def test_get_claims_missing_raises_401():
    with pytest.raises(HTTPException) as exc:
        get_claims(_request())
    assert exc.value.status_code == 401


def test_get_token_missing_raises_401():
    with pytest.raises(HTTPException) as exc:
        get_token(_request())
    assert exc.value.status_code == 401


# --- claim extraction factories ---------------------------------------------


def test_get_claim_value():
    dep = get_claim_value("sub")
    assert dep(_principal()) == "user-1"
    assert get_claim_value("missing")(_principal()) is None


def test_get_claim_values():
    dep = get_claim_values("role")
    assert dep(_principal(role="admin")) == ["admin"]
    assert get_claim_values("missing")(_principal()) == []


# --- authorization factories ------------------------------------------------


def _forbidden(exc: pytest.ExceptionInfo) -> tuple:
    return exc.value.status_code, exc.value.headers


def test_require_claim_pass_and_fail():
    require_claim("role", "admin")(_request(), _principal(role="admin"))  # no raise

    with pytest.raises(HTTPException) as exc:
        require_claim("role", "admin")(_request(), _principal(role="user"))
    assert _forbidden(exc) == (
        403,
        {"WWW-Authenticate": 'Bearer error="insufficient_scope"'},
    )


def test_require_claim_presence_only():
    with pytest.raises(HTTPException) as exc:
        require_claim("role")(_request(), _principal())
    assert _forbidden(exc) == (
        403,
        {"WWW-Authenticate": 'Bearer error="insufficient_scope"'},
    )


def test_require_scope_space_delimited():
    require_scope("api.read")(_request(), {"scope": "openid api.read"})  # no raise

    with pytest.raises(HTTPException) as exc:
        require_scope("api.write")(_request(), {"scope": "openid api.read"})
    assert _forbidden(exc) == (
        403,
        {"WWW-Authenticate": 'Bearer error="insufficient_scope", scope="api.write"'},
    )


def test_require_scope_array_scp_claim():
    require_scope("api.read")(_request(), {"scp": ["api.read", "openid"]})  # no raise


def test_require_scope_no_scope_claim():
    with pytest.raises(HTTPException) as exc:
        require_scope("api.read")(_request(), {})
    assert _forbidden(exc) == (
        403,
        {"WWW-Authenticate": 'Bearer error="insufficient_scope", scope="api.read"'},
    )


def test_require_scope_uses_the_middleware_challenge():
    challenge = AuthChallenge(
        scheme=AuthorizationScheme.DPOP, realm="files", dpop_algs=("ES256",)
    )
    with pytest.raises(HTTPException) as exc:
        require_scope("api.read")(_request(auth_challenge=challenge), {})
    assert _forbidden(exc) == (
        403,
        {
            "WWW-Authenticate": 'DPoP realm="files", error="insufficient_scope", '
            'scope="api.read", algs="ES256"'
        },
    )


@pytest.mark.parametrize("scope", ["", "a b", 'a"b', "a\\b"])
def test_require_scope_rejects_a_value_that_is_not_one_scope_token(scope):
    with pytest.raises(ConfigurationException):
        require_scope(scope)
