"""Public request, options and result types are frozen and keyword-only."""

import dataclasses
import inspect

import pytest

from py_identity_model.core import (
    authorize_response,
    config,
    discovery_policy,
    dpop_verify,
    fapi,
    models,
    state_validation,
    token_binding,
    trust_scope,
)
from py_identity_model.exceptions import (
    FailedResponseAccessError,
    SuccessfulResponseAccessError,
)


_NAMED = [
    authorize_response.AuthorizeCallbackResponse,
    config.ConfigIssue,
    config.HTTPConfig,
    config.CacheConfig,
    discovery_policy.DiscoveryPolicy,
    dpop_verify.DPoPProof,
    dpop_verify.DPoPProofRequest,
    dpop_verify.DPoPVerificationOptions,
    fapi.FAPI2ClientProfile,
    fapi.FAPIValidationResult,
    fapi.FAPIViolation,
    state_validation.StateValidationResult,
    token_binding.TokenPresentation,
    trust_scope.TrustScope,
]

_MODELS = [
    cls
    for _, cls in inspect.getmembers(models, inspect.isclass)
    if dataclasses.is_dataclass(cls) and cls.__module__ == models.__name__
]

_SHAPED = sorted({*_NAMED, *_MODELS}, key=lambda cls: cls.__qualname__)


@pytest.mark.unit
@pytest.mark.parametrize("cls", _SHAPED, ids=lambda cls: cls.__qualname__)
def test_frozen(cls: type) -> None:
    assert cls.__dataclass_params__.frozen is True  # type: ignore[attr-defined]


@pytest.mark.unit
@pytest.mark.parametrize("cls", _SHAPED, ids=lambda cls: cls.__qualname__)
def test_every_parameter_is_keyword_only(cls: type) -> None:
    positional = [
        name
        for name, param in inspect.signature(cls).parameters.items()
        if param.kind is not inspect.Parameter.KEYWORD_ONLY
    ]
    assert positional == []


@pytest.mark.unit
def test_models_module_is_covered() -> None:
    assert {cls.__qualname__ for cls in _MODELS} >= {
        "AuthorizationCodeTokenRequest",
        "DiscoveryDocumentRequest",
        "MtlsClientAuth",
        "PrivateKeyJwt",
        "PushedAuthorizationRequest",
        "RefreshTokenRequest",
        "TokenValidationConfig",
    }


@pytest.mark.unit
def test_replace_runs_validation() -> None:
    cfg = models.TokenValidationConfig(perform_disco=True)
    with pytest.raises(dataclasses.FrozenInstanceError):
        cfg.leeway = 30  # type: ignore[misc]
    assert dataclasses.replace(cfg, leeway=30) == models.TokenValidationConfig(
        perform_disco=True, leeway=30
    )


@pytest.mark.unit
@pytest.mark.parametrize(
    ("response", "error"),
    [
        (
            models.ClientCredentialsTokenResponse(
                is_successful=True, token={"access_token": "at"}
            ),
            SuccessfulResponseAccessError,
        ),
        (
            models.ClientCredentialsTokenResponse(is_successful=False, error="denied"),
            FailedResponseAccessError,
        ),
    ],
    ids=["successful", "failed"],
)
def test_responses_are_read_only(response, error) -> None:
    with pytest.raises(dataclasses.FrozenInstanceError):
        response.is_successful = False  # type: ignore[misc]
    with pytest.raises(error):
        dataclasses.replace(response)
