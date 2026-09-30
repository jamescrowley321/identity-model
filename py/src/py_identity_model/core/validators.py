"""
Validation functions for py-identity-model.

This module contains all validation logic used by both sync and async implementations.
"""

from __future__ import annotations

import math
from typing import TYPE_CHECKING
from urllib.parse import urlparse

from ..exceptions import (
    ConfigurationException,
    DiscoveryException,
    DiscoveryHTTPSRequiredError,
    DiscoveryMissingFieldsError,
)
from .discovery_policy import DiscoveryPolicy, is_loopback


if TYPE_CHECKING:
    from .models import TokenValidationConfig


# ============================================================================
# Discovery Document Validation
# ============================================================================


def validate_issuer(issuer: str, *, require_https: bool = True) -> None:
    """Validate issuer format according to OpenID Connect Discovery 1.0 Section 3.

    Args:
        issuer: The issuer URL to validate.
        require_https: Whether to enforce HTTPS. Defaults to ``True``.
            Set to ``False`` only for local development/testing with HTTP
            providers.
    """
    if not issuer:
        raise ConfigurationException("Issuer parameter is required")

    parsed = urlparse(issuer)
    if require_https:
        if parsed.scheme != "https":
            raise DiscoveryHTTPSRequiredError("Issuer must use HTTPS scheme")
    elif parsed.scheme not in ("http", "https"):
        raise ConfigurationException("Issuer must use HTTP or HTTPS scheme")

    if parsed.query or parsed.fragment:
        raise ConfigurationException(
            "Issuer must not contain query or fragment components",
        )

    if not parsed.netloc:
        raise ConfigurationException("Issuer must be a valid URL with host")


def validate_https_url(url: str, parameter_name: str) -> None:
    """Validate that a URL uses HTTPS.

    This is the strict validator used when no :class:`DiscoveryPolicy` is
    provided.  To allow HTTP on loopback addresses for local development,
    use :func:`validate_https_url_with_policy` with an appropriate policy.
    """
    if not url:
        return  # Optional parameters can be None/empty

    parsed = urlparse(url)
    if not parsed.netloc:
        raise ConfigurationException(
            f"{parameter_name} must be an absolute URL with host",
        )

    if parsed.scheme != "https":
        raise DiscoveryHTTPSRequiredError(
            f"{parameter_name} must use HTTPS scheme",
        )


def validate_required_parameters(response_data: dict) -> None:
    """Validate required parameters per OpenID Connect Discovery 1.0 Section 3"""
    required_params = [
        "issuer",
        "response_types_supported",
        "subject_types_supported",
        "id_token_signing_alg_values_supported",
    ]

    missing_params = [
        param
        for param in required_params
        if param not in response_data or response_data[param] is None
    ]

    if missing_params:
        raise DiscoveryMissingFieldsError(
            f"Missing required parameters: {', '.join(missing_params)}",
            tuple(missing_params),
        )


def _validate_subject_types(subject_types: list) -> None:
    """Validate subject_types_supported values."""
    valid_subject_types = ["public", "pairwise"]
    for subject_type in subject_types:
        if subject_type not in valid_subject_types:
            raise DiscoveryException(
                f"Invalid subject type: {subject_type}. Must be 'public' or 'pairwise'",
            )


def _validate_response_type(response_type: str, valid_response_types: list) -> None:
    """Validate a single response type.

    Accepts all response types defined in OAuth 2.0 Multiple Response Types 1.0
    and OpenID Connect Core 1.0, including ``none``.
    """
    if response_type not in valid_response_types:
        # Allow custom response types that contain valid components
        components = response_type.split()
        valid_components = ["code", "id_token", "token"]
        if not all(comp in valid_components for comp in components):
            raise DiscoveryException(
                f"Invalid response type: {response_type}",
            )


def validate_parameter_values(response_data: dict) -> None:
    """Validate parameter values according to OpenID Connect specifications"""
    # Validate subject_types_supported values
    if response_data.get("subject_types_supported"):
        _validate_subject_types(response_data["subject_types_supported"])

    # Validate response_types_supported values
    if response_data.get("response_types_supported"):
        valid_response_types = [
            "code",
            "id_token",
            "token",
            "none",
            "code id_token",
            "code token",
            "id_token token",
            "code id_token token",
        ]
        for response_type in response_data["response_types_supported"]:
            _validate_response_type(response_type, valid_response_types)


# ============================================================================
# Token Validation Configuration
# ============================================================================


def validate_token_config(
    token_validation_config: TokenValidationConfig,
) -> None:
    """
    Validate token validation configuration.

    Args:
        token_validation_config: Configuration to validate

    Raises:
        ConfigurationException: If configuration is invalid
    """
    # Validate issuer: empty list is a fail-open security defect
    if isinstance(token_validation_config.issuer, list):
        if len(token_validation_config.issuer) == 0:
            raise ConfigurationException(
                "issuer must not be an empty list; omit or set to None to skip issuer validation",
            )
        # Validate list items are non-empty strings
        if not all(isinstance(i, str) and i for i in token_validation_config.issuer):
            raise ConfigurationException(
                "issuer list must contain only non-empty strings",
            )

    # Validate leeway: must be numeric (not bool), non-negative, and finite
    if token_validation_config.leeway is not None:
        if isinstance(token_validation_config.leeway, bool):
            raise ConfigurationException(
                "leeway must be a number, not a boolean",
            )
        if not isinstance(token_validation_config.leeway, (int, float)):
            raise ConfigurationException(
                "leeway must be a number",
            )
        if token_validation_config.leeway < 0:
            raise ConfigurationException(
                "leeway must be non-negative",
            )
        if math.isinf(token_validation_config.leeway) or math.isnan(
            token_validation_config.leeway
        ):
            raise ConfigurationException(
                "leeway must be a finite number",
            )

    if token_validation_config.perform_disco:
        return

    if not token_validation_config.key and not token_validation_config.algorithms:
        raise ConfigurationException(
            "TokenValidationConfig.key and TokenValidationConfig.algorithms are required if perform_disco is False",
        )


def validate_issuer_with_policy(issuer: str, policy: DiscoveryPolicy | None) -> None:
    """Validate issuer, respecting the discovery policy.

    When *policy* is ``None`` or ``policy.validate_issuer`` is ``True``,
    delegates to :func:`validate_issuer`. When validation is disabled
    by the policy, only checks that the issuer is non-empty.

    The ``allow_http_on_loopback`` policy flag is respected: if the
    issuer is an HTTP URL on a loopback address, HTTPS is not required.
    """
    if policy is None or policy.validate_issuer:
        # Determine effective require_https: allow HTTP on loopback
        effective_require_https = policy.require_https if policy else True
        if (
            effective_require_https
            and policy is not None
            and policy.allow_http_on_loopback
        ):
            parsed = urlparse(issuer)
            if parsed.scheme == "http" and is_loopback(parsed.hostname or ""):
                effective_require_https = False

        validate_issuer(issuer, require_https=effective_require_https)
        return

    if not issuer:
        raise ConfigurationException("Issuer parameter is required")


def validate_https_url_with_policy(
    url: str, parameter_name: str, policy: DiscoveryPolicy | None
) -> None:
    """Validate a URL, respecting the discovery policy.

    When *policy* is ``None``, delegates to :func:`validate_https_url`.
    When ``policy.require_https`` is ``False``, only checks URL structure.
    When ``policy.allow_http_on_loopback`` is ``True``, permits HTTP
    on loopback addresses.
    """
    if policy is None:
        validate_https_url(url, parameter_name)
        return

    if not policy.validate_endpoints:
        return

    if not url:
        return

    parsed = urlparse(url)
    if not parsed.netloc:
        raise ConfigurationException(
            f"{parameter_name} must be an absolute URL with host",
        )

    # Even when HTTPS is not required, only allow HTTP/HTTPS schemes
    # to prevent SSRF via ftp://, file://, etc.
    if parsed.scheme not in ("http", "https"):
        raise ConfigurationException(
            f"{parameter_name} must use HTTP or HTTPS scheme, got: {parsed.scheme}",
        )

    if not policy.require_https:
        return

    if parsed.scheme == "https":
        return

    if (
        parsed.scheme == "http"
        and policy.allow_http_on_loopback
        and is_loopback(parsed.hostname or "")
    ):
        return

    raise DiscoveryHTTPSRequiredError(
        f"{parameter_name} must use HTTPS (policy: require_https=True)",
    )


__all__ = [
    "validate_https_url",
    "validate_https_url_with_policy",
    "validate_issuer",
    "validate_issuer_with_policy",
    "validate_parameter_values",
    "validate_required_parameters",
    "validate_token_config",
]
