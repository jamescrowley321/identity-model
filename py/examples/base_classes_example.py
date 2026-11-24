"""
Base Request/Response Classes Examples for py-identity-model

Demonstrates how BaseRequest and BaseResponse provide a consistent
interface across all API operations.
"""

from py_identity_model import (
    BaseRequest,
    BaseResponse,
    ClientCredentialsTokenRequest,
    DiscoveryDocumentRequest,
    JwksRequest,
    UserInfoRequest,
    get_discovery_document,
    get_jwks,
)
from py_identity_model.sync.token_client import (
    request_client_credentials_token,
)
from py_identity_model.sync.userinfo import get_userinfo


# Dispatch table mapping request types to their handler functions
_REQUEST_HANDLERS: dict = {
    JwksRequest: get_jwks,
    ClientCredentialsTokenRequest: request_client_credentials_token,
    UserInfoRequest: get_userinfo,
}


def polymorphic_fetch(request: BaseRequest) -> BaseResponse:
    """Demonstrate polymorphic request handling.

    Any request that inherits from BaseRequest can be dispatched
    to its corresponding handler.
    """
    print(f"  Fetching: {request.address}")

    handler = _REQUEST_HANDLERS.get(type(request))
    if handler is None:
        msg = f"Unknown request type: {type(request).__name__}"
        raise TypeError(msg)
    return handler(request)


def check_response(response: BaseResponse, label: str) -> None:
    """Demonstrate uniform response checking via BaseResponse."""
    if response.is_successful:
        print(f"  {label}: success")
    else:
        print(f"  {label}: failed — {response.error}")


def main():
    """Run base class examples."""
    print("\n" + "=" * 60)
    print("BASE REQUEST/RESPONSE EXAMPLES")
    print("=" * 60)

    issuer = "https://demo.duendesoftware.com"

    # Discovery is addressed by the issuer, not a URL, so it is fetched
    # directly; its response still shares the BaseResponse interface.
    disco_resp = get_discovery_document(DiscoveryDocumentRequest(issuer=issuer))
    check_response(disco_resp, "Discovery")

    if disco_resp.is_successful and disco_resp.jwks_uri:
        # Requests sent to an endpoint URL share the BaseRequest interface
        jwks_req = JwksRequest(address=disco_resp.jwks_uri)
        print(
            f"\n  isinstance(jwks_req, BaseRequest) = {isinstance(jwks_req, BaseRequest)}"
        )
        jwks_resp = polymorphic_fetch(jwks_req)
        check_response(jwks_resp, "JWKS")

    print(
        f"\n  isinstance(disco_resp, BaseResponse) = {isinstance(disco_resp, BaseResponse)}"
    )

    print("\n" + "=" * 60)
    print("Base class examples completed!")
    print("=" * 60)


if __name__ == "__main__":
    main()
