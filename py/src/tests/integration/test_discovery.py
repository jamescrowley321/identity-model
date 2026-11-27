import pytest

from py_identity_model import (
    DiscoveryDocumentRequest,
    get_discovery_document,
)


def test_get_discovery_document_is_successful(discovery_document, test_config):
    """Test using cached discovery document to avoid rate limits."""
    assert discovery_document.is_successful
    # Every provider's issuer is exactly the configured issuer (§4.3).
    assert discovery_document.issuer == test_config["TEST_ISSUER"]
    assert discovery_document.jwks_uri
    assert discovery_document.token_endpoint
    assert discovery_document.authorization_endpoint


@pytest.mark.usefixtures("env_file")
def test_get_discovery_document_fails():
    disco_doc_request = DiscoveryDocumentRequest(issuer="https://google.com")
    disco_doc_response = get_discovery_document(disco_doc_request)
    assert disco_doc_response.is_successful is False
