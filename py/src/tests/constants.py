"""Values shared across test suites."""

ISSUER = "https://example.com"
# Derived from ISSUER: discovery requires the document's issuer to match this URL.
DISCO_URL = f"{ISSUER}/.well-known/openid-configuration"
