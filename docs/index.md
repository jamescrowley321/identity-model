# py-identity-model

![Build](https://github.com/jamescrowley321/identity-model/workflows/Build/badge.svg)
![License](https://img.shields.io/pypi/l/py-identity-model)

Production-grade OIDC/OAuth2.0 client library for Python. Dual sync/async API with comprehensive RFC coverage. Inspired by [Duende.IdentityModel](https://github.com/DuendeSoftware/foss/tree/main/identity-model).

## OpenID Certified

<a href="https://openid.net/certification/certified-openid-relying-parties-profiles/">
  <img src="assets/openid-certified.png" alt="OpenID Certified" width="220">
</a>

py-identity-model is [OpenID Certified<sup>®</sup>](https://openid.net/certification/certified-openid-relying-parties-profiles/) by the OpenID Foundation as a Relying Party (RP) for the **Basic RP**, **Config RP**, and **Form Post Basic RP** conformance profiles (certified 2 July 2026, `py-identity-model 3.1.0`). See [the certification docs](certification.md) for the conformance harness and submission process.

> OpenID Certified is a certification mark of the OpenID Foundation.

## Installation

```bash
pip install py-identity-model
```

**Requirements:** Python 3.12+

## Protocol Coverage

| Feature | RFC/Spec | Since |
|---------|----------|-------|
| OpenID Connect Discovery 1.0 | OIDC Discovery | v1.0 |
| JSON Web Key Sets | RFC 7517 | v1.0 |
| JWT Validation | RFC 7519 | v1.0 |
| Client Credentials Grant | RFC 6749 | v1.0 |
| UserInfo Endpoint | OIDC Core | v2.1 |
| Async/Await API | — | v1.2 |
| Authorization Code + PKCE | RFC 7636 | v2.10 |
| Refresh Token Grant | RFC 6749 | v2.10 |
| Token Introspection | RFC 7662 | v2.10 |
| Token Revocation | RFC 7009 | v2.10 |
| Device Authorization | RFC 8628 | v2.11 |
| Token Exchange | RFC 8693 | v2.11 |
| DPoP | RFC 9449 | v2.12 |
| Pushed Authorization Requests | RFC 9126 | v2.12 |
| JWT Secured Authorization Request | RFC 9101 | v2.13 |
| JWT Secured Authorization Response Mode (JARM) | JARM | v3.5 |
| FAPI 2.0 Security Profile | FAPI 2.0 | v2.14 |
| Policy-Based Configuration | — | v2.15 |
| OAuth Callback State Validation | RFC 6749 | v2.9 |

## Quick Start

```python
from py_identity_model import DiscoveryDocumentRequest, get_discovery_document

response = get_discovery_document(DiscoveryDocumentRequest(address="https://issuer.example.com"))
```

```python
# Async
from py_identity_model.aio import get_discovery_document
response = await get_discovery_document(DiscoveryDocumentRequest(address=url))
```

## Architecture

```
py_identity_model/
├── core/          # Shared business logic (protocol-agnostic, no I/O)
├── sync/          # Synchronous HTTP wrappers (thread-local clients)
└── aio/           # Asynchronous HTTP wrappers (singleton client)
```

## Documentation

- [Getting Started](getting-started.md)
- [Upgrading to 5.0](upgrade-v5.md): breaking changes from 4.x
- [Migration Guide](migration-guide.md)
- [Performance Guide](performance.md)
- [Integration Tests](integration-tests.md)
- [Troubleshooting](troubleshooting.md)
- [FAQ](faq.md)
- [Contributing](contributing.md)
- [Changelog](changelog.md)

### Compliance

- [Discovery Specification Compliance](discovery_specification_compliance_assessment.md)
- [JWKS Specification Compliance](jwks_specification_compliance_assessment.md)

### API Reference

- [API Index](api/index.md)

## License

Apache License 2.0
