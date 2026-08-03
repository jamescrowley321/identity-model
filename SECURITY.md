# Security Policy

`identity-model` is an OIDC/OAuth2 client library that validates security tokens.
Vulnerabilities here can affect the authentication decisions of every downstream
consumer, so reports are taken seriously and triaged promptly.

## Reporting a vulnerability

**Please do not open a public issue for security problems.**

Report privately through GitHub's **[Private Vulnerability Reporting](https://github.com/jamescrowley321/identity-model/security/advisories/new)**
(repository **Security** tab → **Report a vulnerability**). This opens a private
advisory visible only to you and the maintainers, where a fix and CVE can be
coordinated.

When you report, please include as much of the following as you can:

- The affected language binding (`go/` or `rust/`) and version / commit.
- A description of the issue and its security impact (e.g. signature bypass,
  audience/issuer confusion, algorithm confusion, DoS).
- A minimal reproduction — ideally a failing test or a token/JWKS/discovery
  document that demonstrates the problem.

## What to expect

- **Acknowledgement** within 3 business days.
- An initial assessment (severity, affected versions, likely fix approach)
  within 10 business days.
- Coordinated disclosure: a fix is prepared privately, released, and only then
  is the advisory published — with credit to the reporter unless you prefer to
  remain anonymous.

## Supported versions

This project is pre-1.0 and evolving. Security fixes are made against the latest
release of each binding and `main`; there is no back-porting to older
pre-release versions at this time.

## Scope

In scope: the shipped library code (`go/pkg/**`, `rust/src/**`) — token
validation, JWKS handling, discovery, and the HTTP client behavior they rely on.

Out of scope: the test/conformance harnesses (`spec/`, `**/conformance/`,
`internal/integrationtest/`), example applications, and the local provider
fixtures under `infra/`, which are development-only and never shipped to
consumers.
