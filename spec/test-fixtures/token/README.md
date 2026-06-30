# Token endpoint test fixtures

Fixtures backing the `client-credentials` and `authorization-code` conformance
suites (`spec/conformance/client-credentials.json`,
`spec/conformance/authorization-code.json`).

The OAuth2 success and error token bodies (RFC 6749 §5.1/§5.2) are tiny and are
constructed inline in the unit tests via `httptest`, so they are not duplicated
here. The only shared fixture is the PKCE vector:

- `pkce-appendix-b.json` — the [RFC 7636 Appendix B](https://www.rfc-editor.org/rfc/rfc7636#appendix-B)
  worked example. `S256Challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")`
  MUST equal `E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM` (ACG-003).
