# Token endpoint test fixtures

Fixtures backing the `client-credentials` and `authorization-code` conformance
suites (`spec/vectors/client-credentials.json`,
`spec/vectors/authorization-code.json`).

- `client-credentials-success.json` — a 200 RFC 6749 §5.1 token response
  (`access_token`, `token_type`, `expires_in`, `scope`). CC-001 asserts its
  typed fields; the other accepting client-credentials vectors are served it
  and assert the request shape via `expect_request`.
- `error-invalid-client.json` — the body of the HTTP 401 RFC 6749 §5.2 error
  (`error: invalid_client` with `error_description` and `error_uri`) that
  CC-004 must surface as a typed token error. Its `error_uri` is not the
  fixture host, so the runners' host substitution leaves it unchanged.
- `pkce-appendix-b.json` — the [RFC 7636 Appendix B](https://www.rfc-editor.org/rfc/rfc7636#appendix-B)
  worked example. `S256Challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")`
  MUST equal `E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM` (ACG-003).
