# Authorization code test fixtures

Fixtures backing the `authorization-code` conformance suite
(`spec/vectors/authorization-code.json`), per RFC 6749 §4.1.

- `code-exchange-success.json` — the HTTP 200 token response to a code
  exchange: `access_token`, `token_type=Bearer`, `expires_in`, `refresh_token`
  and `scope` (ACG-001, ACG-004; RFC 6749 §5.1).
- `code-exchange-error-invalid-grant.json` — the HTTP 400 OAuth error body for a
  rejected code, carrying `error=invalid_grant`, `error_description` and
  `error_uri` (ACG-005; RFC 6749 §5.2).

The request each exchange must send is asserted by `expect_request.form` in the
vectors themselves. The PKCE vectors (ACG-002, ACG-003) are pure data and need no
fixture; ACG-003 carries the RFC 7636 Appendix B values inline.
