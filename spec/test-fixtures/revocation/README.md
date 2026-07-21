# Token Revocation test fixtures

Fixtures backing the `revocation` conformance suite
(`spec/conformance/revocation.json`), per RFC 7009.

- `revoke-success-empty.json` — an empty (0-byte) body, the most common HTTP 200
  revocation success response. A revocation success carries no response body, so
  clients MUST treat any 2xx as success without attempting to parse a body
  (REV-001, §2.2).
- `revoke-success-empty-object.json` — a 200 response with `{}`, an equally valid
  success body some servers emit; it too must be treated as success (REV-001).
- `error-unsupported-token-type.json` — the body of the HTTP 400 error returned
  when the server does not support revoking the presented token type (REV-003,
  §2.2.1), carrying `error: unsupported_token_type`.
- `error-invalid-client.json` — the body of the HTTP 401 error returned when the
  revoking client fails authentication (REV-004, §2.2.1), carrying
  `error: invalid_client`.
- `discovery-with-revocation.json` — an Authorization Server Metadata / OIDC
  Discovery document containing `revocation_endpoint`, used to resolve the
  endpoint URL from discovery (REV-005, RFC 8414 §2).

The `token_type_hint` body parameter (REV-002) and the `client_secret_basic` vs
`client_secret_post` request shapes are asserted against the request the client
emits and so are constructed inline in the unit tests via `httptest` rather than
as static response fixtures.

RFC 7009 §2.1 requires the revocation endpoint to return HTTP 200 regardless of
whether the token was valid, expired, already revoked, or unknown, so that a
client cannot probe token state; the success fixtures above deliberately carry no
distinguishing content.
