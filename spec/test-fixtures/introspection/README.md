# Token Introspection test fixtures

Fixtures backing the `introspection` conformance suite
(`spec/conformance/introspection.json`), per RFC 7662.

- `active-response.json` — a 200 introspection response with `active: true` and
  the full set of standard §2.2 metadata members (`scope`, `client_id`,
  `username`, `token_type`, `exp`, `iat`, `nbf`, `sub`, `aud`, `iss`, `jti`)
  plus one non-standard member (`extension_field`). The standard members must
  decode into typed fields (INTR-001); `extension_field` must remain reachable
  via the response overflow map.
- `active-minimal.json` — a 200 response with only `active: true`, proving the
  metadata members are truly optional (§2.2).
- `inactive-response.json` — a 200 response with only `active: false`
  (INTR-002); no other member is guaranteed present.
- `error-invalid-client.json` — the body of the HTTP 401 error returned when the
  introspecting client fails authentication (INTR-005, §2.3), carrying
  `error: invalid_client`.
- `discovery-with-introspection.json` — an Authorization Server Metadata /
  OIDC Discovery document containing `introspection_endpoint`, used to resolve
  the endpoint URL from discovery (INTR-006, RFC 8414 §2).

The `client_secret_basic` vs `client_secret_post` request shapes (INTR-003) and
the `token_type_hint` body parameter (INTR-004) are asserted against the request
the client emits and so are constructed inline in the unit tests via `httptest`
rather than as static response fixtures.
