# Token Introspection test fixtures

Fixtures backing the `introspection` conformance suite
(`spec/vectors/introspection.json`), per RFC 7662.

- `active-response.json` — a 200 introspection response with `active: true` and
  the full set of standard §2.2 metadata members (`scope`, `client_id`,
  `username`, `token_type`, `exp`, `iat`, `nbf`, `sub`, `aud`, `iss`, `jti`)
  plus one non-standard member (`extension_field`). Its `iss` is not the
  fixture host, so the runners' host substitution leaves it unchanged. The standard members must
  decode into typed fields (INTR-001); `extension_field` must remain reachable
  via the response overflow map.
- `active-minimal.json` — a 200 response with only `active: true`, proving the
  metadata members are truly optional (§2.2).
- `inactive-response.json` — a 200 response with only `active: false`
  (INTR-002); no other member is guaranteed present.
- `missing-active.json` and `active-not-boolean.json` — 200 responses whose
  REQUIRED `active` member is missing or is the string `"false"`; both must be
  rejected as malformed, not read as an inactive token (INTR-001, §2.2).
- `error-invalid-client.json` — the body of the HTTP 401 error returned when the
  introspecting client fails authentication (INTR-005, §2.3), carrying
  `error: invalid_client`.
- `discovery-with-introspection.json` — an Authorization Server Metadata /
  OIDC Discovery document containing `introspection_endpoint`, used to resolve
  the endpoint URL from discovery (INTR-006, RFC 8414 §2). The endpoint is at
  `/oauth2/introspect`, not the runners' default `/introspect`, so the vector
  proves the discovered URL is the one used.

- `signed-*.jwt` and `signed-jwks.json` — signed JWT introspection responses
  (INTR-007, RFC 9701 §5). Each has `iss` `https://issuer.example.com/`,
  `aud` `cid` and a `token_introspection` claim holding
  `active-response.json`. `signed-response.jwt` is ES256 with
  `typ: token-introspection+jwt` (accepted); `signed-wrong-typ.jwt` has
  `typ: JWT`; `signed-rs256.jwt` is RS256 (outside the FAPI 2.0 set) with the
  `validation/signing-key.jwk.json` key; `signed-wrong-audience.jwt` has
  `aud: other-client`; `signed-tampered.jwt` keeps the signature of
  `signed-response.jwt` over a different payload. `signed-jwks.json` holds the
  ES256 key (`kid` `intr-es256`) and the RS256 key. The ES256 key was generated
  for these fixtures and not kept; regenerate all of them together.

The `client_secret_basic` vs `client_secret_post` request shapes (INTR-003) and
the `token_type_hint` body parameter (INTR-004) are asserted by each vector's
`expect_request`; those vectors are served `active-minimal.json`.
