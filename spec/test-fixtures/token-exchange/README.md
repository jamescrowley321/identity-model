# Token Exchange test fixtures

Fixtures backing the `token-exchange` conformance suite
(`spec/vectors/token-exchange.json`), per RFC 8693.

Response fixtures (HTTP 200 bodies):

- `exchange-impersonation-success.json` — a successful impersonation exchange
  (only `subject_token` was sent). Carries the REQUIRED trio `access_token`,
  `issued_token_type`, `token_type=Bearer`, plus `expires_in` and `scope`
  (EXCH-001, §2.2).
- `exchange-delegation-success.json` — a successful delegation exchange (both
  `subject_token` and `actor_token` were sent). The issued token represents the
  delegation relationship and MAY carry an `act` claim (EXCH-002, §4.1).
- `exchange-n_a-token-type.json` — a success response whose `token_type` is
  `N_A`, used when the issued token is not a bearer token (e.g. a SAML2
  assertion); clients MUST accept `N_A` without error (EXCH-005, §2.2.1).
- `exchange-optional-fields-success.json` — a success response carrying the
  optional `scope` and `refresh_token` alongside `expires_in` (EXCH-005, §2.2).

The request each exchange must send is asserted by `expect_request.form` in the
vectors themselves.

Error fixtures (HTTP 400 bodies):

- `exchange-error-invalid-grant.json` — the standard OAuth error body returned
  when the `subject_token` is expired or otherwise invalid, carrying
  `error=invalid_grant` (EXCH-006, §2.2.2, RFC 6749 §5.2).
- `exchange-error-invalid-request.json` — the error body returned when the
  server rejects the request as invalid (here, an unsupported
  `subject_token_type`), carrying `error=invalid_request` and an `error_uri`
  (EXCH-006).

Reference data:

- `token-type-uris.json` — the six token type identifier URIs from RFC 8693 §3
  (EXCH-003, AC-S.12.7). Go and Rust check their exported constants against it;
  the EXCH-003 vectors carry the same URIs.
