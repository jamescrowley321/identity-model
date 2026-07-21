# Token Exchange test fixtures

Fixtures backing the `token-exchange` conformance suite
(`spec/conformance/token-exchange.json`), per RFC 8693.

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

Request fixtures (annotated `application/x-www-form-urlencoded` bodies, shown as
JSON key/value pairs):

- `exchange-request-impersonation.json` — the request body for an impersonation
  flow, including `requested_token_type` and `audience` (EXCH-001, EXCH-004,
  §2.1). `grant_type` is `urn:ietf:params:oauth:grant-type:token-exchange`.
- `exchange-request-delegation.json` — the request body for a delegation flow,
  adding `actor_token` and `actor_token_type` (`actor_token_type` is REQUIRED
  whenever `actor_token` is present) plus `resource` (EXCH-002, §2.1).

Error fixtures (HTTP 400 bodies):

- `exchange-error-invalid-grant.json` — the standard OAuth error body returned
  when the `subject_token` is expired or otherwise invalid, carrying
  `error=invalid_grant` (EXCH-006, §2.2.2, RFC 6749 §5.2).
- `exchange-error-invalid-request.json` — the error body returned when the
  request is malformed (e.g. `actor_token` without `actor_token_type`), carrying
  `error=invalid_request` (EXCH-006).

Reference data:

- `token-type-uris.json` — the six token type identifier URIs from RFC 8693 §3
  (EXCH-003, AC-S.12.7), used to assert each URI is serialized verbatim.

The `subject_token`/`actor_token` presence in the request and the
`client_secret_basic` vs `client_secret_post` request shapes are asserted
against the request the client emits and so are constructed inline in the unit
tests via `httptest` rather than as static response fixtures.
