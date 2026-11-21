# UserInfo endpoint test fixtures

Fixtures backing the `userinfo` conformance suite
(`spec/vectors/userinfo.json`).

- `standard-claims.json` — a UserInfo response covering the full OpenID Connect
  Core 1.0 §5.1 standard claim set (including the structured `address` claim,
  §5.1.1) plus one non-standard claim (`department`). The standard claims must
  decode into typed fields (UI-001); `department` must remain reachable via the
  response claim map alongside the standard claims (UI-007). Its `sub`
  (`248289761001`) is the value used by the subject-consistency tests
  (UI-002 match, UI-003 mismatch).

- `missing-sub.json` — a 200 UserInfo response with no `sub` claim, which
  must be rejected with or without an expected subject (UI-003).

- `signed-claims.jwt` — a compact JWS UserInfo response, served as
  `application/jwt`, whose payload `sub` (`248289761001`) equals the expected
  subject. Its signature is not valid, so a client that compared the
  unverified `sub` would wrongly accept it; with an expected subject the
  fetch must fail instead (UI-009).

- `server-error.html` — the non-JSON body of the HTTP 500 response (UI-006).

The 401 and 403 responses carry no body; their status and `WWW-Authenticate`
header are given inline in the vectors.
