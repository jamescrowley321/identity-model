# UserInfo endpoint test fixtures

Fixtures backing the `userinfo` conformance suite
(`spec/conformance/userinfo.json`).

- `standard-claims.json` — a UserInfo response covering the full OpenID Connect
  Core 1.0 §5.1 standard claim set (including the structured `address` claim,
  §5.1.1) plus one non-standard claim (`department`). The standard claims must
  decode into typed fields (UI-001); `department` must remain reachable via the
  response claim map alongside the standard claims (UI-007). Its `sub`
  (`248289761001`) is the value used by the subject-consistency tests
  (UI-002 match, UI-003 mismatch).

The error responses (401/403/5xx) and the subject-mismatch case are constructed
inline in the unit tests via `httptest`, so they are not duplicated here.
