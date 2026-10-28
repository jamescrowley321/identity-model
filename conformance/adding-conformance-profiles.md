# Adding a New Conformance Profile

A repeatable playbook for certifying py-identity-model (and the
`fastapi-identity-model` package) against a new conformance profile.

This complements [`README.md`](README.md) (how to *run* the existing plans) and
[`../docs/certification.md`](../docs/certification.md) (the OIDF submission step).
This doc is about how to *add* a profile that doesn't exist yet.

## Methodology: harness-first, work backwards

The governing principle: **the test harness is the source of truth, not the
spec prose.** A profile is "done" when the harness's plan goes green — not when
we think we've read the RFC correctly. So we start from the authoritative
harness, discover its exact plan + variant surface, and work backwards to the
implementation until the plan passes.

```
harness → plan + variant matrix → required behavior → library gap
   → implement (library first, RP harness second) → green → evidence → submit
```

Four things that fall out of this ordering and are easy to get wrong:

- **Don't guess plan or variant names.** Ask the running harness what it offers
  (see step 1). Names drift between suite versions.
- **The variant tuple defines the test set.** Each variant parameter narrows or
  broadens which modules run. Pin it deliberately and document each choice's
  effect (README's Config RP table is the model).
- **Know what the plan does *not* cover.** py-identity-model is an RP *and* a
  resource server. A client/RP plan validates token *acquisition*; it generally
  does not prove the RS *rejects* a bad token. RS-side assurances need their own
  integration/E2E tests (see the FAPI-2 example below).
- **Negative tests are the point of certification.** OIDF RP certification
  requires one client-side log per module proving the RP *rejected* bad inputs
  (`ACCEPTED` / `REJECTED: <reason>` lines — see `app.py`). Budget for these.

## The steps

### 1. Identify and stand up the harness

- **OIDF profiles** (OIDC RP, FAPI, logout, …): the suite is already wired.
  `make conformance-up` brings up the Java suite + MongoDB + nginx.
- **Non-OIDF profiles**: locate the authoritative harness (working group or
  vendor). If there is no automatable harness, stop — a profile we can't
  re-run isn't one we can maintain.

Then **interrogate the harness for its catalog** rather than trusting docs:

- List available test modules on the running suite: `GET /api/runner/available`.
- Read the plan definitions in the suite source
  (`net/openid/conformance/**/*TestPlan.java`) to see the exact `planName`, the
  `@VariantParameters` it accepts, and which modules are
  `@VariantNotApplicable` for a given variant.

Record the exact `planName` and the full set of variant keys/values.

### 2. Pin the profile and variant matrix

- Choose the plan and the exact variant tuple.
- Confirm it's a **client/RP** plan (our target), not an **OP** plan. Most FAPI
  suite tests are OP-side; make sure you're on the client plan.
- Write down each variant parameter and its effect on test selection, following
  the table format README uses for Config RP.
- Note explicitly what the plan leaves unverified so it doesn't silently become
  a coverage gap.

### 3. Enumerate required behavior → gap analysis

- From the module list, derive the concrete protocol behaviors the RP must
  exhibit (e.g. "send PAR", "authenticate with `private_key_jwt`", "present a
  DPoP proof at the token endpoint", "verify a JARM response").
- Diff against current library capability: run `make provider-matrix` (probes
  discovery per configured provider) and grep `src/py_identity_model/` for the
  relevant machinery.
- Produce a gap list, each item mapped to a tracked issue.

### 4. Implement backwards — library first, harness second

- Fill library gaps in `src/py_identity_model/core/` with thin `sync/` + `aio/`
  wrappers, following the existing core-logic-vs-IO split.
- Cover each new capability with **unit tests** (respx-mocked) **and integration
  tests against the `node-oidc-provider` fixture** — it is credential-free and
  already enables DPoP, PAR, JAR, resource-indicator JWTs, and a
  `private_key_jwt` client with FAPI-2 signing algs
  (`infra/node-oidc-provider/provider.js`). Extend the fixture if the
  profile needs a capability it doesn't yet serve.
- Only once the library behavior exists and is tested, wire the RP harness
  (`conformance/app.py`, and `conformance/app_fastapi.py` for the package
  regression shield) to drive it, emitting `ACCEPTED` / `REJECTED` decision
  logs per module.

Gate every capability behind an integration test that proves the **negative**
case, not just the happy path — certification and our own merge discipline both
require it.

### 5. Add the plan config + runner wiring

- Add `conformance/configs/<profile>.json`:
  ```json
  {
    "plan_name": "<exact-planName-from-step-1>",
    "variant": { "<key>": "<value>" },
    "alias": "py-identity-model-<profile>",
    "client": { "client_id": "…", "client_secret": "…" }
  }
  ```
- `run_tests.py --plan <profile>` loads `configs/<profile>.json` automatically —
  a standard plan needs **no runner code change**. If the plan needs behavior
  the generic driver doesn't have (new endpoints, a per-module setup hook), add
  it to `run_tests.py` / the harness app.
- Add a `fastapi-<profile>.json` mirror config so the package harness runs the
  same plan (`--rp-url http://localhost:8889`) as a CI regression shield.
- Register the plan in README's test-plan table.

### 6. Run locally until green

```bash
make conformance-up
cd conformance && python run_tests.py --plan <profile>
```

Iterate over steps 3–5 until every module is `PASS`, or a legitimate `SKIP`.
Document each SKIP the way README documents `oidcc-client-test-idtoken-sig-none`
(the suite auto-skips it because we securely reject `alg:none`). An undocumented
SKIP is a coverage hole, not a pass.

### 7. Capture evidence

- **Signed plan export** — read-only regression/evidence artifact:
  `--export-zip PATH`, or `make conformance-test HOSTED=1` →
  `results/hosted/<plan>-export.zip`.
- **RP client-side logs** — one `<module>.log` per test with the
  `ACCEPTED`/`REJECTED` decisions: `run_tests.py --rp-logs-zip PATH` →
  `results/hosted/<plan>-rp-logs.zip`. This is the `clientSideData` OIDF wants.

### 8. Hosted run + submit

- Rotate the hosted token if stale: `uv run
  conformance/scripts/rotate_conformance_token.py` (interactive first run; token
  expires ~quarterly and a stale token 302-redirects to `login.html`).
- Hosted run against `https://www.certification.openid.net/`.
- Submit via the OIDF portal (`https://submissions.openid.net/`): upload the
  `*-export.zip` (result) + `*-rp-logs.zip` (client data) per profile. OIDF
  returns a DocuSign signature request. This is the owner-driven manual step —
  see `../docs/certification.md`.

### 9. Record what changed

- README: test matrix, test counts, and any "excluded by this variant" notes.
- The gap-analysis issues: close with links to the passing run.
- Auto-memory: the profile, its variant tuple, and any gotchas discovered.

## Worked example — FAPI 2.0 Security Profile (client), epic #476

Applying the playbook to the profile we're actually adding next.

**Steps 1–2 — harness + plan.** OIDF suite, the FAPI 2.0 Security Profile
**client** test plan (confirm the exact `planName` and variant keys against
`/api/plan` on the running suite before writing the config — the
`fapi2-security-profile-final` family predates final naming and the client plan
is distinct from the OP plan). Expected variant axes: sender-constraint
(`dpop` | `mtls`), client auth (`private_key_jwt` | `mtls`), and the message-
signing option (JARM / signed request objects) if we target that add-on.

**Step 3 — gap analysis (already done, see the repo review):**

| Behavior the plan needs | Status | Issue |
|---|---|---|
| PKCE S256, PAR, JAR request objects | ✅ present + live-tested | — |
| `private_key_jwt` client auth (ES256/PS256) | ✅ present + tested vs node-oidc | — |
| DPoP proof at token endpoint (client side) | ✅ `core/dpop.py` | — |
| RS-side DPoP proof + `cnf.jkt` enforcement in the core library | ✅ `core/dpop_verify.py`, `validate_token(..., presentation=)`, `TokenValidationConfig.required_binding` | #478 |
| RS-side sender-constraint enforcement in the FastAPI middleware | ❌ missing — middleware only accepts `Bearer` | #1021 |
| RS-side mTLS `x5t#S256` beyond `validate_certificate_binding` | ❌ missing | #215 |
| **JARM** (verify signed authorization *response*) | ❌ missing (only JAR, the request side) | #218 |
| Response `__repr__` redaction hardening | ⏳ in progress | #431 |
| FAPI-2 plan wired into the harness | ❌ missing | #475 |

**Step 4 — implement backwards (the design for #215):**

- New `src/py_identity_model/core/dpop_verify.py` — the server-side counterpart
  to `core/dpop.py`. Verify an incoming DPoP proof: `typ=dpop+jwt`, signature
  against the embedded `jwk`, `htm`/`htu` match the request, `iat` freshness +
  `jti` replay window, `ath` matches the presented access token, and the proof
  key's RFC 7638 thumbprint equals the token's `cnf.jkt`. (The thumbprint helper
  already exists — `DPoPKey.jwk_thumbprint`.)
- mTLS variant: read the client-cert thumbprint from the TLS terminator
  (`x-forwarded-client-cert` / `ssl_client_cert`) and match `cnf["x5t#S256"]`.
- Extend `TokenValidationConfig` with sender-constraint options (required
  binding: `none` | `dpop` | `mtls`) and thread them through
  `decode_with_config` → a new post-decode `cnf` check.
- In `fastapi-identity-model` middleware, generalize `_extract_bearer_token` to
  accept the `DPoP` auth scheme (today it hard-rejects anything but `Bearer`),
  pass the `DPoP` request header + method/URL into the verifier, and **fail
  closed** when a binding is required but absent or mismatched.

**Why #215 is the load-bearing item:** the client plan proves we *obtain* a
sender-constrained token correctly; it does not prove a resource server built on
this library *rejects* a stolen or mismatched-proof token. Today it wouldn't —
a DPoP-bound token presented as `Bearer` is accepted with zero binding check.
That RS guarantee is verified by our integration tests + the E2E token harness
(#462–#474), which is why #215 must ship with explicit **negative** tests
(mismatched `jkt`, replayed `jti`, wrong `htu`, missing proof).

> **The #475 client plan does not exercise the resource-server verifier.** It
> tests token *acquisition* (client-side DPoP). The RS checks from #478 are
> proven by `src/tests/unit/test_dpop_verify.py`, `test_token_binding.py`, the
> `DPOP-006` spec vectors and the live node-oidc matrix in
> `src/tests/integration/test_dpop_rs_verification_live.py`.

**Steps 5–8 — plan wiring (#475):** add
`conformance/configs/fapi2-security-profile-rp.json` (+ `fastapi-` mirror),
register the confidential client with `private_key_jwt`, teach the RP harness to
run PAR + PKCE + `private_key_jwt` + DPoP, then local-green → evidence → hosted →
portal submission.

> Sequencing note: FAPI-2 implementation is tracked under epic #476 and is
> intended to land through the `ralph/fapi2-hardening` workstream, one profile at
> a time. Keep this doc's process independent of that code so the two don't
> collide.
