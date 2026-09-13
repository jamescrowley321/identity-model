# OIDC RP Conformance Test Harness

Test infrastructure for running the [OpenID Foundation conformance suite](https://openid.net/certification/testing/) against py-identity-model.

> Adding a *new* profile (not just running an existing one)? Follow the
> repeatable playbook in [`adding-conformance-profiles.md`](adding-conformance-profiles.md).

## Architecture

- **Conformance suite** — OIDF Java server + MongoDB + nginx (TLS termination)
- **RP harness** — Thin FastAPI app using py-identity-model's sync API
- **Package RP harness** (`app_fastapi.py`, port 8889) — drives the real
  `fastapi_identity_model.build_oidc_router` through the same plans, one
  in-process router per test issuer (regression stage, not a certification target)
- **Test runner** — Python script that orchestrates test plans via the suite's REST API

## Quick Start

```bash
# From the repo root:
make conformance-build    # Build containers
make conformance-up       # Start the suite + RP harness
make conformance-down     # Tear down

# Run conformance tests:
cd conformance
python run_tests.py --plan basic-rp
python run_tests.py --plan config-rp
```

## SSL Certificate Sharing

The local conformance suite uses a self-signed TLS certificate for `localhost.emobix.co.uk:8443`.
A `cert-init` Docker service generates this certificate at compose-up time and shares it with
both the nginx proxy and the RP harness via a named volume.

The RP container sets `SSL_CERT_FILE=/certs/nginx-selfsigned.crt` so that py-identity-model's
HTTP client trusts the self-signed cert when making discovery and JWKS fetches to the
conformance suite.

No certificate files are committed to the repository — they are generated dynamically on each run.

## DNS

The conformance suite uses `localhost.emobix.co.uk` which resolves to `127.0.0.1`. No `/etc/hosts` changes needed.

## Test Plans

| Plan | Config | Description |
|------|--------|-------------|
| `basic-rp` | `configs/basic-rp.json` | Basic RP certification (code flow, client_secret_basic) |
| `config-rp` | `configs/config-rp.json` | Config RP certification (discovery-based config) |
| `form-post-basic-rp` | `configs/form-post-basic-rp.json` | Basic RP with `form_post` response mode |
| `fapi2-rp` | `configs/fapi2-rp.json` | FAPI 2.0 Security Profile RP (PAR + PKCE S256 + private_key_jwt + DPoP + RFC 9207 `iss`) |
| `fastapi-basic-rp` | `configs/fastapi-basic-rp.json` | Basic RP regression for the fastapi-identity-model router (`--rp-url http://localhost:8889`) |
| `fastapi-config-rp` | `configs/fastapi-config-rp.json` | Config RP regression for the fastapi-identity-model router |
| `fastapi-form-post-basic-rp` | `configs/fastapi-form-post-basic-rp.json` | Form Post Basic RP regression for the fastapi-identity-model router |

The `fastapi-*` plans run the identical suite plans against the package harness
(`make conformance-test-fastapi`). They are a CI regression shield for the
package — the core library remains the OIDF certification target (#242).

## FAPI 2.0 Security Profile RP

The `fapi2-rp` plan drives the OIDF **`fapi2-security-profile-final`** client
test plan against the harness's FAPI 2.0 flow (#475). It exercises the FAPI 2.0
sender-constrained (DPoP) path end-to-end through the library's public API:

- **PAR** (RFC 9126) — every authorization request is pushed; the front channel
  carries only `client_id` + `request_uri`.
- **PKCE `S256`** — mandatory.
- **`private_key_jwt`** client authentication (RFC 7523) — the RP's ES256 signing
  key. The harness serves the **public** JWKS at `GET /fapi2-jwks`; `run_tests.py`
  fetches it and registers it as the client's `jwks` when creating the plan
  (`token_endpoint_auth_method=private_key_jwt`). The private key never leaves the
  RP.
- **DPoP** (RFC 9449) — a per-flow key binds the PAR, token, and UserInfo
  requests. The token-endpoint proof carries no `ath`; the resource (UserInfo)
  proof does. The RFC 9449 §8 `use_dpop_nonce` challenge is honoured with a
  single retry.
- **RFC 9207 `iss`** — the authorization-response issuer is validated
  (`require=True`) to close the mix-up attack class.
- **PS256 / ES256 only** — enforced by the library's FAPI validators.

### Library seams this profile depends on

The FAPI 2.0 DPoP path required threading DPoP through request execution (the
building blocks previously only *produced* proofs):

- `PushedAuthorizationRequest.dpop_key` / `AuthorizationCodeTokenRequest.dpop_key`
  / `UserInfoRequest.dpop_key` — attach a DPoP proof and honour the nonce retry.
- `DiscoveryDocumentResponse.pushed_authorization_request_endpoint` — discover the
  PAR endpoint (RFC 9126 §5) through the typed model.

### Running

```bash
# Local suite (brings up the OP + RP harness):
python run_tests.py --plan fapi2-rp

# Hosted suite (evidence run — requires CONFORMANCE_TOKEN):
python run_tests.py --plan fapi2-rp \
  --suite-url https://www.certification.openid.net \
  --export-zip results/hosted/fapi2-rp-export.zip \
  --rp-logs-zip results/hosted/fapi2-rp-rp-logs.zip
```

> **Variant confirmation:** `configs/fapi2-rp.json` pins the plan name and variant
> (`client_auth_type=private_key_jwt`, `sender_constrain=dpop`,
> `fapi_client_type=oidc`, `fapi_request_method=unsigned`,
> `fapi_response_mode=plain_response`). The exact variant keys and plan name must
> be reconciled against the live suite's plan metadata on the first evidence run —
> the suite is the source of truth. mTLS (`sender_constrain=mtls`, #215) is a
> separate future path; this profile certifies on DPoP.

## Profile Test Counts

### Basic RP

The Basic RP certification plan runs a variable number of tests depending on variant
configuration (response type, client auth type, etc.). With the `code` response type and
`client_secret_basic` auth, the plan produces the standard set of tests covering token
validation, key rotation, scope handling, and userinfo.

### Config RP

The Config RP certification plan contains exactly **6 tests**. This is the complete profile
for our variant configuration, as defined by the conformance suite source
([`OIDCCClientConfigTestPlan.java`](https://gitlab.com/openid/conformance-suite/-/blob/master/src/main/java/net/openid/conformance/openid/client/OIDCCClientConfigTestPlan.java))
and the [OpenID Connect Conformance Profiles v3.0](https://openid.net/wordpress-content/uploads/2018/06/OpenID-Connect-Conformance-Profiles.pdf).

#### Variant configuration

Our `config-rp.json` runs the plan with these variant parameters (see [`configs/config-rp.json`](configs/config-rp.json)):

| Variant parameter | Our value | Effect on test selection |
|---|---|---|
| `client_registration` | `static_client` | Excludes dynamic client registration tests |
| `client_auth_type` | `client_secret_basic` | Standard HTTP Basic auth at the token endpoint |
| `request_type` | `plain_http_request` | Plain authorization requests (not `request_object` / `request_uri`) |
| `response_mode` | `default` | Default response mode for the Config RP profile |

These are the cert-grade variant settings for a Config RP submission — they are the same
values used by other certified RP libraries (see e.g. `erlef/oidcc_conformance`'s submitted
certifications). Changing any of them would narrow or broaden the test set.

#### Test matrix

| Test | Description | Expected Result |
|------|-------------|-----------------|
| `oidcc-client-test-discovery-openid-config` | Fetch and parse discovery document | PASS |
| `oidcc-client-test-discovery-issuer-mismatch` | Detect issuer mismatch in discovery | PASS |
| `oidcc-client-test-discovery-jwks-uri-keys` | Fetch and parse JWKS from discovery | PASS |
| `oidcc-client-test-idtoken-sig-none` | Handle unsigned ID tokens (alg:none) | SKIP (secure default) |
| `oidcc-client-test-signing-key-rotation` | Handle OP signing key rotation | PASS |
| `oidcc-client-test-signing-key-rotation-just-before-signing` | Handle key rotation immediately before signing | PASS |

The SKIP on `oidcc-client-test-idtoken-sig-none` is expected — py-identity-model correctly
rejects unsigned tokens, which is the secure default. The conformance suite auto-skips this
test when the RP does not advertise support for `alg:none`.

#### Tests excluded by this variant

Three additional test classes exist in the suite's `openid/client/config/` directory but
are excluded from our plan because of the `static_client` variant choice and the Config RP
profile's scope:

- **`OIDCCClientTestDynamicRegistration`** — excluded because our variant is
  `client_registration=static_client`. This test requires the RP to dynamically register
  itself with the OP per RFC 7591. It is `@VariantNotApplicable` when `client_registration`
  is `static_client`, so the conformance suite omits it from the plan automatically. This
  test belongs to the **Dynamic RP** profile.
- **`OIDCCClientTestDiscoveryWebfingerAcct`** — excluded because Config RP uses static
  `.well-known/openid-configuration` discovery. WebFinger discovery (RFC 7033) is a
  separate mechanism where the RP discovers the OP from a user-supplied `acct:` URI. It
  is not part of Config RP's scope regardless of variant choice.
- **`OIDCCClientTestDiscoveryWebfingerURL`** — excluded for the same reason as the `Acct`
  variant: WebFinger URL-style discovery is out of scope for Config RP, which tests the
  `.well-known/openid-configuration` discovery path only.

If we wanted to certify WebFinger discovery behavior, it would require a separate
profile and test plan — py-identity-model does not currently implement WebFinger discovery
and it is not in the current certification scope (see [#242](https://github.com/jamescrowley321/identity-model/issues/242)).

## Endpoints

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `GET /` | GET | Health check |
| `GET /authorize` | GET | Start auth flow (redirect to OP) |
| `GET /callback` | GET | Handle authorization callback |
| `POST /callback` | POST | Handle form_post callback |
| `GET /results/{test_id}` | GET | Retrieve test flow results |

## Hosted certification token rotation

For cert-grade runs against `https://www.certification.openid.net/` (the hosted
OIDF suite) the runner needs a Bearer token. The token is created by an
interactive browser session against the hosted suite — there is no headless
API to create one because the creation endpoint itself requires an
OIDC-authenticated browser session.

`scripts/rotate_conformance_token.py` automates the non-interactive parts of
that flow: persistent browser profile, token creation via the suite's REST API,
and pushing the resulting value straight into the GitHub repository secret. The
token is never printed and never written to disk, and a repository secret cannot
be read back — so rotating gives CI a fresh token but gives you no local copy.

```bash
# First run — interactive Google/GitLab sign-in in the browser window
uv run conformance/scripts/rotate_conformance_token.py

# Subsequent runs — persistent profile keeps you signed in
uv run conformance/scripts/rotate_conformance_token.py --headless

# Dry run — confirm the login/session works; mints nothing, writes nothing
uv run conformance/scripts/rotate_conformance_token.py --dry-run
```

**Prerequisites:**
- `uv` (PEP 723 inline dependency support)
- Playwright Chromium binary: `uv run --with playwright playwright install chromium`
- `gh` authenticated against the repository, with permission to set Actions secrets

See the script's module docstring for full design notes and flag reference.

## Plan exports vs. the certification package

Two distinct artifacts — don't confuse them:

### Plan export (automated, safe)

A passing run prints a pass/fail summary; `--export-zip PATH` additionally
downloads the suite's **signed plan export** (`GET /api/plan/export/{plan_id}` —
JSON + RSA signature, the format the suite recommends for CI). It's a read-only
evidence/regression artifact: no publish, no freeze.

```bash
# Hosted run that also downloads the signed plan export per profile
make conformance-test HOSTED=1 CONFORMANCE_SERVER=https://www.certification.openid.net/
# -> conformance/results/hosted/<plan>-export.zip
```

`--export-kind` selects `export` (default, JSON+signature) or `exporthtml`
(human-readable). Exports are only downloaded for a **hosted** suite when
**every test passes**; `--export-zip` is ignored (with a warning) for the local
Docker suite. The zips are git-ignored binaries — in CI they're retained via the
`conformance-hosted` workflow's uploaded artifacts
(`gh run download -n conformance-hosted-results`).

### RP client-side logs (`clientSideData`)

OIDF RP certification additionally requires **one log file per test** (named by the
suite test module name), showing the RP's behaviour — in particular that negative
tests are *rejected* ([connect_rp_submission](https://openid.net/certification/connect_rp_submission/)).
The conformance suite only logs the OP side, so the RP harness produces these:

- The harness (`app.py`) routes its own + `py_identity_model` log records to
  `<RP_LOG_DIR>/<profile>/<test_name>.log` for whichever test the runner has
  active, logging explicit `ACCEPTED` / `REJECTED: <reason>` decision lines.
- `run_tests.py --rp-logs-zip PATH` resets that per-profile directory before the
  run and zips it after — one zip per profile, the `clientSideData` you submit.

```bash
make conformance-test HOSTED=1 CONFORMANCE_SERVER=https://www.certification.openid.net/
# -> conformance/results/hosted/<plan>-rp-logs.zip  (one <test_name>.log per test)
```

`RP_LOG_DIR` defaults to `conformance/results/hosted/rp-logs` (an absolute path
derived from the source location, so the harness and the separately-launched
runner agree regardless of working directory); override it for *both* processes
if you change it. The logs are captured regardless of pass/fail — the logs for a
failed test are exactly what you'd want to inspect.

### Submission (manual — the actual OIDF certification)

Submission is **not automated here**. The current OIDF flow is portal-based:
fill the web form at <https://submissions.openid.net/>, upload the test result
zips (`*-export.zip`) + client data (`*-rp-logs.zip`) per profile, and OIDF
generates the Certification of Conformance and emails a **DocuSign** signature
request — there is no PDF template to fill manually.

(The suite's `scripts/conformance.py` also exposes a programmatic
`POST /api/plan/{plan_id}/certificationpackage` taking a *pre-signed* PDF +
`clientSideData`, which **publishes and permanently freezes** the plan. The
portal is the standard route.)

This is the owner-driven step tracked in **#331**. See the full write-up in
[`docs/certification.md`](../docs/certification.md).

`--publish {none,summary,everything}` (default `none`) is independent: it only
controls whether a *run* is listed on the public published-tests list. The
hosted CI workflow exposes the same choice as a `workflow_dispatch` input.
