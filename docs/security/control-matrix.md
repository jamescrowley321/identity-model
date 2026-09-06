# Security Control Matrix

This matrix is the authoritative map from each **security control** in
`py-identity-model` to the **RFC/attack** it defends against and the
**fail-closed test** that proves it. It is the human-readable companion to the
mechanical mutation gate (`make mutation-security`, Epic 19 G.1): a control is
only "done" when a test under `src/tests/security/` fails if the control is
deleted, and that test kills the corresponding mutant.

The Go and Rust libraries carry the same diff-scoped gate
(`make mutation-security-go` / `make mutation-security-rust`, driven by
`tools/mutation_security_native.py`): every mutant on a changed line inside the
language's security surface must be killed, or waived as an equivalent mutant
in `tools/mutation_security_go_allowlist.txt` /
`tools/mutation_security_rust_allowlist.txt`. Waivers are content-keyed — a
16-hex hash of the transformation itself, never a line number — so position
drift cannot silently rebind a waiver to a different mutant; the driver's
docstring and the allowlist headers document the exact key for each language.

**Provenance:** rows track the remediation of the 2026-08-02 red/blue security
audit (Epic 16, tracked in #476) and the mechanical-gate foundation
(Epic 19). Each remediation task (SC1–SC10) flips its own row from `pending`
to `shipped` and links its proving test as it lands.

## How to read this

| Column | Meaning |
| ------ | ------- |
| **Control** | The specific fail-closed behavior the library enforces. |
| **Module** | Where the control lives (all under `src/py_identity_model/`). |
| **RFC / spec** | The normative requirement the control implements. |
| **Attack (audit ref)** | The threat the control defends against, and its audit finding. |
| **Proving test** | The `src/tests/security/` test whose failure means the control regressed. |
| **Status** | `shipped` (control + proving test merged) or `pending` (remediation task not yet landed). |

## Controls

| Control | Module | RFC / spec | Attack (audit ref) | Proving test | Status |
| ------- | ------ | ---------- | ------------------ | ------------ | ------ |
| Basic-auth credential form-urlencoding | `core/client_auth.py` | RFC 6749 §2.3.1 / App. B | Reserved chars in `client_id`/secret mangled or `:` splits credential (R.5, #482) | `security/test_basic_auth_encoding.py` | shipped |
| Reject alg downgrade / confusion (honor caller allowlist; never trust token header) | `core/parsers.py`, `core/token_validation_logic.py`, `core/jwt_helpers.py` | RFC 7515 §4.1.1, RFC 8725 §2.1 | HS/`none` alg-confusion & downgrade forgery (R.1) | `security/test_alg_confusion_contract.py` | shipped |
| Issuer allowlist pinning before trusting discovery | `core/token_validation_logic.py`, `core/models.py` | OIDC Core §2, RFC 9207 | Multi-tenant issuer spoofing (R.9) | `security/test_issuer_pinning.py` | shipped |
| Sender-constrained tokens (`cnf.x5t#S256` / `cnf.jkt`) + strict audience | `core/mtls.py`, `core/dpop.py`, `core/token_validation_logic.py` | RFC 8705 §3, RFC 9449 §7 | Stolen-token replay against a bearer RS (R.2) | _pending SC3_ | pending |
| Enforce `verify_aud` / `verify_iss` / `require exp` | `core/jwt_helpers.py`, `core/token_validation_logic.py` | RFC 7519 §4.1, RFC 8725 §3.x | Audience/issuer/expiry checks silently disabled (R.3) | _pending SC4_ | pending |
| Require `sub` claim on ID tokens | `core/token_validation_logic.py` | OIDC Core §2 | ID token accepted without a subject (R.10) | _pending SC5_ | pending |
| Reject / try-all on duplicate `kid` | `core/jwks_logic.py`, `core/jwt_helpers.py` | RFC 7517 §4.5 | Colliding-`kid` silent first-match key confusion (R.11) | _pending SC6_ | pending |
| Conformance evidence integrity (gated profiles, honest pass statuses) | `conformance/` | OIDF RP conformance | Inflated conformance claims from ungated/skipped profiles (R.7) | _pending SC7_ | pending |
| mTLS endpoint-alias routing + fail-closed cert presentation | `core/mtls.py` | RFC 8705 §5 | Requests bypass mTLS aliases; cert never actually presented (R.6) | _pending SC8_ | pending |
| DPoP proofs on refresh-token & client-credentials grants | `core/dpop.py`, token clients | RFC 9449 §5 | Refresh/CC tokens issued unbound to the DPoP key (R.4) | _pending SC9_ | pending |

_Rows are added/flipped to `shipped` by the remediation task that lands the control (see the stacked-PR queue in the workstream prompt)._
