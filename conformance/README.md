# OIDF Conformance Harness

identity-model proves its Relying-Party (client) implementations conformant by
driving them through the **official [OpenID Foundation conformance
suite](https://gitlab.com/openid/conformance-suite)** — the same approach the
OIDF-certified [`py-identity-model`](https://github.com/jamescrowley321/py-identity-model)
reference uses. This directory holds the language-neutral harness; the
per-language Relying-Party (RP) apps are added alongside it.

## Architecture

```
conformance/
├── docker-compose.yml   # OIDF suite + mongo + nginx (TLS) + cert-init
├── nginx/               # TLS front for the suite (localhost.emobix.co.uk:8443)
├── configs/             # OIDF test-plan definitions (plan_name + variant + client)
├── run_tests.py         # orchestration runner — drives the suite REST API + an RP
├── requirements.txt     # runner deps (httpx only)
├── rp-go/               # Go RP harness      (added in K2)
└── rp-rust/             # Rust RP harness    (added in K3)
```

The **runner** (`run_tests.py`) is a thin, language-neutral client of the suite's
REST API: it creates a plan, creates each test module, drives the RP through the
flow, polls until each test finishes, and gates on a strict set of passing
statuses (`PASSED` / `WARNING` / `SKIPPED`; an empty run or a `REVIEW` is **not**
a pass). Because it drives the RP purely over `--rp-url`, the *same* runner and
the *same* plans exercise every language's RP harness — one for Go, one for Rust.

## Status — K1 (this PR)

The suite infrastructure and the runner are ported and working; **no RP harness
exists yet**, so full test runs come with the Go RP (K2) and Rust RP (K3). What
works today:

- `docker compose up` brings up the OIDF suite at `https://localhost.emobix.co.uk:8443`.
- `run_tests.py` can reach the suite and create a plan.

## Running the suite

> **One suite per host.** The suite binds port `8443` and the hostname
> `localhost.emobix.co.uk` (an OIDF convention resolving to `127.0.0.1`). Stop
> any other conformance stack before starting this one.

```bash
# Bring the suite up (first run pulls the suite image and builds nginx)
docker compose -f conformance/docker-compose.yml up -d --build --wait

# Suite UI / API is now at https://localhost.emobix.co.uk:8443
#   (self-signed cert — the RP harnesses trust it via SSL_CERT_FILE)

# Tear down
docker compose -f conformance/docker-compose.yml down -v
```

## Running a plan (once an RP harness exists, K2+)

```bash
python3 -m pip install -r conformance/requirements.txt   # httpx
# with the Go RP running on http://localhost:8888:
python3 conformance/run_tests.py --plan basic-rp --rp-url http://localhost:8888
```

Plans (`configs/*.json`) mirror the OIDF RP-certification plans:

| Config | OIDF plan |
|--------|-----------|
| `basic-rp` | `oidcc-client-basic-certification-test-plan` |
| `config-rp` | `oidcc-client-config-certification-test-plan` |
| `form-post-basic-rp` | `oidcc-client-formpost-basic-certification-test-plan` |

Runner flags: `--suite-url` (default `https://localhost.emobix.co.uk:8443`, env
`CONFORMANCE_SERVER`), `--rp-url` (default `http://localhost:8888`), `--output`,
`--export-zip`, `--publish {none,summary,everything}`. Hosted runs against
`https://www.certification.openid.net/` require `CONFORMANCE_TOKEN` and are wired
in a later step (K5).

## Scope note

The OIDF **client** suite certifies the RP login flow (discovery, JWKS + key
rotation, ID-token validation, auth-code/PKCE, `form_post`, UserInfo). It does
**not** cover Extended-tier client behavior (introspection, revocation, token
exchange, DPoP) — those remain validated by their unit + integration tests.
