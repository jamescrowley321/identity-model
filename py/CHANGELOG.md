# CHANGELOG

<!-- version list -->

## v3.12.0 (2026-09-04)

### Chores

- Sync uv.lock with 3.11.5
  ([`111f6fa`](https://github.com/jamescrowley321/identity-model/commit/111f6fad65b5b12746cb4edbc7ecc9a70ad33298))

### Continuous Integration

- **deps)(deps**: Bump actions/deploy-pages in the github-actions group
  ([#606](https://github.com/jamescrowley321/identity-model/pull/606),
  [`3c8336b`](https://github.com/jamescrowley321/identity-model/commit/3c8336b290f9ac740a5fb729b1bd2308c11d595a))

### Features

- **token-validation**: Make discovery policy injectable on the cached path
  ([#585](https://github.com/jamescrowley321/identity-model/pull/585),
  [`00fcac0`](https://github.com/jamescrowley321/identity-model/commit/00fcac0da0ae055393d1336362711b6d5b422d23))

### Testing

- **token-validation**: Prove injected discovery policy on rotation/retry paths
  ([#585](https://github.com/jamescrowley321/identity-model/pull/585),
  [`00fcac0`](https://github.com/jamescrowley321/identity-model/commit/00fcac0da0ae055393d1336362711b6d5b422d23))


## v3.11.5 (2026-09-04)

### Bug Fixes

- **token-validation**: Accept JsonWebKey and null-safe key dicts
  ([#587](https://github.com/jamescrowley321/identity-model/pull/587),
  [`80c7825`](https://github.com/jamescrowley321/identity-model/commit/80c78250d919a0500ef845b1be40b4f9b8fe7216))

### Chores

- Sync uv.lock with 3.11.4
  ([`f221801`](https://github.com/jamescrowley321/identity-model/commit/f2218010984450f4ec84c980de6975d6d956f5c5))

### Continuous Integration

- Remove adversarial-review merge gate (unstable)
  ([#591](https://github.com/jamescrowley321/identity-model/pull/591),
  [`2b9c688`](https://github.com/jamescrowley321/identity-model/commit/2b9c6887854aad3df9bf20588bcbaff2b1fb596c))

- **conformance**: Gate releases on conformance + run it daily off main
  ([#571](https://github.com/jamescrowley321/identity-model/pull/571),
  [`606dd32`](https://github.com/jamescrowley321/identity-model/commit/606dd32de37e1d65380cfe3150aa711f0b77ca8e))

- **conformance**: Pin OIDF suite image to release-v5.2.4 (stop :latest drift)
  ([#582](https://github.com/jamescrowley321/identity-model/pull/582),
  [`1b286c0`](https://github.com/jamescrowley321/identity-model/commit/1b286c0a22da05f55a1646bd26fce404bacbe565))

- **deps)(deps**: Bump softprops/action-gh-release
  ([#581](https://github.com/jamescrowley321/identity-model/pull/581),
  [`6008e2e`](https://github.com/jamescrowley321/identity-model/commit/6008e2e759207ace0e8c28d2090f2ddbc92db3e7))

- **deps)(deps**: Bump the github-actions group with 4 updates
  ([#580](https://github.com/jamescrowley321/identity-model/pull/580),
  [`27c3134`](https://github.com/jamescrowley321/identity-model/commit/27c313482f867d49f7ad901df338cdd9f2952cc7))

- **deps-dev**: Bump mkdocs-material from 9.7.6 to 9.7.7 in /py
  ([#589](https://github.com/jamescrowley321/identity-model/pull/589),
  [`b9a400c`](https://github.com/jamescrowley321/identity-model/commit/b9a400c7d73910de30715b244ca10576a78a6965))

- **release**: Auto-tag and publish Go and Rust releases
  ([#570](https://github.com/jamescrowley321/identity-model/pull/570),
  [`7be588e`](https://github.com/jamescrowley321/identity-model/commit/7be588e03a4f41b4f9a676acffb09753d0664511))

- **release**: Drop orphaned directory line from asset-upload step
  ([`e229748`](https://github.com/jamescrowley321/identity-model/commit/e229748831e89fde3259d1df356bf4ce43bd395b))

- **release**: Pin gitpython<3.1.60 in the fastapi-version job too
  ([`e87a31c`](https://github.com/jamescrowley321/identity-model/commit/e87a31c15a55590509a9d5ea54137d63aa58268c))

- **security-gate**: Scope mutation gate to changed lines, not whole functions
  ([#588](https://github.com/jamescrowley321/identity-model/pull/588),
  [`fde917a`](https://github.com/jamescrowley321/identity-model/commit/fde917a5448ecd31d971963994bc406b5a0511b3))


## v3.11.4 (2026-08-28)

### Bug Fixes

- **release**: Pin GitPython <3.1.60 to unblock semantic-release
  ([#567](https://github.com/jamescrowley321/identity-model/pull/567),
  [`748c09f`](https://github.com/jamescrowley321/identity-model/commit/748c09f29a7ddc44fc2acb8d3ad9dca0f3ae53cc))

- **token-validation**: Use JWT header alg when a kid-matched JWKS key omits alg
  ([#562](https://github.com/jamescrowley321/identity-model/pull/562),
  [`d646628`](https://github.com/jamescrowley321/identity-model/commit/d646628c7d8eba4489a7ed9446887102cd853e1c))

### Chores

- Sync uv.lock with 3.11.3
  ([`00a3f67`](https://github.com/jamescrowley321/identity-model/commit/00a3f67071dc1d2d97c0c51bb84637fc438caca3))

- **deps)(deps**: Bump the python-dependencies group with 4 updates
  ([#565](https://github.com/jamescrowley321/identity-model/pull/565),
  [`9bf6d70`](https://github.com/jamescrowley321/identity-model/commit/9bf6d707576378bb8a725f70fadd7cf7a2954111))

### Continuous Integration

- **deps)(deps**: Bump the github-actions group with 6 updates
  ([#566](https://github.com/jamescrowley321/identity-model/pull/566),
  [`4831b26`](https://github.com/jamescrowley321/identity-model/commit/4831b26d56c18a8b3b913379ee6c1ae4eafe4fc9))

### Testing

- **security**: Pin find_key_by_kid mutants; fix spec-conformance sandbox path
  ([#562](https://github.com/jamescrowley321/identity-model/pull/562),
  [`d646628`](https://github.com/jamescrowley321/identity-model/commit/d646628c7d8eba4489a7ed9446887102cd853e1c))


## v3.11.3 (2026-08-22)

### Bug Fixes

- **http**: Honor the documented HTTP_RETRY_COUNT env var
  ([`e7d7520`](https://github.com/jamescrowley321/identity-model/commit/e7d75205d7b920b3a80cc42ddf0b4c942fa3df19))

### Build System

- **moon**: Add moon workspace orchestration + reserve /node scaffold (CONS-2.3)
  ([`9141c0d`](https://github.com/jamescrowley321/identity-model/commit/9141c0d0b011fbcaf3a8182d8e0d316b0b278b42))

### Chores

- Sync uv.lock with 3.11.2
  ([`513f7e7`](https://github.com/jamescrowley321/identity-model/commit/513f7e7d3f95b8e9fe453132dd60e5bd07b38338))

- **rename**: Repoint references to jamescrowley321/identity-model
  ([`77a1a65`](https://github.com/jamescrowley321/identity-model/commit/77a1a65fcfee0d136c9912d9ab7bd85bff0cae8b))

### Continuous Integration

- Add adversarial review merge gate
  ([#552](https://github.com/jamescrowley321/identity-model/pull/552),
  [`56ea098`](https://github.com/jamescrowley321/identity-model/commit/56ea098bb7b50ec1e704ef79ccef0491c713391a))

- Fail the merge gate closed for fork/bot PRs
  ([#552](https://github.com/jamescrowley321/identity-model/pull/552),
  [`56ea098`](https://github.com/jamescrowley321/identity-model/commit/56ea098bb7b50ec1e704ef79ccef0491c713391a))

- Fix adversarial-review preflight check names
  ([#552](https://github.com/jamescrowley321/identity-model/pull/552),
  [`56ea098`](https://github.com/jamescrowley321/identity-model/commit/56ea098bb7b50ec1e704ef79ccef0491c713391a))

- Harden merge gate — fail closed on partial review, guard empty lens set
  ([#552](https://github.com/jamescrowley321/identity-model/pull/552),
  [`56ea098`](https://github.com/jamescrowley321/identity-model/commit/56ea098bb7b50ec1e704ef79ccef0491c713391a))

- **release**: Fix Go release (drop GoReleaser) + nightly native-suite skip (CONS-2.4 review)
  ([`9aadb05`](https://github.com/jamescrowley321/identity-model/commit/9aadb056f697521e7667b32306a2b56348a33b6b))

- **release**: Go + Rust release pipelines + change-detected CI (CONS-2.4)
  ([`fa75cc0`](https://github.com/jamescrowley321/identity-model/commit/fa75cc03274ae8888caab5df619456d926d36512))

- **release**: Make publish-parity directional + harden (CONS-2.5 review)
  ([`0198391`](https://github.com/jamescrowley321/identity-model/commit/019839103ae5cab05ddb19744282583edae0137b))

- **release**: Publish core py-identity-model to PyPI via OIDC Trusted Publishing
  ([`324fa54`](https://github.com/jamescrowley321/identity-model/commit/324fa5482420f6fdfa1de5508b78b1ff621c81df))

- **release**: Publishing-parity gate — prove /py packages byte-for-byte (CONS-2.5)
  ([`846fdcd`](https://github.com/jamescrowley321/identity-model/commit/846fdcd9febafde8d9532bc8ce04e270972a0e35))

- **release**: Py-v tag scheme + guard core release from cross-language commits (CONS-2.2)
  ([`fc09e50`](https://github.com/jamescrowley321/identity-model/commit/fc09e5017ed3aa9e560b94b4adb5d0f4f571c893))

### Documentation

- Write for users — drop process narration, call them native libraries
  ([#551](https://github.com/jamescrowley321/identity-model/pull/551),
  [`54b6dd6`](https://github.com/jamescrowley321/identity-model/commit/54b6dd6047e6a540a9427b16b56af1c16b14a48d))

- **readme**: Lead with the vision, not a directory listing
  ([#555](https://github.com/jamescrowley321/identity-model/pull/555),
  [`094e589`](https://github.com/jamescrowley321/identity-model/commit/094e58993dbc67ccbbe28c4967d01f43179964de))

- **readme**: Lead with what we have, drop the .NET framing
  ([#558](https://github.com/jamescrowley321/identity-model/pull/558),
  [`7d4c737`](https://github.com/jamescrowley321/identity-model/commit/7d4c7372967e96a55e93117b6334f5bb2746f244))

- **readme**: Surface the OpenID certification on the landing pages
  ([#559](https://github.com/jamescrowley321/identity-model/pull/559),
  [`d1fad88`](https://github.com/jamescrowley321/identity-model/commit/d1fad88795d328a0b17eda95c5f394c159d2d697))

- **release**: Correct release_parsers module docstring to py-v tag format
  ([`ecca6bb`](https://github.com/jamescrowley321/identity-model/commit/ecca6bbd8f003a5335149879a8f322bc00cc561c))


## v3.11.2 (2026-08-21)

### Bug Fixes

- **cons2.1**: Address adversarial review — un-break docs, un-vacuum security gate, fix
  release-asset upload
  ([`4954c30`](https://github.com/jamescrowley321/identity-model/commit/4954c30d5ec99af9512c0dd19789b35c4aa3427a))

- **cons2.1**: Make mutation-security gate rename-aware (exclude pure moves)
  ([`5a8ad60`](https://github.com/jamescrowley321/identity-model/commit/5a8ad604889fac3ba9446323ef871a8051f0c980))

### Refactoring

- **cons2.1**: Drop inline S603 noqas, scope subprocess policy properly
  ([`3b68213`](https://github.com/jamescrowley321/identity-model/commit/3b682130918d53f7051f3f644704df19afc57e20))

- **layout**: Relocate Python package into /py (CONS-2.1)
  ([`649b954`](https://github.com/jamescrowley321/identity-model/commit/649b95430e5b6c738d5ebf04d1ffdebcb5568157))


## v3.11.1 (2026-08-20)

### Bug Fixes

- **rust**: Remove dead RUSTSEC-2023-0071 allowlist from deny.toml
  ([#541](https://github.com/jamescrowley321/identity-model/pull/541),
  [`d683095`](https://github.com/jamescrowley321/identity-model/commit/d683095773c2bb478bee5a3c03c98bb38e9c59d9))

### Chores

- **rust**: Import Rust binding under /rust (CONS-1.2)
  ([#541](https://github.com/jamescrowley321/identity-model/pull/541),
  [`d683095`](https://github.com/jamescrowley321/identity-model/commit/d683095773c2bb478bee5a3c03c98bb38e9c59d9))

### Continuous Integration

- **load**: Upload PR-gate load-smoke summary as an artifact
  ([#542](https://github.com/jamescrowley321/identity-model/pull/542),
  [`b460611`](https://github.com/jamescrowley321/identity-model/commit/b46061150adeaf1e5fac6a5a85a94a2fc2b2122a))

### Refactoring

- **rust**: Drop rsa crate (RUSTSEC-2023-0071) via aws_lc_rs backend
  ([#541](https://github.com/jamescrowley321/identity-model/pull/541),
  [`d683095`](https://github.com/jamescrowley321/identity-model/commit/d683095773c2bb478bee5a3c03c98bb38e9c59d9))

### Testing

- **load**: Make S1 warm-cache proof request-count-independent
  ([#539](https://github.com/jamescrowley321/identity-model/pull/539),
  [`60cfdf4`](https://github.com/jamescrowley321/identity-model/commit/60cfdf4e90cc5964a0240ad3be76e8e9e3d57a4a))


## v3.11.0 (2026-08-18)

### Bug Fixes

- **go**: Narrow spec-fixture guards so non-fixture unit tests run (CONS-1.1)
  ([#538](https://github.com/jamescrowley321/identity-model/pull/538),
  [`6c8f12c`](https://github.com/jamescrowley321/identity-model/commit/6c8f12c58d4fc7c539d84fc549f27519f45fb0cd))

### Documentation

- Consolidation plan — identity-model into py-identity-model
  ([#533](https://github.com/jamescrowley321/identity-model/pull/533),
  [`a10c63a`](https://github.com/jamescrowley321/identity-model/commit/a10c63ab195b553bc424715ca7bf93582579029a))

- Design-of-record for consolidating identity-model into py-identity-model
  ([#533](https://github.com/jamescrowley321/identity-model/pull/533),
  [`a10c63a`](https://github.com/jamescrowley321/identity-model/commit/a10c63ab195b553bc424715ca7bf93582579029a))

- Refine plan — /py|/go|/rust layout, moon orchestrator, tag scheme
  ([#533](https://github.com/jamescrowley321/identity-model/pull/533),
  [`a10c63a`](https://github.com/jamescrowley321/identity-model/commit/a10c63ab195b553bc424715ca7bf93582579029a))

- **go**: Correct imported Go binding README for landed implementation
  ([#538](https://github.com/jamescrowley321/identity-model/pull/538),
  [`6c8f12c`](https://github.com/jamescrowley321/identity-model/commit/6c8f12c58d4fc7c539d84fc549f27519f45fb0cd))

### Features

- **go**: Import Go binding under /go (CONS-1.1)
  ([#538](https://github.com/jamescrowley321/identity-model/pull/538),
  [`6c8f12c`](https://github.com/jamescrowley321/identity-model/commit/6c8f12c58d4fc7c539d84fc549f27519f45fb0cd))


## v3.10.0 (2026-08-14)

### Bug Fixes

- Address delta-review findings in correctness matrix (TH-1.3)
  ([`5fced0d`](https://github.com/jamescrowley321/identity-model/commit/5fced0d7de18b22848c1edf5946d3e1ec53aaf19))

- Address review findings in correctness matrix (TH-1.3)
  ([`fe012df`](https://github.com/jamescrowley321/identity-model/commit/fe012dfb5b1f5d3d797c67ea6397ff48d0a3475e))

- Address review findings in load suite (TH-1.5)
  ([`51e3561`](https://github.com/jamescrowley321/identity-model/commit/51e3561cd6602022fbcccf63d563c34fc2370931))

- Address review findings in RS boot harness (TH-1.2)
  ([`f573ad6`](https://github.com/jamescrowley321/identity-model/commit/f573ad67bca6222e98f38efccbf089020f82359b))

- **cache**: Count cache miss/refresh only on successful upstream fetch
  ([`003724c`](https://github.com/jamescrowley321/identity-model/commit/003724ccf39af04b42ca88739861ea9cb8a05342))

- **harness**: Gate RS-boot suite to node-oidc in the CI matrix (TH-1.2)
  ([`c373ed8`](https://github.com/jamescrowley321/identity-model/commit/c373ed888e3cee1cc77613d58d360982b2ce74b9))

- **token-validation**: Count upstream fetches that FAILED. The
  ([`51e3561`](https://github.com/jamescrowley321/identity-model/commit/51e3561cd6602022fbcccf63d563c34fc2370931))

### Continuous Integration

- **load**: Run CI-short load in PR CI + add nightly soak workflow
  ([`93c5534`](https://github.com/jamescrowley321/identity-model/commit/93c5534a94fe20a8fd005f6e880a66a89766c8f1))

### Documentation

- Add load/soak suite README and CLAUDE.md test command (TH-1.5)
  ([`8115079`](https://github.com/jamescrowley321/identity-model/commit/811507974ce143d035ddcdf723ca4cb7a09e7533))

- Correct CLAUDE.md caching strategy to TTL+LRU cache (T299)
  ([`4a2b33c`](https://github.com/jamescrowley321/identity-model/commit/4a2b33cfb6f37c7cb6e587035a4706a8d0bc8e3a))

- Document Descope multi-tenant harness env vars
  ([`c93b1da`](https://github.com/jamescrowley321/identity-model/commit/c93b1da7029a597e94923a164a1b25b7b6e19a12))

- **performance**: Correct stale lru_cache/cache_info docs to TTL-LRU reality
  ([`54e93f3`](https://github.com/jamescrowley321/identity-model/commit/54e93f34690cf2b83f1276aa0f0cd8f33a3337df))

### Features

- **cache**: Add per-process cache observability counters
  ([`84a2548`](https://github.com/jamescrowley321/identity-model/commit/84a2548cbadb8ce8c79a13bde72d0ce7a736a4fc))

- **harness**: Mock-OP upstream-fetch counters + RS /metrics readout
  ([`9302509`](https://github.com/jamescrowley321/identity-model/commit/930250926e82c0670dc3aba89f903f0ea5db8323))

### Testing

- Cover LoadResult p999 + cache_hit_rate + alg_cost_ratio (TH-1.5)
  ([`6315c79`](https://github.com/jamescrowley321/identity-model/commit/6315c7999ccdb7a6a9faab3d3d5e54c79b551fe0))

- **benchmarks**: Add validate_token warm-path micro-benchmark
  ([`dfaad6f`](https://github.com/jamescrowley321/identity-model/commit/dfaad6f715c6fcdf8e9d144f72c886e3141ee7ed))

- **cache**: Pin kid-miss cooldown in amplification tests to remove wall-clock flake
  ([`e84880d`](https://github.com/jamescrowley321/identity-model/commit/e84880dbcc3a8dd178f9e86d5a2f54bd4c6d12f9))

- **harness**: Add token_source fixture + real-IdP DoD test (TH-1.1)
  ([`bdb0dd6`](https://github.com/jamescrowley321/identity-model/commit/bdb0dd613a3956731e065c8a07b1f0627957c94f))

- **harness**: Add TokenSource minter, mock OP + forged corpus (TH-1.1)
  ([`c506ca4`](https://github.com/jamescrowley321/identity-model/commit/c506ca432269560b84480de2ff983e29d9f09738))

- **harness**: Boot fastapi-identity-model as a real resource server (TH-1.2)
  ([`57b3068`](https://github.com/jamescrowley321/identity-model/commit/57b3068092fd5028fce15d6a740a6f1dbd5ba260))

- **harness**: Close uvicorn stdout pipe in boot_rs teardown
  ([`ae119da`](https://github.com/jamescrowley321/identity-model/commit/ae119da737d0550f5450b2ea36c05a7e2686ca52))

- **harness**: Crash-harden mock OP + real Descope multi-tenant exchange (TH-1.1, #463)
  ([`b689aed`](https://github.com/jamescrowley321/identity-model/commit/b689aedfc4f3ca11ce87fce38211160533faa00b))

- **harness**: Delete descope access-key even on empty-cleartext response (TH-1.1, #463)
  ([`c7f47a1`](https://github.com/jamescrowley321/identity-model/commit/c7f47a1d2a567aaca3f8e2eec787f151471fc313))

- **harness**: Serve mock OP over real HTTP for out-of-proc RS (TH-1.3)
  ([`607d5e0`](https://github.com/jamescrowley321/identity-model/commit/607d5e05be575965befd8905a9d956bb5b2d95fa))

- **harness**: Token correctness assertion matrix through booted RS (TH-1.3)
  ([`cd9f39e`](https://github.com/jamescrowley321/identity-model/commit/cd9f39e3248bfc66a1c4f2b66e2250ef8ca126cf))

- **harness**: Waive equivalent log-string mutants in _refresh_jwks (TH-1.5)
  ([`52eeb54`](https://github.com/jamescrowley321/identity-model/commit/52eeb547b11672371d98f3cfe6f30ebe52359954))

- **load**: Locust scenario framework + pre-minted pool replay (S1-S8 CI-short)
  ([`aa87eb7`](https://github.com/jamescrowley321/identity-model/commit/aa87eb7e6899ece3a8622206ef644d685b114002))

- **security**: Fail-closed tests for aio cache fetch controls (T299)
  ([`43be93b`](https://github.com/jamescrowley321/identity-model/commit/43be93bc942f255d6066bdbc82b941a1beb35c4b))


## v3.9.0 (2026-08-10)

### Features

- **security**: Opt-in multi-tenant issuer pinning via allowed_issuers (R.9)
  ([#512](https://github.com/jamescrowley321/identity-model/pull/512),
  [`428e139`](https://github.com/jamescrowley321/identity-model/commit/428e139303c2119c8713c8cd72c8efc2785ceba5))


## v3.8.7 (2026-08-10)

### Bug Fixes

- **discovery**: Close IP-encoding SSRF bypass + surface off-host escape hatch (F-05/F-06)
  ([#506](https://github.com/jamescrowley321/identity-model/pull/506),
  [`ef812e6`](https://github.com/jamescrowley321/identity-model/commit/ef812e6bb28d6b2a1482fe3b37f8f5939ec8df5b))

### Chores

- Sync uv.lock with 3.8.6
  ([`afd1b46`](https://github.com/jamescrowley321/identity-model/commit/afd1b4678f1fe82973f79b1a198883cf96782bda))


## v3.8.6 (2026-08-10)

### Bug Fixes

- **security**: Reject HS*/none against an asymmetric key with a typed error (F-01)
  ([#507](https://github.com/jamescrowley321/identity-model/pull/507),
  [`3d3b49a`](https://github.com/jamescrowley321/identity-model/commit/3d3b49ae29596126d771d45f08a6c90c161b66f9))


## v3.8.5 (2026-08-09)

### Bug Fixes

- **ci**: Anchor version sed so it can't corrupt the cryptography pin
  ([#505](https://github.com/jamescrowley321/identity-model/pull/505),
  [`ab7f992`](https://github.com/jamescrowley321/identity-model/commit/ab7f992f5bfc04914098f178790972ead8dd96c7))


## v3.8.4 (2026-08-09)

### Bug Fixes

- **ci**: Pin uv to 0.11.29 to unbreak PyPI publish
  ([#504](https://github.com/jamescrowley321/identity-model/pull/504),
  [`e5e3137`](https://github.com/jamescrowley321/identity-model/commit/e5e3137605b03d32687d57c57807b62b10cc1ab2))

### Chores

- Sync uv.lock with 3.8.3
  ([`80c1f4b`](https://github.com/jamescrowley321/identity-model/commit/80c1f4b998cdda50aad19a4fc6e977e3253dfe23))


## v3.8.3 (2026-08-09)

### Bug Fixes

- **discovery**: Reject internal-IP mtls_endpoint_aliases (F-05)
  ([`5d60410`](https://github.com/jamescrowley321/identity-model/commit/5d60410a2bfdccf0f41f9e48acb3bc94c73233c1))

- **discovery**: Validate pushed_authorization_request_endpoint (F-06)
  ([`d9ee46c`](https://github.com/jamescrowley321/identity-model/commit/d9ee46c31ab7b0a3575233b4db10e1b3bcadcf3d))

### Testing

- **integration**: Clear stale cross-run provider cache at session start
  ([#495](https://github.com/jamescrowley321/identity-model/pull/495),
  [`6beb9ad`](https://github.com/jamescrowley321/identity-model/commit/6beb9ad21b9d4b4bda8615bbee7a6d38c501e5c7))

- **integration**: Surface characterization table via CI step summary + artifact
  ([#499](https://github.com/jamescrowley321/identity-model/pull/499),
  [`f89427c`](https://github.com/jamescrowley321/identity-model/commit/f89427c326d51882e5b9f473b93ca29a648be777))

- **integration**: Token characterization harness for F-07 discriminator
  ([#499](https://github.com/jamescrowley321/identity-model/pull/499),
  [`f89427c`](https://github.com/jamescrowley321/identity-model/commit/f89427c326d51882e5b9f473b93ca29a648be777))


## v3.8.2 (2026-08-05)

### Bug Fixes

- **mtls**: Make CertificateBindingError a TokenValidationException subclass
  ([`65f2cc6`](https://github.com/jamescrowley321/identity-model/commit/65f2cc64d7f51bd0feca006abb353f57f8ed5e1e))

### Testing

- **mtls**: Integration proof that cert-binding mismatch fails closed
  ([`71116dd`](https://github.com/jamescrowley321/identity-model/commit/71116dde010c6f7de8b5b48cdbad977fb6e0a1e0))


## v3.8.1 (2026-08-05)

### Bug Fixes

- **deps**: Require cryptography>=50 to patch PYSEC-2026-3552/3553/3554
  ([`7a2c0c7`](https://github.com/jamescrowley321/identity-model/commit/7a2c0c7514214f1f696d4bba71304aa911989edd))

### Continuous Integration

- **prerelease**: Anchor version sed to the project.version line
  ([`3915d42`](https://github.com/jamescrowley321/identity-model/commit/3915d42c2fa715bd0c40a715edc8cb9dd58a2351))


## v3.8.0 (2026-08-02)

### Continuous Integration

- **conformance**: Install cryptography for the test runner
  ([`fc8d8e9`](https://github.com/jamescrowley321/identity-model/commit/fc8d8e90827fefd7222dbdae2f0c82105d8032a1))

### Features

- **conformance**: OIDF RP conformance harness — new profiles + FAPI2/JARM/mTLS
  ([`17650e1`](https://github.com/jamescrowley321/identity-model/commit/17650e1a0da6e681b6be0be08820a445d60fb908))


## v3.7.0 (2026-08-02)

### Bug Fixes

- **jarm**: Harden response parsing per review findings
  ([#218](https://github.com/jamescrowley321/identity-model/pull/218),
  [`91697b8`](https://github.com/jamescrowley321/identity-model/commit/91697b8c812670f7a3d8fe541aee36cea906eca4))

### Documentation

- Document JARM support in feature tables and examples
  ([`8def841`](https://github.com/jamescrowley321/identity-model/commit/8def841d6f03663435cfc29d98e4f34689cf35a5))

- **conformance**: Add repeatable process for adding new profiles
  ([`e70b358`](https://github.com/jamescrowley321/identity-model/commit/e70b3587b76073a8b23ed726152bd31ceb918fab))

### Features

- **jarm**: Add JWT-secured authorization response mode (JARM)
  ([`333b82d`](https://github.com/jamescrowley321/identity-model/commit/333b82d8d7ce388753868741cafb22df8e513716))

- **jarm**: Thread response_mode through the PAR request path
  ([`4e2f9c2`](https://github.com/jamescrowley321/identity-model/commit/4e2f9c2c8a16dc656fa5912b4018cbe7771de204))

### Testing

- **jarm**: Add unit + integration tests for JARM response mode
  ([`7b2bd97`](https://github.com/jamescrowley321/identity-model/commit/7b2bd97ef962d87522ebf4f3fe66cad9f8710fdf))


## v3.6.0 (2026-08-02)

### Bug Fixes

- **mtls**: Address review findings — example, conflict guard, ASCII guard
  ([#215](https://github.com/jamescrowley321/identity-model/pull/215),
  [`545a402`](https://github.com/jamescrowley321/identity-model/commit/545a4027cf42e4a385a7359c190df4dc5afcea18))

- **mtls**: Present client cert on httpx 0.28 + thread mTLS through UserInfo
  ([`528a474`](https://github.com/jamescrowley321/identity-model/commit/528a4745a4c29e2c104c986ef1496522713b3150))

### Documentation

- Document mTLS client auth and cert-bound tokens (RFC 8705)
  ([`8c39748`](https://github.com/jamescrowley321/identity-model/commit/8c39748b09ae3b00b82105837bd0808619bd9216))

### Features

- **mtls**: Add mTLS client auth + certificate-bound token validation (RFC 8705, #215)
  ([`55c2ba0`](https://github.com/jamescrowley321/identity-model/commit/55c2ba09a3e6a220f44a87374913af614448bd06))

### Testing

- **mtls**: Add unit + integration tests for mTLS client auth (RFC 8705, #215)
  ([`4c00748`](https://github.com/jamescrowley321/identity-model/commit/4c0074868bb6cf119190ddacbe026f88f4ccf993))


## v3.5.0 (2026-08-02)

### Bug Fixes

- **auth**: Form-urlencode HTTP Basic client credentials (RFC 6749 §2.3.1)
  ([`ab9e5a5`](https://github.com/jamescrowley321/identity-model/commit/ab9e5a5df9c00f5430b83212784a415ffd25e4f4))

### Features

- **discovery**: Expose pushed_authorization_request_endpoint (RFC 9126 §5)
  ([`21f85e0`](https://github.com/jamescrowley321/identity-model/commit/21f85e0aaa279660a4b7c2c72f400f360efc6363))

- **dpop**: Thread DPoP proofs through PAR + auth-code token requests
  ([`2aabb62`](https://github.com/jamescrowley321/identity-model/commit/2aabb62f8e7f7287e7245001a5a01679747a56c3))

- **dpop**: Thread DPoP proofs through UserInfo resource requests
  ([`e48beba`](https://github.com/jamescrowley321/identity-model/commit/e48bebac34fd10634e4831ff663f9ee7f3ef8e23))


## v3.4.3 (2026-08-02)

### Bug Fixes

- **models**: Guard DeviceAuthorizationResponse repr + redact device_code
  ([#479](https://github.com/jamescrowley321/identity-model/pull/479),
  [`392794a`](https://github.com/jamescrowley321/identity-model/commit/392794ac65e96dbfbd9a13c1f0aaa169bd4f4139))

- **models**: Redact secrets in all token/credential response reprs
  ([#479](https://github.com/jamescrowley321/identity-model/pull/479),
  [`392794a`](https://github.com/jamescrowley321/identity-model/commit/392794ac65e96dbfbd9a13c1f0aaa169bd4f4139))

- **models**: Redact secrets in RefreshTokenResponse/PushedAuthorizationResponse repr
  ([#479](https://github.com/jamescrowley321/identity-model/pull/479),
  [`392794a`](https://github.com/jamescrowley321/identity-model/commit/392794ac65e96dbfbd9a13c1f0aaa169bd4f4139))

- **models**: Redact secrets in response repr (#431)
  ([#479](https://github.com/jamescrowley321/identity-model/pull/479),
  [`392794a`](https://github.com/jamescrowley321/identity-model/commit/392794ac65e96dbfbd9a13c1f0aaa169bd4f4139))

### Testing

- **models**: Assert repr/str redaction for RefreshTokenResponse + PushedAuthorizationResponse
  ([#479](https://github.com/jamescrowley321/identity-model/pull/479),
  [`392794a`](https://github.com/jamescrowley321/identity-model/commit/392794ac65e96dbfbd9a13c1f0aaa169bd4f4139))


## v3.4.2 (2026-07-31)

### Bug Fixes

- **jwks-cache**: Guard write-path reinsert with the structure lock too
  ([#461](https://github.com/jamescrowley321/identity-model/pull/461),
  [`4627094`](https://github.com/jamescrowley321/identity-model/commit/4627094452275516cefa168d71579e48fc5a1db7))

- **jwks-cache**: LRU eviction — refresh recency on read hits
  ([#461](https://github.com/jamescrowley321/identity-model/pull/461),
  [`4627094`](https://github.com/jamescrowley321/identity-model/commit/4627094452275516cefa168d71579e48fc5a1db7))

- **jwks-cache**: Serialize cache clear() under the structure lock too
  ([#461](https://github.com/jamescrowley321/identity-model/pull/461),
  [`4627094`](https://github.com/jamescrowley321/identity-model/commit/4627094452275516cefa168d71579e48fc5a1db7))

- **jwks-cache**: Serialize LRU reorder vs eviction with a process-wide lock
  ([#461](https://github.com/jamescrowley321/identity-model/pull/461),
  [`4627094`](https://github.com/jamescrowley321/identity-model/commit/4627094452275516cefa168d71579e48fc5a1db7))

- **jwks-cache**: Switch JWKS/disco caches to LRU eviction (T236, #397)
  ([#461](https://github.com/jamescrowley321/identity-model/pull/461),
  [`4627094`](https://github.com/jamescrowley321/identity-model/commit/4627094452275516cefa168d71579e48fc5a1db7))

### Testing

- **jwks-cache**: Add end-to-end discovery-cache LRU eviction test
  ([#461](https://github.com/jamescrowley321/identity-model/pull/461),
  [`4627094`](https://github.com/jamescrowley321/identity-model/commit/4627094452275516cefa168d71579e48fc5a1db7))


## v3.4.1 (2026-07-27)

### Bug Fixes

- **conformance**: Surface exc.message instead of str(exc) in logout error
  ([#459](https://github.com/jamescrowley321/identity-model/pull/459),
  [`edce8ca`](https://github.com/jamescrowley321/identity-model/commit/edce8ca3485574efcaed1b2f2b2601404c5043a5))


## v3.4.0 (2026-07-27)

### Bug Fixes

- Address review findings for RFC 9207 issuer validation
  ([#457](https://github.com/jamescrowley321/identity-model/pull/457),
  [`5c2fed7`](https://github.com/jamescrowley321/identity-model/commit/5c2fed70008a9a9c4fbdd25bb38ac3850b54cfb0))

### Documentation

- Surface RFC 9207 issuer identification in README and API nav
  ([#457](https://github.com/jamescrowley321/identity-model/pull/457),
  [`5c2fed7`](https://github.com/jamescrowley321/identity-model/commit/5c2fed70008a9a9c4fbdd25bb38ac3850b54cfb0))

- Surface RFC 9207 issuer validator in API reference
  ([#457](https://github.com/jamescrowley321/identity-model/pull/457),
  [`5c2fed7`](https://github.com/jamescrowley321/identity-model/commit/5c2fed70008a9a9c4fbdd25bb38ac3850b54cfb0))

### Features

- **state-validation**: Add RFC 9207 authorization-response issuer validation
  ([#457](https://github.com/jamescrowley321/identity-model/pull/457),
  [`5c2fed7`](https://github.com/jamescrowley321/identity-model/commit/5c2fed70008a9a9c4fbdd25bb38ac3850b54cfb0))

### Testing

- **state-validation**: Cover RFC 9207 issuer validation + iss discovery field
  ([#457](https://github.com/jamescrowley321/identity-model/pull/457),
  [`5c2fed7`](https://github.com/jamescrowley321/identity-model/commit/5c2fed70008a9a9c4fbdd25bb38ac3850b54cfb0))


## v3.3.0 (2026-07-21)

### Bug Fixes

- Address review findings in live logout/registration tests
  ([#454](https://github.com/jamescrowley321/identity-model/pull/454),
  [`36f6e3e`](https://github.com/jamescrowley321/identity-model/commit/36f6e3ecf9944a7d585f31efcaf9937ab3dc1f9b))

- Address review findings in live logout/registration tests
  ([#453](https://github.com/jamescrowley321/identity-model/pull/453),
  [`3fbd6e3`](https://github.com/jamescrowley321/identity-model/commit/3fbd6e33569e19ac1418454ec2468a5b987d3040))

- Harden Keycloak fixture healthcheck (bash -c + anchored status match)
  ([`60aada0`](https://github.com/jamescrowley321/identity-model/commit/60aada00f744817ca693cba10c854ea5a7157e66))

- Relax over-specified identity assertions in matrix tests
  ([`8330f21`](https://github.com/jamescrowley321/identity-model/commit/8330f21677aeda9ad123fc2d6f33b4cf13e5725e))

- **jwks**: Serialize x5t#S256 with the RFC 7517 member name
  ([`ff3a290`](https://github.com/jamescrowley321/identity-model/commit/ff3a29029cd35b1ccac0284389b634f5116ad55f))

- **keycloak**: Harden login-form parser and identifier handling
  ([`bb0f0cd`](https://github.com/jamescrowley321/identity-model/commit/bb0f0cdf5df350493d43896eb2663851f59ee61d))

- **logout**: Address RP-initiated logout review findings
  ([`4a55e0c`](https://github.com/jamescrowley321/identity-model/commit/4a55e0c8c6901fe0854ec20409a6aedae05d2d71))

- **logout**: Return 400 for malformed logout tokens; snapshot flow context
  ([`337a463`](https://github.com/jamescrowley321/identity-model/commit/337a4639f926005a1a006ae618fde0acf08bf325))

- **registration**: Guard client_secret and truncate error-body echo
  ([`9276901`](https://github.com/jamescrowley321/identity-model/commit/927690148d476d56fd3d40edf89d49b366dd7e87))

### Build System

- **keycloak**: Add keycloak integration tests to make pre-push
  ([#454](https://github.com/jamescrowley321/identity-model/pull/454),
  [`36f6e3e`](https://github.com/jamescrowley321/identity-model/commit/36f6e3ecf9944a7d585f31efcaf9937ab3dc1f9b))

- **keycloak**: Add local Keycloak test fixture (docker-compose + realm + README)
  ([`0382826`](https://github.com/jamescrowley321/identity-model/commit/03828266ff6498dd94d4c37069cfe9e89b8130f0))

- **keycloak**: Enable device grant + token exchange; fix test-user password
  ([`4189692`](https://github.com/jamescrowley321/identity-model/commit/41896927990afee034c0ad0b21d354762882dbdd))

- **keycloak**: Grant test-user offline_access role
  ([`545c898`](https://github.com/jamescrowley321/identity-model/commit/545c898ac09bb4cbca0330b838e28fe6685d6971))

### Continuous Integration

- **deps)(deps**: Bump actions/setup-python in the github-actions group
  ([#445](https://github.com/jamescrowley321/identity-model/pull/445),
  [`f68891f`](https://github.com/jamescrowley321/identity-model/commit/f68891f3f31c691558b00bb1220f3cf26bbce138))

- **keycloak**: Add Keycloak integration CI job, pre-push, and docs
  ([#454](https://github.com/jamescrowley321/identity-model/pull/454),
  [`36f6e3e`](https://github.com/jamescrowley321/identity-model/commit/36f6e3ecf9944a7d585f31efcaf9937ab3dc1f9b))

- **keycloak**: Add Keycloak integration job mirroring node-oidc
  ([#454](https://github.com/jamescrowley321/identity-model/pull/454),
  [`36f6e3e`](https://github.com/jamescrowley321/identity-model/commit/36f6e3ecf9944a7d585f31efcaf9937ab3dc1f9b))

- **release**: Automate fastapi-identity-model releases with scope-routed semantic-release
  ([#444](https://github.com/jamescrowley321/identity-model/pull/444),
  [`52dfcba`](https://github.com/jamescrowley321/identity-model/commit/52dfcba7724798eadb5dc6b2dd4f4516b9f23571))

### Documentation

- **keycloak**: Document Keycloak provider + capability matrix in integration guide
  ([#454](https://github.com/jamescrowley321/identity-model/pull/454),
  [`36f6e3e`](https://github.com/jamescrowley321/identity-model/commit/36f6e3ecf9944a7d585f31efcaf9937ab3dc1f9b))

### Features

- **integration**: Detect end_session/registration/backchannel caps
  ([#454](https://github.com/jamescrowley321/identity-model/pull/454),
  [`36f6e3e`](https://github.com/jamescrowley321/identity-model/commit/36f6e3ecf9944a7d585f31efcaf9937ab3dc1f9b))

- **integration**: Detect end_session/registration/backchannel caps
  ([#453](https://github.com/jamescrowley321/identity-model/pull/453),
  [`3fbd6e3`](https://github.com/jamescrowley321/identity-model/commit/3fbd6e33569e19ac1418454ec2468a5b987d3040))

- **integration**: Wire Keycloak fixture into integration harness
  ([`934c2e6`](https://github.com/jamescrowley321/identity-model/commit/934c2e6fb3186d814b711e83a246bf1e0507ac9f))

- **integration**: Wire Keycloak fixture into integration harness
  ([#447](https://github.com/jamescrowley321/identity-model/pull/447),
  [`1c89c1e`](https://github.com/jamescrowley321/identity-model/commit/1c89c1edc1fb0efec5c475907aa862597fa62a80))

- **logout**: Add backchannel_logout discovery fields + exception
  ([`f4bcc2b`](https://github.com/jamescrowley321/identity-model/commit/f4bcc2b9d9b0ace3372681d0694edd2994d9dad7))

- **logout**: Add build_end_session_url + post-logout state validation
  ([`e044eeb`](https://github.com/jamescrowley321/identity-model/commit/e044eeb59f717dfb59c2091bb4317a06131cb433))

- **logout**: Add end_session_endpoint discovery field
  ([`51c24b3`](https://github.com/jamescrowley321/identity-model/commit/51c24b3289717f4fdb36d3da66a7e5f57d406d49))

- **logout**: Add validate_logout_token (core logic + sync/aio wrappers)
  ([`67fe9e6`](https://github.com/jamescrowley321/identity-model/commit/67fe9e610dae122b5ac057d385acae7a73c0105e))

- **logout**: Conformance harness backchannel-logout receiver + config
  ([`2cdc398`](https://github.com/jamescrowley321/identity-model/commit/2cdc3982dee4665219573744ee85d1cbb18711d8))

- **logout**: Conformance harness RP-initiated logout redirect + callback + config
  ([`4389644`](https://github.com/jamescrowley321/identity-model/commit/4389644fc2482ac40700c4033f785774615d3a00))

- **matrix**: Add logout/registration columns to provider capability matrix
  ([`993e9c2`](https://github.com/jamescrowley321/identity-model/commit/993e9c22fcbcd322afb5308f4070eba7a0fbd41a))

- **registration**: Add dynamic client registration models
  ([`e1ccb91`](https://github.com/jamescrowley321/identity-model/commit/e1ccb91fad0873569c6f93660daec66ffc817598))

- **registration**: Conformance harness dynamic registration endpoint + config
  ([`b57d4f7`](https://github.com/jamescrowley321/identity-model/commit/b57d4f7e4c64fb18f1f1e0115c8cd0eaed5215c4))

- **registration**: Dynamic client registration logic + sync/async APIs
  ([`08068ad`](https://github.com/jamescrowley321/identity-model/commit/08068ad1e85088d1891cb1c69e04a14b24fc3659))

### Testing

- **keycloak**: Gate private_key_jwt to node-oidc; skip KC token-exchange cleanly
  ([`d74fd5e`](https://github.com/jamescrowley321/identity-model/commit/d74fd5ef4dc61295f92df96b4db17e988da27590))

- **keycloak**: Key integration session caches by provider
  ([`7d98170`](https://github.com/jamescrowley321/identity-model/commit/7d981709d02dba42c05fad62ae0d990a907f689f))

- **keycloak**: Live back-channel logout token validation
  ([#454](https://github.com/jamescrowley321/identity-model/pull/454),
  [`36f6e3e`](https://github.com/jamescrowley321/identity-model/commit/36f6e3ecf9944a7d585f31efcaf9937ab3dc1f9b))

- **keycloak**: Live back-channel logout token validation
  ([#453](https://github.com/jamescrowley321/identity-model/pull/453),
  [`3fbd6e3`](https://github.com/jamescrowley321/identity-model/commit/3fbd6e33569e19ac1418454ec2468a5b987d3040))

- **keycloak**: Live dynamic client registration CRUD
  ([#454](https://github.com/jamescrowley321/identity-model/pull/454),
  [`36f6e3e`](https://github.com/jamescrowley321/identity-model/commit/36f6e3ecf9944a7d585f31efcaf9937ab3dc1f9b))

- **keycloak**: Live dynamic client registration CRUD
  ([#453](https://github.com/jamescrowley321/identity-model/pull/453),
  [`3fbd6e3`](https://github.com/jamescrowley321/identity-model/commit/3fbd6e33569e19ac1418454ec2468a5b987d3040))

- **keycloak**: Live logout + dynamic registration integration tests
  ([#453](https://github.com/jamescrowley321/identity-model/pull/453),
  [`3fbd6e3`](https://github.com/jamescrowley321/identity-model/commit/3fbd6e33569e19ac1418454ec2468a5b987d3040))

- **keycloak**: Live RP-initiated logout end-session round-trip
  ([#454](https://github.com/jamescrowley321/identity-model/pull/454),
  [`36f6e3e`](https://github.com/jamescrowley321/identity-model/commit/36f6e3ecf9944a7d585f31efcaf9937ab3dc1f9b))

- **keycloak**: Live RP-initiated logout end-session round-trip
  ([#453](https://github.com/jamescrowley321/identity-model/pull/453),
  [`3fbd6e3`](https://github.com/jamescrowley321/identity-model/commit/3fbd6e33569e19ac1418454ec2468a5b987d3040))

- **keycloak**: Make live logout/registration tests exercise the flow
  ([#454](https://github.com/jamescrowley321/identity-model/pull/454),
  [`36f6e3e`](https://github.com/jamescrowley321/identity-model/commit/36f6e3ecf9944a7d585f31efcaf9937ab3dc1f9b))

- **keycloak**: Make live logout/registration tests exercise the flow
  ([#453](https://github.com/jamescrowley321/identity-model/pull/453),
  [`3fbd6e3`](https://github.com/jamescrowley321/identity-model/commit/3fbd6e33569e19ac1418454ec2468a5b987d3040))

- **keycloak**: Send Secure auth-session cookies over http in auth-code flow
  ([`50eb4ce`](https://github.com/jamescrowley321/identity-model/commit/50eb4cec1737ea31db2d8fb5ffeabfacc1fe4a0c))

- **keycloak**: Support Keycloak login form in auth-code flow helper
  ([`d2684d9`](https://github.com/jamescrowley321/identity-model/commit/d2684d9ee0c10a84eafab56ac0ae89943a44165f))

- **logout**: Unit tests for logout token validation + discovery fields
  ([`c6947b5`](https://github.com/jamescrowley321/identity-model/commit/c6947b51a0c0fe18850643aa7c1b932bb06dfb4b))

- **logout**: Unit tests for RP-initiated logout URL + state (LOGOUT-001/002/003)
  ([`e1dd338`](https://github.com/jamescrowley321/identity-model/commit/e1dd3386b3b1d2fa6bc150174042238f010ff9d9))

- **registration**: Unit tests for dynamic client registration CRUD
  ([`c1f0575`](https://github.com/jamescrowley321/identity-model/commit/c1f05759506bd8cb7ba777cbbe01c82b31ddff9a))


## v3.2.0 (2026-07-06)

### Bug Fixes

- **client-auth**: Redact private_key repr and harden assertion guards
  ([`2dd6420`](https://github.com/jamescrowley321/identity-model/commit/2dd642093d4f6d423d19969529d73db7cf15377b))

- **client-auth**: Route private_key_jwt signing failures through error handlers
  ([`901d4ed`](https://github.com/jamescrowley321/identity-model/commit/901d4ed88184a82fb650a09102130164d67456f1))

### Documentation

- **client-auth**: Add private_key_jwt usage example
  ([`f2acf0c`](https://github.com/jamescrowley321/identity-model/commit/f2acf0c9afdd4f76f84e7ea6585fcdf9065897c4))

### Features

- **client-auth**: Add private_key_jwt (RFC 7523) client authentication
  ([`acbc529`](https://github.com/jamescrowley321/identity-model/commit/acbc529eb248c6acd9bc5dc4e879ef1d79921d17))

### Testing

- **client-auth**: Integration tests for private_key_jwt against node-oidc
  ([`0191f65`](https://github.com/jamescrowley321/identity-model/commit/0191f652715215972243f6163a95272c7f915cea))


## v3.1.1 (2026-06-30)

### Bug Fixes

- **integration**: Exercise real discovery/JWKS fetch instead of fake-primed caches
  ([`0bfe060`](https://github.com/jamescrowley321/identity-model/commit/0bfe060ba4c8fd3222618632159fff26c99980b2))


## v3.1.0 (2026-06-29)

### Bug Fixes

- **conformance**: Download signed plan export, not the certification package
  ([`006e603`](https://github.com/jamescrowley321/identity-model/commit/006e6038d809c1caaabfce04ad4e01c325af9a47))

- **conformance**: Harden RP log path against path injection (CodeQL py/path-injection)
  ([`c1a7e05`](https://github.com/jamescrowley321/identity-model/commit/c1a7e05a0de7699abdf89c373f72c9717c64bcbd))

- **conformance**: Harden submission-artifact gating and log routing
  ([`30a3da2`](https://github.com/jamescrowley321/identity-model/commit/30a3da2f0be16e5b88d2e67952b8963cf9f66599))

- **token-exchange**: Surface raw error body when no standard OAuth error field
  ([`1e50877`](https://github.com/jamescrowley321/identity-model/commit/1e50877b1ba39dd9c52a5923bfba78c28f3f8b5d))

### Documentation

- **certification**: Add OIDC certification guide
  ([`f8e24cc`](https://github.com/jamescrowley321/identity-model/commit/f8e24cc335975fd80a03b5256fda913abc8ffa16))

- **certification**: Correct submission flow — payment code gate, sourced waiver
  ([`50e5c87`](https://github.com/jamescrowley321/identity-model/commit/50e5c87e6ccc47a3ef82ccad7f46e6c523416861))

### Features

- **conformance**: Capture per-test RP client-side logs (clientSideData)
  ([`0b439f5`](https://github.com/jamescrowley321/identity-model/commit/0b439f5afb34f0c98257b9dd2d19d9d7fbfd5bcb))

- **conformance**: Download OIDF certification package for hosted runs
  ([`f3a8bb5`](https://github.com/jamescrowley321/identity-model/commit/f3a8bb543d90359388e6cd5af5a12f89af933484))

### Testing

- **conformance**: Add live hosted plan results as evidence
  ([`ff81387`](https://github.com/jamescrowley321/identity-model/commit/ff8138748df68dabb3c6cbb14aadab3df0b48fbc))

- **conformance**: Refresh hosted evidence from full local run
  ([`d9906dc`](https://github.com/jamescrowley321/identity-model/commit/d9906dcfd3b96fb82bdd656cebf11ab977b81901))

- **integration**: Skip token exchange when provider advertises but rejects grant
  ([`b10618f`](https://github.com/jamescrowley321/identity-model/commit/b10618f3bea05904eaff66c1b87e1caff33a27f2))

- **integration**: Skip token exchange when provider rejects grant as unsupported
  ([`c924385`](https://github.com/jamescrowley321/identity-model/commit/c924385d9dcd58f9c48de589970b6c2aae03a936))


## v3.0.2 (2026-05-23)

### Bug Fixes

- **jwks-cache**: Surface retained cache on empty refresh (#403) (#417)
  ([#417](https://github.com/jamescrowley321/identity-model/pull/417),
  [`bd19d74`](https://github.com/jamescrowley321/identity-model/commit/bd19d741310c040e40b3da1440211460f4ddceee))


## v3.0.1 (2026-05-23)

### Bug Fixes

- **aio**: Per-event-loop async locks (#399)
  ([#399](https://github.com/jamescrowley321/identity-model/pull/399),
  [`94ceddc`](https://github.com/jamescrowley321/identity-model/commit/94ceddcdac559bdbe56bba90d75e0e2d8f461334))

### Testing

- **jwks-cache**: Pin _distinct_lock_per_uri at class level (#398)
  ([#398](https://github.com/jamescrowley321/identity-model/pull/398),
  [`6eb301f`](https://github.com/jamescrowley321/identity-model/commit/6eb301f77178d22b767453c5271d8c164bd7a583))


## v3.0.0 (2026-05-21)

### Bug Fixes

- **jwks-cache**: Convert aio clear_*_cache helpers to async
  ([`06e4236`](https://github.com/jamescrowley321/identity-model/commit/06e4236dd316e4e4f837a757fb3fe3c1fc32793b))

### Breaking Changes

- **jwks-cache**: Callers of ``py_identity_model.aio.token_validation``'s ``clear_discovery_cache``
  and ``clear_jwks_cache`` must now ``await`` them. The sync mirrors in
  ``py_identity_model.sync.token_validation`` are unchanged.


## v2.19.14 (2026-05-21)

### Bug Fixes

- **jwks-cache**: Use monotonic clock and capture request_time inside fetch lock
  ([`d00dcb3`](https://github.com/jamescrowley321/identity-model/commit/d00dcb308861b2e739232f57e22e2166b302ace3))

- **tests**: Backdate cached_at via time.monotonic for stale-entry test
  ([`c724a93`](https://github.com/jamescrowley321/identity-model/commit/c724a932258ba0eb90d1f41f72044c00df440f3d))


## v2.19.13 (2026-05-17)

### Bug Fixes

- **tests**: Unblock CI — Ory 429 in fixture + per-URI lock test flake
  ([`c476753`](https://github.com/jamescrowley321/identity-model/commit/c476753b71acb1d0e2ccdbda694155d7b2929491))


## v2.19.12 (2026-05-17)

### Bug Fixes

- **jwks-cache**: Cap DoS amplification, clamp env config, bound cache size
  ([`d9dfde2`](https://github.com/jamescrowley321/identity-model/commit/d9dfde24852fc88885e04bf7cc461e93f33b8ae9))

- **jwks-cache**: Close second-review findings on cooldown lifecycle
  ([`616f5d7`](https://github.com/jamescrowley321/identity-model/commit/616f5d7c5b6146494d33814bf4bc8201d6c25e78))

- **jwks-cache**: Invalidate stale entry on uncacheable refresh and reject empty keys
  ([`86b5d12`](https://github.com/jamescrowley321/identity-model/commit/86b5d1233c5e747e6ef5034a4ddeac92e0a62b85))

- **jwks-cache**: Respect HTTP cache headers for no-store, no-cache, and failed responses
  ([`e54d503`](https://github.com/jamescrowley321/identity-model/commit/e54d503c227cdee7fe6f0bbed0bc264a5622e88f))

- **jwks-cache**: Use per-URI lock striping so distinct issuers fetch in parallel
  ([`c6cf4d5`](https://github.com/jamescrowley321/identity-model/commit/c6cf4d502ebe836399ac2cccecdd86a61f1497be))

- **token-validation**: Harden kid-miss refresh path with diagnostic, fixed test priming, and
  negative regression
  ([`df9c881`](https://github.com/jamescrowley321/identity-model/commit/df9c88111ce29f19d586cd9bb137729ef8383b3b))

- **token-validation**: Refresh JWKS on cached kid miss
  ([`4f02bfc`](https://github.com/jamescrowley321/identity-model/commit/4f02bfcb2a3ffa5ec5815b3da72b031cf66b14fc))

### Build System

- **conformance**: Wait for app-level readiness in conformance-up
  ([`b901cea`](https://github.com/jamescrowley321/identity-model/commit/b901cea9e1f9d7f0e75c678158cdb7cbbb67406e))

### Testing

- **integration**: Skip caching benchmarks when provider sends no-store/no-cache
  ([`bf22ae6`](https://github.com/jamescrowley321/identity-model/commit/bf22ae650c74fdf0caef96b30bc106a1bbea132a))

- **token-validation**: Pin kid-miss stampede protection
  ([`3dd72d7`](https://github.com/jamescrowley321/identity-model/commit/3dd72d7186e43b4e4098dcb97d5169cc5498d55c))


## v2.19.11 (2026-04-19)

### Bug Fixes

- **security**: Prevent cache stampede on TTL expiry
  ([`58026c4`](https://github.com/jamescrowley321/identity-model/commit/58026c433a6d084c0bd5d4a24f3e32459ecc42bf))

- **security**: Prevent redundant sequential fetches in _refresh_jwks
  ([`0283782`](https://github.com/jamescrowley321/identity-model/commit/028378291f1cfd86ba3d7bd7564791a4d02a778a))

- **security**: Reject JWKS responses with missing Content-Type
  ([`19bc96a`](https://github.com/jamescrowley321/identity-model/commit/19bc96ae0d2fc459b37a498136ba29e5a74d425f))

### Testing

- **security**: Add _refresh_jwks freshness guard coverage
  ([`7a570f1`](https://github.com/jamescrowley321/identity-model/commit/7a570f161acdfa54f2863e23ac6a788d06d4c61b))


## v2.19.10 (2026-04-19)

### Bug Fixes

- **security**: Address review findings for require_https wiring
  ([`dde0341`](https://github.com/jamescrowley321/identity-model/commit/dde03418a24a8ef46a7ace48932e266dc0db3dea))

- **security**: Wire require_https through to DiscoveryPolicy
  ([`372e20e`](https://github.com/jamescrowley321/identity-model/commit/372e20e4aeff3c5dc70556f5d940b5d8e7da0a48))

### Testing

- **security**: Add require_https wiring tests for token validation
  ([`28f2b8a`](https://github.com/jamescrowley321/identity-model/commit/28f2b8ab6d873a91390ca73fc723badf5f2cb946))


## v2.19.9 (2026-04-18)

### Bug Fixes

- Use deepcopy to prevent mutable list field leakage in deprecated function
  ([`84c73f2`](https://github.com/jamescrowley321/identity-model/commit/84c73f2fda42b3c3fe4a6256a64cc2b3c12958d1))

- **security**: Add JWKS max key count limit and KeyError guard
  ([`ba97325`](https://github.com/jamescrowley321/identity-model/commit/ba97325b83695f11e5bcb8f9d5d6afb28acb663a))

- **security**: Address review findings for JWKS key count limit
  ([`a69c477`](https://github.com/jamescrowley321/identity-model/commit/a69c477518d942c12e005c85d44b2e7c6cc1a3aa))

- **security**: Deprecate get_public_key_from_jwk to prevent cached key mutation
  ([`d74be8e`](https://github.com/jamescrowley321/identity-model/commit/d74be8ebd36dfdd456d4faef83161b93a2e59a8e))

- **security**: Log warning on malformed Content-Length header
  ([`4691f06`](https://github.com/jamescrowley321/identity-model/commit/4691f068c5e237af466259474c13530617d5c25b))

### Testing

- **security**: Add key count limit and KeyError guard tests
  ([`312a797`](https://github.com/jamescrowley321/identity-model/commit/312a797d3cc045bc3e0228e6ec1c3c6a8fb59087))

- **security**: Add tests for cached key mutation prevention
  ([`c7fd2c0`](https://github.com/jamescrowley321/identity-model/commit/c7fd2c013389f38240c8c900d0bfa0897fc98a06))


## v2.19.8 (2026-04-13)

### Bug Fixes

- **conformance**: Fix 7 CodeQL alerts in harness — stack traces and sensitive logging
  ([`9f09a55`](https://github.com/jamescrowley321/identity-model/commit/9f09a55e09f5cf1a31e34ee3821b4ddbd8480841))

- **conformance**: Remove token logging and --show-token flag
  ([`4728e4b`](https://github.com/jamescrowley321/identity-model/commit/4728e4b20d152f1fa77f8add8b41f81153ff8798))


## v2.19.7 (2026-04-13)

### Bug Fixes

- **security**: Add JWKS size limit and fix async cleanup lock race
  ([`da859e3`](https://github.com/jamescrowley321/identity-model/commit/da859e3ff2e57fe876939ec909c278a97f11ac75))

- **security**: Enforce key type / algorithm consistency to prevent algorithm confusion
  ([`d02d523`](https://github.com/jamescrowley321/identity-model/commit/d02d52384fa40303017aeb5724c5201e05ef111b))


## v2.19.6 (2026-04-13)

### Bug Fixes

- **security**: Auto-trust discovery URL authority for endpoint validation
  ([`2f173ec`](https://github.com/jamescrowley321/identity-model/commit/2f173ecfe03fd2cf2d769cf7470e7543f92523db))

- **security**: HTTP hardening — disable redirects, enforce HTTPS, validate JWKS Content-Type,
  derive endpoint authority from issuer
  ([`93f7ce5`](https://github.com/jamescrowley321/identity-model/commit/93f7ce5421605d99f46f8e82ec75397339fab32f))

- **security**: Thread discovery_policy through validate_token for endpoint authority control
  ([`95124ca`](https://github.com/jamescrowley321/identity-model/commit/95124ca3383874f24cc72e1942257e73e3e2d4c0))


## v2.19.5 (2026-04-13)

### Bug Fixes

- **jwt**: Block options pass-through from disabling signature verification
  ([`0378f19`](https://github.com/jamescrowley321/identity-model/commit/0378f19be88759a50bb1d750b66605ed6e46de5b))

### Continuous Integration

- Remove pre-push hook from pre-commit config
  ([`8e212b8`](https://github.com/jamescrowley321/identity-model/commit/8e212b83f677d479f956e654f54c05f333a9143e))

### Documentation

- Update CLAUDE.md to reflect pre-push hook removal
  ([`65f82f2`](https://github.com/jamescrowley321/identity-model/commit/65f82f224b50ab2c02dd048ce0ffa6ca7d539e78))


## v2.19.4 (2026-04-13)

### Bug Fixes

- **cache**: Overhaul caching — TTL-based discovery, remove JWT/PyJWK caches
  ([`8d84620`](https://github.com/jamescrowley321/identity-model/commit/8d846204c3528f6ac7243fd57a08a0c69276bedd))

- **conformance**: Update cache clearing to use clear_discovery_cache()
  ([`7042913`](https://github.com/jamescrowley321/identity-model/commit/7042913020c43cb56ba072a7b58438ad48b49434))


## v2.19.3 (2026-04-12)

### Bug Fixes

- **conformance**: Make UserInfo sub mismatch fatal and display claims
  ([`47a86ed`](https://github.com/jamescrowley321/identity-model/commit/47a86edda2d11e779ce74a18a5476b02aae6187a))


## v2.19.2 (2026-04-12)

### Bug Fixes

- **conformance**: Add cert-init service for SSL cert sharing (#343)
  ([#343](https://github.com/jamescrowley321/identity-model/pull/343),
  [`928e9ad`](https://github.com/jamescrowley321/identity-model/commit/928e9ad5b1823939e703b1249e18d855e9c8b97f))

- **conformance**: Add SAN extension and nginx dependency to cert-init (#343)
  ([#343](https://github.com/jamescrowley321/identity-model/pull/343),
  [`5ccc88d`](https://github.com/jamescrowley321/identity-model/commit/5ccc88d14c746d73b4eb5d4af8ca41abe743e486))

- **conformance**: Allow config-rp to continue on known signing-key-rotation timeout (#343)
  ([#343](https://github.com/jamescrowley321/identity-model/pull/343),
  [`dff76bc`](https://github.com/jamescrowley321/identity-model/commit/dff76bc7e5e3e967e091a9a1d079c3f116c4884a))

- **conformance**: Clear discovery and JWKS caches between test modules (#343)
  ([#343](https://github.com/jamescrowley321/identity-model/pull/343),
  [`924e39f`](https://github.com/jamescrowley321/identity-model/commit/924e39fce360fb83f4c5427396e01b461337472e))


## v2.19.1 (2026-04-12)

### Bug Fixes

- **conformance**: Switch token rotation from UI selectors to REST API (#342)
  ([#342](https://github.com/jamescrowley321/identity-model/pull/342),
  [`39ce7d9`](https://github.com/jamescrowley321/identity-model/commit/39ce7d94454f0ce581c4580e4dde5a09bc83882c))

### Chores

- Sync uv.lock with 2.19.0
  ([`52ff89b`](https://github.com/jamescrowley321/identity-model/commit/52ff89b449486f836e87b9c61d7468bc3856d1d5))


## v2.19.0 (2026-04-12)


## v2.18.1 (2026-04-10)

### Bug Fixes

- **infra**: Make sonar_token optional so apply works without it
  ([#318](https://github.com/jamescrowley321/identity-model/pull/318),
  [`c72df52`](https://github.com/jamescrowley321/identity-model/commit/c72df52823d5befbbfeb28dd3c129e2b1da5cccd))

### Continuous Integration

- **deps)(deps**: Bump the github-actions group with 8 updates
  ([#317](https://github.com/jamescrowley321/identity-model/pull/317),
  [`07cccb9`](https://github.com/jamescrowley321/identity-model/commit/07cccb95cdd63459fd68c7da4dd6175df01a0cec))


## v2.18.0 (2026-04-10)

### Features

- **token-validation**: Add JWKS cache TTL with forced refresh on signature failure
  ([#310](https://github.com/jamescrowley321/identity-model/pull/310),
  [`bae53a5`](https://github.com/jamescrowley321/identity-model/commit/bae53a5d7e48672af51f3c487b378ff1f0ed9eee))


## v2.17.4 (2026-04-07)

### Bug Fixes

- **userinfo**: Add sub claim mismatch validation per OIDC Core 5.3.4
  ([`e97555c`](https://github.com/jamescrowley321/identity-model/commit/e97555c00d8a0679d0558a4fd96b6b2dd962e2f0))


## v2.17.3 (2026-04-07)

### Bug Fixes

- **parsers**: Handle missing kid in JWT header per OIDC Core Section 10.1
  ([`fbd6d1e`](https://github.com/jamescrowley321/identity-model/commit/fbd6d1e77e5faf96c8212675dd60ce7775ef184f))


## v2.17.2 (2026-04-05)

### Bug Fixes

- **test**: Extract mutable DEFAULT_OPTIONS to shared fixture and use cache_info.hits
  ([#302](https://github.com/jamescrowley321/identity-model/pull/302),
  [`0ae7a08`](https://github.com/jamescrowley321/identity-model/commit/0ae7a08cacc1470f29e091897cd461ab3260cfea))


## v2.17.1 (2026-03-30)

### Bug Fixes

- **ci**: Add git identity config to uv.lock sync step in release workflow
  ([`5167464`](https://github.com/jamescrowley321/identity-model/commit/51674649062f960f2be795b063330a41aff6991e))


## v2.17.0 (2026-03-30)

### Refactoring

- **test**: Provider-agnostic integration tests with discovery-driven capabilities
  ([#281](https://github.com/jamescrowley321/identity-model/pull/281),
  [`02ff38a`](https://github.com/jamescrowley321/identity-model/commit/02ff38a8d786816b2e6446ba65e932082762f6bf))


## v2.16.0 (2026-03-30)


## v2.15.0 (2026-03-30)


## v2.14.0 (2026-03-30)


## v2.13.0 (2026-03-30)


## v2.12.0 (2026-03-30)


## v2.11.0 (2026-03-30)

### Features

- **par**: Implement Pushed Authorization Requests (RFC 9126)
  ([#230](https://github.com/jamescrowley321/identity-model/pull/230),
  [`aa655ba`](https://github.com/jamescrowley321/identity-model/commit/aa655bae0d1f5230895dcb453903e923bcf1ab79))


## v2.10.0 (2026-03-30)

### Features

- **dpop**: Implement DPoP proof creation and key management (RFC 9449)
  ([#229](https://github.com/jamescrowley321/identity-model/pull/229),
  [`994012e`](https://github.com/jamescrowley321/identity-model/commit/994012ed746bd5e6ee6ef4f59f298ee34f7bb830))


## v2.9.0 (2026-03-30)

### Features

- **refresh**: Implement OAuth 2.0 Refresh Token Grant
  ([#228](https://github.com/jamescrowley321/identity-model/pull/228),
  [`c0eae00`](https://github.com/jamescrowley321/identity-model/commit/c0eae004b9b33e2e2d4ad658d772cdcae4e3fccc))


## v2.8.0 (2026-03-30)


## v2.7.0 (2026-03-30)

### Features

- **introspection**: Implement OAuth 2.0 Token Introspection (RFC 7662)
  ([#226](https://github.com/jamescrowley321/identity-model/pull/226),
  [`6870781`](https://github.com/jamescrowley321/identity-model/commit/6870781318a6163e1e2f8dc1add185ec7eee85d2))


## v2.6.0 (2026-03-30)

### Features

- **auth-code**: Implement Authorization Code Grant with PKCE
  ([#225](https://github.com/jamescrowley321/identity-model/pull/225),
  [`f3ea096`](https://github.com/jamescrowley321/identity-model/commit/f3ea0966930a5408e4d6c581790637f4c49b041d))


## v2.5.0 (2026-03-30)

### Features

- **token-validation**: Add enhanced validation and base request/response classes
  ([#224](https://github.com/jamescrowley321/identity-model/pull/224),
  [`c137b27`](https://github.com/jamescrowley321/identity-model/commit/c137b272852cf8c6c449c9acef0477f44cca74ac))


## v2.4.1 (2026-03-30)

### Bug Fixes

- **ci**: Remove tracked worktree directory breaking CI checkout
  ([`4fbaa7e`](https://github.com/jamescrowley321/identity-model/commit/4fbaa7e68572a9c8feb56cee0518cc58f1cf42c0))


## v2.4.0 (2026-03-30)

### Features

- **http-client**: Add dependency injection support for HTTP client management
  ([#222](https://github.com/jamescrowley321/identity-model/pull/222),
  [`4ad60f2`](https://github.com/jamescrowley321/identity-model/commit/4ad60f2cffbddc149ed307b93fbb427235008dff))


## v2.3.0 (2026-03-30)

### Bug Fixes

- **authorize**: Address code review and security findings
  ([`1976416`](https://github.com/jamescrowley321/identity-model/commit/197641689b20b4b6236cc6c9a66c958397598035))

- **authorize**: Guard against None inputs in callback parsing and state validation
  ([`2e696c5`](https://github.com/jamescrowley321/identity-model/commit/2e696c50d733aef2bfd528470b4c7c61ef8039bc))

- **authorize**: Make state accessible on error responses per RFC 6749
  ([`1a77957`](https://github.com/jamescrowley321/identity-model/commit/1a77957654c8f6241a115e000b13ee500bbc8eba))

- **test**: Make authorization_endpoint HTTPS assertion conditional on require_https
  ([`2cd2801`](https://github.com/jamescrowley321/identity-model/commit/2cd2801c55021e3ad47248d3dddf2c1950f11c79))

### Chores

- Auto-commit before merge (loop primary)
  ([`7e42771`](https://github.com/jamescrowley321/identity-model/commit/7e42771145d9a7781e5a42fce16bcf69781e23b3))

- Exclude __init__.py from SonarCloud duplication analysis
  ([`7886657`](https://github.com/jamescrowley321/identity-model/commit/78866576731b343f917e08aa8d4c375d175224c9))

- **deps**: Automated dependency update
  ([`244735d`](https://github.com/jamescrowley321/identity-model/commit/244735da8b1e988e1cef909ba82c892f61e8831e))

- **deps**: Automated dependency update
  ([`b0ed1fe`](https://github.com/jamescrowley321/identity-model/commit/b0ed1fef76bb3af607dd8fadb393485f68bcd63f))

- **deps**: Automated dependency update
  ([`104cb62`](https://github.com/jamescrowley321/identity-model/commit/104cb62ffcc74e27c05553a80809e525d0d67584))

### Continuous Integration

- Add pull_request trigger to build workflow
  ([`30399f9`](https://github.com/jamescrowley321/identity-model/commit/30399f9225db4d4fb5e68404359c823aaebf0a62))

### Documentation

- **authorize**: Add API docs for callback response and state validation
  ([`41b63b6`](https://github.com/jamescrowley321/identity-model/commit/41b63b6463880cdc61e5bb9f552234bf46582ec5))

- **authorize**: Add authorization callback usage examples
  ([`530cec6`](https://github.com/jamescrowley321/identity-model/commit/530cec6c65ab305d83cae416446ba7b18c9e2bf0))

### Features

- **authorize**: Add AuthorizeCallbackResponse model and parser
  ([`4d8351f`](https://github.com/jamescrowley321/identity-model/commit/4d8351f1024a534ad95963a4e5bbac180312baea))

- **authorize**: Add state parameter validation
  ([`2f4f826`](https://github.com/jamescrowley321/identity-model/commit/2f4f826c5144990ae6c528fef77ab2ff21025d5e))

- **authorize**: Export callback response and state validation API
  ([`6c3ddd9`](https://github.com/jamescrowley321/identity-model/commit/6c3ddd93fcf359eb3b339c67de440e7eb7f94f7f))

- **exceptions**: Add AuthorizeCallbackException
  ([`4804ae2`](https://github.com/jamescrowley321/identity-model/commit/4804ae25c728238f259968b07ac318296faa4f58))

### Refactoring

- **test**: Reduce code duplication in authorize callback tests
  ([`76dfc6c`](https://github.com/jamescrowley321/identity-model/commit/76dfc6c69f35026cd9caa06346fdfa71ad77a819))

### Testing

- Add coverage for review fix findings
  ([`e4a396a`](https://github.com/jamescrowley321/identity-model/commit/e4a396a2bf6193ba340a614a4229aff2e294da3e))

- **authorize**: Add integration tests for callback parsing and state validation
  ([`02a9f94`](https://github.com/jamescrowley321/identity-model/commit/02a9f94b9491bc35780ab46ffcf080c8e18c8c65))

- **authorize**: Add unit tests for callback response and state validation
  ([`1b83e10`](https://github.com/jamescrowley321/identity-model/commit/1b83e10f7e5c2247d34da4c2772a6ebd51484598))


## v2.2.0 (2026-03-14)

### Features

- Add guarded field access on failed response models
  ([#200](https://github.com/jamescrowley321/identity-model/pull/200),
  [`1e2b7ba`](https://github.com/jamescrowley321/identity-model/commit/1e2b7ba3622492ffa0715437decc030e632f3ad8))


## v2.1.5 (2026-03-10)

### Bug Fixes

- Add Terraform and TFLint setup to release workflow
  ([#189](https://github.com/jamescrowley321/identity-model/pull/189),
  [`d76de12`](https://github.com/jamescrowley321/identity-model/commit/d76de12a5cd07473c32394d478f0263be7b660f6))


## v2.1.4 (2026-02-24)

### Bug Fixes

- **hooks**: Remove unnecessary bash -c wrappers from pre-commit config
  ([#183](https://github.com/jamescrowley321/identity-model/pull/183),
  [`e2bab26`](https://github.com/jamescrowley321/identity-model/commit/e2bab26b44a654ea2c77e1d737c4c3a2d8e7686b))


## v2.1.3 (2026-02-24)

### Bug Fixes

- **test**: Warm lru_cache before benchmark to avoid 429 rate limits
  ([#182](https://github.com/jamescrowley321/identity-model/pull/182),
  [`ee6fa2f`](https://github.com/jamescrowley321/identity-model/commit/ee6fa2faadd601b019d70dba0343072c80e982dd))


## v2.1.2 (2026-02-24)

### Bug Fixes

- **docs**: Switch GitHub Pages to Actions deployment and add docs targets
  ([#181](https://github.com/jamescrowley321/identity-model/pull/181),
  [`7ba1135`](https://github.com/jamescrowley321/identity-model/commit/7ba11351bdb926829dad1655e7839bcecff2070a))


## v2.1.1 (2026-02-24)

### Bug Fixes

- **docs**: Resolve MkDocs strict mode build failures
  ([#179](https://github.com/jamescrowley321/identity-model/pull/179),
  [`bec22b4`](https://github.com/jamescrowley321/identity-model/commit/bec22b4dba82b8725578494461b40bc2482c23c5))


## v2.1.0 (2026-02-18)

### Build System

- Consolidate dependabot dependency updates
  ([#175](https://github.com/jamescrowley321/identity-model/pull/175),
  [`e9ae811`](https://github.com/jamescrowley321/identity-model/commit/e9ae81150ee005c68d6de5291b3a02f5a7b7baaa))

### Features

- **userinfo**: Add OpenID Connect UserInfo endpoint support
  ([`9e35dce`](https://github.com/jamescrowley321/identity-model/commit/9e35dce4ead829c2b0676d4c9180714685f24cd2))


## v2.0.0 (2026-01-29)


## v2.0.0-rc.1 (2026-01-17)

### Bug Fixes

- Add retry logic to token client endpoint
  ([`8ec1cc6`](https://github.com/jamescrowley321/identity-model/commit/8ec1cc69e6bc4de45eec7d9276987a87be2c59b3))

- Add thread-safe SSL certificate backward compatibility for httpx
  ([`55b8fe4`](https://github.com/jamescrowley321/identity-model/commit/55b8fe4c4b717046c78052be95f0ba7d0a9f39d6))

- Address high priority issues from PR #108 code review
  ([`15ccf1d`](https://github.com/jamescrowley321/identity-model/commit/15ccf1d75f5ca58c5ef788b353e27c22349ff77c))

- Centralize HTTP default constants and improve content-type handling
  ([`0989b59`](https://github.com/jamescrowley321/identity-model/commit/0989b5985887cb8b3f816634aeb3cd105d1e5869))

- Export to_principal in root __init__.py
  ([`6443dec`](https://github.com/jamescrowley321/identity-model/commit/6443deca1fcb5dad4fc5e9e436c4deb7e079a310))

- Optimize token validation with multi-layer caching
  ([`e42dbb4`](https://github.com/jamescrowley321/identity-model/commit/e42dbb413bc20b81d3ade948798cc72ac614c6eb))

- Reduce code duplication and improve test coverage
  ([`3de5c0a`](https://github.com/jamescrowley321/identity-model/commit/3de5c0a9e755e02cac38613a20f92e6c9acea051))

- Remove private reset functions from public __all__ exports
  ([`a9bf2ef`](https://github.com/jamescrowley321/identity-model/commit/a9bf2efb6b1619373a773e40a7f14de81d175113))

- Sonar quality issues ([#126](https://github.com/jamescrowley321/identity-model/pull/126),
  [`34ab94b`](https://github.com/jamescrowley321/identity-model/commit/34ab94b880cbc6f3a6b581b5cc334ceedae8a7e0))

- Sonarcloud Quality Issues ([#115](https://github.com/jamescrowley321/identity-model/pull/115),
  [`7f74d78`](https://github.com/jamescrowley321/identity-model/commit/7f74d7811324bd1b7d4f765931df5193b1fc779c))

### Chores

- Remove implementation plan before PR merge
  ([`5ea55b4`](https://github.com/jamescrowley321/identity-model/commit/5ea55b4ec5965fd695f52f3f3b0a25007ae4352d))

### Continuous Integration

- Trigger prerelease on PR events with auto-versioning
  ([`bbd1fc7`](https://github.com/jamescrowley321/identity-model/commit/bbd1fc783b2ebc8cca7cc1d9b376c7de5354243c))

- Unify release workflow with workflow_dispatch for prereleases
  ([`735690c`](https://github.com/jamescrowley321/identity-model/commit/735690cf3e715edf391846df34957d06dd535913))

### Documentation

- Add httpx performance note to cached functions
  ([`05d969e`](https://github.com/jamescrowley321/identity-model/commit/05d969e593075b8da617505fc37fba393b35ed97))

- Add Phase 8 architecture improvements to roadmap
  ([`abe7397`](https://github.com/jamescrowley321/identity-model/commit/abe73975850376d2722772550c712c02b10abc9a))

- Complete Phase 5 documentation and examples
  ([`306e99f`](https://github.com/jamescrowley321/identity-model/commit/306e99f5db0275666f1e0d9df639b24a409a8063))

### Features

- Add async support and modular architecture
  ([`55af9f3`](https://github.com/jamescrowley321/identity-model/commit/55af9f37f32c7fccf639cdd463dbd79ad818360c))

- Add retry logic with exponential backoff for rate limiting
  ([`ef667e0`](https://github.com/jamescrowley321/identity-model/commit/ef667e071428bfc336b9e0fdcb8e9ae23566d38a))

- Add SSL certificate backward compatibility and fix Docker examples
  ([`808b16c`](https://github.com/jamescrowley321/identity-model/commit/808b16cc0f160b5d6f11e58f53bde02a146b0ddf))

- Complete async optimizations and add coverage reporting
  ([`155d682`](https://github.com/jamescrowley321/identity-model/commit/155d682adb861f9119a8581f34b6d133d32fa52d))

- Complete async support and add SonarCloud integration
  ([`70f5031`](https://github.com/jamescrowley321/identity-model/commit/70f5031f3a3879741ff4687b26ebc2c9293ff07c))

- Optimize integration tests with session-scoped fixtures
  ([`c01b691`](https://github.com/jamescrowley321/identity-model/commit/c01b69147ef326d343cf7ed2031be83925fafb53))

### Performance Improvements

- Add httpx connection pooling for sync HTTP requests
  ([`54952ee`](https://github.com/jamescrowley321/identity-model/commit/54952eef7cf55edf6870fa193b07721ffa8734ac))

- Add parallel test execution to all test commands
  ([`7496d72`](https://github.com/jamescrowley321/identity-model/commit/7496d7212348cc020a9c1b5cb7445b540c10f425))

- Add public key caching to async token validation
  ([`c34fbd3`](https://github.com/jamescrowley321/identity-model/commit/c34fbd3bcc3dfe6032ddb53a28856dced0d8cc46))

- Add selective parallel test execution to avoid rate limiting
  ([`7b88001`](https://github.com/jamescrowley321/identity-model/commit/7b8800110946b7c819cfad09c722b6e4cfe50b50))

### Refactoring

- Eliminate code duplication with shared response processors
  ([`5c023c6`](https://github.com/jamescrowley321/identity-model/commit/5c023c6a791b405976859ff5215a753df77de9b4))

- Extract common token validation logic to reduce duplication
  ([`b28779b`](https://github.com/jamescrowley321/identity-model/commit/b28779b062b711e03b169934d8e983a07c2c2781))

- Fix Sonar code quality issues
  ([`d52a03f`](https://github.com/jamescrowley321/identity-model/commit/d52a03f09d8b7dc787b2727bae30cd5f8b1d6ee0))

- Reduce code duplication by extracting shared logic
  ([`ea66a42`](https://github.com/jamescrowley321/identity-model/commit/ea66a42fc97d423054ec865ea89ed86068260364))

- Reduce cognitive complexity and eliminate string duplication
  ([`452ea1a`](https://github.com/jamescrowley321/identity-model/commit/452ea1ae9e0212012af24b885e0140ae68c36927))

### Testing

- Add cache validation tests and restore benchmark threshold
  ([`3c5de99`](https://github.com/jamescrowley321/identity-model/commit/3c5de99c987923c1a959bf50574c0a068acc2eb5))

- Add comprehensive coverage for parsers module
  ([`d1645f4`](https://github.com/jamescrowley321/identity-model/commit/d1645f417acbe08f86b9d2509de41b8e96ca87b4))

- Update network error test to handle both error types
  ([`41743e5`](https://github.com/jamescrowley321/identity-model/commit/41743e5b764ba347db3b32a05b77eeaa9023bcb3))


## v1.2.0 (2025-11-08)

### Features

- **Async/Await Support** - Full asynchronous API via `py_identity_model.aio` module
  - Async versions of all client methods (discovery, JWKS, token validation, token client)
  - Async caching with `async-lru` for discovery and JWKS
  - Full backward compatibility maintained (sync API unchanged)
  - Comprehensive async test suite (10 new async tests)
  - Examples for both FastAPI and concurrent operations

- **Modular Architecture** - Clean separation between HTTP layer and business logic
  - Extracted shared business logic to `core/` module
  - Eliminated code duplication between sync/async implementations
  - Major code reduction: sync/jwks.py (390→78 lines), sync/discovery.py (378→246 lines)
  - All 146 tests passing with zero regressions

- **HTTP Client Migration** - Migrated from `requests` to `httpx`
  - Single library supporting both sync and async operations
  - Configurable timeouts (30s default on all HTTP calls)
  - Automatic connection pooling

- Add comprehensive logging and exception handling
  ([#107](https://github.com/jamescrowley321/identity-model/pull/107),
  [`98f88d6`](https://github.com/jamescrowley321/identity-model/commit/98f88d6c9def9f6bff9f7d8625acf258395a2275))

### Documentation

- Consolidate documentation into mkdocs instead of Wiki
  ([#99](https://github.com/jamescrowley321/identity-model/pull/99),
  [`71f5fcb`](https://github.com/jamescrowley321/identity-model/commit/71f5fcb9616c173be26864689bf4e3ba0351c52e))

- Add comprehensive async examples and architecture documentation
- Update roadmap to reflect completed features


## v1.1.1 (2025-10-21)

### Bug Fixes

- **docs**: Remove awesome-pages plugin to fix navigation
  ([`95904d7`](https://github.com/jamescrowley321/identity-model/commit/95904d750959ad8c4151134c8bef3103fc3b3fc3))

### Documentation

- Add CONTRIBUTING.md and fix documentation
  ([#98](https://github.com/jamescrowley321/identity-model/pull/98),
  [`68b266d`](https://github.com/jamescrowley321/identity-model/commit/68b266d4f93b8605a9acdc1a5b8958e6c66a52a3))


## v1.1.0 (2025-10-21)

### Chores

- Updates deps and docs ([#80](https://github.com/jamescrowley321/identity-model/pull/80),
  [`47c4ce2`](https://github.com/jamescrowley321/identity-model/commit/47c4ce2192316a6c1c7b3e2746c9ae22f1d69811))

### Features

- Put in some identity ([#82](https://github.com/jamescrowley321/identity-model/pull/82),
  [`a61cb9b`](https://github.com/jamescrowley321/identity-model/commit/a61cb9b8fbe95671ac9e84677051f3af42601fc7))


## v1.0.0 (2025-05-31)


## v1.0.0-rc.1 (2025-05-31)

### Chores

- Adds release automation
  ([`bd882e3`](https://github.com/jamescrowley321/identity-model/commit/bd882e3473fe4c8d41a01136a0467504da0f187c))

- Adds release automation
  ([`1d0ebad`](https://github.com/jamescrowley321/identity-model/commit/1d0ebadee9a7311577cbef9f8fd66553fa7adb4a))

- Adds release automation
  ([`d2f22cc`](https://github.com/jamescrowley321/identity-model/commit/d2f22cc42905bf0692889f79bad3f107283535ff))

- Fixes makefile
  ([`34096c3`](https://github.com/jamescrowley321/identity-model/commit/34096c36d558d12dd043e14a7fc7f5e7b4d226bc))

- Fixes makefile
  ([`b2ace65`](https://github.com/jamescrowley321/identity-model/commit/b2ace65b9c7f18be41f369a3b2675bbc095f85a4))

- Fixes workflow
  ([`cb2003b`](https://github.com/jamescrowley321/identity-model/commit/cb2003b720e1b9c59ae934a859c55eaaf5743904))

- Fixes workflow
  ([`ce5ed88`](https://github.com/jamescrowley321/identity-model/commit/ce5ed88d4cbd1550116acda3996922b393d80238))

- Fixes workflow
  ([`0e73021`](https://github.com/jamescrowley321/identity-model/commit/0e7302149d314216e532372231a35b3f8a9ab4dd))

- Updates cryptography to latest version
  ([#72](https://github.com/jamescrowley321/identity-model/pull/72),
  [`ea23f0d`](https://github.com/jamescrowley321/identity-model/commit/ea23f0d0d340d454a7f58490cd14a6b46a762a5c))

### Features

- Adds automated versioning
  ([`c4f9846`](https://github.com/jamescrowley321/identity-model/commit/c4f9846a51d3414ab57e1668decd6cf351f6e0b6))

- Adds automated versioning
  ([`05549ab`](https://github.com/jamescrowley321/identity-model/commit/05549abdbc1d8eeb82b41da0778db311782c75ac))

- Cleans up workflow files
  ([`425ed08`](https://github.com/jamescrowley321/identity-model/commit/425ed0840fd1224d87eb84ff708b23dea8499c47))

- Cleans up workflow files
  ([`b612011`](https://github.com/jamescrowley321/identity-model/commit/b61201148de7582d2f2c6b5ed24c067bb9998aed))

- Cleans up workflow files
  ([`f906d8c`](https://github.com/jamescrowley321/identity-model/commit/f906d8c5876408df9e3501d5cde5a891379fa72d))

- Cleans up workflow files
  ([`6febcbe`](https://github.com/jamescrowley321/identity-model/commit/6febcbe53ec61c2b0a7f00f9c3d9cce99ac61b68))

- Cleans up workflow files
  ([`38bff6f`](https://github.com/jamescrowley321/identity-model/commit/38bff6fef5ff58b149604f1e750b825fdff61890))

- Cleans up workflow files
  ([`30451ec`](https://github.com/jamescrowley321/identity-model/commit/30451ec38f691cedce7ad30ecff1aeda4011e3bf))

- Moves from poetry to uv
  ([`33cac19`](https://github.com/jamescrowley321/identity-model/commit/33cac199e25e635dd228cbcf9d34f935ce45582b))

- Moves from poetry to uv
  ([`1d5920e`](https://github.com/jamescrowley321/identity-model/commit/1d5920e14b1a4b5229c8f10909fc375e193510bb))


## v0.11.4 (2024-06-20)

- Initial Release
