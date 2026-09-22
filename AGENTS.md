# AGENTS.md

Guidance for coding agents working in this repository. `CLAUDE.md` is the full
contract; this file carries the points agents most often miss.

## Read the automated review before asking for a merge

The blind-peer-review bot posts its verdict as a **PR comment**, not a GitHub review.
It therefore does not show up in `gh pr view --json reviews`, and its `Claude` check row
goes green when the *workflow* ran — not when the review passed. A PR can show all
checks green while carrying an unread `BLOCK`.

```bash
gh pr view <N> --repo <owner>/<repo> --json comments \
  -q '.comments[] | select(.author.login=="claude") | .body'
```

- Treat `BLOCK` as blocking.
- Findings predate any force-push you made since. Check each against the current tree —
  do not assume stale, and do not assume live. Reproduce before fixing or dismissing.
- Record in the PR which findings were fixed and which were superseded by later commits.
- If a lens is wrong, say so with the evidence rather than quietly complying.
- **Do not self-resolve Policy & Provenance findings.** The AI provenance block goes in
  the PR description; the named-human attestation is the maintainer's to give.

## Behaviour lives in four places

A behaviour change is not done until all four agree:

1. the code
2. `spec/config.md` — the cross-language contract Go and Rust are written against
3. `spec/vectors/*.json` and `spec/test-fixtures/**/*.json` — the machine-readable cases
4. `docs/api/*.md`

Grep `spec/` with **no** `--include` filter. A `--include=*.md` sweep silently misses the
JSON, and those fixtures fail open: the expected values usually stay correct when
behaviour changes, so nothing fails and the drift is invisible until another language
implements the stale note.

## Do not invent limits

Adding a maximum to a configurable value overrides a choice someone made deliberately —
a slow IdP is a real reason to raise a timeout. If a bound is genuinely needed, make it a
**default that configuration can raise**, register it in all four places above, and give
it a test that fails without it. A reviewer asking for a bound is a reason to consider
one, not grounds to pick the number.

## Prove the fix, do not just test around it

Revert the fix and confirm the test fails, for integration tests as much as unit tests.
A test that passes against the unfixed code proves nothing. Where two guards cover the
same behaviour, revert both — otherwise the test passes on the other one and you will
report it as proven when it is not.

Integration coverage is a floor, not a bonus: `make pre-push` is eight targets, and
`make test-integration-node-oidc` runs over **plain HTTP**, so it exercises no TLS. A
change to certificate or trust behaviour is unverified until `make conformance-test` has
run.
