package integrationtest

import "testing"

// FailUnreachable fails t when the live provider cannot be reached. These
// tests compile only under -tags=integration and need the fixtures
// (`make test-integration-go` boots them; `make infra-up` for a manual
// `go test -tags=integration` run), so an unreachable provider is either a
// fixture that was never started or a URL/profile drift between the in-code
// defaults and infra/docker-compose.yml — never a reason to skip.
// Capability/profile skips (e.g. an unset TEST_OPAQUE_CLIENT_ID) are
// deliberately NOT routed through this: those are legitimate per-provider
// gaps, not infrastructure failures.
func FailUnreachable(t testing.TB, format string, args ...any) {
	t.Helper()
	t.Fatalf(format, args...)
}
