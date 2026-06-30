package userinfo

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// fixtureSub is the "sub" claim in spec/test-fixtures/userinfo/standard-claims.json.
const fixtureSub = "248289761001"

// fixture reads a shared conformance fixture from spec/test-fixtures/userinfo.
func fixture(t *testing.T, name string) []byte {
	t.Helper()
	// test file lives at go/pkg/userinfo; fixtures at <repo>/spec/test-fixtures.
	path := filepath.Join("..", "..", "..", "spec", "test-fixtures", "userinfo", name)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return data
}

// claimsServer serves the standard-claims fixture and records the request's
// Authorization header so tests can assert the Bearer credential was sent.
func claimsServer(t *testing.T) (*httptest.Server, *string) {
	t.Helper()
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(fixture(t, "standard-claims.json"))
	}))
	t.Cleanup(srv.Close)
	return srv, &gotAuth
}

// UI-001: Fetch sends Authorization: Bearer and decodes the typed §5.1 claims.
func TestFetch_StandardClaims(t *testing.T) {
	srv, gotAuth := claimsServer(t)

	resp, err := Fetch(context.Background(), srv.URL, "tok-abc", WithInsecureAllowHTTP())
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if *gotAuth != "Bearer tok-abc" {
		t.Errorf("Authorization header = %q, want %q", *gotAuth, "Bearer tok-abc")
	}
	if resp.Sub != fixtureSub {
		t.Errorf("Sub = %q, want %q", resp.Sub, fixtureSub)
	}
	if resp.Email != "janedoe@example.com" {
		t.Errorf("Email = %q", resp.Email)
	}
	if resp.Name != "Jane Doe" || resp.GivenName != "Jane" || resp.FamilyName != "Doe" {
		t.Errorf("name fields wrong: %+v", resp)
	}
	if resp.EmailVerified == nil || !*resp.EmailVerified {
		t.Errorf("EmailVerified = %v, want true", resp.EmailVerified)
	}
	if resp.PhoneNumberVerified == nil || *resp.PhoneNumberVerified {
		t.Errorf("PhoneNumberVerified = %v, want false", resp.PhoneNumberVerified)
	}
	if resp.Address == nil || resp.Address.PostalCode != "90210" || resp.Address.Country != "USA" {
		t.Errorf("Address wrong: %+v", resp.Address)
	}
	if resp.UpdatedAt != 1700000000 {
		t.Errorf("UpdatedAt = %d", resp.UpdatedAt)
	}
}

// UI-002 (regression): a provider that serializes updated_at with a fractional
// or exponent part must not sink the whole decode and drop every claim — the
// value is truncated to whole seconds. Out-of-range values are rejected.
func TestFetch_UpdatedAt_FractionalAndExponent(t *testing.T) {
	serve := func(body string) (*UserInfoResponse, error) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(body))
		}))
		defer srv.Close()
		return Fetch(context.Background(), srv.URL, "tok", WithInsecureAllowHTTP())
	}

	for _, tc := range []struct {
		name string
		raw  string
		want int64
	}{
		{"exponent", `1.7e9`, 1700000000},
		{"fractional", `1700000000.9`, 1700000000},
		{"integer", `1700000000`, 1700000000},
		{"numeric_string", `"1700000000"`, 1700000000},
		{"null", `null`, 0},
		{"empty_string", `""`, 0},
		{"negative", `-100`, -100},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := serve(`{"sub":"abc","updated_at":` + tc.raw + `}`)
			if err != nil {
				t.Fatalf("Fetch: %v", err)
			}
			if resp.Sub != "abc" {
				t.Errorf("Sub dropped: %q", resp.Sub)
			}
			if resp.UpdatedAt != tc.want {
				t.Errorf("UpdatedAt = %d, want %d", resp.UpdatedAt, tc.want)
			}
		})
	}

	// Out-of-range values must be rejected rather than silently wrapping: an
	// exponent that overflows to +Inf, and a finite integer just past MaxInt64.
	for _, bad := range []string{`1e400`, `9223372036854775808`} {
		if _, err := serve(`{"sub":"abc","updated_at":` + bad + `}`); err == nil {
			t.Errorf("updated_at %s: expected out-of-range error, got nil", bad)
		}
	}
}

// UI-002: subject validation passes when the expected sub matches.
func TestFetch_SubjectValidation_Match(t *testing.T) {
	srv, _ := claimsServer(t)

	resp, err := Fetch(context.Background(), srv.URL, "tok", WithInsecureAllowHTTP(),
		WithSubjectValidation(fixtureSub))
	if err != nil {
		t.Fatalf("Fetch with matching sub: %v", err)
	}
	if resp.Sub != fixtureSub {
		t.Errorf("Sub = %q", resp.Sub)
	}
}

// UI-003: subject validation fails with a SubjectMismatchError on mismatch.
func TestFetch_SubjectValidation_Mismatch(t *testing.T) {
	srv, _ := claimsServer(t)

	_, err := Fetch(context.Background(), srv.URL, "tok", WithInsecureAllowHTTP(),
		WithSubjectValidation("someone-else"))
	if err == nil {
		t.Fatal("expected SubjectMismatchError, got nil")
	}
	var sme *SubjectMismatchError
	if !errors.As(err, &sme) {
		t.Fatalf("error = %T (%v), want *SubjectMismatchError", err, err)
	}
	if sme.Expected != "someone-else" || sme.Actual != fixtureSub {
		t.Errorf("mismatch fields wrong: %+v", sme)
	}
	if !errors.Is(err, ErrSubjectMismatch) {
		t.Errorf("errors.Is(err, ErrSubjectMismatch) = false")
	}
}

// UI-004: a 401 yields a UserInfoError carrying the status and WWW-Authenticate
// challenge (RFC 6750 §3).
func TestFetch_Unauthorized_CapturesChallenge(t *testing.T) {
	const challenge = `Bearer realm="example", error="invalid_token", error_description="token expired"`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("WWW-Authenticate", challenge)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	_, err := Fetch(context.Background(), srv.URL, "expired", WithInsecureAllowHTTP())
	var ue *UserInfoError
	if !errors.As(err, &ue) {
		t.Fatalf("error = %T (%v), want *UserInfoError", err, err)
	}
	if ue.StatusCode != http.StatusUnauthorized {
		t.Errorf("StatusCode = %d, want 401", ue.StatusCode)
	}
	if ue.WWWAuthenticate != challenge {
		t.Errorf("WWWAuthenticate = %q, want %q", ue.WWWAuthenticate, challenge)
	}
	if !errors.Is(err, ErrUserInfoResponse) {
		t.Errorf("errors.Is(err, ErrUserInfoResponse) = false")
	}
}

// UI-005: a 403 yields a UserInfoError carrying the status.
func TestFetch_Forbidden(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	_, err := Fetch(context.Background(), srv.URL, "tok", WithInsecureAllowHTTP())
	var ue *UserInfoError
	if !errors.As(err, &ue) {
		t.Fatalf("error = %T (%v), want *UserInfoError", err, err)
	}
	if ue.StatusCode != http.StatusForbidden {
		t.Errorf("StatusCode = %d, want 403", ue.StatusCode)
	}
}

// UI-006: a 5xx response surfaces as a UserInfoError carrying the status.
func TestFetch_ServerError_NonJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("upstream is down"))
	}))
	defer srv.Close()

	_, err := Fetch(context.Background(), srv.URL, "tok", WithInsecureAllowHTTP())
	var ue *UserInfoError
	if !errors.As(err, &ue) {
		t.Fatalf("error = %T (%v), want *UserInfoError", err, err)
	}
	if ue.StatusCode != http.StatusInternalServerError {
		t.Errorf("StatusCode = %d, want 500", ue.StatusCode)
	}
}

// UI-006 (decode half): a 2xx body that is not valid JSON yields a RequestError.
func TestFetch_DecodeError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("not json"))
	}))
	defer srv.Close()

	_, err := Fetch(context.Background(), srv.URL, "tok", WithInsecureAllowHTTP())
	var re *RequestError
	if !errors.As(err, &re) {
		t.Fatalf("error = %T (%v), want *RequestError", err, err)
	}
	if re.StatusCode != http.StatusOK {
		t.Errorf("StatusCode = %d, want 200", re.StatusCode)
	}
	if !errors.Is(err, ErrRequest) {
		t.Errorf("errors.Is(err, ErrRequest) = false")
	}
}

// UI-007: non-standard claims remain reachable via Claims(); standard claims
// stay typed.
func TestFetch_CustomClaimsPreserved(t *testing.T) {
	srv, _ := claimsServer(t)

	resp, err := Fetch(context.Background(), srv.URL, "tok", WithInsecureAllowHTTP())
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	claims := resp.Claims()
	if got := claims["department"]; got != "Engineering" {
		t.Errorf("Claims()[\"department\"] = %v, want Engineering", got)
	}
	// Standard claims are present in the raw map too and not lost from typed fields.
	if claims["sub"] != fixtureSub {
		t.Errorf("Claims()[\"sub\"] = %v", claims["sub"])
	}
	if resp.PreferredUsername != "j.doe" {
		t.Errorf("PreferredUsername = %q", resp.PreferredUsername)
	}
}

// UI-008: WithHTTPClient routes the request through the supplied client and
// WithTimeout bounds a slow endpoint.
func TestFetch_FunctionalOptions(t *testing.T) {
	srv, _ := claimsServer(t)

	marker := &markerTransport{base: http.DefaultTransport}
	client := &http.Client{Transport: marker}
	if _, err := Fetch(context.Background(), srv.URL, "tok",
		WithInsecureAllowHTTP(), WithHTTPClient(client)); err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if !marker.used {
		t.Error("WithHTTPClient transport was not used")
	}

	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(fixture(t, "standard-claims.json"))
	}))
	defer slow.Close()

	start := time.Now()
	_, err := Fetch(context.Background(), slow.URL, "tok",
		WithInsecureAllowHTTP(), WithTimeout(20*time.Millisecond))
	if err == nil {
		t.Fatal("expected timeout error, got nil")
	}
	if elapsed := time.Since(start); elapsed > 150*time.Millisecond {
		t.Errorf("timeout not enforced; took %v", elapsed)
	}
}

// https-gate: an http endpoint without WithInsecureAllowHTTP is rejected before
// any request is made.
func TestFetch_RequiresHTTPS(t *testing.T) {
	_, err := Fetch(context.Background(), "http://userinfo.example.com", "tok")
	var re *RequestError
	if !errors.As(err, &re) {
		t.Fatalf("error = %T (%v), want *RequestError", err, err)
	}
	if !errors.Is(err, ErrRequest) {
		t.Errorf("errors.Is(err, ErrRequest) = false")
	}
}

// An empty access token is rejected before any request is made.
func TestFetch_RequiresAccessToken(t *testing.T) {
	_, err := Fetch(context.Background(), "https://userinfo.example.com", "")
	if !errors.Is(err, ErrRequest) {
		t.Fatalf("error = %v, want ErrRequest", err)
	}
}

// A 2xx response missing the required sub claim is a RequestError, so a subject
// substitution cannot slip through as an empty-but-valid response.
func TestFetch_MissingSub(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"name":"No Sub"}`))
	}))
	defer srv.Close()

	_, err := Fetch(context.Background(), srv.URL, "tok", WithInsecureAllowHTTP())
	if !errors.Is(err, ErrRequest) {
		t.Fatalf("error = %v, want ErrRequest", err)
	}
}

// A signed (application/jwt) UserInfo response is out of scope and reported as a
// descriptive RequestError rather than a JSON decode failure (§5.3.2).
func TestFetch_SignedResponseRejected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/jwt")
		_, _ = w.Write([]byte("eyJhbGciOiJSUzI1NiJ9.e30.sig"))
	}))
	defer srv.Close()

	_, err := Fetch(context.Background(), srv.URL, "tok", WithInsecureAllowHTTP())
	var re *RequestError
	if !errors.As(err, &re) {
		t.Fatalf("error = %T (%v), want *RequestError", err, err)
	}
}

// markerTransport records whether it round-tripped a request.
type markerTransport struct {
	base http.RoundTripper
	used bool
}

func (m *markerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	m.used = true
	return m.base.RoundTrip(r)
}
