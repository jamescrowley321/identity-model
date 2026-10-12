// Package configpage_test checks the Go options against the settings table in
// spec/config.md: every Go option on the page exists, its default is the
// page's default, and it accepts exactly the page's valid range.
package configpage_test

import (
	"context"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jamescrowley321/identity-model/go/internal/transport"
	"github.com/jamescrowley321/identity-model/go/pkg/discovery"
	"github.com/jamescrowley321/identity-model/go/pkg/introspection"
	"github.com/jamescrowley321/identity-model/go/pkg/jwks"
	"github.com/jamescrowley321/identity-model/go/pkg/revocation"
	"github.com/jamescrowley321/identity-model/go/pkg/token"
	"github.com/jamescrowley321/identity-model/go/pkg/userinfo"
)

const header = "| Python | Go option | Rust builder method | Unit | Default | Valid |"

// row is one line of the settings table.
type row struct {
	python, unit, def, valid string
	goOptions                []string
}

// pageRows parses the settings table of spec/config.md.
func pageRows(t *testing.T) []row {
	t.Helper()
	// This file lives at go/internal/configpage; the page at <repo>/spec.
	data, err := os.ReadFile(filepath.Join("..", "..", "..", "spec", "config.md"))
	if err != nil {
		t.Fatalf("read spec/config.md: %v", err)
	}
	lines := strings.Split(string(data), "\n")
	start := slices.Index(lines, header)
	if start < 0 {
		t.Fatalf("spec/config.md has no settings table header %q", header)
	}
	var rows []row
	for _, line := range lines[start+2:] { // skip the header and the |---| line
		if !strings.HasPrefix(line, "|") {
			break
		}
		cells := strings.Split(strings.Trim(line, "|"), "|")
		if len(cells) != 6 {
			t.Fatalf("row %q has %d cells, want 6", line, len(cells))
		}
		for i := range cells {
			cells[i] = strings.Trim(strings.TrimSpace(cells[i]), "`")
		}
		var opts []string
		for _, o := range strings.Split(cells[1], ",") {
			opts = append(opts, strings.Trim(strings.TrimSpace(o), "`"))
		}
		rows = append(rows, row{python: cells[0], goOptions: opts, unit: cells[3], def: cells[4], valid: cells[5]})
	}
	return rows
}

// binding is how this test reaches one Go option: its default, and a check
// that applies a value through every package that has the option and reports
// whether each accepted it.
type binding struct {
	def any // time.Duration, int or string
	// accepts applies the value and returns, per package, whether it was
	// accepted.
	accepts func(t *testing.T, v any) map[string]bool
}

// oneShot calls a request function and reports whether it got past option
// validation. The server answers 400, which is not retried; the calls set a
// zero retry delay before the option under test so a 1 ns timeout's retried
// transport errors stay fast.
func oneShot(call func(endpoint string) error) bool {
	return !errors.Is(call(rejectingServer.URL), transport.ErrInvalidConfig)
}

var rejectingServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusBadRequest)
}))

func dur(v any) time.Duration { return v.(time.Duration) }

// transportBinding covers an option every HTTP package has.
func transportBinding(def any,
	disco func(any) discovery.Option, jw func(any) jwks.Option,
	tok func(any) token.Option, ui func(any) userinfo.Option,
	intro func(any) introspection.Option, rev func(any) revocation.Option,
) binding {
	ctx := context.Background()
	return binding{def: def, accepts: func(t *testing.T, v any) map[string]bool {
		_, dErr := discovery.NewClient(disco(v))
		_, jErr := jwks.NewClient(jw(v))
		return map[string]bool{
			"discovery": dErr == nil,
			"jwks":      jErr == nil,
			"token": oneShot(func(ep string) error {
				_, err := token.ClientCredentials(ctx, ep, "c", "s", token.WithInsecureAllowHTTP(), token.WithRetryBaseDelay(0), tok(v))
				return err
			}),
			"userinfo": oneShot(func(ep string) error {
				_, err := userinfo.Fetch(ctx, ep, "at", userinfo.WithInsecureAllowHTTP(), userinfo.WithRetryBaseDelay(0), ui(v))
				return err
			}),
			"introspection": oneShot(func(ep string) error {
				_, err := introspection.Introspect(ctx, ep, "c", "s", "tok", introspection.WithInsecureAllowHTTP(), introspection.WithRetryBaseDelay(0), intro(v))
				return err
			}),
			"revocation": oneShot(func(ep string) error {
				return revocation.Revoke(ctx, ep, "c", "s", "tok", revocation.WithInsecureAllowHTTP(), revocation.WithRetryBaseDelay(0), rev(v))
			}),
		}
	}}
}

func discoveryBinding(def any, opt func(any) discovery.Option) binding {
	return binding{def: def, accepts: func(t *testing.T, v any) map[string]bool {
		_, err := discovery.NewClient(opt(v))
		return map[string]bool{"discovery": err == nil}
	}}
}

func jwksBinding(def any, opt func(any) jwks.Option) binding {
	return binding{def: def, accepts: func(t *testing.T, v any) map[string]bool {
		_, err := jwks.NewClient(opt(v))
		return map[string]bool{"jwks": err == nil}
	}}
}

// bindings maps every Go option named on the page to how it is reached.
var bindings = map[string]binding{
	"WithTimeout": transportBinding(transport.DefaultTimeout,
		func(v any) discovery.Option { return discovery.WithTimeout(dur(v)) },
		func(v any) jwks.Option { return jwks.WithTimeout(dur(v)) },
		func(v any) token.Option { return token.WithTimeout(dur(v)) },
		func(v any) userinfo.Option { return userinfo.WithTimeout(dur(v)) },
		func(v any) introspection.Option { return introspection.WithTimeout(dur(v)) },
		func(v any) revocation.Option { return revocation.WithTimeout(dur(v)) },
	),
	"WithRetryMaxAttempts": transportBinding(transport.DefaultRetryMaxAttempts,
		func(v any) discovery.Option { return discovery.WithRetryMaxAttempts(v.(int)) },
		func(v any) jwks.Option { return jwks.WithRetryMaxAttempts(v.(int)) },
		func(v any) token.Option { return token.WithRetryMaxAttempts(v.(int)) },
		func(v any) userinfo.Option { return userinfo.WithRetryMaxAttempts(v.(int)) },
		func(v any) introspection.Option { return introspection.WithRetryMaxAttempts(v.(int)) },
		func(v any) revocation.Option { return revocation.WithRetryMaxAttempts(v.(int)) },
	),
	"WithRetryBaseDelay": transportBinding(transport.DefaultRetryBaseDelay,
		func(v any) discovery.Option { return discovery.WithRetryBaseDelay(dur(v)) },
		func(v any) jwks.Option { return jwks.WithRetryBaseDelay(dur(v)) },
		func(v any) token.Option { return token.WithRetryBaseDelay(dur(v)) },
		func(v any) userinfo.Option { return userinfo.WithRetryBaseDelay(dur(v)) },
		func(v any) introspection.Option { return introspection.WithRetryBaseDelay(dur(v)) },
		func(v any) revocation.Option { return revocation.WithRetryBaseDelay(dur(v)) },
	),
	"WithCABundle": transportBinding(transport.Defaults().CABundle,
		func(v any) discovery.Option { return discovery.WithCABundle(v.(string)) },
		func(v any) jwks.Option { return jwks.WithCABundle(v.(string)) },
		func(v any) token.Option { return token.WithCABundle(v.(string)) },
		func(v any) userinfo.Option { return userinfo.WithCABundle(v.(string)) },
		func(v any) introspection.Option { return introspection.WithCABundle(v.(string)) },
		func(v any) revocation.Option { return revocation.WithCABundle(v.(string)) },
	),
	"jwks.WithMaxSize":  jwksBinding(jwks.DefaultMaxSize, func(v any) jwks.Option { return jwks.WithMaxSize(v.(int)) }),
	"jwks.WithMaxKeys":  jwksBinding(jwks.DefaultMaxKeys, func(v any) jwks.Option { return jwks.WithMaxKeys(v.(int)) }),
	"jwks.WithCacheTTL": jwksBinding(jwks.DefaultCacheTTL, func(v any) jwks.Option { return jwks.WithCacheTTL(dur(v)) }),
	"jwks.WithRefreshCooldown": jwksBinding(jwks.DefaultRefreshCooldown, func(v any) jwks.Option {
		return jwks.WithRefreshCooldown(dur(v))
	}),
	"jwks.WithMaxCacheEntries": jwksBinding(jwks.DefaultMaxCacheEntries, func(v any) jwks.Option {
		return jwks.WithMaxCacheEntries(v.(int))
	}),
	"discovery.WithCacheTTL": discoveryBinding(discovery.DefaultCacheTTL, func(v any) discovery.Option {
		return discovery.WithCacheTTL(dur(v))
	}),
	"discovery.WithMaxCacheEntries": discoveryBinding(discovery.DefaultMaxCacheEntries, func(v any) discovery.Option {
		return discovery.WithMaxCacheEntries(v.(int))
	}),
}

func TestEveryPageOptionIsBoundAndViceVersa(t *testing.T) {
	var onPage []string
	for _, r := range pageRows(t) {
		onPage = append(onPage, r.goOptions...)
	}
	var bound []string
	for name := range bindings {
		bound = append(bound, name)
	}
	slices.Sort(onPage)
	slices.Sort(bound)
	if !slices.Equal(onPage, bound) {
		t.Errorf("Go options on the page = %v, bound here = %v", onPage, bound)
	}
}

// pageValue converts a number written on the page into the option's Go type.
func pageValue(t *testing.T, unit, text string, like any) any {
	t.Helper()
	n, err := strconv.ParseInt(strings.TrimSpace(text), 10, 64)
	if err != nil {
		t.Fatalf("page value %q is not an integer: %v", text, err)
	}
	switch like.(type) {
	case time.Duration:
		if unit != "seconds" {
			t.Fatalf("duration option with unit %q, want seconds", unit)
		}
		return time.Duration(n) * time.Second
	case int:
		return int(n)
	}
	t.Fatalf("no numeric conversion for %T", like)
	return nil
}

func TestDefaultsMatchThePage(t *testing.T) {
	for _, r := range pageRows(t) {
		for _, name := range r.goOptions {
			b, ok := bindings[name]
			if !ok {
				continue // reported by TestEveryPageOptionIsBoundAndViceVersa
			}
			if r.def == "none" {
				if b.def != "" {
					t.Errorf("%s default = %v, page says none", name, b.def)
				}
				continue
			}
			if want := pageValue(t, r.unit, r.def, b.def); b.def != want {
				t.Errorf("%s default = %v, page says %v (%s)", name, b.def, want, r.def)
			}
		}
	}
}

// smallest returns the smallest step of the option's type: 1 ns or 1.
func smallest(like any) any {
	if _, ok := like.(time.Duration); ok {
		return time.Nanosecond
	}
	return 1
}

func add(a, b any) any {
	if d, ok := a.(time.Duration); ok {
		return d + b.(time.Duration)
	}
	return a.(int) + b.(int)
}

func neg(a any) any {
	if d, ok := a.(time.Duration); ok {
		return -d
	}
	return -a.(int)
}

// edges returns the values the page's valid range accepts and rejects at its
// boundaries.
func edges(t *testing.T, r row, like any) (accept, reject []any) {
	t.Helper()
	step := smallest(like)
	switch {
	case strings.HasPrefix(r.valid, "> "):
		lo := pageValue(t, r.unit, strings.TrimPrefix(r.valid, "> "), like)
		return []any{add(lo, step)}, []any{lo, add(lo, neg(step))}
	case strings.HasPrefix(r.valid, "≥ "):
		lo := pageValue(t, r.unit, strings.TrimPrefix(r.valid, "≥ "), like)
		return []any{lo}, []any{add(lo, neg(step))}
	case strings.Contains(r.valid, " – "):
		parts := strings.SplitN(r.valid, " – ", 2)
		lo := pageValue(t, r.unit, parts[0], like)
		hi := pageValue(t, r.unit, parts[1], like)
		return []any{lo, hi}, []any{add(lo, neg(step)), add(hi, step)}
	}
	t.Fatalf("%s: unknown valid range %q", r.python, r.valid)
	return nil, nil
}

func TestRangesMatchThePage(t *testing.T) {
	for _, r := range pageRows(t) {
		for _, name := range r.goOptions {
			b, ok := bindings[name]
			if !ok || r.valid == "readable file" {
				continue
			}
			accept, reject := edges(t, r, b.def)
			for _, v := range accept {
				for pkg, ok := range b.accepts(t, v) {
					if !ok {
						t.Errorf("%s(%v) rejected by %s, page says valid is %s", name, v, pkg, r.valid)
					}
				}
			}
			for _, v := range reject {
				for pkg, ok := range b.accepts(t, v) {
					if ok {
						t.Errorf("%s(%v) accepted by %s, page says valid is %s", name, v, pkg, r.valid)
					}
				}
			}
		}
	}
}

func TestCABundleMustBeAReadableFile(t *testing.T) {
	var found *row
	for _, r := range pageRows(t) {
		if slices.Contains(r.goOptions, "WithCABundle") {
			found = &r
		}
	}
	if found == nil || found.valid != "readable file" || found.unit != "path" {
		t.Fatalf("page row for WithCABundle = %+v, want unit path, valid readable file", found)
	}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	good := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(good, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	b := bindings["WithCABundle"]
	for pkg, ok := range b.accepts(t, good) {
		if !ok {
			t.Errorf("WithCABundle(readable PEM) rejected by %s", pkg)
		}
	}
	for pkg, ok := range b.accepts(t, filepath.Join(t.TempDir(), "missing.pem")) {
		if ok {
			t.Errorf("WithCABundle(missing file) accepted by %s", pkg)
		}
	}
}
