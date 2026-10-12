// Package transport holds the HTTP settings every identity-model package shares
// (spec/config.md): the request timeout, retries with exponential backoff and
// the CA bundle. It also holds the Cache-Control rules the discovery and JWKS
// caches apply. It reads no environment: every value comes from the caller's
// options.
package transport

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

// Defaults from spec/config.md.
const (
	DefaultTimeout          = 30 * time.Second
	DefaultRetryMaxAttempts = 3
	DefaultRetryBaseDelay   = time.Second

	// MaxRetryDelay caps the wait before any one retry.
	MaxRetryDelay = 120 * time.Second
)

// Settings are the transport settings of one client or call.
type Settings struct {
	// Timeout bounds each attempt, including reading the response body.
	Timeout time.Duration
	// RetryMaxAttempts is how many times a retryable failure is retried; 0
	// disables retries.
	RetryMaxAttempts int
	// RetryBaseDelay is the base of the exponential backoff.
	RetryBaseDelay time.Duration
	// CABundle is a PEM file of trusted roots; "" uses the system roots.
	CABundle string
	// HTTPClient sends the requests; nil uses [http.DefaultClient].
	HTTPClient *http.Client
}

// Defaults returns the default settings.
func Defaults() Settings {
	return Settings{
		Timeout:          DefaultTimeout,
		RetryMaxAttempts: DefaultRetryMaxAttempts,
		RetryBaseDelay:   DefaultRetryBaseDelay,
	}
}

// Issue is one invalid setting: the option that set it and the rule it broke.
// It never carries the value.
type Issue struct {
	Setting string
	Rule    string
}

// ErrInvalidConfig matches every [ConfigError].
var ErrInvalidConfig = errors.New("invalid configuration")

// ConfigError reports every invalid option of a client or call at once.
type ConfigError struct {
	// Package is the package that rejected the options, e.g. "jwks".
	Package string
	Issues  []Issue
}

// NewConfigError returns a *ConfigError for issues raised in pkg.
func NewConfigError(pkg string, issues []Issue) *ConfigError {
	return &ConfigError{Package: pkg, Issues: issues}
}

func (e *ConfigError) Error() string {
	parts := make([]string, len(e.Issues))
	for i, issue := range e.Issues {
		parts[i] = issue.Setting + " " + issue.Rule
	}
	return e.Package + ": invalid configuration: " + strings.Join(parts, "; ")
}

// Is reports whether target is [ErrInvalidConfig].
func (e *ConfigError) Is(target error) bool { return target == ErrInvalidConfig }

// Rules shared with the packages' own settings.
const (
	RulePositive    = "must be > 0"
	RuleNonNegative = "must be >= 0"
	RuleAtLeastOne  = "must be >= 1"
	// RuleCacheTTL is the range of a configured cache lifetime.
	RuleCacheTTL    = "must be 60s to 86400s"
	ruleCABundle    = "must be a readable PEM file with at least one certificate"
	ruleCAAndClient = "cannot be combined with WithHTTPClient"
)

// Build validates s and returns the transport it describes, or every issue.
func (s Settings) Build() (*Transport, []Issue) {
	var issues []Issue
	if s.Timeout <= 0 {
		issues = append(issues, Issue{"WithTimeout", RulePositive})
	}
	if s.RetryMaxAttempts < 0 {
		issues = append(issues, Issue{"WithRetryMaxAttempts", RuleNonNegative})
	}
	if s.RetryBaseDelay < 0 {
		issues = append(issues, Issue{"WithRetryBaseDelay", RuleNonNegative})
	}
	client := s.HTTPClient
	if s.CABundle != "" {
		if s.HTTPClient != nil {
			issues = append(issues, Issue{"WithCABundle", ruleCAAndClient})
		} else if c, ok := caBundleClient(s.CABundle); ok {
			client = c
		} else {
			issues = append(issues, Issue{"WithCABundle", ruleCABundle})
		}
	}
	if len(issues) > 0 {
		return nil, issues
	}
	if client == nil {
		client = http.DefaultClient
	}
	return &Transport{settings: s, client: client, sleep: sleepCtx}, nil
}

// caBundleClient returns a client that trusts only the certificates in the PEM
// file at path.
func caBundleClient(path string) (*http.Client, bool) {
	pemBytes, err := os.ReadFile(path) // #nosec G304 -- the caller names its own CA bundle
	if err != nil {
		return nil, false
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemBytes) {
		return nil, false
	}
	base, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return nil, false
	}
	rt := base.Clone()
	rt.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	return &http.Client{Transport: rt}, true
}

// Transport sends requests with the settings it was built from.
type Transport struct {
	settings Settings
	client   *http.Client
	sleep    func(context.Context, time.Duration) error
}

// Client returns the HTTP client requests go through.
func (t *Transport) Client() *http.Client { return t.client }

// WithClient returns a copy of t that sends through client.
func (t *Transport) WithClient(client *http.Client) *Transport {
	cp := *t
	cp.client = client
	return &cp
}

// Do sends the request newReq builds, retrying a 429 or 5xx response and a
// transport error up to RetryMaxAttempts times. newReq is called once per
// attempt, so a request body is rebuilt each time. Each attempt has its own
// Timeout, which also covers reading the returned body; close it to release
// the attempt. When retries run out the last response (or error) is returned.
// A cancelled or expired ctx, or an error marked [Permanent], stops retrying.
func (t *Transport) Do(ctx context.Context, newReq func(context.Context) (*http.Request, error)) (*http.Response, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	for attempt := 0; ; attempt++ {
		attemptCtx, cancel := context.WithTimeout(ctx, t.settings.Timeout)
		req, err := newReq(attemptCtx)
		if err != nil {
			cancel()
			return nil, err
		}
		resp, err := t.client.Do(req)
		final := attempt >= t.settings.RetryMaxAttempts || ctx.Err() != nil
		if err != nil {
			cancel()
			var perm *permanentError
			if final || errors.As(err, &perm) {
				return nil, err
			}
			if err := t.sleep(ctx, retryDelay(t.settings.RetryBaseDelay, attempt, "", time.Now())); err != nil {
				return nil, err
			}
			continue
		}
		if final || !retryableStatus(resp.StatusCode) {
			resp.Body = &cancelOnClose{ReadCloser: resp.Body, cancel: cancel}
			return resp, nil
		}
		delay := retryDelay(t.settings.RetryBaseDelay, attempt, resp.Header.Get("Retry-After"), time.Now())
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		_ = resp.Body.Close()
		cancel()
		if err := t.sleep(ctx, delay); err != nil {
			return nil, err
		}
	}
}

// Permanent marks err as not worth retrying: [Transport.Do] returns it at once.
// Use it for a policy refusal, such as a CheckRedirect rejection, that would
// fail the same way on every attempt.
func Permanent(err error) error { return &permanentError{err: err} }

type permanentError struct{ err error }

func (e *permanentError) Error() string { return e.err.Error() }
func (e *permanentError) Unwrap() error { return e.err }

// retryableStatus reports whether a response status is retried: 429 (rate
// limited) and every 5xx.
func retryableStatus(code int) bool {
	return code == http.StatusTooManyRequests || code >= http.StatusInternalServerError
}

// retryDelay is the wait before retry number attempt+1: base * 2^attempt, or a
// longer Retry-After (RFC 9110 §10.2.3), capped at [MaxRetryDelay].
func retryDelay(base time.Duration, attempt int, retryAfter string, now time.Time) time.Duration {
	delay := base
	for i := 0; i < attempt && delay < MaxRetryDelay; i++ {
		delay *= 2
	}
	if ra, ok := parseRetryAfter(retryAfter, now); ok && ra > delay {
		delay = ra
	}
	return min(delay, MaxRetryDelay)
}

// parseRetryAfter reads a Retry-After value in delta-seconds or HTTP-date form.
// A date in the past is a zero delay.
func parseRetryAfter(value string, now time.Time) (time.Duration, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, false
	}
	if secs, err := strconv.ParseInt(value, 10, 64); err == nil {
		if secs < 0 {
			return 0, false
		}
		if secs > int64(MaxRetryDelay/time.Second) {
			return MaxRetryDelay, true
		}
		return time.Duration(secs) * time.Second, true
	}
	if at, err := http.ParseTime(value); err == nil {
		return max(at.Sub(now), 0), true
	}
	return 0, false
}

// sleepCtx waits d or until ctx is done.
func sleepCtx(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// cancelOnClose releases an attempt's context when its body is closed.
type cancelOnClose struct {
	io.ReadCloser
	cancel context.CancelFunc
}

func (b *cancelOnClose) Close() error {
	err := b.ReadCloser.Close()
	b.cancel()
	return err
}
