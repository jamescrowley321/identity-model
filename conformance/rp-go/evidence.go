package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

// evidence writes the per-test OIDF "clientSideData" logs. OIDF RP
// certification requires one log file per test module proving the RP's
// accept/reject decisions — especially that negative tests were REJECTED. The
// suite only records the OP side, so the RP must emit this evidence itself.
//
// Layout mirrors the py-identity-model reference: <base>/<profile>/<test>.log,
// one "ACCEPTED: <what>" / "REJECTED: <reason>" line per decision.
type evidence struct {
	base string
	mu   sync.Mutex
}

// unsafePathChar matches anything outside the safe filename set; every match is
// replaced with "_" so a hostile profile/test name cannot escape the base dir.
var unsafePathChar = regexp.MustCompile(`[^A-Za-z0-9._-]`)

// newEvidence resolves the log base directory (RP_LOG_DIR or a default under the
// harness) to an absolute path used for the containment check.
func newEvidence(logDir string) *evidence {
	if logDir == "" {
		logDir = filepath.Join("results", "hosted", "rp-logs")
	}
	abs, err := filepath.Abs(logDir)
	if err != nil {
		abs = logDir
	}
	return &evidence{base: abs}
}

// sanitize replaces path-unsafe characters and collapses empty or dot-only
// names to a fallback, so "", ".", ".." cannot traverse directories.
func sanitize(value, fallback string) string {
	safe := unsafePathChar.ReplaceAllString(value, "_")
	if safe == "" || strings.Trim(safe, ".") == "" {
		return fallback
	}
	return safe
}

// path returns the sanitized <base>/<profile>/<test>.log and guarantees it stays
// within base (defence in depth alongside sanitize).
func (e *evidence) path(profile, test string) (string, error) {
	p := filepath.Join(e.base, sanitize(profile, "default"), sanitize(test, "unknown")+".log")
	rel, err := filepath.Rel(e.base, p)
	if err != nil || strings.HasPrefix(rel, "..") {
		return "", fmt.Errorf("refusing unsafe RP log path for profile=%q test=%q", profile, test)
	}
	return p, nil
}

// write appends one formatted evidence line to the test's log file. Failures
// never break the request flow — evidence is best-effort — but are surfaced once
// on stderr.
func (e *evidence) write(profile, test, level, msg string) {
	if test == "" {
		return
	}
	p, err := e.path(profile, test)
	if err != nil {
		e.warnOnce(err)
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		e.warnOnce(err)
		return
	}
	f, err := os.OpenFile(p, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		e.warnOnce(err)
		return
	}
	defer f.Close()
	ts := time.Now().UTC().Format("2006-01-02 15:04:05")
	fmt.Fprintf(f, "%s %-8s conformance-rp: %s\n", ts, level, msg)
}

// accept records a passing decision (positive-test evidence).
func (e *evidence) accept(profile, test, what string) {
	e.write(profile, test, "INFO", "ACCEPTED: "+what)
}

// reject records a refusal (negative-test evidence). The reason is the RP's
// stated ground for rejecting, which the suite's negative tests look for.
func (e *evidence) reject(profile, test, reason string) {
	e.write(profile, test, "ERROR", "REJECTED: "+reason)
}

var warnOnce sync.Once

func (e *evidence) warnOnce(err error) {
	warnOnce.Do(func() {
		fmt.Fprintf(os.Stderr, "WARNING: RP per-test log capture failing: %v\n", err)
	})
}
