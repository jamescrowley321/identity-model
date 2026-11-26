package main

import (
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
)

// Per-test RP logs (the clientSideData of an OIDF RP certification
// submission): each test's lines go to $RP_LOG_DIR/<profile>/<test_name>.log.
// profile and test_name arrive as request parameters, so each is reduced to a
// single safe path segment and the result is checked to stay inside the base.

var unsafePathChars = regexp.MustCompile(`[^A-Za-z0-9._-]`)

// sanitizePathComponent reduces value to one path segment of [A-Za-z0-9._-].
// An empty or dots-only result would walk out of the base, so it becomes
// fallback.
func sanitizePathComponent(value, fallback string) string {
	safe := unsafePathChars.ReplaceAllString(value, "_")
	if strings.Trim(safe, ".") == "" {
		return fallback
	}
	return safe
}

// logPath is the log file for test within profile under base.
func logPath(base, profile, test string) (string, error) {
	absBase, err := filepath.Abs(base)
	if err != nil {
		return "", err
	}
	candidate := filepath.Join(absBase, sanitizePathComponent(profile, "default"),
		sanitizePathComponent(test, "unknown")+".log")
	rel, err := filepath.Rel(absBase, candidate)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("refusing unsafe RP log path (profile=%q, test=%q)", profile, test)
	}
	return candidate, nil
}

// logMu serialises appends so concurrent requests never interleave a line.
var logMu sync.Mutex

// warnOnce reports the first log-capture failure on stderr: capture must never
// break the flow under test, but an empty clientSideData bundle is worthless.
var warnOnce sync.Once

// testLogWriter appends to the active test's log file. With no base directory
// or no test it writes nothing.
type testLogWriter struct {
	base    string
	profile string
	test    string
}

func (w *testLogWriter) Write(p []byte) (int, error) {
	if w.base == "" || w.test == "" {
		return len(p), nil
	}
	if err := w.append(p); err != nil {
		warnOnce.Do(func() {
			fmt.Fprintf(os.Stderr, "WARNING: RP per-test log capture failing for profile=%q test=%q: %v\n",
				w.profile, w.test, err)
		})
	}
	return len(p), nil
}

// Log files are world-readable (0644/0755) on purpose: the harness container
// runs as root and writes into a bind mount the runner, as the invoking host
// user, zips into the submission's clientSideData. Writes go through os.Root,
// so they cannot leave the log base whatever the path holds.
const (
	logDirPerm  fs.FileMode = 0o755
	logFilePerm fs.FileMode = 0o644
)

func (w *testLogWriter) append(p []byte) error {
	path, err := logPath(w.base, w.profile, w.test)
	if err != nil {
		return err
	}
	absBase, err := filepath.Abs(w.base)
	if err != nil {
		return err
	}
	rel, err := filepath.Rel(absBase, path)
	if err != nil {
		return err
	}
	logMu.Lock()
	defer logMu.Unlock()
	if err := os.MkdirAll(absBase, logDirPerm); err != nil {
		return err
	}
	root, err := os.OpenRoot(absBase)
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	if err := root.MkdirAll(filepath.Dir(rel), logDirPerm); err != nil {
		return err
	}
	f, err := root.OpenFile(rel, os.O_APPEND|os.O_CREATE|os.O_WRONLY, logFilePerm)
	if err != nil {
		return err
	}
	_, werr := f.Write(p)
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	return werr
}

// newTestLogger logs to stderr and to the test's log file.
func newTestLogger(base, profile, test string) *slog.Logger {
	out := io.MultiWriter(os.Stderr, &testLogWriter{base: base, profile: profile, test: test})
	return slog.New(slog.NewTextHandler(out, nil)).With("profile", profile, "test", test)
}
