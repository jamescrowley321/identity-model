package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSanitizePathComponent(t *testing.T) {
	cases := map[string]string{
		"oidcc-client-test": "oidcc-client-test",
		"basic-rp":          "basic-rp",
		"a/b":               "a_b",
		"../../etc/passwd":  ".._.._etc_passwd",
		"..":                "fallback",
		".":                 "fallback",
		"":                  "fallback",
		"x y\\z":            "x_y_z",
	}
	for in, want := range cases {
		if got := sanitizePathComponent(in, "fallback"); got != want {
			t.Errorf("sanitizePathComponent(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestLogPathStaysInsideBase(t *testing.T) {
	base := t.TempDir()
	got, err := logPath(base, "../basic-rp", "..")
	if err != nil {
		t.Fatalf("logPath: %v", err)
	}
	want := filepath.Join(base, ".._basic-rp", "unknown.log")
	if got != want {
		t.Fatalf("logPath = %q, want %q", got, want)
	}
}

func TestTestLogWriterAppends(t *testing.T) {
	base := t.TempDir()
	w := &testLogWriter{base: base, profile: "config-rp", test: "t1"}
	for _, line := range []string{"one\n", "two\n"} {
		if _, err := w.Write([]byte(line)); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
	data, err := os.ReadFile(filepath.Join(base, "config-rp", "t1.log"))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(data) != "one\ntwo\n" {
		t.Fatalf("log = %q", data)
	}
}

func TestTestLogWriterWithoutTestIsSilent(t *testing.T) {
	base := t.TempDir()
	w := &testLogWriter{base: base}
	if _, err := w.Write([]byte("x\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	entries, err := os.ReadDir(base)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("wrote %d entries with no active test", len(entries))
	}
}
