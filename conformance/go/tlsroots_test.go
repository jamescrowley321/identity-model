package main

import (
	"encoding/pem"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestRootPoolMissingFileKeepsSystemRoots(t *testing.T) {
	pool, err := rootPool(filepath.Join(t.TempDir(), "absent.crt"))
	if err != nil || pool == nil {
		t.Fatalf("rootPool = %v, %v; want the system pool", pool, err)
	}
}

func TestRootPoolRejectsNonPEM(t *testing.T) {
	path := filepath.Join(t.TempDir(), "junk.crt")
	if err := os.WriteFile(path, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := rootPool(path); err == nil {
		t.Fatal("rootPool accepted a file with no certificate")
	}
}

// The extra certificate is trusted: a client built from the pool reaches a
// server presenting it.
func TestRootPoolTrustsExtraCert(t *testing.T) {
	srv := httptest.NewTLSServer(nil)
	defer srv.Close()
	path := filepath.Join(t.TempDir(), "suite.crt")
	block := &pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}
	pool, err := rootPool(path)
	if err != nil {
		t.Fatalf("rootPool: %v", err)
	}
	resp, err := newOPClient(pool).Get(srv.URL)
	if err != nil {
		t.Fatalf("GET via extra root: %v", err)
	}
	_ = resp.Body.Close()
}

func TestOPClientVerifiesCertificates(t *testing.T) {
	srv := httptest.NewTLSServer(nil)
	defer srv.Close()
	pool, err := rootPool("")
	if err != nil {
		t.Fatalf("rootPool: %v", err)
	}
	if resp, err := newOPClient(pool).Get(srv.URL); err == nil {
		_ = resp.Body.Close()
		t.Fatal("client trusted an unknown self-signed certificate")
	}
}
