package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

// rootPool returns the system roots plus the certificates in extraCAFile, the
// local suite's self-signed nginx certificate. The extra file adds trust; it
// never replaces the system roots, which the hosted suite needs. A missing file
// is not an error (a hosted run starts the harness without the local suite's
// cert volume populated).
func rootPool(extraCAFile string) (*x509.CertPool, error) {
	pool, err := x509.SystemCertPool()
	if err != nil {
		return nil, fmt.Errorf("load system roots: %w", err)
	}
	if extraCAFile == "" {
		return pool, nil
	}
	pem, err := os.ReadFile(filepath.Clean(extraCAFile))
	if errors.Is(err, fs.ErrNotExist) {
		return pool, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", extraCAFile, err)
	}
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("%s holds no PEM certificate", extraCAFile)
	}
	return pool, nil
}

// newOPClient is the client for every request to the OP: certificate
// verification on, against roots, and redirects never followed.
func newOPClient(roots *x509.CertPool) *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
	return &http.Client{
		Transport:     transport,
		Timeout:       30 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}
