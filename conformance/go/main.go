// Command conformance-rp-go is the OpenID Connect relying party the OIDF
// conformance runner (conformance/run_tests.py --harness go) drives through the
// Basic, Config and Form Post RP certification plans, using the Go library
// (github.com/jamescrowley321/identity-model/go) for discovery, JWKS, the
// token request, ID Token validation and UserInfo. It speaks the harness
// protocol in conformance/adding-conformance-profiles.md.
//
// Environment:
//
//	RP_PORT              listen port (default 8890)
//	RP_BASE_URL          browser-facing base for redirect_uri (default http://localhost:8890)
//	RP_INTERNAL_BASE_URL OP-facing base reported by /health (default RP_BASE_URL)
//	RP_LOG_DIR           per-test log directory ("" disables)
//	RP_EXTRA_CA_FILE     extra trusted certificate (default /certs/nginx-selfsigned.crt)
//	RP_ALLOWED_ISSUER_ORIGINS comma-separated issuer origins (scheme://host[:port])
//	                     the harness may contact; unset allows any issuer
package main

import (
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"
)

func getenv(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}

func main() {
	healthcheck := flag.Bool("healthcheck", false, "probe /health on RP_PORT and exit 0 when it answers 200")
	flag.Parse()

	port := getenv("RP_PORT", "8890")
	if *healthcheck {
		os.Exit(probe("http://127.0.0.1:" + port + "/health"))
	}

	rpBaseURL := strings.TrimRight(getenv("RP_BASE_URL", "http://localhost:"+port), "/")
	roots, err := rootPool(getenv("RP_EXTRA_CA_FILE", "/certs/nginx-selfsigned.crt"))
	if err != nil {
		slog.Error("trust roots", "error", err)
		os.Exit(1)
	}
	allowed, err := parseAllowedOrigins(os.Getenv("RP_ALLOWED_ISSUER_ORIGINS"))
	if err != nil {
		slog.Error("issuer allowlist", "error", err)
		os.Exit(1)
	}
	h := newServer(serverConfig{
		rpBaseURL:            rpBaseURL,
		opFacingBaseURL:      strings.TrimRight(getenv("RP_INTERNAL_BASE_URL", rpBaseURL), "/"),
		logDir:               os.Getenv("RP_LOG_DIR"),
		httpClient:           newOPClient(roots),
		allowedIssuerOrigins: allowed,
	})
	srv := &http.Server{
		Addr:              ":" + port,
		Handler:           h.routes(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	slog.Info("conformance-rp-go listening", "addr", srv.Addr, "rp_base_url", rpBaseURL)
	if err := srv.ListenAndServe(); err != nil {
		slog.Error("serve", "error", err)
		os.Exit(1)
	}
}

// probe is the container healthcheck (the runtime image has no curl).
func probe(url string) int {
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 1
	}
	return 0
}
