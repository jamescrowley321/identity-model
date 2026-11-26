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
//	RP_LISTEN_ADDR       listen IP address (default 127.0.0.1, loopback only)
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
	"net/netip"
	"os"
	"strconv"
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
	addr, err := listenAddr(os.Getenv("RP_LISTEN_ADDR"), port)
	if err != nil {
		slog.Error("listen address", "error", err)
		os.Exit(1)
	}
	srv := &http.Server{
		Addr:              addr.String(),
		Handler:           h.routes(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	// Constant messages: the address comes from the environment, and gosec
	// (G706) treats any value derived from it as a log-injection source.
	if addr.Addr().IsLoopback() {
		slog.Info("conformance-rp-go listening on loopback only (RP_LISTEN_ADDR, RP_PORT)")
	} else {
		slog.Info("conformance-rp-go listening beyond loopback (RP_LISTEN_ADDR, RP_PORT)")
	}
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

// listenAddr is the address the harness listens on. host must be an IP
// address and defaults to loopback, so only a deployment that sets
// RP_LISTEN_ADDR (the compose overlay, which publishes the port on the host's
// loopback) listens beyond it.
func listenAddr(host, port string) (netip.AddrPort, error) {
	if host == "" {
		host = "127.0.0.1"
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("RP_LISTEN_ADDR: %w", err)
	}
	p, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("RP_PORT: %w", err)
	}
	return netip.AddrPortFrom(addr, uint16(p)), nil
}
