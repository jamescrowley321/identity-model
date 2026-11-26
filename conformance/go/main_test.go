package main

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
)

func TestListenAddr(t *testing.T) {
	cases := map[string]struct {
		host, port, want string
	}{
		"default loopback": {host: "", port: "8890", want: "127.0.0.1:8890"},
		"all interfaces":   {host: "0.0.0.0", port: "8890", want: "0.0.0.0:8890"},
		"ipv6 loopback":    {host: "::1", port: "9000", want: "[::1]:9000"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			got, err := listenAddr(tc.host, tc.port)
			if err != nil {
				t.Fatalf("listenAddr(%q, %q): %v", tc.host, tc.port, err)
			}
			if got.String() != tc.want {
				t.Fatalf("listenAddr(%q, %q) = %q, want %q", tc.host, tc.port, got, tc.want)
			}
		})
	}
}

func TestListenAddrInvalid(t *testing.T) {
	cases := map[string]struct{ host, port string }{
		"hostname":       {host: "evil.example", port: "8890"},
		"non-numeric":    {host: "", port: "http"},
		"port too large": {host: "", port: "70000"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if got, err := listenAddr(tc.host, tc.port); err == nil {
				t.Fatalf("listenAddr(%q, %q) = %q, want an error", tc.host, tc.port, got)
			}
		})
	}
}

func TestProbeAddr(t *testing.T) {
	cases := map[string]struct {
		host, port, want string
	}{
		"default loopback": {host: "", port: "8890", want: "127.0.0.1:8890"},
		"ipv4 unspecified": {host: "0.0.0.0", port: "8890", want: "127.0.0.1:8890"},
		"ipv6 loopback":    {host: "::1", port: "9000", want: "[::1]:9000"},
		"ipv6 unspecified": {host: "::", port: "9000", want: "[::1]:9000"},
		"specific address": {host: "10.0.0.5", port: "8890", want: "10.0.0.5:8890"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			got, err := probeAddr(tc.host, tc.port)
			if err != nil {
				t.Fatalf("probeAddr(%q, %q): %v", tc.host, tc.port, err)
			}
			if got.String() != tc.want {
				t.Fatalf("probeAddr(%q, %q) = %q, want %q", tc.host, tc.port, got, tc.want)
			}
		})
	}
}

func TestProbeAddrInvalid(t *testing.T) {
	if got, err := probeAddr("evil.example", "8890"); err == nil {
		t.Fatalf("probeAddr = %q, want an error", got)
	}
}

func TestProbe(t *testing.T) {
	cases := map[string]struct {
		status int
		want   int
	}{
		"healthy":   {status: http.StatusOK, want: 0},
		"unhealthy": {status: http.StatusServiceUnavailable, want: 1},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/health" {
					w.WriteHeader(http.StatusNotFound)
					return
				}
				w.WriteHeader(tc.status)
			}))
			t.Cleanup(srv.Close)
			target, err := netip.ParseAddrPort(srv.Listener.Addr().String())
			if err != nil {
				t.Fatalf("parse listener address: %v", err)
			}
			if got := probe(target); got != tc.want {
				t.Fatalf("probe(%s) = %d, want %d", target, got, tc.want)
			}
		})
	}
}
