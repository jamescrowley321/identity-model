package main

import "testing"

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
