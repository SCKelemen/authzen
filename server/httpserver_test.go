package server_test

import (
	"crypto/tls"
	"fmt"
	"testing"
	"time"

	"github.com/SCKelemen/authzen/server"
)

// TestNewServerDefaults asserts that NewServer applies non-zero hardening
// timeouts (a zero-value http.Server applies none, leaving it open to
// slowloris/slow-read DoS) and pins a minimum TLS version of 1.2.
func TestNewServerDefaults(t *testing.T) {
	h := server.NewHandler(stubPDP{})
	srv := server.NewServer(":0", h)

	if srv.Addr != ":0" {
		t.Fatalf("Addr = %q, want :0", srv.Addr)
	}
	if srv.Handler == nil {
		t.Fatal("Handler is nil")
	}
	if srv.ReadTimeout <= 0 {
		t.Fatalf("ReadTimeout = %v, want > 0", srv.ReadTimeout)
	}
	if srv.ReadHeaderTimeout <= 0 {
		t.Fatalf("ReadHeaderTimeout = %v, want > 0", srv.ReadHeaderTimeout)
	}
	if srv.WriteTimeout <= 0 {
		t.Fatalf("WriteTimeout = %v, want > 0", srv.WriteTimeout)
	}
	if srv.IdleTimeout <= 0 {
		t.Fatalf("IdleTimeout = %v, want > 0", srv.IdleTimeout)
	}
	if srv.MaxHeaderBytes <= 0 {
		t.Fatalf("MaxHeaderBytes = %d, want > 0", srv.MaxHeaderBytes)
	}
	if srv.TLSConfig == nil || srv.TLSConfig.MinVersion != tls.VersionTLS12 {
		t.Fatalf("TLSConfig MinVersion = %v, want TLS 1.2", srv.TLSConfig)
	}

	// Confirm the documented default values.
	if srv.ReadTimeout != server.DefaultReadTimeout {
		t.Fatalf("ReadTimeout = %v, want %v", srv.ReadTimeout, server.DefaultReadTimeout)
	}
	if srv.ReadHeaderTimeout != server.DefaultReadHeaderTimeout {
		t.Fatalf("ReadHeaderTimeout = %v, want %v", srv.ReadHeaderTimeout, server.DefaultReadHeaderTimeout)
	}
	if srv.WriteTimeout != server.DefaultWriteTimeout {
		t.Fatalf("WriteTimeout = %v, want %v", srv.WriteTimeout, server.DefaultWriteTimeout)
	}
	if srv.IdleTimeout != server.DefaultIdleTimeout {
		t.Fatalf("IdleTimeout = %v, want %v", srv.IdleTimeout, server.DefaultIdleTimeout)
	}
}

// TestNewServerOptionsOverride verifies options take effect and that a
// non-positive value is normalized back to the safe default.
func TestNewServerOptionsOverride(t *testing.T) {
	h := server.NewHandler(stubPDP{})
	srv := server.NewServer(":8443", h,
		server.WithReadTimeout(3*time.Second),
		server.WithIdleTimeout(0), // non-positive -> normalized to default
		server.WithTLSConfig(&tls.Config{MinVersion: tls.VersionTLS13}),
	)

	if srv.ReadTimeout != 3*time.Second {
		t.Fatalf("ReadTimeout = %v, want 3s", srv.ReadTimeout)
	}
	if srv.IdleTimeout != server.DefaultIdleTimeout {
		t.Fatalf("IdleTimeout = %v, want normalized default %v", srv.IdleTimeout, server.DefaultIdleTimeout)
	}
	if srv.TLSConfig == nil || srv.TLSConfig.MinVersion != tls.VersionTLS13 {
		t.Fatalf("TLSConfig MinVersion = %v, want TLS 1.3 override", srv.TLSConfig)
	}
}

// ExampleNewServer shows constructing a hardened HTTP server for an AuthZEN
// handler. In production, serve it over TLS with srv.ListenAndServeTLS.
func ExampleNewServer() {
	h := server.NewHandler(stubPDP{})
	srv := server.NewServer(":8443", h)

	fmt.Println(srv.Addr)
	fmt.Println(srv.ReadHeaderTimeout)
	fmt.Println(srv.TLSConfig.MinVersion == tls.VersionTLS12)

	// In production:
	//   log.Fatal(srv.ListenAndServeTLS("cert.pem", "key.pem"))

	// Output:
	// :8443
	// 5s
	// true
}
