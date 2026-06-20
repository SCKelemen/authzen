package server

import (
	"crypto/tls"
	"net/http"
	"time"
)

// Hardened *http.Server timeout defaults. Go's zero-value http.Server applies
// NO timeouts, which leaves a PDP exposed to slowloris (slow header trickle) and
// slow-read/slow-body denial-of-service attacks: a handful of connections that
// send or read one byte at a time can pin server goroutines indefinitely. These
// defaults bound every phase of a connection's lifetime. All are configurable
// via ServerOptions.
//
// The values are deliberately generous enough for normal JSON request/response
// exchanges yet small enough to reclaim resources from stalled peers.
const (
	// DefaultReadTimeout bounds the time to read the entire request, including
	// the body. Caps slow-body (slow-read) attacks.
	DefaultReadTimeout = 10 * time.Second
	// DefaultReadHeaderTimeout bounds the time to read request headers. This is
	// the primary slowloris defense (a client that dribbles headers forever).
	DefaultReadHeaderTimeout = 5 * time.Second
	// DefaultWriteTimeout bounds the time from the end of the request header
	// read to the end of the response write. Caps slow-read clients that refuse
	// to drain the response.
	DefaultWriteTimeout = 15 * time.Second
	// DefaultIdleTimeout bounds how long a keep-alive connection may sit idle
	// between requests before being closed, reclaiming idle connections.
	DefaultIdleTimeout = 120 * time.Second
	// DefaultMaxHeaderBytes caps the size of request headers, bounding header
	// memory per connection. Mirrors net/http's own default but stated
	// explicitly for clarity.
	DefaultMaxHeaderBytes = 1 << 20 // 1 MiB
)

// serverConfig holds the resolved knobs for NewServer.
type serverConfig struct {
	readTimeout       time.Duration
	readHeaderTimeout time.Duration
	writeTimeout      time.Duration
	idleTimeout       time.Duration
	maxHeaderBytes    int
	tlsConfig         *tls.Config
}

// ServerOption configures the *http.Server returned by NewServer.
type ServerOption func(*serverConfig)

// WithReadTimeout overrides DefaultReadTimeout. A non-positive value resets it
// to the default.
func WithReadTimeout(d time.Duration) ServerOption {
	return func(c *serverConfig) { c.readTimeout = d }
}

// WithReadHeaderTimeout overrides DefaultReadHeaderTimeout. A non-positive value
// resets it to the default.
func WithReadHeaderTimeout(d time.Duration) ServerOption {
	return func(c *serverConfig) { c.readHeaderTimeout = d }
}

// WithWriteTimeout overrides DefaultWriteTimeout. A non-positive value resets it
// to the default.
func WithWriteTimeout(d time.Duration) ServerOption {
	return func(c *serverConfig) { c.writeTimeout = d }
}

// WithIdleTimeout overrides DefaultIdleTimeout. A non-positive value resets it
// to the default.
func WithIdleTimeout(d time.Duration) ServerOption {
	return func(c *serverConfig) { c.idleTimeout = d }
}

// WithMaxHeaderBytes overrides DefaultMaxHeaderBytes. A non-positive value
// resets it to the default.
func WithMaxHeaderBytes(n int) ServerOption {
	return func(c *serverConfig) { c.maxHeaderBytes = n }
}

// WithTLSConfig replaces the default *tls.Config (which pins a minimum of TLS
// 1.2). A nil value resets to the secure default. The returned server still
// requires the caller to invoke ListenAndServeTLS (or serve behind a TLS
// terminator); setting TLSConfig alone does not enable TLS.
func WithTLSConfig(cfg *tls.Config) ServerOption {
	return func(c *serverConfig) { c.tlsConfig = cfg }
}

// NewServer builds a production-hardened *http.Server for an AuthZEN handler (or
// any http.Handler). Unlike a zero-value http.Server, it sets ReadTimeout,
// ReadHeaderTimeout, WriteTimeout, and IdleTimeout so that slow or stalled peers
// cannot exhaust server resources (slowloris and slow-read DoS); see the
// Default* constants for the rationale of each. It also pins a minimum TLS
// version of 1.2 in the default TLSConfig.
//
// Transport security: AuthZEN mandates the HTTPS + JSON binding (Section 10.1),
// so serve this with TLS in production:
//
//	srv := server.NewServer(":8443", handler)
//	log.Fatal(srv.ListenAndServeTLS("cert.pem", "key.pem"))
//
// The default TLSConfig sets MinVersion = tls.VersionTLS12; override it with
// WithTLSConfig to pin TLS 1.3, configure cipher suites, or supply certificates
// via GetCertificate. For plain HTTP (for example behind a TLS-terminating load
// balancer) call srv.ListenAndServe instead; the TLSConfig is then ignored.
//
// OpenID AuthZEN Authorization API 1.0, Section 10.1 (Transport): "The Access
// Evaluation API is a JSON/HTTPS API."
// https://openid.net/specs/authorization-api-1_0.html#name-transport
func NewServer(addr string, h http.Handler, opts ...ServerOption) *http.Server {
	cfg := serverConfig{
		readTimeout:       DefaultReadTimeout,
		readHeaderTimeout: DefaultReadHeaderTimeout,
		writeTimeout:      DefaultWriteTimeout,
		idleTimeout:       DefaultIdleTimeout,
		maxHeaderBytes:    DefaultMaxHeaderBytes,
		tlsConfig:         &tls.Config{MinVersion: tls.VersionTLS12},
	}
	for _, opt := range opts {
		opt(&cfg)
	}
	// Normalize non-positive knobs back to their defaults so a misconfigured
	// option can never disable a timeout (which would reintroduce the DoS
	// exposure the defaults exist to close).
	if cfg.readTimeout <= 0 {
		cfg.readTimeout = DefaultReadTimeout
	}
	if cfg.readHeaderTimeout <= 0 {
		cfg.readHeaderTimeout = DefaultReadHeaderTimeout
	}
	if cfg.writeTimeout <= 0 {
		cfg.writeTimeout = DefaultWriteTimeout
	}
	if cfg.idleTimeout <= 0 {
		cfg.idleTimeout = DefaultIdleTimeout
	}
	if cfg.maxHeaderBytes <= 0 {
		cfg.maxHeaderBytes = DefaultMaxHeaderBytes
	}
	if cfg.tlsConfig == nil {
		cfg.tlsConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	}

	return &http.Server{
		Addr:              addr,
		Handler:           h,
		ReadTimeout:       cfg.readTimeout,
		ReadHeaderTimeout: cfg.readHeaderTimeout,
		WriteTimeout:      cfg.writeTimeout,
		IdleTimeout:       cfg.idleTimeout,
		MaxHeaderBytes:    cfg.maxHeaderBytes,
		TLSConfig:         cfg.tlsConfig,
	}
}
