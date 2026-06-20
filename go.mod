module github.com/SCKelemen/authzen

go 1.26

// Minimum-supported language version is `go 1.26` above; this directive pins
// the toolchain used to build/test to 1.26.2, which carries the stdlib
// security fixes (crypto/x509, net/http, ...) missing from 1.26.0.
toolchain go1.26.2
