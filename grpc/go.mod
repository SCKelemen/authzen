module github.com/SCKelemen/authzen/grpc

go 1.26

// Minimum-supported language version is `go 1.26` above; this directive pins
// the toolchain used to build/test to 1.26.2 (stdlib security fixes).
toolchain go1.26.2

// The gRPC binding lives in a nested module so that the gRPC and protobuf
// dependencies never leak into the zero-dependency root module
// (github.com/SCKelemen/authzen). The root module is consumed locally via the
// replace directive below.
require (
	github.com/SCKelemen/authzen v0.0.0
	google.golang.org/grpc v1.69.2
	google.golang.org/protobuf v1.36.11
)

require google.golang.org/genproto/googleapis/api v0.0.0-20241015192408-796eee8c2d53

require (
	golang.org/x/net v0.30.0 // indirect
	golang.org/x/sys v0.26.0 // indirect
	golang.org/x/text v0.19.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20241015192408-796eee8c2d53 // indirect
)

replace github.com/SCKelemen/authzen => ../
