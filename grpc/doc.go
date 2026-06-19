// Package authzengrpc provides a gRPC binding for the OpenID AuthZEN
// Authorization API 1.0, layered on top of the transport-agnostic core types
// in github.com/SCKelemen/authzen.
//
// The AuthZEN specification defines a normative HTTPS + JSON binding
// (Section 10) and explicitly allows additional bindings (gRPC, CoAP) to be
// defined as profiles (Section 0). This package is such a gRPC profile: the
// service and messages, generated from proto/authzen/v1, mirror the HTTP/JSON
// semantics as closely as possible while following Google's API Improvement
// Proposals (https://google.aip.dev/): resource-oriented design (AIP-121),
// resource names (AIP-122), standard Get/List methods (AIP-131/132), custom
// methods (AIP-136), pagination (AIP-158), and field-behavior annotations
// (AIP-203).
//
// It lives in a nested Go module (github.com/SCKelemen/authzen/grpc) so that
// the gRPC and protobuf dependencies never leak into the zero-dependency root
// module.
//
// The package offers three pieces:
//
//   - Server: adapts a core PDP interface to the generated
//     AccessServiceServer, handling proto<->core conversion and validation
//     (a missing required field becomes codes.InvalidArgument, the gRPC
//     analogue of the spec's mandatory HTTP 400).
//   - Client: an ergonomic PEP wrapper whose methods speak the core types.
//   - Conversions: total functions between the proto wire types and the core
//     types, with google.protobuf.Struct standing in for the free-form
//     properties and context objects.
//
// OpenID AuthZEN Authorization API 1.0 (Final Specification, 2026-01-12).
// https://openid.net/specs/authorization-api-1_0.html
package authzengrpc
