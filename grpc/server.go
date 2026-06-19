package authzengrpc

import (
	"context"

	authzen "github.com/SCKelemen/authzen"
	authzenv1 "github.com/SCKelemen/authzen/grpc/gen/authzen/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// PDP is the Policy Decision Point contract that a Server delegates to. It is
// expressed entirely in terms of the transport-agnostic core types
// (github.com/SCKelemen/authzen) so that a decision engine can be written once
// and served over any binding. The Server handles all proto<->core conversion
// and request validation before calling these methods.
//
// Implementations should return an error created with the google.golang.org/
// grpc/status package to control the gRPC status code; any other (plain) error
// is reported to the caller as codes.Internal. A policy deny is NOT an error:
// it is a successful EvaluationResponse with Decision == false.
//
// OpenID AuthZEN Authorization API 1.0, Section 0 (PDP role) and Sections 6-9.
// https://openid.net/specs/authorization-api-1_0.html
type PDP interface {
	// Evaluate returns a single access decision (Section 6).
	Evaluate(ctx context.Context, req authzen.EvaluationRequest) (authzen.EvaluationResponse, error)
	// EvaluateBatch evaluates a batch request, applying the defaulting and
	// evaluations_semantic rules (Section 7). The request passed in has already
	// been validated; implementations may call req.Resolved to obtain the fully
	// specified member requests.
	EvaluateBatch(ctx context.Context, req authzen.EvaluationsRequest) (authzen.EvaluationsResponse, error)
	// SearchSubjects lists the subjects authorized for the query (Section 8.4).
	SearchSubjects(ctx context.Context, req authzen.SubjectSearchRequest) (authzen.SubjectSearchResponse, error)
	// SearchResources lists the resources authorized for the query (Section 8.5).
	SearchResources(ctx context.Context, req authzen.ResourceSearchRequest) (authzen.ResourceSearchResponse, error)
	// SearchActions lists the actions authorized for the query (Section 8.6).
	SearchActions(ctx context.Context, req authzen.ActionSearchRequest) (authzen.ActionSearchResponse, error)
	// Configuration returns the PDP metadata document (Section 9).
	Configuration(ctx context.Context) (authzen.Metadata, error)
}

// Server adapts a core PDP to the generated gRPC AccessServiceServer. It
// converts each request from its proto form to the core type, validates the
// REQUIRED fields (returning codes.InvalidArgument, the gRPC analogue of the
// spec's mandatory HTTP 400 for a missing required attribute), delegates to the
// PDP, then converts the result back to proto.
//
// OpenID AuthZEN Authorization API 1.0, Section 10.1.2 (status codes).
// https://openid.net/specs/authorization-api-1_0.html
type Server struct {
	authzenv1.UnimplementedAccessServiceServer
	pdp PDP
}

// compile-time assertion that *Server satisfies the generated server interface.
var _ authzenv1.AccessServiceServer = (*Server)(nil)

// NewServer returns a Server that delegates decisions to the given PDP.
func NewServer(pdp PDP) *Server {
	return &Server{pdp: pdp}
}

// Register installs the Server on a gRPC server (or any ServiceRegistrar). It
// is a thin convenience wrapper over the generated RegisterAccessServiceServer.
func (s *Server) Register(reg grpc.ServiceRegistrar) {
	authzenv1.RegisterAccessServiceServer(reg, s)
}

// invalidArgument converts a core validation error into a gRPC
// codes.InvalidArgument status, mirroring the spec's MUST-return-400 rule for a
// missing required attribute (Section 10.1.1).
func invalidArgument(err error) error {
	return status.Error(codes.InvalidArgument, err.Error())
}

// pdpError maps an error returned by the PDP to a gRPC status. A status error
// (or anything wrapping one) is passed through unchanged so the PDP can choose
// the code; any other error becomes codes.Internal (HTTP 500).
//
// OpenID AuthZEN Authorization API 1.0, Section 10.1.2, Table 2.
// https://openid.net/specs/authorization-api-1_0.html
func pdpError(err error) error {
	if err == nil {
		return nil
	}
	if _, ok := status.FromError(err); ok {
		return err
	}
	return status.Error(codes.Internal, err.Error())
}

// Evaluate implements the single Access Evaluation method (Section 6).
func (s *Server) Evaluate(ctx context.Context, in *authzenv1.EvaluateRequest) (*authzenv1.EvaluateResponse, error) {
	req := evaluationRequestFromProto(in)
	if err := req.Validate(); err != nil {
		return nil, invalidArgument(err)
	}
	resp, err := s.pdp.Evaluate(ctx, req)
	if err != nil {
		return nil, pdpError(err)
	}
	return evaluationResponseToProto(resp)
}

// EvaluateBatch implements the Access Evaluations (batch) method (Section 7).
func (s *Server) EvaluateBatch(ctx context.Context, in *authzenv1.EvaluateBatchRequest) (*authzenv1.EvaluateBatchResponse, error) {
	req := evaluationsRequestFromProto(in)
	if err := req.Validate(); err != nil {
		return nil, invalidArgument(err)
	}
	resp, err := s.pdp.EvaluateBatch(ctx, req)
	if err != nil {
		return nil, pdpError(err)
	}
	return evaluationsResponseToProto(resp)
}

// SearchSubjects implements the Subject Search method (Section 8.4).
func (s *Server) SearchSubjects(ctx context.Context, in *authzenv1.SearchSubjectsRequest) (*authzenv1.SearchSubjectsResponse, error) {
	req := subjectSearchRequestFromProto(in)
	if err := req.Validate(); err != nil {
		return nil, invalidArgument(err)
	}
	// The searched subject carries a type only; any supplied id MUST be ignored
	// (Section 8.4). Strip it before handing the request to the PDP, mirroring
	// the HTTP binding.
	if req.Subject != nil {
		req.Subject.ID = ""
	}
	resp, err := s.pdp.SearchSubjects(ctx, req)
	if err != nil {
		return nil, pdpError(err)
	}
	return subjectSearchResponseToProto(resp)
}

// SearchResources implements the Resource Search method (Section 8.5).
func (s *Server) SearchResources(ctx context.Context, in *authzenv1.SearchResourcesRequest) (*authzenv1.SearchResourcesResponse, error) {
	req := resourceSearchRequestFromProto(in)
	if err := req.Validate(); err != nil {
		return nil, invalidArgument(err)
	}
	// The searched resource carries a type only; any supplied id MUST be ignored
	// (Section 8.5). Strip it before handing the request to the PDP, mirroring
	// the HTTP binding.
	if req.Resource != nil {
		req.Resource.ID = ""
	}
	resp, err := s.pdp.SearchResources(ctx, req)
	if err != nil {
		return nil, pdpError(err)
	}
	return resourceSearchResponseToProto(resp)
}

// SearchActions implements the Action Search method (Section 8.6).
func (s *Server) SearchActions(ctx context.Context, in *authzenv1.SearchActionsRequest) (*authzenv1.SearchActionsResponse, error) {
	req := actionSearchRequestFromProto(in)
	if err := req.Validate(); err != nil {
		return nil, invalidArgument(err)
	}
	resp, err := s.pdp.SearchActions(ctx, req)
	if err != nil {
		return nil, pdpError(err)
	}
	return actionSearchResponseToProto(resp)
}

// GetConfiguration implements the PDP metadata method (Section 9).
func (s *Server) GetConfiguration(ctx context.Context, _ *authzenv1.GetConfigurationRequest) (*authzenv1.Configuration, error) {
	meta, err := s.pdp.Configuration(ctx)
	if err != nil {
		return nil, pdpError(err)
	}
	return metadataToProto(meta), nil
}
