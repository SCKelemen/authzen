package authzengrpc

import (
	"context"

	authzen "github.com/SCKelemen/authzen"
	authzenv1 "github.com/SCKelemen/authzen/grpc/gen/authzen/v1"
	"google.golang.org/grpc"
)

// Client is an ergonomic Policy Enforcement Point (PEP) wrapper around the
// generated AccessServiceClient. Its methods accept and return the
// transport-agnostic core types (github.com/SCKelemen/authzen), hiding the
// proto<->core conversion so that callers can speak the same vocabulary they
// use elsewhere in the AuthZEN ecosystem.
//
// OpenID AuthZEN Authorization API 1.0, Section 0 (PEP role).
// https://openid.net/specs/authorization-api-1_0.html
type Client struct {
	grpc authzenv1.AccessServiceClient
}

// NewClient wraps an existing gRPC client connection.
func NewClient(cc grpc.ClientConnInterface) *Client {
	return &Client{grpc: authzenv1.NewAccessServiceClient(cc)}
}

// NewClientFromGRPC wraps an already-constructed generated client, which is
// useful in tests or when the caller needs the raw client as well.
func NewClientFromGRPC(c authzenv1.AccessServiceClient) *Client {
	return &Client{grpc: c}
}

// Raw exposes the underlying generated client for advanced use (for example
// per-call grpc.CallOption values not surfaced by this wrapper).
func (c *Client) Raw() authzenv1.AccessServiceClient {
	return c.grpc
}

// Evaluate requests a single access decision (Section 6).
func (c *Client) Evaluate(ctx context.Context, req authzen.EvaluationRequest, opts ...grpc.CallOption) (authzen.EvaluationResponse, error) {
	in, err := evaluationRequestToProto(req)
	if err != nil {
		return authzen.EvaluationResponse{}, err
	}
	out, err := c.grpc.Evaluate(ctx, in, opts...)
	if err != nil {
		return authzen.EvaluationResponse{}, err
	}
	return evaluationResponseFromProto(out), nil
}

// EvaluateBatch requests a batch of decisions (Section 7).
func (c *Client) EvaluateBatch(ctx context.Context, req authzen.EvaluationsRequest, opts ...grpc.CallOption) (authzen.EvaluationsResponse, error) {
	in, err := evaluationsRequestToProto(req)
	if err != nil {
		return authzen.EvaluationsResponse{}, err
	}
	out, err := c.grpc.EvaluateBatch(ctx, in, opts...)
	if err != nil {
		return authzen.EvaluationsResponse{}, err
	}
	return evaluationsResponseFromProto(out), nil
}

// SearchSubjects lists the subjects authorized for the query (Section 8.4).
func (c *Client) SearchSubjects(ctx context.Context, req authzen.SubjectSearchRequest, opts ...grpc.CallOption) (authzen.SubjectSearchResponse, error) {
	in, err := subjectSearchRequestToProto(req)
	if err != nil {
		return authzen.SubjectSearchResponse{}, err
	}
	out, err := c.grpc.SearchSubjects(ctx, in, opts...)
	if err != nil {
		return authzen.SubjectSearchResponse{}, err
	}
	return subjectSearchResponseFromProto(out), nil
}

// SearchResources lists the resources authorized for the query (Section 8.5).
func (c *Client) SearchResources(ctx context.Context, req authzen.ResourceSearchRequest, opts ...grpc.CallOption) (authzen.ResourceSearchResponse, error) {
	in, err := resourceSearchRequestToProto(req)
	if err != nil {
		return authzen.ResourceSearchResponse{}, err
	}
	out, err := c.grpc.SearchResources(ctx, in, opts...)
	if err != nil {
		return authzen.ResourceSearchResponse{}, err
	}
	return resourceSearchResponseFromProto(out), nil
}

// SearchActions lists the actions authorized for the query (Section 8.6).
func (c *Client) SearchActions(ctx context.Context, req authzen.ActionSearchRequest, opts ...grpc.CallOption) (authzen.ActionSearchResponse, error) {
	in, err := actionSearchRequestToProto(req)
	if err != nil {
		return authzen.ActionSearchResponse{}, err
	}
	out, err := c.grpc.SearchActions(ctx, in, opts...)
	if err != nil {
		return authzen.ActionSearchResponse{}, err
	}
	return actionSearchResponseFromProto(out), nil
}

// GetConfiguration fetches the PDP metadata document (Section 9).
func (c *Client) GetConfiguration(ctx context.Context, opts ...grpc.CallOption) (authzen.Metadata, error) {
	out, err := c.grpc.GetConfiguration(ctx, &authzenv1.GetConfigurationRequest{}, opts...)
	if err != nil {
		return authzen.Metadata{}, err
	}
	return metadataFromProto(out), nil
}
