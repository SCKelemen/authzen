package authzengrpc

import (
	authzen "github.com/SCKelemen/authzen"
	authzenv1 "github.com/SCKelemen/authzen/grpc/gen/authzen/v1"
	"google.golang.org/protobuf/types/known/structpb"
)

// This file holds the conversions between the protobuf wire types
// (package authzenv1, generated from proto/authzen/v1) and the transport-
// agnostic core types (github.com/SCKelemen/authzen). Free-form JSON objects
// (properties and context) are carried as google.protobuf.Struct on the wire
// and as map[string]any in the core, mirroring the JSON binding of the spec.
//
// Note on numbers: google.protobuf.Struct models every JSON number as a
// double, exactly like JSON itself. Converting a map[string]any into a Struct
// and back therefore yields float64 for any numeric value, which matches the
// behavior of encoding/json's decode into an interface{}.
//
// OpenID AuthZEN Authorization API 1.0, Section 5 (Information model) and
// Section 10.1.1 (JSON Serialization).
// https://openid.net/specs/authorization-api-1_0.html

// structToMap converts a google.protobuf.Struct into the map[string]any shape
// used by the core types, returning nil for a nil Struct so that an absent
// object stays absent.
func structToMap(s *structpb.Struct) map[string]any {
	if s == nil {
		return nil
	}
	return s.AsMap()
}

// mapToStruct converts a map[string]any into a google.protobuf.Struct. An empty
// or nil map yields a nil Struct so that an absent object is not serialized as
// an empty object (mirroring the omitempty behavior of the core JSON tags).
func mapToStruct(m map[string]any) (*structpb.Struct, error) {
	if len(m) == 0 {
		return nil, nil
	}
	return structpb.NewStruct(m)
}

// --- Entities (Section 5) ---

// subjectToProto converts a core Subject (Section 5.1) to its proto form.
func subjectToProto(s *authzen.Subject) (*authzenv1.Subject, error) {
	if s == nil {
		return nil, nil
	}
	props, err := mapToStruct(s.Properties)
	if err != nil {
		return nil, err
	}
	return &authzenv1.Subject{Type: s.Type, Id: s.ID, Properties: props}, nil
}

// subjectFromProto converts a proto Subject (Section 5.1) to its core form.
func subjectFromProto(s *authzenv1.Subject) *authzen.Subject {
	if s == nil {
		return nil
	}
	return &authzen.Subject{
		Type:       s.GetType(),
		ID:         s.GetId(),
		Properties: structToMap(s.GetProperties()),
	}
}

// resourceToProto converts a core Resource (Section 5.2) to its proto form.
func resourceToProto(r *authzen.Resource) (*authzenv1.Resource, error) {
	if r == nil {
		return nil, nil
	}
	props, err := mapToStruct(r.Properties)
	if err != nil {
		return nil, err
	}
	return &authzenv1.Resource{Type: r.Type, Id: r.ID, Properties: props}, nil
}

// resourceFromProto converts a proto Resource (Section 5.2) to its core form.
func resourceFromProto(r *authzenv1.Resource) *authzen.Resource {
	if r == nil {
		return nil
	}
	return &authzen.Resource{
		Type:       r.GetType(),
		ID:         r.GetId(),
		Properties: structToMap(r.GetProperties()),
	}
}

// actionToProto converts a core Action (Section 5.3) to its proto form.
func actionToProto(a *authzen.Action) (*authzenv1.Action, error) {
	if a == nil {
		return nil, nil
	}
	props, err := mapToStruct(a.Properties)
	if err != nil {
		return nil, err
	}
	return &authzenv1.Action{Name: a.Name, Properties: props}, nil
}

// actionFromProto converts a proto Action (Section 5.3) to its core form.
func actionFromProto(a *authzenv1.Action) *authzen.Action {
	if a == nil {
		return nil
	}
	return &authzen.Action{
		Name:       a.GetName(),
		Properties: structToMap(a.GetProperties()),
	}
}

// --- Single evaluation (Section 6) ---

// evaluationRequestToProto converts a core EvaluationRequest (Section 6.1) to
// its proto EvaluateRequest form.
func evaluationRequestToProto(r authzen.EvaluationRequest) (*authzenv1.EvaluateRequest, error) {
	subject, err := subjectToProto(r.Subject)
	if err != nil {
		return nil, err
	}
	action, err := actionToProto(r.Action)
	if err != nil {
		return nil, err
	}
	resource, err := resourceToProto(r.Resource)
	if err != nil {
		return nil, err
	}
	ctx, err := mapToStruct(r.Context)
	if err != nil {
		return nil, err
	}
	return &authzenv1.EvaluateRequest{
		Subject:  subject,
		Action:   action,
		Resource: resource,
		Context:  ctx,
	}, nil
}

// evaluationRequestFromProto converts a proto EvaluateRequest (Section 6.1) to
// its core form.
func evaluationRequestFromProto(r *authzenv1.EvaluateRequest) authzen.EvaluationRequest {
	if r == nil {
		return authzen.EvaluationRequest{}
	}
	return authzen.EvaluationRequest{
		Subject:  subjectFromProto(r.GetSubject()),
		Action:   actionFromProto(r.GetAction()),
		Resource: resourceFromProto(r.GetResource()),
		Context:  structToMap(r.GetContext()),
	}
}

// evaluationResponseToProto converts a core EvaluationResponse (Section 6.2) to
// its proto EvaluateResponse form.
func evaluationResponseToProto(r authzen.EvaluationResponse) (*authzenv1.EvaluateResponse, error) {
	ctx, err := mapToStruct(r.Context)
	if err != nil {
		return nil, err
	}
	return &authzenv1.EvaluateResponse{Decision: r.Decision, Context: ctx}, nil
}

// evaluationResponseFromProto converts a proto EvaluateResponse (Section 6.2)
// to its core form.
func evaluationResponseFromProto(r *authzenv1.EvaluateResponse) authzen.EvaluationResponse {
	if r == nil {
		return authzen.EvaluationResponse{}
	}
	return authzen.EvaluationResponse{
		Decision: r.GetDecision(),
		Context:  structToMap(r.GetContext()),
	}
}

// --- Batch evaluation (Section 7) ---

// semanticToProto maps a core evaluations_semantic string (Section 7.1.2.1) to
// the proto enum. The empty string (meaning the default) maps to UNSPECIFIED.
func semanticToProto(s authzen.EvaluationsSemantic) authzenv1.EvaluationsSemantic {
	switch s {
	case authzen.SemanticExecuteAll:
		return authzenv1.EvaluationsSemantic_EVALUATIONS_SEMANTIC_EXECUTE_ALL
	case authzen.SemanticDenyOnFirstDeny:
		return authzenv1.EvaluationsSemantic_EVALUATIONS_SEMANTIC_DENY_ON_FIRST_DENY
	case authzen.SemanticPermitOnFirstPermit:
		return authzenv1.EvaluationsSemantic_EVALUATIONS_SEMANTIC_PERMIT_ON_FIRST_PERMIT
	default:
		return authzenv1.EvaluationsSemantic_EVALUATIONS_SEMANTIC_UNSPECIFIED
	}
}

// semanticFromProto maps the proto enum (Section 7.1.2.1) back to the core
// string. UNSPECIFIED maps to the empty string so that the core layer applies
// its own default (execute_all).
func semanticFromProto(e authzenv1.EvaluationsSemantic) authzen.EvaluationsSemantic {
	switch e {
	case authzenv1.EvaluationsSemantic_EVALUATIONS_SEMANTIC_EXECUTE_ALL:
		return authzen.SemanticExecuteAll
	case authzenv1.EvaluationsSemantic_EVALUATIONS_SEMANTIC_DENY_ON_FIRST_DENY:
		return authzen.SemanticDenyOnFirstDeny
	case authzenv1.EvaluationsSemantic_EVALUATIONS_SEMANTIC_PERMIT_ON_FIRST_PERMIT:
		return authzen.SemanticPermitOnFirstPermit
	default:
		return ""
	}
}

// optionsToProto converts core batch Options (Section 7.1.2) to proto form.
func optionsToProto(o *authzen.Options) (*authzenv1.Options, error) {
	if o == nil {
		return nil, nil
	}
	additional, err := mapToStruct(o.Additional)
	if err != nil {
		return nil, err
	}
	return &authzenv1.Options{
		EvaluationsSemantic: semanticToProto(o.EvaluationsSemantic),
		Additional:          additional,
	}, nil
}

// optionsFromProto converts proto Options (Section 7.1.2) to core form. A nil
// proto Options yields a nil core Options.
func optionsFromProto(o *authzenv1.Options) *authzen.Options {
	if o == nil {
		return nil
	}
	return &authzen.Options{
		EvaluationsSemantic: semanticFromProto(o.GetEvaluationsSemantic()),
		Additional:          structToMap(o.GetAdditional()),
	}
}

// evaluationsRequestToProto converts a core EvaluationsRequest (Section 7.1) to
// its proto EvaluateBatchRequest form, preserving the top-level defaults and
// the per-member overrides without resolving them (resolution is the PDP's
// job, per Section 7.1.1).
func evaluationsRequestToProto(r authzen.EvaluationsRequest) (*authzenv1.EvaluateBatchRequest, error) {
	subject, err := subjectToProto(r.Subject)
	if err != nil {
		return nil, err
	}
	action, err := actionToProto(r.Action)
	if err != nil {
		return nil, err
	}
	resource, err := resourceToProto(r.Resource)
	if err != nil {
		return nil, err
	}
	ctx, err := mapToStruct(r.Context)
	if err != nil {
		return nil, err
	}
	options, err := optionsToProto(r.Options)
	if err != nil {
		return nil, err
	}
	var members []*authzenv1.EvaluateRequest
	if len(r.Evaluations) > 0 {
		members = make([]*authzenv1.EvaluateRequest, len(r.Evaluations))
		for i, e := range r.Evaluations {
			m, err := evaluationRequestToProto(e)
			if err != nil {
				return nil, err
			}
			members[i] = m
		}
	}
	return &authzenv1.EvaluateBatchRequest{
		Subject:     subject,
		Action:      action,
		Resource:    resource,
		Context:     ctx,
		Evaluations: members,
		Options:     options,
	}, nil
}

// evaluationsRequestFromProto converts a proto EvaluateBatchRequest
// (Section 7.1) to its core form.
func evaluationsRequestFromProto(r *authzenv1.EvaluateBatchRequest) authzen.EvaluationsRequest {
	if r == nil {
		return authzen.EvaluationsRequest{}
	}
	var members []authzen.EvaluationRequest
	if len(r.GetEvaluations()) > 0 {
		members = make([]authzen.EvaluationRequest, len(r.GetEvaluations()))
		for i, e := range r.GetEvaluations() {
			members[i] = evaluationRequestFromProto(e)
		}
	}
	return authzen.EvaluationsRequest{
		Subject:     subjectFromProto(r.GetSubject()),
		Action:      actionFromProto(r.GetAction()),
		Resource:    resourceFromProto(r.GetResource()),
		Context:     structToMap(r.GetContext()),
		Evaluations: members,
		Options:     optionsFromProto(r.GetOptions()),
	}
}

// evaluationsResponseToProto converts a core EvaluationsResponse (Section 7.2)
// to its proto EvaluateBatchResponse form.
func evaluationsResponseToProto(r authzen.EvaluationsResponse) (*authzenv1.EvaluateBatchResponse, error) {
	out := &authzenv1.EvaluateBatchResponse{
		Evaluations: make([]*authzenv1.EvaluateResponse, len(r.Evaluations)),
	}
	for i, e := range r.Evaluations {
		m, err := evaluationResponseToProto(e)
		if err != nil {
			return nil, err
		}
		out.Evaluations[i] = m
	}
	return out, nil
}

// evaluationsResponseFromProto converts a proto EvaluateBatchResponse
// (Section 7.2) to its core form.
func evaluationsResponseFromProto(r *authzenv1.EvaluateBatchResponse) authzen.EvaluationsResponse {
	if r == nil {
		return authzen.EvaluationsResponse{}
	}
	out := authzen.EvaluationsResponse{
		Evaluations: make([]authzen.EvaluationResponse, len(r.GetEvaluations())),
	}
	for i, e := range r.GetEvaluations() {
		out.Evaluations[i] = evaluationResponseFromProto(e)
	}
	return out
}

// --- Pagination (Section 8.2 / AIP-158) ---

// pageToProto flattens a core request Page (Section 8.2.1) into the flat,
// AIP-158-idiomatic page_size / page_token / page_properties request fields. A
// nil Page yields zero values.
//
// Unlike the response page (carried as a nullable PageResponse message), the
// request page uses flat scalar fields per AIP-158. The one consequence is a
// single benign normalization documented on pageFromProto: a present-but-empty
// request Page collapses to absent. The request page is purely optional input
// whose fields all default, so an empty page and an absent page are
// semantically identical (no token, default limit, no hints), which makes the
// normalization lossless in meaning.
func pageToProto(p *authzen.Page) (size int32, token string, props *structpb.Struct, err error) {
	if p == nil {
		return 0, "", nil, nil
	}
	props, err = mapToStruct(p.Properties)
	if err != nil {
		return 0, "", nil, err
	}
	return int32(p.Limit), p.Token, props, nil
}

// pageFromProto reassembles a core request Page (Section 8.2.1) from the flat
// AIP-158 fields, returning nil when none are set.
//
// Normalization (intentional, semantically lossless): a request that carried a
// present-but-empty page (limit 0, no token, no properties) is indistinguishable
// on the wire from an absent page and is therefore reconstructed as nil. This
// is safe because every request page field is optional with a default; an empty
// page requests nothing that an absent page does not. The response page does
// NOT share this behavior -- see pageResponseFromProto, which preserves
// presence exactly via the nullable PageResponse message.
func pageFromProto(size int32, token string, props *structpb.Struct) *authzen.Page {
	if size == 0 && token == "" && props == nil {
		return nil
	}
	return &authzen.Page{
		Token:      token,
		Limit:      int(size),
		Properties: structToMap(props),
	}
}

// pageResponseToProto converts a core response PageResponse (Section 8.2.2)
// into the proto PageResponse message. The conversion is lossless: every field
// of the spec's page object (next_token, count, total, properties) is carried
// explicitly, and presence is preserved exactly. A nil core page yields a nil
// message (an absent page object); a present-but-empty page (the end-of-results
// marker, all fields zero) yields a non-nil, all-zero message that remains
// distinguishable from an absent page on the wire.
func pageResponseToProto(p *authzen.PageResponse) (*authzenv1.PageResponse, error) {
	if p == nil {
		return nil, nil
	}
	props, err := mapToStruct(p.Properties)
	if err != nil {
		return nil, err
	}
	return &authzenv1.PageResponse{
		NextToken:  p.NextToken,
		Count:      int32(p.Count),
		Total:      int32(p.Total),
		Properties: props,
	}, nil
}

// pageResponseFromProto converts a proto PageResponse message back to the core
// type. It is the exact inverse of pageResponseToProto: a nil message yields a
// nil core page, and a non-nil message (even when every field is zero) yields a
// non-nil core page, so the present-but-empty end-of-results marker survives
// the round-trip rather than collapsing to an absent page.
func pageResponseFromProto(p *authzenv1.PageResponse) *authzen.PageResponse {
	if p == nil {
		return nil
	}
	return &authzen.PageResponse{
		NextToken:  p.GetNextToken(),
		Count:      int(p.GetCount()),
		Total:      int(p.GetTotal()),
		Properties: structToMap(p.GetProperties()),
	}
}

// --- Search (Section 8) ---

// subjectSearchRequestToProto converts a core SubjectSearchRequest
// (Section 8.4) to its proto form.
func subjectSearchRequestToProto(r authzen.SubjectSearchRequest) (*authzenv1.SearchSubjectsRequest, error) {
	subject, err := subjectToProto(r.Subject)
	if err != nil {
		return nil, err
	}
	action, err := actionToProto(r.Action)
	if err != nil {
		return nil, err
	}
	resource, err := resourceToProto(r.Resource)
	if err != nil {
		return nil, err
	}
	ctx, err := mapToStruct(r.Context)
	if err != nil {
		return nil, err
	}
	size, token, pageProps, err := pageToProto(r.Page)
	if err != nil {
		return nil, err
	}
	return &authzenv1.SearchSubjectsRequest{
		Subject:        subject,
		Action:         action,
		Resource:       resource,
		Context:        ctx,
		PageSize:       size,
		PageToken:      token,
		PageProperties: pageProps,
	}, nil
}

// subjectSearchRequestFromProto converts a proto SearchSubjectsRequest
// (Section 8.4) to its core form.
func subjectSearchRequestFromProto(r *authzenv1.SearchSubjectsRequest) authzen.SubjectSearchRequest {
	if r == nil {
		return authzen.SubjectSearchRequest{}
	}
	return authzen.SubjectSearchRequest{
		Subject:  subjectFromProto(r.GetSubject()),
		Action:   actionFromProto(r.GetAction()),
		Resource: resourceFromProto(r.GetResource()),
		Context:  structToMap(r.GetContext()),
		Page:     pageFromProto(r.GetPageSize(), r.GetPageToken(), r.GetPageProperties()),
	}
}

// subjectSearchResponseToProto converts a core SubjectSearchResponse
// (Sections 8.3/8.4) to its proto form.
func subjectSearchResponseToProto(r authzen.SubjectSearchResponse) (*authzenv1.SearchSubjectsResponse, error) {
	results := make([]*authzenv1.Subject, len(r.Results))
	for i := range r.Results {
		s := r.Results[i]
		m, err := subjectToProto(&s)
		if err != nil {
			return nil, err
		}
		results[i] = m
	}
	page, err := pageResponseToProto(r.Page)
	if err != nil {
		return nil, err
	}
	ctx, err := mapToStruct(r.Context)
	if err != nil {
		return nil, err
	}
	return &authzenv1.SearchSubjectsResponse{
		Results: results,
		Page:    page,
		Context: ctx,
	}, nil
}

// subjectSearchResponseFromProto converts a proto SearchSubjectsResponse
// (Sections 8.3/8.4) to its core form.
func subjectSearchResponseFromProto(r *authzenv1.SearchSubjectsResponse) authzen.SubjectSearchResponse {
	if r == nil {
		return authzen.SubjectSearchResponse{}
	}
	results := make([]authzen.Subject, len(r.GetResults()))
	for i, s := range r.GetResults() {
		results[i] = *subjectFromProto(s)
	}
	return authzen.SubjectSearchResponse{
		Page:    pageResponseFromProto(r.GetPage()),
		Results: results,
		Context: structToMap(r.GetContext()),
	}
}

// resourceSearchRequestToProto converts a core ResourceSearchRequest
// (Section 8.5) to its proto form.
func resourceSearchRequestToProto(r authzen.ResourceSearchRequest) (*authzenv1.SearchResourcesRequest, error) {
	subject, err := subjectToProto(r.Subject)
	if err != nil {
		return nil, err
	}
	action, err := actionToProto(r.Action)
	if err != nil {
		return nil, err
	}
	resource, err := resourceToProto(r.Resource)
	if err != nil {
		return nil, err
	}
	ctx, err := mapToStruct(r.Context)
	if err != nil {
		return nil, err
	}
	size, token, pageProps, err := pageToProto(r.Page)
	if err != nil {
		return nil, err
	}
	return &authzenv1.SearchResourcesRequest{
		Subject:        subject,
		Action:         action,
		Resource:       resource,
		Context:        ctx,
		PageSize:       size,
		PageToken:      token,
		PageProperties: pageProps,
	}, nil
}

// resourceSearchRequestFromProto converts a proto SearchResourcesRequest
// (Section 8.5) to its core form.
func resourceSearchRequestFromProto(r *authzenv1.SearchResourcesRequest) authzen.ResourceSearchRequest {
	if r == nil {
		return authzen.ResourceSearchRequest{}
	}
	return authzen.ResourceSearchRequest{
		Subject:  subjectFromProto(r.GetSubject()),
		Action:   actionFromProto(r.GetAction()),
		Resource: resourceFromProto(r.GetResource()),
		Context:  structToMap(r.GetContext()),
		Page:     pageFromProto(r.GetPageSize(), r.GetPageToken(), r.GetPageProperties()),
	}
}

// resourceSearchResponseToProto converts a core ResourceSearchResponse
// (Sections 8.3/8.5) to its proto form.
func resourceSearchResponseToProto(r authzen.ResourceSearchResponse) (*authzenv1.SearchResourcesResponse, error) {
	results := make([]*authzenv1.Resource, len(r.Results))
	for i := range r.Results {
		res := r.Results[i]
		m, err := resourceToProto(&res)
		if err != nil {
			return nil, err
		}
		results[i] = m
	}
	page, err := pageResponseToProto(r.Page)
	if err != nil {
		return nil, err
	}
	ctx, err := mapToStruct(r.Context)
	if err != nil {
		return nil, err
	}
	return &authzenv1.SearchResourcesResponse{
		Results: results,
		Page:    page,
		Context: ctx,
	}, nil
}

// resourceSearchResponseFromProto converts a proto SearchResourcesResponse
// (Sections 8.3/8.5) to its core form.
func resourceSearchResponseFromProto(r *authzenv1.SearchResourcesResponse) authzen.ResourceSearchResponse {
	if r == nil {
		return authzen.ResourceSearchResponse{}
	}
	results := make([]authzen.Resource, len(r.GetResults()))
	for i, res := range r.GetResults() {
		results[i] = *resourceFromProto(res)
	}
	return authzen.ResourceSearchResponse{
		Page:    pageResponseFromProto(r.GetPage()),
		Results: results,
		Context: structToMap(r.GetContext()),
	}
}

// actionSearchRequestToProto converts a core ActionSearchRequest (Section 8.6)
// to its proto form. There is deliberately no action field.
func actionSearchRequestToProto(r authzen.ActionSearchRequest) (*authzenv1.SearchActionsRequest, error) {
	subject, err := subjectToProto(r.Subject)
	if err != nil {
		return nil, err
	}
	resource, err := resourceToProto(r.Resource)
	if err != nil {
		return nil, err
	}
	ctx, err := mapToStruct(r.Context)
	if err != nil {
		return nil, err
	}
	size, token, pageProps, err := pageToProto(r.Page)
	if err != nil {
		return nil, err
	}
	return &authzenv1.SearchActionsRequest{
		Subject:        subject,
		Resource:       resource,
		Context:        ctx,
		PageSize:       size,
		PageToken:      token,
		PageProperties: pageProps,
	}, nil
}

// actionSearchRequestFromProto converts a proto SearchActionsRequest
// (Section 8.6) to its core form.
func actionSearchRequestFromProto(r *authzenv1.SearchActionsRequest) authzen.ActionSearchRequest {
	if r == nil {
		return authzen.ActionSearchRequest{}
	}
	return authzen.ActionSearchRequest{
		Subject:  subjectFromProto(r.GetSubject()),
		Resource: resourceFromProto(r.GetResource()),
		Context:  structToMap(r.GetContext()),
		Page:     pageFromProto(r.GetPageSize(), r.GetPageToken(), r.GetPageProperties()),
	}
}

// actionSearchResponseToProto converts a core ActionSearchResponse
// (Sections 8.3/8.6) to its proto form.
func actionSearchResponseToProto(r authzen.ActionSearchResponse) (*authzenv1.SearchActionsResponse, error) {
	results := make([]*authzenv1.Action, len(r.Results))
	for i := range r.Results {
		a := r.Results[i]
		m, err := actionToProto(&a)
		if err != nil {
			return nil, err
		}
		results[i] = m
	}
	page, err := pageResponseToProto(r.Page)
	if err != nil {
		return nil, err
	}
	ctx, err := mapToStruct(r.Context)
	if err != nil {
		return nil, err
	}
	return &authzenv1.SearchActionsResponse{
		Results: results,
		Page:    page,
		Context: ctx,
	}, nil
}

// actionSearchResponseFromProto converts a proto SearchActionsResponse
// (Sections 8.3/8.6) to its core form.
func actionSearchResponseFromProto(r *authzenv1.SearchActionsResponse) authzen.ActionSearchResponse {
	if r == nil {
		return authzen.ActionSearchResponse{}
	}
	results := make([]authzen.Action, len(r.GetResults()))
	for i, a := range r.GetResults() {
		results[i] = *actionFromProto(a)
	}
	return authzen.ActionSearchResponse{
		Page:    pageResponseFromProto(r.GetPage()),
		Results: results,
		Context: structToMap(r.GetContext()),
	}
}

// --- Metadata (Section 9) ---

// metadataToProto converts a core Metadata document (Section 9.1) to its proto
// Configuration form.
func metadataToProto(m authzen.Metadata) *authzenv1.Configuration {
	return &authzenv1.Configuration{
		PolicyDecisionPoint:       m.PolicyDecisionPoint,
		AccessEvaluationEndpoint:  m.AccessEvaluationEndpoint,
		AccessEvaluationsEndpoint: m.AccessEvaluationsEndpoint,
		SearchSubjectEndpoint:     m.SearchSubjectEndpoint,
		SearchResourceEndpoint:    m.SearchResourceEndpoint,
		SearchActionEndpoint:      m.SearchActionEndpoint,
		Capabilities:              m.Capabilities,
		SignedMetadata:            m.SignedMetadata,
	}
}

// metadataFromProto converts a proto Configuration (Section 9.1) to its core
// Metadata form.
func metadataFromProto(c *authzenv1.Configuration) authzen.Metadata {
	if c == nil {
		return authzen.Metadata{}
	}
	return authzen.Metadata{
		PolicyDecisionPoint:       c.GetPolicyDecisionPoint(),
		AccessEvaluationEndpoint:  c.GetAccessEvaluationEndpoint(),
		AccessEvaluationsEndpoint: c.GetAccessEvaluationsEndpoint(),
		SearchSubjectEndpoint:     c.GetSearchSubjectEndpoint(),
		SearchResourceEndpoint:    c.GetSearchResourceEndpoint(),
		SearchActionEndpoint:      c.GetSearchActionEndpoint(),
		Capabilities:              c.GetCapabilities(),
		SignedMetadata:            c.GetSignedMetadata(),
	}
}
