package authzengrpc

import (
	"context"
	"errors"
	"net"
	"testing"

	authzen "github.com/SCKelemen/authzen"
	authzenv1 "github.com/SCKelemen/authzen/grpc/gen/authzen/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

// These tests stand up the Server over an in-memory bufconn connection (no real
// network) and drive it through both the ergonomic Client wrapper and the raw
// generated client, covering positive paths, batch semantics, search, metadata,
// and the negative path (missing required field -> codes.InvalidArgument, the
// gRPC analogue of the spec's mandatory HTTP 400).
//
// OpenID AuthZEN Authorization API 1.0.
// https://openid.net/specs/authorization-api-1_0.html

// fakePDP is a configurable in-memory PDP for tests.
type fakePDP struct {
	// decide reports whether a (resolved) evaluation is permitted.
	decide func(authzen.EvaluationRequest) bool
	// search results returned verbatim.
	subjects  []authzen.Subject
	resources []authzen.Resource
	actions   []authzen.Action
	meta      authzen.Metadata
	// err, when non-nil, is returned by every method (to test error mapping).
	err error
}

func (f *fakePDP) Evaluate(_ context.Context, req authzen.EvaluationRequest) (authzen.EvaluationResponse, error) {
	if f.err != nil {
		return authzen.EvaluationResponse{}, f.err
	}
	return authzen.EvaluationResponse{Decision: f.decide(req)}, nil
}

// EvaluateBatch resolves the defaults and applies the evaluations_semantic
// short-circuit rules (Section 7.1.2.1).
func (f *fakePDP) EvaluateBatch(_ context.Context, req authzen.EvaluationsRequest) (authzen.EvaluationsResponse, error) {
	if f.err != nil {
		return authzen.EvaluationsResponse{}, f.err
	}
	semantic := authzen.SemanticExecuteAll
	if req.Options != nil && req.Options.EvaluationsSemantic != "" {
		semantic = req.Options.EvaluationsSemantic
	}
	var out []authzen.EvaluationResponse
	for _, e := range req.Resolved() {
		d := f.decide(e)
		out = append(out, authzen.EvaluationResponse{Decision: d})
		if semantic == authzen.SemanticDenyOnFirstDeny && !d {
			break
		}
		if semantic == authzen.SemanticPermitOnFirstPermit && d {
			break
		}
	}
	return authzen.EvaluationsResponse{Evaluations: out}, nil
}

func (f *fakePDP) SearchSubjects(_ context.Context, _ authzen.SubjectSearchRequest) (authzen.SubjectSearchResponse, error) {
	if f.err != nil {
		return authzen.SubjectSearchResponse{}, f.err
	}
	return authzen.SubjectSearchResponse{
		Page:    &authzen.PageResponse{NextToken: "", Count: len(f.subjects), Total: len(f.subjects)},
		Results: f.subjects,
	}, nil
}

func (f *fakePDP) SearchResources(_ context.Context, _ authzen.ResourceSearchRequest) (authzen.ResourceSearchResponse, error) {
	if f.err != nil {
		return authzen.ResourceSearchResponse{}, f.err
	}
	return authzen.ResourceSearchResponse{Results: f.resources}, nil
}

func (f *fakePDP) SearchActions(_ context.Context, _ authzen.ActionSearchRequest) (authzen.ActionSearchResponse, error) {
	if f.err != nil {
		return authzen.ActionSearchResponse{}, f.err
	}
	return authzen.ActionSearchResponse{Results: f.actions}, nil
}

func (f *fakePDP) Configuration(_ context.Context) (authzen.Metadata, error) {
	if f.err != nil {
		return authzen.Metadata{}, f.err
	}
	return f.meta, nil
}

// newTestRig wires fakePDP <-> Server <-> bufconn <-> Client and returns the
// ergonomic Client plus the raw generated client. Cleanup is registered with
// t.Cleanup.
func newTestRig(t *testing.T, pdp PDP) (*Client, authzenv1.AccessServiceClient) {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	srv := grpc.NewServer()
	NewServer(pdp).Register(srv)
	go func() {
		if err := srv.Serve(lis); err != nil {
			// Serve returns ErrServerStopped on graceful stop.
			t.Logf("server stopped: %v", err)
		}
	}()

	conn, err := grpc.NewClient(
		"passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("grpc.NewClient: %v", err)
	}
	t.Cleanup(func() {
		_ = conn.Close()
		srv.Stop()
		_ = lis.Close()
	})
	return NewClient(conn), authzenv1.NewAccessServiceClient(conn)
}

// permitReads permits can_read and denies everything else.
func permitReads(req authzen.EvaluationRequest) bool {
	return req.Action != nil && req.Action.Name == "can_read"
}

func TestEvaluatePermit(t *testing.T) {
	client, _ := newTestRig(t, &fakePDP{decide: permitReads})
	resp, err := client.Evaluate(context.Background(), authzen.EvaluationRequest{
		Subject:  &authzen.Subject{Type: "user", ID: "alice@example.com"},
		Action:   &authzen.Action{Name: "can_read"},
		Resource: &authzen.Resource{Type: "todo", ID: "1"},
	})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if !resp.Decision {
		t.Fatal("expected decision=true for can_read")
	}
}

func TestEvaluateDenyIsSuccess(t *testing.T) {
	// A deny is a successful response (decision=false), never an error code
	// (Section 10.1.2).
	client, _ := newTestRig(t, &fakePDP{decide: permitReads})
	resp, err := client.Evaluate(context.Background(), authzen.EvaluationRequest{
		Subject:  &authzen.Subject{Type: "user", ID: "alice@example.com"},
		Action:   &authzen.Action{Name: "can_write"},
		Resource: &authzen.Resource{Type: "todo", ID: "1"},
	})
	if err != nil {
		t.Fatalf("Evaluate (deny) should not error: %v", err)
	}
	if resp.Decision {
		t.Fatal("expected decision=false for can_write")
	}
}

func TestEvaluateMissingRequiredFieldInvalidArgument(t *testing.T) {
	// Missing required attribute MUST be rejected; gRPC maps this to
	// codes.InvalidArgument (HTTP 400 in the JSON binding).
	_, raw := newTestRig(t, &fakePDP{decide: permitReads})
	cases := map[string]*authzenv1.EvaluateRequest{
		"missing subject": {
			Action:   &authzenv1.Action{Name: "can_read"},
			Resource: &authzenv1.Resource{Type: "todo", Id: "1"},
		},
		"missing action": {
			Subject:  &authzenv1.Subject{Type: "user", Id: "alice@example.com"},
			Resource: &authzenv1.Resource{Type: "todo", Id: "1"},
		},
		"missing resource": {
			Subject: &authzenv1.Subject{Type: "user", Id: "alice@example.com"},
			Action:  &authzenv1.Action{Name: "can_read"},
		},
		"missing subject.id": {
			Subject:  &authzenv1.Subject{Type: "user"},
			Action:   &authzenv1.Action{Name: "can_read"},
			Resource: &authzenv1.Resource{Type: "todo", Id: "1"},
		},
	}
	for name, req := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := raw.Evaluate(context.Background(), req)
			if status.Code(err) != codes.InvalidArgument {
				t.Fatalf("got code %v (err=%v); want InvalidArgument", status.Code(err), err)
			}
		})
	}
}

func TestEvaluateBatchExecuteAll(t *testing.T) {
	// Spec execute_all example: all three returned (true, false, true).
	client, _ := newTestRig(t, &fakePDP{decide: func(req authzen.EvaluationRequest) bool {
		return req.Resource != nil && req.Resource.ID != "2"
	}})
	resp, err := client.EvaluateBatch(context.Background(), authzen.EvaluationsRequest{
		Subject: &authzen.Subject{Type: "user", ID: "alice@example.com"},
		Action:  &authzen.Action{Name: "read"},
		Options: &authzen.Options{EvaluationsSemantic: authzen.SemanticExecuteAll},
		Evaluations: []authzen.EvaluationRequest{
			{Resource: &authzen.Resource{Type: "document", ID: "1"}},
			{Resource: &authzen.Resource{Type: "document", ID: "2"}},
			{Resource: &authzen.Resource{Type: "document", ID: "3"}},
		},
	})
	if err != nil {
		t.Fatalf("EvaluateBatch: %v", err)
	}
	want := []bool{true, false, true}
	if len(resp.Evaluations) != len(want) {
		t.Fatalf("got %d decisions; want %d", len(resp.Evaluations), len(want))
	}
	for i, w := range want {
		if resp.Evaluations[i].Decision != w {
			t.Errorf("decision[%d] = %v; want %v", i, resp.Evaluations[i].Decision, w)
		}
	}
}

func TestEvaluateBatchDenyOnFirstDeny(t *testing.T) {
	// Spec deny_on_first_deny example: short-circuits at #2 -> [true, false].
	client, _ := newTestRig(t, &fakePDP{decide: func(req authzen.EvaluationRequest) bool {
		return req.Resource != nil && req.Resource.ID != "2"
	}})
	resp, err := client.EvaluateBatch(context.Background(), authzen.EvaluationsRequest{
		Subject: &authzen.Subject{Type: "user", ID: "alice@example.com"},
		Action:  &authzen.Action{Name: "read"},
		Options: &authzen.Options{EvaluationsSemantic: authzen.SemanticDenyOnFirstDeny},
		Evaluations: []authzen.EvaluationRequest{
			{Resource: &authzen.Resource{Type: "document", ID: "1"}},
			{Resource: &authzen.Resource{Type: "document", ID: "2"}},
			{Resource: &authzen.Resource{Type: "document", ID: "3"}},
		},
	})
	if err != nil {
		t.Fatalf("EvaluateBatch: %v", err)
	}
	if len(resp.Evaluations) != 2 {
		t.Fatalf("got %d decisions; want 2 (short-circuit)", len(resp.Evaluations))
	}
	if !resp.Evaluations[0].Decision || resp.Evaluations[1].Decision {
		t.Fatalf("want [true, false]; got %+v", resp.Evaluations)
	}
}

func TestEvaluateBatchPermitOnFirstPermit(t *testing.T) {
	// Spec permit_on_first_permit example: short-circuits at #1 -> [true].
	client, _ := newTestRig(t, &fakePDP{decide: func(authzen.EvaluationRequest) bool { return true }})
	resp, err := client.EvaluateBatch(context.Background(), authzen.EvaluationsRequest{
		Subject: &authzen.Subject{Type: "user", ID: "alice@example.com"},
		Action:  &authzen.Action{Name: "read"},
		Options: &authzen.Options{EvaluationsSemantic: authzen.SemanticPermitOnFirstPermit},
		Evaluations: []authzen.EvaluationRequest{
			{Resource: &authzen.Resource{Type: "document", ID: "1"}},
			{Resource: &authzen.Resource{Type: "document", ID: "2"}},
			{Resource: &authzen.Resource{Type: "document", ID: "3"}},
		},
	})
	if err != nil {
		t.Fatalf("EvaluateBatch: %v", err)
	}
	if len(resp.Evaluations) != 1 || !resp.Evaluations[0].Decision {
		t.Fatalf("want [true]; got %+v", resp.Evaluations)
	}
}

func TestEvaluateBatchDefaultingFillsMembers(t *testing.T) {
	// Top-level subject/action are defaults; members supply only the resource.
	// The PDP sees fully resolved members (Section 7.1.1). The fake decides
	// based on the resolved action name.
	client, _ := newTestRig(t, &fakePDP{decide: permitReads})
	resp, err := client.EvaluateBatch(context.Background(), authzen.EvaluationsRequest{
		Subject: &authzen.Subject{Type: "user", ID: "alice@example.com"},
		Action:  &authzen.Action{Name: "can_read"},
		Evaluations: []authzen.EvaluationRequest{
			{Resource: &authzen.Resource{Type: "document", ID: "boxcarring.md"}},
			{
				Action:   &authzen.Action{Name: "can_edit"}, // overrides default
				Resource: &authzen.Resource{Type: "document", ID: "resource-search.md"},
			},
		},
	})
	if err != nil {
		t.Fatalf("EvaluateBatch: %v", err)
	}
	// First inherits can_read (permit); second overrides to can_edit (deny).
	if want := []bool{true, false}; len(resp.Evaluations) != 2 ||
		resp.Evaluations[0].Decision != want[0] || resp.Evaluations[1].Decision != want[1] {
		t.Fatalf("want %v; got %+v", []bool{true, false}, resp.Evaluations)
	}
}

func TestEvaluateBatchMissingFieldInvalidArgument(t *testing.T) {
	// A member missing the resource, with no top-level default to fill it, is
	// invalid even after defaulting (Section 7.1.1) -> InvalidArgument.
	_, raw := newTestRig(t, &fakePDP{decide: permitReads})
	_, err := raw.EvaluateBatch(context.Background(), &authzenv1.EvaluateBatchRequest{
		Subject: &authzenv1.Subject{Type: "user", Id: "alice@example.com"},
		Action:  &authzenv1.Action{Name: "can_read"},
		Evaluations: []*authzenv1.EvaluateRequest{
			{}, // no resource, no default -> invalid
		},
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("got code %v (err=%v); want InvalidArgument", status.Code(err), err)
	}
}

func TestSearchSubjects(t *testing.T) {
	want := []authzen.Subject{
		{Type: "user", ID: "alice@example.com"},
		{Type: "user", ID: "bob@example.com"},
	}
	client, _ := newTestRig(t, &fakePDP{subjects: want})
	resp, err := client.SearchSubjects(context.Background(), authzen.SubjectSearchRequest{
		Subject:  &authzen.Subject{Type: "user"},
		Action:   &authzen.Action{Name: "can_read"},
		Resource: &authzen.Resource{Type: "account", ID: "123"},
	})
	if err != nil {
		t.Fatalf("SearchSubjects: %v", err)
	}
	if len(resp.Results) != 2 || resp.Results[0].ID != "alice@example.com" {
		t.Fatalf("unexpected results: %+v", resp.Results)
	}
	if resp.Page == nil || resp.Page.NextToken != "" {
		t.Fatalf("expected end-of-results page with empty next_token; got %+v", resp.Page)
	}
}

func TestSearchSubjectsMissingActionInvalidArgument(t *testing.T) {
	// Subject Search requires subject(type), action, resource (Section 8.4).
	_, raw := newTestRig(t, &fakePDP{})
	_, err := raw.SearchSubjects(context.Background(), &authzenv1.SearchSubjectsRequest{
		Subject:  &authzenv1.Subject{Type: "user"},
		Resource: &authzenv1.Resource{Type: "account", Id: "123"},
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("got code %v; want InvalidArgument", status.Code(err))
	}
}

func TestSearchActions(t *testing.T) {
	want := []authzen.Action{{Name: "can_read"}, {Name: "can_write"}}
	client, _ := newTestRig(t, &fakePDP{actions: want})
	resp, err := client.SearchActions(context.Background(), authzen.ActionSearchRequest{
		Subject:  &authzen.Subject{Type: "user", ID: "alice@example.com"},
		Resource: &authzen.Resource{Type: "account", ID: "123"},
	})
	if err != nil {
		t.Fatalf("SearchActions: %v", err)
	}
	if len(resp.Results) != 2 || resp.Results[1].Name != "can_write" {
		t.Fatalf("unexpected results: %+v", resp.Results)
	}
}

func TestSearchResources(t *testing.T) {
	// Resource Search returns the resources the subject may act on (Section 8.5).
	want := []authzen.Resource{
		{Type: "document", ID: "boxcarring.md"},
		{Type: "document", ID: "resource-search.md"},
	}
	client, _ := newTestRig(t, &fakePDP{resources: want})
	resp, err := client.SearchResources(context.Background(), authzen.ResourceSearchRequest{
		Subject:  &authzen.Subject{Type: "user", ID: "alice@example.com"},
		Action:   &authzen.Action{Name: "can_read"},
		Resource: &authzen.Resource{Type: "document"},
	})
	if err != nil {
		t.Fatalf("SearchResources: %v", err)
	}
	if len(resp.Results) != 2 || resp.Results[1].ID != "resource-search.md" {
		t.Fatalf("unexpected results: %+v", resp.Results)
	}
}

func TestSearchResourcesMissingActionInvalidArgument(t *testing.T) {
	// Resource Search requires subject, action, and resource(type)
	// (Section 8.5); a missing action MUST be rejected -> InvalidArgument.
	_, raw := newTestRig(t, &fakePDP{})
	_, err := raw.SearchResources(context.Background(), &authzenv1.SearchResourcesRequest{
		Subject:  &authzenv1.Subject{Type: "user", Id: "alice@example.com"},
		Resource: &authzenv1.Resource{Type: "document"},
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("got code %v; want InvalidArgument", status.Code(err))
	}
}

func TestGetConfiguration(t *testing.T) {
	meta := authzen.Metadata{
		PolicyDecisionPoint:      "https://pdp.example.com",
		AccessEvaluationEndpoint: "https://pdp.example.com" + authzen.DefaultEvaluationPath,
		SearchSubjectEndpoint:    "https://pdp.example.com" + authzen.DefaultSearchSubjectPath,
	}
	client, _ := newTestRig(t, &fakePDP{meta: meta})
	got, err := client.GetConfiguration(context.Background())
	if err != nil {
		t.Fatalf("GetConfiguration: %v", err)
	}
	if got.PolicyDecisionPoint != meta.PolicyDecisionPoint ||
		got.AccessEvaluationEndpoint != meta.AccessEvaluationEndpoint ||
		got.SearchSubjectEndpoint != meta.SearchSubjectEndpoint {
		t.Fatalf("metadata mismatch: got %+v", got)
	}
}

func TestPDPErrorMapsToInternal(t *testing.T) {
	// A plain (non-status) PDP error becomes codes.Internal (HTTP 500).
	_, raw := newTestRig(t, &fakePDP{err: errors.New("boom")})
	_, err := raw.Evaluate(context.Background(), &authzenv1.EvaluateRequest{
		Subject:  &authzenv1.Subject{Type: "user", Id: "alice@example.com"},
		Action:   &authzenv1.Action{Name: "can_read"},
		Resource: &authzenv1.Resource{Type: "todo", Id: "1"},
	})
	if status.Code(err) != codes.Internal {
		t.Fatalf("got code %v; want Internal", status.Code(err))
	}
}

func TestPDPStatusErrorPassesThrough(t *testing.T) {
	// A status error chosen by the PDP is preserved end-to-end.
	want := status.Error(codes.PermissionDenied, "forbidden")
	_, raw := newTestRig(t, &fakePDP{err: want})
	_, err := raw.Evaluate(context.Background(), &authzenv1.EvaluateRequest{
		Subject:  &authzenv1.Subject{Type: "user", Id: "alice@example.com"},
		Action:   &authzenv1.Action{Name: "can_read"},
		Resource: &authzenv1.Resource{Type: "todo", Id: "1"},
	})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("got code %v; want PermissionDenied", status.Code(err))
	}
}
