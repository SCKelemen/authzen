package authzengrpc

import (
	"context"
	"math"
	"reflect"
	"testing"

	authzen "github.com/SCKelemen/authzen"
	authzenv1 "github.com/SCKelemen/authzen/grpc/gen/authzen/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// These tests cover the gRPC-binding reviewer findings. They sit alongside the
// existing round-trip and rig tests (conv_test.go, server_test.go) and reuse
// the in-memory bufconn rig (newTestRig / fakePDP / permitReads) and the
// badMap helper.
//
// OpenID AuthZEN Authorization API 1.0.
// https://openid.net/specs/authorization-api-1_0.html

// --- Finding 1: mapToStruct rejects ordinary Go values ---

// TestMapToStructJSONNormalizesOrdinaryGoValues proves that values the HTTP
// binding handles transparently -- []string (group memberships),
// map[string]string, and nested structs -- now survive the structpb conversion
// after JSON normalization, instead of being rejected by structpb.NewStruct.
func TestMapToStructJSONNormalizesOrdinaryGoValues(t *testing.T) {
	m := map[string]any{
		"groups": []string{"admins", "users"},
		"labels": map[string]string{"team": "security"},
		"nested": struct {
			A string `json:"a"`
			N int    `json:"n"`
		}{A: "x", N: 3},
	}
	s, err := mapToStruct(m)
	if err != nil {
		t.Fatalf("mapToStruct: %v", err)
	}
	got := structToMap(s)
	want := map[string]any{
		"groups": []any{"admins", "users"},
		"labels": map[string]any{"team": "security"},
		"nested": map[string]any{"a": "x", "n": float64(3)},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("normalization mismatch:\n got %#v\n want %#v", got, want)
	}
}

// TestMapToStructEvaluationError covers the special-cased library type, both by
// value and by pointer (Section 7.2.1). Its int Status becomes a JSON number
// (float64) on the wire, like every other number in a Struct.
func TestMapToStructEvaluationError(t *testing.T) {
	wantInner := map[string]any{"status": float64(404), "message": "not found"}

	byValue, err := mapToStruct(map[string]any{"error": authzen.EvaluationError{Status: 404, Message: "not found"}})
	if err != nil {
		t.Fatalf("mapToStruct (value): %v", err)
	}
	if got := structToMap(byValue)["error"]; !reflect.DeepEqual(got, wantInner) {
		t.Fatalf("EvaluationError (value) = %#v; want %#v", got, wantInner)
	}

	byPtr, err := mapToStruct(map[string]any{"error": &authzen.EvaluationError{Status: 404, Message: "not found"}})
	if err != nil {
		t.Fatalf("mapToStruct (pointer): %v", err)
	}
	if got := structToMap(byPtr)["error"]; !reflect.DeepEqual(got, wantInner) {
		t.Fatalf("EvaluationError (pointer) = %#v; want %#v", got, wantInner)
	}
}

// TestEvaluateWithComplexPropertiesOverGRPC is the end-to-end parity check: an
// evaluation whose subject carries []string and map[string]string properties
// (rejected by the old structpb path) now completes over gRPC exactly as it
// would over HTTP.
func TestEvaluateWithComplexPropertiesOverGRPC(t *testing.T) {
	client, _ := newTestRig(t, &fakePDP{decide: permitReads})
	resp, err := client.Evaluate(context.Background(), authzen.EvaluationRequest{
		Subject: &authzen.Subject{Type: "user", ID: "alice@example.com", Properties: map[string]any{
			"groups": []string{"admins", "users"},
			"attrs":  map[string]string{"dept": "security"},
		}},
		Action:   &authzen.Action{Name: "can_read"},
		Resource: &authzen.Resource{Type: "todo", ID: "1"},
	})
	if err != nil {
		t.Fatalf("Evaluate with complex properties: %v", err)
	}
	if !resp.Decision {
		t.Fatal("expected decision=true for can_read")
	}
}

// --- Finding 2: invalid evaluations_semantic must be rejected, not downgraded ---

// TestEvaluateBatchInvalidSemanticRejectedByClient verifies that an invalid
// options.evaluations_semantic is rejected by the client as InvalidArgument
// instead of being silently collapsed to UNSPECIFIED (execute_all) by the lossy
// semanticToProto mapping (Section 7.1.2.1). All other required fields are
// valid so the semantic is the only possible cause of failure.
func TestEvaluateBatchInvalidSemanticRejectedByClient(t *testing.T) {
	client, _ := newTestRig(t, &fakePDP{decide: permitReads})
	_, err := client.EvaluateBatch(context.Background(), authzen.EvaluationsRequest{
		Subject:  &authzen.Subject{Type: "user", ID: "alice@example.com"},
		Action:   &authzen.Action{Name: "can_read"},
		Resource: &authzen.Resource{Type: "todo", ID: "1"},
		Options:  &authzen.Options{EvaluationsSemantic: authzen.EvaluationsSemantic("bogus")},
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("got code %v (err=%v); want InvalidArgument", status.Code(err), err)
	}
}

// --- Finding 3: gRPC search must strip the searched id (Sections 8.4/8.5) ---

// idRecordingPDP records the searched-entity ids it receives so a test can
// assert the server stripped them before delegating, mirroring the HTTP binding.
type idRecordingPDP struct {
	*fakePDP
	gotSubjectID  string
	gotResourceID string
}

func (p *idRecordingPDP) SearchSubjects(ctx context.Context, req authzen.SubjectSearchRequest) (authzen.SubjectSearchResponse, error) {
	if req.Subject != nil {
		p.gotSubjectID = req.Subject.ID
	}
	return p.fakePDP.SearchSubjects(ctx, req)
}

func (p *idRecordingPDP) SearchResources(ctx context.Context, req authzen.ResourceSearchRequest) (authzen.ResourceSearchResponse, error) {
	if req.Resource != nil {
		p.gotResourceID = req.Resource.ID
	}
	return p.fakePDP.SearchResources(ctx, req)
}

func TestSearchSubjectsStripsID(t *testing.T) {
	rec := &idRecordingPDP{fakePDP: &fakePDP{}}
	client, _ := newTestRig(t, rec)
	if _, err := client.SearchSubjects(context.Background(), authzen.SubjectSearchRequest{
		Subject:  &authzen.Subject{Type: "user", ID: "should-be-ignored"},
		Action:   &authzen.Action{Name: "can_read"},
		Resource: &authzen.Resource{Type: "account", ID: "123"},
	}); err != nil {
		t.Fatalf("SearchSubjects: %v", err)
	}
	if rec.gotSubjectID != "" {
		t.Fatalf("PDP received subject id %q; want it stripped to empty (Section 8.4)", rec.gotSubjectID)
	}
}

func TestSearchResourcesStripsID(t *testing.T) {
	rec := &idRecordingPDP{fakePDP: &fakePDP{}}
	client, _ := newTestRig(t, rec)
	if _, err := client.SearchResources(context.Background(), authzen.ResourceSearchRequest{
		Subject:  &authzen.Subject{Type: "user", ID: "alice@example.com"},
		Action:   &authzen.Action{Name: "can_read"},
		Resource: &authzen.Resource{Type: "document", ID: "should-be-ignored"},
	}); err != nil {
		t.Fatalf("SearchResources: %v", err)
	}
	if rec.gotResourceID != "" {
		t.Fatalf("PDP received resource id %q; want it stripped to empty (Section 8.5)", rec.gotResourceID)
	}
}

// --- Finding 4: client must validate and wrap conversion errors ---

// TestClientEvaluateValidationInvalidArgument verifies the client rejects a
// request missing a required attribute as InvalidArgument before any RPC.
func TestClientEvaluateValidationInvalidArgument(t *testing.T) {
	client, _ := newTestRig(t, &fakePDP{decide: permitReads})
	_, err := client.Evaluate(context.Background(), authzen.EvaluationRequest{
		Subject:  &authzen.Subject{Type: "user", ID: "alice@example.com"},
		Resource: &authzen.Resource{Type: "todo", ID: "1"}, // missing action
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("got code %v (err=%v); want InvalidArgument", status.Code(err), err)
	}
}

// TestClientConversionErrorMapsToInternal verifies that a request that passes
// validation but fails proto conversion (an unconvertible property) surfaces as
// codes.Internal via pdpError, not the bare codes.Unknown an unwrapped error
// would produce.
func TestClientConversionErrorMapsToInternal(t *testing.T) {
	client, _ := newTestRig(t, &fakePDP{decide: permitReads})
	_, err := client.Evaluate(context.Background(), authzen.EvaluationRequest{
		Subject:  &authzen.Subject{Type: "user", ID: "alice@example.com", Properties: badMap()},
		Action:   &authzen.Action{Name: "can_read"},
		Resource: &authzen.Resource{Type: "todo", ID: "1"},
	})
	if status.Code(err) != codes.Internal {
		t.Fatalf("got code %v (err=%v); want Internal", status.Code(err), err)
	}
}

// --- Finding 5: nil-deref guard in search-response conversions ---

// TestSearchResponseFromProtoNilResultElements asserts the *SearchResponseFrom
// Proto conversions tolerate a nil/empty response and nil elements in the
// repeated results field (which convert to nil *Subject/*Resource/*Action)
// without panicking.
func TestSearchResponseFromProtoNilResultElements(t *testing.T) {
	subs := subjectSearchResponseFromProto(&authzenv1.SearchSubjectsResponse{
		Results: []*authzenv1.Subject{nil},
	})
	if len(subs.Results) != 1 || !reflect.DeepEqual(subs.Results[0], authzen.Subject{}) {
		t.Fatalf("subjects: got %#v; want one zero-value Subject", subs.Results)
	}

	ress := resourceSearchResponseFromProto(&authzenv1.SearchResourcesResponse{
		Results: []*authzenv1.Resource{nil},
	})
	if len(ress.Results) != 1 || !reflect.DeepEqual(ress.Results[0], authzen.Resource{}) {
		t.Fatalf("resources: got %#v; want one zero-value Resource", ress.Results)
	}

	acts := actionSearchResponseFromProto(&authzenv1.SearchActionsResponse{
		Results: []*authzenv1.Action{nil},
	})
	if len(acts.Results) != 1 || !reflect.DeepEqual(acts.Results[0], authzen.Action{}) {
		t.Fatalf("actions: got %#v; want one zero-value Action", acts.Results)
	}

	// Empty (no results) responses must also convert cleanly.
	if got := subjectSearchResponseFromProto(&authzenv1.SearchSubjectsResponse{}); len(got.Results) != 0 {
		t.Fatalf("empty subject response: got %#v", got)
	}
}

// --- Finding 6: int->int32 truncation guard for limit/count/total ---

// TestClampInt32GuardsOverflow proves the conversion saturates at the int32
// bound instead of wrapping to a negative value on overflow, both directly and
// through the page conversions.
func TestClampInt32GuardsOverflow(t *testing.T) {
	big := int(math.MaxInt32) + 1 // exceeds int32 on 64-bit platforms
	if got := clampInt32(big); got != math.MaxInt32 {
		t.Fatalf("clampInt32(%d) = %d; want MaxInt32 (%d)", big, got, int32(math.MaxInt32))
	}
	if got := clampInt32(-1); got != -1 {
		t.Fatalf("clampInt32(-1) = %d; want -1", got)
	}

	p, err := pageResponseToProto(&authzen.PageResponse{Count: big, Total: big})
	if err != nil {
		t.Fatalf("pageResponseToProto: %v", err)
	}
	if p.GetCount() != math.MaxInt32 || p.GetTotal() != math.MaxInt32 {
		t.Fatalf("got count=%d total=%d; want both saturated to MaxInt32", p.GetCount(), p.GetTotal())
	}

	size, _, _, err := pageToProto(&authzen.Page{Limit: big})
	if err != nil {
		t.Fatalf("pageToProto: %v", err)
	}
	if size != math.MaxInt32 {
		t.Fatalf("page_size = %d; want saturated to MaxInt32", size)
	}
}

// TestEvaluationsResponseSingleDecisionToProto verifies a single-decision core
// response (Section 6.2, e.g. from SingleDecision) is carried as a one-element
// evaluations array rather than being silently dropped by the proto conversion.
func TestEvaluationsResponseSingleDecisionToProto(t *testing.T) {
	out, err := evaluationsResponseToProto(authzen.SingleDecision(true, map[string]any{"reason": "ok"}))
	if err != nil {
		t.Fatalf("evaluationsResponseToProto: %v", err)
	}
	if len(out.GetEvaluations()) != 1 || !out.GetEvaluations()[0].GetDecision() {
		t.Fatalf("single decision not preserved: %#v", out.GetEvaluations())
	}
}
