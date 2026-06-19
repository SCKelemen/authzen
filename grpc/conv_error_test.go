package authzengrpc

import (
	"reflect"
	"testing"

	authzen "github.com/SCKelemen/authzen"
)

// badMap returns a map whose value is not representable in a
// google.protobuf.Struct, so structpb.NewStruct (and therefore mapToStruct)
// fails. This drives the error branches of every *ToProto conversion that
// serializes a free-form properties/context/additional object.
func badMap() map[string]any { return map[string]any{"unconvertible": make(chan int)} }

func TestMapToStructError(t *testing.T) {
	if _, err := mapToStruct(badMap()); err == nil {
		t.Fatal("mapToStruct(badMap) = nil error; want error for unconvertible value")
	}
	// nil / empty maps are not errors; they collapse to a nil Struct.
	if s, err := mapToStruct(nil); err != nil || s != nil {
		t.Fatalf("mapToStruct(nil) = %v, %v; want nil, nil", s, err)
	}
	if s, err := mapToStruct(map[string]any{}); err != nil || s != nil {
		t.Fatalf("mapToStruct(empty) = %v, %v; want nil, nil", s, err)
	}
}

// TestToProtoErrorPaths exercises every error branch that propagates a
// mapToStruct failure out of a *ToProto conversion. Each case sets exactly one
// free-form object to an unconvertible value and asserts the error surfaces.
func TestToProtoErrorPaths(t *testing.T) {
	badSub := &authzen.Subject{Type: "user", ID: "a", Properties: badMap()}
	badRes := &authzen.Resource{Type: "todo", ID: "1", Properties: badMap()}
	badAct := &authzen.Action{Name: "read", Properties: badMap()}
	okSub := &authzen.Subject{Type: "user", ID: "a"}
	okRes := &authzen.Resource{Type: "todo", ID: "1"}
	okAct := &authzen.Action{Name: "read"}
	badCtx := authzen.Context(badMap())
	badPage := &authzen.Page{Properties: badMap()}

	cases := []struct {
		name string
		fn   func() error
	}{
		{"subjectToProto", func() error { _, err := subjectToProto(badSub); return err }},
		{"resourceToProto", func() error { _, err := resourceToProto(badRes); return err }},
		{"actionToProto", func() error { _, err := actionToProto(badAct); return err }},

		{"evaluationRequest/subject", func() error {
			_, err := evaluationRequestToProto(authzen.EvaluationRequest{Subject: badSub, Action: okAct, Resource: okRes})
			return err
		}},
		{"evaluationRequest/action", func() error {
			_, err := evaluationRequestToProto(authzen.EvaluationRequest{Subject: okSub, Action: badAct, Resource: okRes})
			return err
		}},
		{"evaluationRequest/resource", func() error {
			_, err := evaluationRequestToProto(authzen.EvaluationRequest{Subject: okSub, Action: okAct, Resource: badRes})
			return err
		}},
		{"evaluationRequest/context", func() error {
			_, err := evaluationRequestToProto(authzen.EvaluationRequest{Subject: okSub, Action: okAct, Resource: okRes, Context: badCtx})
			return err
		}},

		{"evaluationResponse/context", func() error {
			_, err := evaluationResponseToProto(authzen.EvaluationResponse{Context: badCtx})
			return err
		}},

		{"options/additional", func() error {
			_, err := optionsToProto(&authzen.Options{Additional: badMap()})
			return err
		}},

		{"evaluationsRequest/subject", func() error {
			_, err := evaluationsRequestToProto(authzen.EvaluationsRequest{Subject: badSub})
			return err
		}},
		{"evaluationsRequest/action", func() error {
			_, err := evaluationsRequestToProto(authzen.EvaluationsRequest{Action: badAct})
			return err
		}},
		{"evaluationsRequest/resource", func() error {
			_, err := evaluationsRequestToProto(authzen.EvaluationsRequest{Resource: badRes})
			return err
		}},
		{"evaluationsRequest/context", func() error {
			_, err := evaluationsRequestToProto(authzen.EvaluationsRequest{Context: badCtx})
			return err
		}},
		{"evaluationsRequest/options", func() error {
			_, err := evaluationsRequestToProto(authzen.EvaluationsRequest{Options: &authzen.Options{Additional: badMap()}})
			return err
		}},
		{"evaluationsRequest/member", func() error {
			_, err := evaluationsRequestToProto(authzen.EvaluationsRequest{
				Evaluations: []authzen.EvaluationRequest{{Subject: badSub, Action: okAct, Resource: okRes}},
			})
			return err
		}},

		{"evaluationsResponse/member", func() error {
			_, err := evaluationsResponseToProto(authzen.EvaluationsResponse{
				Evaluations: []authzen.EvaluationResponse{{Context: badCtx}},
			})
			return err
		}},

		{"subjectSearchRequest/subject", func() error {
			_, err := subjectSearchRequestToProto(authzen.SubjectSearchRequest{Subject: badSub, Action: okAct, Resource: okRes})
			return err
		}},
		{"subjectSearchRequest/action", func() error {
			_, err := subjectSearchRequestToProto(authzen.SubjectSearchRequest{Subject: okSub, Action: badAct, Resource: okRes})
			return err
		}},
		{"subjectSearchRequest/resource", func() error {
			_, err := subjectSearchRequestToProto(authzen.SubjectSearchRequest{Subject: okSub, Action: okAct, Resource: badRes})
			return err
		}},
		{"subjectSearchRequest/context", func() error {
			_, err := subjectSearchRequestToProto(authzen.SubjectSearchRequest{Subject: okSub, Action: okAct, Resource: okRes, Context: badCtx})
			return err
		}},
		{"subjectSearchRequest/page", func() error {
			_, err := subjectSearchRequestToProto(authzen.SubjectSearchRequest{Subject: okSub, Action: okAct, Resource: okRes, Page: badPage})
			return err
		}},

		{"subjectSearchResponse/result", func() error {
			_, err := subjectSearchResponseToProto(authzen.SubjectSearchResponse{Results: []authzen.Subject{*badSub}})
			return err
		}},
		{"subjectSearchResponse/page", func() error {
			_, err := subjectSearchResponseToProto(authzen.SubjectSearchResponse{Page: &authzen.PageResponse{Properties: badMap()}})
			return err
		}},
		{"subjectSearchResponse/context", func() error {
			_, err := subjectSearchResponseToProto(authzen.SubjectSearchResponse{Context: badMap()})
			return err
		}},

		{"resourceSearchRequest/subject", func() error {
			_, err := resourceSearchRequestToProto(authzen.ResourceSearchRequest{Subject: badSub, Action: okAct, Resource: okRes})
			return err
		}},
		{"resourceSearchRequest/action", func() error {
			_, err := resourceSearchRequestToProto(authzen.ResourceSearchRequest{Subject: okSub, Action: badAct, Resource: okRes})
			return err
		}},
		{"resourceSearchRequest/resource", func() error {
			_, err := resourceSearchRequestToProto(authzen.ResourceSearchRequest{Subject: okSub, Action: okAct, Resource: badRes})
			return err
		}},
		{"resourceSearchRequest/context", func() error {
			_, err := resourceSearchRequestToProto(authzen.ResourceSearchRequest{Subject: okSub, Action: okAct, Resource: okRes, Context: badCtx})
			return err
		}},
		{"resourceSearchRequest/page", func() error {
			_, err := resourceSearchRequestToProto(authzen.ResourceSearchRequest{Subject: okSub, Action: okAct, Resource: okRes, Page: badPage})
			return err
		}},

		{"resourceSearchResponse/result", func() error {
			_, err := resourceSearchResponseToProto(authzen.ResourceSearchResponse{Results: []authzen.Resource{*badRes}})
			return err
		}},
		{"resourceSearchResponse/page", func() error {
			_, err := resourceSearchResponseToProto(authzen.ResourceSearchResponse{Page: &authzen.PageResponse{Properties: badMap()}})
			return err
		}},
		{"resourceSearchResponse/context", func() error {
			_, err := resourceSearchResponseToProto(authzen.ResourceSearchResponse{Context: badMap()})
			return err
		}},

		{"actionSearchRequest/subject", func() error {
			_, err := actionSearchRequestToProto(authzen.ActionSearchRequest{Subject: badSub, Resource: okRes})
			return err
		}},
		{"actionSearchRequest/resource", func() error {
			_, err := actionSearchRequestToProto(authzen.ActionSearchRequest{Subject: okSub, Resource: badRes})
			return err
		}},
		{"actionSearchRequest/context", func() error {
			_, err := actionSearchRequestToProto(authzen.ActionSearchRequest{Subject: okSub, Resource: okRes, Context: badCtx})
			return err
		}},
		{"actionSearchRequest/page", func() error {
			_, err := actionSearchRequestToProto(authzen.ActionSearchRequest{Subject: okSub, Resource: okRes, Page: badPage})
			return err
		}},

		{"actionSearchResponse/result", func() error {
			_, err := actionSearchResponseToProto(authzen.ActionSearchResponse{Results: []authzen.Action{*badAct}})
			return err
		}},
		{"actionSearchResponse/page", func() error {
			_, err := actionSearchResponseToProto(authzen.ActionSearchResponse{Page: &authzen.PageResponse{Properties: badMap()}})
			return err
		}},
		{"actionSearchResponse/context", func() error {
			_, err := actionSearchResponseToProto(authzen.ActionSearchResponse{Context: badMap()})
			return err
		}},

		{"pageResponseToProto/properties", func() error {
			_, err := pageResponseToProto(&authzen.PageResponse{Properties: badMap()})
			return err
		}},
		{"pageToProto/properties", func() error {
			_, _, _, err := pageToProto(&authzen.Page{Properties: badMap()})
			return err
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.fn(); err == nil {
				t.Fatalf("%s: got nil error; want an error from the unconvertible value", tc.name)
			}
		})
	}
}

// TestFromProtoNilInputs asserts that every *FromProto conversion tolerates a
// nil proto message, returning the zero value (or nil) rather than panicking.
func TestFromProtoNilInputs(t *testing.T) {
	if resourceFromProto(nil) != nil {
		t.Error("resourceFromProto(nil) should be nil")
	}
	if actionFromProto(nil) != nil {
		t.Error("actionFromProto(nil) should be nil")
	}
	if optionsFromProto(nil) != nil {
		t.Error("optionsFromProto(nil) should be nil")
	}
	if pageResponseFromProto(nil) != nil {
		t.Error("pageResponseFromProto(nil) should be nil")
	}
	if got := evaluationRequestFromProto(nil); !reflect.DeepEqual(got, authzen.EvaluationRequest{}) {
		t.Errorf("evaluationRequestFromProto(nil) = %#v; want zero value", got)
	}
	if got := evaluationResponseFromProto(nil); !reflect.DeepEqual(got, authzen.EvaluationResponse{}) {
		t.Errorf("evaluationResponseFromProto(nil) = %#v; want zero value", got)
	}
	if got := evaluationsRequestFromProto(nil); !reflect.DeepEqual(got, authzen.EvaluationsRequest{}) {
		t.Errorf("evaluationsRequestFromProto(nil) = %#v; want zero value", got)
	}
	if got := evaluationsResponseFromProto(nil); !reflect.DeepEqual(got, authzen.EvaluationsResponse{}) {
		t.Errorf("evaluationsResponseFromProto(nil) = %#v; want zero value", got)
	}
	if got := subjectSearchRequestFromProto(nil); !reflect.DeepEqual(got, authzen.SubjectSearchRequest{}) {
		t.Errorf("subjectSearchRequestFromProto(nil) = %#v; want zero value", got)
	}
	if got := subjectSearchResponseFromProto(nil); !reflect.DeepEqual(got, authzen.SubjectSearchResponse{}) {
		t.Errorf("subjectSearchResponseFromProto(nil) = %#v; want zero value", got)
	}
	if got := resourceSearchRequestFromProto(nil); !reflect.DeepEqual(got, authzen.ResourceSearchRequest{}) {
		t.Errorf("resourceSearchRequestFromProto(nil) = %#v; want zero value", got)
	}
	if got := resourceSearchResponseFromProto(nil); !reflect.DeepEqual(got, authzen.ResourceSearchResponse{}) {
		t.Errorf("resourceSearchResponseFromProto(nil) = %#v; want zero value", got)
	}
	if got := actionSearchRequestFromProto(nil); !reflect.DeepEqual(got, authzen.ActionSearchRequest{}) {
		t.Errorf("actionSearchRequestFromProto(nil) = %#v; want zero value", got)
	}
	if got := actionSearchResponseFromProto(nil); !reflect.DeepEqual(got, authzen.ActionSearchResponse{}) {
		t.Errorf("actionSearchResponseFromProto(nil) = %#v; want zero value", got)
	}
	if got := metadataFromProto(nil); !reflect.DeepEqual(got, authzen.Metadata{}) {
		t.Errorf("metadataFromProto(nil) = %#v; want zero value", got)
	}
}
