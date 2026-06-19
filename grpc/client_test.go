package authzengrpc

import (
	"context"
	"testing"

	authzen "github.com/SCKelemen/authzen"
)

// TestNewClientFromGRPCAndRaw covers the alternate constructor and the Raw
// accessor: a Client built from an already-constructed generated client must
// work, and Raw must hand back that same underlying client for advanced use.
func TestNewClientFromGRPCAndRaw(t *testing.T) {
	_, raw := newTestRig(t, &fakePDP{decide: permitReads})

	client := NewClientFromGRPC(raw)
	if client.Raw() != raw {
		t.Fatal("Raw() did not return the wrapped generated client")
	}

	resp, err := client.Evaluate(context.Background(), authzen.EvaluationRequest{
		Subject:  &authzen.Subject{Type: "user", ID: "alice@example.com"},
		Action:   &authzen.Action{Name: "can_read"},
		Resource: &authzen.Resource{Type: "todo", ID: "1"},
	})
	if err != nil {
		t.Fatalf("Evaluate via NewClientFromGRPC: %v", err)
	}
	if !resp.Decision {
		t.Fatal("expected decision=true for can_read")
	}
}

// TestClientConversionErrors drives the request-conversion error branch of each
// Client method. An unconvertible property fails *ToProto before any RPC is
// attempted, so the error must surface directly to the caller.
func TestClientConversionErrors(t *testing.T) {
	client, _ := newTestRig(t, &fakePDP{decide: permitReads})
	ctx := context.Background()

	badSub := &authzen.Subject{Type: "user", ID: "a", Properties: badMap()}
	okAct := &authzen.Action{Name: "can_read"}
	okRes := &authzen.Resource{Type: "todo", ID: "1"}

	if _, err := client.Evaluate(ctx, authzen.EvaluationRequest{Subject: badSub, Action: okAct, Resource: okRes}); err == nil {
		t.Error("Evaluate: expected conversion error")
	}
	if _, err := client.EvaluateBatch(ctx, authzen.EvaluationsRequest{Subject: badSub}); err == nil {
		t.Error("EvaluateBatch: expected conversion error")
	}
	if _, err := client.SearchSubjects(ctx, authzen.SubjectSearchRequest{Subject: badSub, Action: okAct, Resource: okRes}); err == nil {
		t.Error("SearchSubjects: expected conversion error")
	}
	if _, err := client.SearchResources(ctx, authzen.ResourceSearchRequest{Subject: badSub, Action: okAct, Resource: okRes}); err == nil {
		t.Error("SearchResources: expected conversion error")
	}
	if _, err := client.SearchActions(ctx, authzen.ActionSearchRequest{Subject: badSub, Resource: okRes}); err == nil {
		t.Error("SearchActions: expected conversion error")
	}
}
