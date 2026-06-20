package approval_test

import (
	"encoding/json"
	"fmt"
	"net/url"

	"github.com/SCKelemen/authzen/approval"
)

// ExampleStore demonstrates the human-in-the-loop flow: a PDP creates a pending
// approval (a fail-safe deny the PEP can poll), and once a human approves it,
// the next poll observes a permit. IDs and timestamps are omitted from the
// output because they are non-deterministic.
func ExampleStore() {
	store := approval.NewStore()

	// Policy requires human approval: register a pending request.
	pending, err := store.Create(approval.NewPending(&approval.RequestRef{
		Type:    "payment_initiation",
		Actions: []string{"transfer"},
	}))
	if err != nil {
		panic(err)
	}
	fmt.Println("pending decision:", approval.Response(pending).Decision)

	// A human approves; the next poll resolves to a permit.
	approved, err := store.Approve(pending.ID, "manager@example.com", nil)
	if err != nil {
		panic(err)
	}
	fmt.Println("approved decision:", approval.Response(approved).Decision)
	fmt.Println("status:", approved.Status)

	// Output:
	// pending decision: false
	// approved decision: true
	// status: approved
}

// ExampleApproval_ToContext shows how an Approval projects into an AuthZEN
// decision context object under the reserved "approval" key.
func ExampleApproval_ToContext() {
	a := &approval.Approval{
		Status:    approval.StatusPending,
		ID:        "opaque-handle",
		ExpiresIn: 300,
		Interval:  5,
		RequestRef: &approval.RequestRef{
			Type:    "payment_initiation",
			Actions: []string{"transfer"},
		},
	}

	b, err := json.MarshalIndent(a.ToContext(), "", "  ")
	if err != nil {
		panic(err)
	}
	fmt.Println(string(b))

	// Output:
	// {
	//   "approval": {
	//     "approval_id": "opaque-handle",
	//     "expires_in": 300,
	//     "interval": 5,
	//     "request_ref": {
	//       "actions": [
	//         "transfer"
	//       ],
	//       "type": "payment_initiation"
	//     },
	//     "status": "pending"
	//   }
	// }
}

// ExampleAllowList demonstrates the recommended baseline callback-URL validator:
// only https URLs whose host is explicitly allow-listed are accepted. This is
// the safe-by-default policy that a Notifier needs before it will dereference a
// client-supplied callback_url.
func ExampleAllowList() {
	validate := approval.AllowList("hooks.example.com")

	for _, raw := range []string{
		"https://hooks.example.com/cb", // allowed
		"http://hooks.example.com/cb",  // cleartext rejected
		"https://evil.example.com/cb",  // host not allow-listed
	} {
		u, _ := url.Parse(raw)
		fmt.Printf("%s -> %v\n", raw, validate(u))
	}

	// Output:
	// https://hooks.example.com/cb -> <nil>
	// http://hooks.example.com/cb -> approval: scheme "http" not allowed (https required)
	// https://evil.example.com/cb -> approval: host "evil.example.com" not in allow-list
}
