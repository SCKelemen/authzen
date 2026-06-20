package approval

import (
	"errors"
	"sync"
	"testing"
	"time"

	authzen "github.com/SCKelemen/authzen"
)

// newTestStore returns a Store whose clock is pinned to a fixed, controllable
// instant so expiry can be exercised deterministically.
func newTestStore(t *testing.T) (*Store, *time.Time) {
	t.Helper()
	clock := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	s := NewStore()
	current := clock
	s.now = func() time.Time { return current }
	// Return a pointer the test can advance.
	return s, &current
}

func TestStoreCreateAssignsPending(t *testing.T) {
	s, _ := newTestStore(t)

	a, err := s.Create(&Approval{RequestRef: &RequestRef{Type: "payment"}})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if a.Status != StatusPending {
		t.Fatalf("Status = %q, want pending", a.Status)
	}
	if a.ID == "" {
		t.Fatalf("Create did not assign an ID")
	}
	if a.ExpiresIn != DefaultExpiresIn || a.Interval != DefaultInterval {
		t.Fatalf("defaults not applied: expires_in=%d interval=%d", a.ExpiresIn, a.Interval)
	}

	got, err := s.Get(a.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Status != StatusPending {
		t.Fatalf("Get status = %q, want pending", got.Status)
	}
}

func TestStoreCreateUniqueIDs(t *testing.T) {
	s, _ := newTestStore(t)
	seen := make(map[string]bool)
	for i := 0; i < 100; i++ {
		a, err := s.Create(nil)
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		if seen[a.ID] {
			t.Fatalf("duplicate ID minted: %q", a.ID)
		}
		seen[a.ID] = true
	}
}

func TestStoreApproveDenyCancel(t *testing.T) {
	cases := []struct {
		name       string
		act        func(s *Store, id string) (*Approval, error)
		wantStatus Status
	}{
		{
			name: "approve",
			act: func(s *Store, id string) (*Approval, error) {
				exp := time.Date(2025, 1, 1, 1, 0, 0, 0, time.UTC)
				return s.Approve(id, "mgr@example.com", &Grant{ExpiresAt: &exp})
			},
			wantStatus: StatusApproved,
		},
		{
			name: "deny",
			act: func(s *Store, id string) (*Approval, error) {
				return s.Deny(id, "mgr@example.com", authzen.Reasons{"403": "nope"})
			},
			wantStatus: StatusDenied,
		},
		{
			name: "cancel",
			act: func(s *Store, id string) (*Approval, error) {
				return s.Cancel(id)
			},
			wantStatus: StatusCanceled,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, _ := newTestStore(t)
			created, err := s.Create(nil)
			if err != nil {
				t.Fatalf("Create: %v", err)
			}
			got, err := tc.act(s, created.ID)
			if err != nil {
				t.Fatalf("transition: %v", err)
			}
			if got.Status != tc.wantStatus {
				t.Fatalf("Status = %q, want %q", got.Status, tc.wantStatus)
			}
			// The stored state must reflect the transition on the next read.
			reread, err := s.Get(created.ID)
			if err != nil {
				t.Fatalf("Get: %v", err)
			}
			if reread.Status != tc.wantStatus {
				t.Fatalf("re-read Status = %q, want %q", reread.Status, tc.wantStatus)
			}
		})
	}
}

func TestStoreApproveRecordsDecision(t *testing.T) {
	s, current := newTestStore(t)
	created, err := s.Create(nil)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	*current = current.Add(2 * time.Second)
	got, err := s.Approve(created.ID, "mgr@example.com", nil)
	if err != nil {
		t.Fatalf("Approve: %v", err)
	}
	if got.DecidedBy != "mgr@example.com" {
		t.Fatalf("DecidedBy = %q", got.DecidedBy)
	}
	if got.DecidedAt == nil || !got.DecidedAt.Equal(*current) {
		t.Fatalf("DecidedAt = %v, want %v", got.DecidedAt, *current)
	}
}

func TestStoreIllegalTransitions(t *testing.T) {
	// Each case drives a request into a terminal state, then attempts a second
	// transition that must be rejected as ErrAlreadyResolved.
	type step func(s *Store, id string) (*Approval, error)
	approve := func(s *Store, id string) (*Approval, error) { return s.Approve(id, "m", nil) }
	deny := func(s *Store, id string) (*Approval, error) { return s.Deny(id, "m", nil) }
	cancel := func(s *Store, id string) (*Approval, error) { return s.Cancel(id) }

	cases := []struct {
		name    string
		first   step
		second  step
		wantErr error
	}{
		{"approve then deny", approve, deny, ErrAlreadyResolved},
		{"approve then approve", approve, approve, ErrAlreadyResolved},
		{"approve then cancel", approve, cancel, ErrAlreadyResolved},
		{"deny then approve", deny, approve, ErrAlreadyResolved},
		{"deny then cancel", deny, cancel, ErrAlreadyResolved},
		{"cancel then approve", cancel, approve, ErrAlreadyResolved},
		{"cancel then deny", cancel, deny, ErrAlreadyResolved},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, _ := newTestStore(t)
			created, err := s.Create(nil)
			if err != nil {
				t.Fatalf("Create: %v", err)
			}
			if _, err := tc.first(s, created.ID); err != nil {
				t.Fatalf("first transition: %v", err)
			}
			_, err = tc.second(s, created.ID)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("second transition err = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

func TestStoreNotFound(t *testing.T) {
	s, _ := newTestStore(t)
	ops := map[string]func() error{
		"get":     func() error { _, err := s.Get("missing"); return err },
		"approve": func() error { _, err := s.Approve("missing", "m", nil); return err },
		"deny":    func() error { _, err := s.Deny("missing", "m", nil); return err },
		"cancel":  func() error { _, err := s.Cancel("missing"); return err },
	}
	for name, op := range ops {
		t.Run(name, func(t *testing.T) {
			if err := op(); !errors.Is(err, ErrNotFound) {
				t.Fatalf("err = %v, want ErrNotFound", err)
			}
		})
	}
}

func TestStoreLazyExpiry(t *testing.T) {
	s, current := newTestStore(t)
	created, err := s.Create(&Approval{ExpiresIn: 60})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	// Just before the deadline: still pending.
	*current = current.Add(59 * time.Second)
	got, err := s.Get(created.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Status != StatusPending {
		t.Fatalf("before deadline Status = %q, want pending", got.Status)
	}

	// At/after the deadline: lazily expired on read.
	*current = current.Add(1 * time.Second)
	got, err = s.Get(created.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Status != StatusExpired {
		t.Fatalf("after deadline Status = %q, want expired", got.Status)
	}
}

func TestStoreTransitionAfterExpiry(t *testing.T) {
	s, current := newTestStore(t)
	created, err := s.Create(&Approval{ExpiresIn: 30})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	*current = current.Add(31 * time.Second)

	if _, err := s.Approve(created.ID, "m", nil); !errors.Is(err, ErrExpired) {
		t.Fatalf("Approve after expiry err = %v, want ErrExpired", err)
	}
	if _, err := s.Deny(created.ID, "m", nil); !errors.Is(err, ErrExpired) {
		t.Fatalf("Deny after expiry err = %v, want ErrExpired", err)
	}
	if _, err := s.Cancel(created.ID); !errors.Is(err, ErrExpired) {
		t.Fatalf("Cancel after expiry err = %v, want ErrExpired", err)
	}
}

func TestStoreCloneIsolation(t *testing.T) {
	s, _ := newTestStore(t)
	created, err := s.Create(&Approval{
		Delivery:   []string{"poll"},
		RequestRef: &RequestRef{Type: "payment", Actions: []string{"transfer"}},
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	// Mutate the returned clone; the store's copy must be unaffected.
	created.Status = StatusApproved
	created.Delivery[0] = "push"
	created.RequestRef.Actions[0] = "tamper"

	got, err := s.Get(created.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Status != StatusPending {
		t.Fatalf("store mutated via clone: Status = %q", got.Status)
	}
	if got.Delivery[0] != "poll" {
		t.Fatalf("store Delivery mutated via clone: %q", got.Delivery[0])
	}
	if got.RequestRef.Actions[0] != "transfer" {
		t.Fatalf("store RequestRef mutated via clone: %q", got.RequestRef.Actions[0])
	}
}

func TestStoreConcurrentAccess(t *testing.T) {
	s := NewStore()
	created, err := s.Create(nil)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = s.Get(created.ID)
			_, _ = s.Create(nil)
			_, _ = s.Approve(created.ID, "m", nil)
		}()
	}
	wg.Wait()

	got, err := s.Get(created.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	// Exactly one Approve must have won; the rest see ErrAlreadyResolved.
	if got.Status != StatusApproved {
		t.Fatalf("Status = %q, want approved", got.Status)
	}
}
