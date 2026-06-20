package approval

import (
	"errors"
	"testing"
	"time"
)

// TestOnResolveFiresOncePerResolution verifies the Store's optional resolution
// hook fires exactly once when an approval reaches a terminal state, for each
// of the explicit transitions (approve, deny, cancel).
func TestOnResolveFiresOncePerResolution(t *testing.T) {
	cases := map[string]struct {
		act        func(s *Store, id string) error
		wantStatus Status
	}{
		"approve": {
			act:        func(s *Store, id string) error { _, err := s.Approve(id, "mgr@example.com", nil); return err },
			wantStatus: StatusApproved,
		},
		"deny": {
			act:        func(s *Store, id string) error { _, err := s.Deny(id, "mgr@example.com", nil); return err },
			wantStatus: StatusDenied,
		},
		"cancel": {
			act:        func(s *Store, id string) error { _, err := s.Cancel(id); return err },
			wantStatus: StatusCanceled,
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			s, _ := newTestStore(t)
			var calls int
			var last *Approval
			s.OnResolve = func(a *Approval) {
				calls++
				last = a
			}

			created, err := s.Create(NewPending(&RequestRef{Type: "payment"}))
			if err != nil {
				t.Fatalf("Create: %v", err)
			}
			if calls != 0 {
				t.Fatalf("OnResolve fired %d times before resolution, want 0", calls)
			}

			if err := tc.act(s, created.ID); err != nil {
				t.Fatalf("act: %v", err)
			}
			if calls != 1 {
				t.Fatalf("OnResolve fired %d times, want 1", calls)
			}
			if last == nil || last.Status != tc.wantStatus {
				t.Fatalf("OnResolve approval = %+v, want status %q", last, tc.wantStatus)
			}
			if last.ID != created.ID {
				t.Fatalf("OnResolve ID = %q, want %q", last.ID, created.ID)
			}

			// A subsequent read of a terminal approval must not re-fire.
			if _, err := s.Get(created.ID); err != nil {
				t.Fatalf("Get: %v", err)
			}
			if calls != 1 {
				t.Fatalf("OnResolve re-fired on read, calls = %d, want 1", calls)
			}
		})
	}
}

// TestOnResolveFiresOnceOnExpiry verifies lazy expiry observed during Get fires
// the hook exactly once, and never again on subsequent reads.
func TestOnResolveFiresOnceOnExpiry(t *testing.T) {
	s, clock := newTestStore(t)
	var calls int
	var last *Approval
	s.OnResolve = func(a *Approval) {
		calls++
		last = a
	}

	created, err := s.Create(&Approval{ExpiresIn: 60, RequestRef: &RequestRef{Type: "payment"}})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	// Before expiry: a Get must not fire the hook.
	if _, err := s.Get(created.ID); err != nil {
		t.Fatalf("Get (pre-expiry): %v", err)
	}
	if calls != 0 {
		t.Fatalf("OnResolve fired %d times before expiry, want 0", calls)
	}

	// Advance past the deadline; the next Get lazily expires and fires once.
	*clock = clock.Add(61 * time.Second)
	if _, err := s.Get(created.ID); err != nil {
		t.Fatalf("Get (post-expiry): %v", err)
	}
	if calls != 1 {
		t.Fatalf("OnResolve fired %d times on expiry, want 1", calls)
	}
	if last == nil || last.Status != StatusExpired {
		t.Fatalf("OnResolve approval = %+v, want status expired", last)
	}

	// Further reads must not re-fire.
	if _, err := s.Get(created.ID); err != nil {
		t.Fatalf("Get (post-expiry 2): %v", err)
	}
	if calls != 1 {
		t.Fatalf("OnResolve re-fired, calls = %d, want 1", calls)
	}
}

// TestOnResolveFiresOnExpiryDuringMutation verifies that an Approve attempt on a
// just-lapsed approval both returns ErrExpired and fires the resolution hook
// once for the expiry transition.
func TestOnResolveFiresOnExpiryDuringMutation(t *testing.T) {
	s, clock := newTestStore(t)
	var calls int
	s.OnResolve = func(*Approval) { calls++ }

	created, err := s.Create(&Approval{ExpiresIn: 60, RequestRef: &RequestRef{Type: "payment"}})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	*clock = clock.Add(61 * time.Second)
	if _, err := s.Approve(created.ID, "mgr@example.com", nil); !errors.Is(err, ErrExpired) {
		t.Fatalf("Approve err = %v, want ErrExpired", err)
	}
	if calls != 1 {
		t.Fatalf("OnResolve fired %d times on mutation-time expiry, want 1", calls)
	}
}

// TestOnResolveNilSafe verifies that resolution works without panicking when no
// hook is installed (the default).
func TestOnResolveNilSafe(t *testing.T) {
	s, clock := newTestStore(t)
	// OnResolve intentionally left nil.

	created, err := s.Create(&Approval{ExpiresIn: 60, RequestRef: &RequestRef{Type: "payment"}})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := s.Approve(created.ID, "mgr@example.com", nil); err != nil {
		t.Fatalf("Approve with nil OnResolve: %v", err)
	}

	other, err := s.Create(&Approval{ExpiresIn: 60})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	*clock = clock.Add(61 * time.Second)
	if _, err := s.Get(other.ID); err != nil {
		t.Fatalf("Get (expiry) with nil OnResolve: %v", err)
	}
}
