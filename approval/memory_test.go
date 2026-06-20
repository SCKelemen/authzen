package approval

import (
	"errors"
	"testing"
	"time"
)

// TestDelete verifies a record can be reclaimed and that Delete is a pure
// storage operation: it reports presence and never fires OnResolve.
func TestDelete(t *testing.T) {
	s, _ := newTestStore(t)
	var fired int
	s.OnResolve = func(*Approval) { fired++ }

	created, err := s.Create(NewPending(&RequestRef{Type: "payment"}))
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if !s.Delete(created.ID) {
		t.Fatalf("Delete of present id returned false")
	}
	if s.Delete(created.ID) {
		t.Fatalf("Delete of absent id returned true")
	}
	if _, err := s.Get(created.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get after Delete err = %v, want ErrNotFound", err)
	}
	if fired != 0 {
		t.Fatalf("Delete fired OnResolve %d times, want 0", fired)
	}
	if s.Len() != 0 {
		t.Fatalf("Len = %d, want 0", s.Len())
	}
}

// TestSweep verifies Sweep removes terminal and past-expiry records, leaves
// not-yet-expired pending records, returns the removed count, and fires
// OnResolve exactly once (only) for records it newly expires.
func TestSweep(t *testing.T) {
	s, clock := newTestStore(t)
	var resolved []Status
	s.OnResolve = func(a *Approval) { resolved = append(resolved, a.Status) }

	approved, err := s.Create(NewPending(nil))
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := s.Approve(approved.ID, "mgr@example.com", nil); err != nil {
		t.Fatalf("Approve: %v", err)
	}
	denied, err := s.Create(NewPending(nil))
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := s.Deny(denied.ID, "mgr@example.com", nil); err != nil {
		t.Fatalf("Deny: %v", err)
	}
	live, err := s.Create(&Approval{ExpiresIn: 600})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	stale, err := s.Create(&Approval{ExpiresIn: 60})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	_ = stale

	// Discard the hook calls from the explicit Approve/Deny above; we only want
	// to observe what Sweep itself fires.
	resolved = nil

	// Advance past the short deadline (60s) but not the long one (600s).
	*clock = clock.Add(120 * time.Second)

	removed := s.Sweep()
	if removed != 3 {
		t.Fatalf("Sweep removed %d, want 3 (approved + denied + expired)", removed)
	}
	if s.Len() != 1 {
		t.Fatalf("Len = %d, want 1 (the still-live pending record)", s.Len())
	}
	if _, err := s.Get(live.ID); err != nil {
		t.Fatalf("not-yet-expired pending record should survive Sweep: %v", err)
	}
	if len(resolved) != 1 || resolved[0] != StatusExpired {
		t.Fatalf("Sweep OnResolve fired %v, want exactly [expired]", resolved)
	}
}

// TestSweepEnforcesUnpolledExpiry covers M6: a pending request that is never
// polled is still expired (and its resolution hook delivered) by Sweep, exactly
// once.
func TestSweepEnforcesUnpolledExpiry(t *testing.T) {
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
	_ = created

	*clock = clock.Add(61 * time.Second)
	if removed := s.Sweep(); removed != 1 {
		t.Fatalf("Sweep removed %d, want 1", removed)
	}
	if calls != 1 || last == nil || last.Status != StatusExpired {
		t.Fatalf("OnResolve calls=%d last=%v, want exactly one expired", calls, last)
	}
	if s.Len() != 0 {
		t.Fatalf("Len = %d, want 0", s.Len())
	}

	// A second sweep is a no-op and must not re-fire.
	if removed := s.Sweep(); removed != 0 {
		t.Fatalf("second Sweep removed %d, want 0", removed)
	}
	if calls != 1 {
		t.Fatalf("OnResolve re-fired on second Sweep, calls=%d", calls)
	}
}

// TestWithMaxSize verifies the cap fails closed with ErrStoreFull and that
// reclaiming a record frees a slot.
func TestWithMaxSize(t *testing.T) {
	s := NewStore(WithMaxSize(2))
	t.Cleanup(func() { _ = s.Close() })

	first, err := s.Create(NewPending(nil))
	if err != nil {
		t.Fatalf("Create #1: %v", err)
	}
	if _, err := s.Create(NewPending(nil)); err != nil {
		t.Fatalf("Create #2: %v", err)
	}
	if _, err := s.Create(NewPending(nil)); !errors.Is(err, ErrStoreFull) {
		t.Fatalf("Create at cap err = %v, want ErrStoreFull", err)
	}
	if s.Len() != 2 {
		t.Fatalf("Len = %d, want 2", s.Len())
	}

	// Reclaiming a record frees a slot.
	if !s.Delete(first.ID) {
		t.Fatalf("Delete failed")
	}
	if _, err := s.Create(NewPending(nil)); err != nil {
		t.Fatalf("Create after Delete: %v", err)
	}
	if s.Len() != 2 {
		t.Fatalf("Len = %d, want 2", s.Len())
	}
}

// TestMaxSizeCountsTerminalUntilSwept documents that terminal-but-unswept
// records count toward the cap, and that Sweep reclaims them.
func TestMaxSizeCountsTerminalUntilSwept(t *testing.T) {
	s := NewStore(WithMaxSize(1))
	t.Cleanup(func() { _ = s.Close() })

	a, err := s.Create(NewPending(nil))
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := s.Approve(a.ID, "mgr@example.com", nil); err != nil {
		t.Fatalf("Approve: %v", err)
	}
	// Terminal but still retained: the cap is still full.
	if _, err := s.Create(NewPending(nil)); !errors.Is(err, ErrStoreFull) {
		t.Fatalf("Create over terminal record err = %v, want ErrStoreFull", err)
	}
	// Sweep reclaims the terminal record, freeing the slot.
	if removed := s.Sweep(); removed != 1 {
		t.Fatalf("Sweep removed %d, want 1", removed)
	}
	if _, err := s.Create(NewPending(nil)); err != nil {
		t.Fatalf("Create after Sweep: %v", err)
	}
}

// TestJanitorEviction verifies the opt-in background janitor reclaims terminal
// records on its ticker and leaves live pending records alone, and that Close
// stops it cleanly. The janitor uses a real ticker, so the test uses terminal
// (already-approved) records, which Sweep removes independently of the clock.
func TestJanitorEviction(t *testing.T) {
	s := NewStore(WithJanitor(5 * time.Millisecond))
	t.Cleanup(func() { _ = s.Close() })

	for i := 0; i < 5; i++ {
		a, err := s.Create(NewPending(nil))
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		if _, err := s.Approve(a.ID, "mgr@example.com", nil); err != nil {
			t.Fatalf("Approve: %v", err)
		}
	}
	// A long-lived pending record must survive the janitor.
	live, err := s.Create(&Approval{ExpiresIn: 3600})
	if err != nil {
		t.Fatalf("Create live: %v", err)
	}

	deadline := time.Now().Add(2 * time.Second)
	for s.Len() > 1 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if got := s.Len(); got != 1 {
		t.Fatalf("janitor did not reclaim terminal records: Len = %d, want 1", got)
	}
	if _, err := s.Get(live.ID); err != nil {
		t.Fatalf("janitor reclaimed a live pending record: %v", err)
	}
}

// TestCloseIdempotentAndNilSafe verifies Close is safe with and without a
// janitor and may be called repeatedly.
func TestCloseIdempotentAndNilSafe(t *testing.T) {
	// No janitor: Close is a no-op and must not block or error.
	noJanitor := NewStore()
	if err := noJanitor.Close(); err != nil {
		t.Fatalf("Close (no janitor) #1: %v", err)
	}
	if err := noJanitor.Close(); err != nil {
		t.Fatalf("Close (no janitor) #2: %v", err)
	}

	// With a janitor: Close stops the goroutine and is idempotent.
	withJanitor := NewStore(WithJanitor(10 * time.Millisecond))
	if err := withJanitor.Close(); err != nil {
		t.Fatalf("Close (janitor) #1: %v", err)
	}
	if err := withJanitor.Close(); err != nil {
		t.Fatalf("Close (janitor) #2: %v", err)
	}
}

// TestOnResolvePanicRecovered covers M5: a panicking hook must not crash the
// decision path, regardless of which transition fires it.
func TestOnResolvePanicRecovered(t *testing.T) {
	cases := map[string]func(t *testing.T, s *Store, clock *time.Time){
		"approve": func(t *testing.T, s *Store, _ *time.Time) {
			c, err := s.Create(NewPending(nil))
			if err != nil {
				t.Fatalf("Create: %v", err)
			}
			if _, err := s.Approve(c.ID, "mgr@example.com", nil); err != nil {
				t.Fatalf("Approve: %v", err)
			}
		},
		"get-expiry": func(t *testing.T, s *Store, clock *time.Time) {
			c, err := s.Create(&Approval{ExpiresIn: 60})
			if err != nil {
				t.Fatalf("Create: %v", err)
			}
			*clock = clock.Add(61 * time.Second)
			if _, err := s.Get(c.ID); err != nil {
				t.Fatalf("Get: %v", err)
			}
		},
		"sweep-expiry": func(t *testing.T, s *Store, clock *time.Time) {
			if _, err := s.Create(&Approval{ExpiresIn: 60}); err != nil {
				t.Fatalf("Create: %v", err)
			}
			*clock = clock.Add(61 * time.Second)
			s.Sweep()
		},
	}
	for name, run := range cases {
		t.Run(name, func(t *testing.T) {
			s, clock := newTestStore(t)
			s.OnResolve = func(*Approval) { panic("hook boom") }
			// The decision path must complete without propagating the panic.
			run(t, s, clock)
		})
	}
}
