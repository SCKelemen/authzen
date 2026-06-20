package approval

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"sync"
	"time"

	authzen "github.com/SCKelemen/authzen"
)

// Sentinel errors returned by Store, testable with errors.Is.
var (
	// ErrNotFound indicates no approval exists for the given identifier.
	ErrNotFound = errors.New("approval: request not found")
	// ErrAlreadyResolved indicates an illegal transition was attempted on an
	// approval that has already reached a terminal state (other than expiry).
	ErrAlreadyResolved = errors.New("approval: request already resolved")
	// ErrExpired indicates a transition was attempted on an approval whose
	// pending lifetime has elapsed (it has lazily transitioned to
	// StatusExpired).
	ErrExpired = errors.New("approval: request expired")
	// ErrStoreFull indicates Create was refused because the Store has reached
	// its configured maximum size (see WithMaxSize). The Store fails closed: it
	// rejects the new request rather than silently evicting an existing one.
	ErrStoreFull = errors.New("approval: store is full")
)

// idEntropyBytes is the number of cryptographically random bytes used to mint
// an opaque approval identifier. 256 bits of entropy makes the handle
// infeasible to guess, mirroring the unguessability requirement RFC 8628 places
// on the device_code.
//
// RFC 8628 Section 5.2 - Device Code Brute Forcing (high-entropy device_code).
// https://www.rfc-editor.org/rfc/rfc8628#section-5.2
const idEntropyBytes = 32

// record is the Store's internal bookkeeping for one approval: the approval
// itself plus the creation instant used to compute lazy expiry.
type record struct {
	approval  *Approval
	createdAt time.Time
}

// Store is an in-memory, concurrency-safe state machine for pending approvals.
// It assigns opaque high-entropy identifiers, enforces the legal lifecycle
// transitions (pending -> approved/denied/canceled, and lazily -> expired),
// and treats every terminal state as immutable.
//
// The zero value is not usable; construct a Store with NewStore.
//
// # Memory: the Store grows without bound by default
//
// The Store NEVER removes a record on its own: Create inserts, the lifecycle
// transitions mutate in place, and nothing is deleted. A long-running process
// that keeps calling Create will therefore leak memory indefinitely unless the
// caller reclaims records. Choose at least one of:
//
//   - call Delete(id) once a decision has been consumed;
//   - call Sweep() periodically to drop terminal and past-expiry records;
//   - construct the Store with WithJanitor so a background goroutine sweeps on a
//     ticker (remember to Close the Store to stop it);
//   - construct the Store with WithMaxSize to fail closed (ErrStoreFull) instead
//     of leaking past a cap.
//
// Without one of these, the Store is unsuitable for a long-running process.
type Store struct {
	mu    sync.Mutex
	items map[string]*record
	// now returns the current time; overridable in tests to drive expiry
	// deterministically.
	now func() time.Time
	// rand is the entropy source for minting opaque identifiers. It is seeded by
	// NewStore to crypto/rand.Reader and is only overridden in tests (for
	// example to drive the entropy-exhaustion failure path). A Store not
	// constructed via NewStore has a nil rand and is unusable, per the
	// zero-value contract above.
	rand io.Reader
	// maxSize, when > 0, caps the number of records the Store will retain;
	// Create returns ErrStoreFull once the cap is reached. Configured via
	// WithMaxSize.
	maxSize int
	// janitorInterval, when > 0, requests a background sweep goroutine; set by
	// WithJanitor and consumed by NewStore.
	janitorInterval time.Duration
	// janitorStop is closed by Close to signal the janitor goroutine to exit;
	// janitorDone is closed by that goroutine on exit so Close can wait for it
	// race-cleanly. Both are nil when no janitor is running. They are assigned
	// once, in NewStore, before the Store is shared, so they need no locking.
	janitorStop chan struct{}
	janitorDone chan struct{}
	// closeOnce makes Close idempotent.
	closeOnce sync.Once
	// OnResolve, if non-nil, is invoked exactly once with a clone of an approval
	// immediately after it reaches a terminal state (via Approve, Deny, Cancel,
	// or lazy expiry observed during Get or Sweep). It is the optional, decoupled
	// hook through which a caller can wire delivery (for example a Notifier)
	// without the Store itself depending on the network. The callback runs
	// synchronously, outside the Store's lock; a slow or blocking callback (such
	// as a network POST) therefore blocks the triggering call, so wrap it in a
	// goroutine if asynchronous delivery is desired (see the hazard note on Get).
	// A panic from the hook is recovered and swallowed so it cannot crash the
	// decision path. Set it before first use; it is not safe to mutate
	// concurrently with Store operations.
	OnResolve func(*Approval)
}

// Option configures a Store at construction time. See WithMaxSize and
// WithJanitor.
type Option func(*Store)

// WithMaxSize caps the number of records the Store retains. Once the cap is
// reached, Create fails closed with ErrStoreFull rather than evicting an
// existing record. The cap counts ALL retained records, including terminal ones
// that have not yet been swept or deleted, since those still consume memory. A
// non-positive n disables the cap (the default).
func WithMaxSize(n int) Option {
	return func(s *Store) {
		if n > 0 {
			s.maxSize = n
		}
	}
}

// WithJanitor runs Sweep on a background ticker at the given interval, bounding
// memory without manual calls. The janitor is opt-in; a Store constructed
// without it never starts a goroutine. Call Close to stop the janitor cleanly.
// A non-positive interval disables the janitor (the default).
func WithJanitor(interval time.Duration) Option {
	return func(s *Store) {
		if interval > 0 {
			s.janitorInterval = interval
		}
	}
}

// NewStore returns an empty, ready-to-use Store seeded with the secure
// crypto/rand entropy source. Apply WithMaxSize and/or WithJanitor to bound
// memory; see the Store memory note above. When a janitor is configured, the
// caller MUST Close the Store to stop the background goroutine.
func NewStore(opts ...Option) *Store {
	s := &Store{
		items: make(map[string]*record),
		now:   time.Now,
		rand:  rand.Reader,
	}
	for _, opt := range opts {
		if opt != nil {
			opt(s)
		}
	}
	if s.janitorInterval > 0 {
		s.startJanitor(s.janitorInterval)
	}
	return s
}

// startJanitor launches the background sweep goroutine. It is called only from
// NewStore, before the Store is shared, so assigning the channels needs no
// locking.
func (s *Store) startJanitor(interval time.Duration) {
	s.janitorStop = make(chan struct{})
	s.janitorDone = make(chan struct{})
	go func() {
		defer close(s.janitorDone)
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-s.janitorStop:
				return
			case <-t.C:
				s.Sweep()
			}
		}
	}()
}

// Close stops the background janitor, if one is running, and waits for it to
// exit. It is idempotent and safe to call on a Store that never started a
// janitor (in which case it does nothing). Close does not clear stored records.
func (s *Store) Close() error {
	s.closeOnce.Do(func() {
		if s.janitorStop != nil {
			close(s.janitorStop)
			<-s.janitorDone
		}
	})
	return nil
}

// newID mints an opaque, URL-safe, high-entropy identifier by reading
// idEntropyBytes (256 bits) from the given reader. A read failure is propagated
// so the caller can refuse to create an identifier with insufficient entropy.
//
// RFC 8628 Section 5.2 - Device Code Brute Forcing (high-entropy device_code).
// https://www.rfc-editor.org/rfc/rfc8628#section-5.2
func newID(r io.Reader) (string, error) {
	b := make([]byte, idEntropyBytes)
	if _, err := io.ReadFull(r, b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// Create registers req as a new pending approval. It overwrites req.Status with
// StatusPending, assigns a fresh opaque ID, and applies the default expires_in
// and interval when they are unset. It returns a clone reflecting the stored
// state. A nil req is treated as an empty pending approval.
//
// RFC 8628 Section 3.2 - Device Authorization Response (pending, expires_in).
// https://www.rfc-editor.org/rfc/rfc8628#section-3.2
func (s *Store) Create(req *Approval) (*Approval, error) {
	if req == nil {
		req = &Approval{}
	}
	// The Store must be constructed via NewStore (see the zero-value contract on
	// Store); s.rand is therefore the secure crypto/rand reader unless a test
	// injected another. There is no nil-rand fallback: a zero-value Store is
	// unusable by design.
	id, err := newID(s.rand)
	if err != nil {
		// Entropy failure: do not store anything, so a caller that ignores the
		// error cannot end up with an un-minted (empty-ID) approval.
		return nil, err
	}
	req.ID = id
	req.Status = StatusPending
	if req.ExpiresIn <= 0 {
		req.ExpiresIn = DefaultExpiresIn
	}
	if req.Interval <= 0 {
		req.Interval = DefaultInterval
	}
	// A freshly created request is undecided.
	req.DecidedBy = ""
	req.DecidedAt = nil

	s.mu.Lock()
	defer s.mu.Unlock()
	// Fail closed when the configured cap is reached: reject rather than evict.
	if s.maxSize > 0 && len(s.items) >= s.maxSize {
		return nil, ErrStoreFull
	}
	s.items[id] = &record{approval: req, createdAt: s.now()}
	return req.clone(), nil
}

// Get returns a clone of the approval for id, applying lazy expiry first: a
// pending approval whose lifetime has elapsed is transitioned to StatusExpired
// before it is returned. It returns ErrNotFound for an unknown id.
//
// Hazard: when Get observes that expiry it fires OnResolve synchronously on the
// calling goroutine (outside the lock). If OnResolve performs blocking work —
// for example calling Notifier.Notify inline — that work runs on the poll
// request path and can stall a poll GET for up to DefaultNotifyTimeout. Wire
// blocking delivery off the request path (dispatch from a goroutine inside
// OnResolve).
func (s *Store) Get(id string) (*Approval, error) {
	s.mu.Lock()
	r, ok := s.items[id]
	if !ok {
		s.mu.Unlock()
		return nil, ErrNotFound
	}
	justExpired := s.expireLocked(r)
	out := r.approval.clone()
	var resolved *Approval
	if justExpired {
		resolved = r.approval.clone()
	}
	s.mu.Unlock()

	s.fireResolve(resolved)
	return out, nil
}

// Approve transitions a pending approval to StatusApproved, recording the
// deciding principal and time and attaching the optional grant. It returns
// ErrNotFound for an unknown id, ErrExpired if the request has lapsed, and
// ErrAlreadyResolved if it is in any other terminal state.
func (s *Store) Approve(id, by string, grant *Grant) (*Approval, error) {
	s.mu.Lock()
	r, justExpired, err := s.mutableLocked(id)
	if err != nil {
		var resolved *Approval
		if justExpired {
			resolved = r.approval.clone()
		}
		s.mu.Unlock()
		s.fireResolve(resolved)
		return nil, err
	}
	now := s.now()
	r.approval.Status = StatusApproved
	r.approval.DecidedBy = by
	r.approval.DecidedAt = &now
	r.approval.ExpiresIn = 0
	if grant != nil {
		r.approval.Grant = grant
	}
	out := r.approval.clone()
	resolved := r.approval.clone()
	s.mu.Unlock()

	s.fireResolve(resolved)
	return out, nil
}

// Deny transitions a pending approval to StatusDenied, recording the deciding
// principal and the optional user-facing reason. Error semantics match Approve.
func (s *Store) Deny(id, by string, reason authzen.Reasons) (*Approval, error) {
	s.mu.Lock()
	r, justExpired, err := s.mutableLocked(id)
	if err != nil {
		var resolved *Approval
		if justExpired {
			resolved = r.approval.clone()
		}
		s.mu.Unlock()
		s.fireResolve(resolved)
		return nil, err
	}
	now := s.now()
	r.approval.Status = StatusDenied
	r.approval.DecidedBy = by
	r.approval.DecidedAt = &now
	r.approval.ExpiresIn = 0
	if len(reason) > 0 {
		r.approval.ReasonUser = reason
	}
	out := r.approval.clone()
	resolved := r.approval.clone()
	s.mu.Unlock()

	s.fireResolve(resolved)
	return out, nil
}

// Cancel transitions a pending approval to StatusCanceled (the request was
// withdrawn before a decision). Error semantics match Approve.
func (s *Store) Cancel(id string) (*Approval, error) {
	s.mu.Lock()
	r, justExpired, err := s.mutableLocked(id)
	if err != nil {
		var resolved *Approval
		if justExpired {
			resolved = r.approval.clone()
		}
		s.mu.Unlock()
		s.fireResolve(resolved)
		return nil, err
	}
	now := s.now()
	r.approval.Status = StatusCanceled
	r.approval.DecidedAt = &now
	r.approval.ExpiresIn = 0
	out := r.approval.clone()
	resolved := r.approval.clone()
	s.mu.Unlock()

	s.fireResolve(resolved)
	return out, nil
}

// Delete removes the record for id, letting a caller reclaim memory once a
// decision has been consumed. It reports whether a record was present. Delete is
// a storage operation, not a lifecycle transition: it does NOT fire OnResolve
// and does NOT apply lazy expiry.
func (s *Store) Delete(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.items[id]; !ok {
		return false
	}
	delete(s.items, id)
	return true
}

// Sweep reclaims records that no longer need to be retained and returns the
// number removed. It removes every terminal record (approved, denied, canceled,
// expired) and every pending record whose lifetime has elapsed. A past-expiry
// pending record is first transitioned to StatusExpired — firing OnResolve
// exactly once — and then removed; this is how expiry is enforced (and the
// resolution hook delivered) for approvals that are never polled. Pending
// records that have not yet expired are left untouched.
//
// OnResolve is fired outside the lock, after the sweep completes, for each
// record newly expired by this call.
func (s *Store) Sweep() int {
	s.mu.Lock()
	var resolved []*Approval
	removed := 0
	for id, r := range s.items {
		if r.approval.Status == StatusPending {
			// Enforce expiry for unpolled pending records; collect the newly
			// expired ones so their resolution hook fires once, below.
			if s.expireLocked(r) {
				resolved = append(resolved, r.approval.clone())
			}
		}
		if r.approval.Status.Terminal() {
			delete(s.items, id)
			removed++
		}
	}
	s.mu.Unlock()

	for _, a := range resolved {
		s.fireResolve(a)
	}
	return removed
}

// Len returns the number of records currently retained by the Store, including
// terminal records that have not yet been swept or deleted. It does not apply
// lazy expiry.
func (s *Store) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.items)
}

// mutableLocked looks up id, applies lazy expiry, and verifies the approval is
// still pending (and therefore legally mutable). It also reports whether this
// call performed the lazy expiry transition, so a caller handling the resulting
// ErrExpired can fire the resolution hook exactly once. The caller must hold
// s.mu.
func (s *Store) mutableLocked(id string) (r *record, justExpired bool, err error) {
	r, ok := s.items[id]
	if !ok {
		return nil, false, ErrNotFound
	}
	justExpired = s.expireLocked(r)
	switch {
	case r.approval.Status == StatusExpired:
		return r, justExpired, ErrExpired
	case r.approval.Status.Terminal():
		return r, false, ErrAlreadyResolved
	default:
		return r, false, nil
	}
}

// expireLocked transitions a pending record to StatusExpired when its lifetime
// has elapsed, reporting whether this call performed that transition (so the
// caller can fire the resolution hook exactly once). It is a no-op for terminal
// records and for records with no positive expires_in. The caller must hold
// s.mu.
func (s *Store) expireLocked(r *record) bool {
	if r.approval.Status != StatusPending || r.approval.ExpiresIn <= 0 {
		return false
	}
	deadline := r.createdAt.Add(time.Duration(r.approval.ExpiresIn) * time.Second)
	if !s.now().Before(deadline) {
		r.approval.Status = StatusExpired
		r.approval.ExpiresIn = 0
		return true
	}
	return false
}

// fireResolve invokes the optional OnResolve hook with a (already-cloned)
// approval. It is nil-safe in both the hook and the approval, and MUST be called
// without holding s.mu so a blocking callback cannot deadlock the Store.
//
// (M5) A panic from the hook is recovered and swallowed: OnResolve is a
// best-effort, at-most-once side channel, and a misbehaving hook must not crash
// the Approve/Deny/Cancel/Get/Sweep decision path.
func (s *Store) fireResolve(a *Approval) {
	if a == nil {
		return
	}
	cb := s.OnResolve
	if cb == nil {
		return
	}
	defer func() { _ = recover() }()
	cb(a)
}

// clone returns a deep-enough copy of the approval so that callers cannot mutate
// the Store's internal state through the returned pointer.
func (a *Approval) clone() *Approval {
	if a == nil {
		return nil
	}
	c := *a
	if a.Delivery != nil {
		c.Delivery = append([]string(nil), a.Delivery...)
	}
	if a.RequestRef != nil {
		rc := *a.RequestRef
		rc.Locations = append([]string(nil), a.RequestRef.Locations...)
		rc.Actions = append([]string(nil), a.RequestRef.Actions...)
		rc.Datatypes = append([]string(nil), a.RequestRef.Datatypes...)
		rc.Privileges = append([]string(nil), a.RequestRef.Privileges...)
		c.RequestRef = &rc
	}
	if a.Approvers != nil {
		ac := *a.Approvers
		c.Approvers = &ac
	}
	if a.Grant != nil {
		gc := *a.Grant
		if a.Grant.ExpiresAt != nil {
			exp := *a.Grant.ExpiresAt
			gc.ExpiresAt = &exp
		}
		c.Grant = &gc
	}
	if a.DecidedAt != nil {
		dt := *a.DecidedAt
		c.DecidedAt = &dt
	}
	if a.ReasonUser != nil {
		ru := make(authzen.Reasons, len(a.ReasonUser))
		for k, v := range a.ReasonUser {
			ru[k] = v
		}
		c.ReasonUser = ru
	}
	return &c
}
