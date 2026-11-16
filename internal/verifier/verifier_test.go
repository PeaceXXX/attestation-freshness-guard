package verifier

import (
	"testing"
	"time"

	"github.com/PeaceXXX/attestation-freshness-guard/internal/evidence"
	"github.com/PeaceXXX/attestation-freshness-guard/internal/policy"
	"github.com/PeaceXXX/attestation-freshness-guard/internal/store"
)

var testKey = []byte("test-key")

func newVerifier(now time.Time) *Verifier {
	s, err := store.New("")
	if err != nil {
		panic(err)
	}
	return &Verifier{
		Policy: policy.Policy{MaxAge: 5 * time.Minute, MaxSkew: 30 * time.Second, MinTCBSVN: 5, RequireNonce: true},
		Store:  s,
		Key:    testKey,
		Now:    func() time.Time { return now },
	}
}

func signed(t *testing.T, id, workload string, at time.Time, nonce string, seq uint64, tcb uint32) evidence.Evidence {
	t.Helper()
	ev := evidence.Evidence{
		QuoteID:     id,
		WorkloadID:  workload,
		GeneratedAt: at,
		Nonce:       nonce,
		Sequence:    seq,
		TCBSVN:      tcb,
		ReportData:  "deadbeef",
	}
	ev.Sign(testKey)
	return ev
}

func TestFreshValidQuoteAllowed(t *testing.T) {
	now := time.Date(2026, 11, 16, 9, 36, 0, 0, time.UTC)
	v := newVerifier(now)
	ev := signed(t, "q-1", "w-1", now.Add(-60*time.Second), "n-abc", 1, 7)
	vv := v.Verify(ev, "n-abc")
	if !vv.Allowed {
		t.Fatalf("expected allow, got deny: %s (%+v)", vv.Reason, vv.Checks)
	}
	if len(vv.Checks) != 6 {
		t.Fatalf("expected 6 checks, got %d", len(vv.Checks))
	}
}

func TestStaleQuoteDenied(t *testing.T) {
	now := time.Date(2026, 11, 16, 9, 36, 0, 0, time.UTC)
	v := newVerifier(now)
	ev := signed(t, "q-stale", "w-1", now.Add(-10*time.Minute), "n-abc", 1, 7)
	if vv := v.Verify(ev, "n-abc"); vv.Allowed {
		t.Fatal("stale quote must be denied")
	}
}

func TestFutureQuoteBeyondSkewDenied(t *testing.T) {
	now := time.Date(2026, 11, 16, 9, 36, 0, 0, time.UTC)
	v := newVerifier(now)
	ev := signed(t, "q-future", "w-1", now.Add(2*time.Minute), "n-abc", 1, 7)
	if vv := v.Verify(ev, "n-abc"); vv.Allowed {
		t.Fatal("quote from the future must be denied")
	}
	// Within skew: allowed.
	v2 := newVerifier(now)
	ev2 := signed(t, "q-skew-ok", "w-1", now.Add(10*time.Second), "n-abc", 1, 7)
	if vv := v2.Verify(ev2, "n-abc"); !vv.Allowed {
		t.Fatalf("quote within skew should be allowed: %s", vv.Reason)
	}
}

func TestReplayDeniedEvenAfterFirstDenial(t *testing.T) {
	now := time.Date(2026, 11, 16, 9, 36, 0, 0, time.UTC)
	v := newVerifier(now)
	// First presentation is denied for staleness, but the quote is still
	// recorded as presented: the second try must fail as a replay.
	ev := signed(t, "q-replay", "w-1", now.Add(-10*time.Minute), "n-abc", 1, 7)
	first := v.Verify(ev, "n-abc")
	if first.Allowed {
		t.Fatal("first presentation should be denied (stale)")
	}
	// Fresh twin with the same quote ID: replay must fire.
	ev2 := signed(t, "q-replay", "w-1", now.Add(-10*time.Second), "n-abc", 2, 7)
	second := v.Verify(ev2, "n-abc")
	if second.Allowed {
		t.Fatal("replayed quote ID must be denied")
	}
	found := false
	for _, c := range second.Checks {
		if c.Name == "replay" && !c.Passed {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected a failed replay check, got %+v", second.Checks)
	}
}

func TestWrongNonceDenied(t *testing.T) {
	now := time.Date(2026, 11, 16, 9, 36, 0, 0, time.UTC)
	v := newVerifier(now)
	ev := signed(t, "q-nonce", "w-1", now.Add(-10*time.Second), "n-other-session", 1, 7)
	if vv := v.Verify(ev, "n-abc"); vv.Allowed {
		t.Fatal("quote bound to another session's nonce must be denied")
	}
}

func TestTamperedEvidenceDeniedAndNotRecorded(t *testing.T) {
	now := time.Date(2026, 11, 16, 9, 36, 0, 0, time.UTC)
	v := newVerifier(now)
	ev := signed(t, "q-tamper", "w-1", now.Add(-10*time.Second), "n-abc", 1, 7)
	ev.TCBSVN = 99 // tamper after signing
	if vv := v.Verify(ev, "n-abc"); vv.Allowed {
		t.Fatal("tampered evidence must be denied")
	}
	if v.Store.Seen("q-tamper") {
		t.Fatal("an unsigned/forged quote must not poison the replay ledger")
	}
}

func TestSequenceRegressionDenied(t *testing.T) {
	now := time.Date(2026, 11, 16, 9, 36, 0, 0, time.UTC)
	v := newVerifier(now)
	if vv := v.Verify(signed(t, "q-s1", "w-1", now.Add(-50*time.Second), "n-abc", 10, 7), "n-abc"); !vv.Allowed {
		t.Fatalf("first quote should be allowed: %s", vv.Reason)
	}
	if vv := v.Verify(signed(t, "q-s2", "w-1", now.Add(-10*time.Second), "n-abc", 9, 7), "n-abc"); vv.Allowed {
		t.Fatal("sequence regression must be denied")
	}
	if vv := v.Verify(signed(t, "q-s3", "w-1", now.Add(-5*time.Second), "n-abc", 11, 7), "n-abc"); !vv.Allowed {
		t.Fatalf("advancing sequence should be allowed: %s", vv.Reason)
	}
}

func TestTCBFloorDenied(t *testing.T) {
	now := time.Date(2026, 11, 16, 9, 36, 0, 0, time.UTC)
	v := newVerifier(now)
	ev := signed(t, "q-tcb", "w-1", now.Add(-10*time.Second), "n-abc", 1, 3)
	if vv := v.Verify(ev, "n-abc"); vv.Allowed {
		t.Fatal("TCB SVN below the floor must be denied")
	}
}
