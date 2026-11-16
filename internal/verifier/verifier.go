// Package verifier is the core of the project: a fail-closed freshness
// verdict for one attestation evidence document.
//
// A quote can be structurally valid and still untrustworthy. The verifier
// checks the time dimension that signature verification alone does not
// cover:
//
//  1. authenticity  - the demo HMAC signature matches (in production this
//     is real ECDSA quote verification; the freshness logic is identical).
//  2. nonce binding - the quote carries the challenge this session issued.
//  3. freshness     - the quote is not older than MaxAge, and not
//     impossibly far in the future (beyond MaxSkew).
//  4. replay        - this quote ID has never been presented before.
//  5. sequence      - the per-workload counter strictly increases.
//  6. TCB floor     - the reported TCB SVN meets the policy minimum.
//
// Every check reports its own pass/fail with a reason, so a denial is
// explainable. Any failing check denies the evidence: fail-closed, never
// fail-open. A quote is recorded in the replay ledger once its signature
// has verified, so a replay is caught even if the first presentation was
// denied for staleness.
package verifier

import (
	"fmt"
	"time"

	"github.com/PeaceXXX/attestation-freshness-guard/internal/evidence"
	"github.com/PeaceXXX/attestation-freshness-guard/internal/policy"
	"github.com/PeaceXXX/attestation-freshness-guard/internal/store"
)

// Check is the outcome of one rule.
type Check struct {
	Name   string `json:"name"`
	Passed bool   `json:"passed"`
	Detail string `json:"detail"`
}

// Verdict is the full, explainable outcome for one evidence document.
type Verdict struct {
	Allowed  bool      `json:"allowed"`
	QuoteID  string    `json:"quote_id"`
	Checks   []Check   `json:"checks"`
	Reason   string    `json:"reason"`
	Verified time.Time `json:"verified_at"`
}

// Verifier holds the policy, the replay ledger, and the demo signing key.
type Verifier struct {
	Policy policy.Policy
	Store  *store.Store
	Key    []byte
	Now    func() time.Time // overridable for tests; defaults to time.Now
}

func (v *Verifier) now() time.Time {
	if v.Now != nil {
		return v.Now()
	}
	return time.Now().UTC()
}

// Verify runs every check against ev. challenge is the nonce the relying
// party issued for this session; it is ignored when the policy does not
// require a nonce.
func (v *Verifier) Verify(ev evidence.Evidence, challenge string) Verdict {
	now := v.now()
	verdict := Verdict{QuoteID: ev.QuoteID, Verified: now}
	fail := func(name, detail string) {
		verdict.Checks = append(verdict.Checks, Check{Name: name, Passed: false, Detail: detail})
	}

	// 1. Authenticity first: nothing else matters if the evidence is forged,
	// and an unverified quote must not enter the replay ledger.
	if !ev.VerifySignature(v.Key) {
		fail("signature", "HMAC signature does not match the evidence (tampered or wrong key)")
		verdict.Reason = "signature verification failed"
		return verdict
	}
	verdict.Checks = append(verdict.Checks, Check{Name: "signature", Passed: true, Detail: "HMAC signature valid"})

	// Record the quote as presented from here on: a signed quote is
	// single-use even if a later check denies it. Capture the workload's
	// previous sequence first: the sequence check must compare against
	// the value from before this quote.
	alreadySeen := v.Store.Seen(ev.QuoteID)
	lastSeq, hadSeq := v.Store.LastSequence(ev.WorkloadID)
	if err := v.Store.Record(ev.QuoteID, ev.WorkloadID, ev.Sequence); err != nil {
		fail("replay-store", fmt.Sprintf("could not record quote: %v", err))
		verdict.Reason = "replay ledger unavailable; failing closed"
		return verdict
	}

	// 2. Nonce binding: the quote must answer this session's challenge.
	if v.Policy.RequireNonce {
		switch {
		case challenge == "":
			fail("nonce-binding", "policy requires a nonce but no challenge was supplied to the verifier")
		case ev.Nonce != challenge:
			fail("nonce-binding", fmt.Sprintf("quote nonce %q does not match challenge %q (quote belongs to another session)", ev.Nonce, challenge))
		default:
			verdict.Checks = append(verdict.Checks, Check{Name: "nonce-binding", Passed: true, Detail: "quote nonce matches the session challenge"})
		}
	}

	// 3. Freshness: age and clock skew.
	age := now.Sub(ev.GeneratedAt)
	switch {
	case ev.GeneratedAt.After(now.Add(v.Policy.MaxSkew)):
		fail("freshness", fmt.Sprintf("quote timestamp %s is %s ahead of verifier clock (max skew %s)", ev.GeneratedAt.Format(time.RFC3339), ev.GeneratedAt.Sub(now).Round(time.Second), v.Policy.MaxSkew))
	case age > v.Policy.MaxAge:
		fail("freshness", fmt.Sprintf("quote is %s old, older than max age %s", age.Round(time.Second), v.Policy.MaxAge))
	default:
		verdict.Checks = append(verdict.Checks, Check{Name: "freshness", Passed: true, Detail: fmt.Sprintf("quote age %s within max age %s", age.Round(time.Second), v.Policy.MaxAge)})
	}

	// 4. Replay: this quote ID must be new.
	if alreadySeen {
		fail("replay", fmt.Sprintf("quote_id %q was already presented; refusing a replay", ev.QuoteID))
	} else {
		verdict.Checks = append(verdict.Checks, Check{Name: "replay", Passed: true, Detail: "quote_id not seen before"})
	}

	// 5. Sequence: strictly increasing per workload. Record only advances
	// the stored high-water mark when the new sequence is higher, so
	// lastSeq is the high before this quote arrived.
	if hadSeq && ev.Sequence <= lastSeq {
		fail("sequence", fmt.Sprintf("sequence %d does not exceed last seen %d for workload %q", ev.Sequence, lastSeq, ev.WorkloadID))
	} else {
		verdict.Checks = append(verdict.Checks, Check{Name: "sequence", Passed: true, Detail: fmt.Sprintf("sequence %d advances workload %q", ev.Sequence, ev.WorkloadID)})
	}

	// 6. TCB floor.
	if ev.TCBSVN < v.Policy.MinTCBSVN {
		fail("tcb-floor", fmt.Sprintf("TCB SVN %d is below the required minimum %d (platform under-patched)", ev.TCBSVN, v.Policy.MinTCBSVN))
	} else {
		verdict.Checks = append(verdict.Checks, Check{Name: "tcb-floor", Passed: true, Detail: fmt.Sprintf("TCB SVN %d meets minimum %d", ev.TCBSVN, v.Policy.MinTCBSVN)})
	}

	for _, c := range verdict.Checks {
		if !c.Passed {
			verdict.Allowed = false
			verdict.Reason = c.Detail
			return verdict
		}
	}
	verdict.Allowed = true
	verdict.Reason = "all freshness checks passed"
	return verdict
}
