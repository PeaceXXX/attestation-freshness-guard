// Package evidence defines the attestation-evidence document this project
// verifies, plus the demo HMAC signing used to make sample evidence
// tamper-evident.
//
// The document is deliberately a small, self-contained JSON object: it
// carries the fields a relying party needs to answer "is this quote fresh
// and is it mine?" without parsing a full TDX quote. In a real deployment
// these fields would be extracted from a real quote (see the README's
// "How this maps to a real TDX quote" section); here they are carried
// explicitly so the freshness logic can be exercised and tested in isolation.
//
// Clean-room note: every field is a public concept (quote id, timestamp,
// nonce, sequence number, TCB SVN). No Intel-internal data is involved.
package evidence

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
)

// Evidence is one attestation claim presented by a workload to a relying party.
type Evidence struct {
	// QuoteID uniquely identifies this quote. A quote ID must never be
	// accepted twice: that is the replay rule.
	QuoteID string `json:"quote_id"`
	// WorkloadID identifies the workload (VM, container, agent sandbox)
	// the quote speaks for. Sequence numbers are tracked per workload.
	WorkloadID string `json:"workload_id"`
	// GeneratedAt is when the quote was produced, in UTC.
	GeneratedAt time.Time `json:"generated_at"`
	// Nonce is the challenge the relying party issued for this session.
	// A quote is bound to exactly one challenge.
	Nonce string `json:"nonce"`
	// Sequence is a per-workload monotonic counter. It must strictly
	// increase: a lower-or-equal value means an old quote is being replayed.
	Sequence uint64 `json:"sequence"`
	// TCBSVN is the platform TCB security-version level the quote reports.
	TCBSVN uint32 `json:"tcb_svn"`
	// ReportData is a hex digest of the workload's report data (e.g. a
	// measurement of the code that is running). It is opaque here.
	ReportData string `json:"report_data"`
	// Signature is an HMAC-SHA256 over the canonical form of the fields
	// above, hex-encoded. Demo-grade authenticity only: it proves the
	// sample was produced by whoever holds the demo key, and it makes
	// tampering detectable. It is NOT a substitute for real ECDSA quote
	// signature verification (see README).
	Signature string `json:"signature,omitempty"`
}

// canonical returns the exact byte string that is signed: one field per line,
// fixed order, timestamps in UTC RFC3339. Any change to any field changes
// the signature.
func (e Evidence) canonical() string {
	return fmt.Sprintf(
		"quote_id=%s\nworkload_id=%s\ngenerated_at=%s\nnonce=%s\nsequence=%d\ntcb_svn=%d\nreport_data=%s\n",
		e.QuoteID, e.WorkloadID,
		e.GeneratedAt.UTC().Format(time.RFC3339),
		e.Nonce, e.Sequence, e.TCBSVN, e.ReportData,
	)
}

// Sign computes the HMAC-SHA256 of the canonical form with key and stores it.
func (e *Evidence) Sign(key []byte) {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(e.canonical()))
	e.Signature = hex.EncodeToString(mac.Sum(nil))
}

// VerifySignature reports whether Signature matches the canonical form
// under key. A missing signature never verifies.
func (e Evidence) VerifySignature(key []byte) bool {
	if e.Signature == "" {
		return false
	}
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(e.canonical()))
	want := mac.Sum(nil)
	got, err := hex.DecodeString(e.Signature)
	if err != nil {
		return false
	}
	return hmac.Equal(got, want)
}

// MarshalJSON renders the evidence with generated_at in RFC3339 UTC.
func (e Evidence) MarshalJSON() ([]byte, error) {
	type shadow struct {
		QuoteID     string `json:"quote_id"`
		WorkloadID  string `json:"workload_id"`
		GeneratedAt string `json:"generated_at"`
		Nonce       string `json:"nonce"`
		Sequence    uint64 `json:"sequence"`
		TCBSVN      uint32 `json:"tcb_svn"`
		ReportData  string `json:"report_data"`
		Signature   string `json:"signature,omitempty"`
	}
	return json.Marshal(shadow{
		QuoteID:     e.QuoteID,
		WorkloadID:  e.WorkloadID,
		GeneratedAt: e.GeneratedAt.UTC().Format(time.RFC3339),
		Nonce:       e.Nonce,
		Sequence:    e.Sequence,
		TCBSVN:      e.TCBSVN,
		ReportData:  e.ReportData,
		Signature:   e.Signature,
	})
}

// UnmarshalJSON parses evidence, accepting RFC3339 timestamps.
func (e *Evidence) UnmarshalJSON(data []byte) error {
	type shadow struct {
		QuoteID     string `json:"quote_id"`
		WorkloadID  string `json:"workload_id"`
		GeneratedAt string `json:"generated_at"`
		Nonce       string `json:"nonce"`
		Sequence    uint64 `json:"sequence"`
		TCBSVN      uint32 `json:"tcb_svn"`
		ReportData  string `json:"report_data"`
		Signature   string `json:"signature,omitempty"`
	}
	var s shadow
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	t, err := time.Parse(time.RFC3339, s.GeneratedAt)
	if err != nil {
		return fmt.Errorf("generated_at: %w", err)
	}
	*e = Evidence{
		QuoteID:     s.QuoteID,
		WorkloadID:  s.WorkloadID,
		GeneratedAt: t,
		Nonce:       s.Nonce,
		Sequence:    s.Sequence,
		TCBSVN:      s.TCBSVN,
		ReportData:  s.ReportData,
		Signature:   s.Signature,
	}
	return nil
}
