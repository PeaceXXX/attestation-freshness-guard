package evidence

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestSignVerifyRoundTrip(t *testing.T) {
	ev := Evidence{
		QuoteID: "q-1", WorkloadID: "w-1",
		GeneratedAt: time.Date(2026, 11, 16, 9, 0, 0, 0, time.UTC),
		Nonce:       "n-1", Sequence: 1, TCBSVN: 7, ReportData: "abcd",
	}
	key := []byte("k")
	ev.Sign(key)
	if !ev.VerifySignature(key) {
		t.Fatal("freshly signed evidence must verify")
	}
	if ev.VerifySignature([]byte("wrong")) {
		t.Fatal("wrong key must not verify")
	}
	ev.Nonce = "n-2"
	if ev.VerifySignature(key) {
		t.Fatal("tampered evidence must not verify")
	}
}

func TestJSONRoundTrip(t *testing.T) {
	ev := Evidence{
		QuoteID: "q-1", WorkloadID: "w-1",
		GeneratedAt: time.Date(2026, 11, 16, 9, 0, 0, 0, time.UTC),
		Nonce:       "n-1", Sequence: 1, TCBSVN: 7, ReportData: "abcd",
	}
	ev.Sign([]byte("k"))
	raw, err := json.Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"generated_at":"2026-11-16T09:00:00Z"`) {
		t.Fatalf("expected RFC3339 timestamp in JSON, got %s", raw)
	}
	var back Evidence
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}
	if back.QuoteID != ev.QuoteID || !back.GeneratedAt.Equal(ev.GeneratedAt) || back.Signature != ev.Signature {
		t.Fatalf("round trip mismatch: %+v vs %+v", back, ev)
	}
	if !back.VerifySignature([]byte("k")) {
		t.Fatal("signature must survive a JSON round trip")
	}
}
