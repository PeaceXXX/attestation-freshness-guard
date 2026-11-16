// Package store is the replay ledger. A quote ID, once presented, is
// single-use: presenting it again is a replay attack, whatever else about
// the quote is true.
//
// The store also tracks the highest sequence number seen per workload, so a
// quote with a stale sequence can be rejected even if its quote ID is new.
//
// The file-backed store persists across restarts (a verifier that forgets
// every replay on restart is not a verifier). The file is JSON, written
// atomically via rename, and small enough for a demo: a production service
// would use a database with TTL expiry instead.
package store

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// Store is a replay ledger, safe for concurrent use.
type Store struct {
	mu       sync.Mutex
	path     string
	seen     map[string]bool   // quote_id -> presented before
	sequence map[string]uint64 // workload_id -> highest sequence seen
}

// New returns an empty in-memory store. If path is non-empty, the store is
// loaded from that file when it exists and persisted back to it on every
// mutation.
func New(path string) (*Store, error) {
	s := &Store{
		path:     path,
		seen:     map[string]bool{},
		sequence: map[string]uint64{},
	}
	if path == "" {
		return s, nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return s, nil
		}
		return nil, err
	}
	var saved struct {
		Seen     []string          `json:"seen_quote_ids"`
		Sequence map[string]uint64 `json:"workload_sequence"`
	}
	if err := json.Unmarshal(raw, &saved); err != nil {
		return nil, fmt.Errorf("parsing store %s: %w", path, err)
	}
	for _, id := range saved.Seen {
		s.seen[id] = true
	}
	for w, seq := range saved.Sequence {
		s.sequence[w] = seq
	}
	return s, nil
}

// Seen reports whether quoteID has been presented before.
func (s *Store) Seen(quoteID string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.seen[quoteID]
}

// LastSequence returns the highest sequence recorded for a workload,
// and whether any quote from that workload has been seen.
func (s *Store) LastSequence(workloadID string) (uint64, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	seq, ok := s.sequence[workloadID]
	return seq, ok
}

// Record marks a quote as presented and advances the workload's sequence.
// It persists the store if file-backed. Callers record a quote only after
// its signature has verified: an unsigned forgery must not be able to
// poison the ledger and block the genuine quote.
func (s *Store) Record(quoteID, workloadID string, sequence uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.seen[quoteID] = true
	if sequence > s.sequence[workloadID] {
		s.sequence[workloadID] = sequence
	}
	return s.persistLocked()
}

func (s *Store) persistLocked() error {
	if s.path == "" {
		return nil
	}
	seen := make([]string, 0, len(s.seen))
	for id := range s.seen {
		seen = append(seen, id)
	}
	raw, err := json.MarshalIndent(struct {
		Seen     []string          `json:"seen_quote_ids"`
		Sequence map[string]uint64 `json:"workload_sequence"`
	}{Seen: seen, Sequence: s.sequence}, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}
