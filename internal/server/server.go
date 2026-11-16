// Package server exposes the verifier as a small HTTP API so a relying
// party (an admission controller, a gateway, an agent sandbox) can ask
// "is this evidence fresh?" over the network instead of shelling out.
//
//	POST /v1/verify   {"evidence": {...}, "challenge": "nonce"} -> Verdict JSON
//	GET  /healthz     {"status":"ok"}
//
// The server is intentionally boring: stdlib net/http only, no framework.
// Authentication is out of scope for the demo; in production this endpoint
// sits behind mTLS and the demo HMAC key is replaced by real quote
// verification (see README).
package server

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/PeaceXXX/attestation-freshness-guard/internal/evidence"
	"github.com/PeaceXXX/attestation-freshness-guard/internal/verifier"
)

// Server wraps a Verifier with HTTP handlers.
type Server struct {
	Verifier *verifier.Verifier
	Logger   *log.Logger
}

type verifyRequest struct {
	Evidence  evidence.Evidence `json:"evidence"`
	Challenge string            `json:"challenge"`
}

func (s *Server) handleVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req verifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}
	v := s.Verifier.Verify(req.Evidence, req.Challenge)
	w.Header().Set("Content-Type", "application/json")
	if !v.Allowed {
		w.WriteHeader(http.StatusForbidden)
	}
	if err := json.NewEncoder(w).Encode(v); err != nil {
		s.Logger.Printf("encode verdict: %v", err)
	}
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"status":"ok"}` + "\n"))
}

// Handler returns the mux for the API.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/verify", s.handleVerify)
	mux.HandleFunc("/healthz", s.handleHealth)
	return mux
}
