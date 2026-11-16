// Package policy loads the relying party's freshness policy: how old a
// quote may be, how much clock skew is tolerated, and which TCB floor a
// workload must meet before its evidence is trusted.
package policy

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// Policy is the relying party's freshness contract.
type Policy struct {
	// MaxAge is the oldest a quote may be at verification time.
	// A quote generated longer ago than this is stale, however valid
	// its signature is. Default: 5 minutes.
	MaxAge time.Duration `json:"max_age"`
	// MaxSkew is how far in the future a quote's timestamp may sit
	// relative to the verifier's clock before it is rejected as
	// impossible (a sign of a lying clock or a forged timestamp).
	// Default: 30 seconds.
	MaxSkew time.Duration `json:"max_skew"`
	// MinTCBSVN is the lowest platform TCB security-version level the
	// relying party accepts. Below this, the platform is considered
	// under-patched even if the quote is fresh.
	MinTCBSVN uint32 `json:"min_tcb_svn"`
	// RequireNonce, when true, demands that the quote carry the exact
	// challenge nonce the relying party issued for this session.
	RequireNonce bool `json:"require_nonce"`
}

// Default returns the policy used when no file is supplied.
func Default() Policy {
	return Policy{
		MaxAge:       5 * time.Minute,
		MaxSkew:      30 * time.Second,
		MinTCBSVN:    0,
		RequireNonce: true,
	}
}

// Load reads a policy file. Durations are JSON strings such as "5m" or "30s".
// Missing fields keep their defaults.
func Load(path string) (Policy, error) {
	p := Default()
	if path == "" {
		return p, nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return p, err
	}
	var file struct {
		MaxAge       string  `json:"max_age"`
		MaxSkew      string  `json:"max_skew"`
		MinTCBSVN    *uint32 `json:"min_tcb_svn"`
		RequireNonce *bool   `json:"require_nonce"`
	}
	if err := json.Unmarshal(raw, &file); err != nil {
		return p, fmt.Errorf("parsing %s: %w", path, err)
	}
	if file.MaxAge != "" {
		d, err := time.ParseDuration(file.MaxAge)
		if err != nil {
			return p, fmt.Errorf("max_age: %w", err)
		}
		p.MaxAge = d
	}
	if file.MaxSkew != "" {
		d, err := time.ParseDuration(file.MaxSkew)
		if err != nil {
			return p, fmt.Errorf("max_skew: %w", err)
		}
		p.MaxSkew = d
	}
	if file.MinTCBSVN != nil {
		p.MinTCBSVN = *file.MinTCBSVN
	}
	if file.RequireNonce != nil {
		p.RequireNonce = *file.RequireNonce
	}
	if p.MaxAge <= 0 {
		return p, fmt.Errorf("max_age must be positive, got %s", p.MaxAge)
	}
	if p.MaxSkew < 0 {
		return p, fmt.Errorf("max_skew must not be negative, got %s", p.MaxSkew)
	}
	return p, nil
}
