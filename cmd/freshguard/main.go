// Command freshguard is the CLI for attestation-freshness-guard: a
// relying-party freshness verifier for attestation evidence.
//
//	freshguard gen-sample --out data/samples [--key ...]
//	freshguard sign --in evidence.json [--key ...]
//	freshguard verify --evidence evidence.json --policy data/policy.json \
//	   --challenge <nonce> [--store /tmp/replay.json] [--now RFC3339]
//	freshguard serve --addr :8080 --policy data/policy.json [--store ...]
//
// The demo HMAC key defaults to a well-known value and is read from
// --key or the FRESHGUARD_KEY environment variable. It is demo-grade only:
// it makes samples tamper-evident, it does not authenticate a real TDX
// quote. See README for how this maps to real ECDSA quote verification.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/PeaceXXX/attestation-freshness-guard/internal/evidence"
	"github.com/PeaceXXX/attestation-freshness-guard/internal/policy"
	"github.com/PeaceXXX/attestation-freshness-guard/internal/server"
	"github.com/PeaceXXX/attestation-freshness-guard/internal/store"
	"github.com/PeaceXXX/attestation-freshness-guard/internal/verifier"
)

const defaultKey = "freshguard-demo-key-do-not-use-in-production"

func keyFromFlag(v string) []byte {
	if v != "" {
		return []byte(v)
	}
	if env := os.Getenv("FRESHGUARD_KEY"); env != "" {
		return []byte(env)
	}
	return []byte(defaultKey)
}

func loadEvidence(path string) (evidence.Evidence, error) {
	var ev evidence.Evidence
	raw, err := os.ReadFile(path)
	if err != nil {
		return ev, err
	}
	if err := json.Unmarshal(raw, &ev); err != nil {
		return ev, fmt.Errorf("parsing %s: %w", path, err)
	}
	return ev, nil
}

func writeEvidence(path string, ev evidence.Evidence) error {
	raw, err := json.MarshalIndent(ev, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, append(raw, '\n'), 0o644)
}

func newVerifier(policyPath, storePath string, key []byte) (*verifier.Verifier, error) {
	p, err := policy.Load(policyPath)
	if err != nil {
		return nil, err
	}
	s, err := store.New(storePath)
	if err != nil {
		return nil, err
	}
	return &verifier.Verifier{Policy: p, Store: s, Key: key}, nil
}

func cmdGenSample(fs *flag.FlagSet, args []string) error {
	out := fs.String("out", "data/samples", "output directory for sample evidence")
	keyFlag := fs.String("key", "", "HMAC key (default: FRESHGUARD_KEY or demo key)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	key := keyFromFlag(*keyFlag)
	now := time.Now().UTC().Truncate(time.Second)
	reportHash := sha256.Sum256([]byte("agent-sandbox-01:41"))
	base := evidence.Evidence{
		WorkloadID: "agent-sandbox-01",
		Nonce:      "challenge-2026-11-16-0936",
		Sequence:   41,
		TCBSVN:     7,
		ReportData: hex.EncodeToString(reportHash[:]),
	}
	samples := []struct {
		name string
		ev   evidence.Evidence
	}{
		{"fresh-valid.json", func() evidence.Evidence {
			e := base
			e.QuoteID = "q-fresh-0001"
			e.GeneratedAt = now.Add(-45 * time.Second)
			e.Sign(key)
			return e
		}()},
		{"stale.json", func() evidence.Evidence {
			e := base
			e.QuoteID = "q-stale-0002"
			e.GeneratedAt = now.Add(-30 * time.Minute) // older than default 5m max age
			e.Sequence = 42
			e.Sign(key)
			return e
		}()},
		{"wrong-nonce.json", func() evidence.Evidence {
			e := base
			e.QuoteID = "q-nonce-0003"
			e.GeneratedAt = now.Add(-20 * time.Second)
			e.Nonce = "challenge-someone-elses-session"
			e.Sequence = 43
			e.Sign(key)
			return e
		}()},
		{"under-patched.json", func() evidence.Evidence {
			e := base
			e.QuoteID = "q-tcb-0004"
			e.GeneratedAt = now.Add(-20 * time.Second)
			e.TCBSVN = 2 // below the data/policy.json minimum of 5
			e.Sequence = 44
			e.Sign(key)
			return e
		}()},
	}
	for _, s := range samples {
		path := filepath.Join(*out, s.name)
		if err := writeEvidence(path, s.ev); err != nil {
			return err
		}
		fmt.Printf("wrote %s\n", path)
	}
	return nil
}

func cmdSign(fs *flag.FlagSet, args []string) error {
	in := fs.String("in", "", "evidence JSON to sign (signature field is overwritten)")
	keyFlag := fs.String("key", "", "HMAC key (default: FRESHGUARD_KEY or demo key)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *in == "" {
		return fmt.Errorf("--in is required")
	}
	ev, err := loadEvidence(*in)
	if err != nil {
		return err
	}
	ev.Sign(keyFromFlag(*keyFlag))
	if err := writeEvidence(*in, ev); err != nil {
		return err
	}
	fmt.Printf("signed %s (quote_id=%s)\n", *in, ev.QuoteID)
	return nil
}

func cmdVerify(fs *flag.FlagSet, args []string) error {
	evPath := fs.String("evidence", "", "evidence JSON file")
	policyPath := fs.String("policy", "", "policy JSON file (default policy if empty)")
	storePath := fs.String("store", "", "replay ledger file (in-memory only if empty)")
	challenge := fs.String("challenge", "", "challenge nonce the quote must answer")
	keyFlag := fs.String("key", "", "HMAC key (default: FRESHGUARD_KEY or demo key)")
	nowFlag := fs.String("now", "", "override verification time (RFC3339, for demos/tests)")
	jsonOut := fs.Bool("json", false, "print the raw verdict JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *evPath == "" {
		return fmt.Errorf("--evidence is required")
	}
	ev, err := loadEvidence(*evPath)
	if err != nil {
		return err
	}
	v, err := newVerifier(*policyPath, *storePath, keyFromFlag(*keyFlag))
	if err != nil {
		return err
	}
	if *nowFlag != "" {
		t, err := time.Parse(time.RFC3339, *nowFlag)
		if err != nil {
			return fmt.Errorf("--now: %w", err)
		}
		v.Now = func() time.Time { return t }
	}
	verdict := v.Verify(ev, *challenge)
	if *jsonOut {
		raw, _ := json.MarshalIndent(verdict, "", "  ")
		fmt.Println(string(raw))
	} else {
		status := "DENY"
		if verdict.Allowed {
			status = "ALLOW"
		}
		fmt.Printf("%s  quote_id=%s  verified_at=%s\n", status, verdict.QuoteID, verdict.Verified.Format(time.RFC3339))
		for _, c := range verdict.Checks {
			mark := "pass"
			if !c.Passed {
				mark = "FAIL"
			}
			fmt.Printf("  [%s] %-14s %s\n", mark, c.Name, c.Detail)
		}
		fmt.Printf("reason: %s\n", verdict.Reason)
	}
	if !verdict.Allowed {
		os.Exit(1)
	}
	return nil
}

func cmdServe(fs *flag.FlagSet, args []string) error {
	addr := fs.String("addr", ":8080", "listen address")
	policyPath := fs.String("policy", "", "policy JSON file (default policy if empty)")
	storePath := fs.String("store", "", "replay ledger file (in-memory only if empty)")
	keyFlag := fs.String("key", "", "HMAC key (default: FRESHGUARD_KEY or demo key)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	v, err := newVerifier(*policyPath, *storePath, keyFromFlag(*keyFlag))
	if err != nil {
		return err
	}
	srv := &server.Server{Verifier: v, Logger: log.Default()}
	log.Printf("freshguard listening on %s (policy max_age=%s, min_tcb_svn=%d)", *addr, v.Policy.MaxAge, v.Policy.MinTCBSVN)
	return http.ListenAndServe(*addr, srv.Handler())
}

func main() {
	log.SetFlags(0)
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: freshguard <gen-sample|sign|verify|serve> [flags]")
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "gen-sample":
		err = cmdGenSample(flag.NewFlagSet("gen-sample", flag.ExitOnError), os.Args[2:])
	case "sign":
		err = cmdSign(flag.NewFlagSet("sign", flag.ExitOnError), os.Args[2:])
	case "verify":
		err = cmdVerify(flag.NewFlagSet("verify", flag.ExitOnError), os.Args[2:])
	case "serve":
		err = cmdServe(flag.NewFlagSet("serve", flag.ExitOnError), os.Args[2:])
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n", os.Args[1])
		os.Exit(2)
	}
	if err != nil {
		log.Fatal(err)
	}
}
