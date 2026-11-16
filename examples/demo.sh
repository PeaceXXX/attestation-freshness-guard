#!/usr/bin/env bash
# Demo: four attack scenarios against the freshness verifier.
# Run from the repo root:  make demo
# Expects: ./freshguard built, data/samples generated, data/policy.json present.
set -u
BIN=./freshguard
STORE=/tmp/freshguard-replay.json
CHALLENGE=challenge-2026-11-16-0936
rm -f "$STORE"

section() { echo; echo "=== $1 ==="; }

section "1. Fresh, valid quote -> ALLOW"
"$BIN" verify --evidence data/samples/fresh-valid.json \
  --policy data/policy.json --challenge "$CHALLENGE" --store "$STORE" || true

section "2. Replay the exact same quote -> DENY (replay)"
"$BIN" verify --evidence data/samples/fresh-valid.json \
  --policy data/policy.json --challenge "$CHALLENGE" --store "$STORE" || true

section "3. Stale quote (30 min old, max age 5m) -> DENY (freshness)"
"$BIN" verify --evidence data/samples/stale.json \
  --policy data/policy.json --challenge "$CHALLENGE" --store "$STORE" || true

section "4. Quote bound to another session's nonce -> DENY (nonce-binding)"
"$BIN" verify --evidence data/samples/wrong-nonce.json \
  --policy data/policy.json --challenge "$CHALLENGE" --store "$STORE" || true

section "5. Under-patched platform (TCB SVN 2 < minimum 5) -> DENY (tcb-floor)"
"$BIN" verify --evidence data/samples/under-patched.json \
  --policy data/policy.json --challenge "$CHALLENGE" --store "$STORE" || true

section "Replay ledger after the demo:"
cat "$STORE"
