# attestation-freshness-guard

A relying-party freshness verifier for attestation evidence: it answers
"is this quote fresh, is it mine, and has it been used before?" — the
questions signature verification alone cannot answer.

Go, stdlib-only. CLI + HTTP API. No external dependencies.

## Why this exists

A structurally valid attestation quote can still be untrustworthy. That
point stopped being theoretical in the confidential-computing community
this autumn: the **DDROP** attack showed a freshness gap in TDX and SEV
— a quote can be perfectly well-formed yet stale, its TCB levels lagging
behind current patch levels — and the conversation in the Intel
Confidential Computing sphere shifted from "does it work?" to "how do
you prove it?" (see e.g. the DDrop threads and the "from does it work to
how prove it" discussion circulating on LinkedIn in early November 2026).

This project is the relying-party half of that answer. It takes an
attestation claim and enforces the time dimension:

- **Nonce binding** — the quote must answer *this* session's challenge,
  not a challenge issued to someone else.
- **Freshness** — the quote must be younger than `max_age` (default 5m)
  and not impossibly far in the future (beyond `max_skew`).
- **Replay protection** — a quote ID is single-use. Presenting it twice
  is a replay, even if the first presentation was denied for staleness.
- **Sequence monotonicity** — a per-workload counter must strictly
  increase, so an old quote cannot be smuggled back in under a new ID.
- **TCB floor** — the reported TCB SVN must meet the policy minimum, so
  an under-patched platform cannot hide behind a fresh timestamp.

It complements, and does not duplicate, the sibling projects in this
series: `tdx-quote-parser` decodes what a quote *says*, `tdx-tcb-gate`
decides whether a platform is *patched enough*, and this one decides
whether the evidence is *fresh enough and really for this session*.

> **Clean-room statement.** All concepts here are public: quote IDs,
> timestamps, nonces, sequence numbers and TCB SVN levels are standard
> attestation concepts, and every evidence file in `data/samples/` is
> synthetic, generated deterministically by `freshguard gen-sample` and
> marked by its obviously fake IDs. No Intel-internal code, APIs, or
> non-public details are used or implied.

## Architecture

```
                    +---------------------------+
                    |  data/policy.json         |  max_age 5m,
                    |  max_skew 30s, min_tcb 5  |  require_nonce
                    +-------------+-------------+
                                  |
  +------------------+            v            +------------------+
  | evidence JSON    | ->  internal/verifier  -> | verdict:         |
  | quote_id,        |     1 signature        |   allowed bool    |
  | generated_at,    |     2 nonce-binding    |   6 named checks  |
  | nonce, sequence, |     3 freshness        |   with reasons    |
  | tcb_svn,          |     4 replay           +------------------+
  | report_data,     |     5 sequence              |        |
  | signature (HMAC) |     6 tcb-floor             v        v
  +------------------+    fail-closed      CLI   HTTP API
                          (any fail = DENY)  |  POST /v1/verify
                                  |           v
                          +------------------+
                          | internal/store   |  replay ledger:
                          | seen quote IDs + |  JSON file, atomic
                          | per-workload seq |  write via rename
                          +------------------+
```

The verifier is fail-closed: any failing check denies the evidence, and
a denial names the check that failed and why. A quote is recorded in the
replay ledger as soon as its signature verifies — so a signed quote is
single-use even if its first presentation was denied for staleness.
An unsigned forgery is never recorded: it must not be able to poison
the ledger and block the genuine quote.

## Quickstart

```bash
go build -o freshguard ./cmd/freshguard
./freshguard gen-sample --out data/samples   # samples are time-sensitive: regenerate if stale

# 1. Fresh, valid quote -> ALLOW
./freshguard verify --evidence data/samples/fresh-valid.json \
  --policy data/policy.json \
  --challenge challenge-2026-11-16-0936 \
  --store /tmp/freshguard-replay.json

# 2. Replay the same quote -> DENY (replay)
./freshguard verify --evidence data/samples/fresh-valid.json \
  --policy data/policy.json \
  --challenge challenge-2026-11-16-0936 \
  --store /tmp/freshguard-replay.json

# 3-5. Stale quote, wrong-nonce quote, under-patched platform -> DENY
./freshguard verify --evidence data/samples/stale.json \
  --policy data/policy.json --challenge challenge-2026-11-16-0936
./freshguard verify --evidence data/samples/wrong-nonce.json \
  --policy data/policy.json --challenge challenge-2026-11-16-0936
./freshguard verify --evidence data/samples/under-patched.json \
  --policy data/policy.json --challenge challenge-2026-11-16-0936
```

Or run all five scenarios at once:

```bash
make demo
```

Exit code 0 means ALLOW; exit code 1 means DENY. Add `--json` for the
machine-readable verdict. `--now RFC3339` overrides the verification
clock (useful for demos and tests).

### HTTP API

```bash
./freshguard serve --addr :8080 --policy data/policy.json --store /tmp/freshguard-replay.json

curl -s -X POST localhost:8080/v1/verify -H 'Content-Type: application/json' \
  -d "{\"evidence\": $(cat data/samples/fresh-valid.json), \"challenge\": \"challenge-2026-11-16-0936\"}"
```

| Endpoint | Method | Description |
|---|---|---|
| `/v1/verify` | POST | `{"evidence": {...}, "challenge": "..."}` → verdict JSON. HTTP 200 on ALLOW, 403 on DENY. |
| `/healthz` | GET | `{"status":"ok"}` |

### Docker

```bash
docker build -t freshguard .
docker run -p 8080:8080 freshguard
```

## API reference

### Evidence document (`internal/evidence`)

| Field | Meaning |
|---|---|
| `quote_id` | Unique ID of this quote. Single-use: never accepted twice. |
| `workload_id` | Workload the quote speaks for (VM, container, agent sandbox). Sequence numbers are tracked per workload. |
| `generated_at` | When the quote was produced (UTC, RFC3339). |
| `nonce` | The challenge the relying party issued for this session. |
| `sequence` | Per-workload monotonic counter; must strictly increase. |
| `tcb_svn` | Platform TCB security-version level the quote reports. |
| `report_data` | Hex digest of the workload's report data (opaque here). |
| `signature` | HMAC-SHA256 over the canonical form of the fields above. |

### Policy (`data/policy.json`)

| Field | Default | Meaning |
|---|---|---|
| `max_age` | `5m` | Oldest a quote may be at verification time. |
| `max_skew` | `30s` | How far in the future a quote timestamp may sit before it is rejected as impossible. |
| `min_tcb_svn` | `5` | Lowest TCB SVN accepted. |
| `require_nonce` | `true` | Demand the quote carry the session challenge. |

### CLI

| Command | Purpose |
|---|---|
| `gen-sample --out DIR` | Generate the four sample evidence files. |
| `sign --in FILE` | (Re-)sign an evidence JSON with the HMAC key. |
| `verify --evidence F --policy F --challenge N [--store F] [--json] [--now T]` | Verify one evidence file; exit 0 ALLOW / 1 DENY. |
| `serve --addr :8080 [--policy F] [--store F]` | Run the HTTP API. |

The HMAC key comes from `--key` or `FRESHGUARD_KEY`. The built-in
default is a public demo key: it makes samples tamper-evident, it
authenticates nothing. **In production the HMAC is replaced by real
ECDSA quote signature verification** (see Limitations).

## What this demonstrates

Interview talking points this project is built to support:

- **Fail-closed design.** Every check is independent and explainable;
  one failure denies the whole verdict, and the denial names the rule.
  The ledger records a quote once its signature verifies, so a replay
  is caught even when the first attempt was denied for another reason.
- **The freshness gap is a real attack surface.** DDrop showed that
  "valid signature" and "trustworthy evidence" are different claims.
  The fix is not a better parser; it is a relying party that binds
  evidence to a session (nonce), to a time window (max age), and to a
  single use (replay ledger).
- **Replay protection needs persistence.** An in-memory seen-set that
  dies with the process is not a control. The ledger here is a JSON
  file written atomically, so a restart does not resurrect spent quotes.
- **Time is a trust input, not a log field.** Clock skew is bounded
  explicitly; a quote from the future is rejected rather than trusted.
- **Separation of concerns.** Parsing (what the quote says), TCB
  gating (is the platform patched), and freshness (is this evidence
  current and mine) are three different decisions, in three different
  components, that compose into one verdict.

## Limitations / how I'd productionize it

- **Demo HMAC, not real quote verification.** The signature here is an
  HMAC with a shared demo key. Production replaces it with ECDSA
  verification against the quote's certificate chain and collateral
  (PCK certs, TCB info, CRLs), as in `tdx-quote-parser`, and the
  freshness checks then run on the verified fields.
- **Single-node ledger.** The JSON-file store is correct for one
  verifier process. A fleet of verifiers needs a shared store with
  atomic compare-and-swap (Redis, etcd, or a database) so two replicas
  cannot both accept the same quote.
- **No TTL expiry.** Seen quote IDs accumulate forever. Production adds
  expiry (e.g. drop IDs older than `max_age` plus a safety margin) and
  compaction.
- **No authenticated transport.** The HTTP API has no auth. In
  production it sits behind mTLS, and the challenge nonce is issued
  per session by the relying party, never accepted from the prover.
- **Clock trust.** Freshness assumes the verifier's clock is sound.
  Production runs NTP with monitoring and alerts on skew, and treats
  sustained skew as a verifier-health failure, not a data problem.
- **Sequence is advisory without a registry.** A sequence only proves
  ordering if the relying party knows the workload's starting point.
  Production pairs it with workload registration and attested boot
  measurements.

## Tests

```bash
go test ./...   # verifier: 8 scenarios; evidence: sign/verify + JSON round trip
go vet ./...
```
