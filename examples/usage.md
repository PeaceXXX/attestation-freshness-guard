# Usage examples

## Verify one evidence file

```bash
go build -o freshguard ./cmd/freshguard
./freshguard gen-sample --out data/samples

./freshguard verify \
  --evidence data/samples/fresh-valid.json \
  --policy data/policy.json \
  --challenge challenge-2026-11-16-0936 \
  --store /tmp/freshguard-replay.json
```

Exit code 0 means ALLOW; exit code 1 means DENY. Add `--json` for the
machine-readable verdict.

## Run the attack demo

```bash
make demo
```

Five scenarios: fresh quote (ALLOW), replay of the same quote (DENY),
30-minute-old quote (DENY), quote bound to another session's nonce (DENY),
under-patched platform (DENY).

## Serve the HTTP API

```bash
./freshguard serve --addr :8080 --policy data/policy.json --store /tmp/freshguard-replay.json
```

```bash
curl -s -X POST localhost:8080/v1/verify \
  -H 'Content-Type: application/json' \
  -d "{\"evidence\": $(cat data/samples/fresh-valid.json), \"challenge\": \"challenge-2026-11-16-0936\"}"
```

A denied verdict returns HTTP 403 with the same verdict JSON body.

## Sign your own evidence

```bash
# Edit the fields in a copy of a sample, then sign it:
cp data/samples/fresh-valid.json /tmp/mine.json
./freshguard sign --in /tmp/mine.json
./freshguard verify --evidence /tmp/mine.json --policy data/policy.json \
  --challenge challenge-2026-11-16-0936
```

The key comes from `--key` or `FRESHGUARD_KEY`. The default demo key is
public and only makes tampering detectable in a demo; it authenticates
nothing in production.
