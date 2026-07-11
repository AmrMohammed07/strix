---
name: race-conditions
description: Race condition testing for TOCTOU bugs, double-spend, and concurrent state manipulation
---

# Race Conditions

Concurrency bugs enable duplicate state changes, quota bypass, financial abuse, and privilege errors. Treat every read–modify–write and multi-step workflow as adversarially concurrent.

## Attack Surface

**Read-Modify-Write**
- Sequences without atomicity or proper locking

**Multi-Step Operations**
- Check → reserve → commit with gaps between phases

**Cross-Service Workflows**
- Sagas, async jobs with eventual consistency

**Rate Limits and Quotas**
- Controls implemented at the edge only

## High-Value Targets

- Payments: auth/capture/refund/void; credits/loyalty points; gift cards
- Coupons/discounts: single-use codes, stacking checks, per-user limits
- Quotas/limits: API usage, inventory reservations, seat counts, vote limits
- Auth flows: password reset/OTP consumption, session minting, device trust
- File/object storage: multi-part finalize, version writes, share-link generation
- Background jobs: export/import create/finalize endpoints; job cancellation/approve
- GraphQL mutations and batch operations; WebSocket actions

## Reconnaissance

### Identify Race Windows

- Look for explicit sequences: "check balance then deduct", "verify coupon then apply", "check inventory then purchase"
- Watch for optimistic concurrency markers: ETag/If-Match, version fields, updatedAt checks
- Examine idempotency-key support: scope (path vs principal), TTL, and persistence (cache vs DB)
- Map cross-service steps: when is state written vs published, what retries/compensations exist

### Signals

- Sequential request fails but parallel succeeds
- Duplicate rows, negative counters, over-issuance, or inconsistent aggregates
- Distinct response shapes/timings for simultaneous vs sequential requests
- Audit logs out of order; multiple 2xx for the same intent; missing or duplicate correlation IDs

## Key Vulnerabilities

### Request Synchronization

- HTTP/2 multiplexing for tight concurrency; send many requests on warmed connections
- Last-byte synchronization: hold requests open and release final byte simultaneously
- Connection warming: pre-establish sessions, cookies, and TLS to remove jitter

### Idempotency and Dedup Bypass

- Reuse the same idempotency key across different principals/paths if scope is inadequate
- Hit the endpoint before the idempotency store is written (cache-before-commit windows)
- App-level dedup drops only the response while side effects (emails/credits) still occur

### Atomicity Gaps

- Lost update: read-modify-write increments without atomic DB statements
- Partial two-phase workflows: success committed before validation completes
- Unique checks done outside a unique index/upsert: create duplicates under load

### Cross-Service Races

- Saga/compensation timing gaps: execute compensation without preventing the original success path
- Eventual consistency windows: act in Service B before Service A's write is visible
- Retry storms: duplicate side effects due to at-least-once delivery without idempotent consumers

### Rate Limits and Quotas

- Per-IP or per-connection enforcement: bypass with multiple IPs/sessions
- Counter updates not atomic or sharded inconsistently; send bursts before counters propagate

### Optimistic Concurrency Evasion

- Omit If-Match/ETag where optional; supply stale versions if server ignores them
- Version fields accepted but not validated across all code paths (e.g., GraphQL vs REST)

### Database Isolation

- Exploit READ COMMITTED/REPEATABLE READ anomalies: phantoms, non-serializable sequences
- Upsert races: use unique indexes with proper ON CONFLICT/UPSERT or exploit naive existence checks
- Lock granularity issues: row vs table; application locks held only in-process

### Distributed Locks

- Redis locks without NX/EX or fencing tokens allow multiple winners
- Locks stored in memory on a single node; bypass by hitting other nodes/regions

## Bypass Techniques

- Distribute across IPs, sessions, and user accounts to evade per-entity throttles
- Switch methods/content-types/endpoints that trigger the same state change via different code paths
- Intentionally trigger timeouts to provoke retries that cause duplicate side effects
- Degrade the target (large payloads, slow endpoints) to widen race windows

## Special Contexts

### GraphQL

- Parallel mutations and batched operations may bypass per-mutation guards
- Ensure resolver-level idempotency and atomicity
- Persisted queries and aliases can hide multiple state changes in one request

### WebSocket

- Per-message authorization and idempotency must hold
- Concurrent emits can create duplicates if only the handshake is checked

### Files and Storage

- Parallel finalize/complete on multi-part uploads can create duplicate or corrupted objects
- Re-use pre-signed URLs concurrently

### Auth Flows

- Concurrent consumption of one-time tokens (reset codes, magic links) to mint multiple sessions
- Verify consume is atomic

## Chaining Attacks

- Race + Business logic: violate invariants (double-refund, limit slicing)
- Race + IDOR: modify or read others' resources before ownership checks complete
- Race + CSRF: trigger parallel actions from a victim to amplify effects
- Race + Caching: stale caches re-serve privileged states after concurrent changes

## Testing Methodology

1. **Model invariants** - Conservation of value, uniqueness, maximums for each workflow
2. **Identify reads/writes** - Where they occur (service, DB, cache)
3. **Baseline** - Single requests to establish expected behavior
4. **Concurrent requests** - Issue parallel requests with identical inputs; observe deltas
5. **Scale and synchronize** - Ramp up parallelism, use HTTP/2, align timing (last-byte sync)
6. **Cross-channel** - Test across web, API, GraphQL, WebSocket
7. **Confirm durability** - Verify state changes persist and are reproducible

## Validation

1. Single request denied; N concurrent requests succeed where only 1 should
2. Durable state change proven (ledger entries, inventory counts, role/flag changes)
3. Reproducible under controlled synchronization (HTTP/2, last-byte sync) across multiple runs
4. Evidence across channels (e.g., REST and GraphQL) if applicable
5. Include before/after state and exact request set used

## False Positives

- Truly idempotent operations with enforced ETag/version checks or unique constraints
- Serializable transactions or correct advisory locks/queues
- Visual-only glitches without durable state change
- Rate limits that reject excess with atomic counters

## Impact

- Financial loss (double spend, over-issuance of credits/refunds)
- Policy/limit bypass (quotas, single-use tokens, seat counts)
- Data integrity corruption and audit trail inconsistencies
- Privilege or role errors due to concurrent updates

## Pro Tips

1. Favor HTTP/2 with warmed connections; add last-byte sync for precision
2. Start small (N=5–20), then scale; too much noise can mask the window
3. Target read–modify–write code paths and endpoints with idempotency keys
4. Compare REST vs GraphQL vs WebSocket; protections often differ
5. Look for cross-service gaps (queues, jobs, webhooks) and retry semantics
6. Check unique constraints and upsert usage; avoid relying on pre-insert checks
7. Use correlation IDs and logs to prove concurrent interleaving
8. Widen windows by adding server load or slow backend dependencies
9. Validate on production-like latency; some races only appear under real load
10. Document minimal, repeatable request sets that demonstrate durable impact

## Summary

Concurrency safety is a property of every path that mutates state. If any path lacks atomicity, proper isolation, or idempotency, parallel requests will eventually break invariants.


## Additional Techniques — ported from WebSkills (writeup-techniques/race-condition)

Concrete delivery primitives, tooling recipes, and disclosed-report provenance that complement the methodology above. Core research: PortSwigger "Smashing the State Machine" (James Kettle).

### HTTP/2 single-packet attack (the reliable modern primitive)
Send many complete requests but withhold the final frame of each, then release all withheld frames so they land in one TCP packet → server processes them in the same tick. Removes network jitter entirely.
```
1. Send headers + body minus the final byte, without ending the stream.
2. Pause ~100ms after the initial send.
3. Disable TCP_NODELAY so Nagle's algorithm batches the final frames.
4. Ping to warm the connection.
   -> Withheld frames arrive in one packet (verify in Wireshark).
```
Puts ~20–30 requests' first-halves on one connection, then flushes. Does not apply to static files.

### HTTP/1.1 last-byte synchronization (when no HTTP/2)
Same idea over keep-alive: pre-send 20–30 requests minus their last byte, hold, then flush all last bytes together for simultaneous arrival.

### Turbo Intruder — single-endpoint template
```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=1,
                           engine=Engine.BURP2)   # HTTP/2 single-packet
    for i in range(30):
        engine.queue(target.req, gate='race1')    # queue N on ONE gate
    engine.openGate('race1')                       # release all tails at once

def handleResponse(req, interesting):
    table.add(req)
```
For HTTP/1.1-only targets, swap `Engine.BURP2` for `THREADED`/`CLUSTERBOMB`. Diagnostic: **negative timestamps** in Turbo Intruder mean the server responded before the request finished sending — proof the requests genuinely overlapped.

### Burp Repeater delivery (fastest)
Select the requests → **"Send group in parallel"** (single-packet under the hood). For a limit-overrun, just add the same request 50× to the group; even 2–3 wins prove it.

### Multi-endpoint race (hidden sub-state)
Fire a request that pushes the app into a transient hidden state, then flood a *different* endpoint that only works in that state. To tune delay between two sub-states, insert extra padding requests between the two real ones.

### Defeat PHP per-session serialization
Frameworks that lock the session file per session (PHP) serialize requests and hide the race. Use a **different session token per request** so they aren't serialized.

### Extend the 1,500-byte single-packet limit (IP fragmentation)
The single-packet attack is capped at ~1,500 B. IP-layer fragment one packet into many and send out of order so reassembly waits for all fragments → up to TCP's 65,535 B window (~10,000 requests in ~166 ms). Tool: `Ry0taK/first-sequence-sync`. Watch concurrent-stream caps: **Apache 100, Nginx 128, Go 250; Node/nghttp2 unlimited.**

### HTTP/3 last-frame synchronization (QUIC)
No TCP coalescing/Nagle over QUIC, so last-byte sync fails. Coalesce multiple QUIC stream-final (FIN) DATA frames into the **same UDP datagram**. For GET-style requests craft fake DATA frames (or tiny body + Content-Length) and end all streams in one datagram. Library: **H3SpaceX** (manipulates quic-go); `max_streams` caps parallelism.

### WebSocket races
The default WS Turbo Intruder engine batches messages on one connection (bad for races). Use the **THREADED** engine to spawn multiple WS connections and fire in parallel. Tool: PortSwigger **WebSocket Turbo Intruder** (BApp Store).

### 2FA / OTP verification race + resend quirk
Concurrent verify requests slip through before the attempt counter / code-consumed flag is written → brute-force or reuse a code. Note the rate-limit quirk seen in the HackerOne 2FA bypass: even after a 401 "rate limited" at 20 attempts, sending the *valid* OTP still returned 200; and **code-resend resets the throttle**, so keep brute-forcing. Rate limits often protect login but not internal account actions.

### TOCTOU on setup / privilege bootstrap
Race a one-time first-run setup endpoint that checks "is setup done / does an admin exist?" then creates a privileged object — fire many setup requests in the gap. Case: Querybook "How I Created 20 Super-Admins in 1 Second."

### TOCTOU on file / config operations
- **Upload saved before validation** — file lands on a predictable public path before MIME/content check runs and isn't cleaned up on error → grab it during the window (VaahCMS CVE-2025-61183, path `/storage/media/YYYY/MM/<name>.svg`).
- **Config-rewrite race** — if the app sanitizes right before running Git, spam the endpoint that writes your malicious config while triggering the Git action to win a race and get your hook executed.
- **phpinfo() LFI2RCE** — race the multipart upload (temp file exists briefly in `/tmp`) against an LFI that includes it before PHP deletes it; brute-force phpinfo to leak `tmp_name`, send many concurrent requests to widen the flush window.

### Cache-key collision race (framework)
Simultaneous requests collide on a shared cache/promise key so one request's private response entangles with another. Case: Next.js "Eclipse" CVE-2025-32421 — simultaneous `/_error-0` requests collide on the promise-batcher `cacheKey` → server-side data exposure.

### Single-packet-powered timing attack
The single-packet attack removes network jitter so pure server-side timing deltas (~5 ms) become measurable — detect hidden params/headers this way (added to Burp **Param Miner**). Research: PortSwigger "Listen to the Whispers: Web Timing Attacks that Actually Work."

### Reliability tuning + confirmation checklist
```
- Warm the connection (a few non-static requests first).
- Disable TCP_NODELAY (let Nagle batch the final frames).
- Different session token per request (defeat PHP session locking).
- Trip a rate/resource limit deliberately to induce server delay if the window is too tight.
- Queue 20-50 copies; look for >1 success or a negative timestamp.
- Confirm withheld frames left in a single packet via Wireshark.
- Baseline sequentially first to prove the app normally enforces the limit.
- Races are probabilistic — show repeated wins / state a win rate (e.g. Eclipse "100% (50/50)").
```

### Disclosed-report provenance (signal for prioritization)
Gift-card multi-redeem → free money (Reverb.com, 303 upvotes); duplicate payments/payouts (HackerOne, 237 / 72 upvotes); infinite in-game diamonds via email-activation race (InnoGames, $2000); wallet-balance manipulation (Coinbase, 272); loyalty/cashback claim (Vend); HackerOne 2FA bypass (132); verification-check bypass (Tools for Humanity, $3000); extra free domains (Automattic); undeletable/duplicated group members; vote/poll stuffing from one account. Financial and auth/verification races triage strongest and pay best.
