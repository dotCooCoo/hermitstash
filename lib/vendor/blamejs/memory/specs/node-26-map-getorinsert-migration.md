# Node 26 — `Map.prototype.getOrInsertComputed` migration plan

**Status:** detector landed; sweep deferred to the Node 26 floor-bump
(eligible Oct 2026 per the LTS calendar).

**Floor today:** `engines.node: ">=24"`. Do NOT do the sweep yet.

## What changes when the floor moves

Node 26 ships
[`Map.prototype.getOrInsertComputed(key, factory)`](https://github.com/tc39/proposal-upsert)
(TC39 stage-4, V8 13.x). It replaces two distinct framework-internal
shapes:

**Variant A** — `var X = M.get(k); if (!X) { ... ; M.set(k, ...); }`:

```js
// before
var s = tagIndex.get(tags[i]);
if (!s) { s = new Set(); tagIndex.set(tags[i], s); }
s.add(key);

// after
var s = tagIndex.getOrInsertComputed(tags[i], function () { return new Set(); });
s.add(key);
```

**Variant B** — `if (!M.has(k)) { ... M.set(k, ...); }`:

```js
// before
if (!channelToConns.has(channel)) {
  channelToConns.set(channel, new Set());
  var token = ps.subscribe(channel, _onPubsubMessage);
  channelToToken.set(channel, token);
}
channelToConns.get(channel).add(conn);

// after — single lookup, no half-built-state observer window
var conns = channelToConns.getOrInsertComputed(channel, function () {
  channelToToken.set(channel, ps.subscribe(channel, _onPubsubMessage));
  return new Set();
});
conns.add(conn);
```

Two wins:

1. **One lookup instead of two.** `has` + `set` (or `get` + `set`) is a
   double hash probe. `getOrInsertComputed` is one probe with an
   on-miss factory call.
2. **Race-window closure in cluster-shared registries.** Between
   `M.has(k) === false` and `M.set(k, v)`, an interleaved observer
   (debug tooling, registry-snapshot, audit-chain walker) could see
   the key as absent OR halfway-built. `getOrInsertComputed`
   collapses the gap to a single engine-internal step; no
   intermediate state is observable.

## Call-site survey (lib/ ground truth, vendor/ excluded)

Detector survey at v0.11.2. Counts are *call sites*, not files —
several files house multiple sites in different methods of the same
closure-built object (e.g. metrics counters/gauges/histograms).

### Agent substrate / cluster-shared state

None. (`lib/agent-event-bus.js`, `lib/agent-orchestrator.js`,
`lib/agent-snapshot.js`, `lib/agent-idempotency.js`,
`lib/audit-chain.js`, `lib/audit.js`, `lib/break-glass.js`,
`lib/cms-codec.js` audited — only guard-throw / presence-assertion
shapes, no get-or-insert.)

### Cache / memoization

| File                              | Lines | Map                       | Factory               |
| --------------------------------- | ----- | ------------------------- | --------------------- |
| `lib/cache.js`                    | 318   | `tagIndex`                | `new Set()`           |
| `lib/i18n-messageformat.js`       | 317   | `_pluralRulesCache`       | `new Intl.PluralRules`|
| `lib/i18n.js`                     | 360   | formatter cache (closure) | closure-`make()`      |
| `lib/deprecate.js`                | 134   | `_seen`                   | object-literal        |

### Observability / metrics

| File                                  | Lines              | Map               | Factory          |
| ------------------------------------- | ------------------ | ----------------- | ---------------- |
| `lib/metrics.js`                      | 390, 430, 526      | `values` (×3)     | object-literal (counter + gauge `_ensure` + histogram observe; each with cardinality-cap early-return) |
| `lib/observability-otlp-exporter.js`  | 164                | `byResource`      | object-literal   |
| `lib/otel-export.js`                  | 138, 151           | `counters` / `observations` | object-literal |

### Rate-limiting / quotas

| File                              | Lines              | Map                                                        | Factory          |
| --------------------------------- | ------------------ | ---------------------------------------------------------- | ---------------- |
| `lib/mail-server-rate-limit.js`   | 209, 261, 291      | `connectionTimes` / `authFailureTimes` / `rcptFailureTimes` | `[]` (array)     |
| `lib/middleware/rate-limit.js`    | 130                | `buckets`                                                  | object-literal   |
| `lib/network-byte-quota.js`       | 82                 | `store`                                                    | `_newEntry()`    |

### Pubsub / websocket-channels

| File                              | Lines | Map               | Factory       | Race-window callout |
| --------------------------------- | ----- | ----------------- | ------------- | ------------------- |
| `lib/pubsub.js`                   | 350   | `exactSubs`       | `new Set()`   | local-only; sub-record under same-process closure — race-window benign |
| `lib/websocket-channels.js`       | 193   | `channelToConns`  | `new Set()`   | **cluster-shared via `ps.subscribe` — race-window non-trivial.** Between `has(channel) === false` and `set(channel, new Set())`, the pubsub backend opens a remote subscription; a concurrent `subscribe(otherConn, sameChannel)` can see `channel`-as-known and skip the pubsub `subscribe()` even though the new Set is empty. `getOrInsertComputed` collapses the gap; the factory closure runs once, the pubsub subscribe call lifts inside it. |

### Edge cases — flagged structurally, do NOT migrate cleanly

| File                              | Lines | Why it doesn't migrate                                                                                                                                                                                                                  |
| --------------------------------- | ----- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `lib/mail-greylist.js`            | 405   | `memoryStore.put` is *put-or-replace-with-insertion-order-side-effect*. `data.set(key, value)` runs unconditionally (always overwrites the value); the `if (!data.has(key))` block manages an evict-oldest `insertionOrder` sidecar. `getOrInsertComputed` only runs the factory on miss — wrong semantics for an always-write. **Skip during sweep; keep inline.** |
| `lib/dsr.js`                      | 875   | `memoryTicketStore.update` is a *presence assertion*: `if (!byId.has(id)) throw new DsrError(...)` then `byId.set(id, ...)` runs OUTSIDE the if-block as an UPDATE. False positive — detector window crosses the closing `}`. **Skip during sweep; no rewrite.** |

### Totals

- **Migratable call sites:** ~17 across 11 files (variants A + B; metrics + rate-limit + otel each have multiple sites per file).
- **Files allowlisted (migratable):** 12 (`cache.js`, `deprecate.js`, `i18n-messageformat.js`, `i18n.js`, `mail-server-rate-limit.js`, `metrics.js`, `middleware/rate-limit.js`, `network-byte-quota.js`, `observability-otlp-exporter.js`, `otel-export.js`, `pubsub.js`, `websocket-channels.js`).
- **Files allowlisted (do-not-migrate edge cases):** 2 (`mail-greylist.js`, `dsr.js`).

The user-supplied "~137 sites across 80+ files" figure was an estimate
that included WeakMap / plain-object / `has`-as-allowlist-membership
shapes; the actual `getOrInsertComputed`-migratable surface is the
~17 sites above.

## Floor-bump sweep plan

When `engines.node` advances to `>=26` (eligible Oct 2026 per LTS
calendar; do NOT bump earlier):

1. **One commit per domain group** (cache, observability, rate-limit,
   pubsub/websocket). Each commit:
   - Walks every call site in the matching allowlist entry.
   - Converts `var X = M.get(k); if (!X) { X = factory(); M.set(k, X); }`
     to `var X = M.getOrInsertComputed(k, function () { return factory(); });`.
   - Verifies the factory closure is pure (or its side-effects are
     intentional in the on-miss-only path). For `websocket-channels`
     specifically, the pubsub-subscribe side-effect MUST move into
     the factory — that's the race-window fix.
   - Removes the file from the detector's allowlist.
   - Runs the full release-gate sequence (codebase-patterns, smoke,
     wiki-e2e, container-smoke).
2. **Final commit** flips both detector entries' `reason` field from
   "documentation" framing to enforcement framing and removes any
   remaining edge-case entries (after auditing whether
   `mail-greylist.js` / `dsr.js` actually need a different rewrite or
   are genuinely no-ops).
3. **CHANGELOG entry** describes the perf win (single-lookup) and the
   `websocket-channels` race-window closure as operator-visible
   improvements. No internal narrative.

## How the detector behaves between now and the floor bump

`test/layer-0-primitives/codebase-patterns.test.js` has two sibling
entries in `KNOWN_ANTIPATTERNS`:

- `map-get-or-insert-pre-node-26` — variant A, prefix `var X = M.get(k); if (!X) {`.
- `map-has-then-set-pre-node-26` — variant B, prefix `if (!M.has(k)) {`.

Both detectors run as part of `node test/layer-0-primitives/codebase-patterns.test.js`
on every release. Existing call sites are allowlisted (the gate is
green at v0.11.2). **New code introduced before the floor bump trips
the detector** and gets a clear message pointing at this spec — at
which point the operator either waits for the floor bump or adds the
new file to BOTH the allowlist AND this spec's call-site table in
the SAME patch (per the framework's audit-existing-code discipline,
rule §7).
