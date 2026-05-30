"use strict";

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;
var { assertJsonRoundTrip } = require("../helpers/json-round-trip");

function expectRejection(label, p, codeMatch) {
  return p.then(
    function () { check(label + " (did not reject)", false); },
    function (e) { check(label, (e && e.code || "").indexOf(codeMatch) !== -1); }
  );
}

function testSurface() {
  check("create is fn",      typeof b.agent.idempotency.create === "function");
  check("AgentIdempotencyError",
    typeof b.agent.idempotency.AgentIdempotencyError === "function");
  check("guards.key",        b.agent.idempotency.guards.key === b.guardIdempotencyKey);
  var e = new b.agent.idempotency.AgentIdempotencyError("agent-idempotency/test", "t");
  check("error carries code", e.code === "agent-idempotency/test");
}

async function testBasicGetPut() {
  var idem = b.agent.idempotency.create({});
  var miss = await idem.get("move", "u1", "jmap-req-abc");
  check("miss returns null",       miss === null);

  await idem.put("move", "u1", "jmap-req-abc", { changed: 1, modseq: 5 });
  var hit = await idem.get("move", "u1", "jmap-req-abc");
  check("hit returns cached",      hit && hit.result.changed === 1);
  check("hit modseq preserved",    hit && hit.result.modseq === 5);
  check("hit firstAt set",         hit && typeof hit.firstAt === "number");
  check("hit replayCount = 1",     hit && hit.replayCount === 1);

  // Second read increments replayCount.
  var hit2 = await idem.get("move", "u1", "jmap-req-abc");
  check("hit2 replayCount = 2",    hit2 && hit2.replayCount === 2);
}

async function testInMemoryBackendBounded() {
  // The default in-memory backend caps its entry count so a flood of
  // distinct idempotency keys can't grow it without bound (OOM). Eviction
  // is oldest-first — a dropped record just means that one key re-executes
  // on retry, never a crash. Operators needing a hard guarantee at scale
  // supply a durable opts.store.
  var idem = b.agent.idempotency.create({ maxInMemoryEntries: 3 });
  await idem.put("m", "u", "k1", { n: 1 });
  await idem.put("m", "u", "k2", { n: 2 });
  await idem.put("m", "u", "k3", { n: 3 });
  check("at cap: oldest still present",  (await idem.get("m", "u", "k1")) !== null);
  // 4th distinct key pushes past the cap → evicts the oldest (k1).
  await idem.put("m", "u", "k4", { n: 4 });
  check("over cap: newest key retained", (await idem.get("m", "u", "k4")) !== null);
  check("over cap: oldest key evicted",  (await idem.get("m", "u", "k1")) === null);
  check("over cap: middle keys retained",
        (await idem.get("m", "u", "k2")) !== null && (await idem.get("m", "u", "k3")) !== null);
}

async function testCrossActorIsolation() {
  var idem = b.agent.idempotency.create({});
  await idem.put("move", "u1", "shared-key", { changed: 1 });
  var crossActor = await idem.get("move", "u2", "shared-key");
  check("cross-actor returns null", crossActor === null);
}

async function testCrossMethodIsolation() {
  var idem = b.agent.idempotency.create({});
  await idem.put("move", "u1", "shared-key", { changed: 1 });
  var crossMethod = await idem.get("flag", "u1", "shared-key");
  check("cross-method returns null", crossMethod === null);
}

async function testKeyReuseDifferentArgs() {
  var idem = b.agent.idempotency.create({});
  await idem.put("move", "u1", "k", { changed: 1 }, {
    args: { folder: "INBOX", objectIds: ["o1"] },
  });
  // Same key, different args → refuse.
  await expectRejection("refuses key reuse with different args",
    idem.put("move", "u1", "k", { changed: 2 }, {
      args: { folder: "Drafts", objectIds: ["o2"] },
    }),
    "agent-idempotency/key-reuse-different-args");
}

async function testInvalidate() {
  var idem = b.agent.idempotency.create({});
  await idem.put("send", "u1", "k", { messageId: "m1" });
  var hit = await idem.get("send", "u1", "k");
  check("invalidate-before: hit",    hit !== null);
  await idem.invalidate("send", "u1", "k");
  var miss = await idem.get("send", "u1", "k");
  check("invalidate-after: miss",    miss === null);
}

async function testTtlExpiry() {
  // Use a very-short TTL to exercise the lazy-GC path on read.
  var idem = b.agent.idempotency.create({ ttlMs: 50 });
  await idem.put("move", "u1", "k", { changed: 1 });
  var expired = await helpers.waitUntil(async function () {
    var v = await idem.get("move", "u1", "k");
    return v === null ? "expired" : false;
  }, { label: "agent-idempotency: 50ms TTL key expired" });
  check("expired returns null",      expired === "expired");
}

async function testResultSizeCap() {
  var idem = b.agent.idempotency.create({ maxResultBytes: 1024 });                                    // allow:raw-byte-literal — test cap
  var big = { rows: [] };
  for (var i = 0; i < 100; i += 1) big.rows.push({ idx: i, data: "x".repeat(20) });
  await expectRejection("refuses result over cap",
    idem.put("search", "u1", "k", big),
    "agent-idempotency/result-too-big");
}

async function testGuardRefusalsAtBoundary() {
  var idem = b.agent.idempotency.create({});
  await expectRejection("refuses CR in key",
    idem.put("move", "u1", "a\rb", { changed: 1 }),
    "idempotency-key/control-char");
  await expectRejection("refuses slash in key",
    idem.put("move", "u1", "a/b", { changed: 1 }),
    "idempotency-key/slash");
  await expectRejection("refuses empty key",
    idem.put("move", "u1", "", { changed: 1 }),
    "idempotency-key/empty");
}

async function testJsonRoundTripCachedResult() {
  // Detector applied: the cached-result entry must round-trip cleanly
  // through JSON.parse(JSON.stringify(...)). Catches the class of bug
  // where operators try to cache a Buffer / Date / function ref.
  var idem = b.agent.idempotency.create({});
  await idem.put("search", "u1", "k", {
    rows:        [{ objectid: "obj_abc", subject: "hi" }],
    nextModseq:  5,
    folder:      "INBOX",
  });
  var hit = await idem.get("search", "u1", "k");
  assertJsonRoundTrip(hit.result, "agent-idempotency cached search result");
}

async function testRefusesBadStore() {
  var threw = null;
  try { b.agent.idempotency.create({ store: { get: function () {} } }); }
  catch (e) { threw = e; }
  check("refuses store missing put",
    threw && (threw.code || "").indexOf("agent-idempotency/bad-store") !== -1);
}

async function testCanonicalFingerprint() {
  // Args with different key insertion order must produce the SAME
  // fingerprint. Without canonicalization, a JMAP client retrying with
  // re-serialized args (different JSON encoder, different runtime)
  // would trigger key-reuse-different-args false-positive.
  var idem = b.agent.idempotency.create({});
  await idem.put("send", "u1", "k", { messageId: "m1" }, {
    args: { from: "a@x", to: ["b@y"], subject: "hi" },
  });
  // Same key + same logical args but different insertion order:
  await idem.put("send", "u1", "k", { messageId: "m1" }, {
    args: { subject: "hi", to: ["b@y"], from: "a@x" },
  });
  check("canonical fingerprint accepts key-reorder", true);

  // But genuinely different args still refuse:
  await expectRejection("canonical fingerprint refuses different args",
    idem.put("send", "u1", "k", { messageId: "m2" }, {
      args: { from: "a@x", to: ["b@y"], subject: "different" },
    }),
    "agent-idempotency/key-reuse-different-args");
}

async function testParseCapTracksWriteCap() {
  // Operator raises maxResultBytes above the previously-static
  // MAX_PARSE_BYTES (4 MiB). Writes succeeded; reads must succeed too.
  var idem = b.agent.idempotency.create({ maxResultBytes: 2048 });                                    // allow:raw-byte-literal — test cap
  var bigResult = { rows: [] };
  for (var i = 0; i < 30; i += 1) bigResult.rows.push({ idx: i, data: "x".repeat(40) });
  await idem.put("search", "u1", "k", bigResult);
  var hit = await idem.get("search", "u1", "k");
  check("parse cap tracks write cap (read succeeds)",
    hit && Array.isArray(hit.result.rows) && hit.result.rows.length === 30);
}

async function testGc() {
  var idem = b.agent.idempotency.create({ ttlMs: 100 });
  await idem.put("move", "u1", "k1", { changed: 1 });
  await idem.put("move", "u1", "k2", { changed: 2 });
  // Both 100ms-TTL keys must expire before gc can purge them.
  await helpers.waitUntil(async function () {
    return (await idem.get("move", "u1", "k1")) === null
        && (await idem.get("move", "u1", "k2")) === null;
  }, { label: "agent-idempotency.gc: 100ms TTL keys expired" });
  var r = await idem.gc({ olderThanMs: 0 });
  check("gc returns purged count", r && typeof r.purged === "number");
}

async function testPutIfAbsentAtomicClaim() {
  // SUBSTRATE-4 — atomic claim: first call wins, second returns
  // alreadyClaimed pending; after the winner commits the result the
  // third call returns the cached result.
  var idem = b.agent.idempotency.create({});
  var claim1 = await idem.putIfAbsent("move", "u1", "jmap-req-A", { args: { from: "INBOX", to: "Archive" } });
  check("SUBSTRATE-4: first claim wins",     claim1.alreadyClaimed === false);
  var claim2 = await idem.putIfAbsent("move", "u1", "jmap-req-A", { args: { from: "INBOX", to: "Archive" } });
  check("SUBSTRATE-4: second sees alreadyClaimed", claim2.alreadyClaimed === true);
  check("SUBSTRATE-4: second sees pending",       claim2.pending === true);
  // Winner commits the cached result.
  await idem.put("move", "u1", "jmap-req-A", { changed: 1 },
    { args: { from: "INBOX", to: "Archive" } });
  var claim3 = await idem.putIfAbsent("move", "u1", "jmap-req-A", { args: { from: "INBOX", to: "Archive" } });
  check("SUBSTRATE-4: third sees cached result",
    claim3.alreadyClaimed === true && claim3.pending === false && claim3.result.changed === 1);
}

async function testFingerprintIncludesPostureChain() {
  // SUBSTRATE-11 — fingerprint binds the postureSet so an
  // elevated-posture cached result is not returned to a downgraded
  // caller. Two args identical except for _postureChain should produce
  // DIFFERENT fingerprints.
  var idem = b.agent.idempotency.create({});
  var fp1 = idem.fingerprintArgs({
    from: "INBOX", to: "Archive",
    _postureChain: { postureSet: ["hipaa", "pci-dss"], chainTrail: ["a"], enteredAt: [1], hopCount: 1 },
  });
  var fp2 = idem.fingerprintArgs({
    from: "INBOX", to: "Archive",
    _postureChain: { postureSet: ["pci-dss"], chainTrail: ["a"], enteredAt: [1], hopCount: 1 },
  });
  check("SUBSTRATE-11: different postureSet → different fingerprint", fp1 !== fp2);
  // Same postureSet (order-insensitive) → same fingerprint.
  var fp3 = idem.fingerprintArgs({
    from: "INBOX", to: "Archive",
    _postureChain: { postureSet: ["pci-dss", "hipaa"], chainTrail: ["x"], enteredAt: [2], hopCount: 1 },
  });
  check("SUBSTRATE-11: sorted postureSet stable", fp1 === fp3);
}

async function testReplayCountAtomic() {
  // SUBSTRATE-12 — incrementReplayCount path is used when the store
  // exposes it; both fall paths produce the right count.
  var idem = b.agent.idempotency.create({});
  await idem.put("move", "u1", "jmap-req-B", { changed: 1 });
  // Two concurrent gets — in-memory backend is naturally race-free; both
  // see distinct replayCounts.
  var [r1, r2] = await Promise.all([
    idem.get("move", "u1", "jmap-req-B"),
    idem.get("move", "u1", "jmap-req-B"),
  ]);
  check("SUBSTRATE-12: concurrent replayCount = 1 + 2",
    (r1.replayCount === 1 && r2.replayCount === 2) ||
    (r1.replayCount === 2 && r2.replayCount === 1));
}

async function testAtRestSealingWithVault() {
  // The cached result is sealed at rest via b.cryptoField when a vault
  // is configured. Init a vault, capture what actually lands in the
  // backend, and assert the sensitive payload is not stored in the
  // clear — then confirm it round-trips. Reset the vault afterwards so
  // the remaining (vault-less) tests run in their expected mode.
  var os   = require("node:os");
  var path = require("node:path");
  var fs   = require("node:fs");
  var dir  = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-idem-seal-"));
  check("vault.isInitialized() is false before init", b.vault.isInitialized() === false);
  await b.vault.init({ mode: "plaintext", dataDir: dir });
  try {
    check("vault.isInitialized() is true after init", b.vault.isInitialized() === true);
    var SECRET = "patient-PII-9007199254740993";
    var captured = null;
    var backend = {
      _m: Object.create(null),
      async get(m, a, h) { return this._m[m + a + h] || null; },
      async put(m, a, h, row) { this._m[m + a + h] = row; captured = row; },
      async delete(m, a, h) { delete this._m[m + a + h]; },
    };
    var idem = b.agent.idempotency.create({ store: backend });
    await idem.put("move", "u-seal", "jmap-seal-1", { payload: SECRET });
    check("at-rest: result blob is sealed (no plaintext leak)",
      typeof captured.resultBlob === "string" && captured.resultBlob.indexOf(SECRET) === -1);
    check("at-rest: sealed blob carries a vault prefix",
      /^vault(\.aad)?:/.test(String(captured.resultBlob)));
    var hit = await idem.get("move", "u-seal", "jmap-seal-1");
    check("at-rest: sealed result round-trips to plaintext",
      hit && hit.result && hit.result.payload === SECRET);
  } finally {
    b.vault._resetForTest();
  }
}

async function run() {
  testSurface();
  await testAtRestSealingWithVault();
  await testBasicGetPut();
  await testInMemoryBackendBounded();
  await testCrossActorIsolation();
  await testCrossMethodIsolation();
  await testKeyReuseDifferentArgs();
  await testInvalidate();
  await testTtlExpiry();
  await testResultSizeCap();
  await testGuardRefusalsAtBoundary();
  await testJsonRoundTripCachedResult();
  await testRefusesBadStore();
  await testCanonicalFingerprint();
  await testParseCapTracksWriteCap();
  await testGc();
  await testPutIfAbsentAtomicClaim();
  await testFingerprintIncludesPostureChain();
  await testReplayCountAtomic();
}

module.exports = { run: run };
if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e); process.exit(1); });
}
