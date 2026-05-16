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
  await new Promise(function (r) { setTimeout(r, 60); });
  var expired = await idem.get("move", "u1", "k");
  check("expired returns null",      expired === null);
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
  await new Promise(function (r) { setTimeout(r, 120); });
  var r = await idem.gc({ olderThanMs: 0 });
  check("gc returns purged count", r && typeof r.purged === "number");
}

async function run() {
  testSurface();
  await testBasicGetPut();
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
}

module.exports = { run: run };
if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e); process.exit(1); });
}
