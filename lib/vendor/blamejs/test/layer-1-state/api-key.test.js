"use strict";
/**
 * b.apiKey — operator-facing API key registry.
 *
 * Run standalone: `node test/layer-1-state/api-key.test.js`
 * Or via smoke:   `node test/smoke.js`
 */

var fs = require("fs");
var os = require("os");
var path = require("path");
var helpers = require("../helpers");
var b               = helpers.b;
var check           = helpers.check;
var C               = b.constants;
var setupTestDb     = helpers.setupTestDb;
var teardownTestDb  = helpers.teardownTestDb;

function _tmp() { return fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-apikey-")); }

// ---- Surface ----

function testApiKeySurface() {
  check("b.apiKey namespace present",      typeof b.apiKey === "object");
  check("b.apiKey.create is a function",   typeof b.apiKey.create === "function");
  check("b.apiKey.parseFormat is a fn",    typeof b.apiKey.parseFormat === "function");
  check("ApiKeyError class",               typeof b.apiKey.ApiKeyError === "function");
  check("DEFAULTS frozen",                 Object.isFrozen(b.apiKey.DEFAULTS));
  check("DEFAULTS.prefix",                 b.apiKey.DEFAULTS.prefix === "bk");
  check("DEFAULTS.idBytes",                b.apiKey.DEFAULTS.idBytes === 8);
  check("DEFAULTS.secretBytes",            b.apiKey.DEFAULTS.secretBytes === 16);
  check("DEFAULTS.trackLastUsedAt true (security default)",
        b.apiKey.DEFAULTS.trackLastUsedAt === true);
  check("DEFAULTS.auditFailures true (security default)",
        b.apiKey.DEFAULTS.auditFailures === true);
  check("DEFAULTS.auditSuccess true (compliance trail when audit wired)",
        b.apiKey.DEFAULTS.auditSuccess === true);
}

function testParseFormat() {
  var pf = b.apiKey.parseFormat;
  var parts = pf("bk_live_abcd1234_deadbeefcafe1234");
  check("parseFormat: returns 4-part object",
        parts && parts.prefix === "bk" && parts.namespace === "live" &&
        parts.idHex === "abcd1234" && parts.secretHex === "deadbeefcafe1234");
  check("parseFormat: rejects empty",      pf("") === null);
  check("parseFormat: rejects undefined",  pf(undefined) === null);
  check("parseFormat: rejects too-few parts", pf("bk_live_abc") === null);
  check("parseFormat: rejects too-many parts", pf("a_b_c_d_e") === null);
  check("parseFormat: rejects non-hex idHex", pf("bk_live_NOT-HEX_deadbeef") === null);
  check("parseFormat: rejects non-hex secret", pf("bk_live_abcd_NOT-HEX") === null);
}

// ---- Issue / verify roundtrip ----

async function testIssueAndVerifyRoundtrip(tmpDir) {
  var keys = b.apiKey.create({ namespace: "live" });
  var issued = await keys.issue({
    ownerId:  "user-42",
    scopes:   ["read:users", "write:posts"],
    metadata: { name: "Test app" },
  });
  check("issue: returns id",               typeof issued.id === "string" && issued.id.length === 16);
  check("issue: returns secret",           typeof issued.secret === "string" && issued.secret.length === 32);
  check("issue: returns full key",         typeof issued.key === "string");
  check("issue: key parses back",
        b.apiKey.parseFormat(issued.key).idHex === issued.id);
  check("issue: returns scopes",           Array.isArray(issued.scopes) && issued.scopes.length === 2);
  check("issue: createdAt set",            typeof issued.createdAt === "number");
  check("issue: expiresAt null when not set", issued.expiresAt === null);

  var verified = await keys.verify(issued.key);
  check("verify: returns record",          verified !== null);
  check("verify: id matches",              verified.id === issued.id);
  check("verify: ownerId unsealed",        verified.ownerId === "user-42");
  check("verify: scopes restored",
        verified.scopes.length === 2 && verified.scopes[0] === "read:users");
  check("verify: metadata restored",
        verified.metadata && verified.metadata.name === "Test app");
  check("verify: namespace returned",      verified.namespace === "live");
  check("verify: no secret in record",     verified.secret === undefined);
  check("verify: no secretHash in record", verified.secretHash === undefined);
}

async function testVerifyMalformed() {
  var keys = b.apiKey.create({ namespace: "live" });
  check("verify(undefined) → null",        (await keys.verify(undefined)) === null);
  check("verify(null) → null",             (await keys.verify(null)) === null);
  check("verify('') → null",               (await keys.verify("")) === null);
  check("verify(garbage) → null",          (await keys.verify("not-a-key")) === null);
  check("verify(wrong-prefix) → null",     (await keys.verify("xx_live_abcd1234_deadbeefcafe1234")) === null);
  check("verify(wrong-namespace) → null",  (await keys.verify("bk_test_abcd1234_deadbeefcafe1234")) === null);
  check("verify(unknown id) → null",       (await keys.verify("bk_live_0123456789abcdef_00112233445566778899aabbccddeeff")) === null);
}

async function testVerifyWrongSecret() {
  var keys = b.apiKey.create({ namespace: "live" });
  var issued = await keys.issue({ ownerId: "u1" });
  // Build a key with the same id but a different secret
  var parts = b.apiKey.parseFormat(issued.key);
  var bogusKey = parts.prefix + "_" + parts.namespace + "_" + parts.idHex + "_" +
                 "00112233445566778899aabbccddeeff";
  var result = await keys.verify(bogusKey);
  check("verify: wrong secret → null", result === null);
}

// ---- Revocation ----

async function testRevoke() {
  var keys = b.apiKey.create({ namespace: "live" });
  var issued = await keys.issue({ ownerId: "u1" });
  var pre = await keys.verify(issued.key);
  check("revoke: pre-state verifies",      pre !== null);

  var revoked = await keys.revoke(issued.id);
  check("revoke: returns true on first",   revoked === true);

  var post = await keys.verify(issued.key);
  check("revoke: verify returns null after revoke", post === null);

  var revokedAgain = await keys.revoke(issued.id);
  check("revoke: idempotent (no row newly touched)", revokedAgain === false);

  var revokedMissing = await keys.revoke("0000000000000000");
  check("revoke: missing id returns false", revokedMissing === false);
}

// ---- Expiry ----

async function testExpired() {
  var clk = b.testing.fakeClock(2_000_000_000_000);
  var keys = b.apiKey.create({
    namespace: "live",
    clock: clk.now,
  });
  var issued = await keys.issue({ ownerId: "u1", expiresAt: clk.ms - C.TIME.seconds(1) });
  var result = await keys.verify(issued.key);
  check("verify: expired key returns null", result === null);

  var keysFuture = b.apiKey.create({
    namespace: "live2",
    clock: clk.now,
  });
  var future = await keysFuture.issue({ ownerId: "u1", expiresAt: clk.ms + C.TIME.minutes(1) });
  var fresh = await keysFuture.verify(future.key);
  check("verify: not-yet-expired returns record", fresh !== null);
}

// ---- Rotate ----

async function testRotate() {
  var keys = b.apiKey.create({ namespace: "live" });
  var issued = await keys.issue({ ownerId: "u1", scopes: ["read:x"] });
  var rotated = await keys.rotate(issued.id);
  check("rotate: returns new key",         typeof rotated.key === "string" && rotated.key !== issued.key);
  check("rotate: returns new secret",      rotated.secret !== issued.secret);

  // Old secret stops working
  var oldResult = await keys.verify(issued.key);
  check("rotate: old secret no longer verifies", oldResult === null);

  // New secret works, scopes preserved
  var newResult = await keys.verify(rotated.key);
  check("rotate: new secret verifies",     newResult !== null);
  check("rotate: id unchanged",            newResult.id === issued.id);
  check("rotate: scopes preserved",
        newResult.scopes.length === 1 && newResult.scopes[0] === "read:x");
}

async function testRotateNotFoundOrRevoked() {
  var keys = b.apiKey.create({ namespace: "live" });
  var threw = null;
  try { await keys.rotate("0000000000000000"); } catch (e) { threw = e; }
  check("rotate: missing id throws NOT_FOUND",
        threw && threw.code === "NOT_FOUND");

  var issued = await keys.issue({ ownerId: "u1" });
  await keys.revoke(issued.id);
  threw = null;
  try { await keys.rotate(issued.id); } catch (e) { threw = e; }
  check("rotate: revoked id throws REVOKED",
        threw && threw.code === "REVOKED");
}

// ---- listForOwner ----

async function testListForOwner() {
  var keys = b.apiKey.create({ namespace: "list-test" });
  var k1 = await keys.issue({ ownerId: "owner-A", scopes: ["a"] });
  var k2 = await keys.issue({ ownerId: "owner-A", scopes: ["b"] });
  var k3 = await keys.issue({ ownerId: "owner-B", scopes: ["c"] });
  await keys.revoke(k2.id);

  var listA = await keys.listForOwner("owner-A");
  check("listForOwner: filters to owner",   listA.length === 1);
  check("listForOwner: excludes revoked by default",
        listA[0].id === k1.id);

  var listAWithRevoked = await keys.listForOwner("owner-A", { includeRevoked: true });
  check("listForOwner: includes revoked when asked",
        listAWithRevoked.length === 2);

  var listB = await keys.listForOwner("owner-B");
  check("listForOwner: different owner",     listB.length === 1 && listB[0].id === k3.id);

  // No secret in scrubbed records
  for (var i = 0; i < listA.length; i++) {
    check("listForOwner: no secretHash leaked",
          listA[i].secretHash === undefined && listA[i].secret === undefined);
  }
}

// ---- getById ----

async function testEnvelopeFormatPersisted() {
  var keys = b.apiKey.create({ namespace: "envelope-shape" });
  var issued = await keys.issue({ ownerId: "u1" });
  // Read the row directly to confirm what's stored
  var rec = await keys.getById(issued.id);
  // The scrubbed record doesn't expose secretHash, so reach into the
  // verify path's behavior: re-issue same secret would get a different
  // envelope (random salt-free but the secret IS the same so SHAKE256
  // is deterministic — we'll inspect format another way).
  var inspect = b.credentialHash.inspect;
  // We need the raw secretHash; pull from cluster-storage directly.
  var row = await b.clusterStorage.executeOne(
    "SELECT secretHash FROM _blamejs_api_keys WHERE id = ?",
    [(rec.namespace || "envelope-shape") + ":" + rec.id]
  );
  // After unsealing... actually secretHash is NOT sealed (it's already a hash);
  // it's stored raw. So row.secretHash IS the envelope string.
  var info = inspect(row.secretHash);
  check("envelope: stored as base64 envelope",       info !== null);
  check("envelope: algoId is SHAKE256 (0x01)",       info.algoId === 0x01);
  check("envelope: algoName is shake256",            info.algoName === "shake256");
  check("envelope: payload is 128 bytes by default", info.payloadBytes === 128);
}

async function testHashAlgoOptArgon2id() {
  // Argon2id costs ~250ms per verify — keep this test small (issue +
  // verify only; no rotation, no purge sweep).
  var keys = b.apiKey.create({
    namespace: "argon2id",
    hashAlgo:  "argon2id",
  });
  var issued = await keys.issue({ ownerId: "u1" });
  var record = await keys.verify(issued.key);
  check("argon2id: roundtrip verifies", record !== null && record.id === issued.id);

  var row = await b.clusterStorage.executeOne(
    "SELECT secretHash FROM _blamejs_api_keys WHERE id = ?",
    ["argon2id:" + issued.id]
  );
  var info = b.credentialHash.inspect(row.secretHash);
  check("argon2id: envelope algoId 0x02",   info.algoId === 0x02);
  check("argon2id: envelope algoName argon2id", info.algoName === "argon2id");

  var wrong = await keys.verify("bk_argon2id_" + issued.id + "_" + "0".repeat(32));
  check("argon2id: wrong secret returns null", wrong === null);
}

async function testGetById() {
  var keys = b.apiKey.create({ namespace: "get-test" });
  var issued = await keys.issue({ ownerId: "u1" });
  var record = await keys.getById(issued.id);
  check("getById: returns record",         record !== null);
  check("getById: id matches",             record.id === issued.id);
  check("getById: ownerId unsealed",       record.ownerId === "u1");
  check("getById: no secret",              record.secret === undefined);

  var missing = await keys.getById("0000000000000000");
  check("getById: missing returns null",   missing === null);

  check("getById: empty string returns null", (await keys.getById("")) === null);
}

// ---- trackLastUsedAt ----

async function testTrackLastUsedAt() {
  // Default ON (visibility defaults are on)
  var keysOn = b.apiKey.create({ namespace: "track-on" });
  var iOn = await keysOn.issue({ ownerId: "u1" });
  await keysOn.verify(iOn.key);
  // verify() updates lastUsedAt asynchronously; poll until the write
  // surfaces in getById().
  var recOn = await helpers.waitUntil(async function () {
    var r = await keysOn.getById(iOn.id);
    return typeof r.lastUsedAt === "number" && r.lastUsedAt > 0 ? r : false;
  }, { label: "api-key: trackLastUsedAt write surfaced in getById" });
  check("trackLastUsedAt default ON: lastUsedAt set",
        typeof recOn.lastUsedAt === "number" && recOn.lastUsedAt > 0);

  // Operator opt-out
  var keysOff = b.apiKey.create({ namespace: "track-off", trackLastUsedAt: false });
  var iOff = await keysOff.issue({ ownerId: "u1" });
  await keysOff.verify(iOff.key);
  var recOff = await keysOff.getById(iOff.id);
  check("trackLastUsedAt explicit false: stays null",
        recOff.lastUsedAt === null);
}

async function testGracefulRotation() {
  var clk = b.testing.fakeClock(4_000_000_000_000);
  var keys = b.apiKey.create({
    namespace: "graceful",
    clock: clk.now,
  });
  var issued = await keys.issue({ ownerId: "u1" });
  var rotated = await keys.rotate(issued.id, { graceful: true });
  check("graceful rotate: returns gracePeriodMs",
        rotated.gracePeriodMs > 0);
  check("graceful rotate: returns secondaryExpiresAt",
        typeof rotated.secondaryExpiresAt === "number");

  // BOTH secrets should verify during the grace window
  var oldStillWorks = await keys.verify(issued.key);
  check("graceful rotate: old secret still verifies", oldStillWorks !== null);
  check("graceful rotate: usedSecondary flag set on old",
        oldStillWorks.usedSecondary === true);

  var newWorks = await keys.verify(rotated.key);
  check("graceful rotate: new secret verifies",       newWorks !== null);
  check("graceful rotate: usedSecondary false on new",
        newWorks.usedSecondary === false);

  // After grace expires, old stops working but new keeps going
  clk.set(rotated.secondaryExpiresAt + C.TIME.seconds(1));
  var oldExpired = await keys.verify(issued.key);
  check("graceful rotate: old secret stops after grace",
        oldExpired === null);
  var newAfter = await keys.verify(rotated.key);
  check("graceful rotate: new secret still works after grace",
        newAfter !== null);
}

async function testGracefulRotationExplicitMs() {
  var clk = b.testing.fakeClock(4_500_000_000_000);
  var keys = b.apiKey.create({
    namespace: "graceful-explicit",
    clock: clk.now,
  });
  var issued = await keys.issue({ ownerId: "u1" });
  var rotated = await keys.rotate(issued.id, { gracePeriodMs: C.TIME.minutes(1) });
  check("graceful rotate: explicit gracePeriodMs honored",
        rotated.gracePeriodMs === C.TIME.minutes(1));
  check("graceful rotate: secondaryExpiresAt = now + 60s",
        rotated.secondaryExpiresAt === clk.ms + C.TIME.minutes(1));
}

async function testHardRotateClearsSecondary() {
  var keys = b.apiKey.create({ namespace: "hard-rotate" });
  var issued = await keys.issue({ ownerId: "u1" });
  var graceful = await keys.rotate(issued.id, { graceful: true });
  // Now do a hard rotation; secondary should be cleared
  var hard = await keys.rotate(issued.id);
  check("hard rotate: gracePeriodMs is 0",     hard.gracePeriodMs === 0);
  check("hard rotate: secondaryExpiresAt null", hard.secondaryExpiresAt === null);

  // The previous (graceful) key should NOT verify anymore — hard rotation
  // wiped the secondary slot.
  var prev = await keys.verify(graceful.key);
  // The current primary IS the graceful's hash (now bumped to secondary,
  // then cleared). Wait — let me trace this carefully:
  //   issue:           primary = secret_orig
  //   rotate(graceful): primary = secret_graceful, secondary = secret_orig (with expiry)
  //   rotate(hard):    primary = secret_hard,     secondary = NULL
  //   So secret_graceful is no longer accepted (it was primary, replaced).
  check("hard rotate: previous graceful key no longer works",
        prev === null);
  var newOne = await keys.verify(hard.key);
  check("hard rotate: new key works", newOne !== null);
}

// ---- purgeExpired ----

async function testPurgeExpired() {
  var clk = b.testing.fakeClock(3_000_000_000_000);
  var keys = b.apiKey.create({
    namespace: "purge",
    purgeAfterMs: C.TIME.minutes(1),
    clock: clk.now,
  });
  var fresh = await keys.issue({ ownerId: "u1", expiresAt: clk.ms + C.TIME.hours(1) });
  var oldExpired = await keys.issue({ ownerId: "u2", expiresAt: clk.ms - C.TIME.minutes(5) });
  var oldRevoked = await keys.issue({ ownerId: "u3" });
  await keys.revoke(oldRevoked.id);
  // Fast-forward
  clk.advance(C.TIME.minutes(10));

  var deleted = await keys.purgeExpired();
  check("purgeExpired: deletes expired + revoked old rows", deleted >= 2);

  var freshStillThere = await keys.getById(fresh.id);
  check("purgeExpired: keeps fresh row",  freshStillThere !== null);

  var purgedExpiredGone = await keys.getById(oldExpired.id);
  check("purgeExpired: removes expired row", purgedExpiredGone === null);
}

// ---- Input validation (rejects bad opts at create time) ----

function testCreateRejectsBadOpts() {
  function expect(label, fn, code) {
    var threw = null;
    try { fn(); } catch (e) { threw = e; }
    check(label, threw && threw.code === code);
  }

  expect("create: missing namespace",
    function () { b.apiKey.create({}); }, "BAD_OPT");
  expect("create: namespace with underscore",
    function () { b.apiKey.create({ namespace: "bad_ns" }); }, "BAD_OPT");
  expect("create: namespace with whitespace",
    function () { b.apiKey.create({ namespace: "bad ns" }); }, "BAD_OPT");
  expect("create: prefix with underscore",
    function () { b.apiKey.create({ namespace: "ok", prefix: "bad_x" }); }, "BAD_OPT");
  expect("create: bad idBytes",
    function () { b.apiKey.create({ namespace: "ok", idBytes: 0 }); }, "BAD_OPT");
  expect("create: bad audit shape",
    function () { b.apiKey.create({ namespace: "ok", audit: {} }); }, "BAD_OPT");
}

async function testIssueRejectsBadOpts() {
  var keys = b.apiKey.create({ namespace: "issue-bad-opts" });
  function expect(label, p, code) {
    return p.then(
      function () { check(label + " — should have thrown", false); },
      function (e) { check(label, e && e.code === code); }
    );
  }
  await expect("issue: missing ownerId",
    keys.issue({}),
    "MISSING_OWNER");
  await expect("issue: empty ownerId",
    keys.issue({ ownerId: "" }),
    "MISSING_OWNER");
  await expect("issue: scopes not array",
    keys.issue({ ownerId: "u", scopes: "read" }),
    "BAD_SCOPES");
  await expect("issue: scopes contains non-string",
    keys.issue({ ownerId: "u", scopes: ["ok", 42] }),
    "BAD_SCOPES");
  await expect("issue: metadata not object",
    keys.issue({ ownerId: "u", metadata: "notobj" }),
    "BAD_METADATA");
  await expect("issue: bad expiresAt",
    keys.issue({ ownerId: "u", expiresAt: "soon" }),
    "BAD_OPT");
}

// ---- Audit emission ----

async function testPurgeAuditEmission() {
  var clk = b.testing.fakeClock(5_000_000_000_000);
  var audit = b.testing.captureAudit();
  var keys = b.apiKey.create({
    namespace: "purge-audit",
    purgeAfterMs: C.TIME.minutes(1),
    audit: audit,
    clock: clk.now,
  });
  var k1 = await keys.issue({ ownerId: "u1", expiresAt: clk.ms - C.TIME.minutes(5) });
  var k2 = await keys.issue({ ownerId: "u2" });
  await keys.revoke(k2.id);
  // Fast-forward so both rows are past purgeAfterMs
  clk.advance(C.TIME.minutes(10));

  // Drain audit captures from the issue/revoke setup so we only assert
  // on the purge emission.
  audit.clear();
  var deleted = await keys.purgeExpired();
  check("purge: returned count matches",      deleted === 2);

  var purgeEvents = audit.byAction("apikey.purge");
  check("purge: emits apikey.purge audit",    purgeEvents.length === 1);
  check("purge: audit metadata.count matches", purgeEvents[0].metadata.count === 2);
  check("purge: audit metadata has purgedIds array",
        Array.isArray(purgeEvents[0].metadata.purgedIds) &&
        purgeEvents[0].metadata.purgedIds.length === 2);
  check("purge: purgedIds contain k1.id",
        purgeEvents[0].metadata.purgedIds.indexOf(k1.id) !== -1);
  check("purge: purgedIds contain k2.id",
        purgeEvents[0].metadata.purgedIds.indexOf(k2.id) !== -1);
  check("purge: resource kind is apikey-namespace",
        purgeEvents[0].resource && purgeEvents[0].resource.kind === "apikey-namespace");
  check("purge: resource id is the namespace",
        purgeEvents[0].resource.id === "purge-audit");
}

async function testFiveWsAuditPropagation() {
  var audit = b.testing.captureAudit();
  var keys = b.apiKey.create({ namespace: "five-ws", audit: audit });

  // Simulate a request with all 5 W's populated
  var fakeReq = b.testing.mockReq({
    ip:        "203.0.113.42",
    userAgent: "test-client/1.0",
    requestId: "req-abc-123",
    method:    "POST",
    url:       "/admin/keys/issue",
  });
  fakeReq.sessionId = "sess-xyz";
  fakeReq.user      = { id: "admin-7" };

  audit.clear();
  var issued = await keys.issue({
    ownerId: "u1",
    req: fakeReq,
  });
  var issueEvent = audit.byAction("apikey.issue")[0];
  check("5 W's: issue audit has actor",
        issueEvent && issueEvent.actor && typeof issueEvent.actor === "object");
  check("5 W's: issue actor.userId (WHO)",      issueEvent.actor.userId === "u1");
  check("5 W's: issue actor.ip (WHERE)",        issueEvent.actor.ip === "203.0.113.42");
  check("5 W's: issue actor.userAgent (HOW)",   issueEvent.actor.userAgent === "test-client/1.0");
  check("5 W's: issue actor.sessionId",         issueEvent.actor.sessionId === "sess-xyz");
  check("5 W's: issue actor.requestId",         issueEvent.actor.requestId === "req-abc-123");
  check("5 W's: issue actor.method",            issueEvent.actor.method === "POST");
  check("5 W's: issue actor.route",             issueEvent.actor.route === "/admin/keys/issue");

  // Verify path also propagates context
  audit.clear();
  var verifyReq = Object.assign({}, fakeReq, { url: "/api/data", method: "GET" });
  await keys.verify(issued.key, { req: verifyReq });
  var verifyEvent = audit.byAction("apikey.verify")[0];
  check("5 W's: verify audit has WHO (ownerId from row)",
        verifyEvent.actor.userId === "u1");
  check("5 W's: verify audit has WHERE (ip)",
        verifyEvent.actor.ip === "203.0.113.42");
  check("5 W's: verify audit has HOW (route)",
        verifyEvent.actor.route === "/api/data");
  check("5 W's: verify audit has HOW (method)",
        verifyEvent.actor.method === "GET");

  // List + getById propagate too
  audit.clear();
  await keys.listForOwner("u1", { req: fakeReq });
  await keys.getById(issued.id, { req: fakeReq });
  var listEvent = audit.byAction("apikey.list")[0];
  var getEvent  = audit.byAction("apikey.get")[0];
  check("5 W's: list audit has full context",
        listEvent.actor.ip === "203.0.113.42" && listEvent.actor.requestId === "req-abc-123");
  check("5 W's: get audit has full context",
        getEvent.actor.ip === "203.0.113.42" && getEvent.actor.requestId === "req-abc-123");

  // Explicit context override beats req fields
  audit.clear();
  await keys.revoke(issued.id, {
    req: fakeReq,
    context: { ip: "10.0.0.1", requestId: "manual-override" },
  });
  var revokeEvent = audit.byAction("apikey.revoke")[0];
  check("5 W's: explicit context.ip overrides req.ip",
        revokeEvent.actor.ip === "10.0.0.1");
  check("5 W's: explicit context.requestId overrides",
        revokeEvent.actor.requestId === "manual-override");
  check("5 W's: non-overridden fields still come from req",
        revokeEvent.actor.method === "POST" && revokeEvent.actor.route === "/admin/keys/issue");
}

async function testReadAccessAudit() {
  var audit = b.testing.captureAudit();
  var keys = b.apiKey.create({ namespace: "read-audit", audit: audit });
  var k1 = await keys.issue({ ownerId: "u1" });
  var k2 = await keys.issue({ ownerId: "u1" });

  audit.clear();             // drain issue events
  await keys.getById(k1.id);
  await keys.getById("0000000000000000");
  await keys.listForOwner("u1");

  check("read audit: getById emits apikey.get",
        audit.byAction("apikey.get").length > 0);
  check("read audit: listForOwner emits apikey.list",
        audit.byAction("apikey.list").length > 0);

  var getEvents = audit.byAction("apikey.get");
  check("read audit: get includes both calls (hit + miss)",
        getEvents.length === 2);
  check("read audit: hit event has found=true",
        getEvents.some(function (e) { return e.metadata && e.metadata.found === true; }));
  check("read audit: miss event has found=false",
        getEvents.some(function (e) { return e.metadata && e.metadata.found === false; }));

  var listEvent = audit.byAction("apikey.list")[0];
  check("read audit: list metadata has ownerId",
        listEvent.metadata.ownerId === "u1");
  check("read audit: list metadata has count",
        listEvent.metadata.count === 2);
  check("read audit: list metadata has observedIds",
        Array.isArray(listEvent.metadata.observedIds) &&
        listEvent.metadata.observedIds.length === 2 &&
        listEvent.metadata.observedIds.indexOf(k1.id) !== -1 &&
        listEvent.metadata.observedIds.indexOf(k2.id) !== -1);
}

async function testReadAuditOptOut() {
  var audit = b.testing.captureAudit();
  var keys = b.apiKey.create({
    namespace: "read-audit-off",
    audit: audit,
    auditSuccess: false,            // operator opt-out for extreme volume
  });
  var issued = await keys.issue({ ownerId: "u1" });
  audit.clear();
  await keys.getById(issued.id);
  await keys.listForOwner("u1");
  check("opt-out: getById not audited",   audit.byAction("apikey.get").length === 0);
  check("opt-out: listForOwner not audited", audit.byAction("apikey.list").length === 0);
}

async function testVerifySuccessAudit() {
  var audit = b.testing.captureAudit();
  var keys = b.apiKey.create({ namespace: "verify-audit", audit: audit });
  var issued = await keys.issue({ ownerId: "u1" });
  audit.clear();
  await keys.verify(issued.key);
  var verifyEvent = audit.byAction("apikey.verify")[0];
  check("verify success now audited by default", !!verifyEvent);
  check("verify success outcome label",        verifyEvent.outcome === "success");
}

async function testReadObservability() {
  var cap = b.testing.captureMetricsTap();
  try {
    var keys = b.apiKey.create({ namespace: "read-obs" });
    var issued = await keys.issue({ ownerId: "u1" });
    await keys.getById(issued.id);
    await keys.getById("0000000000000000");          // miss
    await keys.listForOwner("u1");
    await keys.purgeExpired();                        // 0 rows but should emit
  } finally {
    cap.restore();
  }
  check("emits apikey.get",                   cap.byName("apikey.get").length > 0);
  check("emits apikey.list",                  cap.byName("apikey.list").length > 0);
  check("emits apikey.purge (zero-count)",    cap.byName("apikey.purge").length > 0);

  var getEvents = cap.byName("apikey.get");
  var hasFound = getEvents.some(function (e) { return e.labels.found === true; });
  var hasMiss  = getEvents.some(function (e) { return e.labels.found === false; });
  check("apikey.get emits found=true label",  hasFound === true);
  check("apikey.get emits found=false label", hasMiss === true);

  var listEvent = cap.byName("apikey.list")[0];
  check("apikey.list has count label",
        listEvent && typeof listEvent.labels.count === "number");
}

async function testAuditEmission() {
  // Build a capture-only audit via the framework's testing primitive
  var audit = b.testing.captureAudit();
  var keys = b.apiKey.create({ namespace: "audit-test", audit: audit });
  var issued = await keys.issue({ ownerId: "u1", scopes: ["x"] });
  await keys.revoke(issued.id);
  // Fresh issue for rotate
  var second = await keys.issue({ ownerId: "u2" });
  await keys.rotate(second.id);

  check("audit: apikey.issue emitted",     audit.byAction("apikey.issue").length > 0);
  check("audit: apikey.revoke emitted",    audit.byAction("apikey.revoke").length > 0);
  check("audit: apikey.rotate emitted",    audit.byAction("apikey.rotate").length > 0);

  var issueEvent = audit.byAction("apikey.issue")[0];
  check("audit: issue event has resource",
        issueEvent.resource && issueEvent.resource.kind === "apikey");
  check("audit: issue event has scope metadata",
        issueEvent.metadata && Array.isArray(issueEvent.metadata.scopes));
}

// ---- Run ----

async function run() {
  testApiKeySurface();
  testParseFormat();
  testCreateRejectsBadOpts();

  var tmp = _tmp();
  await setupTestDb(tmp);
  try {
    await testIssueAndVerifyRoundtrip(tmp);
    await testVerifyMalformed();
    await testVerifyWrongSecret();
    await testRevoke();
    await testExpired();
    await testRotate();
    await testRotateNotFoundOrRevoked();
    await testGracefulRotation();
    await testGracefulRotationExplicitMs();
    await testHardRotateClearsSecondary();
    await testEnvelopeFormatPersisted();
    await testHashAlgoOptArgon2id();
    await testListForOwner();
    await testGetById();
    await testTrackLastUsedAt();
    await testPurgeExpired();
    await testIssueRejectsBadOpts();
    await testPurgeAuditEmission();
    await testFiveWsAuditPropagation();
    await testReadAccessAudit();
    await testReadAuditOptOut();
    await testVerifySuccessAudit();
    await testReadObservability();
    await testAuditEmission();
  } finally {
    await teardownTestDb(tmp);
  }
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e.message); process.exit(1); }
  );
}
