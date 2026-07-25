// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.session — canonical lifecycle + adversarial coverage for lib/session.js.
 *
 * Drives the real b.session consumer surface (create / verify / touch /
 * rotate / destroy / destroyAllForUser / updateData / purgeExpired / count /
 * logout) against a live encrypted test DB — the production path, no
 * NODE_ENV=test bypass. The device-binding / valid-from / store-backed
 * fingerprint paths are exercised by their dedicated siblings; this file
 * targets the remaining lifecycle branches those tests don't reach:
 *
 *   - config-time input validation (ttl bounds, missing userId, bad
 *     cookieName, bad extendBy)
 *   - token-shape guards on every mutator (empty / non-string /
 *     pre-sealed-format / tampered-envelope tokens)
 *   - the idle + absolute + operator-ttl timeout floors on verify() and
 *     touch() (rows aged deterministically via a localDbThin store, so no
 *     wall-clock sleeps)
 *   - purgeExpired() and count()
 *   - rotate() ttl / data-replace / carry-forward / unknown-token branches
 *   - the decrypt-then-parse failure path on verify() + updateData() (a
 *     valid envelope whose plaintext is not JSON — key-skew / corruption)
 *   - custom function-form fingerprint fields
 *
 * Run standalone: node test/layer-0-primitives/session.test.js
 * Or via smoke:   node test/smoke.js
 */

var helpers = require("../helpers");
var b              = helpers.b;
var check          = helpers.check;
var setupTestDb    = helpers.setupTestDb;
var teardownTestDb = helpers.teardownTestDb;
var fs   = require("fs");
var os   = require("os");
var path = require("path");

var TIME = b.constants.TIME;
var SESSION_TABLE = "_blamejs_sessions";

function _mktmp(tag) {
  return fs.mkdtempSync(path.join(os.tmpdir(), "ses-" + tag + "-"));
}

// A localDbThin session store whose rows we can age with raw SQL so the
// idle / absolute / operator-ttl timeout floors trip deterministically —
// no reliance on wall-clock elapsed time (poll-don't-sleep).
function _thinStore(tmpDir, tag) {
  return b.session.stores.localDbThin({ file: path.join(tmpDir, tag + ".db"), audit: false });
}

// Age every row in the store's session table by rewriting the plain int
// columns (createdAt / lastActivity / expiresAt are not sealed).
function _ageAll(store, cols) {
  var sets = [];
  var params = [];
  Object.keys(cols).forEach(function (c) { sets.push('"' + c + '" = ?'); params.push(cols[c]); });
  return store.execute('UPDATE "' + SESSION_TABLE + '" SET ' + sets.join(", "), params);
}

// ---------------------------------------------------------------------------
// Block A — default store (framework DB). No row aging needed.
// ---------------------------------------------------------------------------

async function testBasicLifecycle() {
  var tmpDir = _mktmp("life");
  try {
    await setupTestDb(tmpDir);
    var s = await b.session.create({ userId: "u-1", data: { role: "admin" } });
    check("create returns a sealed token + expiresAt",
      typeof s.token === "string" && s.token.indexOf("vault:") === 0 && typeof s.expiresAt === "number");

    var info = await b.session.verify(s.token);
    check("verify returns the userId + data + timestamps",
      info && info.userId === "u-1" && info.data.role === "admin" &&
      typeof info.createdAt === "number" && typeof info.lastActivity === "number");
    check("verify surfaces fingerprintDrift:false / anomalyScore:null on an unbound session",
      info.fingerprintDrift === false && info.fingerprintAnomalyScore === null);

    var n = await b.session.count();
    check("count reports the one live session", n === 1);

    var gone = await b.session.destroy(s.token);
    check("destroy returns true", gone === true);
    check("verify returns null after destroy", (await b.session.verify(s.token)) === null);
    check("destroy again returns false (already gone)", (await b.session.destroy(s.token)) === false);
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function testCreateInputValidation() {
  var tmpDir = _mktmp("cval");
  try {
    await setupTestDb(tmpDir);

    async function throws(fn) {
      try { await fn(); return null; } catch (e) { return e; }
    }

    var e1 = await throws(function () { return b.session.create({}); });
    check("create({}) with no userId throws INVALID_ARG", e1 && e1.code === "INVALID_ARG");
    var e2 = await throws(function () { return b.session.create(); });
    check("create() with no opts throws INVALID_ARG", e2 && e2.code === "INVALID_ARG");

    var eNeg = await throws(function () { return b.session.create({ userId: "u", ttlMs: -5 }); });
    check("create ttlMs negative throws", eNeg && eNeg.code === "INVALID_ARG");
    var eZero = await throws(function () { return b.session.create({ userId: "u", ttlMs: 0 }); });
    check("create ttlMs 0 throws", eZero && eZero.code === "INVALID_ARG");
    var eInf = await throws(function () { return b.session.create({ userId: "u", ttlMs: Infinity }); });
    check("create ttlMs Infinity throws (non-finite)", eInf && eInf.code === "INVALID_ARG");
    var eNaN = await throws(function () { return b.session.create({ userId: "u", ttlMs: NaN }); });
    check("create ttlMs NaN throws", eNaN && eNaN.code === "INVALID_ARG");
    var eStr = await throws(function () { return b.session.create({ userId: "u", ttlMs: "3600000" }); });
    check("create ttlMs string throws (not a number)", eStr && eStr.code === "INVALID_ARG");
    var eMax = await throws(function () { return b.session.create({ userId: "u", ttlMs: TIME.days(4000) }); });
    check("create ttlMs beyond ~10y ceiling throws", eMax && eMax.code === "INVALID_ARG" && /exceeds maximum/.test(eMax.message));
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function testVerifyTokenGuards() {
  var tmpDir = _mktmp("vguard");
  try {
    await setupTestDb(tmpDir);
    check("verify('') returns null", (await b.session.verify("")) === null);
    check("verify(null) returns null", (await b.session.verify(null)) === null);
    check("verify(number) returns null", (await b.session.verify(12345)) === null);
    check("verify(pre-sealed raw hex) returns null",
      (await b.session.verify("deadbeefcafef00d".repeat(4))) === null);
    check("verify(tampered vault: envelope) returns null",
      (await b.session.verify("vault:not-real-ciphertext")) === null);
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function testDestroyGuards() {
  var tmpDir = _mktmp("dguard");
  try {
    await setupTestDb(tmpDir);
    check("destroy('') returns false", (await b.session.destroy("")) === false);
    check("destroy(null) returns false", (await b.session.destroy(null)) === false);
    check("destroy(pre-sealed raw) returns false",
      (await b.session.destroy("deadbeefcafef00d".repeat(4))) === false);
    check("destroy(tampered vault: envelope) returns false",
      (await b.session.destroy("vault:garbage")) === false);
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function testDestroyAllForUserGuards() {
  var tmpDir = _mktmp("daguard");
  try {
    await setupTestDb(tmpDir);
    async function throws(fn) { try { await fn(); return null; } catch (e) { return e; } }
    var e1 = await throws(function () { return b.session.destroyAllForUser(""); });
    check("destroyAllForUser('') throws INVALID_ARG", e1 && e1.code === "INVALID_ARG");
    var e2 = await throws(function () { return b.session.destroyAllForUser(null); });
    check("destroyAllForUser(null) throws INVALID_ARG", e2 && e2.code === "INVALID_ARG");

    // Happy path: two sessions for one user, both revoked in one call.
    await b.session.create({ userId: "multi" });
    await b.session.create({ userId: "multi" });
    var revoked = await b.session.destroyAllForUser("multi");
    check("destroyAllForUser revokes every live session for the user", revoked === 2);
    check("destroyAllForUser on a user with no sessions returns 0",
      (await b.session.destroyAllForUser("nobody")) === 0);
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function testRotateVariants() {
  var tmpDir = _mktmp("rot");
  try {
    await setupTestDb(tmpDir);
    check("rotate('') returns null", (await b.session.rotate("")) === null);
    check("rotate(tampered vault: envelope) returns null",
      (await b.session.rotate("vault:garbage")) === null);

    // Rotate on a destroyed (unknown) session → null.
    var dead = await b.session.create({ userId: "u-dead" });
    await b.session.destroy(dead.token);
    check("rotate on a destroyed session returns null", (await b.session.rotate(dead.token)) === null);

    // Rotate replacing data + shrinking ttl to 1h (verifies both the
    // data-replace and expiresAt-set branches).
    var s1 = await b.session.create({ userId: "u-rot1", data: { a: 1, keep: "x" }, ttlMs: TIME.days(7) });
    var r1 = await b.session.rotate(s1.token, { data: { b: 2 }, ttlMs: TIME.hours(1), reason: "login" });
    check("rotate returns a fresh sealed token", r1 && r1.token.indexOf("vault:") === 0 && r1.token !== s1.token);
    check("old token no longer verifies after rotate", (await b.session.verify(s1.token)) === null);
    var v1 = await b.session.verify(r1.token);
    check("rotate replaced the data payload (b present, a/keep gone)",
      v1 && v1.data && v1.data.b === 2 && v1.data.a === undefined && v1.data.keep === undefined);
    check("rotate ttlMs shrank expiresAt to ~now+1h (well under 7d)",
      v1.expiresAt <= Date.now() + TIME.hours(2));

    // Rotate WITHOUT opts.data carries the existing payload forward unchanged.
    var s2 = await b.session.create({ userId: "u-rot2", data: { carried: true } });
    var r2 = await b.session.rotate(s2.token);
    var v2 = await b.session.verify(r2.token);
    check("rotate without opts.data carries the existing payload forward",
      v2 && v2.data && v2.data.carried === true);

    // Rotate rejects a bad ttlMs (config-time throw).
    var s3 = await b.session.create({ userId: "u-rot3" });
    var eTtl = null;
    try { await b.session.rotate(s3.token, { ttlMs: -1 }); } catch (e) { eTtl = e; }
    check("rotate rejects a negative ttlMs", eTtl && eTtl.code === "INVALID_ARG");
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function testLogoutValidation() {
  var tmpDir = _mktmp("lval");
  try {
    await setupTestDb(tmpDir);
    var s = await b.session.create({ userId: "u-lo" });

    async function throws(fn) { try { await fn(); return null; } catch (e) { return e; } }

    var eEmpty = await throws(function () {
      return b.session.logout({ setHeader: function () {} }, s.token, { cookieName: "" });
    });
    check("logout rejects an empty cookieName", eEmpty && eEmpty.code === "session/bad-cookie-name");
    var eNonStr = await throws(function () {
      return b.session.logout({ setHeader: function () {} }, s.token, { cookieName: 42 });
    });
    check("logout rejects a non-string cookieName", eNonStr && eNonStr.code === "session/bad-cookie-name");

    // The rejected logouts must not have destroyed the row (validate-before-revoke).
    check("logout validation throw left the session intact", (await b.session.verify(s.token)) !== null);
  } finally {
    await teardownTestDb(tmpDir);
  }
}

// Custom function-form fingerprint fields — both a value-returning fn and a
// throwing fn (the catch substitutes ""), proven to bind + match on verify.
async function testFingerprintFunctionField() {
  var tmpDir = _mktmp("fpfn");
  try {
    await setupTestDb(tmpDir);
    function tenantTag(req) { return String((req.headers && req.headers["x-tenant"]) || ""); }
    function boom() { throw new Error("scorer-style throw"); }
    // An anonymous field (name "") exercises the "custom<i>" naming fallback.
    function makeAnon() { return function (req) { return String((req.headers && req.headers["x-anon"]) || ""); }; }
    var req = { headers: { "x-tenant": "acme", "x-anon": "z" }, socket: { remoteAddress: "203.0.113.9" } };
    var fields1 = [tenantTag, boom, makeAnon()];
    var fields2 = [tenantTag, boom, makeAnon()];

    var s = await b.session.create({ userId: "u-fp", req: req, fingerprintFields: fields1 });
    var same = await b.session.verify(s.token, { req: req, fingerprintFields: fields2 });
    check("custom fn fingerprint field binds + matches (no drift)", same && same.fingerprintDrift === false);

    var other = { headers: { "x-tenant": "evilcorp", "x-anon": "z" }, socket: { remoteAddress: "203.0.113.9" } };
    var drift = await b.session.verify(s.token, { req: other, fingerprintFields: fields2 });
    check("custom fn fingerprint field drifts when its value changes", drift && drift.fingerprintDrift === true);
  } finally {
    await teardownTestDb(tmpDir);
  }
}

// Odds-and-ends guards: validFrom on an empty subject, and updateData on a
// token whose sid unseals fine but whose row is already gone.
async function testMiscGuards() {
  var tmpDir = _mktmp("misc");
  try {
    await setupTestDb(tmpDir);
    check("validFrom('') returns 0 (no subject)", (await b.session.validFrom("")) === 0);

    var s = await b.session.create({ userId: "u-misc", data: { a: 1 } });
    await b.session.destroy(s.token);
    check("updateData on a valid-sid but deleted row returns false",
      (await b.session.updateData(s.token, { b: 2 })) === false);
  } finally {
    await teardownTestDb(tmpDir);
  }
}

// count()'s defensive null-guard: a store whose executeOne yields no COUNT
// row makes count() return 0 rather than crash. Real SQL backends always
// return a row for COUNT(*), so this exercises the fail-safe path only a
// store contract violation can reach.
async function testCountDefensiveNullRow() {
  var tmpDir = _mktmp("cnt0");
  try {
    await setupTestDb(tmpDir);
    b.session.useStore({
      execute:    function () { return Promise.resolve({ rows: [], rowCount: 0 }); },
      executeOne: function () { return Promise.resolve(null); },
    });
    check("count() returns 0 when the store yields no count row", (await b.session.count()) === 0);
  } finally {
    b.session.useStore(null);
    await teardownTestDb(tmpDir);
  }
}

// ---------------------------------------------------------------------------
// Block B — localDbThin store, rows aged with raw SQL so timeout floors trip
// deterministically.
// ---------------------------------------------------------------------------

async function testVerifyExpiredTtl() {
  var tmpDir = _mktmp("vexp");
  var store = _thinStore(tmpDir, "vexp");
  try {
    await setupTestDb(tmpDir);
    b.session.useStore(store);
    var s = await b.session.create({ userId: "u-exp" });
    // Age the operator-set expiry into the past.
    await _ageAll(store, { expiresAt: Date.now() - TIME.minutes(1) });
    check("verify returns null for a session past its operator ttl",
      (await b.session.verify(s.token)) === null);
    // The leader-side cleanup deleted the row.
    check("expired-ttl verify purged the row (count 0)", (await b.session.count()) === 0);
  } finally {
    b.session.useStore(null);
    try { store.close(); } catch (_e) { /* best-effort */ }
    await teardownTestDb(tmpDir);
  }
}

async function testVerifyIdleFloor() {
  var tmpDir = _mktmp("vidle");
  var store = _thinStore(tmpDir, "vidle");
  try {
    await setupTestDb(tmpDir);
    b.session.useStore(store);
    var s = await b.session.create({ userId: "u-idle" });
    // expiresAt stays in the future; lastActivity is aged past the 30m idle floor.
    await _ageAll(store, { lastActivity: Date.now() - TIME.minutes(45) });
    check("verify returns null when the idle floor is breached",
      (await b.session.verify(s.token)) === null);
    check("idle-floor verify purged the row (count 0)", (await b.session.count()) === 0);

    // Explicit idle opt-out (idleTimeoutMs:0) keeps an idle-aged session usable.
    var s2 = await b.session.create({ userId: "u-idle2" });
    await _ageAll(store, { lastActivity: Date.now() - TIME.minutes(45) });
    var ok = await b.session.verify(s2.token, { idleTimeoutMs: 0, absoluteTimeoutMs: 0 });
    check("verify with idle+absolute disabled returns an idle-aged session", ok && ok.userId === "u-idle2");
  } finally {
    b.session.useStore(null);
    try { store.close(); } catch (_e) { /* best-effort */ }
    await teardownTestDb(tmpDir);
  }
}

async function testVerifyAbsoluteFloor() {
  var tmpDir = _mktmp("vabs");
  var store = _thinStore(tmpDir, "vabs");
  try {
    await setupTestDb(tmpDir);
    b.session.useStore(store);
    var s = await b.session.create({ userId: "u-abs" });
    // lastActivity recent (idle OK), createdAt past the 12h absolute ceiling.
    await _ageAll(store, { lastActivity: Date.now(), createdAt: Date.now() - TIME.hours(13) });
    check("verify returns null when the absolute floor is breached",
      (await b.session.verify(s.token)) === null);
    check("absolute-floor verify purged the row (count 0)", (await b.session.count()) === 0);
  } finally {
    b.session.useStore(null);
    try { store.close(); } catch (_e) { /* best-effort */ }
    await teardownTestDb(tmpDir);
  }
}

async function testTouchLifecycleAndFloor() {
  var tmpDir = _mktmp("touch");
  var store = _thinStore(tmpDir, "touch");
  try {
    await setupTestDb(tmpDir);
    b.session.useStore(store);

    // Token-shape guards.
    check("touch('') returns false", (await b.session.touch("")) === false);
    check("touch(pre-sealed raw) returns false",
      (await b.session.touch("deadbeefcafef00d".repeat(4))) === false);

    // touch on an unknown (destroyed) session → false (no floorRow).
    var dead = await b.session.create({ userId: "u-t-dead" });
    await b.session.destroy(dead.token);
    check("touch on a destroyed session returns false", (await b.session.touch(dead.token)) === false);

    // Plain touch bumps lastActivity forward: age it into the past, touch,
    // then read it back through verify.
    var s = await b.session.create({ userId: "u-touch" });
    await _ageAll(store, { lastActivity: Date.now() - TIME.minutes(10) });
    var touched = await b.session.touch(s.token);
    check("touch returns true for a live session", touched === true);
    var after = await b.session.verify(s.token);
    check("touch bumped lastActivity forward to ~now",
      after && after.lastActivity >= Date.now() - TIME.minutes(1));

    // extendBy resets expiresAt relative to now.
    var ext = await b.session.touch(s.token, { extendBy: TIME.hours(3) });
    check("touch({extendBy}) returns true", ext === true);
    var afterExt = await b.session.verify(s.token);
    check("touch extendBy moved expiresAt to ~now+3h",
      afterExt && afterExt.expiresAt <= Date.now() + TIME.hours(4) && afterExt.expiresAt > Date.now() + TIME.hours(2));

    // touch rejects a bad extendBy (config-time throw).
    var eExt = null;
    try { await b.session.touch(s.token, { extendBy: -1 }); } catch (e) { eExt = e; }
    check("touch rejects a negative extendBy", eExt && eExt.code === "INVALID_ARG");

    // touch on an idle-aged session refuses AND purges (floor breach).
    var s2 = await b.session.create({ userId: "u-touch-idle" });
    await _ageAll(store, { lastActivity: Date.now() - TIME.minutes(45) });
    var refused = await b.session.touch(s2.token);
    check("touch on an idle-floor-breached session returns false", refused === false);
    check("touch floor breach purged the row (verify null)", (await b.session.verify(s2.token)) === null);
  } finally {
    b.session.useStore(null);
    try { store.close(); } catch (_e) { /* best-effort */ }
    await teardownTestDb(tmpDir);
  }
}

async function testPurgeExpired() {
  var tmpDir = _mktmp("purge");
  var store = _thinStore(tmpDir, "purge");
  try {
    await setupTestDb(tmpDir);
    b.session.useStore(store);

    await b.session.create({ userId: "u-p1" });
    await b.session.create({ userId: "u-p2" });
    check("count sees both live sessions", (await b.session.count()) === 2);

    // Age both past expiry — count() now excludes them but they remain on disk.
    await _ageAll(store, { expiresAt: Date.now() - TIME.minutes(5) });
    check("count excludes expired-but-unpurged rows", (await b.session.count()) === 0);

    var dropped = await b.session.purgeExpired();
    check("purgeExpired removes the expired rows", dropped === 2);
    check("purgeExpired again removes nothing (returns 0)", (await b.session.purgeExpired()) === 0);

    // A fresh live session survives a purge.
    var live = await b.session.create({ userId: "u-live" });
    check("purgeExpired leaves a live session (returns 0)", (await b.session.purgeExpired()) === 0);
    check("the live session still verifies after purge", (await b.session.verify(live.token)) !== null);
  } finally {
    b.session.useStore(null);
    try { store.close(); } catch (_e) { /* best-effort */ }
    await teardownTestDb(tmpDir);
  }
}

// A sealed `data` cell that decrypts to a valid envelope but non-JSON
// plaintext (key-rotation skew / corruption). verify() must null the data,
// keep the session usable for non-data flows, and updateData() must recover
// by writing the fresh payload over the unparseable one.
async function testUnparseableDataRecovery() {
  var tmpDir = _mktmp("garbage");
  var store = _thinStore(tmpDir, "garbage");
  try {
    await setupTestDb(tmpDir);
    b.session.useStore(store);

    // A valid vault: envelope whose plaintext is not JSON.
    var garbage = b.cryptoField.sealRow(SESSION_TABLE, { data: "not-json{{{" }).data;
    check("prepared a sealed envelope with non-JSON plaintext",
      typeof garbage === "string" && garbage.indexOf("vault:") === 0);

    var s = await b.session.create({ userId: "u-garbage", data: { real: 1 } });
    await store.execute('UPDATE "' + SESSION_TABLE + '" SET "data" = ?', [garbage]);

    var info = await b.session.verify(s.token);
    check("verify returns the session with data=null when data can't be parsed",
      info && info.userId === "u-garbage" && info.data === null);

    // updateData over an unparseable payload still lands the new data.
    var wrote = await b.session.updateData(s.token, { fresh: true });
    check("updateData recovers from an unparseable existing payload", wrote === true);
    var after = await b.session.verify(s.token);
    check("updateData wrote the fresh payload", after && after.data && after.data.fresh === true);
  } finally {
    b.session.useStore(null);
    try { store.close(); } catch (_e) { /* best-effort */ }
    await teardownTestDb(tmpDir);
  }
}

async function run() {
  // Block A — default store.
  await testBasicLifecycle();
  await testCreateInputValidation();
  await testVerifyTokenGuards();
  await testDestroyGuards();
  await testDestroyAllForUserGuards();
  await testRotateVariants();
  await testLogoutValidation();
  await testFingerprintFunctionField();
  await testMiscGuards();
  await testCountDefensiveNullRow();
  // Block B — localDbThin store with deterministic row aging.
  await testVerifyExpiredTtl();
  await testVerifyIdleFloor();
  await testVerifyAbsoluteFloor();
  await testTouchLifecycleAndFloor();
  await testRotateUpdateDataEnforceFloor();
  await testStrictBindingWithoutReqFailsClosed();
  await testPurgeExpired();
  await testUnparseableDataRecovery();
}

// rotate() and updateData() must enforce the SAME idle/absolute floor
// verify()/touch() do — a refresh/write must never resurrect a session
// verify() would expire (OWASP ASVS 5.0 §3.3 / NIST SP 800-63B-4).
async function testRotateUpdateDataEnforceFloor() {
  var tmpDir = _mktmp("vfloor");
  var store = _thinStore(tmpDir, "vfloor");
  try {
    await setupTestDb(tmpDir);
    b.session.useStore(store);

    var s1 = await b.session.create({ userId: "u-rot-idle" });
    await _ageAll(store, { lastActivity: Date.now() - TIME.minutes(45) });   // idle floor breached, TTL still live
    check("rotate on an idle-floor-breached session returns null",
      (await b.session.rotate(s1.token)) === null);
    check("rotate floor breach purged the row (count 0)", (await b.session.count()) === 0);

    var s2 = await b.session.create({ userId: "u-upd-idle" });
    await _ageAll(store, { lastActivity: Date.now() - TIME.minutes(45) });
    check("updateData on an idle-floor-breached session returns false",
      (await b.session.updateData(s2.token, { a: 1 })) === false);
    check("updateData floor breach purged the row (verify null)",
      (await b.session.verify(s2.token)) === null);

    var s3 = await b.session.create({ userId: "u-rot-abs" });
    await _ageAll(store, { lastActivity: Date.now(), createdAt: Date.now() - TIME.hours(13) });   // absolute floor breached
    check("rotate on an absolute-floor-breached session returns null",
      (await b.session.rotate(s3.token)) === null);

    // The floor policy is per-call: a deployment disabling the idle floor via
    // idleTimeoutMs:0 must have that honored by rotate/updateData too, exactly
    // as verify() does — a long-idle session is NOT purged when the override is
    // passed.
    var s4 = await b.session.create({ userId: "u-ov-rot" });
    await _ageAll(store, { lastActivity: Date.now() - TIME.minutes(45) });
    check("rotate with idleTimeoutMs:0 keeps a long-idle session (override respected)",
      (await b.session.rotate(s4.token, { idleTimeoutMs: 0, absoluteTimeoutMs: 0 })) !== null);

    var s5 = await b.session.create({ userId: "u-ov-upd" });
    await _ageAll(store, { lastActivity: Date.now() - TIME.minutes(45) });
    check("updateData with idleTimeoutMs:0 keeps a long-idle session (override respected)",
      (await b.session.updateData(s5.token, { x: 1 }, { idleTimeoutMs: 0, absoluteTimeoutMs: 0 })) === true);
  } finally {
    b.session.useStore(null);
    try { store.close(); } catch (_e) { /* best-effort */ }
    await teardownTestDb(tmpDir);
  }
}

// A strict binding flag (requireFingerprintMatch / maxAnomalyScore) asserted
// WITHOUT a req cannot compute the current device fingerprint, so verify must
// fail CLOSED — never silently admit the session from any device.
async function testStrictBindingWithoutReqFailsClosed() {
  var tmpDir = _mktmp("sbind");
  var store = _thinStore(tmpDir, "sbind");
  try {
    await setupTestDb(tmpDir);
    b.session.useStore(store);
    var s = await b.session.create({ userId: "u-strict" });
    check("verify requireFingerprintMatch without req → null (fail closed)",
      (await b.session.verify(s.token, { requireFingerprintMatch: true })) === null);
    check("verify maxAnomalyScore without req → null (fail closed)",
      (await b.session.verify(s.token, { maxAnomalyScore: 0.5 })) === null);
    check("non-strict verify without req still admits (unchanged)",
      (await b.session.verify(s.token)) !== null);
  } finally {
    b.session.useStore(null);
    try { store.close(); } catch (_e) { /* best-effort */ }
    await teardownTestDb(tmpDir);
  }
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK session — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e && e.stack || e); process.exit(1); }
  );
}
