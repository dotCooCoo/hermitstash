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

    // A res without setHeader is refused before any side effect.
    var eBadRes = await throws(function () { return b.session.logout(null, s.token); });
    check("logout rejects a res without setHeader()", eBadRes && eBadRes.code === "session/bad-res");

    // Happy path: destroy the row AND emit the client-wipe headers.
    var headers = {};
    var res = { setHeader: function (k, v) { headers[k] = v; } };
    var destroyed = await b.session.logout(res, s.token);
    check("logout returns true when it destroyed the session", destroyed === true);
    check("logout emitted a Clear-Site-Data header", typeof headers["Clear-Site-Data"] === "string" && headers["Clear-Site-Data"].length > 0);
    check("logout expired the sid cookie", /(^|\b)sid=; /.test(headers["Set-Cookie"]) && /Max-Age=0/.test(headers["Set-Cookie"]));
    check("logout revoked the session server-side", (await b.session.verify(s.token)) === null);

    // A custom cookieName is honored on the Set-Cookie.
    var s2 = await b.session.create({ userId: "u-lo2" });
    var headers2 = {};
    var res2 = { setHeader: function (k, v) { headers2[k] = v; } };
    await b.session.logout(res2, s2.token, { cookieName: "session" });
    check("logout honors a custom cookieName", /^session=; /.test(headers2["Set-Cookie"]));

    // An explicit types set overrides the RFC 9527 default directive set.
    var s3 = await b.session.create({ userId: "u-lo3" });
    var headers3 = {};
    var res3 = { setHeader: function (k, v) { headers3[k] = v; } };
    await b.session.logout(res3, s3.token, { types: ["cookies", "storage"] });
    check("logout honors an explicit Clear-Site-Data types set",
      /"cookies"/.test(headers3["Clear-Site-Data"]) && /"storage"/.test(headers3["Clear-Site-Data"]));
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
  // Block C — anon sessions, string fingerprint fields, drift/strict binding,
  // rotate/updateData payload branches, stateless valid-from boundary.
  await testAnonymousSessions();
  await testFingerprintStringFields();
  await testFingerprintDriftAndScorer();
  await testStrictBindingMissingAndUnreadable();
  await testRotateBoundAndPayload();
  await testUpdateDataBranches();
  await testRotateUnparseableCarryForward();
  await testBumpValidFromCheck();
  await testValidFromStoreFallback();
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

// ---------------------------------------------------------------------------
// Block C — anonymous sessions, string-form fingerprint fields, drift/strict
// binding, rotate/updateData payload branches, and the stateless valid-from
// boundary (bump / validFrom / check) on both the framework db and the
// store-backed fallback.
// ---------------------------------------------------------------------------

// b.session.create({ anonymous: true }) mints an "anon:"-prefixed opaque
// userId; passing anonymous + userId together is refused; destroyAllForUser
// refuses anon ids (per-session, not portable); isAnonymous reflects the flag.
async function testAnonymousSessions() {
  var tmpDir = _mktmp("anon");
  try {
    await setupTestDb(tmpDir);
    async function throws(fn) { try { await fn(); return null; } catch (e) { return e; } }

    var s = await b.session.create({ anonymous: true });
    check("create({anonymous:true}) returns a sealed token", s && s.token.indexOf("vault:") === 0);
    var info = await b.session.verify(s.token);
    check("anonymous session verifies with an anon:-prefixed userId",
      info && typeof info.userId === "string" && info.userId.indexOf("anon:") === 0);
    check("isAnonymous(anon userId) is true", b.session.isAnonymous(info.userId) === true);
    check("isAnonymous(plain userId) is false", b.session.isAnonymous("user-42") === false);

    var eBoth = await throws(function () { return b.session.create({ anonymous: true, userId: "u" }); });
    check("create({anonymous:true, userId}) refuses both", eBoth && eBoth.code === "INVALID_ARG");

    var eAnon = await throws(function () { return b.session.destroyAllForUser("anon:deadbeef"); });
    check("destroyAllForUser refuses an anon:-prefixed id", eAnon && eAnon.code === "INVALID_ARG" && /per-session/.test(eAnon.message));
  } finally {
    await teardownTestDb(tmpDir);
  }
}

// The default + string-form fingerprint fields (clientIp / clientIpPrefix /
// userAgent / acceptLanguage) plus a custom clientIpResolver, proven to bind
// on create and match on verify with no drift.
async function testFingerprintStringFields() {
  var tmpDir = _mktmp("fpstr");
  try {
    await setupTestDb(tmpDir);
    var reqA = {
      headers: { "user-agent": "Mozilla/5.0 UA-A", "accept-language": "en-US,en;q=0.9" },
      socket:  { remoteAddress: "203.0.113.7" },
    };

    // Session AA — default fingerprint fields (clientIp / userAgent /
    // acceptLanguage), bound via socket peer.
    var aa = await b.session.create({ userId: "u-fpA", req: reqA });
    var va = await b.session.verify(aa.token, { req: reqA });
    check("default-field fingerprint binds + matches (no drift)", va && va.fingerprintDrift === false);

    // Session BB — explicit string fields incl. clientIpPrefix, with a custom
    // clientIpResolver owning IP resolution end-to-end.
    function resolver(req) { return (req.socket && req.socket.remoteAddress) || ""; }
    var bbFields = ["clientIp", "clientIpPrefix", "userAgent", "acceptLanguage"];
    var bb = await b.session.create({ userId: "u-fpB", req: reqA, fingerprintFields: bbFields, clientIpResolver: resolver });
    var vb = await b.session.verify(bb.token, { req: reqA, fingerprintFields: bbFields, clientIpResolver: resolver });
    check("clientIpPrefix + clientIpResolver fingerprint binds + matches", vb && vb.fingerprintDrift === false);

    // A req with neither a headers object nor a socket exercises the
    // `req.headers || {}` fallback AND the empty-value `|| ""` coalescing on the
    // clientIp / userAgent fields (both resolve to "" and still match).
    var reqBare = {};
    var bareFields = ["clientIp", "userAgent"];
    var cc = await b.session.create({ userId: "u-fpC", req: reqBare, fingerprintFields: bareFields });
    var vc = await b.session.verify(cc.token, { req: reqBare, fingerprintFields: bareFields });
    check("bare req (no headers/socket) still binds + matches on empty-coalesced fields", vc && vc.fingerprintDrift === false);
  } finally {
    await teardownTestDb(tmpDir);
  }
}

// Fingerprint drift under every strict policy: requireFingerprintMatch kills;
// maxAnomalyScore kills when uncomputable OR above threshold, admits below;
// a scorer's throw / non-finite return leaves the score null (fail closed).
async function testFingerprintDriftAndScorer() {
  var tmpDir = _mktmp("fpscore");
  try {
    await setupTestDb(tmpDir);
    var reqA = { headers: { "user-agent": "UA-ORIG", "accept-language": "en-US" }, socket: { remoteAddress: "203.0.113.7" } };
    var reqB = { headers: { "user-agent": "UA-DIFFERENT", "accept-language": "en-US" }, socket: { remoteAddress: "203.0.113.7" } };

    var s = await b.session.create({ userId: "u-drift", req: reqA });

    // Non-strict drift returns the session with the drift flag set.
    var soft = await b.session.verify(s.token, { req: reqB });
    check("non-strict drift returns the session with fingerprintDrift:true", soft && soft.fingerprintDrift === true);

    // requireFingerprintMatch — any drift kills.
    check("requireFingerprintMatch:true kills a drifting session",
      (await b.session.verify(s.token, { req: reqB, requireFingerprintMatch: true })) === null);

    // maxAnomalyScore with NO scorer — score uncomputable → fail closed.
    check("maxAnomalyScore without a scorer fails closed on drift",
      (await b.session.verify(s.token, { req: reqB, maxAnomalyScore: 0.5 })) === null);

    // scorer returns a benign 0.1 (below threshold) — admitted, drift flagged.
    var below = await b.session.verify(s.token, {
      req: reqB, maxAnomalyScore: 0.5,
      scorer: function () { return 0.1; },
    });
    check("maxAnomalyScore admits drift scored below threshold",
      below && below.fingerprintDrift === true && below.fingerprintAnomalyScore === 0.1);

    // scorer returns 0.9 (above threshold) — killed.
    check("maxAnomalyScore kills drift scored above threshold",
      (await b.session.verify(s.token, { req: reqB, maxAnomalyScore: 0.5, scorer: function () { return 0.9; } })) === null);

    // scorer that throws — score stays null → fail closed.
    check("a throwing scorer leaves the score null → fail closed",
      (await b.session.verify(s.token, { req: reqB, maxAnomalyScore: 0.5, scorer: function () { throw new Error("boom"); } })) === null);

    // scorer returns a non-finite value — ignored, score stays null → fail closed.
    check("a non-finite scorer return fails closed",
      (await b.session.verify(s.token, { req: reqB, maxAnomalyScore: 0.5, scorer: function () { return NaN; } })) === null);

    // A scorer that clamps out-of-range high still admits below-threshold; prove
    // the >1 clamp path by scoring 5 (clamped to 1) above a 0.9 threshold → kill.
    check("an out-of-range scorer return is clamped (5 → 1 kills at 0.9)",
      (await b.session.verify(s.token, { req: reqB, maxAnomalyScore: 0.9, scorer: function () { return 5; } })) === null);
  } finally {
    await teardownTestDb(tmpDir);
  }
}

// A strict binding flag asserted against a session with NO comparable binding
// must fail closed — whether the binding is simply ABSENT (created without req)
// or UNREADABLE (a data cell that decrypts but doesn't parse).
async function testStrictBindingMissingAndUnreadable() {
  var tmpDir = _mktmp("sbmiss");
  var store = _thinStore(tmpDir, "sbmiss");
  try {
    await setupTestDb(tmpDir);
    b.session.useStore(store);
    var req = { headers: { "user-agent": "UA" }, socket: { remoteAddress: "203.0.113.7" } };

    // ABSENT binding — session created without req.
    var s = await b.session.create({ userId: "u-nobind" });
    check("strict verify (req present) with an unbound session fails closed",
      (await b.session.verify(s.token, { req: req, requireFingerprintMatch: true })) === null);

    // UNREADABLE binding — a valid envelope whose plaintext is not JSON.
    var garbage = b.cryptoField.sealRow(SESSION_TABLE, { data: "not-json{{{" }).data;
    var s2 = await b.session.create({ userId: "u-unreadable", data: { real: 1 } });
    await store.execute('UPDATE "' + SESSION_TABLE + '" SET "data" = ?', [garbage]);
    check("strict verify with an unreadable binding fails closed",
      (await b.session.verify(s2.token, { req: req, requireFingerprintMatch: true })) === null);
  } finally {
    b.session.useStore(null);
    try { store.close(); } catch (_e) { /* best-effort */ }
    await teardownTestDb(tmpDir);
  }
}

// rotate() on a fingerprint-bound session: re-keys the binding to the new sid
// (carry-forward + custom fields), requires req when bound, and clears data
// when opts.data is explicitly null.
async function testRotateBoundAndPayload() {
  var tmpDir = _mktmp("rotb");
  var store = _thinStore(tmpDir, "rotb");
  try {
    await setupTestDb(tmpDir);
    b.session.useStore(store);
    async function throws(fn) { try { await fn(); return null; } catch (e) { return e; } }
    var req = { headers: { "user-agent": "UA-ROT", "accept-language": "en-US" }, socket: { remoteAddress: "203.0.113.7" } };

    // A bound session rotated WITHOUT req cannot re-key the binding → throws.
    var sb = await b.session.create({ userId: "u-rb", data: { keep: 1 }, req: req });
    var eReq = await throws(function () { return b.session.rotate(sb.token); });
    check("rotate on a bound session without req throws ROTATE_FINGERPRINT_REQ_REQUIRED",
      eReq && eReq.code === "ROTATE_FINGERPRINT_REQ_REQUIRED");

    // Rotate WITH req, no opts.data → carry the payload forward and re-key the
    // binding to the new sid; the new token still matches the same device.
    var rb = await b.session.rotate(sb.token, { req: req });
    check("rotate (bound, carry-forward) returns a fresh token", rb && rb.token !== sb.token);
    var vrb = await b.session.verify(rb.token, { req: req });
    check("rotated bound session carries data forward + re-keyed binding matches",
      vrb && vrb.data && vrb.data.keep === 1 && vrb.fingerprintDrift === false);

    // Rotate WITH req + explicit custom fingerprintFields (the length>0 branch).
    var sc = await b.session.create({ userId: "u-rc", req: req, fingerprintFields: ["userAgent"] });
    var rc = await b.session.rotate(sc.token, { req: req, fingerprintFields: ["userAgent"] });
    var vrc = await b.session.verify(rc.token, { req: req, fingerprintFields: ["userAgent"] });
    check("rotate re-keys a custom-field binding (matches on new token)", vrc && vrc.fingerprintDrift === false);

    // Rotate an UNBOUND session with opts.data:null → clears the payload.
    var sd = await b.session.create({ userId: "u-rd", data: { gone: true } });
    var rd = await b.session.rotate(sd.token, { data: null });
    var vrd = await b.session.verify(rd.token);
    check("rotate with data:null clears the payload", vrd && vrd.data === null);

    // Rotate a BOUND session with opts.data:null + req — the data object is
    // cleared but re-seeded to carry the re-keyed binding forward.
    var se = await b.session.create({ userId: "u-re", data: { drop: 1 }, req: req });
    var re = await b.session.rotate(se.token, { data: null, req: req });
    var vre = await b.session.verify(re.token, { req: req });
    check("rotate (bound, data:null) clears operator data but keeps the binding",
      vre && vre.data === null && vre.fingerprintDrift === false);
  } finally {
    b.session.useStore(null);
    try { store.close(); } catch (_e) { /* best-effort */ }
    await teardownTestDb(tmpDir);
  }
}

// updateData input guards + payload branches: token guards, non-object data
// throws, null wipes the payload, merge:true deep-merges one level, and a
// bound session's __bj_fingerprint survives the write.
async function testUpdateDataBranches() {
  var tmpDir = _mktmp("upd");
  var store = _thinStore(tmpDir, "upd");
  try {
    await setupTestDb(tmpDir);
    b.session.useStore(store);
    async function throws(fn) { try { await fn(); return null; } catch (e) { return e; } }
    var req = { headers: { "user-agent": "UA-UPD" }, socket: { remoteAddress: "203.0.113.7" } };

    check("updateData('') returns false", (await b.session.updateData("", { a: 1 })) === false);
    check("updateData(tampered vault:) returns false", (await b.session.updateData("vault:garbage", { a: 1 })) === false);

    var s = await b.session.create({ userId: "u-upd", data: { keep: 1, nested: { x: 1 } } });
    var eStr = await throws(function () { return b.session.updateData(s.token, "not-an-object"); });
    check("updateData rejects a non-object data", eStr && eStr.code === "INVALID_ARG");
    var eArr = await throws(function () { return b.session.updateData(s.token, [1, 2]); });
    check("updateData rejects an array data", eArr && eArr.code === "INVALID_ARG");

    // merge:true — one-level deep merge into the existing payload.
    var merged = await b.session.updateData(s.token, { added: 2, nested: { y: 2 } }, { merge: true });
    check("updateData merge:true returns true", merged === true);
    var vm = await b.session.verify(s.token);
    check("updateData merge kept existing keys + added new ones, and merged the inner object ONE LEVEL DEEP (nested.x survives)",
      vm && vm.data && vm.data.keep === 1 && vm.data.added === 2 && vm.data.nested &&
      vm.data.nested.x === 1 && vm.data.nested.y === 2);
    // arrays / non-objects REPLACE (the other half of the documented one-level-deep merge): an array
    // value replaces the existing inner object, and a scalar replaces an existing scalar.
    var merged2 = await b.session.updateData(s.token, { nested: [9], keep: 5 }, { merge: true });
    var vm2 = await b.session.verify(s.token);
    check("updateData merge REPLACES an inner array and REPLACES a scalar (arrays/non-objects do not merge)",
      merged2 === true && vm2 && vm2.data && Array.isArray(vm2.data.nested) &&
      vm2.data.nested.length === 1 && vm2.data.nested[0] === 9 && vm2.data.keep === 5);
    // A NON-PLAIN object (Date) REPLACES an existing plain object — only two PLAIN objects merge (else a
    // Date, which has no enumerable keys, would leave the old object in place; a Buffer would mangle to
    // byte-index keys). The Date must reach JSON as its own ISO-string form.
    var sd = await b.session.create({ userId: "u-plain", data: { obj: { a: 1 } } });
    await b.session.updateData(sd.token, { obj: new Date("2020-01-02T03:04:05.000Z") }, { merge: true });
    var vsd = await b.session.verify(sd.token);
    check("updateData merge REPLACES a plain object with a Date (stored as its JSON ISO string, not the retained old object)",
      vsd && vsd.data && vsd.data.obj === "2020-01-02T03:04:05.000Z");

    // A merge that carries the reserved __bj_fingerprint key is ignored for it
    // (operators can't overwrite the binding) while other keys still merge.
    var mergedReserved = await b.session.updateData(s.token, { __bj_fingerprint: "forged", also: 3 }, { merge: true });
    check("updateData merge ignores a forged __bj_fingerprint but writes other keys", mergedReserved === true);
    var vmr = await b.session.verify(s.token);
    check("merge did not surface a forged __bj_fingerprint", vmr && vmr.data && vmr.data.also === 3 && vmr.data.__bj_fingerprint === undefined);

    // data:null wipes the payload.
    var wiped = await b.session.updateData(s.token, null);
    check("updateData(null) returns true", wiped === true);
    var vw = await b.session.verify(s.token);
    check("updateData(null) wiped the payload", vw && vw.data === null);

    // A bound session's fingerprint survives an updateData write.
    var sb = await b.session.create({ userId: "u-updfp", req: req });
    var wroteFp = await b.session.updateData(sb.token, { pref: "dark" });
    check("updateData on a bound session returns true", wroteFp === true);
    var vfp = await b.session.verify(sb.token, { req: req });
    check("updateData preserved the fingerprint binding (still matches)",
      vfp && vfp.fingerprintDrift === false && vfp.data && vfp.data.pref === "dark");
  } finally {
    b.session.useStore(null);
    try { store.close(); } catch (_e) { /* best-effort */ }
    await teardownTestDb(tmpDir);
  }
}

// rotate() carrying forward an UNPARSEABLE existing payload must not throw —
// the decrypt-then-parse catch drops the stale data and proceeds.
async function testRotateUnparseableCarryForward() {
  var tmpDir = _mktmp("rotgb");
  var store = _thinStore(tmpDir, "rotgb");
  try {
    await setupTestDb(tmpDir);
    b.session.useStore(store);
    var garbage = b.cryptoField.sealRow(SESSION_TABLE, { data: "not-json{{{" }).data;
    var s = await b.session.create({ userId: "u-rotgb", data: { real: 1 } });
    await store.execute('UPDATE "' + SESSION_TABLE + '" SET "data" = ?', [garbage]);
    var r = await b.session.rotate(s.token, { reason: "recover" });
    check("rotate over an unparseable payload still returns a fresh token", r && r.token.indexOf("vault:") === 0);
    var v = await b.session.verify(r.token);
    check("rotated session recovered (data null, session usable)", v && v.userId === "u-rotgb" && v.data === null);
  } finally {
    b.session.useStore(null);
    try { store.close(); } catch (_e) { /* best-effort */ }
    await teardownTestDb(tmpDir);
  }
}

// The stateless valid-from boundary against the framework db: bump input
// guards, explicit epochMs, monotonic no-op, validFrom read-back, and check()
// revoking a pre-boundary token while admitting a post-boundary one.
async function testBumpValidFromCheck() {
  var tmpDir = _mktmp("vfdb");
  try {
    await setupTestDb(tmpDir);
    async function throws(fn) { try { await fn(); return null; } catch (e) { return e; } }

    var eEmpty = await throws(function () { return b.session.bump(""); });
    check("bump('') throws INVALID_ARG", eEmpty && eEmpty.code === "INVALID_ARG");
    var eNeg = await throws(function () { return b.session.bump("u-vf", { epochMs: -1 }); });
    check("bump negative epochMs throws INVALID_ARG", eNeg && eNeg.code === "INVALID_ARG");
    var eNaN = await throws(function () { return b.session.bump("u-vf", { epochMs: NaN }); });
    check("bump NaN epochMs throws INVALID_ARG", eNaN && eNaN.code === "INVALID_ARG");

    var eff = await b.session.bump("u-vf", { epochMs: 5000 });
    check("bump with explicit epochMs returns that boundary", eff === 5000);
    var noop = await b.session.bump("u-vf", { epochMs: 1000 });
    check("a lower bump is a monotonic no-op (boundary unchanged)", noop === 5000);

    check("validFrom returns the bumped boundary", (await b.session.validFrom("u-vf")) === 5000);
    check("validFrom on a never-bumped subject returns 0", (await b.session.validFrom("u-never")) === 0);

    check("check admits a token issued at/after the boundary", (await b.session.check("u-vf", 6000)) === true);
    check("check revokes a token issued before the boundary", (await b.session.check("u-vf", 4000)) === false);
    check("check fails closed on a negative iat", (await b.session.check("u-vf", -1)) === false);
    check("check fails closed on a non-number iat", (await b.session.check("u-vf", "nope")) === false);
    check("check fails closed on a non-finite iat", (await b.session.check("u-vf", Infinity)) === false);
    check("check admits any non-negative iat for a never-bumped subject", (await b.session.check("u-never", 1)) === true);
  } finally {
    await teardownTestDb(tmpDir);
  }
}

// The valid-from boundary in a store-backed-only deployment: no framework db
// (b.db.init never awaited) but a configured store — the boundary provisions
// its table on demand and routes through the store instead of throwing
// db/not-initialized (#340).
async function testValidFromStoreFallback() {
  var tmpDir = _mktmp("vffb");
  var store = _thinStore(tmpDir, "vffb");
  try {
    // Deliberately NO setupTestDb — the framework db stays uninitialized so the
    // valid-from operations exercise the operator-store fallback path.
    b.session.useStore(store);
    var eff = await b.session.bump("store-subj", { epochMs: 7000 });
    check("bump routes through the operator store when no framework db exists", eff === 7000);
    check("validFrom reads the boundary back from the store", (await b.session.validFrom("store-subj")) === 7000);
    check("check revokes a pre-boundary token via the store", (await b.session.check("store-subj", 6999)) === false);
    check("check admits a post-boundary token via the store", (await b.session.check("store-subj", 7000)) === true);

    // With the store removed AND no framework db, the boundary can't be reached:
    // db/not-initialized propagates unchanged (fail closed — never silently
    // dropped). This exercises the _runValidFrom re-throw path.
    b.session.useStore(null);
    var propagated = null;
    try { await b.session.validFrom("store-subj"); } catch (e) { propagated = e; }
    check("validFrom with neither a framework db nor a store fails closed (propagates)",
      propagated && propagated.code === "db/not-initialized");
  } finally {
    b.session.useStore(null);
    try { store.close(); } catch (_e) { /* best-effort */ }
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch (_e) { /* best-effort */ }
  }
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK session — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e && e.stack || e); process.exit(1); }
  );
}
