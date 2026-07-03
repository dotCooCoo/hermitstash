// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.session.destroyAllForUser must succeed for a store-backed-only consumer
 * (b.session.useStore) that never called b.db.init() (#340).
 *
 * A store-backed-only deployment points session data at an isolated localDbThin
 * file and registers the _blamejs_sessions sealed/derived-hash schema directly
 * (so sealRow / lookupHash work) WITHOUT initializing the framework db. Every
 * revoke-all path — logout-everywhere, suspend, delete, role change — calls
 * destroyAllForUser, which deletes the store rows and then raises the stateless
 * valid-from boundary via bump(). The boundary table lives in the framework db,
 * so an uninitialized db threw db/not-initialized (a regression: worked in
 * 0.15.11, broke when bump() was added) and 500'd the revoke even though the
 * store rows were already deleted.
 *
 * RED on the pre-fix tree: destroyAllForUser throws (db/not-initialized rewrapped
 * to MISCONFIGURED). GREEN: it resolves AND the stateless valid-from boundary is
 * honored (routed through the configured store), so b.session.check revokes a
 * token issued before the boundary.
 *
 * Drives the real consumer path through the public b.session surface — no db.init.
 */

var helpers = require("../helpers");
var b     = helpers.b;
var check = helpers.check;
var setupVaultOnly    = helpers.setupVaultOnly;
var teardownVaultOnly = helpers.teardownVaultOnly;
var fs   = require("fs");
var os   = require("os");
var path = require("path");

// Mirror the framework's _blamejs_sessions sealed/derived schema (db.js
// FRAMEWORK_SCHEMA) so sealRow / lookupHash work without b.db.init().
function _registerSessionSchema() {
  b.cryptoField.registerTable("_blamejs_sessions", {
    sealedFields:  ["userId", "data"],
    derivedHashes: { userIdHash: { from: "userId" } },
  });
}

async function run() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-das-"));
  var storeFile = path.join(tmpDir, "sessions.db");
  var store = null;
  try {
    // Vault only — NO b.db.init(). This is the store-backed-only deployment.
    await setupVaultOnly(tmpDir);
    b.cluster._resetForTest();
    b.session._resetForTest();
    b.cryptoField.clearForTest();
    _registerSessionSchema();

    store = b.session.stores.localDbThin({ file: storeFile, audit: false });
    b.session.useStore(store);

    var s = b.session;
    var uid = "user-340";

    // Create a real store-backed session so destroyAllForUser has a row to
    // delete (drives sealRow + the store INSERT — the shipped consumer path).
    var created = await s.create({ userId: uid });
    check("create returns a sealed cookie token", typeof created.token === "string" && created.token.length > 0);

    // A token issued NOW (before any revoke) is valid against the boundary.
    var iatBefore = Date.now();
    check("a token issued before any revoke passes session.check",
      (await s.check(uid, iatBefore)) === true);
    check("a fresh subject's valid-from boundary is 0", (await s.validFrom(uid)) === 0);

    // The bug: destroyAllForUser deletes the store rows, then bump() routes the
    // valid-from upsert to the framework db (uninitialized) and throws. With the
    // fix it falls back to the configured store and resolves.
    var revoked = null;
    var threw = null;
    try {
      revoked = await s.destroyAllForUser(uid);
    } catch (e) {
      threw = e;
    }
    check("destroyAllForUser resolves for a store-backed-only consumer (no db.init)",
      threw === null);
    if (threw) {
      check("  (pre-fix would throw db/not-initialized → MISCONFIGURED): " +
        (threw.code || threw.message), false);
    }
    check("destroyAllForUser reports the deleted store-row count",
      typeof revoked === "number" && revoked >= 1);

    // The stateless valid-from boundary was actually raised (routed through the
    // store), not silently dropped — a token issued before it is now revoked.
    var boundary = await s.validFrom(uid);
    check("the stateless valid-from boundary was raised (honored, not dropped)",
      typeof boundary === "number" && boundary >= iatBefore);
    check("a token issued BEFORE the revoke now fails session.check",
      (await s.check(uid, iatBefore - 1000)) === false);
    check("a token issued AFTER the boundary still passes session.check",
      (await s.check(uid, boundary + 5000)) === true);

    // Monotonicity still holds through the store backend.
    var lower = await s.bump(uid, { epochMs: boundary - 5000 });
    check("a lower-epoch bump is a monotonic no-op through the store",
      lower === boundary);

    // With NEITHER a framework db NOR a store, bump still fails closed (the
    // boundary is never silently dropped — a real misconfiguration propagates).
    b.session.useStore(null);
    var threwNoStorage = null;
    try {
      await s.bump("user-no-storage");
    } catch (e) { threwNoStorage = e; }
    check("bump fails closed when neither a framework db nor a store exists",
      threwNoStorage !== null);
  } finally {
    try { if (store && store.close) store.close(); } catch (_e) { /* best-effort */ }
    b.session.useStore(null);
    b.session._resetForTest();
    b.cryptoField.clearForTest();
    try { teardownVaultOnly(tmpDir); } catch (_e) { /* best-effort */ }
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch (_e) { /* best-effort */ }
  }
}

module.exports = { run: run };
if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e && e.stack ? e.stack : e); process.exit(1); });
}
