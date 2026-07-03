// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.session.bump / validFrom / check — per-subject valid-from boundary for
 * STATELESS self-validating tokens (sealed cookies with no DB row, JWTs) that
 * destroy()/destroyAllForUser() can't revoke by deleting a row (#331).
 *
 * Drives the real consumer path through the public b.session surface against a
 * real test DB (setupTestDb provisions the framework _blamejs_session_valid_from
 * table). RED on the current tree: b.session.bump is undefined.
 */

var helpers = require("../helpers");
var b     = helpers.b;
var check = helpers.check;
var setupTestDb = helpers.setupTestDb;
var teardownTestDb = helpers.teardownTestDb;
var fs   = require("fs");
var os   = require("os");
var path = require("path");

async function run() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-svf-"));
  try {
    await setupTestDb(tmpDir);
    var s = b.session;

    check("bump / validFrom / check are exported on b.session",
      typeof s.bump === "function" && typeof s.validFrom === "function" && typeof s.check === "function");

    // A never-bumped subject has boundary 0 — every non-negative iat is valid.
    check("validFrom is 0 for a never-bumped subject", (await s.validFrom("user-1")) === 0);
    var t0 = Date.now() - 10000;
    check("a token issued before any bump is valid", (await s.check("user-1", t0)) === true);

    // bump raises the boundary to now; tokens issued before it are revoked.
    var boundary = await s.bump("user-1");
    check("bump returns the effective boundary (>= the pre-bump iat)",
      typeof boundary === "number" && boundary >= t0);
    check("validFrom now reflects the bump", (await s.validFrom("user-1")) === boundary);
    check("a token issued BEFORE the bump is now revoked", (await s.check("user-1", t0)) === false);
    check("a token issued AFTER the bump is still valid", (await s.check("user-1", boundary + 1000)) === true);

    // Monotonic: a lower (replayed / clock-skewed) epoch can't move it back.
    var lower = await s.bump("user-1", { epochMs: boundary - 5000 });
    check("a bump to a LOWER epoch is a monotonic no-op", lower === boundary);
    var higher = await s.bump("user-1", { epochMs: boundary + 5000 });
    check("a bump to a HIGHER epoch advances the boundary", higher === boundary + 5000);

    // check fails CLOSED on a malformed iat (treat an unparseable token as revoked).
    check("check fails closed on NaN iat", (await s.check("user-1", NaN)) === false);
    check("check fails closed on a negative iat", (await s.check("user-1", -1)) === false);
    check("check fails closed on a non-number iat", (await s.check("user-1", "123")) === false);

    // bump validates its inputs (config-time throw tier).
    var threwSubject = false;
    try { await s.bump(""); } catch (e) { threwSubject = /INVALID_ARG/.test(e.code || ""); }
    check("bump rejects an empty subjectId", threwSubject);
    var threwEpoch = false;
    try { await s.bump("user-1", { epochMs: -1 }); } catch (e) { threwEpoch = /INVALID_ARG/.test(e.code || ""); }
    check("bump rejects a negative epochMs", threwEpoch);

    // #17 integration: a "logout everywhere" via destroyAllForUser also raises
    // the stateless boundary, so the operator's stateless tokens are revoked
    // too — not only the store-backed rows.
    check("a fresh subject starts un-bumped", (await s.validFrom("user-2")) === 0);
    await s.destroyAllForUser("user-2");
    check("destroyAllForUser raises the stateless valid-from boundary", (await s.validFrom("user-2")) > 0);
  } finally {
    try { await teardownTestDb(tmpDir); } catch (_e) { /* best-effort */ }
  }
}

module.exports = { run: run };
