// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.session.verify must FAIL CLOSED under a strict device-fingerprint policy
 * (requireFingerprintMatch / maxAnomalyScore) when the session carries NO stored
 * binding at all — i.e. it was created WITHOUT { req } (the framework's own
 * primary create() example does exactly this), so no __bj_fingerprint was ever
 * sealed into its data.
 *
 * This is the sibling of the "binding unreadable" fail-closed case: there the
 * sealed data cell existed but would not decrypt; here there is simply no
 * binding. Both mean the same thing to a strict verify — the device match
 * cannot be proven — so both must refuse, not silently skip the gate. The
 * pre-fix behaviour treated "there is no binding to compare" as "the binding
 * matches", admitting an unbound session from ANY device even though the
 * operator asked for strict fingerprint matching (directly, or through the
 * attachUser middleware that threads the flag into every verify).
 */

var helpers = require("../helpers");
var b = helpers.b;
var check = helpers.check;
var setupTestDb = helpers.setupTestDb;
var teardownTestDb = helpers.teardownTestDb;
var fs = require("fs");
var os = require("os");
var path = require("path");

var attachUser = b.middleware._modules.attachUser;

function _makeReq(headers) {
  return { headers: headers || {}, socket: {}, connection: {} };
}

// Drive the attachUser middleware to completion (it always calls next()).
async function _drive(mw, req) {
  var called = false;
  mw(req, {}, function () { called = true; });
  await helpers.waitUntil(function () { return called; }, {
    timeoutMs: 5000,
    label:     "session-strict-binding-missing: middleware called next()",
  });
}

async function run() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "ses-strict-missing-"));
  try {
    await setupTestDb(tmpDir);

    // Session created WITHOUT { req } — no device-fingerprint binding is sealed.
    // (This is exactly the shape of the create() docstring's primary example.)
    var s = await b.session.create({ userId: "u-unbound", data: { role: "admin" } });

    var devB = _makeReq({ "x-forwarded-for": "198.51.100.1", "user-agent": "attacker-device" });

    // --- requireFingerprintMatch on an UNBOUND session must FAIL CLOSED.
    var strict = await b.session.verify(s.token, { req: devB, requireFingerprintMatch: true });
    check("requireFingerprintMatch on an unbound session FAILS CLOSED (null)",
          strict === null);

    // --- maxAnomalyScore on an UNBOUND session must FAIL CLOSED too.
    var scored = await b.session.verify(s.token, { req: devB, maxAnomalyScore: 0.1 });
    check("maxAnomalyScore on an unbound session FAILS CLOSED (null)",
          scored === null);

    // --- The strict refusal must NOT destroy the row: a legitimate non-strict
    //     verify still returns the session (fail-closed, not fail-deleted).
    var loose = await b.session.verify(s.token, { req: devB });
    check("advisory verify (req, no strict opt) still returns the unbound session",
          loose && loose.userId === "u-unbound" && loose.fingerprintDrift === false);

    // --- Plain verify (no req) is unchanged — unbound sessions remain usable
    //     when the operator does not assert a strict binding policy.
    var plain = await b.session.verify(s.token);
    check("plain verify (no req) still returns the unbound session",
          plain && plain.userId === "u-unbound");

    // --- Regression guard: a BOUND session under the strict policy from its
    //     own device still verifies (the fix only closes the no-binding hole).
    var devA = _makeReq({ "x-forwarded-for": "203.0.113.10", "user-agent": "deviceA" });
    var bound = await b.session.create({ userId: "u-bound", req: devA });
    var boundOk = await b.session.verify(bound.token, { req: devA, requireFingerprintMatch: true });
    check("bound session under strict policy from its own device still verifies",
          boundOk && boundOk.userId === "u-bound");

    // --- The real consumer path: attachUser({ requireFingerprintMatch: true })
    //     threads the strict flag into every verify. An unbound session token
    //     must NOT attach a user from a foreign device.
    var mw = attachUser.create({
      userLoader:              async function (sess) { return { id: sess.userId }; },
      tokenFrom:               "header",
      requireFingerprintMatch: true,
      audit:                   false,
    });
    var mwReq = _makeReq({ authorization: "Bearer " + s.token });
    await _drive(mw, mwReq);
    check("attachUser(requireFingerprintMatch) does NOT attach an unbound session",
          mwReq.user === null && mwReq.session === null);
  } finally {
    await teardownTestDb(tmpDir);
  }
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e.stack || e); process.exit(1); });
}
