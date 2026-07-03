// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.middleware.fetchMetadata — Sec-Fetch-* resource-isolation gate.
 *
 * Covers the destination-vocabulary surface added for FedCM /
 * Storage Access API traffic (Fetch Metadata Request Headers spec):
 *
 *   - default behavior unchanged when the new opts are unset;
 *   - deniedDest refuses a "webidentity" (FedCM) Sec-Fetch-Dest on a
 *     non-identity route, regardless of Sec-Fetch-Site;
 *   - the cross-site Sec-Fetch-Storage-Access: active|inactive escalation
 *     is REFUSED BY DEFAULT (v0.15.0), "none" passes through, and
 *     allowStorageAccess:true opts back in for Storage-Access-flow routes;
 *   - strictDest throws at config time on an unknown destination value;
 *   - membership tests are exact (no substring / prototype-pollution
 *     bypass).
 */

var helpers   = require("../helpers");
var b         = helpers.b;
var check     = helpers.check;
var _bodyReq  = helpers._bodyReq;
var _bodyRes  = helpers._bodyRes;

function _run(mw, req, res) {
  return new Promise(function (resolve) {
    var settled = false;
    function done(via) {
      if (settled) return;
      settled = true;
      resolve({ next: via === "next", status: res._endedStatus, captured: res._captured });
    }
    // Register the finish listener BEFORE invoking the middleware: the
    // refusal path is fully synchronous (writeHead + end → emit "finish")
    // so a listener attached after mw() would miss the event entirely.
    res.on("finish", function () { done("finish"); });
    mw(req, res, function () { done("next"); });
  });
}

function _post(headers) {
  return _bodyReq("POST", headers || {}, "");
}

function _reason(captured) {
  try { return JSON.parse(captured || "{}").error || ""; }
  catch (_e) { return ""; }
}

// Default surface: opts unset → prior behavior is preserved. A FedCM
// webidentity Sec-Fetch-Dest cross-site is still refused by the existing
// cross-site rule (not by the new deniedDest path), and a same-origin
// webidentity passes through.
async function testDefaultUnchanged() {
  check("middleware.fetchMetadata exposed",
        typeof b.middleware.fetchMetadata === "function");

  var mw = b.middleware.fetchMetadata({});

  var sameOrigin = await _run(mw, _post({
    "sec-fetch-site": "same-origin", "sec-fetch-dest": "webidentity",
  }), _bodyRes());
  check("same-origin webidentity passes through by default",
        sameOrigin.next === true);

  var cross = await _run(mw, _post({
    "sec-fetch-site": "cross-site", "sec-fetch-dest": "webidentity",
  }), _bodyRes());
  check("cross-site request still refused by default (unchanged)",
        cross.next === false && cross.status === 403);
}

// deniedDest gates webidentity first-class — refused even when the
// request is same-origin (a route that is not a FedCM endpoint should
// never see a webidentity destination).
async function testDeniedDestWebIdentity() {
  var mw = b.middleware.fetchMetadata({ deniedDest: ["webidentity"] });

  var denied = await _run(mw, _post({
    "sec-fetch-site": "same-origin", "sec-fetch-dest": "webidentity",
  }), _bodyRes());
  check("deniedDest webidentity → 403 even same-origin",
        denied.next === false && denied.status === 403);
  check("deniedDest refusal carries the dest-not-allowed message",
        /destination not allowed/i.test(_reason(denied.captured)));

  // A non-denied destination on the same gate still passes through.
  var allowed = await _run(mw, _post({
    "sec-fetch-site": "same-origin", "sec-fetch-dest": "document",
  }), _bodyRes());
  check("non-denied destination passes through with deniedDest set",
        allowed.next === true);
}

// Storage Access API escalation: active|inactive REFUSED BY DEFAULT
// (v0.15.0); none passes through; allowStorageAccess:true opts back in for
// Storage-Access-flow routes.
async function testStorageAccessGate() {
  var strict = b.middleware.fetchMetadata({ allowStorageAccess: false });

  var active = await _run(strict, _post({
    "sec-fetch-site": "cross-site", "sec-fetch-storage-access": "active",
  }), _bodyRes());
  check("allowStorageAccess:false refuses cross-site active escalation",
        active.next === false && active.status === 403 &&
        /storage access/i.test(_reason(active.captured)));

  var inactive = await _run(strict, _post({
    "sec-fetch-site": "cross-site", "sec-fetch-storage-access": "inactive",
  }), _bodyRes());
  check("allowStorageAccess:false refuses cross-site inactive escalation",
        inactive.next === false && inactive.status === 403);

  var none = await _run(strict, _post({
    "sec-fetch-site": "same-origin", "sec-fetch-storage-access": "none",
  }), _bodyRes());
  check("storage-access none on same-origin passes through",
        none.next === true);

  // Default (opt unset) REFUSES the escalation (v0.15.0) — checked before
  // the allowCrossSite shortcut, so even a cross-site-permitting mount
  // refuses the storage-access escalation by default.
  var dflt = b.middleware.fetchMetadata({ allowCrossSite: true });
  var refusedByDefault = await _run(dflt, _post({
    "sec-fetch-site": "cross-site", "sec-fetch-storage-access": "active",
  }), _bodyRes());
  check("storage-access escalation refused by default (opt unset)",
        refusedByDefault.next === false && refusedByDefault.status === 403);

  // Documented opt-in: allowStorageAccess:true lets the Storage-Access-flow
  // route through.
  var optedIn = b.middleware.fetchMetadata({ allowCrossSite: true, allowStorageAccess: true });
  var permitted = await _run(optedIn, _post({
    "sec-fetch-site": "cross-site", "sec-fetch-storage-access": "active",
  }), _bodyRes());
  check("allowStorageAccess:true opts back in (escalation permitted)",
        permitted.next === true);
}

// strictDest is a config-time tier opt — an unknown Sec-Fetch-Dest value
// throws at construction so an operator typo surfaces at boot.
function testStrictDestThrows() {
  var threw = null;
  try {
    b.middleware.fetchMetadata({ strictDest: true, deniedDest: ["web-identity"] });
  } catch (e) { threw = e; }
  check("strictDest rejects an unknown Sec-Fetch-Dest value at config time",
        threw && /not a known Sec-Fetch-Dest value/.test(threw.message || ""));

  // A known value under strictDest constructs cleanly.
  var ok = true;
  try {
    b.middleware.fetchMetadata({ strictDest: true, deniedDest: ["webidentity"], allowedDest: ["empty"] });
  } catch (_e) { ok = false; }
  check("strictDest accepts known destination values", ok === true);
}

// Exact membership — a header value that is a substring of, or a
// prototype name relative to, a denied value must NOT match.
async function testExactMembershipNoBypass() {
  var mw = b.middleware.fetchMetadata({ deniedDest: ["webidentity"] });

  // Substring of the denied value — must not be treated as denied.
  var substr = await _run(mw, _post({
    "sec-fetch-site": "same-origin", "sec-fetch-dest": "web",
  }), _bodyRes());
  check("substring of a denied dest is not refused (exact match only)",
        substr.next === true);

  // Prototype-name header value must not satisfy the membership map.
  var proto = await _run(mw, _post({
    "sec-fetch-site": "same-origin", "sec-fetch-dest": "__proto__",
  }), _bodyRes());
  check("__proto__ as Sec-Fetch-Dest does not match the deny map",
        proto.next === true);

  // deniedDest rejects a prototype-name value at config time (non-empty
  // string array validation passes it; it simply never matches a real
  // header). Construction with such a value must not pollute.
  var safe = b.middleware.fetchMetadata({ deniedDest: ["constructor"] });
  var plain = await _run(safe, _post({
    "sec-fetch-site": "same-origin", "sec-fetch-dest": "image",
  }), _bodyRes());
  check("deniedDest with a reserved-name entry does not pollute the map",
        plain.next === true);
}

function testMethodsEmptyThrows() {
  var threw = null;
  try { b.middleware.fetchMetadata({ methods: [] }); } catch (e) { threw = e; }
  check("fetchMetadata({ methods: [] }) refused at config time (no silent pass-through)",
        threw && /non-empty array/.test(threw.message || ""));
}

async function testLayeredStricterGateRuns() {
  // A lenient app-level mount must NOT silently disable a STRICTER sub-route
  // mount sharing the request — each instance gates independently.
  var lenient = b.middleware.fetchMetadata({});                 // allowSameSite default true
  var strict  = b.middleware.fetchMetadata({ allowSameSite: false });
  var req = _post({ "sec-fetch-site": "same-site", "sec-fetch-mode": "cors", "sec-fetch-dest": "empty" });
  var r1 = await _run(lenient, req, _bodyRes());
  check("lenient app-level gate passes the same-site request", r1.next === true);
  // The SAME req now carries the lenient gate's flag; the stricter instance
  // must still evaluate (previously a shared boolean made it a no-op).
  var r2 = await _run(strict, req, _bodyRes());
  check("stricter sub-route gate still refuses (not disabled by the earlier mount)",
        r2.next === false && r2.status === 403);
  // The SAME stricter instance run twice on a request IS idempotent.
  var req2 = _post({ "sec-fetch-site": "same-site", "sec-fetch-mode": "cors", "sec-fetch-dest": "empty" });
  var s1 = await _run(strict, req2, _bodyRes());
  var s2 = await _run(strict, req2, _bodyRes());
  check("same instance is idempotent (first refuses, second no-ops to next)",
        s1.next === false && s2.next === true);
}

async function run() {
  await testDefaultUnchanged();
  await testDeniedDestWebIdentity();
  await testStorageAccessGate();
  testStrictDestThrows();
  await testExactMembershipNoBypass();
  testMethodsEmptyThrows();
  await testLayeredStricterGateRuns();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { process.exitCode = 1; throw e; });
}
