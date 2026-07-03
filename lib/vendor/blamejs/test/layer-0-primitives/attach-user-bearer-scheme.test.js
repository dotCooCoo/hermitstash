// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * attach-user — configurable Authorization scheme + token extractor.
 *
 * Covers the bearerScheme / tokenExtractor escape hatches: the default
 * "Bearer" scheme (RFC 6750 §2.1), operator-configured schemes
 * ("Token", "DPoP" per RFC 9449), regex-metacharacter-safe matching,
 * config-time opt validation, and the tokenExtractor override that
 * fully owns header extraction.
 *
 * Run standalone: `node test/layer-0-primitives/attach-user-bearer-scheme.test.js`
 * Or via smoke:   `node test/smoke.js`
 */

var helpers   = require("../helpers");
var b         = helpers.b;
var check     = helpers.check;

var attachUser = b.middleware._modules.attachUser;

async function _drive(mw, req) {
  // attachUser always calls next() — synchronously for no-token paths,
  // after session.verify resolves otherwise. Poll the next()-called flag
  // instead of racing a fixed sleep that drifts under runner contention.
  var called = false;
  mw(req, {}, function () { called = true; });
  await helpers.waitUntil(function () { return called; }, {
    timeoutMs: 5000,
    label:     "attach-user-bearer-scheme: middleware called next()",
  });
}

function _req(headers) {
  return {
    headers:    headers || {},
    socket:     { remoteAddress: "127.0.0.1" },
    connection: { remoteAddress: "127.0.0.1" },
  };
}

function testReadBearerDefaultScheme() {
  check("default scheme extracts after Bearer",
        attachUser._readBearer("Bearer abc123") === "abc123");
  check("default scheme is case-insensitive (RFC 9110 §11.1)",
        attachUser._readBearer("bearer abc123") === "abc123");
  check("default scheme ignores a Token header",
        attachUser._readBearer("Token abc123") === null);
  check("no header → null",
        attachUser._readBearer(undefined) === null);
}

function testReadBearerCustomScheme() {
  check("custom Token scheme extracts the credential",
        attachUser._readBearer("Token abc123", "Token") === "abc123");
  check("DPoP scheme (RFC 9449) extracts the credential",
        attachUser._readBearer("DPoP xyz", "DPoP") === "xyz");
  // A scheme containing regex metacharacters must match literally, not
  // as an injected pattern — "a.b" must not match "axb".
  check("regex-meta scheme matches literally",
        attachUser._readBearer("a.b qqq", "a.b") === "qqq");
  check("regex-meta scheme does NOT match a wildcard expansion",
        attachUser._readBearer("axb qqq", "a.b") === null);
}

function testCreateValidatesOpts() {
  function threw(fn) { try { fn(); return null; } catch (e) { return e; } }
  var loader = async function () { return null; };

  var e1 = threw(function () {
    attachUser.create({ userLoader: loader, bearerScheme: "" });
  });
  check("empty bearerScheme → throws", e1 && /bearerScheme/.test(e1.message));

  var e2 = threw(function () {
    attachUser.create({ userLoader: loader, bearerScheme: 42 });
  });
  check("non-string bearerScheme → throws", e2 && /bearerScheme/.test(e2.message));

  var e3 = threw(function () {
    attachUser.create({ userLoader: loader, tokenExtractor: "nope" });
  });
  check("non-function tokenExtractor → throws", e3 && /tokenExtractor/.test(e3.message));

  var ok = threw(function () {
    attachUser.create({ userLoader: loader, bearerScheme: "Token", tokenExtractor: function () { return null; } });
  });
  check("valid bearerScheme + tokenExtractor accepted", ok === null);
}

async function testCustomSchemeHeaderConsumed() {
  // With bearerScheme "Token", a "Token <x>" header is read; a "Bearer
  // <x>" header is ignored. A bogus token fails session.verify
  // gracefully (no throw) → req.user stays null and next() runs.
  var mw = attachUser.create({
    userLoader: async function (s) { return { id: s.userId }; },
    tokenFrom:  "header",
    bearerScheme: "Token",
    audit:      false,
  });
  var req = _req({ authorization: "Token bogus-session-id" });
  await _drive(mw, req);
  check("custom scheme: middleware ran, attached req.user (null for bogus token)",
        req.user === null && req.session === null);
}

async function testTokenExtractorOwnsExtraction() {
  // tokenExtractor fully owns header extraction: it is invoked and its
  // result is the token handed to session.verify.
  var calls = 0;
  var seenReq = null;
  var mw = attachUser.create({
    userLoader: async function (s) { return { id: s.userId }; },
    tokenFrom:  "header",
    tokenExtractor: function (req) { calls += 1; seenReq = req; return "extractor-token"; },
    audit:      false,
  });
  var req = _req({ authorization: "Bearer should-be-ignored" });
  await _drive(mw, req);
  check("tokenExtractor was invoked exactly once", calls === 1);
  check("tokenExtractor received the request object", seenReq === req);
  check("tokenExtractor path: bogus token → req.user null + next() ran", req.user === null);
}

async function testTokenExtractorNullSkipsAuth() {
  // tokenExtractor returning null/undefined means "no token" — the
  // middleware short-circuits to next() with req.user = null.
  var mw = attachUser.create({
    userLoader: async function () { throw new Error("userLoader must not run with no token"); },
    tokenFrom:  "header",
    tokenExtractor: function () { return null; },
    audit:      false,
  });
  var req = _req({ authorization: "Bearer ignored" });
  await _drive(mw, req);
  check("tokenExtractor null → req.user null, no userLoader call", req.user === null);
}

async function run() {
  testReadBearerDefaultScheme();
  testReadBearerCustomScheme();
  testCreateValidatesOpts();
  await testCustomSchemeHeaderConsumed();
  await testTokenExtractorOwnsExtraction();
  await testTokenExtractorNullSkipsAuth();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[attach-user-bearer-scheme] OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e.stack || e); process.exit(1); }
  );
}
