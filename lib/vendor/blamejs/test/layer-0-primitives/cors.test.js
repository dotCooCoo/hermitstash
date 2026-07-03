// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * cors middleware — same-origin pass-through + allow-list refusal.
 *
 * Run standalone: `node test/layer-0-primitives/cors.test.js`
 * Or via smoke:   `node test/smoke.js`
 */

var helpers = require("../helpers");
var b      = helpers.b;
var check  = helpers.check;

function _req(opts) {
  opts = opts || {};
  return {
    method:  opts.method  || "POST",
    url:     opts.url     || "/login",
    headers: Object.assign({
      host:   "localhost:8080",
      origin: "http://localhost:8080",
    }, opts.headers || {}),
    socket:  opts.socket  || { remoteAddress: "127.0.0.1", encrypted: false },
  };
}

function _res() {
  var sent = { headers: {}, statusCode: null, body: "" };
  return {
    setHeader: function (k, v) { sent.headers[k.toLowerCase()] = v; },
    writeHead: function (sc, h) {
      sent.statusCode = sc;
      if (h) {
        var keys = Object.keys(h);
        for (var i = 0; i < keys.length; i++) sent.headers[keys[i].toLowerCase()] = h[keys[i]];
      }
    },
    end:      function (b) { sent.body = b || ""; },
    _sent:    sent,
  };
}

function _drive(mw, req) {
  return new Promise(function (resolve) {
    var res = _res();
    var nextCalled = false;
    mw(req, res, function () { nextCalled = true; resolve({ res: res, nextCalled: nextCalled }); });
    // If next was synchronous, the resolve above happened. Otherwise
    // the middleware terminated the response — fall through after a
    // tiny passive window and resolve with whatever state we observed.
    helpers.passiveObserve(5, "cors: middleware short-circuit window")
      .then(function () { resolve({ res: res, nextCalled: nextCalled }); });
  });
}

async function testCorsSameOriginPostPassesWithoutAllowList() {
  // Empty allow-list: a same-origin POST (browser sets Origin header
  // per Fetch spec) must NOT get refused. This was the wiki login bug.
  var mw = b.middleware.cors({ origins: [], refuseUnknown: true });
  var req = _req({
    method:  "POST",
    headers: { host: "localhost:8080", origin: "http://localhost:8080" },
  });
  var out = await _drive(mw, req);
  check("same-origin POST passes through (no 403)",     out.nextCalled === true);
  check("same-origin POST: no CORS headers added",      out.res._sent.headers["access-control-allow-origin"] === undefined);
}

async function testCorsCrossOriginPostStillRefused() {
  // Same allow-list, different origin → refused as before.
  var mw = b.middleware.cors({ origins: [], refuseUnknown: true });
  var req = _req({
    method:  "POST",
    headers: { host: "localhost:8080", origin: "https://attacker.example.com" },
  });
  var out = await _drive(mw, req);
  check("cross-origin POST refused (403)",              out.res._sent.statusCode === 403);
  check("cross-origin POST refusal body intact",        /CORS: origin not allowed/.test(out.res._sent.body));
  check("cross-origin POST: next NOT called",           out.nextCalled === false);
}

async function testCorsExplicitSiteOriginAcceptsThatOrigin() {
  // Operator-supplied siteOrigin is the authoritative same-origin
  // signal — used behind TLS terminators where the framework can't
  // infer scheme from the socket.
  var mw = b.middleware.cors({
    origins:    [],
    siteOrigin: "https://wiki.example.com",
  });
  var req = _req({
    method:  "POST",
    headers: { host: "internal-wiki:8080", origin: "https://wiki.example.com" },
  });
  var out = await _drive(mw, req);
  check("explicit siteOrigin: matching Origin passes",  out.nextCalled === true);
}

async function testCorsExplicitSiteOriginRejectsInferredOrigin() {
  // Once siteOrigin is supplied, the framework's inferred-origin
  // check is replaced — the request's own Host/scheme is no longer
  // trusted as same-origin.
  var mw = b.middleware.cors({
    origins:    [],
    siteOrigin: "https://wiki.example.com",
  });
  var req = _req({
    method:  "POST",
    headers: { host: "localhost:8080", origin: "http://localhost:8080" },
  });
  var out = await _drive(mw, req);
  check("explicit siteOrigin: non-matching origin refused (403)",
        out.res._sent.statusCode === 403);
}

async function testCorsXForwardedProtoRespected() {
  // Behind a TLS terminator: socket is HTTP but Origin claims https. With
  // trustedProxies covering the proxy peer, X-Forwarded-Proto: https flips the
  // inferred scheme so same-origin detection matches — peer-gated, so only a
  // request arriving via the trusted proxy gets the header honored.
  var mw = b.middleware.cors({ origins: [], refuseUnknown: true, trustedProxies: ["127.0.0.0/8"] });
  var req = _req({
    method:  "POST",
    headers: {
      host:   "wiki.example.com",
      origin: "https://wiki.example.com",
      "x-forwarded-proto": "https",
    },
    socket:  { remoteAddress: "127.0.0.1", encrypted: false },
  });
  var out = await _drive(mw, req);
  check("X-Forwarded-Proto: https via trusted proxy → same-origin pass-through",
        out.nextCalled === true);

  // A bare trustProxy is refused at construction (spoofable).
  var threwBare = false;
  try { b.middleware.cors({ origins: [], refuseUnknown: true, trustProxy: true }); }
  catch (_e) { threwBare = true; }
  check("cors: bare trustProxy refused (spoofable)", threwBare === true);

  // Forged X-Forwarded-Proto from an UNTRUSTED peer is ignored → inferred
  // origin stays http://… so the https Origin is cross-origin → blocked.
  var forged = _req({
    method:  "POST",
    headers: {
      host:   "wiki.example.com",
      origin: "https://wiki.example.com",
      "x-forwarded-proto": "https",
    },
    socket:  { remoteAddress: "198.51.100.66", encrypted: false },
  });
  var outForged = await _drive(mw, forged);
  check("forged X-Forwarded-Proto from untrusted peer ignored → blocked",
        outForged.nextCalled === false);
}

async function testCorsXForwardedProtoIgnoredWithoutTrustProxy() {
  // Same request without trustProxy: the framework refuses to consult
  // forwarded headers, so the inferred origin is http://… and the
  // same-origin check fails — refuseUnknown rejects the request. This
  // is the secure default: an attacker can't forge the header.
  var mw = b.middleware.cors({ origins: [], refuseUnknown: true });
  var req = _req({
    method:  "POST",
    headers: {
      host:   "wiki.example.com",
      origin: "https://wiki.example.com",
      "x-forwarded-proto": "https",
    },
    socket:  { remoteAddress: "127.0.0.1", encrypted: false },
  });
  var out = await _drive(mw, req);
  check("X-Forwarded-Proto without trustProxy → cross-origin treated as cross-origin",
        out.nextCalled === false);
}

async function testCorsNoOriginHeaderPassesThrough() {
  // GET requests typically have no Origin header (and same-origin
  // GETs definitely don't). Pass through untouched.
  var mw = b.middleware.cors({ origins: [], refuseUnknown: true });
  var req = _req({
    method:  "GET",
    url:     "/",
    headers: { host: "localhost:8080" },   // no origin
  });
  var out = await _drive(mw, req);
  check("no Origin header: next called (no 403)",       out.nextCalled === true);
}

async function testCorsNullOriginStrictByDefault() {
  // Default: strictNullOrigin: true — refuse Origin: null even with
  // Sec-Fetch-Site: same-origin, because non-browser callers can forge
  // that header freely. Operators with a no-referrer page producing
  // legitimate Origin: null on same-origin POSTs flip strictNullOrigin: false.
  var mw = b.middleware.cors({ origins: [], refuseUnknown: true });
  var req = _req({
    method:  "POST",
    headers: {
      host:   "localhost:8080",
      origin: "null",
      "sec-fetch-site": "same-origin",   // browsers send this; non-browsers can forge it
    },
  });
  var out = await _drive(mw, req);
  check("Origin:null refused even with sec-fetch-site:same-origin (default strict)",
        out.res._sent.statusCode === 403);
}

async function testCorsNullOriginRelaxedOptIn() {
  // Operators with a no-referrer page that produces Origin: null on
  // same-origin POSTs flip strictNullOrigin: false to allow the
  // Sec-Fetch-Site shortcut.
  var mw = b.middleware.cors({
    origins: [], refuseUnknown: true, strictNullOrigin: false,
  });
  var req = _req({
    method:  "POST",
    headers: {
      host:   "localhost:8080",
      origin: "null",
      "sec-fetch-site": "same-origin",
    },
  });
  var out = await _drive(mw, req);
  check("strictNullOrigin:false honors sec-fetch-site:same-origin",
        out.nextCalled === true);
}

async function testCorsNullOriginRelaxedRequiresSameOrigin() {
  // Even with strictNullOrigin: false, only same-origin / none signals
  // pass — a cross-site fetch-metadata still gets refused.
  var mw = b.middleware.cors({
    origins: [], refuseUnknown: true, strictNullOrigin: false,
  });
  var req = _req({
    method:  "POST",
    headers: {
      host:   "localhost:8080",
      origin: "null",
      "sec-fetch-site": "cross-site",
    },
  });
  var out = await _drive(mw, req);
  check("strictNullOrigin:false + cross-site fetch-site still refused",
        out.res._sent.statusCode === 403);
}

async function testCorsNullOriginWithoutFetchSiteRefused() {
  // Origin:null with no fetch-metadata at all (older browser, curl, etc.)
  // — without the same-origin signal we can't trust it. Refuse.
  var mw = b.middleware.cors({ origins: [], refuseUnknown: true });
  var req = _req({
    method:  "POST",
    headers: { host: "localhost:8080", origin: "null" },
  });
  var out = await _drive(mw, req);
  check("Origin:null without Sec-Fetch-Site refused",
        out.res._sent.statusCode === 403);
}

function testCorsConfigValidationThrows() {
  // Bad config surfaces at create() not at request time.
  var threwOnBadOrigin = null;
  try { b.middleware.cors({ origins: [42] }); }
  catch (e) { threwOnBadOrigin = e; }
  check("bad origins[] entry throws CorsError",
        threwOnBadOrigin && threwOnBadOrigin.code === "cors/bad-origin");

  var threwOnBadSiteOriginType = null;
  try { b.middleware.cors({ siteOrigin: 42 }); }
  catch (e) { threwOnBadSiteOriginType = e; }
  check("non-string siteOrigin throws CorsError",
        threwOnBadSiteOriginType && threwOnBadSiteOriginType.code === "cors/bad-site-origin");

  var threwOnUnparseableSiteOrigin = null;
  try { b.middleware.cors({ siteOrigin: "not-a-url" }); }
  catch (e) { threwOnUnparseableSiteOrigin = e; }
  check("unparseable siteOrigin URL throws CorsError",
        threwOnUnparseableSiteOrigin && threwOnUnparseableSiteOrigin.code === "cors/bad-site-origin");

  // A catastrophic-backtracking (ReDoS) RegExp in origins[] is screened
  // at create() — the wrapped nested quantifier /((a)+)+$/ would pin a
  // CPU when .test()'d against a hostile Origin header, so it's refused
  // before the middleware is built.
  var threwOnUnsafePattern = null;
  try { b.middleware.cors({ origins: [/((a)+)+$/] }); }
  catch (e) { threwOnUnsafePattern = e; }
  check("ReDoS-shaped origins[] RegExp throws cors/unsafe-pattern",
        threwOnUnsafePattern && threwOnUnsafePattern.code === "cors/unsafe-pattern");

  // undefined / not-passed → no throw, default behaviour.
  var ok = b.middleware.cors({});
  check("no opts: returns a function (default behaviour)", typeof ok === "function");

  // Allowlist canonicalization — case + default-port differences match.
  var threwOnUnparseableOrigin = null;
  try { b.middleware.cors({ origins: ["not-a-url"] }); }
  catch (e) { threwOnUnparseableOrigin = e; }
  check("unparseable origin URL throws cors/bad-origin",
        threwOnUnparseableOrigin && threwOnUnparseableOrigin.code === "cors/bad-origin");
}

async function testCorsAllowlistCanonicalization() {
  // String entries are canonicalized at create() — case + default-port
  // differences between the configured value and the inbound Origin
  // header now match consistently.
  var mw = b.middleware.cors({
    origins:       ["https://APP.example.com:443"],   // upper-case + default port
    refuseUnknown: true,
  });

  // Browser sends the canonical lower-case host without the default port.
  var req = _req({
    method:  "POST",
    headers: { host: "wiki.example.com", origin: "https://app.example.com" },
  });
  var out = await _drive(mw, req);
  check("allowlist: case + default-port differences match",
        out.nextCalled === true || out.res._sent.statusCode !== 403);

  // Different host: still refused.
  var req2 = _req({
    method:  "POST",
    headers: { host: "wiki.example.com", origin: "https://other.example.com" },
  });
  var out2 = await _drive(mw, req2);
  check("allowlist: different host still refused",
        out2.res._sent.statusCode === 403);
}

async function testCorsPnaPreflightDefaultRefused() {
  var mw = b.middleware.cors({ origins: ["https://app.example.com"] });
  var req = _req({
    method:  "OPTIONS",
    headers: {
      host:                                "app.example.com",
      origin:                              "https://app.example.com",
      "access-control-request-method":     "GET",
      "access-control-request-private-network": "true",
    },
  });
  var out = await _drive(mw, req);
  check("PNA: preflight refused by default",
        out.res._sent.statusCode === 403 || !out.res._sent.headers["access-control-allow-private-network"]);
}

async function testCorsPnaPreflightAllowedWhenOptedIn() {
  var mw = b.middleware.cors({
    origins: ["https://app.example.com"],
    allowPrivateNetwork: true,
  });
  var req = _req({
    method:  "OPTIONS",
    headers: {
      host:                                "app.example.com",
      origin:                              "https://app.example.com",
      "access-control-request-method":     "GET",
      "access-control-request-private-network": "true",
    },
  });
  var out = await _drive(mw, req);
  check("PNA: preflight allowed when allowPrivateNetwork: true",
        out.res._sent.headers["access-control-allow-private-network"] === "true");
}

async function run() {
  await testCorsSameOriginPostPassesWithoutAllowList();
  await testCorsCrossOriginPostStillRefused();
  await testCorsExplicitSiteOriginAcceptsThatOrigin();
  await testCorsExplicitSiteOriginRejectsInferredOrigin();
  await testCorsXForwardedProtoRespected();
  await testCorsXForwardedProtoIgnoredWithoutTrustProxy();
  await testCorsNoOriginHeaderPassesThrough();
  await testCorsNullOriginStrictByDefault();
  await testCorsNullOriginRelaxedOptIn();
  await testCorsNullOriginRelaxedRequiresSameOrigin();
  await testCorsNullOriginWithoutFetchSiteRefused();
  testCorsConfigValidationThrows();
  await testCorsAllowlistCanonicalization();
  await testCorsPnaPreflightDefaultRefused();
  await testCorsPnaPreflightAllowedWhenOptedIn();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e.message); process.exit(1); }
  );
}
