// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.httpClient.cache — RFC 9111 §3.5 Authorization rule.
 *
 * A shared cache MUST NOT reuse a stored response to a request that
 * carried an `Authorization` header to satisfy a subsequent request
 * unless the response explicitly permits it via `public`, `s-maxage`,
 * or `must-revalidate`. Without that gate a per-user authenticated
 * response lands in a fleet-shared cache and a different principal's
 * request is served it — a cross-user data leak.
 *
 * Coverage:
 *   - shared cache + Authorization + only max-age → NOT reused across users
 *   - shared cache + Authorization + `public` → reuse permitted (origin opt-in)
 *   - shared cache + Authorization + `s-maxage` → reuse permitted
 *   - private cache (sharedCache:false) + Authorization → cached (single tenant)
 *
 * No live network — local http.Server on a random loopback port via
 * b.testing.listenOnRandomPort.
 */

var http = require("http");

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

function _httpDate(ms) { return new Date(ms).toUTCString(); }

async function _withServer(handler, fn) {
  var server = http.createServer(handler);
  var port = await b.testing.listenOnRandomPort(server, "127.0.0.1");
  try {
    return await fn("http://127.0.0.1:" + port);
  } finally {
    await new Promise(function (resolve) { server.close(function () { resolve(); }); });
  }
}

function _newCache(extra) {
  var store = b.httpClient.cache.memoryStore({ maxBytes: 1024 * 1024, maxEntries: 64 });
  return b.httpClient.cache.create(Object.assign({ store: store }, extra || {}));
}

// A handler that echoes the caller's Authorization into the body so the
// served bytes reveal which principal the response was generated for.
function _echoAuthHandler(cacheControl, hitsRef) {
  return function (req, res) {
    hitsRef.n += 1;
    res.writeHead(200, {
      "Content-Type":  "text/plain",
      "Cache-Control": cacheControl,
      "Date":          _httpDate(Date.now()),
    });
    res.end("secret-for:" + (req.headers["authorization"] || "anon"));
  };
}

// A handler whose FIRST 200 carries the `must-revalidate` §3.5 opt-in (with
// max-age=0 so the entry is immediately stale), then answers the conditional
// revalidation with a 304 that DROPS must-revalidate and substitutes a plain
// max-age=60. A shared cache that refreshes the entry from that 304 without
// re-applying the Authorization gate would retain a now-freely-shareable
// authed response.
function _optInThenDropOn304Handler(hitsRef) {
  return function (req, res) {
    hitsRef.n += 1;
    if (req.headers["if-none-match"]) {
      res.writeHead(304, {
        "Cache-Control": "max-age=60",
        "ETag":          '"v1"',
        "Date":          _httpDate(Date.now()),
      });
      res.end();
      return;
    }
    res.writeHead(200, {
      "Content-Type":  "text/plain",
      "Cache-Control": "must-revalidate, max-age=0",
      "ETag":          '"v1"',
      "Date":          _httpDate(Date.now()),
    });
    res.end("secret-for:" + (req.headers["authorization"] || "anon"));
  };
}

// A 304 can replace Cache-Control: an authed entry first stored under the
// must-revalidate opt-in can be revalidated into a plain max-age=60 response.
// The refresh must re-apply RFC 9111 §3.5 and EVICT the entry (it lost its
// opt-in) rather than retain it as a freely-shareable authed response served
// to a different principal.
async function testAuthOptInDroppedOn304EvictsNotShares() {
  var hits = { n: 0 };
  await _withServer(_optInThenDropOn304Handler(hits), async function (baseUrl) {
    var cache = _newCache({ sharedCache: true });
    var r1 = await b.httpClient.request({
      url: baseUrl + "/acct", cache: cache,
      headers: { Authorization: "Bearer USER-AAA" },
      allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL, allowInternal: true,
    });
    check("304-optin: AAA first request MISS", r1.headers["x-blamejs-cache"] === "MISS");
    check("304-optin: AAA body", r1.body.toString("utf8") === "secret-for:Bearer USER-AAA");
    // AAA again — entry is stale (max-age=0), revalidates, gets the 304 that
    // drops must-revalidate for max-age=60.
    var r2 = await b.httpClient.request({
      url: baseUrl + "/acct", cache: cache,
      headers: { Authorization: "Bearer USER-AAA" },
      allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL, allowInternal: true,
    });
    check("304-optin: AAA revalidated serve is still AAA's body",
          r2.body.toString("utf8") === "secret-for:Bearer USER-AAA");
    // BBB (a different principal) must NOT receive AAA's body — the entry must
    // have been evicted on the opt-in-dropping 304.
    var r3 = await b.httpClient.request({
      url: baseUrl + "/acct", cache: cache,
      headers: { Authorization: "Bearer USER-BBB" },
      allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL, allowInternal: true,
    });
    check("304-optin: BBB does NOT receive AAA's body after the 304 dropped the opt-in",
          r3.body.toString("utf8") !== "secret-for:Bearer USER-AAA");
    check("304-optin: BBB receives its own response",
          r3.body.toString("utf8") === "secret-for:Bearer USER-BBB");
  });
}

// A store that strips `hadAuthorization` from every entry it returns —
// simulating a persistent shared store (Redis / filesystem) whose records were
// written by a version before that field existed. Such a legacy entry must be
// treated as Authorization-bearing (fail closed), not unauthenticated, so the
// §3.5 gate still applies on its 304 refresh.
function _legacyStrippingStore() {
  var inner = b.httpClient.cache.memoryStore({ maxBytes: 1024 * 1024, maxEntries: 64 });
  return {
    get: function (k) {
      var e = inner.get(k);
      if (e && typeof e === "object" && !e.__varyMarker) {
        var copy = Object.assign({}, e);
        delete copy.hadAuthorization;
        return copy;
      }
      return e;
    },
    set:    function (k, v) { return inner.set(k, v); },
    delete: function (k)    { return inner.delete(k); },
    clear:  function ()     { return inner.clear(); },
  };
}

// A legacy entry (no hadAuthorization metadata) must fail closed on a 304 that
// drops the opt-in: the refresh cannot assume it was unauthenticated, so it
// re-applies the §3.5 gate and evicts rather than leaving a previously-stored
// authenticated response shareable across the version upgrade.
async function testLegacyEntryWithoutAuthFlagFailsClosedOn304() {
  var hits = { n: 0 };
  await _withServer(_optInThenDropOn304Handler(hits), async function (baseUrl) {
    var cache = b.httpClient.cache.create({ store: _legacyStrippingStore(), sharedCache: true });
    await b.httpClient.request({
      url: baseUrl + "/legacy", cache: cache,
      headers: { Authorization: "Bearer USER-AAA" },
      allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL, allowInternal: true,
    });
    await b.httpClient.request({
      url: baseUrl + "/legacy", cache: cache,
      headers: { Authorization: "Bearer USER-AAA" },
      allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL, allowInternal: true,
    });
    var r3 = await b.httpClient.request({
      url: baseUrl + "/legacy", cache: cache,
      headers: { Authorization: "Bearer USER-BBB" },
      allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL, allowInternal: true,
    });
    check("legacy-entry: a pre-field entry fails closed — BBB does NOT receive AAA's body",
          r3.body.toString("utf8") !== "secret-for:Bearer USER-AAA");
    check("legacy-entry: BBB receives its own response",
          r3.body.toString("utf8") === "secret-for:Bearer USER-BBB");
  });
}

// A still-FRESH legacy entry (positive freshness, no hadAuthorization) is
// served directly on a HIT without ever reaching the 304 refresh. In a shared
// cache it could be a pre-upgrade authenticated response, so the lookup itself
// must fail closed and evict it rather than serve a cached body across
// principals.
async function testLegacyFreshEntryNotServedOnHit() {
  var hits = { n: 0 };
  await _withServer(_echoAuthHandler("max-age=60", hits), async function (baseUrl) {
    var cache = b.httpClient.cache.create({ store: _legacyStrippingStore(), sharedCache: true });
    // Seed a fresh entry via an UNAUTHENTICATED request (the store-time gate
    // stores it); the legacy store then strips hadAuthorization so it presents
    // as a record written before the field existed.
    var r0 = await b.httpClient.request({
      url: baseUrl + "/legacy-fresh", cache: cache,
      allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL, allowInternal: true,
    });
    check("legacy-fresh: seed request MISS", r0.headers["x-blamejs-cache"] === "MISS");
    // A principal now requests the same URL. The stored entry has no
    // hadAuthorization (legacy), so it must NOT be served on a fresh HIT.
    var r1 = await b.httpClient.request({
      url: baseUrl + "/legacy-fresh", cache: cache,
      headers: { Authorization: "Bearer USER-BBB" },
      allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL, allowInternal: true,
    });
    check("legacy-fresh: a legacy entry is not served on a HIT (evicted at lookup)",
          r1.headers["x-blamejs-cache"] === "MISS");
    check("legacy-fresh: caller receives its own fresh response, not the legacy cached body",
          r1.body.toString("utf8") === "secret-for:Bearer USER-BBB");
  });
}

// ---- The leak: shared cache must not cross Authorization principals ----

async function testAuthNotSharedAcrossUsersSharedCache() {
  var hits = { n: 0 };
  await _withServer(_echoAuthHandler("max-age=60", hits), async function (baseUrl) {
    var cache = _newCache({ sharedCache: true });

    var r1 = await b.httpClient.request({
      url: baseUrl + "/account", cache: cache,
      headers: { Authorization: "Bearer USER-AAA" },
      allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL, allowInternal: true,
    });
    check("shared+auth: first request MISS",
          r1.headers["x-blamejs-cache"] === "MISS");
    check("shared+auth: first request body is AAA's",
          r1.body.toString("utf8") === "secret-for:Bearer USER-AAA");

    var r2 = await b.httpClient.request({
      url: baseUrl + "/account", cache: cache,
      headers: { Authorization: "Bearer USER-BBB" },
      allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL, allowInternal: true,
    });
    // The core assertion: USER-BBB must NEVER receive USER-AAA's body.
    check("shared+auth: USER-BBB does NOT receive USER-AAA's cached response",
          r2.body.toString("utf8") !== "secret-for:Bearer USER-AAA");
    check("shared+auth: USER-BBB receives its own response",
          r2.body.toString("utf8") === "secret-for:Bearer USER-BBB");
    check("shared+auth: second request was not served from cache",
          r2.headers["x-blamejs-cache"] === "MISS");
    check("shared+auth: both requests reached upstream", hits.n === 2);
  });
}

// ---- `public` is the origin's opt-in to share an authed response ----

async function testPublicPermitsSharedAuthReuse() {
  var hits = { n: 0 };
  await _withServer(_echoAuthHandler("public, max-age=60", hits), async function (baseUrl) {
    var cache = _newCache({ sharedCache: true });

    var r1 = await b.httpClient.request({
      url: baseUrl + "/pub", cache: cache,
      headers: { Authorization: "Bearer USER-AAA" },
      allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL, allowInternal: true,
    });
    check("public+auth: first request MISS", r1.headers["x-blamejs-cache"] === "MISS");

    var r2 = await b.httpClient.request({
      url: baseUrl + "/pub", cache: cache,
      headers: { Authorization: "Bearer USER-BBB" },
      allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL, allowInternal: true,
    });
    // `public` is an explicit origin declaration that the response is
    // shareable, so a HIT here is correct RFC 9111 §3.5 behaviour.
    check("public+auth: second request served from cache (origin opt-in)",
          r2.headers["x-blamejs-cache"] === "HIT");
    check("public+auth: only one upstream call", hits.n === 1);
  });
}

async function testSmaxagePermitsSharedAuthReuse() {
  var hits = { n: 0 };
  await _withServer(_echoAuthHandler("s-maxage=60", hits), async function (baseUrl) {
    var cache = _newCache({ sharedCache: true });

    await b.httpClient.request({
      url: baseUrl + "/s", cache: cache,
      headers: { Authorization: "Bearer USER-AAA" },
      allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL, allowInternal: true,
    });
    var r2 = await b.httpClient.request({
      url: baseUrl + "/s", cache: cache,
      headers: { Authorization: "Bearer USER-BBB" },
      allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL, allowInternal: true,
    });
    check("s-maxage+auth: second request served from cache",
          r2.headers["x-blamejs-cache"] === "HIT");
    check("s-maxage+auth: only one upstream call", hits.n === 1);
  });
}

// ---- A private cache (single tenant) may cache an authed response ----

async function testPrivateCacheCachesAuthedResponse() {
  var hits = { n: 0 };
  await _withServer(_echoAuthHandler("max-age=60", hits), async function (baseUrl) {
    var cache = _newCache({ sharedCache: false });

    await b.httpClient.request({
      url: baseUrl + "/me", cache: cache,
      headers: { Authorization: "Bearer USER-AAA" },
      allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL, allowInternal: true,
    });
    var r2 = await b.httpClient.request({
      url: baseUrl + "/me", cache: cache,
      headers: { Authorization: "Bearer USER-AAA" },
      allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL, allowInternal: true,
    });
    check("private+auth: same-principal repeat served from cache",
          r2.headers["x-blamejs-cache"] === "HIT");
    check("private+auth: only one upstream call", hits.n === 1);
  });
}

// ---- Run ----------------------------------------------------------------

async function run() {
  try {
    await testAuthNotSharedAcrossUsersSharedCache();
    await testAuthOptInDroppedOn304EvictsNotShares();
    await testLegacyEntryWithoutAuthFlagFailsClosedOn304();
    await testLegacyFreshEntryNotServedOnHit();
    await testPublicPermitsSharedAuthReuse();
    await testSmaxagePermitsSharedAuthReuse();
    await testPrivateCacheCachesAuthedResponse();
  } finally {
    await _drainTcpHandles();
  }
}

async function _drainTcpHandles() {
  b.httpClient._resetForTest();
  if (typeof process.getActiveResourcesInfo !== "function") return;
  await helpers.waitUntil(function () {
    return process.getActiveResourcesInfo().filter(function (t) {
      return t === "TCPSocketWrap" || t === "TCPServerWrap";
    }).length === 0;
  }, { timeoutMs: 5000, label: "http-client-cache-authorization: TCP handle drain" });
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}
