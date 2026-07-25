// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.httpClient.cache — RFC 9111 outbound cache.
 *
 * Coverage:
 *   - cache.create / memoryStore opts validation (throws at config-time)
 *   - First request → MISS, response stored
 *   - Second request → HIT (no upstream hit)
 *   - max-age expiry → conditional revalidation → 304 → REVALIDATED
 *   - max-age expiry → 200 → MISS (replace stored entry)
 *   - no-store skips storage
 *   - no-cache stores but always revalidates
 *   - Cache-Control: private with sharedCache:true skips storage
 *   - Vary: Accept-Encoding splits cache entries per request
 *   - stale-while-revalidate serves STALE + background revalidation
 *   - stale-if-error returns stored entry when upstream fails
 *   - Age header reflects elapsed time since storedAt
 *   - X-Blamejs-Cache header set to HIT/MISS/STALE/REVALIDATED
 *   - eviction at maxBytes / maxEntries removes LRU entry + emits audit
 *   - 304 header merging preserves stored body, updates Date / ETag
 *   - Heuristic freshness from Last-Modified caps at 24h
 *   - Pragma: no-cache without Cache-Control treated as no-cache
 *   - Body-bearing requests (POST) bypass cache entirely
 *   - cache.invalidate / inspect / clear / stats helpers
 *   - cache wired with audit emits hit/miss/stale/revalidated events
 *
 * No live network — local http.Server on a random port via
 * b.testing.listenOnRandomPort.
 */

var http = require("http");

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

function _mkAuditCapture() {
  var events = [];
  return {
    events: events,
    safeEmit: function (e) { events.push(e); },
  };
}

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

function _httpDate(ms) { return new Date(ms).toUTCString(); }

// ---- Surface tests --------------------------------------------------

function testSurface() {
  check("httpClient.cache.create is a function",
        typeof b.httpClient.cache.create === "function");
  check("httpClient.cache.memoryStore is a function",
        typeof b.httpClient.cache.memoryStore === "function");
}

function testCreateBadOpts() {
  var threw = false;
  try { b.httpClient.cache.create({}); }
  catch (_e) { threw = true; }
  check("cache.create: throws when store missing", threw);

  threw = false;
  try { b.httpClient.cache.create({ store: { get: 1, set: 2, delete: 3, clear: 4 } }); }
  catch (_e) { threw = true; }
  check("cache.create: throws when store methods aren't functions", threw);

  threw = false;
  try { b.httpClient.cache.create({ store: _newCache().store, sharedCache: "yes" }); }
  catch (_e) { threw = true; }
  check("cache.create: throws on non-boolean sharedCache", threw);

  threw = false;
  try { b.httpClient.cache.memoryStore({ maxBytes: -1 }); }
  catch (_e) { threw = true; }
  check("memoryStore: throws on negative maxBytes", threw);

  threw = false;
  try { b.httpClient.cache.memoryStore({ maxEntries: 1.5 }); }
  catch (_e) { threw = true; }
  check("memoryStore: throws on non-integer maxEntries", threw);

  threw = false;
  try { b.httpClient.cache.memoryStore({ evictionPolicy: "fifo" }); }
  catch (_e) { threw = true; }
  check("memoryStore: throws on unknown evictionPolicy", threw);

  // statusHeader: default / custom / suppress / bad
  check("cache.create: default statusHeader is x-blamejs-cache",
        b.httpClient.cache.create({ store: _newCache().store }).statusHeader === "x-blamejs-cache");
  check("cache.create: custom statusHeader honored",
        b.httpClient.cache.create({ store: _newCache().store, statusHeader: "X-Cache" }).statusHeader === "x-cache");
  check("cache.create: statusHeader null suppresses",
        b.httpClient.cache.create({ store: _newCache().store, statusHeader: null }).statusHeader === null);
  threw = false;
  try { b.httpClient.cache.create({ store: _newCache().store, statusHeader: 123 }); }
  catch (_e) { threw = true; }
  check("cache.create: throws on non-string statusHeader", threw);
}

// ---- Hit / miss / store ---------------------------------------------

async function testMissThenHit() {
  var hits = 0;
  await _withServer(function (req, res) {
    hits += 1;
    res.writeHead(200, {
      "Content-Type":  "text/plain",
      "Cache-Control": "public, max-age=60",
      "Date":          _httpDate(Date.now()),
      "ETag":          '"v1"',
    });
    res.end("hello");
  }, async function (baseUrl) {
    var cache = _newCache();
    var res1 = await b.httpClient.request({
      url:              baseUrl + "/r",
      cache:            cache,
      allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL,
      allowInternal:    true,
    });
    check("first request: MISS",
          res1.headers["x-blamejs-cache"] === "MISS" && res1.statusCode === 200);
    check("first request: hit upstream once", hits === 1);

    var res2 = await b.httpClient.request({
      url:              baseUrl + "/r",
      cache:            cache,
      allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL,
      allowInternal:    true,
    });
    check("second request: HIT", res2.headers["x-blamejs-cache"] === "HIT");
    check("second request: no upstream call", hits === 1);
    check("HIT response body matches stored body",
          Buffer.isBuffer(res2.body) && res2.body.toString("utf8") === "hello");
    check("HIT response includes Age header",
          typeof res2.headers["age"] === "string" &&
          parseInt(res2.headers["age"], 10) >= 0);
  });
}

async function testNoStoreSkips() {
  var hits = 0;
  await _withServer(function (req, res) {
    hits += 1;
    res.writeHead(200, {
      "Cache-Control": "no-store",
      "Date":          _httpDate(Date.now()),
    });
    res.end("nope");
  }, async function (baseUrl) {
    var cache = _newCache();
    await b.httpClient.request({
      url: baseUrl + "/", cache: cache,
      allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL, allowInternal: true,
    });
    await b.httpClient.request({
      url: baseUrl + "/", cache: cache,
      allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL, allowInternal: true,
    });
    check("no-store: both requests reach upstream", hits === 2);
  });
}

async function testNoCacheRevalidatesEveryRead() {
  var hits = 0;
  await _withServer(function (req, res) {
    hits += 1;
    if (req.headers["if-none-match"] === '"v1"') {
      res.writeHead(304, { "ETag": '"v1"', "Date": _httpDate(Date.now()) });
      res.end();
      return;
    }
    res.writeHead(200, {
      "Content-Type":  "text/plain",
      "Cache-Control": "no-cache",
      "ETag":          '"v1"',
      "Date":          _httpDate(Date.now()),
    });
    res.end("ncbody");
  }, async function (baseUrl) {
    var cache = _newCache();
    var r1 = await b.httpClient.request({
      url: baseUrl + "/", cache: cache,
      allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL, allowInternal: true,
    });
    check("no-cache first call: MISS", r1.headers["x-blamejs-cache"] === "MISS");

    var r2 = await b.httpClient.request({
      url: baseUrl + "/", cache: cache,
      allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL, allowInternal: true,
    });
    check("no-cache second call: REVALIDATED",
          r2.headers["x-blamejs-cache"] === "REVALIDATED");
    check("no-cache second call: upstream hit twice (revalidated)", hits === 2);
    check("no-cache REVALIDATED body restored from cache",
          Buffer.isBuffer(r2.body) && r2.body.toString("utf8") === "ncbody");
  });
}

async function testPrivateRefusedInSharedCache() {
  var hits = 0;
  await _withServer(function (req, res) {
    hits += 1;
    res.writeHead(200, {
      "Cache-Control": "private, max-age=60",
      "Date":          _httpDate(Date.now()),
    });
    res.end("private");
  }, async function (baseUrl) {
    var cache = _newCache({ sharedCache: true });
    await b.httpClient.request({
      url: baseUrl + "/", cache: cache,
      allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL, allowInternal: true,
    });
    await b.httpClient.request({
      url: baseUrl + "/", cache: cache,
      allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL, allowInternal: true,
    });
    check("private response refused in shared cache: upstream hit twice",
          hits === 2);
  });

  var hits2 = 0;
  await _withServer(function (req, res) {
    hits2 += 1;
    res.writeHead(200, {
      "Cache-Control": "private, max-age=60",
      "Date":          _httpDate(Date.now()),
    });
    res.end("private2");
  }, async function (baseUrl) {
    var cache = _newCache({ sharedCache: false });
    await b.httpClient.request({
      url: baseUrl + "/p", cache: cache,
      allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL, allowInternal: true,
    });
    var r = await b.httpClient.request({
      url: baseUrl + "/p", cache: cache,
      allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL, allowInternal: true,
    });
    check("private response in non-shared cache: HIT on second call",
          r.headers["x-blamejs-cache"] === "HIT");
    check("private non-shared: upstream hit once", hits2 === 1);
  });
}

async function testVarySplitsEntries() {
  await _withServer(function (req, res) {
    var enc = (req.headers["accept-encoding"] || "identity").trim();
    res.writeHead(200, {
      "Content-Type":  "text/plain",
      "Cache-Control": "public, max-age=60",
      "Date":          _httpDate(Date.now()),
      "Vary":          "Accept-Encoding",
    });
    res.end("body-for-" + enc);
  }, async function (baseUrl) {
    var cache = _newCache();
    var r1 = await b.httpClient.request({
      url: baseUrl + "/v", cache: cache,
      headers: { "Accept-Encoding": "identity" },
      allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL, allowInternal: true,
    });
    check("Vary: first call (identity) MISS", r1.headers["x-blamejs-cache"] === "MISS");

    var r2 = await b.httpClient.request({
      url: baseUrl + "/v", cache: cache,
      headers: { "Accept-Encoding": "identity" },
      allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL, allowInternal: true,
    });
    check("Vary: second call (identity) HIT", r2.headers["x-blamejs-cache"] === "HIT");
    check("Vary: HIT body matches identity variant",
          Buffer.isBuffer(r2.body) && r2.body.toString("utf8").indexOf("identity") !== -1);

    var r3 = await b.httpClient.request({
      url: baseUrl + "/v", cache: cache,
      headers: { "Accept-Encoding": "gzip" },
      allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL, allowInternal: true,
    });
    check("Vary: third call (gzip) MISS — different vary key",
          r3.headers["x-blamejs-cache"] === "MISS");
    check("Vary: gzip variant body distinct",
          r3.body.toString("utf8") !== r2.body.toString("utf8"));
  });
}

async function testRevalidate304() {
  var serverEtag = '"abc"';
  var hits = 0;
  await _withServer(function (req, res) {
    hits += 1;
    if (req.headers["if-none-match"] === serverEtag) {
      res.writeHead(304, { "ETag": serverEtag, "Date": _httpDate(Date.now()) });
      res.end();
      return;
    }
    res.writeHead(200, {
      "Content-Type":  "text/plain",
      "Cache-Control": "public, max-age=0",
      "ETag":          serverEtag,
      "Date":          _httpDate(Date.now()),
    });
    res.end("payload");
  }, async function (baseUrl) {
    var cache = _newCache();
    var r1 = await b.httpClient.request({
      url: baseUrl + "/v", cache: cache,
      allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL, allowInternal: true,
    });
    check("304 path: first call MISS", r1.headers["x-blamejs-cache"] === "MISS");

    var r2 = await b.httpClient.request({
      url: baseUrl + "/v", cache: cache,
      allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL, allowInternal: true,
    });
    check("304 path: second call REVALIDATED",
          r2.headers["x-blamejs-cache"] === "REVALIDATED");
    check("304 path: revalidated body restored from cache",
          Buffer.isBuffer(r2.body) && r2.body.toString("utf8") === "payload");
    check("304 path: server hit twice (initial + revalidate)", hits === 2);
  });
}

async function testStaleWhileRevalidate() {
  var hits = 0;
  await _withServer(function (req, res) {
    hits += 1;
    res.writeHead(200, {
      "Content-Type":  "text/plain",
      "Cache-Control": "max-age=0, stale-while-revalidate=60",
      "Date":          _httpDate(Date.now()),
      "ETag":          '"swr-' + hits + '"',
    });
    res.end("swr-body-" + hits);
  }, async function (baseUrl) {
    var cache = _newCache();
    var r1 = await b.httpClient.request({
      url: baseUrl + "/swr", cache: cache,
      allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL, allowInternal: true,
    });
    check("swr first call: MISS", r1.headers["x-blamejs-cache"] === "MISS");

    var r2 = await b.httpClient.request({
      url: baseUrl + "/swr", cache: cache,
      allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL, allowInternal: true,
    });
    check("swr second call: STALE (served immediately)",
          r2.headers["x-blamejs-cache"] === "STALE");

    // Wait for background revalidation to hit upstream.
    await helpers.waitUntil(function () { return hits >= 2; }, {
      label: "http-client-cache: swr background revalidation reached upstream",
    });
    check("swr: background revalidation hit upstream", hits >= 2);
  });
}

async function testStaleIfError() {
  var phase = "good";
  var port;
  await _withServer(function (req, res) {
    if (phase === "error") {
      // Hard reset — destroy the socket. Simulates a network failure.
      try { req.socket.destroy(); } catch (_e) { /* test-only socket teardown */ }
      return;
    }
    res.writeHead(200, {
      "Content-Type":  "text/plain",
      "Cache-Control": "max-age=0, stale-if-error=60",
      "Date":          _httpDate(Date.now()),
      "ETag":          '"sie"',
    });
    res.end("sie-body");
  }, async function (baseUrl) {
    void port;
    var cache = _newCache();
    var r1 = await b.httpClient.request({
      url: baseUrl + "/sie", cache: cache,
      allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL, allowInternal: true,
    });
    check("sie first call: MISS", r1.headers["x-blamejs-cache"] === "MISS");

    phase = "error";
    var r2 = await b.httpClient.request({
      url: baseUrl + "/sie", cache: cache,
      allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL, allowInternal: true,
    });
    check("sie: served STALE on upstream error",
          r2.headers["x-blamejs-cache"] === "STALE" &&
          r2.body.toString("utf8") === "sie-body");
  });
}

async function testEvictionAtMaxBytes() {
  // Tiny cap so a single payload triggers eviction the moment a second
  // entry is stored.
  var store = b.httpClient.cache.memoryStore({ maxBytes: 512, maxEntries: 16 });
  var audit = _mkAuditCapture();
  var cache = b.httpClient.cache.create({ store: store, audit: audit });

  await _withServer(function (req, res) {
    var pad = "x".repeat(400);
    res.writeHead(200, {
      "Content-Type":  "text/plain",
      "Cache-Control": "public, max-age=60",
      "Date":          _httpDate(Date.now()),
    });
    res.end(req.url + ":" + pad);
  }, async function (baseUrl) {
    await b.httpClient.request({
      url: baseUrl + "/a", cache: cache,
      allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL, allowInternal: true,
    });
    await b.httpClient.request({
      url: baseUrl + "/b", cache: cache,
      allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL, allowInternal: true,
    });
    var stats = cache.stats();
    check("eviction: bytes within cap", stats.bytes <= 512 + 100 /* leeway for header bytes */);
    var evicted = audit.events.find(function (e) {
      return e.action === "httpclient.cache.evicted";
    });
    check("eviction: audit event emitted", evicted != null);
  });
}

async function testEvictionAtMaxEntries() {
  var store = b.httpClient.cache.memoryStore({ maxBytes: 1024 * 1024, maxEntries: 2 });
  var cache = b.httpClient.cache.create({ store: store });

  await _withServer(function (req, res) {
    res.writeHead(200, {
      "Content-Type":  "text/plain",
      "Cache-Control": "public, max-age=60",
      "Date":          _httpDate(Date.now()),
    });
    res.end(req.url);
  }, async function (baseUrl) {
    await b.httpClient.request({ url: baseUrl + "/1", cache: cache, allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL, allowInternal: true });
    await b.httpClient.request({ url: baseUrl + "/2", cache: cache, allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL, allowInternal: true });
    await b.httpClient.request({ url: baseUrl + "/3", cache: cache, allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL, allowInternal: true });
    var stats = cache.stats();
    check("entry-cap eviction: at most 2 entries retained", stats.entries <= 2);
    // /1 should have been evicted (LRU) — re-fetching it goes upstream.
    var hits = 0;
    var server2;
    void server2;
    var r = await b.httpClient.request({
      url: baseUrl + "/1", cache: cache,
      allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL, allowInternal: true,
    });
    check("entry-cap eviction: LRU evicted entry refetched as MISS",
          r.headers["x-blamejs-cache"] === "MISS");
    void hits;
  });
}

async function testHeuristicFreshnessFromLastModified() {
  var now = Date.now();
  var lastMod = now - 10 * 60 * 1000;  // 10 min ago → 10% = 1 minute fresh
  var hits = 0;
  await _withServer(function (req, res) {
    hits += 1;
    res.writeHead(200, {
      "Content-Type":  "text/plain",
      "Date":          _httpDate(Date.now()),
      "Last-Modified": _httpDate(lastMod),
    });
    res.end("heuristic");
  }, async function (baseUrl) {
    var cache = _newCache();
    await b.httpClient.request({
      url: baseUrl + "/h", cache: cache,
      allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL, allowInternal: true,
    });
    var r2 = await b.httpClient.request({
      url: baseUrl + "/h", cache: cache,
      allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL, allowInternal: true,
    });
    check("heuristic freshness: HIT on second call within 10% window",
          r2.headers["x-blamejs-cache"] === "HIT" && hits === 1);
  });
}

async function testPragmaNoCache() {
  var hits = 0;
  await _withServer(function (req, res) {
    hits += 1;
    if (req.headers["if-none-match"] === '"pn"') {
      res.writeHead(304, { "ETag": '"pn"', "Date": _httpDate(Date.now()) });
      res.end();
      return;
    }
    res.writeHead(200, {
      "Content-Type":  "text/plain",
      "Pragma":        "no-cache",
      "ETag":          '"pn"',
      "Date":          _httpDate(Date.now()),
    });
    res.end("pragma-body");
  }, async function (baseUrl) {
    var cache = _newCache();
    var r1 = await b.httpClient.request({
      url: baseUrl + "/p", cache: cache,
      allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL, allowInternal: true,
    });
    check("Pragma no-cache: first call MISS", r1.headers["x-blamejs-cache"] === "MISS");
    var r2 = await b.httpClient.request({
      url: baseUrl + "/p", cache: cache,
      allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL, allowInternal: true,
    });
    check("Pragma no-cache: second call REVALIDATED",
          r2.headers["x-blamejs-cache"] === "REVALIDATED");
    check("Pragma no-cache: server hit twice (initial + revalidate)", hits === 2);
  });
}

async function testPostBypassesCache() {
  var hits = 0;
  await _withServer(function (req, res) {
    hits += 1;
    res.writeHead(200, {
      "Content-Type":  "text/plain",
      "Cache-Control": "public, max-age=60",
      "Date":          _httpDate(Date.now()),
    });
    res.end("ok");
  }, async function (baseUrl) {
    var cache = _newCache();
    await b.httpClient.request({
      method: "POST", body: Buffer.from("payload"),
      url: baseUrl + "/", cache: cache,
      headers: { "Content-Type": "text/plain" },
      allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL, allowInternal: true,
    });
    await b.httpClient.request({
      method: "POST", body: Buffer.from("payload"),
      url: baseUrl + "/", cache: cache,
      headers: { "Content-Type": "text/plain" },
      allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL, allowInternal: true,
    });
    check("POST: cache bypassed, both requests reach upstream", hits === 2);
  });
}

async function testInvalidateInspectClear() {
  await _withServer(function (req, res) {
    res.writeHead(200, {
      "Content-Type":  "text/plain",
      "Cache-Control": "public, max-age=60",
      "Date":          _httpDate(Date.now()),
    });
    res.end("body");
  }, async function (baseUrl) {
    var cache = _newCache();
    await b.httpClient.request({
      url: baseUrl + "/x", cache: cache,
      allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL, allowInternal: true,
    });
    var inspected = cache.inspect("GET", baseUrl + "/x", {});
    check("inspect: hit reports fresh entry",
          inspected.hit === true && inspected.fresh === true);

    var deleted = cache.invalidate("GET", baseUrl + "/x");
    check("invalidate: returns true when entry existed", deleted === true);

    var inspected2 = cache.inspect("GET", baseUrl + "/x", {});
    check("invalidate: subsequent inspect reports miss", inspected2.hit === false);

    await b.httpClient.request({
      url: baseUrl + "/y", cache: cache,
      allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL, allowInternal: true,
    });
    cache.clear();
    var statsAfter = cache.stats();
    check("clear: stats report empty after clear",
          statsAfter && statsAfter.entries === 0 && statsAfter.bytes === 0);
  });
}

async function testAuditAndObservabilityWired() {
  var audit = _mkAuditCapture();
  var obsEvents = [];
  var obs = {
    safeEvent: function (name, value, labels) {
      obsEvents.push({ name: name, value: value, labels: labels });
    },
  };
  var cache = b.httpClient.cache.create({
    store: b.httpClient.cache.memoryStore(),
    audit: audit,
    observability: obs,
  });
  await _withServer(function (req, res) {
    res.writeHead(200, {
      "Content-Type":  "text/plain",
      "Cache-Control": "public, max-age=60",
      "Date":          _httpDate(Date.now()),
    });
    res.end("audited");
  }, async function (baseUrl) {
    await b.httpClient.request({
      url: baseUrl + "/", cache: cache,
      allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL, allowInternal: true,
    });
    await b.httpClient.request({
      url: baseUrl + "/", cache: cache,
      allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL, allowInternal: true,
    });
    var miss = audit.events.find(function (e) { return e.action === "httpclient.cache.miss"; });
    var hit  = audit.events.find(function (e) { return e.action === "httpclient.cache.hit"; });
    check("audit: miss event emitted", miss != null);
    check("audit: hit event emitted", hit != null);
    check("observability: miss event emitted",
          obsEvents.some(function (e) { return e.name === "httpclient.cache.miss"; }));
    check("observability: hit event emitted",
          obsEvents.some(function (e) { return e.name === "httpclient.cache.hit"; }));
  });
}

async function test304MergesHeaders() {
  var initialDate = Date.now() - 5 * 1000;
  var hits = 0;
  await _withServer(function (req, res) {
    hits += 1;
    if (req.headers["if-none-match"] === '"merge"') {
      res.writeHead(304, {
        "ETag":          '"merge"',
        "Date":          _httpDate(Date.now()),
        "X-Refreshed":   "yes",
      });
      res.end();
      return;
    }
    res.writeHead(200, {
      "Content-Type":  "text/plain",
      "Cache-Control": "max-age=0",
      "ETag":          '"merge"',
      "Date":          _httpDate(initialDate),
    });
    res.end("merged");
  }, async function (baseUrl) {
    var cache = _newCache();
    await b.httpClient.request({
      url: baseUrl + "/m", cache: cache,
      allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL, allowInternal: true,
    });
    var r2 = await b.httpClient.request({
      url: baseUrl + "/m", cache: cache,
      allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL, allowInternal: true,
    });
    check("304 merge: REVALIDATED status", r2.headers["x-blamejs-cache"] === "REVALIDATED");
    check("304 merge: new header from 304 response merged in",
          r2.headers["x-refreshed"] === "yes");
    check("304 merge: stored body preserved",
          Buffer.isBuffer(r2.body) && r2.body.toString("utf8") === "merged");
    check("304 merge: upstream hit twice", hits === 2);
  });
}

// ---- Cache-Control parsing edge cases -------------------------------

function testParseCacheControlBranches() {
  var pcc = b.httpClient.cache._parseCacheControl;

  // Non-string / empty input returns an empty directive set.
  check("_parseCacheControl: empty string → {}",
        Object.keys(pcc("")).length === 0);
  check("_parseCacheControl: non-string → {}",
        Object.keys(pcc(123)).length === 0);

  // A quoted directive argument must NOT be sliced at the comma inside
  // the quotes — RFC 9111 §5.2 / RFC 8941 §3.3.3 quote-aware split. A
  // naive value.split(",") would emit a fake "Cookie" directive.
  var quoted = pcc('no-cache="Authorization, Cookie", max-age=5');
  check("_parseCacheControl: quoted comma not split into fake directive",
        quoted["no-cache"] === "Authorization, Cookie" &&
        quoted["max-age"] === "5" &&
        quoted.cookie === undefined);

  // Empty segments from a double comma are skipped.
  var doubled = pcc("public, , max-age=60");
  check("_parseCacheControl: empty segment skipped",
        doubled.public === "" && doubled["max-age"] === "60");

  // Bare valueless directive.
  var bare = pcc("no-store");
  check("_parseCacheControl: bare directive → empty-string value",
        Object.prototype.hasOwnProperty.call(bare, "no-store") && bare["no-store"] === "");
}

// ---- Storage decision branch coverage (RFC 9111 §3) -----------------

function testEvaluateStorageBranches() {
  var es = b.httpClient.cache._evaluateStorage;
  var now = Date.now();
  var d = new Date(now).toUTCString();

  check("_evaluateStorage: POST → method-not-cacheable",
        es("POST", 200, { "cache-control": "max-age=60" }, true, {}).reason === "method-not-cacheable");

  // Undefined method defaults to GET and remains cacheable.
  check("_evaluateStorage: undefined method defaults to GET",
        es(undefined, 200, { "cache-control": "max-age=60" }, true, {}).cacheable === true);

  check("_evaluateStorage: status 500 → status-not-cacheable",
        es("GET", 500, { "cache-control": "max-age=60" }, true, {}).reason === "status-not-cacheable");

  check("_evaluateStorage: Vary:* → vary-star",
        es("GET", 200, { "cache-control": "max-age=60", "vary": "*" }, true, {}).reason === "vary-star");

  check("_evaluateStorage: no lifetime + no validator → no-freshness-no-validator",
        es("GET", 200, {}, true, {}).reason === "no-freshness-no-validator");

  var etagOnly = es("GET", 200, { "etag": '"x"' }, true, {});
  check("_evaluateStorage: ETag but no lifetime → validator-only, freshness 0",
        etagOnly.reason === "validator-only" && etagOnly.freshnessMs === 0);

  // Malformed max-age parses to null (_ccNumber isFinite/negative guard),
  // so a validator-only decision is reached instead of a bogus lifetime.
  check("_evaluateStorage: max-age=abc ignored → validator-only",
        es("GET", 200, { "cache-control": "max-age=abc", "etag": '"x"' }, true, {}).reason === "validator-only");

  var expFuture = es("GET", 200, { "date": d, "expires": new Date(now + 60000).toUTCString() }, true, {});
  check("_evaluateStorage: Expires in future (with Date) → cacheable, positive freshness",
        expFuture.cacheable === true && expFuture.freshnessMs > 0);

  check("_evaluateStorage: Expires in past → expires-in-past",
        es("GET", 200, { "date": d, "expires": new Date(now - 60000).toUTCString() }, true, {}).reason === "expires-in-past");

  var expNoDate = es("GET", 200, { "expires": new Date(now + 60000).toUTCString() }, true, {});
  check("_evaluateStorage: Expires with no Date header still cacheable",
        expNoDate.cacheable === true && expNoDate.freshnessMs > 0);

  // h2-style array-valued header — _headerOne picks the first element.
  check("_evaluateStorage: array-valued Cache-Control uses first element",
        es("GET", 200, { "cache-control": ["max-age=60"], "date": [d] }, true, {}).freshnessMs === 60000);

  // An empty-array header value resolves to null (no first element).
  check("_evaluateStorage: empty-array header treated as absent",
        es("GET", 200, { "cache-control": [], "etag": '"x"' }, true, {}).reason === "validator-only");

  // A garbage Date header parses to null and is simply ignored.
  check("_evaluateStorage: unparseable Date ignored, max-age still applies",
        es("GET", 200, { "cache-control": "max-age=60", "date": "not-a-date" }, true, {}).cacheable === true);

  // Null response headers must not throw (defensive _lcHeaders guard).
  check("_evaluateStorage: null response headers → no-freshness-no-validator",
        es("GET", 200, null, true, null).reason === "no-freshness-no-validator");
}

function testEvaluateStorageAuthAndSMaxage() {
  var es = b.httpClient.cache._evaluateStorage;

  // RFC 9111 §3.5 — a shared cache must not store an Authorization-bearing
  // response that lacks an explicit share opt-in.
  check("_evaluateStorage: shared + Authorization + no opt-in → authorization-shared",
        es("GET", 200, { "cache-control": "max-age=60" }, true, { authorization: "Bearer t" }).reason === "authorization-shared");

  check("_evaluateStorage: shared + Authorization + public → cacheable",
        es("GET", 200, { "cache-control": "public, max-age=60" }, true, { authorization: "Bearer t" }).cacheable === true);

  var authSMax = es("GET", 200, { "cache-control": "s-maxage=60" }, true, { authorization: "Bearer t" });
  check("_evaluateStorage: shared + Authorization + s-maxage → cacheable, s-maxage lifetime",
        authSMax.cacheable === true && authSMax.freshnessMs === 60000);

  // An empty Authorization value is not treated as authenticated — the
  // §3.5 gate must not fire, so the plain max-age response stays cacheable.
  check("_evaluateStorage: empty Authorization value does not trip §3.5 gate",
        es("GET", 200, { "cache-control": "max-age=60" }, true, { authorization: "" }).cacheable === true);

  // Private cache ignores §3.5 entirely.
  check("_evaluateStorage: non-shared cache ignores Authorization",
        es("GET", 200, { "cache-control": "max-age=60" }, false, { authorization: "Bearer t" }).cacheable === true);
}

// ---- Pure helper branch coverage ------------------------------------

function testUrlKeyAndVaryHelpers() {
  var cacheNs = b.httpClient.cache;

  // Query parameters are sorted for a stable key.
  check("_normalizeUrl: query params sorted",
        cacheNs._normalizeUrl("http://h/p?b=2&a=1&b=1") === "http://h/p?a=1&b=1&b=2");

  // An unparseable URL falls back to String(url).
  check("_normalizeUrl: invalid URL falls back to String(url)",
        cacheNs._normalizeUrl("http://[bad") === "http://[bad");

  // Missing path normalizes to "/".
  check("_normalizeUrl: missing path → /",
        cacheNs._normalizeUrl("http://h") === "http://h/");

  // Default method + null vary in the key shape.
  var key = cacheNs._buildCacheKey(undefined, "http://h/");
  check("_buildCacheKey: undefined method defaults to GET, vary null",
        key.indexOf('"m":"GET"') !== -1 && key.indexOf('"v":null') !== -1);

  // Vary:* is the "uncacheable" sentinel.
  check("_extractVaryValues: '*' → null sentinel",
        cacheNs._extractVaryValues("*", {}) === null);

  // A Vary name absent from the request headers projects to null.
  var pairs = cacheNs._extractVaryValues("accept, x-missing", { accept: "a" });
  check("_extractVaryValues: absent request header → null value",
        pairs.length === 2 && pairs[1][0] === "x-missing" && pairs[1][1] === null);

  // Non-string Vary header → empty pair list.
  check("_extractVaryValues: non-string Vary → []",
        Array.isArray(cacheNs._extractVaryValues(123, {})) && cacheNs._extractVaryValues(123, {}).length === 0);

  // Age header dominates apparent age when the Date header is absent.
  var now = Date.now();
  check("_currentAgeMs: Age header dominates when Date missing",
        cacheNs._currentAgeMs({ storedAtMs: now - 5000, dateMs: null, ageHeaderSec: 10 }, now) === 15000);
}

// ---- memoryStore direct branch coverage -----------------------------

function testMemoryStoreDirectBranches() {
  var ms = b.httpClient.cache.memoryStore;

  var threw = false;
  try { ms("not-an-object"); }
  catch (_e) { threw = true; }
  check("memoryStore: throws when opts is a non-object primitive", threw);

  // Oversized single entry is refused (not stored, not a full wipe) and
  // reported via the eviction hook.
  var store = ms({ maxBytes: 100, maxEntries: 8 });
  var reasons = [];
  store._setOnEvict(function (info) { reasons.push(info.reason); });
  store.set("big", { body: Buffer.alloc(500), headers: {} });
  check("memoryStore: oversized entry refused via entry-too-large",
        store.get("big") === null && reasons.indexOf("entry-too-large") !== -1);

  // Non-string key / falsy entry are no-ops.
  store.set(123, { body: Buffer.alloc(1), headers: {} });
  store.set("k", null);
  check("memoryStore: bad key / null entry are no-ops",
        store._stats().entries === 0);

  // Deleting an absent key is a no-op.
  store.delete("never-stored");
  check("memoryStore: delete of absent key is a no-op",
        store._stats().entries === 0);

  // Byte-cap eviction loop runs its body; a non-function onEvict is
  // accepted and silently ignored.
  var store2 = ms({ maxBytes: 1000, maxEntries: 100 });
  store2._setOnEvict("not-a-function");
  store2.set("a", { body: Buffer.alloc(400), headers: {} });
  store2.set("b", { body: Buffer.alloc(400), headers: {} });
  store2.set("c", { body: Buffer.alloc(400), headers: {} });
  check("memoryStore: byte-cap eviction drops the LRU head",
        store2.get("a") === null && store2._stats().entries === 2);

  // A throwing eviction callback during a real (max-entries) eviction is
  // best-effort — it must not surface out of set().
  var store3 = ms({ maxBytes: 1048576, maxEntries: 1 });
  store3._setOnEvict(function () { throw new Error("evict callback boom"); });
  store3.set("first", { body: Buffer.alloc(10), headers: {} });
  var evictThrowOk = true;
  try { store3.set("second", { body: Buffer.alloc(10), headers: {} }); }
  catch (_e) { evictThrowOk = false; }
  check("memoryStore: throwing eviction callback swallowed during eviction",
        evictThrowOk && store3._stats().entries === 1 && store3.get("first") === null);

  // An entry with no body buffer still contributes header bytes and stores.
  var store4 = ms({ maxBytes: 1048576, maxEntries: 8 });
  store4.set("headers-only", { headers: { "x-a": "b" } });
  check("memoryStore: body-less entry stored, counts header bytes",
        store4._stats().entries === 1 && store4._stats().bytes > 0);

  // A throwing eviction callback on the oversized-entry (entry-too-large)
  // path is also swallowed.
  var store5 = ms({ maxBytes: 100, maxEntries: 8 });
  store5._setOnEvict(function () { throw new Error("too-large callback boom"); });
  var tooLargeThrowOk = true;
  try { store5.set("big", { body: Buffer.alloc(500), headers: {} }); }
  catch (_e) { tooLargeThrowOk = false; }
  check("memoryStore: throwing callback on entry-too-large swallowed",
        tooLargeThrowOk && store5.get("big") === null);
}

// ---- Audit / observability sink branch coverage ---------------------

function testEmitAndObsSinkBranches() {
  var cacheNs = b.httpClient.cache;

  // A throwing audit sink must not surface out of _emit (drop-silent).
  var throwingAudit = { safeEmit: function () { throw new Error("audit boom"); } };
  var cacheA = cacheNs.create({ store: cacheNs.memoryStore(), audit: throwingAudit });
  var emitOk = true;
  try { cacheA._emit("httpclient.cache.test"); }  // outcome + metadata defaulted
  catch (_e) { emitOk = false; }
  check("_emit: throwing audit sink swallowed (drop-silent)", emitOk);

  // observability with only `event` (no safeEvent) uses the event fallback.
  var obsCalls = [];
  var cacheB = cacheNs.create({
    store: cacheNs.memoryStore(),
    observability: { event: function (name) { obsCalls.push(name); } },
  });
  cacheB._obsEvent("httpclient.cache.probe", 1, {});
  check("_obsEvent: falls back to obs.event when safeEvent absent",
        obsCalls.indexOf("httpclient.cache.probe") !== -1);

  // A throwing observability sink must not surface out of _obsEvent.
  var cacheC = cacheNs.create({
    store: cacheNs.memoryStore(),
    observability: { event: function () { throw new Error("obs boom"); } },
  });
  var obsOk = true;
  try { cacheC._obsEvent("x", 1, {}); }
  catch (_e) { obsOk = false; }
  check("_obsEvent: throwing sink swallowed (drop-silent)", obsOk);

  // observability present but exposing neither safeEvent nor event as a
  // function → _obsEvent short-circuits without emitting.
  var cacheD = cacheNs.create({
    store: cacheNs.memoryStore(),
    observability: { event: 123 },  // not a function
  });
  var obsNoFnOk = true;
  try { cacheD._obsEvent("noop", 1, {}); }
  catch (_e) { obsNoFnOk = false; }
  check("_obsEvent: non-function sink is a no-op", obsNoFnOk);
}

// ---- Operator-facing miss / no-op helper branches -------------------

function testInspectInvalidateAndStoreMissBranches() {
  var cache = _newCache();

  // inspect with the requestHeaders arg omitted (defaults to {}).
  var missed = cache.inspect("GET", "http://127.0.0.1:9/absent");
  check("inspect: absent entry → { hit: false } (no requestHeaders arg)",
        missed.hit === false);

  // invalidate on a non-existent entry returns false.
  check("invalidate: false when no entry present",
        cache.invalidate("GET", "http://127.0.0.1:9/absent") === false);

  // A Vary:* response cannot build an entry, so _store refuses it.
  var stored = cache._store("GET", "http://127.0.0.1:9/vs", {}, 200,
    { vary: "*" }, Buffer.from("x"),
    { varyHeader: "*", freshnessMs: 60000, directives: {} });
  check("_store: Vary:* response is not stored (buildEntry null)",
        stored === false && cache.stats().entries === 0);

  var okEval = { varyHeader: null, freshnessMs: 60000, directives: {} };

  // Undefined method defaults to GET, and a non-Buffer (string) body is
  // coerced to a Buffer on store.
  var storedStr = cache._store(undefined, "http://127.0.0.1:9/str", {}, 200,
    { "cache-control": "max-age=60" }, "string-body", okEval);
  var inspStr = cache.inspect("GET", "http://127.0.0.1:9/str", {});
  check("_store: undefined method + string body stored under GET",
        storedStr === true && inspStr.hit === true);

  // A null body is stored as an empty buffer.
  var storedNull = cache._store("GET", "http://127.0.0.1:9/nullbody", {}, 204,
    { "cache-control": "max-age=60" }, null, okEval);
  check("_store: null body stored as empty buffer",
        storedNull === true && cache.inspect("GET", "http://127.0.0.1:9/nullbody", {}).hit === true);

  // _isFresh reflects the freshness evaluation of a synthetic entry.
  var freshEntry = {
    storedAtMs: Date.now(), dateMs: Date.now(), ageHeaderSec: 0,
    freshnessMs: 60000, directives: {},
  };
  var staleEntry = {
    storedAtMs: Date.now(), dateMs: Date.now(), ageHeaderSec: 0,
    freshnessMs: 0, directives: {},
  };
  check("_isFresh: true for an in-lifetime entry, false past expiry",
        cache._isFresh(freshEntry) === true && cache._isFresh(staleEntry) === false);

  // An entry with no directives field is tolerated (defaults to {}).
  var noDirectivesEntry = {
    storedAtMs: Date.now(), dateMs: Date.now(), ageHeaderSec: 0,
    freshnessMs: 60000,
  };
  check("_isFresh: entry without a directives field defaults cleanly",
        cache._isFresh(noDirectivesEntry) === true);

  // stats() reports null when the store's _stats implementation throws.
  var throwingStatsStore = {
    get: function () { return null; }, set: function () {},
    delete: function () {}, clear: function () {},
    _stats: function () { throw new Error("stats boom"); },
  };
  var cacheS = b.httpClient.cache.create({ store: throwingStatsStore });
  check("stats: throwing store._stats → null", cacheS.stats() === null);
}

// ---- Vary lookup with the varied header absent from the request -----

async function testVaryLookupMissingRequestHeader() {
  await _withServer(function (req, res) {
    res.writeHead(200, {
      "Content-Type":  "text/plain",
      "Cache-Control": "public, max-age=60",
      "Date":          _httpDate(Date.now()),
      "Vary":          "Accept-Encoding",
    });
    res.end("varied");
  }, async function (baseUrl) {
    var cache = _newCache();
    // Store a variant keyed on Accept-Encoding: identity.
    await b.httpClient.request({
      url: baseUrl + "/v", cache: cache, headers: { "Accept-Encoding": "identity" },
      allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL, allowInternal: true,
    });
    // A lookup that omits the varied header projects it to null and must
    // NOT match the stored identity variant.
    check("Vary lookup: request missing the varied header does not match",
          cache.inspect("GET", baseUrl + "/v", {}).hit === false);
    // The exact variant still hits.
    check("Vary lookup: matching varied header still hits",
          cache.inspect("GET", baseUrl + "/v", { "Accept-Encoding": "identity" }).hit === true);
  });
}

// ---- §3.5 fail-closed for pre-upgrade persistent-store records -------

function testLegacyEntryFailClosedInSharedCache() {
  var store = b.httpClient.cache.memoryStore();
  var cache = b.httpClient.cache.create({ store: store, sharedCache: true });
  var url = "http://legacy.example/x";

  // Seed a record written before `hadAuthorization` existed (flag absent).
  var key = b.httpClient.cache._buildCacheKey("GET", url, []);
  store.set(key, {
    statusCode: 200, headers: {}, body: Buffer.from("legacy"),
    storedAtMs: Date.now(), dateMs: Date.now(), ageHeaderSec: 0,
    freshnessMs: 60000, directives: {}, method: "GET", url: url,
    varyValues: [], varyHeader: null,
    // NOTE: no hadAuthorization field — the pre-upgrade shape.
  });
  check("legacy fail-closed: seeded entry present before lookup",
        store._stats().entries === 1);

  var insp = cache.inspect("GET", url, {});
  check("legacy fail-closed: shared-cache lookup of flag-less entry reports miss",
        insp.hit === false);
  check("legacy fail-closed: flag-less entry evicted on lookup",
        store._stats().entries === 0);

  // The eviction store.delete is drop-silent: an operator store whose
  // delete throws while purging a flag-less legacy entry must still yield a
  // clean miss rather than surfacing the error.
  var throwDelStore = {
    get: function () {
      return {
        statusCode: 200, headers: {}, body: Buffer.from("legacy"),
        storedAtMs: Date.now(), dateMs: Date.now(), ageHeaderSec: 0,
        freshnessMs: 60000, directives: {}, method: "GET", url: url,
        varyValues: [], varyHeader: null,
        // no hadAuthorization — pre-upgrade shape
      };
    },
    set: function () {},
    delete: function () { throw new Error("delete boom"); },
    clear: function () {},
  };
  var cache2 = b.httpClient.cache.create({ store: throwDelStore, sharedCache: true });
  var insp2;
  var lookupOk = true;
  try { insp2 = cache2.inspect("GET", url, {}); }
  catch (_e) { lookupOk = false; }
  check("legacy fail-closed: throwing store.delete during eviction is drop-silent → miss",
        lookupOk && insp2.hit === false);
}

// ---- Behavioral: shared-cache Authorization leak prevention ----------

async function testAuthorizationSharedCacheLeakPrevented() {
  var hits = 0;
  await _withServer(function (req, res) {
    hits += 1;
    // No public / s-maxage / must-revalidate → not shareable per §3.5.
    res.writeHead(200, {
      "Cache-Control": "max-age=60",
      "Date":          _httpDate(Date.now()),
    });
    res.end("secret-" + hits);
  }, async function (baseUrl) {
    var cache = b.httpClient.cache.create({
      store: b.httpClient.cache.memoryStore(), sharedCache: true,
    });
    await b.httpClient.request({
      url: baseUrl + "/a", cache: cache, headers: { Authorization: "Bearer alice" },
      allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL, allowInternal: true,
    });
    await b.httpClient.request({
      url: baseUrl + "/a", cache: cache, headers: { Authorization: "Bearer bob" },
      allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL, allowInternal: true,
    });
    check("§3.5 leak guard: authed response without opt-in never served from shared cache",
          hits === 2);
  });

  // With `public`, the same response is shareable and the second call HITs.
  var hits2 = 0;
  await _withServer(function (req, res) {
    hits2 += 1;
    res.writeHead(200, {
      "Cache-Control": "public, max-age=60",
      "Date":          _httpDate(Date.now()),
    });
    res.end("public-body");
  }, async function (baseUrl) {
    var cache = b.httpClient.cache.create({
      store: b.httpClient.cache.memoryStore(), sharedCache: true,
    });
    await b.httpClient.request({
      url: baseUrl + "/p", cache: cache, headers: { Authorization: "Bearer x" },
      allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL, allowInternal: true,
    });
    var r2 = await b.httpClient.request({
      url: baseUrl + "/p", cache: cache, headers: { Authorization: "Bearer x" },
      allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL, allowInternal: true,
    });
    check("§3.5 opt-in: public authed response is cacheable → HIT",
          r2.headers["x-blamejs-cache"] === "HIT" && hits2 === 1);
  });
}

// ---- Behavioral: uncacheable status / Vary:* bypass the store --------

async function testUncacheableStatusAndVaryStarBypass() {
  var hits = 0;
  await _withServer(function (req, res) {
    hits += 1;
    // 202 Accepted resolves (2xx) but is NOT in the cacheable status set.
    res.writeHead(202, {
      "Cache-Control": "public, max-age=60",
      "Date":          _httpDate(Date.now()),
    });
    res.end("accepted");
  }, async function (baseUrl) {
    var cache = _newCache();
    var r1 = await b.httpClient.request({
      url: baseUrl + "/acc", cache: cache,
      allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL, allowInternal: true,
    });
    await b.httpClient.request({
      url: baseUrl + "/acc", cache: cache,
      allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL, allowInternal: true,
    });
    check("status-not-cacheable: 202 resolved but not stored → upstream hit twice",
          r1.statusCode === 202 && hits === 2);
  });

  var hits2 = 0;
  await _withServer(function (req, res) {
    hits2 += 1;
    res.writeHead(200, {
      "Cache-Control": "public, max-age=60",
      "Vary":          "*",
      "Date":          _httpDate(Date.now()),
    });
    res.end("varystar");
  }, async function (baseUrl) {
    var cache = _newCache();
    await b.httpClient.request({
      url: baseUrl + "/vs", cache: cache,
      allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL, allowInternal: true,
    });
    await b.httpClient.request({
      url: baseUrl + "/vs", cache: cache,
      allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL, allowInternal: true,
    });
    check("vary-star: Vary:* response uncacheable → upstream hit twice", hits2 === 2);
  });
}

// ---- Behavioral: Expires + s-maxage freshness computation ------------

async function testExpiresAndSMaxageFreshness() {
  // Expires (no max-age) drives freshness; a malformed Age header on the
  // stored response must not corrupt the entry.
  await _withServer(function (req, res) {
    res.writeHead(200, {
      "Date":    _httpDate(Date.now()),
      "Expires": _httpDate(Date.now() + 60000),
      "Age":     "not-a-number",
    });
    res.end("exp-body");
  }, async function (baseUrl) {
    var cache = _newCache();
    var r1 = await b.httpClient.request({
      url: baseUrl + "/e", cache: cache,
      allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL, allowInternal: true,
    });
    var r2 = await b.httpClient.request({
      url: baseUrl + "/e", cache: cache,
      allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL, allowInternal: true,
    });
    check("Expires freshness: first MISS then HIT (malformed Age tolerated)",
          r1.headers["x-blamejs-cache"] === "MISS" && r2.headers["x-blamejs-cache"] === "HIT");
  });

  // s-maxage wins over max-age=0 in a shared cache.
  var hits = 0;
  await _withServer(function (req, res) {
    hits += 1;
    res.writeHead(200, {
      "Cache-Control": "s-maxage=60, max-age=0",
      "Date":          _httpDate(Date.now()),
    });
    res.end("smax");
  }, async function (baseUrl) {
    var cache = b.httpClient.cache.create({
      store: b.httpClient.cache.memoryStore(), sharedCache: true,
    });
    await b.httpClient.request({
      url: baseUrl + "/sm", cache: cache,
      allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL, allowInternal: true,
    });
    var r2 = await b.httpClient.request({
      url: baseUrl + "/sm", cache: cache,
      allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL, allowInternal: true,
    });
    check("s-maxage: shared cache treats s-maxage=60 as fresh → HIT",
          r2.headers["x-blamejs-cache"] === "HIT" && hits === 1);
  });
}

// ---- Behavioral: validator-only + no-validator storage decisions -----

async function testValidatorOnlyAndNoValidatorStorage() {
  // ETag with no lifetime → stored with freshness 0 → revalidates.
  var hits = 0;
  await _withServer(function (req, res) {
    hits += 1;
    if (req.headers["if-none-match"] === '"vo"') {
      // A hop-by-hop header (RFC 9111 §5) must be stripped on merge; a
      // normal header must be carried into the served response.
      res.writeHead(304, {
        "ETag":               '"vo"',
        "Date":               _httpDate(Date.now()),
        "Proxy-Authenticate": "Basic realm=x",
        "X-Merged-In":        "yes",
      });
      res.end();
      return;
    }
    res.writeHead(200, { "ETag": '"vo"', "Date": _httpDate(Date.now()) });
    res.end("vobody");
  }, async function (baseUrl) {
    var cache = _newCache();
    var r1 = await b.httpClient.request({
      url: baseUrl + "/vo", cache: cache,
      allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL, allowInternal: true,
    });
    var r2 = await b.httpClient.request({
      url: baseUrl + "/vo", cache: cache,
      allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL, allowInternal: true,
    });
    check("validator-only: ETag-only response stored + revalidated",
          r1.headers["x-blamejs-cache"] === "MISS" &&
          r2.headers["x-blamejs-cache"] === "REVALIDATED" &&
          r2.body.toString("utf8") === "vobody" && hits === 2);
    check("304 merge: hop-by-hop header stripped, normal header carried through",
          r2.headers["proxy-authenticate"] === undefined &&
          r2.headers["x-merged-in"] === "yes");
  });

  // No lifetime AND no validator → not stored at all.
  var hits2 = 0;
  await _withServer(function (req, res) {
    hits2 += 1;
    res.writeHead(200, { "Date": _httpDate(Date.now()) });
    res.end("no-validator");
  }, async function (baseUrl) {
    var cache = _newCache();
    await b.httpClient.request({
      url: baseUrl + "/nv", cache: cache,
      allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL, allowInternal: true,
    });
    await b.httpClient.request({
      url: baseUrl + "/nv", cache: cache,
      allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL, allowInternal: true,
    });
    check("no-freshness-no-validator: nothing cached → upstream hit twice", hits2 === 2);
  });
}

// ---- Behavioral: oversized entry refused, not wiped ------------------

async function testEntryTooLargeRefusedOverNetwork() {
  var hits = 0;
  var audit = _mkAuditCapture();
  var store = b.httpClient.cache.memoryStore({ maxBytes: 200, maxEntries: 16 });
  var cache = b.httpClient.cache.create({ store: store, audit: audit });
  await _withServer(function (req, res) {
    hits += 1;
    res.writeHead(200, {
      "Cache-Control": "public, max-age=60",
      "Date":          _httpDate(Date.now()),
    });
    res.end("y".repeat(2000));  // far larger than the 200-byte cap
  }, async function (baseUrl) {
    var r1 = await b.httpClient.request({
      url: baseUrl + "/big", cache: cache,
      allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL, allowInternal: true,
    });
    var r2 = await b.httpClient.request({
      url: baseUrl + "/big", cache: cache,
      allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL, allowInternal: true,
    });
    check("entry-too-large: oversized body refused → both requests MISS",
          r1.headers["x-blamejs-cache"] === "MISS" &&
          r2.headers["x-blamejs-cache"] === "MISS" && hits === 2);
    check("entry-too-large: store stays empty (no wipe-and-store)",
          store._stats().entries === 0);
    var tooLarge = audit.events.find(function (e) {
      return e.action === "httpclient.cache.evicted" &&
             e.metadata && e.metadata.reason === "entry-too-large";
    });
    check("entry-too-large: eviction audit records the entry-too-large reason",
          tooLarge != null);
  });
}

// ---- Behavioral: cache errors never surface as request failures ------

function _faultStore(faults) {
  return {
    get:    function () { if (faults.get) throw new Error("store.get boom"); return null; },
    set:    function () { if (faults.set) throw new Error("store.set boom"); },
    delete: function () { if (faults.delete) throw new Error("store.delete boom"); },
    clear:  function () { if (faults.clear) throw new Error("store.clear boom"); },
  };
}

async function testOperatorStoreFaultTolerance() {
  // A store whose get() throws is treated as a miss; the request succeeds.
  var hits = 0;
  await _withServer(function (req, res) {
    hits += 1;
    res.writeHead(200, {
      "Cache-Control": "public, max-age=60",
      "Date":          _httpDate(Date.now()),
    });
    res.end("ok");
  }, async function (baseUrl) {
    var cache = b.httpClient.cache.create({ store: _faultStore({ get: true }) });
    var r1 = await b.httpClient.request({
      url: baseUrl + "/g", cache: cache,
      allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL, allowInternal: true,
    });
    check("store.get throw: request still resolves as MISS via the origin",
          r1.statusCode === 200 && r1.headers["x-blamejs-cache"] === "MISS" && hits === 1);
    check("store.get throw: stats() returns null for a store without _stats",
          cache.stats() === null);
  });

  // A store whose set() throws drops the entry silently → re-fetch on next call.
  var hits2 = 0;
  await _withServer(function (req, res) {
    hits2 += 1;
    res.writeHead(200, {
      "Cache-Control": "public, max-age=60",
      "Date":          _httpDate(Date.now()),
    });
    res.end("ok");
  }, async function (baseUrl) {
    var cache = b.httpClient.cache.create({ store: _faultStore({ set: true }) });
    await b.httpClient.request({
      url: baseUrl + "/s", cache: cache,
      allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL, allowInternal: true,
    });
    await b.httpClient.request({
      url: baseUrl + "/s", cache: cache,
      allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL, allowInternal: true,
    });
    check("store.set throw: swallowed → nothing cached, upstream hit twice", hits2 === 2);
  });

  // invalidate whose delete() throws returns false; clear() swallows throws.
  var entry = {
    statusCode: 200, headers: {}, body: Buffer.from("x"), storedAtMs: Date.now(),
    freshnessMs: 60000, directives: {}, method: "GET", url: "u",
    varyValues: [], varyHeader: null, hadAuthorization: false,
  };
  var hitStore = {
    get:    function () { return entry; },
    set:    function () {},
    delete: function () { throw new Error("delete boom"); },
    clear:  function () { throw new Error("clear boom"); },
  };
  var cacheI = b.httpClient.cache.create({ store: hitStore, sharedCache: false });
  check("invalidate: store.delete throw → returns false",
        cacheI.invalidate("GET", "http://h/z") === false);
  var clearOk = true;
  try { cacheI.clear(); }
  catch (_e) { clearOk = false; }
  check("clear: store.clear throw swallowed (drop-silent)", clearOk);
}

// ---- Behavioral: §3.5 re-gate on a 304 that drops the share opt-in ---

async function testRefreshFrom304DropsShareOptInAuthEvict() {
  var hits = 0;
  await _withServer(function (req, res) {
    hits += 1;
    if (req.headers["if-none-match"] === '"e1"') {
      // The 304 replaces Cache-Control with a plain max-age — dropping the
      // must-revalidate opt-in that first permitted the authed entry into
      // the shared cache.
      res.writeHead(304, {
        "ETag":          '"e1"',
        "Cache-Control": "max-age=60",
        "Date":          _httpDate(Date.now()),
      });
      res.end();
      return;
    }
    res.writeHead(200, {
      "Cache-Control": "must-revalidate, max-age=0",
      "ETag":          '"e1"',
      "Date":          _httpDate(Date.now()),
    });
    res.end("authmerged");
  }, async function (baseUrl) {
    var store = b.httpClient.cache.memoryStore();
    var cache = b.httpClient.cache.create({ store: store, sharedCache: true });
    var r1 = await b.httpClient.request({
      url: baseUrl + "/m", cache: cache, headers: { Authorization: "Bearer alice" },
      allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL, allowInternal: true,
    });
    check("304 re-gate: authed must-revalidate response initially stored (MISS)",
          r1.headers["x-blamejs-cache"] === "MISS" && store._stats().entries >= 1);

    var r2 = await b.httpClient.request({
      url: baseUrl + "/m", cache: cache, headers: { Authorization: "Bearer alice" },
      allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL, allowInternal: true,
    });
    check("304 re-gate: current caller still receives revalidated body",
          r2.headers["x-blamejs-cache"] === "REVALIDATED" &&
          r2.body.toString("utf8") === "authmerged");
    check("304 re-gate: entry evicted once the merged headers drop the opt-in",
          store._stats().entries === 0);

    // A third request from a different principal must go to the origin.
    var r3 = await b.httpClient.request({
      url: baseUrl + "/m", cache: cache, headers: { Authorization: "Bearer bob" },
      allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL, allowInternal: true,
    });
    check("304 re-gate: subsequent principal is not served the evicted entry (MISS)",
          r3.headers["x-blamejs-cache"] === "MISS" && hits === 3);
  });
}

// ---- 304 refresh merge/vary/eviction branch coverage ----------------

function _storedEntryFixture(extra) {
  return Object.assign({
    method:    "GET",
    url:       "http://refresh.example/x",
    statusCode: 200,
    headers:   { "content-type": "text/plain", "cache-control": "max-age=0", "date": _httpDate(Date.now() - 1000) },
    body:      Buffer.from("stored-body"),
    storedAtMs: Date.now() - 1000,
    dateMs:     Date.now() - 1000,
    ageHeaderSec: 0,
    freshnessMs: 0,
    directives: { "max-age": "0" },
    etag:       '"old"',   // field set; headers above deliberately omit ETag
    lastModified: null,
    varyHeader: null,
    varyValues: [],
    hadAuthorization: false,
  }, extra || {});
}

function testRefreshFrom304DirectBranches() {
  var cacheNs = b.httpClient.cache;

  // Cacheable merge: hop-by-hop header stripped, a normal header carried,
  // a malformed Age clamped to 0, and — since the 304 omits ETag and the
  // stored headers omit it too — the stored entry's ETag is carried forward.
  var store1 = cacheNs.memoryStore();
  var cache1 = cacheNs.create({ store: store1, sharedCache: false });
  var refreshed1 = cache1._refreshFrom304(_storedEntryFixture(), {
    "cache-control":      "max-age=60",
    "date":               _httpDate(Date.now()),
    "proxy-authenticate": "Basic realm=x",   // hop-by-hop → stripped
    "content-length":     "999",             // never overwrites the stored body length
    "x-new":              "n",                // normal → merged
    "age":                "not-a-number",     // malformed → 0
  });
  check("_refreshFrom304: hop-by-hop stripped, content-length not merged, normal header merged",
        refreshed1.headers["proxy-authenticate"] === undefined &&
        refreshed1.headers["content-length"] === undefined &&
        refreshed1.headers["x-new"] === "n");
  check("_refreshFrom304: malformed Age clamped, ETag carried forward, freshness re-derived",
        refreshed1.ageHeaderSec === 0 && refreshed1.etag === '"old"' &&
        refreshed1.freshnessMs === 60000);
  check("_refreshFrom304: cacheable refresh is re-stored",
        store1.get(cacheNs._buildCacheKey("GET", "http://refresh.example/x", [])) != null);

  // A Vary'd entry is re-stored under its vary key after a 304.
  var store2 = cacheNs.memoryStore();
  var cache2 = cacheNs.create({ store: store2, sharedCache: false });
  cache2._refreshFrom304(
    _storedEntryFixture({ varyHeader: "accept", varyValues: [["accept", "text/html"]] }),
    { "cache-control": "max-age=60", "date": _httpDate(Date.now()) });
  check("_refreshFrom304: Vary'd entry re-stored under its vary key",
        store2.get(cacheNs._buildCacheKey("GET", "http://refresh.example/x", [["accept", "text/html"]])) != null);

  // store.set throwing during a cacheable refresh is drop-silent.
  var setThrowStore = {
    get: function () { return null; }, set: function () { throw new Error("set boom"); },
    delete: function () {}, clear: function () {},
  };
  var cache3 = cacheNs.create({ store: setThrowStore, sharedCache: false });
  var refresh3Ok = true;
  var refreshed3;
  try { refreshed3 = cache3._refreshFrom304(_storedEntryFixture(), { "cache-control": "max-age=60", "date": _httpDate(Date.now()) }); }
  catch (_e) { refresh3Ok = false; }
  check("_refreshFrom304: store.set throw swallowed, merged body still returned",
        refresh3Ok && refreshed3.freshnessMs === 60000);

  // A shared-cache Authorization-bearing entry whose 304 drops the opt-in
  // is evicted; a throwing store.delete on that eviction is drop-silent and
  // the freshly-revalidated body is still returned to the current caller.
  var delThrowStore = {
    get: function () { return null; }, set: function () {},
    delete: function () { throw new Error("delete boom"); }, clear: function () {},
  };
  var cache4 = cacheNs.create({ store: delThrowStore, sharedCache: true });
  var refresh4Ok = true;
  var refreshed4;
  try {
    // hadAuthorization absent → §3.5 fail-closed treats it as authenticated.
    refreshed4 = cache4._refreshFrom304(
      _storedEntryFixture({ hadAuthorization: undefined }),
      { "cache-control": "max-age=60", "date": _httpDate(Date.now()) });
  } catch (_e) { refresh4Ok = false; }
  check("_refreshFrom304: eviction store.delete throw swallowed, body still returned",
        refresh4Ok && refreshed4.body.toString("utf8") === "stored-body");
}

// ---- Run ----------------------------------------------------------------

async function run() {
  try {
    testSurface();
    testCreateBadOpts();
    await testMissThenHit();
    await testNoStoreSkips();
    await testNoCacheRevalidatesEveryRead();
    await testPrivateRefusedInSharedCache();
    await testVarySplitsEntries();
    await testRevalidate304();
    await testStaleWhileRevalidate();
    await testStaleIfError();
    await testEvictionAtMaxBytes();
    await testEvictionAtMaxEntries();
    await testHeuristicFreshnessFromLastModified();
    await testPragmaNoCache();
    await testPostBypassesCache();
    await testInvalidateInspectClear();
    await testAuditAndObservabilityWired();
    await test304MergesHeaders();

    // Branch-coverage additions — error paths, adversarial inputs,
    // fallbacks, and the RFC 9111 §3.5 shared-cache guard.
    testParseCacheControlBranches();
    testEvaluateStorageBranches();
    testEvaluateStorageAuthAndSMaxage();
    testUrlKeyAndVaryHelpers();
    testMemoryStoreDirectBranches();
    testEmitAndObsSinkBranches();
    testInspectInvalidateAndStoreMissBranches();
    await testVaryLookupMissingRequestHeader();
    testLegacyEntryFailClosedInSharedCache();
    await testAuthorizationSharedCacheLeakPrevented();
    await testUncacheableStatusAndVaryStarBypass();
    await testExpiresAndSMaxageFreshness();
    await testValidatorOnlyAndNoValidatorStorage();
    await testEntryTooLargeRefusedOverNetwork();
    await testOperatorStoreFaultTolerance();
    await testRefreshFrom304DropsShareOptInAuthEvict();
    testRefreshFrom304DirectBranches();
  } finally {
    // Tear down the httpClient's keep-alive transport pool so the
    // client-side sockets it cached don't outlive run() and keep the
    // forked worker's event loop open (delays exit on a slow runner).
    // agent.destroy() schedules the socket teardown asynchronously, so
    // poll until the TCP handles have actually drained before returning.
    await _drainTcpHandles();
  }
}

// Destroy the httpClient transport pool and wait for every TCP handle
// (client sockets + any server-side sockets they kept open) to close.
// Polling drives real event-loop turns so the close completes inside
// run(), not in the worker's post-run grace window.
async function _drainTcpHandles() {
  b.httpClient._resetForTest();
  if (typeof process.getActiveResourcesInfo !== "function") return;
  await helpers.waitUntil(function () {
    return process.getActiveResourcesInfo().filter(function (t) {
      return t === "TCPSocketWrap" || t === "TCPServerWrap";
    }).length === 0;
  }, { timeoutMs: 5000, label: "http-client-cache: TCP handle drain after _resetForTest" });
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}
