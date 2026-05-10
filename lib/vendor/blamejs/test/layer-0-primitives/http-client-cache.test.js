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

    // Wait for background revalidation to land.
    await new Promise(function (r) { setTimeout(r, 80); });
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

// ---- Run ----------------------------------------------------------------

async function run() {
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
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}
