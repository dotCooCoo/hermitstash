// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.middleware.idempotencyKey — draft-ietf-httpapi-idempotency-key.
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

var nodeFs   = require("node:fs");
var nodeOs   = require("node:os");
var nodePath = require("node:path");
var vault    = require("../../lib/vault");
var cryptoField = require("../../lib/crypto-field");

function _mockReq(method, url, key, body) {
  return {
    method:  method,
    url:     url,
    headers: key ? { "idempotency-key": key } : {},
    body:    body,
  };
}

function _mockRes() {
  var headers = {};
  var chunks = [];
  var statusCode = 200;
  var endCalled = false;
  return {
    setHeader: function (k, v) { headers[k.toLowerCase()] = v; },
    getHeader: function (k) { return headers[k.toLowerCase()]; },
    getHeaders: function () { return Object.assign({}, headers); },
    write:     function (chunk) { chunks.push(Buffer.from(chunk)); },
    end:       function (chunk) {
      if (chunk) chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
      endCalled = true;
    },
    get statusCode() { return statusCode; },
    set statusCode(v) { statusCode = v; },
    _getBody:    function () { return Buffer.concat(chunks).toString("utf8"); },
    _getHeaders: function () { return headers; },
    _ended:      function () { return endCalled; },
    _statusCode: function () { return statusCode; },
  };
}

function testSurface() {
  check("idempotencyKey is a function",            typeof b.middleware.idempotencyKey === "function");
  check("idempotencyKey.memoryStore is a function", typeof b.middleware.idempotencyKey.memoryStore === "function");
  check("idempotencyKey.DEFAULT_METHODS is array",  Array.isArray(b.middleware.idempotencyKey.DEFAULT_METHODS));
}

function testBadOpts() {
  function expectCode(label, fn, code) {
    var threw = null;
    try { fn(); } catch (e) { threw = e; }
    check(label, threw && (threw.code || "").indexOf(code) !== -1);
  }
  expectCode("idempotencyKey: bad opts null", function () { b.middleware.idempotencyKey(null); }, "idempotency/bad-opts");
  expectCode("idempotencyKey: missing store", function () { b.middleware.idempotencyKey({}); }, "idempotency/bad-store");
  expectCode("idempotencyKey: bad store interface", function () { b.middleware.idempotencyKey({ store: {} }); }, "idempotency/bad-store");
  expectCode("idempotencyKey: bad bodyFingerprint type",
    function () {
      b.middleware.idempotencyKey({
        store: b.middleware.idempotencyKey.memoryStore(),
        bodyFingerprint: "not-a-function",
      });
    },
    "idempotency/bad-body-fingerprint");
}

function testBodyFingerprintHook() {
  // v0.9.42 gap-list fix: operators sometimes need to canonicalize
  // the parsed-body shape (sorted keys, stripped metadata) before
  // the fingerprint hash so retry-with-equivalent-payload doesn't
  // trip the §4.3 same-key-different-body refusal. The
  // `bodyFingerprint(req)` hook lets the operator return the
  // canonicalized bytes; the hook runs at the moment idempotency
  // executes, so idempotency MUST mount AFTER body-parser regardless
  // of whether the hook is used (the misordered-mount detector
  // below catches the failure mode).
  var store = b.middleware.idempotencyKey.memoryStore();
  var fpCalls = 0;
  var mw = b.middleware.idempotencyKey({
    store: store,
    bodyFingerprint: function (req) {
      fpCalls += 1;
      return req.body ? JSON.stringify(req.body) : null;
    },
  });

  // First request — body { amount: 100 }
  var req1 = _mockReq("POST", "/charges", "key-fp-1", { amount: 100 });
  var res1 = _mockRes();
  var calledNext1 = false;
  mw(req1, res1, function () { calledNext1 = true; });
  check("bodyFingerprint: hook called for first req",  fpCalls === 1);
  check("bodyFingerprint: next() called (cache miss)", calledNext1 === true);

  // Operator handler "completes" the response — write entry to store
  // so the next request can be a fingerprint-mismatch test.
  res1.end("ok");

  // Second request — SAME key, DIFFERENT body. The bodyFingerprint
  // hook produces a different fingerprint; framework refuses with
  // 422 key-reuse-mismatch.
  var req2 = _mockReq("POST", "/charges", "key-fp-1", { amount: 999 });
  var res2 = _mockRes();
  var calledNext2 = false;
  mw(req2, res2, function () { calledNext2 = true; });
  check("bodyFingerprint: hook called for second req", fpCalls === 2);
  check("bodyFingerprint: mismatch refused with 422",  res2._statusCode() === 422);
  check("bodyFingerprint: next() NOT called on mismatch", calledNext2 === false);
}

function testCrossActorIsolation() {
  var store = b.middleware.idempotencyKey.memoryStore();
  var mw = b.middleware.idempotencyKey({
    store: store,
    bodyFingerprint: function (req) { return req.body ? JSON.stringify(req.body) : null; },
  });

  // Principal A caches a private response under Idempotency-Key "shared".
  var reqA = _mockReq("POST", "/account/export", "shared", { op: "export" });
  reqA.user = { id: "alice" };
  var resA = _mockRes();
  mw(reqA, resA, function () { resA.statusCode = 200; resA.end("ALICE-PRIVATE"); });

  // Principal B sends the SAME Idempotency-Key + same request shape. The
  // slot must be scoped to the authenticated principal — B must NOT be
  // served A's cached response (cross-actor disclosure), and B's own
  // handler must run.
  var reqB = _mockReq("POST", "/account/export", "shared", { op: "export" });
  reqB.user = { id: "bob" };
  var resB = _mockRes();
  var handlerRanForB = false;
  mw(reqB, resB, function () { handlerRanForB = true; resB.statusCode = 200; resB.end("BOB-OWN"); });
  check("idempotency: principal B not served principal A's cached response",
    resB._getBody() !== "ALICE-PRIVATE");
  check("idempotency: principal B's own handler runs (no cross-actor replay)",
    handlerRanForB === true);

  // Same principal + same key → legitimate replay (no over-isolation).
  var reqA2 = _mockReq("POST", "/account/export", "shared", { op: "export" });
  reqA2.user = { id: "alice" };
  var resA2 = _mockRes();
  var handlerRanForA2 = false;
  mw(reqA2, resA2, function () { handlerRanForA2 = true; resA2.end("ALICE-SECOND"); });
  check("idempotency: same principal + key still replays (no over-isolation)",
    resA2._getBody() === "ALICE-PRIVATE" && handlerRanForA2 === false);
}

function testMethodSkipsGet() {
  var store = b.middleware.idempotencyKey.memoryStore();
  var mw = b.middleware.idempotencyKey({ store: store });
  var req = _mockReq("GET", "/x");
  var res = _mockRes();
  var nextCalled = false;
  mw(req, res, function () { nextCalled = true; });
  check("GET is pass-through (skips middleware)", nextCalled === true);
}

function testMissingKeyDefault() {
  // Without requireIdempotencyKey, missing key is a pass-through.
  var store = b.middleware.idempotencyKey.memoryStore();
  var mw = b.middleware.idempotencyKey({ store: store });
  var req = _mockReq("POST", "/x");
  var res = _mockRes();
  var nextCalled = false;
  mw(req, res, function () { nextCalled = true; });
  check("POST without key + require:false → next()", nextCalled === true);
}

function testMissingKeyRequired() {
  var store = b.middleware.idempotencyKey.memoryStore();
  var mw = b.middleware.idempotencyKey({ store: store, requireIdempotencyKey: true });
  var req = _mockReq("POST", "/x");
  var res = _mockRes();
  var nextCalled = false;
  mw(req, res, function () { nextCalled = true; });
  check("POST without key + require:true → 400 problem-details, no next()",
        !nextCalled && res._statusCode() === 400 &&
        res._getHeaders()["content-type"] === "application/problem+json");
  var body = JSON.parse(res._getBody());
  check("missing-key problem type",
        /\/idempotency\/missing-key$/.test(body.type));
}

function testBadKeyShape() {
  var store = b.middleware.idempotencyKey.memoryStore();
  var mw = b.middleware.idempotencyKey({ store: store });
  var req = _mockReq("POST", "/x", "bad\x01key");  // control char
  var res = _mockRes();
  var nextCalled = false;
  mw(req, res, function () { nextCalled = true; });
  check("bad-key control char → 400 problem-details",
        !nextCalled && res._statusCode() === 400);
  var body = JSON.parse(res._getBody());
  check("bad-key problem type",
        /\/idempotency\/bad-key$/.test(body.type));
}

function testMissThenReplay() {
  var store = b.middleware.idempotencyKey.memoryStore();
  var mw = b.middleware.idempotencyKey({ store: store, ttlMs: 60000 });

  // First call — miss. Handler runs.
  var req1 = _mockReq("POST", "/x", "key-abc-123");
  req1._rawBody = Buffer.from('{"a":1}');
  var res1 = _mockRes();
  var nextCalled = false;
  mw(req1, res1, function () { nextCalled = true; });
  check("miss: handler invoked via next()", nextCalled);
  // Simulate handler writing a response.
  res1.statusCode = 201;
  res1.setHeader("Content-Type", "application/json");
  res1.end('{"id":"42"}');

  check("miss: response written", res1._getBody() === '{"id":"42"}');
  check("miss: cache stored", store._size() === 1);

  // Second call — same key + same body → replay.
  var req2 = _mockReq("POST", "/x", "key-abc-123");
  req2._rawBody = Buffer.from('{"a":1}');
  var res2 = _mockRes();
  var next2Called = false;
  mw(req2, res2, function () { next2Called = true; });
  check("replay: handler NOT invoked",   !next2Called);
  check("replay: statusCode restored",   res2._statusCode() === 201);
  check("replay: body restored",         res2._getBody() === '{"id":"42"}');
  check("replay: Content-Type restored", res2._getHeaders()["content-type"] === "application/json");
}

function testFingerprintMismatch() {
  var store = b.middleware.idempotencyKey.memoryStore();
  var mw = b.middleware.idempotencyKey({ store: store });

  // First call
  var req1 = _mockReq("POST", "/x", "key-conflict");
  req1._rawBody = Buffer.from('{"v":1}');
  var res1 = _mockRes();
  mw(req1, res1, function () {});
  res1.statusCode = 200;
  res1.end("ok");

  // Second call same key, DIFFERENT body
  var req2 = _mockReq("POST", "/x", "key-conflict");
  req2._rawBody = Buffer.from('{"v":2}');
  var res2 = _mockRes();
  var nextCalled = false;
  mw(req2, res2, function () { nextCalled = true; });
  check("fingerprint mismatch: 422 not handler",
        !nextCalled && res2._statusCode() === 422);
  var body = JSON.parse(res2._getBody());
  check("fingerprint mismatch: problem type",
        /\/idempotency\/key-reuse-mismatch$/.test(body.type));
}

function testSkip5xx() {
  var store = b.middleware.idempotencyKey.memoryStore();
  var mw = b.middleware.idempotencyKey({ store: store });

  var req = _mockReq("POST", "/x", "key-server-err");
  req._rawBody = Buffer.from('{}');
  var res = _mockRes();
  mw(req, res, function () {});
  res.statusCode = 500;
  res.end("server error");

  check("5xx not cached (transient infra failure)", store._size() === 0);
}

function testMemoryStoreFIFO() {
  var store = b.middleware.idempotencyKey.memoryStore({ maxEntries: 2 });
  store.set("a", { fingerprint: "f1", statusCode: 200, headers: {}, body: "" }, 60000);
  store.set("b", { fingerprint: "f2", statusCode: 200, headers: {}, body: "" }, 60000);
  store.set("c", { fingerprint: "f3", statusCode: 200, headers: {}, body: "" }, 60000);
  check("memoryStore FIFO: oldest evicted",
        store._size() === 2 && store.get("a") === null && store.get("c") !== null);
}

function testMemoryStoreTtlExpiry() {
  var store = b.middleware.idempotencyKey.memoryStore();
  store.set("expiring", { fingerprint: "f1", statusCode: 200, headers: {}, body: "" }, 1);
  // Force a small wait so TTL passes.
  var start = Date.now();
  while (Date.now() - start < 5) { /* spin briefly */ }
  check("memoryStore TTL: expired returns null", store.get("expiring") === null);
}

function _mockDb() {
  var data = new Map();   // k → { fingerprint, status_code, headers, body, expires_at }
  return {
    _data: data,
    prepare: function (sql) {
      if (/^CREATE (TABLE|INDEX)/i.test(sql)) {
        return { run: function () { return { changes: 0 }; } };
      }
      // b.sql emits double-quoted identifiers ("k", "fingerprint", ...);
      // the patterns tolerate optional quotes so the mock matches the
      // builder's quote-by-construction output as well as the legacy bare
      // form.
      if (/^SELECT "?k"?(, "?fingerprint"?)?.* FROM /i.test(sql)) {
        return {
          get: function (k) {
            var row = data.get(k);
            return row ? Object.assign({ k: k }, row) : undefined;
          },
          // resealMigrate() also issues `SELECT "k", ... FROM <table>`
          // without a WHERE "k" = ? clause — walk all rows.
          all: function () {
            var out = [];
            data.forEach(function (row, k) {
              out.push(Object.assign({ k: k }, row));
            });
            return out;
          },
        };
      }
      if (/^INSERT INTO .*\(\s*"?k"?, "?fingerprint"?, "?status_code"?, "?headers"?, "?body"?, "?expires_at"?\s*\)/i.test(sql)) {
        return {
          run: function (k, fingerprint, statusCode, headers, body, expiresAt) {
            data.set(k, {
              fingerprint: fingerprint,
              status_code: statusCode,
              headers:     headers,
              body:        body,
              expires_at:  expiresAt,
            });
            return { changes: 1 };
          },
        };
      }
      if (/^DELETE FROM .* WHERE "?k"? = \? AND "?expires_at"? <= \?/i.test(sql)) {
        return {
          run: function (k, expiresAt) {
            var row = data.get(k);
            if (row && row.expires_at <= expiresAt) {
              data.delete(k);
              return { changes: 1 };
            }
            return { changes: 0 };
          },
        };
      }
      if (/^DELETE FROM /i.test(sql)) {
        return {
          run: function (k) {
            var had = data.has(k);
            data.delete(k);
            return { changes: had ? 1 : 0 };
          },
        };
      }
      throw new Error("_mockDb: unsupported SQL: " + sql);
    },
  };
}

function testDbStoreSurface() {
  var db = _mockDb();
  var store = b.middleware.idempotencyKey.dbStore({ db: db });
  check("dbStore: get fn",    typeof store.get === "function");
  check("dbStore: set fn",    typeof store.set === "function");
  check("dbStore: delete fn", typeof store.delete === "function");
  check("dbStore: default tableName", store._tableName === "blamejs_idempotency_keys");
}

function testDbStoreBadOpts() {
  function expectThrow(label, fn, codeMatch) {
    var threw = null;
    try { fn(); } catch (e) { threw = e; }
    check(label, threw && (threw.code || "").indexOf(codeMatch) !== -1);
  }
  expectThrow("dbStore: missing db refused",
    function () { b.middleware.idempotencyKey.dbStore({}); },
    "idempotency/bad-db");
  expectThrow("dbStore: db without prepare() refused",
    function () { b.middleware.idempotencyKey.dbStore({ db: {} }); },
    "idempotency/bad-db");
  expectThrow("dbStore: bad tableName refused",
    function () { b.middleware.idempotencyKey.dbStore({ db: _mockDb(), tableName: "drop;table--" }); },
    "idempotency/bad-table-name");
  expectThrow("dbStore: tableName with quotes refused",
    function () { b.middleware.idempotencyKey.dbStore({ db: _mockDb(), tableName: 'a"b' }); },
    "idempotency/bad-table-name");
}

function testDbStoreSetGetDelete() {
  var db = _mockDb();
  var store = b.middleware.idempotencyKey.dbStore({ db: db });
  store.set("k1", { fingerprint: "abc", statusCode: 200, headers: {}, body: "" }, 60000);
  var v = store.get("k1");
  check("dbStore: set+get roundtrip",  v && v.fingerprint === "abc" && v.statusCode === 200);
  check("dbStore: get missing → null", store.get("nope") === null);
  store.delete("k1");
  check("dbStore: delete clears",      store.get("k1") === null);
}

function testDbStoreTtlExpiry() {
  var db = _mockDb();
  var store = b.middleware.idempotencyKey.dbStore({ db: db });
  store.set("short", { fingerprint: "x", statusCode: 200, headers: {}, body: "" }, 1);
  var start = Date.now();
  while (Date.now() - start < 5) { /* spin briefly */ }
  check("dbStore TTL: expired returns null + row cleaned",
        store.get("short") === null && db._data.has("short") === false);
}

function testDbStoreUpsert() {
  var db = _mockDb();
  var store = b.middleware.idempotencyKey.dbStore({ db: db });
  store.set("k", { fingerprint: "v1", statusCode: 200, headers: {}, body: "" }, 60000);
  store.set("k", { fingerprint: "v2", statusCode: 201, headers: {}, body: "" }, 60000);
  var v = store.get("k");
  check("dbStore: second set upserts", v && v.fingerprint === "v2" && v.statusCode === 201);
}

function testDbStoreCorruptRow() {
  var db = _mockDb();
  var store = b.middleware.idempotencyKey.dbStore({ db: db, hashKeys: false, seal: false });
  // Inject a row whose `headers` column is unparseable JSON.
  db._data.set("corrupt", {
    fingerprint: "x", status_code: 200,
    headers:     "not-json-{{{",
    body:        "",
    expires_at:  Date.now() + 60000,
  });
  check("dbStore: corrupt headers JSON treated as miss + cleaned",
        store.get("corrupt") === null && db._data.has("corrupt") === false);
}

function testDbStoreExpiredRaceNoFreshClobber() {
  // Multi-process race: process A reads the expired row, then process
  // B upserts a fresh row before process A's cleanup-delete fires.
  // The delete must NOT remove the fresh row.
  var db = _mockDb();
  b.middleware.idempotencyKey.dbStore({ db: db, hashKeys: false, seal: false });
  var staleExpires = Date.now() - 1000;
  db._data.set("k", {
    fingerprint: "old", status_code: 200,
    headers:     JSON.stringify({}),
    body:        "",
    expires_at:  staleExpires,
  });
  // Wrap stmtGet to simulate a concurrent upsert mid-read.
  var origGet = db.prepare;
  db.prepare = function (sql) {
    var stmt = origGet.call(db, sql);
    if (/^SELECT "?k"?(, "?fingerprint"?)?.* FROM /i.test(sql)) {
      var realGet = stmt.get;
      return {
        get: function (k) {
          var row = realGet(k);
          if (row && row.expires_at <= staleExpires) {
            // Concurrent upsert: another process writes a fresh row.
            db._data.set(k, {
              fingerprint: "fresh", status_code: 201,
              headers:     JSON.stringify({}),
              body:        "",
              expires_at:  Date.now() + 60000,
            });
          }
          return row;
        },
      };
    }
    return stmt;
  };
  var racingStore = b.middleware.idempotencyKey.dbStore({ db: db, hashKeys: false, seal: false });
  var result = racingStore.get("k");
  check("dbStore race: stale read returns null (miss)", result === null);
  check("dbStore race: concurrent fresh row preserved", db._data.has("k") === true);
  var freshRow = db._data.get("k");
  check("dbStore race: fresh row is the concurrent upsert",
        freshRow.fingerprint === "fresh");
}

function testDbStoreHashKeysDefault() {
  // hashKeys defaults ON — raw operator key NEVER lands in db._data.
  var db = _mockDb();
  var store = b.middleware.idempotencyKey.dbStore({ db: db, seal: false });
  check("dbStore: hashKeys default true", store._hashKeys === true);
  var rawKey = "order-12345-alice@example.com";
  store.set(rawKey, { fingerprint: "fp", statusCode: 200, headers: {}, body: "" }, 60000);
  // db._data keys are the SHA3-512 namespace-hash; raw key must not appear.
  var stored = Array.from(db._data.keys());
  check("dbStore hashKeys: raw key absent from DB",
        stored.indexOf(rawKey) === -1);
  check("dbStore hashKeys: hashed key (128-hex) present in DB",
        stored.length === 1 && /^[0-9a-f]{128}$/.test(stored[0]));
  // Round-trip with the raw key still works (transparent hashing).
  var v = store.get(rawKey);
  check("dbStore hashKeys: round-trip with raw key", v && v.fingerprint === "fp");
}

function testDbStoreHashKeysOptOut() {
  var db = _mockDb();
  var store = b.middleware.idempotencyKey.dbStore({ db: db, hashKeys: false, seal: false });
  check("dbStore: hashKeys: false respected", store._hashKeys === false);
  store.set("plain-key", { fingerprint: "fp", statusCode: 200, headers: {}, body: "" }, 60000);
  check("dbStore opt-out: raw key in DB", db._data.has("plain-key"));
}

function testDbStoreSealedRowAcrossProcessesNotDeleted() {
  // Codex P1 on PR #45: process A has seal=false (vault not init);
  // process B (seal=true) writes a sealed row. Process A reading
  // that row must NOT delete it — leave for B to consume.
  var db = _mockDb();
  var store = b.middleware.idempotencyKey.dbStore({
    db: db, tableName: "_t_xproc", hashKeys: false, seal: false,
  });
  // Inject a row whose headers look vault-sealed (vault: prefix).
  db._data.set("k", {
    fingerprint: "fp",
    status_code: 200,
    headers:     "vault:eyJzb21lIjoiZW52ZWxvcGUifQ==",   // not JSON; mimics sealed envelope
    body:        "vault:eyJib2R5IjoiYmFzZTY0In0=",
    expires_at:  Date.now() + 60000,
  });
  var result = store.get("k");
  check("dbStore xproc-sealed: read returns null (miss)", result === null);
  check("dbStore xproc-sealed: sealed row LEFT IN PLACE for sibling process",
        db._data.has("k") === true);
}

function testDbStoreCorruptHeadersDeletedWhenNotSealed() {
  // Companion to the test above: genuinely corrupt headers (NOT
  // vault-sealed) ARE deleted on read. Distinguishes a real
  // corruption from a cross-process seal-format mismatch.
  var db = _mockDb();
  var store = b.middleware.idempotencyKey.dbStore({
    db: db, tableName: "_t_corrupt", hashKeys: false, seal: false,
  });
  db._data.set("k", {
    fingerprint: "fp",
    status_code: 200,
    headers:     "{this is not json{",   // genuine corruption, no vault: prefix
    body:        "",
    expires_at:  Date.now() + 60000,
  });
  var result = store.get("k");
  check("dbStore corrupt-headers: read returns null", result === null);
  check("dbStore corrupt-headers: row DELETED (no cross-process value to preserve)",
        db._data.has("k") === false);
}

function testDbStoreSealReqWithoutVault() {
  // Probe-falls-back path: when vault.init() hasn't run, seal request
  // silently degrades to plaintext (with an audit warning).
  var db = _mockDb();
  // Use a fresh tableName so cryptoField doesn't carry registration
  // state from prior tests in this run.
  var store = b.middleware.idempotencyKey.dbStore({
    db: db, tableName: "_t_no_vault", hashKeys: false,
  });
  // sealEnabled false because the test env hasn't initialized vault.
  check("dbStore: seal disabled when vault not ready", store._sealEnabled === false);
  store.set("k", { fingerprint: "fp", statusCode: 200, headers: { "X-Hi": "y" }, body: "QUJD" }, 60000);
  var row = db._data.get("k");
  // body/headers stored as plaintext (no vault: prefix).
  check("dbStore seal-skipped: body plaintext", row.body === "QUJD");
  check("dbStore seal-skipped: headers plaintext",
        row.headers.indexOf("vault:") === -1);
}

async function testDbStoreSealRoundTripWithVault() {
  // Default-ON seal path exercised: bootstrap vault, build dbStore
  // with seal=true (default), set a record + read it back via the
  // unseal path. Verifies sealed envelope is actually written + the
  // unseal restore matches what was set.
  var dataDir = nodeFs.mkdtempSync(nodePath.join(nodeOs.tmpdir(), "idemp-seal-"));
  try {
    if (typeof vault._resetForTest === "function") vault._resetForTest();
    cryptoField.clearForTest();
    await vault.init({ dataDir: dataDir, mode: "plaintext" });

    var db = _mockDb();
    var store = b.middleware.idempotencyKey.dbStore({
      db: db, tableName: "_t_seal_roundtrip", hashKeys: false, seal: true,
    });
    check("dbStore seal RT: seal enabled when vault ready", store._sealEnabled === true);

    var headersIn = { "x-trace-id": "abc-123", "content-type": "application/json" };
    var bodyIn = Buffer.from('{"ok":true}').toString("base64");
    store.set("k1", {
      fingerprint: "fp",
      statusCode:  200,
      headers:     headersIn,
      body:        bodyIn,
    }, 60000);

    // Inspect raw row — headers + body must be vault-sealed envelopes.
    // CRYPTO-1 (v0.9.58): the default is now AAD-bound seal, so the
    // prefix is "vault.aad:" rather than the legacy plain "vault:".
    var raw = db._data.get("k1");
    check("dbStore seal RT: headers column carries an AAD-bound seal envelope",
          typeof raw.headers === "string" && raw.headers.indexOf("vault.aad:") === 0);
    check("dbStore seal RT: body column carries an AAD-bound seal envelope",
          typeof raw.body === "string" && raw.body.indexOf("vault.aad:") === 0);
    check("dbStore seal RT: status_code stays plaintext (forensic-queryable)",
          raw.status_code === 200);

    // Round-trip the read through unseal — values must equal what we set.
    var v = store.get("k1");
    check("dbStore seal RT: round-trip fingerprint", v.fingerprint === "fp");
    check("dbStore seal RT: round-trip statusCode",  v.statusCode === 200);
    check("dbStore seal RT: round-trip body",        v.body === bodyIn);
    check("dbStore seal RT: round-trip headers",
          v.headers["x-trace-id"] === "abc-123" &&
          v.headers["content-type"] === "application/json");
  } finally {
    if (typeof vault._resetForTest === "function") vault._resetForTest();
    cryptoField.clearForTest();
    try { nodeFs.rmSync(dataDir, { recursive: true, force: true }); } catch (_e) { /* best-effort */ }
  }
}

function testResealMigrateInMemoryStoreUnsupported() {
  // Operators on the in-memory store can't bulk-reseal — the helper
  // reports the reason instead of throwing so a boot script stays quiet.
  var store = b.middleware.idempotencyKey.memoryStore();
  var info = b.middleware.idempotencyKey.resealMigrate(store);
  check("resealMigrate: in-memory store reports store-does-not-support-reseal",
    info.migrated === 0 && info.skipped === 0 &&
    info.reason === "store-does-not-support-reseal");
}

function testResealMigrateSealDisabled() {
  // A dbStore with sealing off (vault not wired) can't reseal — the
  // helper delegates and surfaces the aad-or-seal-disabled reason.
  var db = _mockDb();
  var store = b.middleware.idempotencyKey.dbStore({
    db: db, tableName: "_t_reseal_noseal", hashKeys: false, seal: false,
  });
  var info = b.middleware.idempotencyKey.resealMigrate(store);
  check("resealMigrate: seal-disabled dbStore reports aad-or-seal-disabled",
    info.migrated === 0 && info.skipped === 0 && info.reason === "aad-or-seal-disabled");
}

async function testResealMigrateAlreadyAadSealed() {
  // With vault + AAD sealing on, a row written by the store is already
  // in the vault.aad: envelope. resealMigrate walks the table, detects
  // it's already migrated, and skips it — succeeding with reason:null.
  var dataDir = nodeFs.mkdtempSync(nodePath.join(nodeOs.tmpdir(), "idemp-reseal-"));
  try {
    if (typeof vault._resetForTest === "function") vault._resetForTest();
    cryptoField.clearForTest();
    await vault.init({ dataDir: dataDir, mode: "plaintext" });

    var db = _mockDb();
    var store = b.middleware.idempotencyKey.dbStore({
      db: db, tableName: "_t_reseal_aad", hashKeys: false, seal: true, aad: true,
    });
    check("resealMigrate: seal + aad enabled when vault ready",
      store._sealEnabled === true && store._aadOn === true);

    store.set("k1", {
      fingerprint: "fp",
      statusCode:  200,
      headers:     { "x-a": "1" },
      body:        Buffer.from('{"ok":true}').toString("base64"),
    }, 60000);
    check("resealMigrate: fresh row is written in the vault.aad: envelope",
      typeof db._data.get("k1").headers === "string" &&
      db._data.get("k1").headers.indexOf("vault.aad:") === 0);

    var info = b.middleware.idempotencyKey.resealMigrate(store);
    check("resealMigrate: already-AAD row is skipped, migration succeeds",
      info.migrated === 0 && info.skipped === 1 && info.reason === null);

    // The row still round-trips after the walk (no corruption).
    var v = store.get("k1");
    check("resealMigrate: row still readable after the walk",
      v && v.fingerprint === "fp" && v.headers["x-a"] === "1");
  } finally {
    if (typeof vault._resetForTest === "function") vault._resetForTest();
    cryptoField.clearForTest();
    try { nodeFs.rmSync(dataDir, { recursive: true, force: true }); } catch (_e) { /* best-effort */ }
  }
}

// ---- config-time validation throws (entry-point tier) ----

function testMemoryStoreBadMaxEntries() {
  function expectCode(label, fn, code) {
    var threw = null;
    try { fn(); } catch (e) { threw = e; }
    check(label, threw && (threw.code || "").indexOf(code) !== -1);
  }
  expectCode("memoryStore: negative maxEntries refused",
    function () { b.middleware.idempotencyKey.memoryStore({ maxEntries: -1 }); },
    "idempotency/bad-max-entries");
  expectCode("memoryStore: non-integer maxEntries refused",
    function () { b.middleware.idempotencyKey.memoryStore({ maxEntries: 1.5 }); },
    "idempotency/bad-max-entries");
  expectCode("memoryStore: Infinity maxEntries refused",
    function () { b.middleware.idempotencyKey.memoryStore({ maxEntries: Infinity }); },
    "idempotency/bad-max-entries");
  expectCode("memoryStore: string maxEntries refused",
    function () { b.middleware.idempotencyKey.memoryStore({ maxEntries: "10" }); },
    "idempotency/bad-max-entries");
}

function testCreateBadNumericOpts() {
  function expectCode(label, fn, code) {
    var threw = null;
    try { fn(); } catch (e) { threw = e; }
    check(label, threw && (threw.code || "").indexOf(code) !== -1);
  }
  var store = b.middleware.idempotencyKey.memoryStore();
  expectCode("create: negative ttlMs refused",
    function () { b.middleware.idempotencyKey({ store: store, ttlMs: -5 }); },
    "idempotency/bad-ttl");
  expectCode("create: Infinity ttlMs refused",
    function () { b.middleware.idempotencyKey({ store: store, ttlMs: Infinity }); },
    "idempotency/bad-ttl");
  expectCode("create: non-integer maxBodyBytes refused",
    function () { b.middleware.idempotencyKey({ store: store, maxBodyBytes: 1.2 }); },
    "idempotency/bad-max-body");
  expectCode("create: bad scopeFn type refused",
    function () { b.middleware.idempotencyKey({ store: store, scopeFn: "nope" }); },
    "idempotency/bad-scope-fn");
  expectCode("create: unknown bodyFingerprintFallback refused",
    function () { b.middleware.idempotencyKey({ store: store, bodyFingerprintFallback: "sometimes" }); },
    "idempotency/bad-body-fingerprint-fallback");
}

// ---- key-shape adversarial branches ----

function testKeyTooLong() {
  var store = b.middleware.idempotencyKey.memoryStore();
  var mw = b.middleware.idempotencyKey({ store: store });
  var longKey = new Array(257).join("a");   // 256 chars, > KEY_MAX_LEN (255)
  var req = _mockReq("POST", "/x", longKey);
  req._rawBody = Buffer.from("{}");
  var res = _mockRes();
  var nextCalled = false;
  mw(req, res, function () { nextCalled = true; });
  check("bad-key over-length → 400, no next()",
        !nextCalled && res._statusCode() === 400);
  var body = JSON.parse(res._getBody());
  check("bad-key over-length problem type",
        /\/idempotency\/bad-key$/.test(body.type));
}

function testArrayKeyHeaderUsesFirst() {
  // A repeated Idempotency-Key header arrives as an array; the
  // middleware uses the first element as the cache key.
  var store = b.middleware.idempotencyKey.memoryStore();
  var mw = b.middleware.idempotencyKey({ store: store, ttlMs: 60000 });

  var req1 = _mockReq("POST", "/x", "placeholder");
  req1.headers["idempotency-key"] = ["arr-key-1", "arr-key-2"];
  req1._rawBody = Buffer.from('{"a":1}');
  var res1 = _mockRes();
  var next1 = false;
  mw(req1, res1, function () { next1 = true; });
  check("array key: first request is a miss (handler runs)", next1 === true);
  res1.statusCode = 201;
  res1.end("created");

  // A single-value header equal to the FIRST array element must replay
  // the cached response — proving key[0] was the slot key.
  var req2 = _mockReq("POST", "/x", "arr-key-1");
  req2._rawBody = Buffer.from('{"a":1}');
  var res2 = _mockRes();
  var next2 = false;
  mw(req2, res2, function () { next2 = true; });
  check("array key: replay keyed on first element",
        !next2 && res2._statusCode() === 201 && res2._getBody() === "created");
}

// ---- custom methods / headerName ----

function testCustomMethodsSkipsUnlisted() {
  var store = b.middleware.idempotencyKey.memoryStore();
  var mw = b.middleware.idempotencyKey({ store: store, methods: ["post"] });
  // PUT is NOT in the operator-narrowed method set → pass-through.
  var req = _mockReq("PUT", "/x", "k-put");
  req._rawBody = Buffer.from("{}");
  var res = _mockRes();
  var nextCalled = false;
  mw(req, res, function () { nextCalled = true; });
  check("custom methods: PUT not listed → pass-through next()", nextCalled === true);
  check("custom methods: nothing cached for unlisted method", store._size() === 0);
}

function testCustomHeaderName() {
  var store = b.middleware.idempotencyKey.memoryStore();
  var mw = b.middleware.idempotencyKey({ store: store, headerName: "X-Idem", ttlMs: 60000 });

  var req1 = _mockReq("POST", "/x");
  req1.headers["x-idem"] = "custom-hdr-1";
  req1._rawBody = Buffer.from('{"a":1}');
  var res1 = _mockRes();
  var next1 = false;
  mw(req1, res1, function () { next1 = true; });
  check("custom headerName: read from operator header (miss)", next1 === true);
  res1.statusCode = 200;
  res1.end("via-custom-header");

  var req2 = _mockReq("POST", "/x");
  req2.headers["x-idem"] = "custom-hdr-1";
  req2._rawBody = Buffer.from('{"a":1}');
  var res2 = _mockRes();
  var next2 = false;
  mw(req2, res2, function () { next2 = true; });
  check("custom headerName: replays on the operator header",
        !next2 && res2._getBody() === "via-custom-header");
}

// ---- bodyFingerprintFallback branches (real middleware run) ----

function testDenyFallbackRefusesMissingBody() {
  // Default fallback is "deny": a body-bearing POST that arrives with
  // neither a parsed body nor a raw-body buffer is refused with HTTP
  // 400 idempotency/missing-body-fingerprint (draft §4.3 protection —
  // silent method+path degrade would false-replay different bodies).
  var store = b.middleware.idempotencyKey.memoryStore();
  var mw = b.middleware.idempotencyKey({ store: store });
  var req = _mockReq("POST", "/pay", "k-nobody");   // no body, no _rawBody
  var res = _mockRes();
  var nextCalled = false;
  mw(req, res, function () { nextCalled = true; });
  check("deny fallback: missing body → 400, no next()",
        !nextCalled && res._statusCode() === 400);
  var body = JSON.parse(res._getBody());
  check("deny fallback: missing-body-fingerprint problem type",
        /\/idempotency\/missing-body-fingerprint$/.test(body.type));
  check("deny fallback: nothing cached", store._size() === 0);
}

function testMethodPathOnlyFallbackAllows() {
  // Operator opts into the pre-0.9.58 behavior: a bodyless POST is
  // allowed through (fingerprint degrades to method+path), and a
  // subsequent identical request replays.
  var store = b.middleware.idempotencyKey.memoryStore();
  var mw = b.middleware.idempotencyKey({
    store: store, ttlMs: 60000, bodyFingerprintFallback: "method-path-only",
  });
  var req1 = _mockReq("POST", "/ping", "k-mpo");
  var res1 = _mockRes();
  var next1 = false;
  mw(req1, res1, function () { next1 = true; });
  check("method-path-only: bodyless POST allowed through (miss)", next1 === true);
  res1.statusCode = 202;
  res1.end("accepted");

  var req2 = _mockReq("POST", "/ping", "k-mpo");
  var res2 = _mockRes();
  var next2 = false;
  mw(req2, res2, function () { next2 = true; });
  check("method-path-only: identical bodyless POST replays",
        !next2 && res2._statusCode() === 202 && res2._getBody() === "accepted");
}

// ---- default (non-hook) body extraction branches ----

function testObjectBodyDefaultPath() {
  // No bodyFingerprint hook: an already-parsed object body is
  // JSON-stringified for a stable fingerprint.
  var store = b.middleware.idempotencyKey.memoryStore();
  var mw = b.middleware.idempotencyKey({ store: store, ttlMs: 60000 });

  var req1 = _mockReq("POST", "/o", "k-obj", { amount: 100 });
  var res1 = _mockRes();
  var next1 = false;
  mw(req1, res1, function () { next1 = true; });
  check("object body: first request is a miss", next1 === true);
  res1.end("obj-ok");

  // Same object → replay.
  var req2 = _mockReq("POST", "/o", "k-obj", { amount: 100 });
  var res2 = _mockRes();
  var next2 = false;
  mw(req2, res2, function () { next2 = true; });
  check("object body: identical object replays", !next2 && res2._getBody() === "obj-ok");

  // Different object → 422 mismatch.
  var req3 = _mockReq("POST", "/o", "k-obj", { amount: 999 });
  var res3 = _mockRes();
  var next3 = false;
  mw(req3, res3, function () { next3 = true; });
  check("object body: different object → 422 mismatch",
        !next3 && res3._statusCode() === 422);
}

function testCircularObjectBodyDenied() {
  // A non-serializable (circular) body cannot be fingerprinted; the
  // default-path JSON.stringify throws, bodyBytes becomes null, and
  // the deny fallback refuses with 400.
  var store = b.middleware.idempotencyKey.memoryStore();
  var mw = b.middleware.idempotencyKey({ store: store });
  var circ = {};
  circ.self = circ;
  var req = _mockReq("POST", "/c", "k-circ", circ);
  var res = _mockRes();
  var nextCalled = false;
  mw(req, res, function () { nextCalled = true; });
  check("circular body: unserializable body → 400 deny, no next()",
        !nextCalled && res._statusCode() === 400);
}

// ---- bodyFingerprint hook return-type + throw branches ----

function testBodyFingerprintHookReturnTypes() {
  // Buffer and object hook returns both produce stable fingerprints.
  var store = b.middleware.idempotencyKey.memoryStore();
  var bufMw = b.middleware.idempotencyKey({
    store: store, ttlMs: 60000,
    bodyFingerprint: function () { return Buffer.from("fixed-buffer-fp"); },
  });
  var r1 = _mockReq("POST", "/b", "k-buf");
  var s1 = _mockRes();
  bufMw(r1, s1, function () {});
  s1.end("buf-ok");
  var r2 = _mockReq("POST", "/b", "k-buf");
  var s2 = _mockRes();
  var n2 = false;
  bufMw(r2, s2, function () { n2 = true; });
  check("hook Buffer return: replay on stable buffer fingerprint",
        !n2 && s2._getBody() === "buf-ok");

  var store2 = b.middleware.idempotencyKey.memoryStore();
  var objMw = b.middleware.idempotencyKey({
    store: store2, ttlMs: 60000,
    bodyFingerprint: function (req) { return req.body || null; },
  });
  var r3 = _mockReq("POST", "/j", "k-objhook", { k: 1 });
  var s3 = _mockRes();
  objMw(r3, s3, function () {});
  s3.end("objhook-ok");
  var r4 = _mockReq("POST", "/j", "k-objhook", { k: 1 });
  var s4 = _mockRes();
  var n4 = false;
  objMw(r4, s4, function () { n4 = true; });
  check("hook object return: replay on JSON-stringified fingerprint",
        !n4 && s4._getBody() === "objhook-ok");
}

function testBodyFingerprintHookThrows() {
  // A throwing hook is caught (audit warning), bodyBytes becomes null.
  // For DELETE (not in the POST/PUT/PATCH deny check) the request still
  // proceeds on a method+path fingerprint.
  var store = b.middleware.idempotencyKey.memoryStore();
  var mw = b.middleware.idempotencyKey({
    store: store, ttlMs: 60000,
    bodyFingerprint: function () { throw new Error("hook boom"); },
  });
  var req = _mockReq("DELETE", "/resource/1", "k-hookthrow");
  var res = _mockRes();
  var nextCalled = false;
  mw(req, res, function () { nextCalled = true; });
  check("hook throws on DELETE: caught, request proceeds (next runs)",
        nextCalled === true && res._statusCode() !== 400);
}

function testDeleteMissThenReplay() {
  // DELETE is a default method but is exempt from the body-fingerprint
  // deny check; a bodyless DELETE caches + replays on method+path.
  var store = b.middleware.idempotencyKey.memoryStore();
  var mw = b.middleware.idempotencyKey({ store: store, ttlMs: 60000 });
  var req1 = _mockReq("DELETE", "/resource/9", "k-del");
  var res1 = _mockRes();
  var next1 = false;
  mw(req1, res1, function () { next1 = true; });
  check("DELETE: first request handled (not pass-through)", next1 === true);
  res1.statusCode = 204;
  res1.end("");
  check("DELETE: response cached", store._size() === 1);

  var req2 = _mockReq("DELETE", "/resource/9", "k-del");
  var res2 = _mockRes();
  var next2 = false;
  mw(req2, res2, function () { next2 = true; });
  check("DELETE: identical request replays cached 204",
        !next2 && res2._statusCode() === 204);
}

// ---- store fault-tolerance (get/set throw) ----

function testStoreReadFailureTreatedAsMiss() {
  var store = {
    get: function () { throw new Error("read exploded"); },
    set: function () {},
    delete: function () {},
  };
  var mw = b.middleware.idempotencyKey({ store: store });
  var req = _mockReq("POST", "/x", "k-readfail");
  req._rawBody = Buffer.from("{}");
  var res = _mockRes();
  var nextCalled = false;
  var threw = false;
  try { mw(req, res, function () { nextCalled = true; }); }
  catch (_e) { threw = true; }
  check("store read failure: no throw escapes the middleware", threw === false);
  check("store read failure: treated as miss, handler runs", nextCalled === true);
}

function testStoreWriteFailureDoesNotBreakResponse() {
  var store = {
    get: function () { return null; },
    set: function () { throw new Error("write exploded"); },
    delete: function () {},
  };
  var mw = b.middleware.idempotencyKey({ store: store });
  var req = _mockReq("POST", "/x", "k-writefail");
  req._rawBody = Buffer.from("{}");
  var res = _mockRes();
  var threw = false;
  mw(req, res, function () {});
  try { res.statusCode = 200; res.end("still works"); }
  catch (_e) { threw = true; }
  check("store write failure: response completes without throwing", threw === false);
  check("store write failure: handler body still written", res._getBody() === "still works");
  check("store write failure: response ended", res._ended() === true);
}

// ---- response-capture edge branches ----

function testBodyTooLargeNotCached() {
  var store = b.middleware.idempotencyKey.memoryStore();
  var mw = b.middleware.idempotencyKey({ store: store, maxBodyBytes: 4 });
  var req = _mockReq("POST", "/big", "k-big");
  req._rawBody = Buffer.from("{}");
  var res = _mockRes();
  mw(req, res, function () {});
  res.statusCode = 200;
  res.end("abcdefgh");   // 8 bytes > maxBodyBytes (4)
  check("body-too-large: oversized response NOT cached", store._size() === 0);
  check("body-too-large: response still delivered to client",
        res._getBody() === "abcdefgh" && res._ended() === true);
}

function testStreamingWriteCaptureReplays() {
  // Handler streams via res.write(...) then res.end() with no final
  // chunk; the write-wrapper captures the streamed bytes and replays
  // the concatenation on the retry.
  var store = b.middleware.idempotencyKey.memoryStore();
  var mw = b.middleware.idempotencyKey({ store: store, ttlMs: 60000 });
  var req1 = _mockReq("POST", "/stream", "k-stream");
  req1._rawBody = Buffer.from("{}");
  var res1 = _mockRes();
  mw(req1, res1, function () {
    res1.statusCode = 200;
    res1.write("part1-");
    res1.write("part2");
    res1.end();
  });
  check("streaming capture: full body assembled from writes",
        res1._getBody() === "part1-part2");
  check("streaming capture: cached", store._size() === 1);

  var req2 = _mockReq("POST", "/stream", "k-stream");
  req2._rawBody = Buffer.from("{}");
  var res2 = _mockRes();
  var next2 = false;
  mw(req2, res2, function () { next2 = true; });
  check("streaming capture: retry replays the concatenated body",
        !next2 && res2._getBody() === "part1-part2");
}

function testReplaySkipsThrowingSetHeader() {
  // On replay, an operator-restricted header whose setHeader() throws is
  // skipped without aborting the replay — status + body still restored.
  var store = b.middleware.idempotencyKey.memoryStore();
  var mw = b.middleware.idempotencyKey({ store: store, ttlMs: 60000 });
  var req1 = _mockReq("POST", "/h", "k-hdrthrow");
  req1._rawBody = Buffer.from("{}");
  var res1 = _mockRes();
  mw(req1, res1, function () {
    res1.statusCode = 200;
    res1.setHeader("X-Test", "v");
    res1.end("hdr-body");
  });

  var req2 = _mockReq("POST", "/h", "k-hdrthrow");
  req2._rawBody = Buffer.from("{}");
  var res2 = _mockRes();
  res2.setHeader = function () { throw new Error("restricted header"); };
  var next2 = false;
  var threw = false;
  try { mw(req2, res2, function () { next2 = true; }); }
  catch (_e) { threw = true; }
  check("replay setHeader throw: no throw escapes replay", threw === false);
  check("replay setHeader throw: handler not re-invoked", next2 === false);
  check("replay setHeader throw: status + body still restored",
        res2._statusCode() === 200 && res2._getBody() === "hdr-body" && res2._ended() === true);
}

async function run() {
  testSurface();
  testBadOpts();
  testMemoryStoreBadMaxEntries();
  testCreateBadNumericOpts();
  testKeyTooLong();
  testArrayKeyHeaderUsesFirst();
  testCustomMethodsSkipsUnlisted();
  testCustomHeaderName();
  testDenyFallbackRefusesMissingBody();
  testMethodPathOnlyFallbackAllows();
  testObjectBodyDefaultPath();
  testCircularObjectBodyDenied();
  testBodyFingerprintHookReturnTypes();
  testBodyFingerprintHookThrows();
  testDeleteMissThenReplay();
  testStoreReadFailureTreatedAsMiss();
  testStoreWriteFailureDoesNotBreakResponse();
  testBodyTooLargeNotCached();
  testStreamingWriteCaptureReplays();
  testReplaySkipsThrowingSetHeader();
  testMethodSkipsGet();
  testMissingKeyDefault();
  testMissingKeyRequired();
  testBadKeyShape();
  testMissThenReplay();
  testFingerprintMismatch();
  testCrossActorIsolation();
  testBodyFingerprintHook();
  testSkip5xx();
  testMemoryStoreFIFO();
  testMemoryStoreTtlExpiry();
  testDbStoreSurface();
  testDbStoreBadOpts();
  testDbStoreSetGetDelete();
  testDbStoreTtlExpiry();
  testDbStoreUpsert();
  testDbStoreCorruptRow();
  testDbStoreExpiredRaceNoFreshClobber();
  testDbStoreHashKeysDefault();
  testDbStoreHashKeysOptOut();
  testDbStoreSealReqWithoutVault();
  testDbStoreSealedRowAcrossProcessesNotDeleted();
  testDbStoreCorruptHeadersDeletedWhenNotSealed();
  await testDbStoreSealRoundTripWithVault();
  testResealMigrateInMemoryStoreUnsupported();
  testResealMigrateSealDisabled();
  await testResealMigrateAlreadyAadSealed();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e); process.exit(1); });
}
