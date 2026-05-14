"use strict";
/**
 * b.middleware.idempotencyKey — draft-ietf-httpapi-idempotency-key.
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

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
      if (/^SELECT fingerprint, status_code, headers, body, expires_at FROM /i.test(sql)) {
        return {
          get: function (k) {
            var row = data.get(k);
            return row ? Object.assign({}, row) : undefined;
          },
        };
      }
      if (/^INSERT INTO [^ ]+\(k, fingerprint, status_code, headers, body, expires_at\)/i.test(sql)) {
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
      if (/^DELETE FROM [^ ]+ WHERE k = \? AND expires_at <= \?/i.test(sql)) {
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
    if (/^SELECT fingerprint, status_code, headers, body, expires_at FROM /i.test(sql)) {
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

async function run() {
  testSurface();
  testBadOpts();
  testMethodSkipsGet();
  testMissingKeyDefault();
  testMissingKeyRequired();
  testBadKeyShape();
  testMissThenReplay();
  testFingerprintMismatch();
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
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e); process.exit(1); });
}
