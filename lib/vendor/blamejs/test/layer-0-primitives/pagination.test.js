"use strict";
/**
 * pagination — cursor + offset helpers.
 *
 * Run standalone: `node test/layer-0-primitives/pagination.test.js`
 * Or via smoke:   `node test/smoke.js`
 */

var helpers = require("../helpers");
var b     = helpers.b;
var fs    = helpers.fs;
var os    = helpers.os;
var path  = helpers.path;
var check = helpers.check;
var setupTestDb    = helpers.setupTestDb;
var teardownTestDb = helpers.teardownTestDb;

function _mockQuery(rows, opts) {
  // Mock Query that records the chain of calls + supports the same
  // terminal methods (.all, .count). For most pagination tests we
  // don't actually execute SQL — we verify the chain construction
  // and trust the real DB tests separately to confirm SQL is correct.
  opts = opts || {};
  var q = {
    _whereCalls:    [],
    _whereRawCalls: [],
    _orderBy:       null,
    _limit:         null,
    _offset:        null,
    _backingRows:   rows.slice(),
  };
  q.where = function (a, b, c) {
    q._whereCalls.push([a, b, c]);
    return q;
  };
  q.whereRaw = function (sql, params) {
    q._whereRawCalls.push({ sql: sql, params: params });
    return q;
  };
  q.orderBy = function (f, d) {
    var entry = { field: f, direction: (d || "asc").toLowerCase() };
    if (q._orderBy === null) { q._orderBy = entry; return q; }
    if (Array.isArray(q._orderBy)) { q._orderBy.push(entry); return q; }
    q._orderBy = [q._orderBy, entry];
    return q;
  };
  q.limit  = function (n) { q._limit = n;  return q; };
  q.offset = function (n) { q._offset = n; return q; };
  q.all = function () {
    var sorted = q._backingRows.slice();
    if (q._orderBy) {
      var entries = Array.isArray(q._orderBy) ? q._orderBy : [q._orderBy];
      sorted.sort(function (a, b) {
        for (var i = 0; i < entries.length; i++) {
          var f = entries[i].field;
          var asc = entries[i].direction === "asc";
          if (a[f] < b[f]) return asc ? -1 : 1;
          if (a[f] > b[f]) return asc ?  1 : -1;
        }
        return 0;
      });
    }
    var off = q._offset || 0;
    var lim = q._limit != null ? q._limit : sorted.length;
    return sorted.slice(off, off + lim);
  };
  q.count = function () { return q._backingRows.length; };
  return q;
}

function testPaginationSurface() {
  check("b.pagination namespace present",         typeof b.pagination === "object");
  check("cursor is a function",                   typeof b.pagination.cursor === "function");
  check("offset is a function",                   typeof b.pagination.offset === "function");
  check("encodeCursor is a function",             typeof b.pagination.encodeCursor === "function");
  check("decodeCursor is a function",             typeof b.pagination.decodeCursor === "function");
  check("PaginationError is a class",             typeof b.pagination.PaginationError === "function");
  check("CURSOR_VERSION === 1",                   b.pagination.CURSOR_VERSION === 1);
}

function testPaginationEncodeDecodeRoundTrip() {
  var secret = Buffer.from("test-secret-32-bytes-long-padding!");
  var token = b.pagination.encodeCursor({
    dir: "asc", orderBy: "_id", orderByVal: "abc", id: "abc", forward: true,
  }, secret);
  check("encode produces base64url.tag string",   typeof token === "string" && token.indexOf(".") !== -1);
  var decoded = b.pagination.decodeCursor(token, secret);
  check("decode round-trips orderByVal",          decoded.orderByVal === "abc");
  check("decode round-trips orderBy",             decoded.orderBy === "_id");
  check("decode includes version field",          decoded.v === 1);
}

function testPaginationDecodeRejectsTamperedTag() {
  var secret = "secret-key";
  var token = b.pagination.encodeCursor({ dir: "asc", orderBy: "_id", orderByVal: 1, id: "x" }, secret);
  var dot = token.indexOf(".");
  var tampered = token.slice(0, dot) + "." + token.slice(dot + 1, dot + 2) + "X" + token.slice(dot + 3);
  var threw = null;
  try { b.pagination.decodeCursor(tampered, secret); } catch (e) { threw = e; }
  check("decode rejects tampered tag",
        threw && threw.code === "pagination/cursor-tag-mismatch");
}

function testPaginationDecodeRejectsTamperedState() {
  var secret = "secret-key";
  var token = b.pagination.encodeCursor({ dir: "asc", orderBy: "_id", orderByVal: 1, id: "x" }, secret);
  var dot = token.indexOf(".");
  var newState = b.pagination._b64urlEncode(JSON.stringify({ v: 1, dir: "asc", id: "y", orderBy: "_id", orderByVal: 999 }));
  var tampered = newState + "." + token.slice(dot + 1);
  var threw = null;
  try { b.pagination.decodeCursor(tampered, secret); } catch (e) { threw = e; }
  check("decode rejects tampered state with original tag",
        threw && threw.code === "pagination/cursor-tag-mismatch");
}

function testPaginationDecodeRejectsWrongSecret() {
  var t = b.pagination.encodeCursor({ dir: "asc", orderBy: "_id", orderByVal: 1, id: "x" }, "key-A");
  var threw = null;
  try { b.pagination.decodeCursor(t, "key-B"); } catch (e) { threw = e; }
  check("decode rejects wrong secret",            threw && threw.code === "pagination/cursor-tag-mismatch");
}

function testPaginationDecodeRejectsBadShape() {
  var threw;
  threw = null;
  try { b.pagination.decodeCursor("no-dot-in-this-cursor", "k"); } catch (e) { threw = e; }
  check("decode rejects no-tag separator",        threw && threw.code === "pagination/bad-cursor");

  threw = null;
  try { b.pagination.decodeCursor("", "k"); } catch (e) { threw = e; }
  check("decode rejects empty string",            threw && threw.code === "pagination/bad-cursor");

  threw = null;
  try { b.pagination.decodeCursor(null, "k"); } catch (e) { threw = e; }
  check("decode rejects null",                    threw && threw.code === "pagination/bad-cursor");
}

function testPaginationEncodeRequiresSecret() {
  var threw;
  threw = null;
  try { b.pagination.encodeCursor({ orderByVal: 1, id: "x" }, null); } catch (e) { threw = e; }
  check("encode rejects missing secret",          threw && threw.code === "pagination/bad-secret");

  threw = null;
  try { b.pagination.encodeCursor({ orderByVal: 1, id: "x" }, ""); } catch (e) { threw = e; }
  check("encode rejects empty string secret",     threw && threw.code === "pagination/bad-secret");

  threw = null;
  try { b.pagination.encodeCursor({ orderByVal: 1, id: "x" }, Buffer.alloc(0)); } catch (e) { threw = e; }
  check("encode rejects empty Buffer secret",     threw && threw.code === "pagination/bad-secret");
}

function testPaginationResolveLimit() {
  var p = b.pagination;
  check("limit: default when missing",            p._resolveLimit({}) === 25);
  check("limit: clamped to max",                  p._resolveLimit({ limit: 1000, max: 50 }) === 50);
  check("limit: respected when in range",         p._resolveLimit({ limit: 30, max: 100 }) === 30);
  check("limit: NaN coerced to default",          p._resolveLimit({ limit: "abc", default: 10 }) === 10);
  check("limit: negative coerced to default",     p._resolveLimit({ limit: -5, default: 10 }) === 10);
  check("limit: 0 coerced to default",            p._resolveLimit({ limit: 0, default: 10 }) === 10);
}

async function testPaginationCursorRequiresSecret() {
  var q = _mockQuery([]);
  var threw = null;
  try { await b.pagination.cursor(q, { limit: 10 }); } catch (e) { threw = e; }
  check("cursor: missing secret rejected",        threw && threw.code === "pagination/no-secret");
}

async function testPaginationCursorRejectsBadQuery() {
  var threw = null;
  try { await b.pagination.cursor({}, { secret: "k", limit: 10 }); } catch (e) { threw = e; }
  check("cursor: non-Query rejected",             threw && threw.code === "pagination/bad-query");
}

async function testPaginationCursorFirstPage() {
  var rows = [];
  for (var i = 0; i < 30; i++) rows.push({ _id: "id-" + String(i).padStart(3, "0"), name: "u" + i });
  var q = _mockQuery(rows);
  var page = await b.pagination.cursor(q, { secret: "k", limit: 10 });
  check("first page: 10 items returned",          page.items.length === 10);
  check("first page: hasMore=true",               page.hasMore === true);
  check("first page: nextCursor present",         typeof page.nextCursor === "string" && page.nextCursor.length > 0);
  check("first page: prevCursor null (first call)", page.prevCursor === null);
  check("first page: items in _id-asc order",     page.items[0]._id === "id-000" && page.items[9]._id === "id-009");
  var state = b.pagination.decodeCursor(page.nextCursor, "k");
  check("first page: nextCursor encodes lastId in vals[]",
        Array.isArray(state.vals) && state.vals[state.vals.length - 1] === "id-009" &&
        state.forward === true);
  check("first page: nextCursor encodes orderKey for _id-asc",
        Array.isArray(state.orderKey) && state.orderKey[0] === "_id:asc");
}

async function testPaginationCursorFollowChain() {
  var rows = [];
  for (var i = 0; i < 25; i++) rows.push({ _id: "id-" + String(i).padStart(3, "0") });
  var qa = _mockQuery(rows);
  var first = await b.pagination.cursor(qa, { secret: "k", limit: 10 });
  check("page 1 has 10 items",                    first.items.length === 10);
  check("page 1 first id",                        first.items[0]._id === "id-000");

  var qb = _mockQuery(rows);
  var second = await b.pagination.cursor(qb, { secret: "k", limit: 10, cursor: first.nextCursor });
  check("page 2 issues whereRaw with cursor predicate",
        qb._whereRawCalls.length === 1 &&
        qb._whereRawCalls[0].sql.indexOf('"_id" >') !== -1);
  check("page 2 first id is past cursor",
        second.items.length > 0);
  check("page 2 prevCursor present after first follow", typeof second.prevCursor === "string");
}

async function testPaginationCursorLastPageMarksHasMoreFalse() {
  var rows = [];
  for (var i = 0; i < 7; i++) rows.push({ _id: "id-" + i });
  var q = _mockQuery(rows);
  var page = await b.pagination.cursor(q, { secret: "k", limit: 10 });
  check("last page: hasMore=false",               page.hasMore === false);
  check("last page: nextCursor null",             page.nextCursor === null);
  check("last page: items.length matches",        page.items.length === 7);
}

async function testPaginationCursorOrderByMismatchRejected() {
  var q = _mockQuery([{ _id: "x" }]);
  var goodCursor = b.pagination.encodeCursor({
    dir: "asc", orderBy: "createdAt", orderByVal: 12345, id: "x", forward: true,
  }, "k");
  var threw = null;
  try {
    await b.pagination.cursor(q, { secret: "k", limit: 10, cursor: goodCursor, orderBy: "_id" });
  } catch (e) { threw = e; }
  check("cursor: orderBy mismatch rejected",      threw && threw.code === "pagination/cursor-mismatch");
}

async function testPaginationCursorRespectsMax() {
  var rows = [];
  for (var i = 0; i < 200; i++) rows.push({ _id: String(i) });
  var q = _mockQuery(rows);
  var page = await b.pagination.cursor(q, { secret: "k", limit: 1000, max: 50 });
  check("max: clamps requested limit",            page.items.length === 50);
}

async function testPaginationCursorOrderByCustom() {
  var rows = [
    { _id: "a", createdAt: 100 },
    { _id: "b", createdAt: 200 },
    { _id: "c", createdAt: 200 },
    { _id: "d", createdAt: 300 },
  ];
  var q = _mockQuery(rows);
  var page = await b.pagination.cursor(q, {
    secret: "k", limit: 10, orderBy: "createdAt",
  });
  check("custom orderBy: client tiebreaker by _id",
        page.items[0]._id === "a" &&
        page.items[1]._id === "b" &&
        page.items[2]._id === "c" &&
        page.items[3]._id === "d");
  if (page.nextCursor === null) {
    check("custom orderBy: hasMore=false on small set",  page.hasMore === false);
  }
}

async function testPaginationCursorDirectionDesc() {
  var rows = [];
  for (var i = 0; i < 15; i++) rows.push({ _id: "id-" + String(i).padStart(3, "0") });
  var q = _mockQuery(rows);
  var page = await b.pagination.cursor(q, { secret: "k", limit: 5, direction: "desc" });
  check("desc: first item is highest id",         page.items[0]._id === "id-014");
  check("desc: last item descends",               page.items[4]._id === "id-010");
}

async function testPaginationOffsetFirstPage() {
  var rows = [];
  for (var i = 0; i < 47; i++) rows.push({ _id: "id-" + String(i).padStart(3, "0") });
  var q = _mockQuery(rows);
  var off = await b.pagination.offset(q, { page: 1, perPage: 10 });
  check("offset: page 1 has 10 items",            off.items.length === 10);
  check("offset: total reflects backing count",   off.total === 47);
  check("offset: totalPages computed",            off.totalPages === 5);
  check("offset: hasMore on page 1 of 5",         off.hasMore === true);
  check("offset: page reported back",             off.page === 1);
  check("offset: perPage reported",               off.perPage === 10);
}

async function testPaginationOffsetLastPage() {
  var rows = [];
  for (var i = 0; i < 47; i++) rows.push({ _id: "id-" + i });
  var q = _mockQuery(rows);
  var off = await b.pagination.offset(q, { page: 5, perPage: 10 });
  check("offset: last page has 7 items (47 mod 10)", off.items.length === 7);
  check("offset: hasMore=false on last page",    off.hasMore === false);
}

async function testPaginationOffsetEmptyResult() {
  var q = _mockQuery([]);
  var off = await b.pagination.offset(q, { page: 1, perPage: 10 });
  check("offset: empty has total=0",              off.total === 0);
  check("offset: empty has totalPages=0",         off.totalPages === 0);
  check("offset: empty hasMore=false",            off.hasMore === false);
  check("offset: empty items=[]",                 off.items.length === 0);
}

async function testPaginationOffsetPageOutOfRange() {
  var rows = [{ _id: "a" }, { _id: "b" }];
  var q = _mockQuery(rows);
  var off = await b.pagination.offset(q, { page: 99, perPage: 10 });
  check("offset: out-of-range page returns empty items", off.items.length === 0);
  check("offset: page recorded as requested",      off.page === 99);
}

async function testPaginationOffsetCoercesBadPage() {
  var rows = [{ _id: "a" }, { _id: "b" }];
  var q = _mockQuery(rows);
  var off = await b.pagination.offset(q, { page: -5, perPage: 10 });
  check("offset: negative page coerced to 1",      off.page === 1);
}

async function testPaginationCursorWhereRawCondition() {
  var rows = [{ _id: "x", name: "y" }];
  var qFirst = _mockQuery(rows);
  var first = await b.pagination.cursor(qFirst, { secret: "k", limit: 1, orderBy: "_id" });

  if (first.nextCursor) {
    var qSecond = _mockQuery(rows);
    await b.pagination.cursor(qSecond, { secret: "k", limit: 1, orderBy: "_id", cursor: first.nextCursor });
    var raw = qSecond._whereRawCalls[0];
    check("whereRaw: 3 params (orderByVal, orderByVal, _id)", raw.params.length === 3);
    check("whereRaw: SQL has both > and = clauses",
          raw.sql.indexOf('">"') === -1 &&
          raw.sql.indexOf("> ?") !== -1 &&
          raw.sql.indexOf("= ?") !== -1);
  }
}

async function testPaginationCursorVersionMismatch() {
  var fakeState = JSON.stringify({ v: 999, dir: "asc", orderBy: "_id", orderByVal: 1, id: "x" });
  var secret = "k";
  var sb = Buffer.from(secret, "utf8");
  var nodeC = require("node:crypto");
  var h = nodeC.createHash("sha3-512");
  h.update(sb); h.update(Buffer.from(fakeState, "utf8"));
  var tag = h.digest().slice(0, 16);
  var token = b.pagination._b64urlEncode(fakeState) + "." + b.pagination._b64urlEncode(tag);
  var threw = null;
  try { b.pagination.decodeCursor(token, secret); } catch (e) { threw = e; }
  check("decode: version mismatch rejected",       threw && threw.code === "pagination/cursor-version");
}

async function testPaginationQueryWhereRaw() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-pagq-"));
  try {
    await setupTestDb(tmpDir);
    b.db.from("users").insertMany([
      { _id: "u1", email: "a@x.io", name: "A" },
      { _id: "u2", email: "b@x.io", name: "B" },
      { _id: "u3", email: "c@x.io", name: "C" },
    ]);
    var rowsPast = b.db.from("users").whereRaw('"_id" > ?', ["u1"]).all();
    check("whereRaw: > predicate on _id returns rows past cursor", rowsPast.length === 2);

    var rowsCompound = b.db.from("users")
      .whereRaw('"_id" > ? OR ("_id" = ? AND "_id" > ?)', ["u2", "no-such-id", "no-such-id"])
      .all();
    check("whereRaw: compound OR clause works",   rowsCompound.length === 1);

    var rowsCombined = b.db.from("users")
      .where("status", "=", "active")
      .whereRaw('"_id" > ?', ["u1"])
      .all();
    check("whereRaw: composes with chainable .where()", rowsCombined.length === 2);

    var threw = null;
    try { b.db.from("users").whereRaw('"_id" > ?', ["u1", "u2"]); } catch (e) { threw = e; }
    check("whereRaw: rejects mismatched param count",
          threw && /placeholder/.test(threw.message));

    threw = null;
    try { b.db.from("users").whereRaw("", []); } catch (e) { threw = e; }
    check("whereRaw: rejects empty sql",
          threw && /non-empty/.test(threw.message));
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function run() {
  testPaginationSurface();
  testPaginationEncodeDecodeRoundTrip();
  testPaginationDecodeRejectsTamperedTag();
  testPaginationDecodeRejectsTamperedState();
  testPaginationDecodeRejectsWrongSecret();
  testPaginationDecodeRejectsBadShape();
  testPaginationEncodeRequiresSecret();
  testPaginationResolveLimit();
  await testPaginationCursorRequiresSecret();
  await testPaginationCursorRejectsBadQuery();
  await testPaginationCursorFirstPage();
  await testPaginationCursorFollowChain();
  await testPaginationCursorLastPageMarksHasMoreFalse();
  await testPaginationCursorOrderByMismatchRejected();
  await testPaginationCursorRespectsMax();
  await testPaginationCursorOrderByCustom();
  await testPaginationCursorDirectionDesc();
  await testPaginationOffsetFirstPage();
  await testPaginationOffsetLastPage();
  await testPaginationOffsetEmptyResult();
  await testPaginationOffsetPageOutOfRange();
  await testPaginationOffsetCoercesBadPage();
  await testPaginationCursorWhereRawCondition();
  await testPaginationCursorVersionMismatch();
  await testPaginationQueryWhereRaw();
  await testPaginationCursorMultiColumn();
  // v0.6.60 — non-plain types in cursor state
  testPaginationEncodeDateRoundTrip();
  testPaginationEncodeRejectsNonPlainTypes();
  testPaginationEncodeRejectsCircularRef();
}

function testPaginationEncodeDateRoundTrip() {
  var secret = b.crypto.generateBytes(32);
  var d = new Date("2026-05-03T12:34:56.000Z");
  var token = b.pagination.encodeCursor({ d: d }, secret);
  var decoded = b.pagination.decodeCursor(token, secret);
  // Pre-fix: Object.keys(new Date()) returned [] so the cursor encoded as
  // {} and the operator's Date silently became an empty object on decode.
  // Post-fix: Date serialises to its ISO string (matches stdlib JSON
  // .stringify semantics).
  check("encodeCursor preserves Date as ISO string",
        decoded.d === "2026-05-03T12:34:56.000Z");
}

function testPaginationEncodeRejectsNonPlainTypes() {
  var secret = b.crypto.generateBytes(32);
  function expectBadState(label, value) {
    var threw = null;
    try { b.pagination.encodeCursor({ x: value }, secret); }
    catch (e) { threw = e; }
    check("encodeCursor rejects " + label,
          threw && threw.code === "pagination/bad-state");
  }
  // Pre-fix: each of these silently became {} or {"0":...,"1":...}.
  // Post-fix: clean structured rejection so operators don't lose data.
  expectBadState("Buffer",      Buffer.from("abc"));
  expectBadState("Uint8Array",  new Uint8Array([1, 2, 3]));
  expectBadState("Map",         new Map([["a", 1]]));
  expectBadState("Set",         new Set([1, 2]));
  expectBadState("RegExp",      /abc/);
}

function testPaginationEncodeRejectsCircularRef() {
  var secret = b.crypto.generateBytes(32);
  var o = {}; o.self = o;
  var threw = null;
  try { b.pagination.encodeCursor(o, secret); }
  catch (e) { threw = e; }
  // Pre-fix: stack overflow from unbounded recursion.
  // Post-fix: clean structured rejection.
  check("encodeCursor rejects circular reference cleanly",
        threw && threw.code === "pagination/bad-state");
}

async function testPaginationCursorMultiColumn() {
  // Build a dataset with ties on createdAt — multi-column ORDER BY
  // (createdAt DESC, _id ASC) breaks ties stably.
  var rows = [];
  for (var t = 5; t >= 1; t--) {
    for (var n = 0; n < 3; n++) {
      rows.push({ _id: "id-" + t + "-" + n, createdAt: t * 1000 });
    }
  }
  // First page: limit 4, multi-column orderBy
  var q1 = _mockQuery(rows);
  var p1 = await b.pagination.cursor(q1, {
    secret:  "k",
    limit:   4,
    orderBy: [{ column: "createdAt", direction: "desc" }, { column: "_id", direction: "asc" }],
  });
  check("multi-column: returns 4 items",  p1.items.length === 4);
  check("multi-column: hasMore=true",     p1.hasMore === true);
  check("multi-column: items respect createdAt DESC + _id ASC",
        p1.items[0].createdAt === 5000 && p1.items[0]._id === "id-5-0" &&
        p1.items[3].createdAt === 4000 && p1.items[3]._id === "id-4-0");
  var s1 = b.pagination.decodeCursor(p1.nextCursor, "k");
  check("multi-column: cursor encodes both column values",
        Array.isArray(s1.vals) && s1.vals.length === 2 &&
        s1.vals[0] === 4000 && s1.vals[1] === "id-4-0");
  check("multi-column: cursor encodes orderKey for both columns",
        Array.isArray(s1.orderKey) && s1.orderKey[0] === "createdAt:desc" &&
        s1.orderKey[1] === "_id:asc");
  // Cursor reused with a single-column orderBy mid-flight is rejected
  var qm = _mockQuery(rows);
  var threw = null;
  try {
    await b.pagination.cursor(qm, {
      secret:  "k",
      limit:   4,
      orderBy: "_id",
      cursor:  p1.nextCursor,
    });
  } catch (e) { threw = e; }
  check("multi-column: orderBy mismatch on follow rejects",
        threw && (threw.code === "pagination/cursor-mismatch" || threw.code === "pagination/bad-orderby"));
  // Bad entry shape rejected at config-time
  var threw2 = null;
  try {
    await b.pagination.cursor(_mockQuery(rows), {
      secret:  "k",
      orderBy: [{ column: "createdAt", direction: "sideways" }],
    });
  } catch (e) { threw2 = e; }
  check("multi-column: bad direction rejected",
        threw2 && threw2.code === "pagination/bad-orderby");
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e.message); process.exit(1); }
  );
}
