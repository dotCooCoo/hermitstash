"use strict";
/**
 * @module b.pagination
 * @nav    Tools
 * @title  Pagination
 *
 * @intro
 *   Cursor-based pagination — opaque tokens that encode the last-row
 *   sort key + direction, resilient to inserts and deletes between
 *   pages.
 *
 *   Every CRUD list endpoint reinvents pagination, usually wrong. The
 *   two failure modes: offset pagination at depth (`LIMIT n OFFSET
 *   50000` scan-and-skips 50,000 rows; concurrent writes shift the
 *   offset and rows get missed or duplicated), and cursor pagination
 *   without a tie-breaker (`WHERE createdAt > ?` skips or duplicates
 *   rows when two records share `createdAt`).
 *
 *   This module ships both done correctly. `cursor()` uses composite
 *   `(orderBy, _id)` ordering — `_id` is the implicit tie-breaker, so
 *   two rows with identical `orderByVal` are still totally ordered.
 *   Forward navigation: `WHERE (orderByVal > ?) OR (orderByVal = ? AND
 *   _id > ?)`. Backward: same with `<`, then reverse the result set.
 *
 *   Cursors are HMAC-tagged with operator-supplied `secret`. A tampered
 *   cursor is detected at decode time and rejected with
 *   `PaginationError`. Cursor format: `<base64url state>.<base64url
 *   tag>`, state is canonical JSON of `{ v, orderKey, vals, forward }`,
 *   tag is `SHA3-512(secret || stateJson).slice(0, 16)`. Direction is
 *   part of the cursor — operators don't round-trip it via query
 *   string. Multi-column ordering accepted: a string, an array of
 *   strings, or `[{ column, direction }, ...]`; `_id` is appended as a
 *   tiebreaker if not already in the chain.
 *
 *   `offset()` is the legacy-client tool, not the recommended path.
 *   It returns `total` (from `COUNT(*)`) and computes `totalPages` so
 *   legacy clients can render numbered nav.
 *
 *   Cursor TTL / expiry is operator-side: embed a timestamp in your own
 *   state and check at decode-time before passing to `.cursor()`. The
 *   framework's HMAC tag carries no notion of time. Search / filter
 *   integration composes — chain `.where()` on the Query before handing
 *   to `.cursor()`.
 *
 * @card
 *   Cursor-based pagination — opaque tokens that encode the last-row sort key + direction, resilient to inserts and deletes between pages.
 */

var nodeCrypto = require("node:crypto");
var C = require("./constants");
var canonicalJson = require("./canonical-json");
var bCrypto = require("./crypto");
var validateOpts = require("./validate-opts");
var numericBounds = require("./numeric-bounds");
var safeJson = require("./safe-json");
var safeSql = require("./safe-sql");
var { defineClass } = require("./framework-error");

var PaginationError = defineClass("PaginationError", { alwaysPermanent: true });

var CURSOR_VERSION = 1;
var TAG_BYTES = C.BYTES.bytes(16);  // 128-bit HMAC tag truncated from SHA3-512
var DEFAULT_LIMIT = 25;
var DEFAULT_MAX_LIMIT = 100;
var MAX_CURSOR_BYTES = C.BYTES.kib(8);

// Canonical JSON via the shared lib/canonical-json walker with
// bufferAs: "reject" — cursor state must contain only plain data, so
// Buffer / Uint8Array reject loudly. Map / Set / RegExp / Symbol /
// function / circular always reject; Date → ISO; BigInt → decimal
// string. Wraps the walker's generic Error in a PaginationError so
// callers can route on `pagination/bad-state`.
function _canonicalize(value) {
  try { return canonicalJson.stringify(value, { bufferAs: "reject" }); }
  catch (e) {
    throw new PaginationError("pagination/bad-state", e.message);
  }
}

function _toBuf(secret) {
  if (Buffer.isBuffer(secret)) return secret;
  if (typeof secret === "string") return Buffer.from(secret, "utf8");
  throw new PaginationError("pagination/bad-secret",
    "secret must be a Buffer or non-empty string");
}

function _b64urlEncode(buf) { return bCrypto.toBase64Url(buf); }

var _b64urlDecode = bCrypto.makeBase64UrlDecoder({
  errorClass:  PaginationError,
  code:        "pagination/bad-cursor",
  typeMessage: "cursor must be a string",
  badMessage:  "cursor is not valid base64url",
});

function _tag(secretBuf, stateJson) {
  var h = nodeCrypto.createHash("sha3-512");
  h.update(secretBuf);
  h.update(Buffer.from(stateJson, "utf8"));
  return h.digest().slice(0, TAG_BYTES);
}

/**
 * @primitive b.pagination.encodeCursor
 * @signature b.pagination.encodeCursor(state, secret)
 * @since     0.6.20
 * @related   b.pagination.decodeCursor, b.pagination.cursor
 *
 * Low-level cursor encoder for raw-SQL or custom row-source paths.
 * Wraps `state` with the framework version field, canonicalises via
 * the shared canonical-JSON walker, then computes the SHA3-512 HMAC
 * tag and emits `<base64url(stateJson)>.<base64url(tag)>`. State is
 * any plain-data object — `Buffer` / `Map` / `Set` / `RegExp` /
 * functions / circular references are rejected loudly. `secret` is a
 * `Buffer` or non-empty string; an empty secret throws.
 *
 * @example
 *   var token = b.pagination.encodeCursor(
 *     { orderKey: ["createdAt:asc", "_id:asc"], vals: [1700000000000, "u-42"], forward: true },
 *     "page-secret"
 *   );
 *   // token is `<base64url state>.<base64url tag>`, ready to round-trip via query string.
 *   var state = b.pagination.decodeCursor(token, "page-secret");
 *   state.forward;   // → true
 */
function encodeCursor(state, secret) {
  if (!state || typeof state !== "object") {
    throw new PaginationError("pagination/bad-state",
      "encodeCursor: state must be an object");
  }
  var sb = _toBuf(secret);
  if (sb.length === 0) {
    throw new PaginationError("pagination/bad-secret", "secret must be non-empty");
  }
  var withMeta = Object.assign({ v: CURSOR_VERSION }, state);
  var json = _canonicalize(withMeta);
  var tag  = _tag(sb, json);
  return _b64urlEncode(json) + "." + _b64urlEncode(tag);
}

/**
 * @primitive b.pagination.decodeCursor
 * @signature b.pagination.decodeCursor(token, secret)
 * @since     0.6.20
 * @related   b.pagination.encodeCursor, b.pagination.cursor
 *
 * Inverse of `encodeCursor`. Splits on the `.` separator, base64url-
 * decodes both halves, recomputes the HMAC tag against `secret` and
 * compares with `b.crypto.timingSafeEqual`. On mismatch (tamper or
 * wrong secret) throws `PaginationError("pagination/cursor-tag-
 * mismatch")`. State JSON is parsed via `b.safeJson.parse` with a
 * 8-KiB byte cap. The framework version field (`v`) must match the
 * current `CURSOR_VERSION`; older cursors throw `pagination/cursor-
 * version` so operators can detect rolling-deploy mismatches.
 *
 * @example
 *   try {
 *     var state = b.pagination.decodeCursor(req.query.cursor, "page-secret");
 *     state.vals;       // → [1700000000000, "u-42"]
 *     state.forward;    // → true
 *   } catch (e) {
 *     // PaginationError — tamper, wrong secret, or stale cursor version.
 *     res.statusCode = 400;
 *     res.end("invalid cursor");
 *   }
 */
function decodeCursor(token, secret) {
  if (typeof token !== "string" || token.length === 0) {
    throw new PaginationError("pagination/bad-cursor", "cursor must be a non-empty string");
  }
  var dot = token.indexOf(".");
  if (dot === -1) {
    throw new PaginationError("pagination/bad-cursor", "cursor missing tag separator");
  }
  var sb = _toBuf(secret);
  var jsonPart = token.slice(0, dot);
  var tagPart  = token.slice(dot + 1);
  var json, tag;
  try {
    json = _b64urlDecode(jsonPart).toString("utf8");
    tag  = _b64urlDecode(tagPart);
  } catch (_e) {
    throw new PaginationError("pagination/bad-cursor", "cursor base64 decode failed");
  }
  var expected = _tag(sb, json);
  if (!bCrypto.timingSafeEqual(tag, expected)) {
    throw new PaginationError("pagination/cursor-tag-mismatch",
      "cursor HMAC verification failed (tampered or wrong secret)");
  }
  var state;
  try { state = safeJson.parse(json, { maxBytes: MAX_CURSOR_BYTES }); }
  catch (_e) {
    throw new PaginationError("pagination/bad-cursor", "cursor state JSON malformed");
  }
  if (!state || typeof state !== "object") {
    throw new PaginationError("pagination/bad-cursor", "cursor state is not an object");
  }
  if (state.v !== CURSOR_VERSION) {
    throw new PaginationError("pagination/cursor-version",
      "cursor version " + state.v + " unsupported (current: " + CURSOR_VERSION + ")");
  }
  return state;
}

function _resolveLimit(opts) {
  numericBounds.requirePositiveFiniteIntIfPresent(opts.max,
    "max", PaginationError, "pagination/bad-opt");
  numericBounds.requirePositiveFiniteIntIfPresent(opts.default,
    "default", PaginationError, "pagination/bad-opt");
  var max = opts.max || DEFAULT_MAX_LIMIT;
  var def = opts.default || DEFAULT_LIMIT;
  var requested = parseInt(opts.limit, 10);
  if (isNaN(requested) || requested < 1) requested = def;
  if (requested > max) requested = max;
  return requested;
}

// ---- Cursor pagination ----

// Normalize opts.orderBy into an array of { column, direction } entries.
// Accepts:
//   undefined / null            → [{ column: "_id", direction: opts.direction || "asc" }]
//   "createdAt"                 → [{ column: "createdAt", direction: opts.direction || "asc" }]
//   ["createdAt", "_id"]        → all entries default to opts.direction || "asc"
//   [{column:"a",direction:"desc"}, {column:"b"}]
//                               → mixed; missing direction defaults to opts.direction || "asc"
// Always appends an _id tiebreaker if not present, so cursor uniqueness
// is guaranteed regardless of the operator's spec.
function _normalizeOrderBy(opts) {
  var defaultDir = (opts && opts.direction === "desc") ? "desc" : "asc";
  var raw = opts && opts.orderBy;
  var entries;
  if (raw == null) {
    entries = [{ column: "_id", direction: defaultDir }];
  } else if (typeof raw === "string") {
    entries = [{ column: raw, direction: defaultDir }];
  } else if (Array.isArray(raw)) {
    entries = raw.map(function (e) {
      if (typeof e === "string") return { column: e, direction: defaultDir };
      if (!e || typeof e !== "object" || typeof e.column !== "string") {
        throw new PaginationError("pagination/bad-orderby",
          "orderBy[] entries must be strings or { column, direction } objects, got " +
          JSON.stringify(e));
      }
      var d = (e.direction || defaultDir).toLowerCase();
      if (d !== "asc" && d !== "desc") {
        throw new PaginationError("pagination/bad-orderby",
          "orderBy[].direction must be 'asc' | 'desc', got " + JSON.stringify(e.direction));
      }
      return { column: e.column, direction: d };
    });
  } else {
    throw new PaginationError("pagination/bad-orderby",
      "orderBy must be a string, array, or omitted; got " + typeof raw);
  }
  for (var i = 0; i < entries.length; i++) {
    if (typeof entries[i].column !== "string" ||
        entries[i].column.length === 0 ||
        entries[i].column.length > safeSql.MAX_IDENTIFIER_LENGTH ||
        !safeSql.DEFAULT_IDENTIFIER_RE.test(entries[i].column)) {
      throw new PaginationError("pagination/bad-orderby",
        "orderBy column must match " + safeSql.DEFAULT_IDENTIFIER_RE +
        " and be 1.." + safeSql.MAX_IDENTIFIER_LENGTH + " chars, got " +
        JSON.stringify(entries[i].column));
    }
  }
  // Append _id tiebreaker if not already in the chain. Direction
  // matches the chain's last entry by convention so the tiebreaker
  // doesn't reverse the natural reading order.
  var hasId = entries.some(function (e) { return e.column === "_id"; });
  if (!hasId) {
    entries.push({ column: "_id", direction: entries[entries.length - 1].direction });
  }
  return entries;
}

// Build the keyset WHERE clause for next-page navigation given the
// cursor's column values. Each (col, dir) entry expands the OR cascade:
//   col0 [op0] ? OR (col0 = ? AND col1 [op1] ?) OR ... OR (col0 = ? AND ... AND coln [opn] ?)
// The compareOp per column flips by direction × forward (XNOR).
function _buildKeysetWhere(orderEntries, cursorVals, forward) {
  var clauses = [];
  var params = [];
  for (var i = 0; i < orderEntries.length; i++) {
    var entry = orderEntries[i];
    // Effective direction: asc + forward → ">", desc + forward → "<", and reversed for backward.
    var effectiveAsc = (entry.direction === "asc") === forward;
    var op = effectiveAsc ? ">" : "<";
    var equalChain = [];
    for (var j = 0; j < i; j++) {
      equalChain.push('"' + orderEntries[j].column + '" = ?');
      params.push(cursorVals[j]);
    }
    equalChain.push('"' + entry.column + '" ' + op + ' ?');
    params.push(cursorVals[i]);
    clauses.push("(" + equalChain.join(" AND ") + ")");
  }
  return { sql: clauses.join(" OR "), params: params };
}

/**
 * @primitive b.pagination.cursor
 * @signature b.pagination.cursor(query, opts)
 * @since     0.6.20
 * @related   b.pagination.offset, b.pagination.encodeCursor
 *
 * Cursor pagination over a `b.db.from(...)` Query. O(1) at any depth.
 * Builds the keyset `WHERE` from the previous page's column values,
 * applies the operator's `orderBy` chain (with `_id` appended as
 * tiebreaker), fetches `limit + 1` rows to detect `hasMore` without a
 * second `COUNT(*)`, and returns `{ items, nextCursor, prevCursor,
 * limit, hasMore }`. Cursors round-trip via opaque base64url strings
 * — operators don't pick apart the encoded state.
 *
 * Operators MUST pass `opts.secret` (Buffer or non-empty string) for
 * HMAC tagging. There's no auto-derivation — framework-derived
 * secrets would surprise across deploys.
 *
 * @opts
 *   cursor:    string,                    // opaque token from a previous response (omit for first page)
 *   limit:     number,                    // requested page size; clamped to opts.max, defaults to opts.default
 *   max:       number,                    // hard cap on limit (defaults to 100)
 *   default:   number,                    // limit when none requested (defaults to 25)
 *   orderBy:   string|array,              // column name, ["a","b"], or [{column,direction}]
 *   direction: "asc"|"desc",              // default direction applied to string/array forms
 *   secret:    Buffer|string,             // REQUIRED — HMAC key for cursor tag
 *   forward:   boolean,                   // override cursor's encoded direction (rare)
 *
 * @example
 *   var page = await b.pagination.cursor(b.db.from("users"), {
 *     cursor:    req.query.cursor,
 *     limit:     parseInt(req.query.limit, 10),
 *     max:       100,
 *     default:   25,
 *     orderBy:   "createdAt",
 *     direction: "desc",
 *     secret:    "page-secret",
 *   });
 *   page.items;        // → array of rows (length <= limit)
 *   page.nextCursor;   // → string token, or null when there's no next page
 *   page.hasMore;      // → true when more rows exist beyond this page
 *
 *   // Multi-column ordering with mixed directions:
 *   var mixed = await b.pagination.cursor(b.db.from("orders"), {
 *     orderBy: [{ column: "priority", direction: "desc" }, { column: "createdAt", direction: "asc" }],
 *     secret:  "page-secret",
 *   });
 */
async function cursor(query, opts) {
  validateOpts.requireMethods(query, ["where", "orderBy", "limit", "all"],
    "cursor: first arg (db Query)", PaginationError, "pagination/bad-query");
  opts = opts || {};
  if (opts.secret == null) {
    throw new PaginationError("pagination/no-secret",
      "cursor: opts.secret is required (Buffer or non-empty string for HMAC tagging)");
  }
  var limit = _resolveLimit(opts);
  var orderEntries = _normalizeOrderBy(opts);
  // Cursor compatibility key: array of `column:direction` pairs canonicalizes
  // the orderBy spec so a stored cursor must match exactly to be replayed.
  var orderKey = orderEntries.map(function (e) { return e.column + ":" + e.direction; });

  var cursorState = null;
  var forward = (opts.forward !== false);
  if (opts.cursor) {
    cursorState = decodeCursor(opts.cursor, opts.secret);
    var cursorKey = Array.isArray(cursorState.orderKey) ? cursorState.orderKey :
      // Back-compat with v0.6.20 single-column cursors: synthesize the
      // key from the legacy orderBy/dir fields.
      [cursorState.orderBy + ":" + cursorState.dir];
    if (JSON.stringify(cursorKey) !== JSON.stringify(orderKey)) {
      throw new PaginationError("pagination/cursor-mismatch",
        "cursor orderKey [" + cursorKey.join(", ") + "] does not match call orderKey [" +
        orderKey.join(", ") + "] — operator must use the same orderBy/direction spec");
    }
    if (typeof cursorState.forward === "boolean") forward = cursorState.forward;
  }

  // Apply the keyset WHERE if a cursor is present.
  if (cursorState) {
    var cursorVals;
    if (Array.isArray(cursorState.vals)) {
      cursorVals = cursorState.vals;
    } else {
      // v0.6.20 single-column shape — synthesize the vals array.
      cursorVals = [cursorState.orderByVal, cursorState.id];
      // Drop the synthetic _id append if the legacy cursor already had it
      if (orderEntries.length === 1) cursorVals = [cursorState.orderByVal];
    }
    if (cursorVals.length !== orderEntries.length) {
      throw new PaginationError("pagination/cursor-mismatch",
        "cursor encoded " + cursorVals.length + " column value(s) but orderBy has " +
        orderEntries.length + " — operator changed the orderBy spec mid-flight");
    }
    var where = _buildKeysetWhere(orderEntries, cursorVals, forward);
    query.whereRaw(where.sql, where.params);
  }

  // Apply ORDER BY for each entry. When forward=false we reverse direction
  // per entry so the SQL returns rows in the right reading order; we then
  // reverse client-side at the end.
  for (var oi = 0; oi < orderEntries.length; oi++) {
    var entry = orderEntries[oi];
    var effectiveDir = ((entry.direction === "asc") === forward) ? "asc" : "desc";
    query.orderBy(entry.column, effectiveDir);
  }
  query.limit(limit + 1);

  var rows = await Promise.resolve(query.all());

  var hasMore = rows.length > limit;
  var page = hasMore ? rows.slice(0, limit) : rows.slice();
  if (!forward) page.reverse();

  function _valsForRow(row) {
    return orderEntries.map(function (e) {
      return e.column === "_id" ? String(row._id) : row[e.column];
    });
  }

  var nextCursor = null;
  var prevCursor = null;
  if (hasMore && page.length > 0) {
    var last = page[page.length - 1];
    nextCursor = encodeCursor({
      orderKey: orderKey,
      vals:     _valsForRow(last),
      forward:  true,
    }, opts.secret);
  }
  if (cursorState && page.length > 0) {
    var first = page[0];
    prevCursor = encodeCursor({
      orderKey: orderKey,
      vals:     _valsForRow(first),
      forward:  false,
    }, opts.secret);
  }

  return {
    items:      page,
    nextCursor: nextCursor,
    prevCursor: prevCursor,
    limit:      limit,
    hasMore:    hasMore,
  };
}

// ---- Offset pagination ----

/**
 * @primitive b.pagination.offset
 * @signature b.pagination.offset(query, opts)
 * @since     0.6.20
 * @related   b.pagination.cursor
 *
 * Offset pagination — page-numbered, ergonomic for legacy clients
 * that render numbered nav. Issues `COUNT(*)` to compute `total` and
 * `totalPages`. Use `cursor()` for new endpoints; `offset()` is only
 * the right shape when the consumer's UI already binds to page
 * numbers. Re-applies the operator's `where()` chain unmodified, then
 * adds `ORDER BY orderBy direction LIMIT perPage OFFSET (page-1)*perPage`.
 *
 * @opts
 *   page:      number,           // 1-based page number (defaults to 1; non-integer coerces to 1)
 *   perPage:   number,           // rows per page (clamped to opts.max, defaults to opts.default)
 *   max:       number,           // hard cap on perPage (defaults to 100)
 *   default:   number,           // perPage when none requested (defaults to 25)
 *   orderBy:   string,           // column name (defaults to "_id"); identifier-validated against safeSql
 *   direction: "asc"|"desc",     // sort direction (defaults to "asc")
 *
 * @example
 *   var page = await b.pagination.offset(b.db.from("users"), {
 *     page:    parseInt(req.query.page, 10),
 *     perPage: parseInt(req.query.perPage, 10),
 *     max:     100,
 *     default: 25,
 *     orderBy: "createdAt",
 *     direction: "desc",
 *   });
 *   page.total;        // → e.g. 1284
 *   page.totalPages;   // → e.g. 52 (when perPage=25)
 *   page.hasMore;      // → true when page < totalPages
 */
async function offset(query, opts) {
  validateOpts.requireMethods(query, ["limit", "offset", "all", "count"],
    "offset: first arg (db Query)", PaginationError, "pagination/bad-query");
  opts = opts || {};
  var perPage = _resolveLimit({ limit: opts.perPage, max: opts.max, default: opts.default });
  var page = parseInt(opts.page, 10);
  if (isNaN(page) || page < 1) page = 1;
  var orderBy = typeof opts.orderBy === "string" && opts.orderBy.length > 0 ? opts.orderBy : "_id";
  // Same identifier-only check on offset() as cursor() — orderBy passes
  // through to the db Query; throw at call site to prevent SQL injection.
  if (orderBy.length > safeSql.MAX_IDENTIFIER_LENGTH ||
      !safeSql.DEFAULT_IDENTIFIER_RE.test(orderBy)) {
    throw new PaginationError("pagination/bad-orderby",
      "offset: orderBy must match " + safeSql.DEFAULT_IDENTIFIER_RE +
      " and be 1.." + safeSql.MAX_IDENTIFIER_LENGTH + " chars, got " +
      JSON.stringify(orderBy));
  }
  var direction = (opts.direction === "desc") ? "desc" : "asc";

  // Count gives total — required for totalPages calculation. Cheap on
  // an indexed column (which most app tables have via _id).
  var total = await Promise.resolve(query.count());

  // Build the page query — the operator's existing where() chain is
  // already applied; we just add ordering + limit + offset.
  query.orderBy(orderBy, direction);
  query.limit(perPage);
  query.offset((page - 1) * perPage);
  var items = await Promise.resolve(query.all());

  var totalPages = total === 0 ? 0 : Math.ceil(total / perPage);
  var hasMore = page < totalPages;
  return {
    items:      items,
    total:      total,
    page:       page,
    perPage:    perPage,
    totalPages: totalPages,
    hasMore:    hasMore,
  };
}

module.exports = {
  cursor:           cursor,
  offset:           offset,
  encodeCursor:     encodeCursor,
  decodeCursor:     decodeCursor,
  PaginationError:  PaginationError,
  // Internal helpers exposed for tests
  _resolveLimit:    _resolveLimit,
  _b64urlEncode:    _b64urlEncode,
  _b64urlDecode:    _b64urlDecode,
  CURSOR_VERSION:   CURSOR_VERSION,
};
