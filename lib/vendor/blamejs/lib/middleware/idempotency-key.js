"use strict";
/**
 * @module     b.middleware.idempotencyKey
 * @nav        Middleware
 * @title      Idempotency-Key
 * @order      400
 *
 * @intro
 *   draft-ietf-httpapi-idempotency-key middleware — replay-safe POST /
 *   PUT / PATCH / DELETE handling for retry-capable clients. A client
 *   sends `Idempotency-Key: <opaque>` on a mutating request; the
 *   middleware:
 *
 *     1. Looks up the key in the operator-supplied `store`. A hit
 *        replays the cached `{ statusCode, headers, body }` without
 *        invoking the handler (idempotent replay).
 *     2. Compares the inbound request fingerprint (method + path +
 *        body hash) against the cached fingerprint. A mismatch is a
 *        client-side mistake — same key, different request — and
 *        refuses with 422 + RFC 9457 Problem Details
 *        `idempotency/key-reuse-mismatch` per the draft §4.3.
 *     3. On miss, attaches a capture wrapper to `res.end` so the
 *        handler's response is intercepted, persisted, and replayed
 *        on every subsequent retry within `ttlMs`.
 *
 *   `Idempotency-Key` is OPTIONAL — clients that don't send it skip
 *   the cache and the middleware is a no-op. Idempotency is a
 *   client-asserted contract; the server promises "if you send the
 *   same key + same body, you get the same answer." Operators
 *   wanting strict idempotency on a particular route compose with
 *   `requireIdempotencyKey: true` to refuse missing headers with
 *   `400 idempotency/missing-key`.
 *
 *   Store interface is operator-supplied so cluster deployments can
 *   plug their distributed store (Redis, SQLite-cluster, etc.). The
 *   first-party `memoryStore` is included for single-instance
 *   testing — it accepts `{ ttlMs }` and exposes `_resetForTest()`.
 *
 * @card
 *   draft-ietf-httpapi-idempotency-key middleware — replay-safe POST/PUT/PATCH/DELETE handling for retry-capable clients with operator-supplied distributed store.
 */

var nodeCrypto    = require("node:crypto");
var lazyRequire   = require("../lazy-require");
var numericBounds = require("../numeric-bounds");
var safeBuffer    = require("../safe-buffer");
var { defineClass } = require("../framework-error");

var audit          = lazyRequire(function () { return require("../audit"); });
var problemDetails = lazyRequire(function () { return require("../problem-details"); });
var C              = require("../constants");

var IdempotencyError = defineClass("IdempotencyError", { alwaysPermanent: true });

// Default applicable methods per draft-ietf-httpapi-idempotency-key §3:
// GET / HEAD / OPTIONS are inherently idempotent (RFC 9110 §9.2.2) so
// the middleware skips them by default. DELETE is included because
// the draft endorses it as the canonical "idempotent but not safe"
// retry surface.
var DEFAULT_METHODS = Object.freeze(["POST", "PUT", "PATCH", "DELETE"]);

// Idempotency-Key shape per the draft §2 — ASCII printable, no
// control chars, length 1..255 (typical client implementations cap
// at 36 for UUID + a few extra for vendor prefixes; 255 is the
// upper bound that still fits a single HTTP header line).
var KEY_RE = /^[\x21-\x7E]+$/;                                                                     // allow:raw-byte-literal — printable ASCII codepoint range
var KEY_MAX_LEN = 255;                                                                             // allow:raw-byte-literal — draft §2 upper bound

/**
 * @primitive b.middleware.idempotencyKey.memoryStore
 * @signature b.middleware.idempotencyKey.memoryStore(opts?)
 * @since     0.8.84
 * @status    stable
 * @related   b.middleware.idempotencyKey
 *
 * First-party in-memory store for `idempotencyKey` middleware.
 * Single-instance only — cluster deployments compose against a
 * distributed store (Redis / SQLite-cluster) matching the
 * three-method interface: `get(key) → record | null`,
 * `set(key, value, ttlMs)`, `delete(key)`. TTL is enforced lazily
 * at read time; the store's resident size is operator-supplied via
 * `opts.maxEntries` (default 10000) — when the cap is hit, the
 * oldest entry is evicted (FIFO; the recorded request was
 * idempotent anyway so re-running is correct, not just safe).
 *
 * @opts
 *   maxEntries: number, // default 10000 — FIFO eviction on overflow
 *
 * @example
 *   var store = b.middleware.idempotencyKey.memoryStore({ maxEntries: 5000 });
 *   var mw = b.middleware.idempotencyKey({ store: store, ttlMs: C.TIME.hours(24) });
 *   app.use(mw);
 */
function memoryStore(opts) {
  opts = opts || {};
  numericBounds.requirePositiveFiniteIntIfPresent(
    opts.maxEntries, "memoryStore.maxEntries", IdempotencyError, "idempotency/bad-max-entries");
  var maxEntries = opts.maxEntries !== undefined ? opts.maxEntries : 10000;                       // allow:raw-byte-literal — default in-memory cap, not bytes
  var data = new Map();
  return {
    get: function (key) {
      var rec = data.get(key);
      if (!rec) return null;
      if (rec.expiresAt < Date.now()) {
        data.delete(key);
        return null;
      }
      return rec.value;
    },
    set: function (key, value, ttlMs) {
      if (data.size >= maxEntries) {
        var oldest = data.keys().next().value;
        data.delete(oldest);
      }
      data.set(key, { value: value, expiresAt: Date.now() + ttlMs });
    },
    delete: function (key) {
      data.delete(key);
    },
    _resetForTest: function () {
      data.clear();
    },
    _size: function () { return data.size; },
  };
}

function _validateStore(store, where) {
  if (!store || typeof store !== "object") {
    throw new IdempotencyError("idempotency/bad-store",
      where + ": store must be an object", true);
  }
  if (typeof store.get !== "function" ||
      typeof store.set !== "function" ||
      typeof store.delete !== "function") {
    throw new IdempotencyError("idempotency/bad-store",
      where + ": store must implement { get, set, delete }", true);
  }
}

function _fingerprintRequest(req, bodyBytes) {
  // Fingerprint = method + path + body sha3-256. Per the draft §4.3,
  // a key+body mismatch is a client-side mistake; our fingerprint
  // covers method + path so a client reusing a key across different
  // endpoints is also caught. Body hash uses SHA3-256 to match the
  // framework's PQC-first crypto posture (SHA-256 is fine for
  // collision-resistance here but we use SHA3 for codebase
  // uniformity).
  var hash = nodeCrypto.createHash("sha3-256");
  hash.update((req.method || "GET") + "\n");
  hash.update((req.url || "/") + "\n");
  if (bodyBytes && bodyBytes.length > 0) {
    hash.update(bodyBytes);
  }
  return hash.digest("hex");
}

function _emitAudit(action, metadata, outcome) {
  try {
    audit().safeEmit({
      action:   action,
      outcome:  outcome || "success",
      metadata: metadata,
    });
  } catch (_e) { /* best-effort */ }
}

/**
 * @primitive b.middleware.idempotencyKey
 * @signature b.middleware.idempotencyKey(opts)
 * @since     0.8.84
 * @status    stable
 * @related   b.middleware.idempotencyKey.memoryStore, b.problemDetails
 *
 * Build the Idempotency-Key middleware. Returns a connect-style
 * `(req, res, next) => void` handler.
 *
 *   - When `req.method` is not in `opts.methods` (default POST / PUT /
 *     PATCH / DELETE), the middleware is a pass-through.
 *   - When the request lacks an `Idempotency-Key` header and
 *     `opts.requireIdempotencyKey === true`, refuses with HTTP 400 +
 *     `application/problem+json` body
 *     `idempotency/missing-key`.
 *   - When the key is present but malformed (control chars, length
 *     out of range), refuses with HTTP 400 +
 *     `idempotency/bad-key`.
 *   - When the store has a hit AND the cached fingerprint matches the
 *     inbound request fingerprint, replays the cached
 *     `{ statusCode, headers, body }` and DOES NOT call `next()`.
 *   - When the store has a hit AND the fingerprint differs, refuses
 *     with HTTP 422 + `idempotency/key-reuse-mismatch`.
 *   - On a miss, wraps `res.end` to capture the handler's response
 *     and persist `{ fingerprint, statusCode, headers, body }` to
 *     the store with `ttlMs` (default 24h) after the handler
 *     finishes. The wrapper does NOT capture 5xx server-error
 *     responses — replaying a transient infrastructure failure is
 *     not idempotent.
 *
 * Per the draft §4.4, a concurrent-retry from the same client (two
 * requests with the same key arriving in quick succession before
 * the first has written to the store) is allowed to handler-execute
 * twice and either response is acceptable; the framework does not
 * lock the key. Operators wanting strict at-most-once execution
 * implement a distributed-lock layer in their store's `set()`
 * method (the interface is opaque to the middleware).
 *
 * @opts
 *   store:                 object,   // required — get/set/delete interface
 *   ttlMs:                 number,   // default: 24h
 *   methods:               string[], // default: ["POST","PUT","PATCH","DELETE"]
 *   headerName:            string,   // default: "idempotency-key"
 *   requireIdempotencyKey: boolean,  // default: false — refuse missing-key
 *
 * @example
 *   var store = b.middleware.idempotencyKey.memoryStore({ maxEntries: 10000 });
 *   var mw = b.middleware.idempotencyKey({
 *     store:     store,
 *     ttlMs:     C.TIME.hours(24),
 *     methods:   ["POST", "PUT", "PATCH"],
 *   });
 *   app.use(mw);
 */
function create(opts) {
  if (!opts || typeof opts !== "object") {
    throw new IdempotencyError("idempotency/bad-opts",
      "idempotencyKey: opts must be a non-null object", true);
  }
  _validateStore(opts.store, "idempotencyKey");
  numericBounds.requirePositiveFiniteIntIfPresent(
    opts.ttlMs, "idempotencyKey.ttlMs", IdempotencyError, "idempotency/bad-ttl");
  var ttlMs = opts.ttlMs !== undefined ? opts.ttlMs : C.TIME.hours(24);
  var methods = Array.isArray(opts.methods) && opts.methods.length > 0
    ? opts.methods.map(function (m) { return String(m).toUpperCase(); })
    : DEFAULT_METHODS.slice();
  var headerName = typeof opts.headerName === "string" && opts.headerName.length > 0
    ? opts.headerName.toLowerCase()
    : "idempotency-key";
  var requireKey = opts.requireIdempotencyKey === true;

  // Per-response collector cap. Idempotency replay only makes sense
  // for response bodies that fit in memory; the cap is operator-
  // tunable via opts.maxBodyBytes (default 1 MiB).
  numericBounds.requirePositiveFiniteIntIfPresent(
    opts.maxBodyBytes, "idempotencyKey.maxBodyBytes", IdempotencyError, "idempotency/bad-max-body");
  var maxBodyBytes = opts.maxBodyBytes !== undefined ? opts.maxBodyBytes : C.BYTES.mib(1);

  return function idempotencyMiddleware(req, res, next) {
    var method = (req.method || "GET").toUpperCase();
    if (methods.indexOf(method) === -1) return next();

    var key = req.headers && req.headers[headerName];
    if (Array.isArray(key)) key = key[0];

    if (!key || typeof key !== "string" || key.length === 0) {
      if (!requireKey) return next();
      var missing = problemDetails().create({
        type:   problemDetails().getBase() + "/idempotency/missing-key",
        title:  "Idempotency-Key header required",
        status: 400,                                                                               // allow:raw-byte-literal — HTTP status 400 Bad Request
        detail: "This endpoint requires an Idempotency-Key header (draft-ietf-httpapi-idempotency-key).",
      });
      _emitAudit("idempotency.missing_key", { method: method, path: req.url }, "denied");
      return problemDetails().respond(res, missing);
    }

    if (key.length > KEY_MAX_LEN || !KEY_RE.test(key)) {
      var bad = problemDetails().create({
        type:   problemDetails().getBase() + "/idempotency/bad-key",
        title:  "Idempotency-Key malformed",
        status: 400,                                                                               // allow:raw-byte-literal — HTTP status 400
        detail: "Idempotency-Key must be ASCII printable, length 1.." + KEY_MAX_LEN + " (draft §2).",
      });
      _emitAudit("idempotency.bad_key", { method: method, keyLen: key.length }, "denied");
      return problemDetails().respond(res, bad);
    }

    var bodyBytes = req._rawBody || req.body || null;
    if (bodyBytes && typeof bodyBytes === "object" && !Buffer.isBuffer(bodyBytes)) {
      // Buffer-ize a non-buffer body (already-parsed JSON, etc.) so the
      // hash is stable. JSON.stringify with sorted keys would be more
      // robust but the operator-attached body shape is whatever the
      // upstream parser produced; canonicalization is operator-side.
      try {
        bodyBytes = Buffer.from(JSON.stringify(bodyBytes), "utf8");
      } catch (_e) {
        bodyBytes = null;
      }
    }

    var fingerprint = _fingerprintRequest(req, bodyBytes);

    var cached = null;
    try { cached = opts.store.get(key); }
    catch (_storeErr) {
      // Store-read failure — emit audit + treat as miss. Idempotency is
      // a best-effort optimization; the handler runs anyway.
      _emitAudit("idempotency.store_read_failed",
        { key: _redactKey(key), error: String(_storeErr.message || _storeErr) }, "warning");
      cached = null;
    }

    if (cached) {
      if (cached.fingerprint !== fingerprint) {
        // §4.3 — same key, different request body. Client mistake.
        var mismatch = problemDetails().create({
          type:   problemDetails().getBase() + "/idempotency/key-reuse-mismatch",
          title:  "Idempotency-Key reused with different request",
          status: 422,                                                                             // allow:raw-byte-literal — HTTP status 422 Unprocessable Content (RFC 9110)
          detail: "The Idempotency-Key matches a prior request but the request body/method/path differs (draft §4.3).",
        });
        _emitAudit("idempotency.key_reuse_mismatch",
          { method: method, path: req.url, keyHash: _hashKey(key) }, "denied");
        return problemDetails().respond(res, mismatch);
      }
      // Replay. The cached body is a base64 string of the original
      // bytes; restore Buffer + write through the response.
      var rawBody;
      try { rawBody = Buffer.from(cached.body || "", "base64"); }
      catch (_decodeErr) { rawBody = Buffer.alloc(0); }
      res.statusCode = cached.statusCode;
      var headerKeys = Object.keys(cached.headers || {});
      for (var i = 0; i < headerKeys.length; i += 1) {
        try { res.setHeader(headerKeys[i], cached.headers[headerKeys[i]]); }
        catch (_hdrErr) { /* operator-restricted header — skip */ }
      }
      _emitAudit("idempotency.replay",
        { method: method, path: req.url, statusCode: cached.statusCode, keyHash: _hashKey(key) });
      res.end(rawBody);
      return;
    }

    // Miss — capture the handler's response. The bounded collector
    // refuses bodies > maxBodyBytes at push() time (operator can
    // tune via opts.maxBodyBytes; default 1 MiB). When the cap is
    // hit, we abandon the capture + emit audit + DO NOT cache;
    // operators wanting larger replay windows raise the cap.
    var origEnd   = res.end.bind(res);
    var origWrite = res.write.bind(res);
    var collector = safeBuffer.boundedChunkCollector({
      maxBytes:    maxBodyBytes,
      errorClass:  IdempotencyError,
      sizeCode:    "idempotency/body-too-large",
      sizeMessage: "idempotency: response body exceeded maxBodyBytes (cap=" + maxBodyBytes + "); not cached.",
    });
    var captured = false;
    var oversized = false;
    function _pushChunk(chunk, encoding) {
      if (oversized || !chunk) return;
      try { collector.push(_toBuffer(chunk, encoding)); }
      catch (_capErr) {
        oversized = true;
        _emitAudit("idempotency.body_too_large",
          { method: method, path: req.url, cap: maxBodyBytes, keyHash: _hashKey(key) }, "warning");
      }
    }
    res.write = function (chunk, encoding) {
      _pushChunk(chunk, encoding);
      return origWrite(chunk, encoding);
    };
    res.end = function (chunk, encoding) {
      if (!captured) {
        captured = true;
        _pushChunk(chunk, encoding);
        var status = res.statusCode || 200;                                                        // allow:raw-byte-literal — default HTTP status 200
        // Only persist 2xx-4xx responses; 5xx is transient infra
        // failure that should be retried fresh, not replayed.
        if (!oversized && status >= 200 && status < 500) {                                         // allow:raw-byte-literal — HTTP status class boundaries
          var headerMap = {};
          try {
            var allHeaders = typeof res.getHeaders === "function" ? res.getHeaders() : {};
            var hk = Object.keys(allHeaders);
            for (var j = 0; j < hk.length; j += 1) {
              if (hk[j] === "set-cookie") continue;   // Set-Cookie is per-request and unsafe to replay
              headerMap[hk[j]] = allHeaders[hk[j]];
            }
          } catch (_e) { /* ignore */ }
          var combined = collector.result();
          try {
            opts.store.set(key, {
              fingerprint: fingerprint,
              statusCode:  status,
              headers:     headerMap,
              body:        combined.toString("base64"),
            }, ttlMs);
            _emitAudit("idempotency.cache_store",
              { method: method, path: req.url, statusCode: status, keyHash: _hashKey(key), bodyBytes: combined.length });
          } catch (storeErr) {
            _emitAudit("idempotency.store_write_failed",
              { key: _redactKey(key), error: String(storeErr.message || storeErr) }, "warning");
          }
        } else if (!oversized) {
          _emitAudit("idempotency.skip_5xx",
            { method: method, path: req.url, statusCode: status, keyHash: _hashKey(key) });
        }
      }
      return origEnd(chunk, encoding);
    };
    next();
  };
}

function _toBuffer(chunk, encoding) {
  if (Buffer.isBuffer(chunk)) return chunk;
  if (typeof chunk === "string") return Buffer.from(chunk, encoding || "utf8");
  return Buffer.from(String(chunk));
}

function _hashKey(key) {
  // Hash before logging — operator's audit chain shouldn't carry raw
  // idempotency keys (clients sometimes inadvertently put PII / order
  // numbers in them).
  return nodeCrypto.createHash("sha3-256").update(key, "utf8").digest("hex").slice(0, 16);         // allow:raw-byte-literal — log-truncation length, not bytes
}

function _redactKey(key) {
  if (typeof key !== "string") return "<non-string>";
  if (key.length <= 8) return "<short:" + key.length + ">";                                        // allow:raw-byte-literal — log-redaction length threshold
  return key.slice(0, 4) + "..." + key.slice(-2) + " (len=" + key.length + ")";                    // allow:raw-byte-literal — log-redaction prefix/suffix lengths
}

module.exports = create;
module.exports.create     = create;
module.exports.memoryStore = memoryStore;
module.exports.DEFAULT_METHODS = DEFAULT_METHODS;
module.exports.IdempotencyError = IdempotencyError;
