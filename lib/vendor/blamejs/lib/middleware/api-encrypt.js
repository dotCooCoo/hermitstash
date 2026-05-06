"use strict";
/**
 * api-encrypt — end-to-end PQC payload encryption for operator-
 * controlled clients.
 *
 * TLS protects browser ↔ load-balancer; api-encrypt protects request
 * and response bodies *end-to-end* through every intermediate hop
 * (LB → app cleartext segment, sidecar proxy, queue, log aggregator,
 * APM tooling). A tampered byte anywhere downstream of the encrypted
 * boundary fails the AEAD tag at this middleware before the route
 * handler runs.
 *
 * Threat model targets:
 *   - Stripped-or-MITM TLS at any internal hop
 *   - Body capture at log aggregators / APM tooling
 *   - Replay (timestamp + nonce window catches it)
 *   - Forged client requests (no key holder = no valid ciphertext)
 *
 * What it does NOT defend against:
 *   - Semantic attacks from authorized clients (a key-holder can
 *     encrypt a malicious payload validly — safe-schema is the next
 *     layer)
 *   - Server-side key compromise
 *   - Application logic bugs in handlers
 *
 * The encryption layer is for operator-controlled clients (your
 * mobile app, your service-to-service traffic). Public APIs that
 * accept third-party callers should use TLS + webhook signatures
 * instead — the encryption requires a key bootstrap step.
 *
 * Wire format (request body, JSON):
 *
 *   {
 *     _ek:    "<base64 envelope>",   // session key wrapped to server pubkey
 *     _ct:    "<base64 packed>",     // payload encrypted with session key
 *     _ts:    1738000000000,         // unix ms
 *     _nonce: "<32 hex>"             // 16 random bytes, replay-checked
 *   }
 *
 * Wire format (response body, JSON):
 *
 *   { _ct: "<base64 packed>" }       // same session key, fresh nonce
 *
 * Crypto:
 *   - _ek is the framework's standard envelope encrypt:
 *       ML-KEM-1024 + P-384 ECDH hybrid → SHAKE256 KDF → XChaCha20-Poly1305
 *     The plaintext inside the envelope is the base64-encoded session key.
 *   - _ct is the framework's encryptPacked symmetric format:
 *       1-byte version + 24-byte XChaCha20-Poly1305 nonce + ciphertext + tag
 *     Keyed by the session key recovered from _ek.
 *
 * Operator API:
 *
 *   var apiEncrypt = b.middleware.apiEncrypt({
 *     keypair:        { publicKey, privateKey, ecPublicKey, ecPrivateKey },
 *     replayWindowMs: C.TIME.minutes(5),
 *     nonceStore:     b.nonceStore.create({ backend: 'cluster' }),
 *     exemptPaths:    ["/healthz", "/.well-known/blamejs-pubkey"],
 *     contentTypes:   ["application/json"],   // default; pass null to disable
 *   });
 *   router.use(apiEncrypt);
 *   router.get("/.well-known/blamejs-pubkey", apiEncrypt.publishPublicKey());
 *
 *   // Outbound (server-to-server, browser/mobile, etc.):
 *   var client = b.middleware.apiEncrypt.client({ pubkey });
 *   var { body, decryptResponse } = client.encryptRequest({ msg: "hi" });
 *
 *   // Server-to-server with framework HTTP client:
 *   var enc = b.httpClient.encrypted({ pubkey, baseUrl: "https://service" });
 *   var resp = await enc.request({ method: "POST", path: "/api/widget", body: { ... } });
 *
 * Key rotation:
 *   To rotate the server keypair, generate a new keypair and pass BOTH
 *   the new and the previous keypair to the middleware as `keypairs`:
 *
 *     b.middleware.apiEncrypt({
 *       keypairs: [newKeypair, prevKeypair],
 *       ...
 *     });
 *
 *   keypairs[0] is the "active" keypair — published by publishPublicKey()
 *   so new client-side bootstraps pin to it. Both keypairs are tried
 *   when decrypting `_ek`, so in-flight requests still encrypted to the
 *   previous keypair continue to decrypt for as long as the previous
 *   keypair stays in the array. Operators drop the previous keypair
 *   from the array once the rotation overlap window has elapsed.
 *
 * Failure surfacing:
 *   AEAD tag failure / stale timestamp / replay / malformed envelope
 *   all return 400 with the same body { error: "encrypted-payload-rejected" }.
 *   The category that actually matched lands in the audit event +
 *   b.events.API_ENCRYPT_FAILURE so operators get metrics / alerting
 *   without leaking which check the attacker tripped. Missing _ek /
 *   _ct / _ts / _nonce on a non-exempt path is distinguishable in the
 *   response ("encrypted-payload-required") so operators with hybrid
 *   public/private routes can debug their wiring.
 */

var crypto = require("../crypto");
var C = require("../constants");
var lazyRequire = require("../lazy-require");
var nonceStoreLib = require("../nonce-store");
var requestHelpers = require("../request-helpers");
var safeJson = require("../safe-json");
var validateOpts = require("../validate-opts");
var { defineClass } = require("../framework-error");

var audit      = lazyRequire(function () { return require("../audit"); });
var events     = lazyRequire(function () { return require("../events"); });
var httpClient = lazyRequire(function () { return require("../http-client"); });
var logger     = lazyRequire(function () { return require("../log").boot("api-encrypt"); });

var ApiEncryptError = defineClass("ApiEncryptError", { withStatusCode: true });

var DEFAULT_REPLAY_WINDOW_MS = C.TIME.minutes(5);
var DEFAULT_CONTENT_TYPES = ["application/json"];
var SESSION_KEY_BYTES = C.BYTES.bytes(32);
var REQUEST_NONCE_BYTES = C.BYTES.bytes(16);
var DEFAULT_SESSION_TTL_MS = C.TIME.minutes(15);
// 1024 ≈ "a session with a thousand response rotations" — round-number
// kibi-aligned default; operators raise this for chat / streaming sessions
// or lower it for strict per-key forward-secrecy postures.
var DEFAULT_SESSION_MAX_RESPONSES = 0x400;
// SID format: UUID-shaped string. Operators with their own session-id
// vocabulary subscribe to the same shape (cluster-storage / cache backends
// already index on string keys).
var SID_RE = /^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$/;
var SID_MAX_LENGTH = C.BYTES.bytes(64);

function _err(code, message, statusCode) {
  return new ApiEncryptError(code, message, true, statusCode || 400);
}

function _validateKeypair(kp, label) {
  if (!kp || typeof kp !== "object") {
    throw _err("INVALID_KEYPAIR", "apiEncrypt: " + label + " is required", 500);
  }
  if (typeof kp.publicKey !== "string" || typeof kp.privateKey !== "string") {
    throw _err("INVALID_KEYPAIR",
      "apiEncrypt: " + label + ".publicKey + .privateKey are required (ML-KEM-1024 PEM)", 500);
  }
  if (typeof kp.ecPublicKey !== "string" || typeof kp.ecPrivateKey !== "string") {
    throw _err("INVALID_KEYPAIR",
      "apiEncrypt: " + label + ".ecPublicKey + .ecPrivateKey are required (P-384 PEM hybrid)", 500);
  }
}

// Resolve the operator's keypair input into an ordered array. The
// first keypair is "active" — used by publishPublicKey() and as the
// hint for response encryption (responses use the per-request session
// key, so the active keypair only matters for what the bootstrap
// endpoint advertises). Every keypair in the array is tried in order
// when decrypting `_ek` so that during a rotation overlap window,
// in-flight requests encrypted to a previous keypair still decrypt
// successfully.
function _resolveKeypairs(opts) {
  if (Array.isArray(opts.keypairs)) {
    if (opts.keypairs.length === 0) {
      throw _err("INVALID_KEYPAIR", "apiEncrypt: keypairs must be a non-empty array", 500);
    }
    opts.keypairs.forEach(function (kp, i) { _validateKeypair(kp, "keypairs[" + i + "]"); });
    return opts.keypairs.slice();
  }
  if (opts.keypair) {
    _validateKeypair(opts.keypair, "keypair");
    return [opts.keypair];
  }
  throw _err("INVALID_KEYPAIR",
    "apiEncrypt: { keypair } or { keypairs: [...] } is required", 500);
}

var HTTP_STATUS = requestHelpers.HTTP_STATUS;

// _defaultSessionStore — in-memory session table for single-process
// deployments. Operators with multi-replica deploys pass an
// operator-supplied store (b.cache.create({ backend: "cluster" }) or any
// `{ get, set, delete }`-shaped handle). Per-replica isolation in default
// mode means sticky sessions; the limit is documented in the wiki.
//
//   .get(sid)  → row | null
//   .set(sid, row, { ttlMs }) → void
//   .delete(sid) → void
//
// Each row stores:
//   { sessionKey: Buffer, lastReqCtr: int, responsesEmitted: int,
//     createdAt: ms, expiresAt: ms, lastUsedAt: ms }
function _defaultSessionStore() {
  var rows = new Map();
  return {
    get: function (sid) {
      var row = rows.get(sid);
      if (!row) return null;
      if (Date.now() > row.expiresAt) {
        rows.delete(sid);
        return null;
      }
      return row;
    },
    set: function (sid, row /* opts */) {
      rows.set(sid, row);
    },
    delete: function (sid) {
      rows.delete(sid);
    },
    purgeExpired: function () {
      var now = Date.now();
      var purged = 0;
      rows.forEach(function (row, sid) {
        if (now > row.expiresAt) { rows.delete(sid); purged += 1; }
      });
      return purged;
    },
    size: function () { return rows.size; },
    close: function () { rows.clear(); },
  };
}

function _validSid(sid) {
  return typeof sid === "string" &&
         sid.length > 0 &&
         sid.length <= SID_MAX_LENGTH &&
         SID_RE.test(sid);
}

function _writeRejection(res, code, body) {
  if (res.headersSent || res.writableEnded) return;
  if (typeof res.writeHead === "function") {
    res.writeHead(code, { "Content-Type": "application/json" });
    res.end(JSON.stringify(body));
  }
}

// ---- Server-side middleware ----

function create(opts) {
  opts = opts || {};
  validateOpts(opts, [
    "keypair", "keypairs", "replayWindowMs", "pruneIntervalMs",
    "nonceStore", "exemptPaths", "contentTypes", "audit",
    "maxDecryptedBytes", "trustProxy",
    // Per-session keying mode (opt-in; per-request stays default).
    "keying", "sessionStore", "sessionTtlMs", "sessionMaxResponses",
    "observability",
  ], "middleware.apiEncrypt");
  var keypairs       = _resolveKeypairs(opts);
  var activeKeypair  = keypairs[0];
  var replayWindowMs = opts.replayWindowMs || DEFAULT_REPLAY_WINDOW_MS;
  // Cap on decrypted-payload size handed to safeJson.parse. Defaults
  // to 4 MiB (bodyParser's default 1 MiB plus headroom for crypto +
  // base64 round-trip). Operators with chunkier inbound payloads
  // raise this; the framework refuses to parse anything larger as a
  // parse-bomb defense.
  var maxDecryptedBytes = opts.maxDecryptedBytes != null
    ? opts.maxDecryptedBytes
    : C.BYTES.mib(4);
  // The spec calls for a sweep cadence of replayWindowMs/2 — short
  // enough that expired nonces don't pile up but not so frequent the
  // sweep query becomes a hot path. Operators can override.
  var pruneIntervalMs = opts.pruneIntervalMs != null
    ? opts.pruneIntervalMs : Math.max(C.TIME.seconds(30), Math.floor(replayWindowMs / 2));
  var nonceStore     = opts.nonceStore || nonceStoreLib.create({ backend: "memory" });
  var exemptPaths    = Array.isArray(opts.exemptPaths) ? opts.exemptPaths.slice() : [];
  // contentTypes scoping — middleware only operates on requests whose
  // Content-Type is in this list. Default JSON; operators with more
  // exotic clients (form-encoded, gRPC-web, etc.) widen the list.
  // Set to null/false/empty array to disable content-type filtering
  // (treat every non-exempt request as encrypted).
  var contentTypes   = opts.contentTypes === null || opts.contentTypes === false
    ? null
    : (Array.isArray(opts.contentTypes) && opts.contentTypes.length > 0
        ? opts.contentTypes.slice()
        : DEFAULT_CONTENT_TYPES.slice());
  var auditOn        = opts.audit !== false;
  var trustProxy     = opts.trustProxy === true;
  var lastPruneAt    = 0;

  // ---- per-session keying opts ----
  var keying = opts.keying != null ? opts.keying : "per-request";
  if (keying !== "per-request" && keying !== "per-session") {
    throw _err("BAD_OPT",
      "apiEncrypt: keying must be 'per-request' (default) or 'per-session', got " +
      JSON.stringify(opts.keying), 500);
  }
  var sessionTtlMs = opts.sessionTtlMs != null ? opts.sessionTtlMs : DEFAULT_SESSION_TTL_MS;
  var sessionMaxResponses = opts.sessionMaxResponses != null
    ? opts.sessionMaxResponses : DEFAULT_SESSION_MAX_RESPONSES;
  if (typeof sessionTtlMs !== "number" || !isFinite(sessionTtlMs) || sessionTtlMs <= 0) {
    throw _err("BAD_OPT",
      "apiEncrypt: sessionTtlMs must be a positive finite number (ms), got " +
      JSON.stringify(opts.sessionTtlMs), 500);
  }
  if (typeof sessionMaxResponses !== "number" || !isFinite(sessionMaxResponses) ||
      sessionMaxResponses <= 0 || Math.floor(sessionMaxResponses) !== sessionMaxResponses) {
    throw _err("BAD_OPT",
      "apiEncrypt: sessionMaxResponses must be a positive finite integer, got " +
      JSON.stringify(opts.sessionMaxResponses), 500);
  }
  // sessionStore — duck-typed handle exposing { get, set, delete }. The
  // helper optionalObjectWithMethod only checks one method; here we need
  // three. Inline shape kept; not a generic enough pattern to warrant a
  // separate helper.
  if (opts.sessionStore !== undefined && opts.sessionStore !== null) {
    var ss = opts.sessionStore;
    var ssOk = typeof ss === "object" &&
               typeof ss.get === "function" &&
               typeof ss.set === "function" &&
               typeof ss.delete === "function";
    if (!ssOk) {
      throw _err("BAD_OPT",
        "apiEncrypt: sessionStore must expose { get(sid), set(sid, row, opts?), delete(sid) } " +
        "(b.cache.create() is shape-compatible)", 500);
    }
  }
  var sessionStore = (keying === "per-session" && opts.sessionStore)
    ? opts.sessionStore
    : (keying === "per-session" ? _defaultSessionStore() : null);
  // Observability tap — per-session emits counters for sessions
  // established / replay-rejected / expired / rotated. Per-request mode
  // ignores this opt; the existing events.API_ENCRYPT_FAILURE channel
  // already carries failure shape there.
  validateOpts.observabilityShape(opts.observability,
    "apiEncrypt", ApiEncryptError, "BAD_OPT");
  var observabilityHandle = opts.observability || null;
  function _emitObs(name, value, labels) {
    if (observabilityHandle) {
      observabilityHandle.safeEvent(name, value, labels || {});
    }
  }
  function _emitSessionAudit(action, info) {
    if (!auditOn) return;
    try {
      audit().safeEmit({
        action: action, outcome: info.outcome || "success",
        metadata: info.metadata || {},
        actor: info.actor || null,
        requestId: info.requestId || null,
      });
    } catch (_e) { /* audit best-effort */ }
  }

  function _isExempt(req) {
    var p = req.pathname || (req.url || "/").split("?")[0];
    for (var i = 0; i < exemptPaths.length; i++) {
      var rule = exemptPaths[i];
      if (typeof rule === "string" ? p === rule || p.indexOf(rule + "/") === 0 : rule.test(p)) {
        return true;
      }
    }
    return false;
  }

  function _matchesContentType(req) {
    if (!contentTypes) return true;  // filtering disabled
    var ct = req.headers && (req.headers["content-type"] || req.headers["Content-Type"]);
    if (typeof ct !== "string") return false;
    // Strip parameters like "; charset=utf-8"
    var bare = ct.split(";")[0].trim().toLowerCase();
    for (var i = 0; i < contentTypes.length; i++) {
      if (contentTypes[i].toLowerCase() === bare) return true;
    }
    return false;
  }

  function _emitFailure(req, reason) {
    var info = {
      reason:    reason,
      ip:        requestHelpers.clientIp(req, { trustProxy: trustProxy }),
      path:      req.pathname || (req.url || "/").split("?")[0],
      method:    req.method,
      ts:        new Date().toISOString(),
      requestId: req.requestId || null,
    };
    if (auditOn) {
      audit().safeEmit({
        actor:    requestHelpers.extractActorContext(req),
        action:   "system.api_encrypt.failure",
        outcome:  "denied",
        reason:   reason,
        metadata: { reason: reason, path: info.path, method: info.method },
        requestId: info.requestId,
      });
    }
    try { events().emit(events().EVENTS.API_ENCRYPT_FAILURE, info); }
    catch (_e) { /* events best-effort */ }
  }

  function _maybePrune() {
    var now = Date.now();
    if (now - lastPruneAt < pruneIntervalMs) return;
    lastPruneAt = now;
    nonceStore.purgeExpired().catch(function (e) {
      try {
        logger().warn("nonce-store prune failed: " + ((e && e.message) || String(e)));
      } catch (_e) { /* logger best-effort */ }
    });
  }

  // _wrapResJson — install res.json that encrypts the response with the
  // session key. In per-request mode the response is `{ _ct }`; in
  // per-session mode it carries `{ _ct, _sid, _ctr }` so the client can
  // detect tampered / replayed responses with a monotonic counter check.
  function _wrapResJson(res, sessionKey, sessionCtx) {
    var origJson = res.json;
    res.json = function (data) {
      try {
        var ptBuf = Buffer.from(JSON.stringify(data), "utf8");
        var ctBuf = crypto.encryptPacked(ptBuf, sessionKey);
        var encrypted = { _ct: ctBuf.toString("base64") };
        if (sessionCtx) {
          encrypted._sid = sessionCtx.sid;
          encrypted._ctr = sessionCtx.responseCtr;
        }
        if (typeof origJson === "function") {
          return origJson.call(res, encrypted);
        }
        // Fallback if router didn't install res.json yet.
        if (!res.headersSent) {
          res.writeHead(res.statusCode || HTTP_STATUS.OK, { "Content-Type": "application/json" });
        }
        res.end(JSON.stringify(encrypted));
      } catch (e) {
        try {
          logger().error("response encryption failed: " + ((e && e.message) || String(e)));
        } catch (_e) { /* logger best-effort */ }
        if (!res.headersSent) {
          res.writeHead(HTTP_STATUS.INTERNAL_SERVER_ERROR, { "Content-Type": "application/json" });
        }
        res.end(JSON.stringify({ error: "response-encryption-failed" }));
      }
    };
  }

  // _decryptEkToSessionKey — try every keypair in order; returns the
  // 32-byte sessionKey buffer or null on AEAD failure across all keypairs.
  function _decryptEkToSessionKey(ek) {
    for (var ki = 0; ki < keypairs.length; ki++) {
      try {
        var sessionKeyB64 = crypto.decrypt(ek, keypairs[ki]);
        var candidate = Buffer.from(sessionKeyB64, "base64");
        if (candidate.length === SESSION_KEY_BYTES) return candidate;
      } catch (_e) { /* try next keypair */ }
    }
    return null;
  }

  async function middleware(req, res, next) {
    if (_isExempt(req)) return next();
    if (!_matchesContentType(req)) return next();

    var body = req.body;
    if (!body || typeof body !== "object") {
      _emitFailure(req, "shape");
      return _writeRejection(res, HTTP_STATUS.BAD_REQUEST, { error: "encrypted-payload-required" });
    }

    var now = Date.now();
    var ct = body._ct, ts = body._ts;
    if (typeof ct !== "string" || typeof ts !== "number") {
      _emitFailure(req, "shape");
      return _writeRejection(res, HTTP_STATUS.BAD_REQUEST, { error: "encrypted-payload-required" });
    }
    if (Math.abs(now - ts) > replayWindowMs) {
      _emitFailure(req, "stale");
      return _writeRejection(res, HTTP_STATUS.BAD_REQUEST, { error: "encrypted-payload-rejected" });
    }

    // Per-request OR per-session bootstrap path: shape includes _ek + _nonce.
    // Per-session subsequent path: shape includes _sid + _ctr (no _ek).
    var ek = body._ek, nonce = body._nonce, sid = body._sid, ctr = body._ctr;
    var sessionKey = null;
    var sessionCtx = null;             // null = per-request mode response shape
    var session = null;

    if (typeof ek === "string" && typeof nonce === "string") {
      // ---- Bootstrap path (per-request mode OR first request of session) ----
      var nonceHash = crypto.sha3Hash(nonce, "hex");
      var expireAt = now + replayWindowMs;
      var freshNonce;
      try { freshNonce = await nonceStore.checkAndInsert(nonceHash, expireAt); }
      catch (_e) {
        _emitFailure(req, "nonce-store-error");
        return _writeRejection(res, HTTP_STATUS.INTERNAL_SERVER_ERROR, { error: "nonce-store-unavailable" });
      }
      if (!freshNonce) {
        _emitFailure(req, "replay");
        return _writeRejection(res, HTTP_STATUS.BAD_REQUEST, { error: "encrypted-payload-rejected" });
      }
      sessionKey = _decryptEkToSessionKey(ek);
      if (!sessionKey) {
        _emitFailure(req, "tag");
        return _writeRejection(res, HTTP_STATUS.BAD_REQUEST, { error: "encrypted-payload-rejected" });
      }
      if (keying === "per-session") {
        if (!_validSid(sid)) {
          _emitFailure(req, "shape");
          return _writeRejection(res, HTTP_STATUS.BAD_REQUEST, { error: "encrypted-payload-required" });
        }
        if (typeof ctr !== "number" || !isFinite(ctr) || ctr < 0 || Math.floor(ctr) !== ctr) {
          _emitFailure(req, "shape");
          return _writeRejection(res, HTTP_STATUS.BAD_REQUEST, { error: "encrypted-payload-required" });
        }
        // Bootstrap a new session row keyed by sid.
        session = {
          sessionKey:       sessionKey,
          lastReqCtr:       ctr,
          responsesEmitted: 0,
          createdAt:        now,
          lastUsedAt:       now,
          expiresAt:        now + sessionTtlMs,
        };
        try { await sessionStore.set(sid, session, { ttlMs: sessionTtlMs }); }
        catch (_e) {
          _emitFailure(req, "session-store-error");
          return _writeRejection(res, HTTP_STATUS.INTERNAL_SERVER_ERROR, { error: "session-store-unavailable" });
        }
        _emitObs("apiEncrypt.session.created", 1, { mode: "per-session" });
        _emitSessionAudit("apiEncrypt.session.created", {
          actor: requestHelpers.extractActorContext(req),
          metadata: { sid: sid, expiresAt: session.expiresAt },
          requestId: req.requestId || null,
        });
        sessionCtx = { sid: sid, responseCtr: 1 };
        session.responsesEmitted = 1;
      }
    } else if (keying === "per-session" &&
               typeof sid === "string" && typeof ctr === "number") {
      // ---- Per-session subsequent-request path ----
      if (!_validSid(sid)) {
        _emitFailure(req, "shape");
        return _writeRejection(res, HTTP_STATUS.BAD_REQUEST, { error: "encrypted-payload-required" });
      }
      if (!isFinite(ctr) || ctr < 0 || Math.floor(ctr) !== ctr) {
        _emitFailure(req, "shape");
        return _writeRejection(res, HTTP_STATUS.BAD_REQUEST, { error: "encrypted-payload-required" });
      }
      try { session = await sessionStore.get(sid); }
      catch (_e) {
        _emitFailure(req, "session-store-error");
        return _writeRejection(res, HTTP_STATUS.INTERNAL_SERVER_ERROR, { error: "session-store-unavailable" });
      }
      if (!session) {
        _emitObs("apiEncrypt.session.unknown", 1, {});
        _emitFailure(req, "session-unknown");
        return _writeRejection(res, HTTP_STATUS.UNAUTHORIZED, { error: "session-unknown" });
      }
      if (now > session.expiresAt) {
        try { await sessionStore.delete(sid); } catch (_e) { /* best-effort */ }
        _emitObs("apiEncrypt.session.expired", 1, {});
        _emitSessionAudit("apiEncrypt.session.expired", {
          outcome: "denied",
          actor: requestHelpers.extractActorContext(req),
          metadata: { sid: sid, reason: "ttl_exceeded" },
          requestId: req.requestId || null,
        });
        _emitFailure(req, "session-expired");
        return _writeRejection(res, HTTP_STATUS.UNAUTHORIZED, { error: "session-expired" });
      }
      if (session.responsesEmitted >= sessionMaxResponses) {
        try { await sessionStore.delete(sid); } catch (_e) { /* best-effort */ }
        _emitObs("apiEncrypt.session.rotated", 1, { reason: "max_responses" });
        _emitSessionAudit("apiEncrypt.session.rotated", {
          actor: requestHelpers.extractActorContext(req),
          metadata: { sid: sid, reason: "max_responses_exceeded",
                      responsesEmitted: session.responsesEmitted },
          requestId: req.requestId || null,
        });
        _emitFailure(req, "session-rotation-required");
        return _writeRejection(res, HTTP_STATUS.UNAUTHORIZED, { error: "session-rotation-required" });
      }
      // Replay defense: counter MUST strictly increase.
      if (ctr <= session.lastReqCtr) {
        _emitObs("apiEncrypt.session.replay_rejected", 1, {});
        _emitSessionAudit("apiEncrypt.session.replay_rejected", {
          outcome: "denied",
          actor: requestHelpers.extractActorContext(req),
          metadata: { sid: sid, receivedCtr: ctr, lastSeen: session.lastReqCtr },
          requestId: req.requestId || null,
        });
        _emitFailure(req, "counter-replay");
        return _writeRejection(res, HTTP_STATUS.BAD_REQUEST, { error: "encrypted-payload-rejected" });
      }
      sessionKey = session.sessionKey;
      if (Buffer.isBuffer(sessionKey) === false) {
        // Operator-supplied store may have JSON-serialised the buffer.
        // Accept hex / base64 / Uint8Array and coerce.
        if (typeof sessionKey === "string") {
          sessionKey = Buffer.from(sessionKey, "base64");
        } else if (sessionKey && sessionKey.type === "Buffer" && Array.isArray(sessionKey.data)) {
          sessionKey = Buffer.from(sessionKey.data);
        } else if (sessionKey instanceof Uint8Array) {
          sessionKey = Buffer.from(sessionKey);
        }
      }
      if (!Buffer.isBuffer(sessionKey) || sessionKey.length !== SESSION_KEY_BYTES) {
        _emitFailure(req, "session-store-error");
        return _writeRejection(res, HTTP_STATUS.INTERNAL_SERVER_ERROR, { error: "session-store-unavailable" });
      }
      session.lastReqCtr = ctr;
      session.lastUsedAt = now;
      session.responsesEmitted += 1;
      try { await sessionStore.set(sid, session, { ttlMs: session.expiresAt - now }); }
      catch (_e) { /* best-effort — request still proceeds */ }
      sessionCtx = { sid: sid, responseCtr: session.responsesEmitted };
    } else {
      _emitFailure(req, "shape");
      return _writeRejection(res, HTTP_STATUS.BAD_REQUEST, { error: "encrypted-payload-required" });
    }

    // Decrypt _ct → cleartext payload bytes → JSON object.
    var clearObj;
    try {
      var ctBuf = Buffer.from(ct, "base64");
      var ptBuf = crypto.decryptPacked(ctBuf, sessionKey);
      clearObj = safeJson.parse(ptBuf.toString("utf8"), { maxBytes: maxDecryptedBytes });
    } catch (_e) {
      _emitFailure(req, "tag");
      return _writeRejection(res, HTTP_STATUS.BAD_REQUEST, { error: "encrypted-payload-rejected" });
    }

    // Replace req.body with cleartext, stash session key for any
    // operator code that wants to attach extra encrypted side-channel
    // data (e.g. send a follow-up encrypted SSE event).
    req.body = clearObj;
    req.apiEncryptSessionKey = sessionKey;
    if (sessionCtx) req.apiEncryptSession = { sid: sessionCtx.sid };

    _wrapResJson(res, sessionKey, sessionCtx);
    _maybePrune();

    return next();
  }

  // Route handler that publishes the server's public keys for client
  // bootstrap. Returns the PEM strings + KEM ID + a stable cache hint
  // so clients can pin / rotate based on the published keys.
  function publishPublicKey() {
    return function publishHandler(_req, res) {
      var body = {
        publicKey:    activeKeypair.publicKey,
        ecPublicKey:  activeKeypair.ecPublicKey,
        kemId:        C.ACTIVE.KEM,
        cipherId:     C.ACTIVE.CIPHER,
        kdfId:        C.ACTIVE.KDF,
      };
      if (typeof res.json === "function") return res.json(body);
      if (!res.headersSent) {
        res.writeHead(HTTP_STATUS.OK, { "Content-Type": "application/json" });
      }
      res.end(JSON.stringify(body));
    };
  }

  middleware.publishPublicKey = publishPublicKey;
  middleware.close = function () {
    if (typeof nonceStore.close === "function") nonceStore.close();
    if (sessionStore && typeof sessionStore.close === "function") sessionStore.close();
  };
  // Expose for tests / operator dashboards. Counts are 0 in per-request mode.
  middleware.sessionStore = sessionStore;
  middleware.keying = keying;

  return middleware;
}

// ---- Client-side helper ----
//
// Operators import this in their browser/mobile/native code or in
// service-to-service callers. The pubkey shape MUST match what
// publishPublicKey() returns: { publicKey, ecPublicKey, kemId,
// cipherId, kdfId }.

function client(opts) {
  opts = opts || {};
  validateOpts(opts, ["pubkey", "maxDecryptedBytes", "keying"], "middleware.apiEncrypt.client");
  if (!opts.pubkey || typeof opts.pubkey !== "object") {
    throw _err("CLIENT_INVALID_PUBKEY",
      "apiEncrypt.client: opts.pubkey is required ({ publicKey, ecPublicKey })", 500);
  }
  if (typeof opts.pubkey.publicKey !== "string" ||
      typeof opts.pubkey.ecPublicKey !== "string") {
    throw _err("CLIENT_INVALID_PUBKEY",
      "apiEncrypt.client: pubkey.publicKey + ecPublicKey must be PEM strings", 500);
  }
  var pubkey = opts.pubkey;
  var maxDecryptedBytes = opts.maxDecryptedBytes != null
    ? opts.maxDecryptedBytes
    : C.BYTES.mib(4);
  var keying = opts.keying != null ? opts.keying : "per-request";
  if (keying !== "per-request" && keying !== "per-session") {
    throw _err("CLIENT_BAD_OPT",
      "apiEncrypt.client: keying must be 'per-request' (default) or 'per-session', got " +
      JSON.stringify(opts.keying), 500);
  }

  if (keying === "per-request") {
    return { encryptRequest: _encryptPerRequest, keying: keying };
  }

  // Per-session: stateful client. encryptRequest mutates internal counter.
  // First call sends the bootstrap envelope; subsequent calls omit _ek/_nonce
  // and increment the counter. Operator can call resetSession() to force a
  // new bootstrap (e.g. after server returns "session-expired").
  var perSessionKey = null;
  var perSessionSid = null;
  var perSessionReqCtr = 0;
  var perSessionLastResCtr = 0;

  function _resetSession() {
    perSessionKey = crypto.generateBytes(SESSION_KEY_BYTES);
    perSessionSid = _generateUuidV4();
    perSessionReqCtr = 0;
    perSessionLastResCtr = 0;
  }

  function _decryptPerSessionResponse(responseBody) {
    if (!responseBody || typeof responseBody !== "object" ||
        typeof responseBody._ct !== "string") {
      throw _err("CLIENT_RESPONSE_SHAPE",
        "apiEncrypt.client: response missing _ct field");
    }
    if (typeof responseBody._sid !== "string" || responseBody._sid !== perSessionSid) {
      throw _err("CLIENT_RESPONSE_SID",
        "apiEncrypt.client: response sid does not match opened session");
    }
    if (typeof responseBody._ctr !== "number" || responseBody._ctr <= perSessionLastResCtr) {
      throw _err("CLIENT_RESPONSE_REPLAY",
        "apiEncrypt.client: response counter is not strictly increasing " +
        "(got " + responseBody._ctr + ", lastSeen " + perSessionLastResCtr + ")");
    }
    perSessionLastResCtr = responseBody._ctr;
    var resCtBuf = Buffer.from(responseBody._ct, "base64");
    var resPtBuf = crypto.decryptPacked(resCtBuf, perSessionKey);
    return safeJson.parse(resPtBuf.toString("utf8"), { maxBytes: maxDecryptedBytes });
  }

  function _encryptPerSession(payload) {
    if (payload === undefined) payload = null;
    if (!perSessionKey) _resetSession();
    var ts = Date.now();
    var ptBuf = Buffer.from(JSON.stringify(payload), "utf8");
    var ctBuf = crypto.encryptPacked(ptBuf, perSessionKey);
    perSessionReqCtr += 1;
    var body;
    if (perSessionReqCtr === 1) {
      // Bootstrap envelope — full _ek + _nonce; server stores sid → sessionKey.
      var ek = crypto.encrypt(perSessionKey.toString("base64"), pubkey);
      var nonce = crypto.generateBytes(REQUEST_NONCE_BYTES).toString("hex");
      body = {
        _ek:    ek,
        _ct:    ctBuf.toString("base64"),
        _ts:    ts,
        _nonce: nonce,
        _sid:   perSessionSid,
        _ctr:   perSessionReqCtr,
      };
    } else {
      // Subsequent — sid + ctr only. KEM material amortized across the session.
      body = {
        _ct:    ctBuf.toString("base64"),
        _ts:    ts,
        _sid:   perSessionSid,
        _ctr:   perSessionReqCtr,
      };
    }
    return { body: body, decryptResponse: _decryptPerSessionResponse };
  }

  function _encryptPerRequest(payload) {
    if (payload === undefined) payload = null;
    var sessionKey = crypto.generateBytes(SESSION_KEY_BYTES);
    var ek = crypto.encrypt(sessionKey.toString("base64"), pubkey);
    var ptBuf = Buffer.from(JSON.stringify(payload), "utf8");
    var ctBuf = crypto.encryptPacked(ptBuf, sessionKey);
    var requestNonce = crypto.generateBytes(REQUEST_NONCE_BYTES).toString("hex");
    var ts = Date.now();
    return {
      body: {
        _ek:    ek,
        _ct:    ctBuf.toString("base64"),
        _ts:    ts,
        _nonce: requestNonce,
      },
      decryptResponse: function (responseBody) {
        if (!responseBody || typeof responseBody !== "object" ||
            typeof responseBody._ct !== "string") {
          throw _err("CLIENT_RESPONSE_SHAPE",
            "apiEncrypt.client: response missing _ct field");
        }
        var resCtBuf = Buffer.from(responseBody._ct, "base64");
        var resPtBuf = crypto.decryptPacked(resCtBuf, sessionKey);
        return safeJson.parse(resPtBuf.toString("utf8"), { maxBytes: maxDecryptedBytes });
      },
    };
  }

  return {
    encryptRequest: _encryptPerSession,
    resetSession:   _resetSession,
    sessionInfo:    function () {
      return {
        sid: perSessionSid,
        reqCtr: perSessionReqCtr,
        lastResCtr: perSessionLastResCtr,
      };
    },
    keying: keying,
  };
}

// _generateUuidV4 — UUID v4 from 16 random bytes, formatted dash-separated.
// Used for client-side session-id generation in per-session keying.
// Slice offsets are RFC 4122 UUID hex-byte boundaries (`xxxxxxxx-xxxx-Mxxx-Nxxx-xxxxxxxxxxxx`)
// — protocol-fixed values, not byte sizes. allow:raw-byte-literal
function _generateUuidV4() {
  var b = crypto.generateBytes(16);                     // allow:raw-byte-literal — UUID is exactly 16 bytes
  // Set version (4) and variant (10x) bits per RFC 4122.
  b[6] = (b[6] & 0x0f) | 0x40;
  b[8] = (b[8] & 0x3f) | 0x80;
  var hex = b.toString("hex");
  return hex.slice(0, 8) + "-" +                        // allow:raw-byte-literal — RFC 4122 hex offsets
         hex.slice(8, 12) + "-" +                       // allow:raw-byte-literal
         hex.slice(12, 16) + "-" +                      // allow:raw-byte-literal
         hex.slice(16, 20) + "-" +                      // allow:raw-byte-literal
         hex.slice(20, 32);                             // allow:raw-byte-literal
}

// ---- Server-to-server convenience ----
//
// Wraps the framework's HTTP client so service-to-service callers
// don't have to juggle encryptRequest + httpClient.request +
// JSON parsing + decryptResponse on every call. The pubkey is the
// callee's public bootstrap document (the JSON `publishPublicKey()`
// returns) so this helper works between any two blamejs instances.
//
//   var enc = b.httpClient.encrypted({
//     pubkey:  callee.pubkey,           // { publicKey, ecPublicKey }
//     baseUrl: "https://callee.example",
//     headers: { Authorization: "Bearer ..." },
//   });
//   var resp = await enc.request({
//     method: "POST",
//     path:   "/api/widget",
//     body:   { user: "alice" },
//   });
//   resp.body  // → decrypted plaintext object
//
// The helper handles only JSON-shaped request/response payloads,
// matching the middleware's contentTypes default.
function httpClientEncrypted(opts) {
  opts = opts || {};
  validateOpts(opts, [
    "pubkey", "baseUrl", "headers", "method", "maxDecryptedBytes", "keying",
  ], "middleware.apiEncrypt.httpClient");
  if (!opts.pubkey) {
    throw _err("CLIENT_INVALID_PUBKEY",
      "httpClient.encrypted: opts.pubkey is required (the callee's bootstrap doc)", 500);
  }
  var maxDecryptedBytes = opts.maxDecryptedBytes != null
    ? opts.maxDecryptedBytes
    : C.BYTES.mib(4);
  var keying = opts.keying != null ? opts.keying : "per-request";
  var clientCtx = client({
    pubkey: opts.pubkey,
    maxDecryptedBytes: maxDecryptedBytes,
    keying: keying,
  });
  var baseUrl       = opts.baseUrl ? String(opts.baseUrl).replace(/\/$/, "") : "";
  var defaultHdrs   = opts.headers || {};
  var defaultMethod = opts.method  || "POST";

  function _resolveUrl(reqOpts) {
    if (typeof reqOpts.url === "string" && reqOpts.url.length > 0) return reqOpts.url;
    if (typeof reqOpts.path === "string" && reqOpts.path.length > 0) {
      if (!baseUrl) {
        throw _err("CLIENT_INVALID_URL",
          "httpClient.encrypted.request: { path } requires opts.baseUrl at create time", 500);
      }
      return baseUrl + (reqOpts.path[0] === "/" ? reqOpts.path : "/" + reqOpts.path);
    }
    throw _err("CLIENT_INVALID_URL",
      "httpClient.encrypted.request: requires { url } or { path } (with opts.baseUrl)", 500);
  }

  async function request(reqOpts) {
    reqOpts = reqOpts || {};
    var url = _resolveUrl(reqOpts);
    var encrypted = clientCtx.encryptRequest(
      reqOpts.body !== undefined ? reqOpts.body : null
    );

    // Merge headers — operator's per-request headers win over default
    // headers, but Content-Type is forced because the encrypted body
    // is always JSON.
    var headers = Object.assign({}, defaultHdrs, reqOpts.headers || {});
    headers["Content-Type"] = "application/json";

    var passThrough = {};
    var passable = ["allowedProtocols", "allowInternal", "idleTimeoutMs", "maxResponseBytes",
                    "agent", "errorClass"];
    for (var i = 0; i < passable.length; i++) {
      if (reqOpts[passable[i]] !== undefined) passThrough[passable[i]] = reqOpts[passable[i]];
    }

    var rawBody = Buffer.from(JSON.stringify(encrypted.body), "utf8");
    var resp = await httpClient().request(Object.assign({
      url:     url,
      method:  reqOpts.method || defaultMethod,
      headers: headers,
      body:    rawBody,
    }, passThrough));

    // Empty body → no decryption (e.g. 204 No Content).
    if (!resp.body || resp.body.length === 0) {
      return { statusCode: resp.statusCode, headers: resp.headers, body: null };
    }
    var parsed;
    try { parsed = safeJson.parse(resp.body.toString("utf8"), { maxBytes: maxDecryptedBytes }); }
    catch (e) {
      throw _err("CLIENT_RESPONSE_NOT_JSON",
        "httpClient.encrypted: response body is not valid JSON: " + e.message);
    }
    return {
      statusCode: resp.statusCode,
      headers:    resp.headers,
      body:       encrypted.decryptResponse(parsed),
    };
  }

  return { request: request };
}

module.exports = Object.assign(create, {
  client:           client,
  httpClient:       httpClientEncrypted,
  ApiEncryptError:  ApiEncryptError,
});
