// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

var bCrypto = require("../crypto");
var C = require("../constants");
var numericBounds = require("../numeric-bounds");
var lazyRequire = require("../lazy-require");
var nonceStore = require("../nonce-store");
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
var DEFAULT_SESSION_MAX_RESPONSES = 0x400;
var SID_RE = /^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$/;
var SID_MAX_LENGTH = C.BYTES.bytes(64);

function _err(code, message, statusCode) {
  return new ApiEncryptError(code, message, true, statusCode || 400);
}

function _validateKeypair(kp, label) {
  if (!kp || typeof kp !== "object") {
    throw _err("api-encrypt/invalid-keypair", "apiEncrypt: " + label + " is required", 500);
  }
  if (typeof kp.publicKey !== "string" || typeof kp.privateKey !== "string") {
    throw _err("api-encrypt/invalid-keypair",
      "apiEncrypt: " + label + ".publicKey + .privateKey are required (ML-KEM-1024 PEM)", 500);
  }
  if (typeof kp.ecPublicKey !== "string" || typeof kp.ecPrivateKey !== "string") {
    throw _err("api-encrypt/invalid-keypair",
      "apiEncrypt: " + label + ".ecPublicKey + .ecPrivateKey are required (P-384 PEM hybrid)", 500);
  }
}

function _resolveKeypairs(opts) {
  if (Array.isArray(opts.keypairs)) {
    if (opts.keypairs.length === 0) {
      throw _err("api-encrypt/invalid-keypair", "apiEncrypt: keypairs must be a non-empty array", 500);
    }
    opts.keypairs.forEach(function (kp, i) { _validateKeypair(kp, "keypairs[" + i + "]"); });
    return opts.keypairs.slice();
  }
  if (opts.keypair) {
    _validateKeypair(opts.keypair, "keypair");
    return [opts.keypair];
  }
  throw _err("api-encrypt/invalid-keypair",
    "apiEncrypt: { keypair } or { keypairs: [...] } is required", 500);
}

var HTTP_STATUS = requestHelpers.HTTP_STATUS;

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
    set: function (sid, row ) {
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

function _writeRejection(req, res, code, body, opts) {
  if (res.headersSent || res.writableEnded) return;
  if (typeof res.writeHead !== "function") return;
  var out = body;
  var encode = (!opts || !opts.plaintext) && req && req.apiEncryptRejectEncode;
  if (typeof encode === "function") {
    try { out = encode(body); }
    catch (_e) { out = body; }
  }
  res.writeHead(code, { "Content-Type": "application/json" });
  res.end(JSON.stringify(out));
}

/**
 * @primitive b.middleware.apiEncrypt
 * @signature b.middleware.apiEncrypt(opts)
 * @since     0.1.0
 * @related   b.middleware.csrfProtect
 *
 * End-to-end PQC payload encryption for operator-controlled clients.
 * TLS protects browser to load-balancer; this middleware protects the
 * request and response bodies through every intermediate hop (LB,
 * sidecars, queues, log aggregators, APM tooling). A tampered byte
 * anywhere downstream of the encrypted boundary fails the AEAD tag
 * before the route handler runs. Defends against stripped TLS,
 * body capture in observability tooling, and replay (timestamp +
 * nonce window). Mount with a server keypair set; the configured
 * client SDK encrypts to the keypair's public half.
 *
 * @opts
 *   {
 *     keypair:             { publicKey, privateKey, ecPublicKey, ecPrivateKey },
 *     keypairs:            [...]            // multi-key rotation set; first = active
 *     replayWindowMs:      number,
 *     pruneIntervalMs:     number,
 *     nonceStore:          { checkAndInsert, purgeExpired, close },
 *     exemptPaths:         string[],
 *     contentTypes:        string[],         // default ["application/json"]
 *     audit:               boolean,
 *     maxDecryptedBytes:   number,
 *     trustProxy:          boolean|number,
 *     keying:              "per-request"|"per-session",
 *     sessionStore:        object,
 *     sessionTtlMs:        number,
 *     sessionMaxResponses: number,
 *     observability:       object,
 *   }
 *
 * @example
 *   var b = require("@blamejs/core");
 *   var app = b.router.create();
 *   var kp = b.crypto.generateEncryptionKeyPair();
 *   app.use(b.middleware.apiEncrypt({
 *     keypair:        kp,
 *     replayWindowMs: 30000,
 *     contentTypes:   ["application/json"],
 *   }));
 */
function create(opts) {
  opts = opts || {};
  validateOpts(opts, [
    "keypair", "keypairs", "replayWindowMs", "pruneIntervalMs",
    "nonceStore", "exemptPaths", "contentTypes", "audit",
    "maxDecryptedBytes", "trustProxy",
    "keying", "sessionStore", "sessionTtlMs", "sessionMaxResponses",
    "observability",
  ], "middleware.apiEncrypt");
  var keypairs       = _resolveKeypairs(opts);
  var activeKeypair  = keypairs[0];
  validateOpts.optionalPositiveFinite(opts.replayWindowMs,
    "apiEncrypt: replayWindowMs", ApiEncryptError, "api-encrypt/bad-opt");
  var replayWindowMs = opts.replayWindowMs || DEFAULT_REPLAY_WINDOW_MS;
  validateOpts.optionalPositiveInt(opts.maxDecryptedBytes,
    "apiEncrypt: maxDecryptedBytes", ApiEncryptError, "api-encrypt/bad-opt");
  var maxDecryptedBytes = opts.maxDecryptedBytes != null
    ? opts.maxDecryptedBytes
    : C.BYTES.mib(4);
  validateOpts.optionalPositiveFinite(opts.pruneIntervalMs,
    "apiEncrypt: pruneIntervalMs", ApiEncryptError, "api-encrypt/bad-opt");
  var pruneIntervalMs = opts.pruneIntervalMs != null
    ? opts.pruneIntervalMs : Math.max(C.TIME.seconds(30), Math.floor(replayWindowMs / 2));
  var store          = opts.nonceStore || nonceStore.create({ backend: "memory" });
  var exemptPaths    = Array.isArray(opts.exemptPaths) ? opts.exemptPaths.slice() : [];
  var contentTypes   = opts.contentTypes === null || opts.contentTypes === false
    ? null
    : (Array.isArray(opts.contentTypes) && opts.contentTypes.length > 0
        ? opts.contentTypes.slice()
        : DEFAULT_CONTENT_TYPES.slice());
  var auditOn        = opts.audit !== false;
  var trustProxy     = opts.trustProxy === true;
  var lastPruneAt    = 0;

  var keying = opts.keying != null ? opts.keying : "per-request";
  if (keying !== "per-request" && keying !== "per-session") {
    throw _err("api-encrypt/bad-opt",
      "apiEncrypt: keying must be 'per-request' (default) or 'per-session', got " +
      JSON.stringify(opts.keying), 500);
  }
  var sessionTtlMs = opts.sessionTtlMs != null ? opts.sessionTtlMs : DEFAULT_SESSION_TTL_MS;
  var sessionMaxResponses = opts.sessionMaxResponses != null
    ? opts.sessionMaxResponses : DEFAULT_SESSION_MAX_RESPONSES;
  if (typeof sessionTtlMs !== "number" || !isFinite(sessionTtlMs) || sessionTtlMs <= 0) {
    throw _err("api-encrypt/bad-opt",
      "apiEncrypt: sessionTtlMs must be a positive finite number (ms), got " +
      JSON.stringify(opts.sessionTtlMs), 500);
  }
  numericBounds.requirePositiveFiniteInt(sessionMaxResponses,
    "apiEncrypt: sessionMaxResponses", ApiEncryptError, "api-encrypt/bad-opt", null,
    { permanent: true, statusCode: C.HTTP.STATUS.INTERNAL_SERVER_ERROR });
  if (opts.sessionStore !== undefined && opts.sessionStore !== null) {
    var ss = opts.sessionStore;
    var ssOk = typeof ss === "object" &&
               typeof ss.get === "function" &&
               typeof ss.set === "function" &&
               typeof ss.delete === "function";
    if (!ssOk) {
      throw _err("api-encrypt/bad-opt",
        "apiEncrypt: sessionStore must expose { get(sid), set(sid, row, opts?), delete(sid) } " +
        "(b.cache.create() is shape-compatible)", 500);
    }
  }
  var sessionStore = (keying === "per-session" && opts.sessionStore)
    ? opts.sessionStore
    : (keying === "per-session" ? _defaultSessionStore() : null);
  validateOpts.observabilityShape(opts.observability,
    "apiEncrypt", ApiEncryptError, "api-encrypt/bad-opt");
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

  var _isExempt = requestHelpers.makeSkipMatcher({ skipPaths: exemptPaths }, "middleware.apiEncrypt");

  function _matchesContentType(req) {
    if (!contentTypes) return true;
    var ct = req.headers && (req.headers["content-type"] || req.headers["Content-Type"]);
    if (typeof ct !== "string") return false;
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
    store.purgeExpired().catch(function (e) {
      try {
        logger().warn("nonce-store prune failed: " + ((e && e.message) || String(e)));
      } catch (_e) { /* logger best-effort */ }
    });
  }

  function _encodeEnvelope(data, sessionKey, sessionCtx) {
    var ptBuf = Buffer.from(JSON.stringify(data), "utf8");
    var ctBuf = bCrypto.encryptPacked(ptBuf, sessionKey,
      _responseAad(sessionCtx ? sessionCtx.sid : undefined,
                   sessionCtx ? sessionCtx.responseCtr : undefined));
    var encrypted = { _ct: ctBuf.toString("base64") };
    if (sessionCtx) {
      encrypted._sid = sessionCtx.sid;
      encrypted._ctr = sessionCtx.responseCtr;
    }
    return encrypted;
  }

  function _installRejectEncoder(req, sessionKey, sid, responseCtr) {
    req.apiEncryptRejectEncode = function (body) {
      return _encodeEnvelope(body, sessionKey, { sid: sid, responseCtr: responseCtr });
    };
  }

  function _wrapResJson(res, sessionKey, sessionCtx) {
    var origJson = res.json;
    res.json = function (data) {
      try {
        var encrypted = _encodeEnvelope(data, sessionKey, sessionCtx);
        if (typeof origJson === "function") {
          return origJson.call(res, encrypted);
        }
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

  function _decryptEkToSessionKey(ek) {
    for (var ki = 0; ki < keypairs.length; ki++) {
      try {
        var sessionKeyB64 = bCrypto.decrypt(ek, keypairs[ki]);
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
      return _writeRejection(req, res, HTTP_STATUS.BAD_REQUEST, { error: "encrypted-payload-required" });
    }

    var now = Date.now();
    var ct = body._ct, ts = body._ts;
    if (typeof ct !== "string" || typeof ts !== "number") {
      _emitFailure(req, "shape");
      return _writeRejection(req, res, HTTP_STATUS.BAD_REQUEST, { error: "encrypted-payload-required" });
    }
    if (Math.abs(now - ts) > replayWindowMs) {
      _emitFailure(req, "stale");
      return _writeRejection(req, res, HTTP_STATUS.BAD_REQUEST, { error: "encrypted-payload-rejected" });
    }

    var ek = body._ek, nonce = body._nonce, sid = body._sid, ctr = body._ctr;
    var sessionKey = null;
    var sessionCtx = null;
    var session = null;

    if (typeof ek === "string" && typeof nonce === "string") {
      var nonceHash = bCrypto.sha3Hash(nonce, "hex");
      var expireAt = now + replayWindowMs;
      var freshNonce;
      try { freshNonce = await store.checkAndInsert(nonceHash, expireAt); }
      catch (_e) {
        _emitFailure(req, "nonce-store-error");
        return _writeRejection(req, res, HTTP_STATUS.INTERNAL_SERVER_ERROR, { error: "nonce-store-unavailable" });
      }
      if (!freshNonce) {
        _emitFailure(req, "replay");
        return _writeRejection(req, res, HTTP_STATUS.BAD_REQUEST, { error: "encrypted-payload-rejected" });
      }
      sessionKey = _decryptEkToSessionKey(ek);
      if (!sessionKey) {
        _emitFailure(req, "tag");
        return _writeRejection(req, res, HTTP_STATUS.BAD_REQUEST, { error: "encrypted-payload-rejected" });
      }
      if (keying === "per-session") {
        if (!_validSid(sid)) {
          _emitFailure(req, "shape");
          return _writeRejection(req, res, HTTP_STATUS.BAD_REQUEST, { error: "encrypted-payload-required" });
        }
        if (!numericBounds.isNonNegativeFiniteInt(ctr)) {
          _emitFailure(req, "shape");
          return _writeRejection(req, res, HTTP_STATUS.BAD_REQUEST, { error: "encrypted-payload-required" });
        }
        session = {
          sessionKey:       sessionKey,
          lastReqCtr:       ctr,
          responsesEmitted: 1,
          createdAt:        now,
          lastUsedAt:       now,
          expiresAt:        now + sessionTtlMs,
        };
        try { await sessionStore.set(sid, session, { ttlMs: sessionTtlMs }); }
        catch (_e) {
          _emitFailure(req, "session-store-error");
          return _writeRejection(req, res, HTTP_STATUS.INTERNAL_SERVER_ERROR, { error: "session-store-unavailable" });
        }
        _emitObs("apiEncrypt.session.created", 1, { mode: "per-session" });
        _emitSessionAudit("apiEncrypt.session.created", {
          actor: requestHelpers.extractActorContext(req),
          metadata: { sid: sid, expiresAt: session.expiresAt },
          requestId: req.requestId || null,
        });
        sessionCtx = { sid: sid, responseCtr: 1 };
        _installRejectEncoder(req, sessionKey, sid, 1);
      }
    } else if (keying === "per-session" &&
               typeof sid === "string" && typeof ctr === "number") {
      if (!_validSid(sid)) {
        _emitFailure(req, "shape");
        return _writeRejection(req, res, HTTP_STATUS.BAD_REQUEST, { error: "encrypted-payload-required" });
      }
      if (!numericBounds.isNonNegativeFiniteInt(ctr)) {
        _emitFailure(req, "shape");
        return _writeRejection(req, res, HTTP_STATUS.BAD_REQUEST, { error: "encrypted-payload-required" });
      }
      try { session = await sessionStore.get(sid); }
      catch (_e) {
        _emitFailure(req, "session-store-error");
        return _writeRejection(req, res, HTTP_STATUS.INTERNAL_SERVER_ERROR, { error: "session-store-unavailable" });
      }
      if (!session) {
        _emitObs("apiEncrypt.session.unknown", 1, {});
        _emitFailure(req, "session-unknown");
        return _writeRejection(req, res, HTTP_STATUS.UNAUTHORIZED, { error: "session-unknown" });
      }
      sessionKey = session.sessionKey;
      if (Buffer.isBuffer(sessionKey) === false) {
        if (typeof sessionKey === "string") {
          sessionKey = Buffer.from(sessionKey, "base64");
        } else if (sessionKey && sessionKey.type === "Buffer" && Array.isArray(sessionKey.data)) {
          sessionKey = Buffer.from(sessionKey.data);
        } else if (sessionKey instanceof Uint8Array) {
          sessionKey = Buffer.from(sessionKey);
        }
      }
      if (!Buffer.isBuffer(sessionKey) || sessionKey.length !== SESSION_KEY_BYTES) {
        sessionKey = null;
        _emitFailure(req, "session-store-error");
        return _writeRejection(req, res, HTTP_STATUS.INTERNAL_SERVER_ERROR, { error: "session-store-unavailable" });
      }
      _installRejectEncoder(req, sessionKey, sid, session.responsesEmitted + 1);
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
        return _writeRejection(req, res, HTTP_STATUS.UNAUTHORIZED, { error: "session-expired" });
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
        return _writeRejection(req, res, HTTP_STATUS.UNAUTHORIZED, { error: "session-rotation-required" });
      }
      if (ctr <= session.lastReqCtr) {
        _emitObs("apiEncrypt.session.replay_rejected", 1, {});
        _emitSessionAudit("apiEncrypt.session.replay_rejected", {
          outcome: "denied",
          actor: requestHelpers.extractActorContext(req),
          metadata: { sid: sid, receivedCtr: ctr, lastSeen: session.lastReqCtr },
          requestId: req.requestId || null,
        });
        _emitFailure(req, "counter-replay");
        return _writeRejection(req, res, HTTP_STATUS.BAD_REQUEST, { error: "encrypted-payload-rejected" }, { plaintext: true });
      }
      var ctrKey = "ctr:" + sid + ":" + ctr;
      var ctrFresh;
      try { ctrFresh = await store.checkAndInsert(ctrKey, session.expiresAt); }
      catch (_e) {
        _emitFailure(req, "nonce-store-error");
        return _writeRejection(req, res, HTTP_STATUS.INTERNAL_SERVER_ERROR, { error: "nonce-store-unavailable" });
      }
      if (!ctrFresh) {
        _emitObs("apiEncrypt.session.replay_rejected", 1, { lane: "atomic" });
        _emitSessionAudit("apiEncrypt.session.replay_rejected", {
          outcome: "denied",
          actor: requestHelpers.extractActorContext(req),
          metadata: { sid: sid, receivedCtr: ctr, lane: "atomic" },
          requestId: req.requestId || null,
        });
        _emitFailure(req, "counter-replay");
        return _writeRejection(req, res, HTTP_STATUS.BAD_REQUEST, { error: "encrypted-payload-rejected" }, { plaintext: true });
      }
      session.lastReqCtr = ctr;
      session.lastUsedAt = now;
      session.responsesEmitted += 1;
      try { await sessionStore.set(sid, session, { ttlMs: session.expiresAt - now }); }
      catch (_e) { /* best-effort — request still proceeds */ }
      sessionCtx = { sid: sid, responseCtr: session.responsesEmitted };
    } else {
      _emitFailure(req, "shape");
      return _writeRejection(req, res, HTTP_STATUS.BAD_REQUEST, { error: "encrypted-payload-required" });
    }

    var clearObj;
    try {
      var ctBuf = Buffer.from(ct, "base64");
      var ptBuf = bCrypto.decryptPacked(ctBuf, sessionKey, _requestAad(ts, nonce, sid, ctr));
      clearObj = safeJson.parse(ptBuf.toString("utf8"), { maxBytes: maxDecryptedBytes });
    } catch (_e) {
      _emitFailure(req, "tag");
      return _writeRejection(req, res, HTTP_STATUS.BAD_REQUEST, { error: "encrypted-payload-rejected" });
    }

    req.body = clearObj;
    req.apiEncryptSessionKey = sessionKey;
    if (sessionCtx) req.apiEncryptSession = { sid: sessionCtx.sid };

    req.apiEncryptEncode = function (data) { return _encodeEnvelope(data, sessionKey, sessionCtx); };

    _wrapResJson(res, sessionKey, sessionCtx);
    _maybePrune();

    return next();
  }

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
    if (typeof store.close === "function") store.close();
    if (sessionStore && typeof sessionStore.close === "function") sessionStore.close();
  };
  middleware.sessionStore = sessionStore;
  middleware.keying = keying;

  return middleware;
}

function client(opts) {
  opts = opts || {};
  validateOpts(opts, ["pubkey", "maxDecryptedBytes", "keying"], "middleware.apiEncrypt.client");
  if (!opts.pubkey || typeof opts.pubkey !== "object") {
    throw _err("api-encrypt/client-invalid-pubkey",
      "apiEncrypt.client: opts.pubkey is required ({ publicKey, ecPublicKey })", 500);
  }
  if (typeof opts.pubkey.publicKey !== "string" ||
      typeof opts.pubkey.ecPublicKey !== "string") {
    throw _err("api-encrypt/client-invalid-pubkey",
      "apiEncrypt.client: pubkey.publicKey + ecPublicKey must be PEM strings", 500);
  }
  var pubkey = opts.pubkey;
  validateOpts.optionalPositiveInt(opts.maxDecryptedBytes,
    "apiEncrypt.client: maxDecryptedBytes", ApiEncryptError, "api-encrypt/client-bad-opt");
  var maxDecryptedBytes = opts.maxDecryptedBytes != null
    ? opts.maxDecryptedBytes
    : C.BYTES.mib(4);
  var keying = opts.keying != null ? opts.keying : "per-request";
  if (keying !== "per-request" && keying !== "per-session") {
    throw _err("api-encrypt/client-bad-opt",
      "apiEncrypt.client: keying must be 'per-request' (default) or 'per-session', got " +
      JSON.stringify(opts.keying), 500);
  }

  if (keying === "per-request") {
    return { encryptRequest: _encryptPerRequest, keying: keying };
  }

  var perSessionKey = null;
  var perSessionSid = null;
  var perSessionReqCtr = 0;
  var perSessionLastResCtr = 0;

  function _resetSession() {
    perSessionKey = bCrypto.generateBytes(SESSION_KEY_BYTES);
    perSessionSid = _generateUuidV4();
    perSessionReqCtr = 0;
    perSessionLastResCtr = 0;
  }

  function _decryptPerSessionResponse(responseBody) {
    if (!responseBody || typeof responseBody !== "object" ||
        typeof responseBody._ct !== "string") {
      throw _err("api-encrypt/client-response-shape",
        "apiEncrypt.client: response missing _ct field");
    }
    if (typeof responseBody._sid !== "string" || responseBody._sid !== perSessionSid) {
      throw _err("api-encrypt/client-response-sid",
        "apiEncrypt.client: response sid does not match opened session");
    }
    if (typeof responseBody._ctr !== "number" || responseBody._ctr <= perSessionLastResCtr) {
      throw _err("api-encrypt/client-response-replay",
        "apiEncrypt.client: response counter is not strictly increasing " +
        "(got " + responseBody._ctr + ", lastSeen " + perSessionLastResCtr + ")");
    }
    var resCtBuf = Buffer.from(responseBody._ct, "base64");
    var resPtBuf;
    try {
      resPtBuf = bCrypto.decryptPacked(resCtBuf, perSessionKey,
        _responseAad(responseBody._sid, responseBody._ctr));
    } catch (_e) {
      throw _err("api-encrypt/client-response-tampered",
        "apiEncrypt.client: response failed authenticated decryption (ciphertext or envelope metadata tampered)");
    }
    perSessionLastResCtr = responseBody._ctr;
    return safeJson.parse(resPtBuf.toString("utf8"), { maxBytes: maxDecryptedBytes });
  }

  function _encryptPerSession(payload) {
    if (payload === undefined) payload = null;
    if (!perSessionKey) _resetSession();
    var ts = Date.now();
    perSessionReqCtr += 1;
    var ptBuf = Buffer.from(JSON.stringify(payload), "utf8");
    var ctBuf;
    var body;
    if (perSessionReqCtr === 1) {
      var ek = bCrypto.encrypt(perSessionKey.toString("base64"), pubkey);
      var nonce = bCrypto.generateBytes(REQUEST_NONCE_BYTES).toString("hex");
      ctBuf = bCrypto.encryptPacked(ptBuf, perSessionKey,
        _requestAad(ts, nonce, perSessionSid, perSessionReqCtr));
      body = {
        _ek:    ek,
        _ct:    ctBuf.toString("base64"),
        _ts:    ts,
        _nonce: nonce,
        _sid:   perSessionSid,
        _ctr:   perSessionReqCtr,
      };
    } else {
      ctBuf = bCrypto.encryptPacked(ptBuf, perSessionKey,
        _requestAad(ts, undefined, perSessionSid, perSessionReqCtr));
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
    var sessionKey = bCrypto.generateBytes(SESSION_KEY_BYTES);
    var ek = bCrypto.encrypt(sessionKey.toString("base64"), pubkey);
    var requestNonce = bCrypto.generateBytes(REQUEST_NONCE_BYTES).toString("hex");
    var ts = Date.now();
    var ptBuf = Buffer.from(JSON.stringify(payload), "utf8");
    var ctBuf = bCrypto.encryptPacked(ptBuf, sessionKey,
      _requestAad(ts, requestNonce, undefined, undefined));
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
          throw _err("api-encrypt/client-response-shape",
            "apiEncrypt.client: response missing _ct field");
        }
        var resCtBuf = Buffer.from(responseBody._ct, "base64");
        var resPtBuf;
        try {
          resPtBuf = bCrypto.decryptPacked(resCtBuf, sessionKey,
            _responseAad(undefined, undefined));
        } catch (_e) {
          throw _err("api-encrypt/client-response-tampered",
            "apiEncrypt.client: response failed authenticated decryption (ciphertext or envelope metadata tampered)");
        }
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

function _requestAad(ts, nonce, sid, ctr) {
  return "blamejs-apienc/req/1|ts=" + String(ts) +
         "|nonce=" + (typeof nonce === "string" ? nonce : "") +
         "|sid=" + (typeof sid === "string" ? sid : "") +
         "|ctr=" + (typeof ctr === "number" ? String(ctr) : "");
}

function _responseAad(sid, ctr) {
  return "blamejs-apienc/res/1|sid=" + (typeof sid === "string" ? sid : "") +
         "|ctr=" + (typeof ctr === "number" ? String(ctr) : "");
}

function _generateUuidV4() {
  var b = bCrypto.generateBytes(16);
  b[6] = (b[6] & 0x0f) | 0x40;
  b[8] = (b[8] & 0x3f) | 0x80;
  var hex = b.toString("hex");
  return hex.slice(0, 8) + "-" +
         hex.slice(8, 12) + "-" +
         hex.slice(12, 16) + "-" +
         hex.slice(16, 20) + "-" +
         hex.slice(20, 32);
}

function httpClientEncrypted(opts) {
  opts = opts || {};
  validateOpts(opts, [
    "pubkey", "baseUrl", "headers", "method", "maxDecryptedBytes", "keying",
    "responseMode",
  ], "middleware.apiEncrypt.httpClient");
  if (!opts.pubkey) {
    throw _err("api-encrypt/client-invalid-pubkey",
      "httpClient.encrypted: opts.pubkey is required (the callee's bootstrap doc)", 500);
  }
  validateOpts.optionalPositiveInt(opts.maxDecryptedBytes,
    "httpClient.encrypted: maxDecryptedBytes", ApiEncryptError, "api-encrypt/client-bad-opt");
  var maxDecryptedBytes = opts.maxDecryptedBytes != null
    ? opts.maxDecryptedBytes
    : C.BYTES.mib(4);
  var keying = opts.keying != null ? opts.keying : "per-request";
  var responseModeDefault = opts.responseMode != null ? opts.responseMode : "reject";
  if (responseModeDefault !== "reject" && responseModeDefault !== "passthrough") {
    throw _err("api-encrypt/client-bad-opt",
      "httpClient.encrypted: responseMode must be 'reject' (default) or 'passthrough', got " +
      JSON.stringify(opts.responseMode), 500);
  }
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
        throw _err("api-encrypt/client-invalid-url",
          "httpClient.encrypted.request: { path } requires opts.baseUrl at create time", 500);
      }
      return baseUrl + (reqOpts.path[0] === "/" ? reqOpts.path : "/" + reqOpts.path);
    }
    throw _err("api-encrypt/client-invalid-url",
      "httpClient.encrypted.request: requires { url } or { path } (with opts.baseUrl)", 500);
  }

  async function request(reqOpts) {
    reqOpts = reqOpts || {};
    var url = _resolveUrl(reqOpts);
    var mode = (reqOpts && reqOpts.responseMode != null) ? reqOpts.responseMode : responseModeDefault;
    if (mode !== "reject" && mode !== "passthrough") {
      throw _err("api-encrypt/client-bad-opt",
        "httpClient.encrypted.request: responseMode must be 'reject' (default) or 'passthrough', got " +
        JSON.stringify(reqOpts.responseMode), 500);
    }
    var encrypted = clientCtx.encryptRequest(
      reqOpts.body !== undefined ? reqOpts.body : null
    );

    var headers = Object.assign({}, defaultHdrs, reqOpts.headers || {});
    headers["Content-Type"] = "application/json";

    var passThrough = {};
    var passable = ["allowedProtocols", "allowInternal", "timeoutMs", "idleTimeoutMs",
                    "maxResponseBytes", "signal", "agent", "errorClass"];
    for (var i = 0; i < passable.length; i++) {
      if (reqOpts[passable[i]] !== undefined) passThrough[passable[i]] = reqOpts[passable[i]];
    }

    var rawBody = Buffer.from(JSON.stringify(encrypted.body), "utf8");
    var requestArgs = Object.assign({
      url:     url,
      method:  reqOpts.method || defaultMethod,
      headers: headers,
      body:    rawBody,
    }, passThrough);
    if (mode === "passthrough") {
      requestArgs.responseMode = "always-resolve";
    }
    var resp = await httpClient().request(requestArgs);

    var ok = resp.statusCode >= 200 && resp.statusCode < 300;

    if (!resp.body || resp.body.length === 0) {
      return { statusCode: resp.statusCode, headers: resp.headers, body: null, ok: ok };
    }
    var parsed;
    try { parsed = safeJson.parse(resp.body.toString("utf8"), { maxBytes: maxDecryptedBytes }); }
    catch (e) {
      throw _err("api-encrypt/client-response-not-json",
        "httpClient.encrypted: response body is not valid JSON: " + e.message);
    }
    var body;
    if (mode === "passthrough") {
      body = (parsed && typeof parsed._ct === "string") ? encrypted.decryptResponse(parsed) : parsed;
    } else {
      body = encrypted.decryptResponse(parsed);
    }
    return {
      statusCode: resp.statusCode,
      headers:    resp.headers,
      body:       body,
      ok:         ok,
    };
  }

  return { request: request };
}

module.exports = Object.assign(create, {
  client:           client,
  httpClient:       httpClientEncrypted,
  ApiEncryptError:  ApiEncryptError,
});
