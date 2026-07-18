// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module b.webhook
 * @featured true
 * @nav    Communication
 * @title  Webhook
 *
 * @intro
 *   Outbound webhook delivery with cryptographic signing in a single
 *   `Webhook-Signature` header, retry + dead-letter via `b.retry`, and
 *   idempotency keys baked into the signed string so a captured
 *   signature cannot be replayed with a fresh id. Inbound verification
 *   is the symmetric primitive: `verifier()` returns a middleware that
 *   parses the header, enforces the timestamp window, finds a matching
 *   kid, runs constant-time signature compare, and (when configured)
 *   consults a nonce store for replay defense.
 *
 *   Algorithms: `hmac-sha3-512` (symmetric, kid → Buffer/string secret)
 *   or `pqc-pem` (asymmetric — SLH-DSA-SHAKE-256f / ML-DSA-87 / ML-DSA-65,
 *   auto-detected by Node from the PEM). No classical (Ed25519 / RSA /
 *   ECDSA) signature scheme is exposed.
 *
 *   Signed string is prefix-bound to defend against algorithm- and
 *   key-substitution attacks: `<algo>.<kid>.<timestamp>.<id>.<body>`.
 *   Header is the Stripe-shape `t=<seconds>,id=<uuid>,<kid>=<sig>`;
 *   `t` and `id` are reserved segment names, every other pair is a
 *   kid → signature mapping. The signer emits exactly one kid; the
 *   verifier accepts any number so operators rotating keys point the
 *   verifier at both old + new keys and migrate signers progressively.
 *
 *   PQC signatures are emitted as base64url (~40 KB for SLH-DSA-SHAKE-
 *   256f, vs ~59 KB hex) to fit common front-end header caps; the
 *   verifier accepts EITHER encoding for transition windows.
 *
 *   Replay defense: passing a `nonceStore` (any object exposing
 *   `checkAndInsert(nonce, expireAt) → bool/Promise<bool>`) records
 *   seen ids; a second delivery with the same id rejects with REPLAY.
 *   `b.nonceStore` is the reference implementation; operators plug in
 *   Redis / SQL by satisfying the same shape.
 *
 *   Audit defaults are ON for both success and failure on both sides
 *   — the inbound verify IS the auditable boundary event, not a
 *   precursor to one. Operators with extreme volume opt out via
 *   `auditSuccess: false`; failures remain on regardless.
 *
 * @card
 *   Outbound webhook delivery with cryptographic signing in a single `Webhook-Signature` header, retry + dead-letter via `b.retry`, and idempotency keys baked into the signed string so a captured signature cannot be replayed with a fresh id.
 */

var nodeCrypto = require("node:crypto");
var numericBounds = require("./numeric-bounds");
var bCrypto = require("./crypto");
var safeBuffer = require("./safe-buffer");
var safeUrl = require("./safe-url");
var retryHelper = require("./retry");
var C = require("./constants");
var lazyRequire = require("./lazy-require");
var numericChecks = require("./numeric-checks");
var requestHelpers = require("./request-helpers");
// Lazy — ssrf-guard pulls in the DNS/network stack; only touched on send().
var ssrfGuard = lazyRequire(function () { return require("./ssrf-guard"); });
// Lazy — http-client pulls in node:http / node:https / node:http2; only the
// outbound send() path touches it. Keeping it lazy lets b.webhook.verify (HMAC
// + timing-safe compare only) load in a Worker / edge runtime with no Node
// networking module available.
var httpClient = lazyRequire(function () { return require("./http-client"); });
var validateOpts = require("./validate-opts");
var { WebhookError } = require("./framework-error");
// b.webhook.dispatcher — durable signed-webhook delivery store. Lives in its
// own module (distinct domain: persistence) and pulls the SQL stack (and so
// node:fs). Lazy — only resolved when b.webhook.dispatcher is accessed — so
// importing the webhook module for the inbound verify path stays free of the
// persistence/networking stack and loads in a Worker / edge runtime. The
// module lazyRequires this file back, so the cycle stays deferred on both ends.
var webhookDispatcher = lazyRequire(function () { return require("./webhook-dispatcher"); });

var observability = lazyRequire(function () { return require("./observability"); });

function _emitEvent(n, v, l) { observability().safeEvent(n, v, l || {}); }

var _err = WebhookError.factory;

// ---- Constants ----

var ALGOS = Object.freeze({
  HMAC_SHA3_512: "hmac-sha3-512",
  PQC_PEM:       "pqc-pem",
});

// PQC signature algorithms accepted under the "pqc-pem" algo. Node
// auto-detects the active algorithm from the PEM (asymmetricKeyType ===
// "ml-dsa-65" | "ml-dsa-87" | "slh-dsa-shake-256f"). When the operator
// pins `pqcAlgorithm` at signer/verifier construction the framework
// asserts the PEM matches at config time so a key-rotation that
// accidentally swapped algorithms surfaces at boot, not at first
// signature failure. Permitted values match the audit-signing primitive
// (lib/audit-sign.js SUPPORTED_SIGNING_ALGS).
var PQC_ALGORITHMS = Object.freeze(["slh-dsa-shake-256f", "ml-dsa-87", "ml-dsa-65"]);

var HEADER = Object.freeze({
  SIGNATURE: "Webhook-Signature",
});

var DEFAULTS = Object.freeze({
  toleranceMs:     C.TIME.minutes(5),
  clockSkewMs:     C.TIME.minutes(1),
  signatureHeader: HEADER.SIGNATURE,
  // Audit defaults: BOTH success and failure default ON. The webhook
  // verify is the framework boundary where an inbound message gets
  // accepted — that acceptance IS the audit-worthy event, not a
  // precursor to one. "Inbound webhook id <X> verified from kid <Y>
  // at time T" is the compliance trail. The send side mirrors:
  // outbound delivery success/failure to a partner is also a
  // standalone audit event. Operators with extreme volume opt out
  // via auditSuccess: false; failures remain on regardless.
  auditFailures:   true,
  auditSuccess:    true,
});

// ---- Call-site validation helpers (throw on bad input) ----

var _isPositiveInt  = numericChecks.isPositiveInt;
var _isNonNegFinite = numericChecks.isFiniteNonNegative;
function _hasOwn(obj, k) { return Object.prototype.hasOwnProperty.call(obj, k); }
function _objectKeys(obj) { return Object.keys(obj); }

function _validateAlgo(algo) {
  if (algo !== ALGOS.HMAC_SHA3_512 && algo !== ALGOS.PQC_PEM) {
    throw _err("BAD_OPT", "webhook: algo must be one of " +
      JSON.stringify([ALGOS.HMAC_SHA3_512, ALGOS.PQC_PEM]) + ", got " + JSON.stringify(algo));
  }
}

function _validateKeysShape(name, algo, keys, side) {
  if (!keys || typeof keys !== "object" || Array.isArray(keys)) {
    throw _err("BAD_OPT", name + ": keys must be a non-empty object map of kid → key, got " +
      typeof keys);
  }
  var kids = _objectKeys(keys);
  if (kids.length === 0) {
    throw _err("BAD_OPT", name + ": keys must have at least one kid entry");
  }
  for (var i = 0; i < kids.length; i++) {
    var kid = kids[i];
    if (kid.length === 0 || /[,=\s]/.test(kid)) {
      throw _err("BAD_OPT", name + ": kid must be non-empty and contain no comma/equals/whitespace, got " +
        JSON.stringify(kid));
    }
    if (kid === "t" || kid === "id") {
      throw _err("BAD_OPT", name + ": kid '" + kid + "' is reserved (collides with header field)");
    }
    var k = keys[kid];
    if (algo === ALGOS.HMAC_SHA3_512) {
      if (!Buffer.isBuffer(k) && typeof k !== "string") {
        throw _err("BAD_OPT", name + ": HMAC key for kid '" + kid +
          "' must be a Buffer or string, got " + typeof k);
      }
      if (k.length === 0) {
        throw _err("BAD_OPT", name + ": HMAC key for kid '" + kid + "' must be non-empty");
      }
    } else if (algo === ALGOS.PQC_PEM) {
      if (side === "signer") {
        if (!k || typeof k !== "object" || Array.isArray(k) ||
            (typeof k.privateKey !== "string" && !Buffer.isBuffer(k.privateKey)) ||
            (typeof k.publicKey  !== "string" && !Buffer.isBuffer(k.publicKey))) {
          throw _err("BAD_OPT", name + ": PQC signer key for kid '" + kid +
            "' must be { privateKey, publicKey } as PEM strings/Buffers");
        }
      } else {
        if (typeof k !== "string" && !Buffer.isBuffer(k)) {
          throw _err("BAD_OPT", name + ": PQC verifier key for kid '" + kid +
            "' must be a PEM string/Buffer (public key)");
        }
      }
    }
  }
}

// _detectPqcAlgorithmFromPem — read asymmetricKeyType from a PEM key.
// Used to assert the operator-pinned pqcAlgorithm matches the PEM at
// config time. Returns null on un-parseable input (caller already
// validated key shape, so this only fires for malformed PEM).
function _detectPqcAlgorithmFromPem(pem) {
  try {
    var k = typeof pem === "string"
      ? nodeCrypto.createPrivateKey(pem)
      : nodeCrypto.createPrivateKey({ key: pem, format: "pem" });
    return k.asymmetricKeyType;
  } catch (_e1) {
    try {
      var pubk = typeof pem === "string"
        ? nodeCrypto.createPublicKey(pem)
        : nodeCrypto.createPublicKey({ key: pem, format: "pem" });
      return pubk.asymmetricKeyType;
    } catch (_e2) { return null; }
  }
}

function _assertPqcAlgorithmMatches(name, pqcAlgorithm, keys, side) {
  if (typeof pqcAlgorithm !== "string") return;
  if (PQC_ALGORITHMS.indexOf(pqcAlgorithm) === -1) {
    throw _err("BAD_OPT", name + ": pqcAlgorithm must be one of " +
      PQC_ALGORITHMS.join(", ") + ", got " + JSON.stringify(pqcAlgorithm));
  }
  var kids = Object.keys(keys);
  for (var i = 0; i < kids.length; i++) {
    var k = keys[kids[i]];
    var pem = side === "signer" ? (k.privateKey || k.publicKey) : k;
    var detected = _detectPqcAlgorithmFromPem(pem);
    if (detected && detected !== pqcAlgorithm) {
      throw _err("BAD_OPT", name + ": pqcAlgorithm '" + pqcAlgorithm +
        "' does not match PEM (kid '" + kids[i] + "' has asymmetricKeyType=" +
        JSON.stringify(detected) + ")");
    }
  }
}

function _validateBody(body) {
  if (typeof body !== "string" && !Buffer.isBuffer(body)) {
    throw _err("BAD_BODY", "webhook: body must be a string or Buffer, got " + typeof body);
  }
}

// ---- Signed-string composition ----

function _composeSignedString(algo, kid, timestamp, id, body) {
  var prefix = algo + "." + kid + "." + timestamp + "." + id + ".";
  if (Buffer.isBuffer(body)) {
    return Buffer.concat([Buffer.from(prefix, "utf8"), body]);
  }
  return Buffer.from(prefix + body, "utf8");
}

// ---- Sign / verify primitives ----

function _hmacSign(key, data) {
  return bCrypto.hmacSha3(key, data);    // hex string
}

function _hmacVerify(key, data, expectedHex) {
  if (!safeBuffer.isHex(expectedHex)) return false;
  var actualHex = bCrypto.hmacSha3(key, data);
  return bCrypto.timingSafeEqual(actualHex, expectedHex);
}

// PQC signatures encode as base64url. SLH-DSA-SHAKE-256f signatures
// are ~29.5 KB binary → ~59 KB hex but only ~40 KB base64url. The hex
// form blew past common front-end limits (nginx default 8 KB / Cloudflare
// default 16 KB / many CDN edge limits 32 KB). base64url keeps the
// signature in-header for the bulk of operators while still allowing
// body-bound signatures (operator passes the wire-encoded sig in body
// when even base64url is too large for their topology).
//
// Verification accepts EITHER encoding for a transition window: a
// base64url-shaped value is decoded as base64url; otherwise a hex-
// shaped value is decoded as hex. New signatures are emitted as
// base64url; old hex-encoded signatures still verify.
function _pqcSign(privateKeyPem, data) {
  return bCrypto.sign(data, privateKeyPem).toString("base64url");
}

var _BASE64URL_RE = safeBuffer.BASE64URL_RE;

function _pqcVerify(publicKeyPem, data, expectedSig) {
  if (typeof expectedSig !== "string" || expectedSig.length === 0) return false;
  var sigBuf;
  try {
    if (_BASE64URL_RE.test(expectedSig) &&                                       // allow:regex-no-length-cap — sig length bounded by header parser cap
        !/^[0-9a-f]+$/.test(expectedSig)) {                                      // allow:regex-no-length-cap — same
      sigBuf = Buffer.from(expectedSig, "base64url");
    } else if (safeBuffer.isHex(expectedSig) && (expectedSig.length % 2) === 0) {
      sigBuf = Buffer.from(expectedSig, "hex");
    } else {
      return false;
    }
  } catch (_e) { return false; }
  try { return bCrypto.verify(data, sigBuf, publicKeyPem); }
  catch (_e) { return false; }
}

// ---- Header parsing ----
//
// Format:  t=<seconds>,id=<uuid>,<kid>=<hex>[,<kid>=<hex>]*
// `t` and `id` are reserved segment names; everything else is treated as
// a kid → signature pair. Whitespace tolerated around commas.

function _parseSignatureHeader(headerValue) {
  var segs = requestHelpers.parseListHeader(headerValue);
  var t = null, id = null, sigs = {};
  for (var i = 0; i < segs.length; i++) {
    var seg = segs[i];
    var eq = seg.indexOf("=");
    if (eq <= 0) continue;            // skip malformed segments rather than failing whole header
    var name = seg.slice(0, eq);
    var value = seg.slice(eq + 1);
    if (name === "t") t = value;
    else if (name === "id") id = value;
    else if (name.length > 0) sigs[name] = value;   // kid → sig hex
  }
  return { t: t, id: id, sigs: sigs };
}

// ---- Signer ----

function _validateSignerOpts(opts) {
  validateOpts.requireObject(opts, "webhook.signer", WebhookError);
  _validateAlgo(opts.algo);
  _validateKeysShape("webhook.signer", opts.algo, opts.keys, "signer");
  var kids = _objectKeys(opts.keys);
  if (opts.defaultKid !== undefined) {
    if (!_hasOwn(opts.keys, opts.defaultKid)) {
      throw _err("BAD_OPT", "webhook.signer: defaultKid '" + opts.defaultKid +
        "' not present in keys (have: " + JSON.stringify(kids) + ")");
    }
  } else if (kids.length > 1) {
    throw _err("BAD_OPT", "webhook.signer: defaultKid required when keys has " +
      kids.length + " entries");
  }
  validateOpts.optionalNonEmptyString(opts.signatureHeader, "webhook.signer: signatureHeader", WebhookError);
  validateOpts.optionalFunction(opts.idGenerator, "webhook.signer: idGenerator", WebhookError);
  validateOpts.optionalFunction(opts.now, "webhook.signer: now", WebhookError);
  validateOpts.auditShape(opts.audit, "webhook.signer", WebhookError);
  if (opts.pqcAlgorithm !== undefined) {
    if (opts.algo !== ALGOS.PQC_PEM) {
      throw _err("BAD_OPT", "webhook.signer: pqcAlgorithm only meaningful with algo='pqc-pem'");
    }
    _assertPqcAlgorithmMatches("webhook.signer", opts.pqcAlgorithm, opts.keys, "signer");
  }
}

/**
 * @primitive b.webhook.signer
 * @signature b.webhook.signer(opts)
 * @since     0.1.0
 * @status    stable
 * @compliance soc2, pci-dss
 * @related   b.webhook.verifier
 *
 * Build an outbound signer. Returns `{ sign, headers, send }`: `sign`
 * computes the signature header pair for a body without doing I/O;
 * `headers` returns just the headers map; `send` performs the POST via
 * `b.httpClient.request` wrapped in `b.retry.withRetry`. Each call
 * generates a fresh idempotency `id` (ULID-shaped via `b.crypto.
 * generateToken` by default; operators override with `idGenerator`)
 * that's bound into the signed string so captured signatures cannot
 * replay with a different id.
 *
 * @opts
 *   algo:            "hmac-sha3-512" | "pqc-pem",
 *   keys:            { [kid]: Buffer | string }       // hmac
 *                  | { [kid]: { privateKey, publicKey } }  // pqc-pem
 *   defaultKid:      string,                          // required when keys has >1 kid
 *   pqcAlgorithm:    "slh-dsa-shake-256f" | "ml-dsa-87" | "ml-dsa-65",
 *   signatureHeader: string,                          // default "Webhook-Signature"
 *   idGenerator:     function () => string,
 *   now:             function () => number,           // ms
 *   retry:           object,                          // b.retry.withRetry opts
 *   http:            object,                          // b.httpClient.request opts
 *   audit:           object,                          // b.audit handle
 *   auditFailures:   boolean,                         // default true
 *   auditSuccess:    boolean,                         // default true
 *
 * @example
 *   var b = require("@blamejs/core");
 *   var signer = b.webhook.signer({
 *     algo:       "hmac-sha3-512",
 *     keys:       { v1: Buffer.from("0123456789abcdef0123456789abcdef") },
 *     defaultKid: "v1",
 *   });
 *   var headers = signer.headers('{"event":"user.created"}');
 *   // → { "Webhook-Signature": "t=1714500000,id=...,v1=<hex>" }
 */
function signer(opts) {
  _validateSignerOpts(opts);
  var algo = opts.algo;
  var cfg = validateOpts.applyDefaults(opts, DEFAULTS);
  var keys = opts.keys;
  var kids = _objectKeys(keys);
  var defaultKid = opts.defaultKid || kids[0];
  var sigHeader = cfg.signatureHeader;
  var idGen = opts.idGenerator || function () { return bCrypto.generateToken(C.BYTES.bytes(16)); };
  var nowFn = opts.now || function () { return Date.now(); };
  var retryOpts = opts.retry || retryHelper.DEFAULT_RETRY;
  var httpOpts = opts.http || {};
  var audit = opts.audit || null;
  var auditFailures = cfg.auditFailures;
  var auditSuccess  = cfg.auditSuccess;

  var _auditEmit = validateOpts.makeAuditEmitter(audit);

  function _signOne(body, kid) {
    _validateBody(body);
    var keyForKid = kids.indexOf(kid) === -1 ? null : keys[kid];
    if (keyForKid == null) {
      throw _err("BAD_OPT", "webhook.signer: unknown kid '" + kid + "'");
    }
    var timestamp = Math.floor(nowFn() / C.TIME.seconds(1));
    var id = idGen();
    if (typeof id !== "string" || id.length === 0 || /[,=\s]/.test(id)) {
      throw _err("BAD_OPT", "webhook.signer: idGenerator must return a non-empty string with no comma/equals/whitespace, got " + JSON.stringify(id));
    }
    var signed = _composeSignedString(algo, kid, timestamp, id, body);
    var sigHex;
    if (algo === ALGOS.HMAC_SHA3_512) {
      sigHex = _hmacSign(keyForKid, signed);
    } else {
      sigHex = _pqcSign(keyForKid.privateKey, signed);
    }
    return { kid: kid, timestamp: timestamp, id: id, signature: sigHex };
  }

  function sign(body, callOpts) {
    var kid = (callOpts && callOpts.kid) || defaultKid;
    var s = _signOne(body, kid);
    var headerValue = "t=" + s.timestamp + ",id=" + s.id + "," + s.kid + "=" + s.signature;
    var headers = {};
    headers[sigHeader] = headerValue;
    return {
      headers:   headers,
      timestamp: s.timestamp,
      id:        s.id,
      kid:       s.kid,
      signature: s.signature,
    };
  }

  function headers(body, callOpts) {
    return sign(body, callOpts).headers;
  }

  async function send(input) {
    if (!input || typeof input !== "object") {
      throw _err("BAD_OPT", "webhook.signer.send: input must be { url, body, headers? }");
    }
    var url = input.url;
    var body = input.body;
    safeUrl.parse(url, {
      allowedProtocols: httpOpts.allowedProtocols || safeUrl.ALLOW_HTTP_TLS,
      errorClass:       WebhookError,
    });
    // SSRF gate at the webhook layer: refuse private / loopback / link-local /
    // cloud-metadata destinations up front, before the retry loop. httpClient
    // also enforces this on every request, but checking here fails fast (no
    // wasted retries) and keeps the SSRF boundary explicit at the send() API
    // rather than relying on the transport's internal gate. allowInternal
    // mirrors the operator's http opts (its affirmative waiver).
    try {
      await ssrfGuard().checkUrl(url, { allowInternal: httpOpts.allowInternal === true });
    } catch (e) {
      if (e && e.isSsrfError) throw _err("SSRF_REFUSED", "webhook.signer.send: " + e.message);
      throw e;
    }
    _validateBody(body);
    var signed = sign(body, { kid: input.kid });
    var mergedHeaders = Object.assign({}, input.headers || {}, signed.headers);
    if (!mergedHeaders["Content-Type"] && !mergedHeaders["content-type"]) {
      mergedHeaders["Content-Type"] = Buffer.isBuffer(body)
        ? "application/octet-stream"
        : "application/json";
    }
    var requestOpts = Object.assign({
      method:           "POST",
      url:              url,
      headers:          mergedHeaders,
      body:             body,
      allowedProtocols: safeUrl.ALLOW_HTTP_TLS,
      errorClass:       WebhookError,
    }, httpOpts);
    requestOpts.headers = mergedHeaders;
    requestOpts.url = url;
    requestOpts.body = body;
    requestOpts.method = "POST";
    var hostLabel = "";
    try {
      hostLabel = safeUrl.parse(url, {
        allowedProtocols: httpOpts.allowedProtocols || safeUrl.ALLOW_HTTP_TLS,
        errorClass:       WebhookError,
      }).host;
    } catch (_e) { hostLabel = ""; }
    try {
      var res = await retryHelper.withRetry(function () {
        return httpClient().request(requestOpts);
      }, retryOpts);
      var statusCode = (res && (res.statusCode || res.status)) || 0;
      _emitEvent("webhook.send", 1, {
        outcome: statusCode >= 200 && statusCode < 300 ? "success" : "failure",
        status: statusCode,
        host: hostLabel,
      });
      if (auditSuccess && statusCode >= 200 && statusCode < 300) {
        _auditEmit("webhook.send", {
          resource: { kind: "webhook", id: hostLabel },
          outcome:  "success",
          metadata: { status: statusCode },
        });
      }
      if (auditFailures && (statusCode < 200 || statusCode >= 300)) {
        _auditEmit("webhook.send", {
          resource: { kind: "webhook", id: hostLabel },
          outcome:  "failure",
          reason:   "http-" + statusCode,
        });
      }
      return res;
    } catch (err) {
      _emitEvent("webhook.send", 1, {
        outcome: "failure", reason: "transport-error", host: hostLabel,
      });
      if (auditFailures) {
        _auditEmit("webhook.send", {
          resource: { kind: "webhook", id: hostLabel },
          outcome:  "failure",
          reason:   (err && err.code) || "transport-error",
        });
      }
      throw err;
    }
  }

  return {
    sign:    sign,
    headers: headers,
    send:    send,
  };
}

// ---- Verifier ----

function _validateVerifierOpts(opts) {
  validateOpts.requireObject(opts, "webhook.verifier", WebhookError);
  _validateAlgo(opts.algo);
  _validateKeysShape("webhook.verifier", opts.algo, opts.keys, "verifier");
  validateOpts.optionalFiniteNonNegative(opts.toleranceMs, "webhook.verifier: toleranceMs", WebhookError);
  validateOpts.optionalFiniteNonNegative(opts.clockSkewMs, "webhook.verifier: clockSkewMs", WebhookError);
  validateOpts.optionalNonEmptyString(opts.signatureHeader, "webhook.verifier: signatureHeader", WebhookError);
  validateOpts.optionalObjectWithMethod(opts.nonceStore, "checkAndInsert",
    "webhook.verifier: nonceStore", WebhookError, "BAD_OPT",
    "must implement checkAndInsert(nonce, expireAt)");
  validateOpts.optionalFunction(opts.now, "webhook.verifier: now", WebhookError);
  validateOpts.auditShape(opts.audit, "webhook.verifier", WebhookError);
  validateOpts.optionalBoolean(opts.auditFailures, "webhook.verifier: auditFailures", WebhookError);
  validateOpts.optionalBoolean(opts.auditSuccess, "webhook.verifier: auditSuccess", WebhookError);
  if (opts.pqcAlgorithm !== undefined) {
    if (opts.algo !== ALGOS.PQC_PEM) {
      throw _err("BAD_OPT", "webhook.verifier: pqcAlgorithm only meaningful with algo='pqc-pem'");
    }
    _assertPqcAlgorithmMatches("webhook.verifier", opts.pqcAlgorithm, opts.keys, "verifier");
  }
}

/**
 * @primitive b.webhook.verifier
 * @signature b.webhook.verifier(opts)
 * @since     0.1.0
 * @status    stable
 * @compliance soc2, pci-dss
 * @related   b.webhook.signer
 *
 * Build an inbound verifier. Returns `{ verify, middleware }`: `verify`
 * checks an explicit `{ body, headers }` pair and resolves to
 * `{ algo, kid, timestamp, id }` on success; `middleware` is an
 * Express-style middleware that pulls `req.bodyRaw` (requires
 * `b.middleware.bodyParser({ keepRawBody: true })`), verifies, and
 * stashes the result on `req.webhook`. Failures throw `WebhookError`
 * with a stable `code` (`MISSING_HEADER` / `BAD_HEADER_FORMAT` /
 * `EXPIRED` / `FUTURE` / `UNKNOWN_KID` / `BAD_SIGNATURE` / `REPLAY` /
 * ...) and the middleware translates them to HTTP 401 / 500.
 *
 * @opts
 *   algo:            "hmac-sha3-512" | "pqc-pem",
 *   keys:            { [kid]: Buffer | string }       // hmac
 *                  | { [kid]: string | Buffer },      // pqc-pem (PEM public key)
 *   pqcAlgorithm:    "slh-dsa-shake-256f" | "ml-dsa-87" | "ml-dsa-65",
 *   toleranceMs:     number,                          // default 5 minutes
 *   clockSkewMs:     number,                          // default 1 minute
 *   signatureHeader: string,                          // default "Webhook-Signature"
 *   nonceStore:      { checkAndInsert(nonce, expireAt) },
 *   now:             function () => number,
 *   audit:           object,
 *   auditFailures:   boolean,                         // default true
 *   auditSuccess:    boolean,                         // default true
 *
 * @example
 *   var b = require("@blamejs/core");
 *   var verifier = b.webhook.verifier({
 *     algo:        "hmac-sha3-512",
 *     keys:        { v1: Buffer.from("0123456789abcdef0123456789abcdef") },
 *     toleranceMs: b.constants.TIME.minutes(5),
 *   });
 *   // wire into a router:
 *   //   router.use(b.middleware.bodyParser({ keepRawBody: true }));
 *   //   router.post("/inbound", verifier.middleware(), function (req, res) {
 *   //     // req.webhook = { algo, kid, timestamp, id }
 *   //   });
 *   var mw = verifier.middleware();
 *   // → function (req, res, next) { ... }
 */
function verifier(opts) {
  _validateVerifierOpts(opts);
  var cfg = validateOpts.applyDefaults(opts, DEFAULTS);
  var algo = opts.algo;
  var keys = opts.keys;
  var toleranceMs = cfg.toleranceMs;
  var clockSkewMs = cfg.clockSkewMs;
  var sigHeader = cfg.signatureHeader.toLowerCase();
  var nonceStore = opts.nonceStore || null;
  var nowFn = opts.now || function () { return Date.now(); };
  var audit = opts.audit || null;
  var auditFailures = cfg.auditFailures;
  var auditSuccess  = cfg.auditSuccess;

  function _auditEmit(outcome, reason, info, req) {
    if (!audit) return;
    if (outcome === "success" && !auditSuccess) return;
    if (outcome === "failure" && !auditFailures) return;
    try {
      audit.safeEmit({
        action:   "webhook.verify",
        actor:    requestHelpers.extractActorContext(req),
        resource: { kind: "webhook" },
        outcome:  outcome,
        reason:   reason || null,
        metadata: info || null,
      });
    } catch (_e) { /* audit best-effort */ }
  }

  function _failure(code, message, reason, req) {
    _emitEvent("webhook.verify", 1, { outcome: "failure", reason: reason || code });
    _auditEmit("failure", reason || code, null, req);
    return _err(code, message);
  }

  async function verify(input) {
    if (!input || typeof input !== "object") {
      throw _err("BAD_OPT", "webhook.verifier.verify: input must be { body, headers }");
    }
    var headers = input.headers;
    if (!headers || typeof headers !== "object") {
      throw _err("BAD_OPT", "webhook.verifier.verify: headers must be an object");
    }
    var body = input.body;
    _validateBody(body);
    var ctxReq = input.req || null;

    // Headers may be node-style (lowercased keys) or operator-supplied
    // (mixed case). Resolve case-insensitively.
    var headerValue = null;
    var headerKeys = Object.keys(headers);
    for (var i = 0; i < headerKeys.length; i++) {
      if (headerKeys[i].toLowerCase() === sigHeader) {
        headerValue = headers[headerKeys[i]];
        break;
      }
    }
    if (typeof headerValue !== "string" || headerValue.length === 0) {
      throw _failure("MISSING_HEADER",
        "webhook: " + (opts.signatureHeader || HEADER.SIGNATURE) + " header missing",
        "missing-header", ctxReq);
    }

    var parsed = _parseSignatureHeader(headerValue);
    if (parsed.t === null && parsed.id === null && Object.keys(parsed.sigs).length === 0) {
      throw _failure("BAD_HEADER_FORMAT", "webhook: signature header could not be parsed", "bad-header-format", ctxReq);
    }
    if (parsed.t === null) {
      throw _failure("MISSING_TIMESTAMP", "webhook: t= field missing from signature header", "missing-timestamp", ctxReq);
    }
    var ts = Number(parsed.t);
    // The authenticated timestamp is re-composed into the signed string from
    // `ts` (the Number) below, so it must be the exact canonical decimal the
    // signer emits (`String(Math.floor(now / 1000))`). Validating only the
    // post-coercion value would accept every string Number() maps to the same
    // integer — scientific ("1.7e9"), a trailing ".0", hex ("0x..."), a
    // leading "0"/"+"/whitespace — each of which re-canonicalizes into the
    // signed string and re-verifies, making the authenticated t= field
    // malleable. Require the raw bytes to equal String(ts) so the sole
    // canonical form the signer produces is the sole form accepted (matching
    // the strict digits-only parse the Stripe verifier already applies).
    if (!numericBounds.isNonNegativeFiniteInt(ts) || String(ts) !== parsed.t) {
      throw _failure("BAD_TIMESTAMP", "webhook: t= field is not a canonical non-negative integer, got " + JSON.stringify(parsed.t), "bad-timestamp", ctxReq);
    }
    if (parsed.id === null || parsed.id.length === 0) {
      throw _failure("MISSING_ID", "webhook: id= field missing from signature header", "missing-id", ctxReq);
    }
    var sigKids = Object.keys(parsed.sigs);
    if (sigKids.length === 0) {
      throw _failure("MISSING_SIGNATURE", "webhook: no v<kid>= segment found in signature header", "missing-signature", ctxReq);
    }

    // Timestamp window: signed in seconds, compare to ms clock.
    var nowMs = nowFn();
    var ageMs = nowMs - C.TIME.seconds(ts);
    if (ageMs > toleranceMs) {
      throw _failure("EXPIRED", "webhook: timestamp older than toleranceMs (age=" + ageMs + "ms)", "expired", ctxReq);
    }
    if (-ageMs > clockSkewMs) {
      throw _failure("FUTURE", "webhook: timestamp in the future beyond clockSkewMs (skew=" + (-ageMs) + "ms)", "future", ctxReq);
    }

    // Find the first kid the verifier holds a key for.
    var matchedKid = null;
    for (var j = 0; j < sigKids.length; j++) {
      if (_hasOwn(keys, sigKids[j])) { matchedKid = sigKids[j]; break; }
    }
    if (matchedKid === null) {
      throw _failure("UNKNOWN_KID",
        "webhook: no registered key matches signed kids " + JSON.stringify(sigKids),
        "unknown-kid", ctxReq);
    }

    var signed = _composeSignedString(algo, matchedKid, ts, parsed.id, body);
    var ok;
    if (algo === ALGOS.HMAC_SHA3_512) {
      ok = _hmacVerify(keys[matchedKid], signed, parsed.sigs[matchedKid]);
    } else {
      ok = _pqcVerify(keys[matchedKid], signed, parsed.sigs[matchedKid]);
    }
    if (!ok) {
      throw _failure("BAD_SIGNATURE", "webhook: cryptographic verification failed", "bad-signature", ctxReq);
    }

    if (nonceStore) {
      var expireAt = C.TIME.seconds(ts) + toleranceMs;
      var fresh = await nonceStore.checkAndInsert(parsed.id, expireAt);
      if (!fresh) {
        throw _failure("REPLAY", "webhook: id '" + parsed.id + "' has been seen before", "replay", ctxReq);
      }
    }

    _emitEvent("webhook.verify", 1, { outcome: "success", kid: matchedKid });
    _auditEmit("success", null, { kid: matchedKid }, ctxReq);
    return { algo: algo, kid: matchedKid, timestamp: ts, id: parsed.id };
  }

  function middleware() {
    return function (req, res, next) {
      var raw = req.bodyRaw;
      if (raw === undefined) {
        if (Buffer.isBuffer(req.body)) raw = req.body;
        else if (typeof req.body === "string") raw = req.body;
      }
      if (raw === undefined) {
        return _writeError(res, 401, "MISSING_RAW_BODY",
          "webhook verifier middleware requires bodyParser({ keepRawBody: true })");
      }
      verify({ body: raw, headers: req.headers, req: req }).then(
        function (info) {
          req.webhook = info;
          next();
        },
        function (err) {
          if (err && err.isWebhookError) {
            _writeError(res, 401, err.code, err.message);
          } else {
            _writeError(res, 500, "VERIFY_ERROR", "webhook verification error");
          }
        }
      );
    };
  }

  return {
    verify:     verify,
    middleware: middleware,
  };
}

function _writeError(res, status, code, message) {
  res.writeHead(status, { "Content-Type": "application/json; charset=utf-8" });
  res.end(JSON.stringify({ error: code, message: message }));
}

// ---- Stripe-compatible inbound HMAC-SHA-256 verifier (v0.11.25) ----
//
// Stripe (+ Stripe-shaped: Paddle, Shopify) ships inbound webhooks with
// `Stripe-Signature: t=<unix>,v1=<hex>[,v0=<hex>...]`. The signed payload
// is the literal string `<t>.<rawBody>` and the MAC is HMAC-SHA-256 keyed
// by the operator's `whsec_...` secret bytes (the `whsec_` prefix IS the
// key — Stripe's spec preserves it; do NOT strip).
//
// Spec: https://docs.stripe.com/webhooks/signature
// Paddle:   https://developer.paddle.com/webhooks/signature-verification
// Shopify:  https://shopify.dev/docs/apps/webhooks/configuration/https
//
// RFC 2104 (HMAC) + RFC 6234 (SHA-256). Constant-time compare via
// b.crypto.timingSafeEqual — never `===`.

var STRIPE_HMAC_ALG = "hmac-sha256-stripe";
var STRIPE_SIG_MAX_HEX = 256;                                                                          // hex-char anti-DoS cap, not bytes
var STRIPE_DEFAULT_TOLERANCE_MS = C.TIME.minutes(5);                                                   // RFC 3161-ish 5 minute window default
var STRIPE_MIN_TOLERANCE_MS = C.TIME.seconds(30);                                                      // refuse below 30s

function _hmacSha256Hex(keyBytes, dataString) {
  return nodeCrypto.createHmac("sha256", keyBytes).update(dataString, "utf8").digest("hex");
}

function _parseStripeSignatureHeader(header) {
  if (typeof header !== "string" || header.length === 0) {
    throw new WebhookError("webhook/bad-stripe-header",
      "verify: Stripe-Signature header must be a non-empty string");
  }
  if (header.length > 4096) {                                                                          // anti-DoS header cap
    throw new WebhookError("webhook/bad-stripe-header",
      "verify: Stripe-Signature header exceeds 4096 bytes");
  }
  var parts = header.split(",");
  var ts = null;
  var v1 = [];
  for (var i = 0; i < parts.length; i += 1) {
    var p = parts[i].trim();
    var eq = p.indexOf("=");
    if (eq <= 0) continue;
    var k = p.slice(0, eq);
    var v = p.slice(eq + 1);
    if (k === "t") ts = v;
    else if (k === "v1") {
      if (v.length > STRIPE_SIG_MAX_HEX) {
        throw new WebhookError("webhook/bad-stripe-header",
          "verify: Stripe-Signature v1 entry exceeds " + STRIPE_SIG_MAX_HEX + " hex chars");
      }
      if (!/^[0-9a-f]+$/i.test(v)) continue;
      v1.push(v.toLowerCase());
    }
  }
  if (ts === null || !/^\d+$/.test(ts)) {
    throw new WebhookError("webhook/bad-stripe-header",
      "verify: Stripe-Signature missing or malformed t=<unix>");
  }
  if (v1.length === 0) {
    throw new WebhookError("webhook/bad-stripe-header",
      "verify: Stripe-Signature missing v1=<hex> entry");
  }
  return { timestamp: parseInt(ts, 10), v1: v1 };
}

function _timingSafeHexEqual(aHex, bHex) {
  if (typeof aHex !== "string" || typeof bHex !== "string") return false;
  if (aHex.length !== bHex.length) return false;
  // Route through the framework's length-tolerant timing-safe compare;
  // bCrypto handles the hex-string shape directly without manual
  // Buffer.from coercion.
  return bCrypto.timingSafeEqual(aHex, bHex);
}

function _coerceSecretBytes(secret) {
  if (typeof secret === "string") return Buffer.from(secret, "utf8");
  if (Buffer.isBuffer(secret)) return Buffer.from(secret);
  throw new WebhookError("webhook/bad-secret",
    "verify: secret must be a non-empty string or Buffer");
}

function _coerceBodyString(body) {
  if (typeof body === "string") return body;
  if (Buffer.isBuffer(body)) return body.toString("utf8");
  throw new WebhookError("webhook/bad-body",
    "verify: body must be a Buffer or string");
}

/**
 * @primitive b.webhook.verify
 * @signature b.webhook.verify(input)
 * @since     0.11.25
 * @status    stable
 *
 * Stripe-spec inbound webhook signature verifier. Validates the
 * `Stripe-Signature: t=<unix>,v1=<hex>[,v1=<hex>...]` header against an
 * HMAC-SHA-256 over the literal `<t>.<rawBody>` string using the
 * operator's `whsec_...` secret bytes verbatim (the prefix IS the key).
 * Refuses signatures older than the tolerance window (default 5 min,
 * minimum 30 s). When `nonceStore` is supplied the verifier atomically
 * records the accepted v1 signature so a replay within the tolerance window
 * is refused; the store speaks the same `checkAndInsert(nonce, expireAt) →
 * bool` contract as `b.webhook.verifier` and `b.nonceStore.create`, so the
 * framework's own replay store plugs in directly and concurrent redeliveries
 * cannot race. Constant-time compare via `b.crypto.timingSafeEqual`.
 *
 * @opts
 *   alg:        "hmac-sha256-stripe",
 *   secret:     string | Buffer,                      // whsec_... bytes verbatim
 *   header:     string,                               // Stripe-Signature value
 *   body:       string | Buffer,                      // raw request body
 *   toleranceMs: number,                              // default 5 min, min 30 s
 *   nonceStore: { checkAndInsert(nonce, expireAt) },  // optional atomic replay defense
 *
 * @example
 *   await b.webhook.verify({
 *     alg:        "hmac-sha256-stripe",
 *     secret:     "whsec_abc...",
 *     header:     req.headers["stripe-signature"],
 *     body:       rawBodyBuffer,
 *     nonceStore: b.nonceStore.create({ backend: "memory" }),
 *   });
 *   // → { ok: true, timestamp: 1700000000, scheme: "v1" }
 */
async function verify(input) {
  if (!input || typeof input !== "object") {
    throw new WebhookError("webhook/bad-opts",
      "verify: input object required");
  }
  if (input.alg !== STRIPE_HMAC_ALG) {
    throw new WebhookError("webhook/bad-alg",
      "verify: alg must be '" + STRIPE_HMAC_ALG + "'");
  }
  var secretBytes = _coerceSecretBytes(input.secret);
  if (secretBytes.length === 0) {
    throw new WebhookError("webhook/bad-secret",
      "verify: secret must be non-empty");
  }
  var bodyStr = _coerceBodyString(input.body);
  var parsed = _parseStripeSignatureHeader(input.header);
  var tolerance = input.toleranceMs;
  if (tolerance === undefined) tolerance = STRIPE_DEFAULT_TOLERANCE_MS;
  if (typeof tolerance !== "number" || !isFinite(tolerance) || tolerance < STRIPE_MIN_TOLERANCE_MS) {
    throw new WebhookError("webhook/bad-tolerance",
      "verify: toleranceMs must be a finite number >= " + STRIPE_MIN_TOLERANCE_MS);
  }
  var nowMs = (input._nowMs !== undefined && typeof input._nowMs === "number")
    ? input._nowMs : Date.now();
  var ageMs = nowMs - C.TIME.seconds(parsed.timestamp);
  if (ageMs < 0) ageMs = -ageMs;
  if (ageMs > tolerance) {
    throw new WebhookError("webhook/stale-timestamp",
      "verify: signature timestamp outside tolerance (" + ageMs + "ms > " + tolerance + "ms)");
  }

  var expectedHex = _hmacSha256Hex(secretBytes, parsed.timestamp + "." + bodyStr);
  var matched = false;
  for (var i = 0; i < parsed.v1.length; i += 1) {
    if (_timingSafeHexEqual(parsed.v1[i], expectedHex)) {
      matched = true;
      break;
    }
  }
  if (!matched) {
    throw new WebhookError("webhook/bad-signature",
      "verify: no v1 signature matched HMAC-SHA-256 of <t>.<body>");
  }

  // Optional replay defense — the nonceStore speaks the SAME atomic
  // `checkAndInsert(nonce, expireAt) → bool` contract as b.webhook.verifier
  // and b.nonceStore.create, so the framework's own replay store drops in
  // with no adapter. The check + insert is one atomic step: a non-atomic
  // check-then-set would race two concurrent redeliveries of the same event
  // (both observe "unseen", both proceed) — the exact failure replay defense
  // exists to prevent. checkAndInsert MAY return a Promise (Redis / KV /
  // cluster SQL); we always await it. `expireAt` is the absolute epoch-ms at
  // which the signature itself falls outside the tolerance window, so a stored
  // nonce is retained exactly as long as a replay of it could still be fresh.
  if (input.nonceStore) {
    var ns = input.nonceStore;
    if (typeof ns.checkAndInsert !== "function") {
      throw new WebhookError("webhook/bad-nonce-store",
        "verify: nonceStore must expose checkAndInsert(nonce, expireAt) — the " +
        "b.nonceStore contract shared with b.webhook.verifier");
    }
    var nonceKey = "stripe:" + parsed.timestamp + ":" + expectedHex;
    var expireAt = C.TIME.seconds(parsed.timestamp) + tolerance;
    var fresh = await ns.checkAndInsert(nonceKey, expireAt);
    if (!fresh) {
      throw new WebhookError("webhook/replay",
        "verify: signature already seen within tolerance window (replay)");
    }
  }

  return { ok: true, timestamp: parsed.timestamp, scheme: "v1" };
}

/**
 * @primitive b.webhook.sign
 * @signature b.webhook.sign(input)
 * @since     0.11.25
 * @status    stable
 *
 * Round-trip companion to `b.webhook.verify` for the
 * `hmac-sha256-stripe` algorithm. Returns the `Stripe-Signature`
 * header value `t=<unix>,v1=<hex>` for a given body + secret +
 * (optional) timestamp. Operators emitting Stripe-shaped webhooks
 * downstream — and the test surface — use this to produce the
 * matching header.
 *
 * @example
 *   var header = b.webhook.sign({
 *     alg:    "hmac-sha256-stripe",
 *     secret: "whsec_abc...",
 *     body:   '{"id":"evt_1"}',
 *   });
 */
function sign(input) {
  if (!input || typeof input !== "object") {
    throw new WebhookError("webhook/bad-opts",
      "sign: input object required");
  }
  if (input.alg !== STRIPE_HMAC_ALG) {
    throw new WebhookError("webhook/bad-alg",
      "sign: alg must be '" + STRIPE_HMAC_ALG + "'");
  }
  var secretBytes = _coerceSecretBytes(input.secret);
  if (secretBytes.length === 0) {
    throw new WebhookError("webhook/bad-secret",
      "sign: secret must be non-empty");
  }
  var bodyStr = _coerceBodyString(input.body);
  var ts;
  if (input.timestamp !== undefined) {
    if (typeof input.timestamp !== "number" || !isFinite(input.timestamp) || input.timestamp < 0) {
      throw new WebhookError("webhook/bad-timestamp",
        "sign: timestamp must be a non-negative finite number (unix seconds)");
    }
    ts = Math.floor(input.timestamp);
  } else {
    ts = Math.floor(Date.now() / 1000);
  }
  var hex = _hmacSha256Hex(secretBytes, ts + "." + bodyStr);
  return "t=" + ts + ",v1=" + hex;
}

// ---- Public surface ----

module.exports = {
  signer:         signer,
  verifier:       verifier,
  ALGOS:          ALGOS,
  PQC_ALGORITHMS: PQC_ALGORITHMS,
  HEADER:         HEADER,
  DEFAULTS:       DEFAULTS,
  WebhookError:   WebhookError,
  // v0.11.25 — Stripe-shaped inbound HMAC-SHA-256 verifier + signer.
  verify:         verify,
  sign:           sign,
};

// Durable signed-webhook delivery store (sign + persist + deliver + retry +
// dead-letter + operator replay). Defined in lib/webhook-dispatcher.js, which
// pulls the SQL/persistence stack — exposed as a lazy getter so requiring the
// webhook module for the inbound verify path doesn't load it (edge-safe).
Object.defineProperty(module.exports, "dispatcher", {
  enumerable:   true,
  configurable: true,
  get: function () { return webhookDispatcher().dispatcher; },
});
