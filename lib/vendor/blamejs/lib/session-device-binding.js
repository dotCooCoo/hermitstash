// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

var C            = require("./constants");
var bCrypto = require("./crypto");
var nodeCrypto   = require("node:crypto");
var lazyRequire  = require("./lazy-require");
var requestHelpers = require("./request-helpers");
var validateOpts = require("./validate-opts");
var { SessionDeviceBindingError } = require("./framework-error");

var observability = lazyRequire(function () { return require("./observability"); });

var DEFAULT_TTL_MS         = C.TIME.days(7);
var DEFAULT_IP_V4_PREFIX   = 24;
var DEFAULT_IP_V6_PREFIX   = 48;
var FINGERPRINT_BYTES      = C.BYTES.bytes(32);

var ALLOWED_OPTS = [
  "session", "audit", "requireBoundKey", "boundKeyResolver",
  "fingerprintExtras", "ipPrefixBits", "bindingStore", "ttlMs",
  "storeInSession", "observability", "clock",
];

function _requireFunction(name, val) {
  if (typeof val !== "function") {
    throw new SessionDeviceBindingError("session-device-binding/bad-opt",
      name + ": expected function, got " + typeof val);
  }
}

function _requireBindingStore(s) {
  validateOpts.requireMethods(s, ["get", "set", "del"],
    "bindingStore (b.cache-shaped)", SessionDeviceBindingError, "session-device-binding/bad-opt");
}

function _requireToken(token) {
  if (typeof token !== "string" || token.length === 0) {
    throw new SessionDeviceBindingError("session-device-binding/bad-token",
      "token must be a non-empty string, got " + typeof token);
  }
}

function _requireReq(req) {
  if (!req || typeof req !== "object") {
    throw new SessionDeviceBindingError("session-device-binding/bad-req",
      "req must be a request-shaped object, got " + typeof req);
  }
}

function _normalizeAcceptLanguage(value) {
  if (typeof value !== "string" || value.length === 0) return "";
  return value.split(",")
    .map(function (s) { return s.trim().split(";")[0].trim().toLowerCase(); })
    .filter(function (s) { return s.length > 0; })
    .sort()
    .join(",");
}

function _normalizeAcceptEncoding(value) {
  if (typeof value !== "string" || value.length === 0) return "";
  return value.split(",")
    .map(function (s) { return s.trim().split(";")[0].trim().toLowerCase(); })
    .filter(function (s) { return s.length > 0; })
    .sort()
    .join(",");
}

function _ipPrefix(ip, bits) {
  if (typeof ip !== "string" || ip.length === 0) return "";
  if (bits === 0) return "";
  return requestHelpers.ipPrefix(ip, { v4Bits: bits, v6Bits: bits });
}

function _resolveExtrasFn(fn, req) {
  if (!fn) return "";
  var v;
  try { v = fn(req); } catch (_e) { return ""; }
  if (v === null || v === undefined) return "";
  if (typeof v === "string") return v;
  try { return JSON.stringify(v); } catch (_e) { return ""; }
}

function _resolveIpBits(ipBits) {
  ipBits = ipBits || {};
  return {
    v4: (typeof ipBits.v4 === "number" && isFinite(ipBits.v4) && ipBits.v4 >= 0 && ipBits.v4 <= 32)
      ? ipBits.v4 : DEFAULT_IP_V4_PREFIX,
    v6: (typeof ipBits.v6 === "number" && isFinite(ipBits.v6) && ipBits.v6 >= 0 && ipBits.v6 <= 128)
      ? ipBits.v6 : DEFAULT_IP_V6_PREFIX,
  };
}

function _computeDeviceFingerprint(req, cfg) {
  _requireReq(req);
  var headers = req.headers || {};
  var ua = typeof headers["user-agent"] === "string" ? headers["user-agent"] : "";
  var al = _normalizeAcceptLanguage(headers["accept-language"]);
  var ae = _normalizeAcceptEncoding(headers["accept-encoding"]);
  var ip = "";
  try { ip = requestHelpers.clientIp(req); } catch (_e) { ip = ""; }
  if (typeof ip !== "string") ip = "";
  var family = ip.indexOf(":") !== -1 ? "v6" : "v4";
  var ipPart = _ipPrefix(ip, family === "v6" ? cfg.v6Bits : cfg.v4Bits);
  var keyPart = "";
  if (Buffer.isBuffer(cfg.boundKey)) {
    keyPart = "k:" + nodeCrypto.createHash("sha3-256").update(cfg.boundKey).digest("hex");
  }
  var canonical = [
    "ua=" + ua,
    "al=" + al,
    "ae=" + ae,
    "ip=" + ipPart,
    "ex=" + (cfg.extras || ""),
    keyPart,
  ].join("\n");
  var hash = nodeCrypto.createHash("shake256", { outputLength: FINGERPRINT_BYTES })
    .update(canonical)
    .digest();
  return { fingerprint: hash, components: {
    ua: ua, al: al, ae: ae, ip: ipPart, hasBoundKey: !!keyPart,
  } };
}

/**
 * @primitive  b.sessionDeviceBinding.fingerprint
 * @signature  b.sessionDeviceBinding.fingerprint(req, opts?)
 * @since      0.15.13
 * @status     stable
 * @related    b.session.rotate, b.session.create
 *
 * Compute the stateless SHAKE256 device-shape digest for a request with no
 * store, no session, and no side effects — the soft device-binding building
 * block for self-validating tokens (a sealed cookie, a JWT) that carry the
 * fingerprint inside the token and compare it themselves. `create()` requires a
 * bindingStore for the persisted bind()/verify() lifecycle; this static form
 * skips that gate because it touches no store. Returns a 32-byte Buffer derived
 * from User-Agent + normalized Accept-Language / Accept-Encoding + the masked
 * client-IP prefix (+ optional operator extras). Throws only on a missing or
 * malformed request object.
 *
 * @opts
 *   ipPrefixBits:      { v4: number, v6: number },          // default { v4: 24, v6: 48 } — mask width that survives a roaming IP
 *   fingerprintExtras: function,                            // (req) => string|object, optional extra signal folded into the digest
 *
 * @example
 *   var fp = b.sessionDeviceBinding.fingerprint(req);
 *   // seal fp inside the cookie/JWT; on the next request recompute + constant-time compare
 */
function fingerprint(req, opts) {
  opts = opts || {};
  if (opts.fingerprintExtras !== undefined && opts.fingerprintExtras !== null &&
      typeof opts.fingerprintExtras !== "function") {
    throw new SessionDeviceBindingError("session-device-binding/bad-opt",
      "fingerprint: fingerprintExtras must be a function (req) => string|object");
  }
  var bits = _resolveIpBits(opts.ipPrefixBits);
  return _computeDeviceFingerprint(req, {
    v4Bits: bits.v4,
    v6Bits: bits.v6,
    extras: _resolveExtrasFn(opts.fingerprintExtras, req),
    boundKey: null,
  }).fingerprint;
}

function create(opts) {
  opts = opts || {};
  validateOpts(opts, ALLOWED_OPTS, "sessionDeviceBinding.create");

  validateOpts.auditShape(opts.audit, "sessionDeviceBinding.create",
    SessionDeviceBindingError);

  if (opts.session !== undefined && (typeof opts.session !== "object" || opts.session === null)) {
    throw new SessionDeviceBindingError("session-device-binding/bad-opt",
      "session must be a b.session-shaped object or undefined");
  }
  if (opts.boundKeyResolver !== undefined) _requireFunction("boundKeyResolver", opts.boundKeyResolver);
  // drop-silent catch, so a non-function clock made bind record `stored: false`,
  validateOpts.optionalFunction(opts.clock, "sessionDeviceBinding.create: clock",
    SessionDeviceBindingError, "session-device-binding/bad-opt");
  validateOpts.optionalBoolean(opts.storeInSession, "sessionDeviceBinding.create: storeInSession",
    SessionDeviceBindingError, "session-device-binding/bad-opt");
  if (opts.fingerprintExtras !== undefined) _requireFunction("fingerprintExtras", opts.fingerprintExtras);

  var requireBoundKey = !!opts.requireBoundKey;
  if (requireBoundKey && typeof opts.boundKeyResolver !== "function") {
    throw new SessionDeviceBindingError("session-device-binding/bad-opt",
      "requireBoundKey requires opts.boundKeyResolver");
  }

  var ipBits = opts.ipPrefixBits || {};
  var v4Bits = typeof ipBits.v4 === "number" && isFinite(ipBits.v4) && ipBits.v4 >= 0 && ipBits.v4 <= 32
    ? ipBits.v4 : DEFAULT_IP_V4_PREFIX;
  var v6Bits = typeof ipBits.v6 === "number" && isFinite(ipBits.v6) && ipBits.v6 >= 0 && ipBits.v6 <= 128
    ? ipBits.v6 : DEFAULT_IP_V6_PREFIX;

  var ttlMs = opts.ttlMs !== undefined ? opts.ttlMs : DEFAULT_TTL_MS;
  if (typeof ttlMs !== "number" || !isFinite(ttlMs) || ttlMs <= 0) {
    throw new SessionDeviceBindingError("session-device-binding/bad-opt",
      "ttlMs must be a positive finite number, got " + JSON.stringify(ttlMs));
  }

  var storeInSession = !!opts.storeInSession;
  var hasStore = !!(storeInSession || opts.bindingStore);
  if (opts.bindingStore) _requireBindingStore(opts.bindingStore);
  if (storeInSession && (!opts.session ||
      typeof opts.session.updateData !== "function" ||
      typeof opts.session.verify !== "function")) {
    throw new SessionDeviceBindingError("session-device-binding/bad-opt",
      "storeInSession requires opts.session with updateData() and verify() " +
      "(the fingerprint is written to, and read back from, the session's sealed data payload)");
  }

  var sessionRef     = opts.session || null;
  var bindingStore   = opts.bindingStore || null;
  var auditInst      = opts.audit || null;
  var obsInst        = opts.observability || null;
  var clock          = opts.clock || Date.now;
  var boundKeyResolver = opts.boundKeyResolver || null;
  var fingerprintExtras = opts.fingerprintExtras || null;

  var _emitObs = observability().makeCounterEmitter(obsInst);

  var _emitAudit = requestHelpers.makeResourceAuditEmitter(auditInst, "session.device");

  function _hashTokenForAudit(token) {
    return nodeCrypto.createHash("sha3-256").update("bj-session-device:" + token).digest("hex").slice(0, 16);
  }

  function _resolveBoundKey(req) {
    if (!boundKeyResolver) return null;
    var key;
    try { key = boundKeyResolver(req); }
    catch (_e) { return undefined; }
    if (key === null || key === undefined) return null;
    if (Buffer.isBuffer(key)) return key;
    if (typeof key === "string" && key.length > 0) return Buffer.from(key, "utf8");
    if (key instanceof Uint8Array) return Buffer.from(key);
    throw new SessionDeviceBindingError("session-device-binding/bad-bound-key",
      "boundKeyResolver returned a non-Buffer / non-string value (got " + typeof key + ")");
  }

  function _resolveExtras(req) {
    return _resolveExtrasFn(fingerprintExtras, req);
  }

  function _computeFingerprint(req) {
    _requireReq(req);
    var boundKeyMaybe = _resolveBoundKey(req);
    if (requireBoundKey && (boundKeyMaybe === null || boundKeyMaybe === undefined)) {
      return { ok: false, reason: "missing-bound-key" };
    }
    var r = _computeDeviceFingerprint(req, {
      v4Bits:   v4Bits,
      v6Bits:   v6Bits,
      extras:   _resolveExtras(req),
      boundKey: Buffer.isBuffer(boundKeyMaybe) ? boundKeyMaybe : null,
    });
    return { ok: true, fingerprint: r.fingerprint, components: r.components };
  }

  function _writeBinding(token, value) {
    if (sessionRef && typeof sessionRef._setDeviceBinding === "function") {
      return sessionRef._setDeviceBinding(token, value);
    }
    return sessionRef.updateData(token, { __bj_deviceBinding: value }, { merge: true });
  }
  function _canWriteBinding() {
    return !!(sessionRef && (typeof sessionRef._setDeviceBinding === "function" ||
                             typeof sessionRef.updateData === "function"));
  }

  function _requireStore(stage) {
    if (!hasStore) {
      throw new SessionDeviceBindingError("session-device-binding/no-store",
        stage + ": no store configured — pass bindingStore (b.cache-shaped) or "
        + "storeInSession=true to create(), or use the stateless "
        + "b.sessionDeviceBinding.fingerprint(req, opts) for soft binding");
    }
  }

  async function bind(token, req) {
    _requireToken(token);
    _requireStore("bind");
    var fp = _computeFingerprint(req);
    if (!fp.ok) {
      _emitObs("session.device.refused", { reason: fp.reason });
      _emitAudit("session.device.refused", _hashTokenForAudit(token), "denied",
        { reason: fp.reason, stage: "bind" }, req);
      throw new SessionDeviceBindingError("session-device-binding/missing-bound-key",
        "bind: requireBoundKey is true but no bound key resolved for this request");
    }
    var written = false;
    if (bindingStore) {
      try {
        await bindingStore.set(token, fp.fingerprint, { ttlMs: ttlMs });
        written = true;
      } catch (_e) { /* fail-OPEN on bind: don't lose the fresh session */ }
    }
    var staleClearFailed = false;
    if (written && storeInSession && _canWriteBinding()) {
      try {
        staleClearFailed = (await _writeBinding(token, null)) !== true;
      } catch (_e) { staleClearFailed = true; }
    }
    if (staleClearFailed) {
      _emitObs("session.device.stale_fallback", {});
      _emitAudit("session.device.stale_fallback", _hashTokenForAudit(token), "failure",
        { stage: "bind" }, req);
    }
    if (!written && storeInSession && _canWriteBinding()) {
      try {
        written = (await _writeBinding(token, {
          fingerprint: fp.fingerprint.toString("hex"),
          boundAt:     clock(),
        })) === true;
      } catch (_e) { /* drop-silent */ }
    }
    _emitObs("session.device.bound", { stored: written ? "1" : "0" });
    _emitAudit("session.device.bound", _hashTokenForAudit(token), "success",
      { components: fp.components, stored: written }, req);
    return fp.fingerprint;
  }

  function _fallbackIsFresh(bound) {
    var boundAt = bound && bound.boundAt;
    if (typeof boundAt !== "number" || !isFinite(boundAt)) return false;
    var age = clock() - boundAt;
    return age >= 0 && age < ttlMs;
  }

  async function _readBound(token) {
    if (bindingStore) {
      try {
        var raw = await bindingStore.get(token);
        if (Buffer.isBuffer(raw)) return raw;
        if (typeof raw === "string" && raw.length > 0) return Buffer.from(raw, "hex");
        if (raw instanceof Uint8Array) return Buffer.from(raw);
        if (!storeInSession) return null;
      } catch (_e) { return undefined; }
    }
    if (sessionRef && typeof sessionRef.verify === "function") {
      try {
        var session = await sessionRef.verify(token);
        var bound = session && session.data && session.data.__bj_deviceBinding;
        if (bound && typeof bound.fingerprint === "string" && _fallbackIsFresh(bound)) {
          return Buffer.from(bound.fingerprint, "hex");
        }
        return null;
      } catch (_e) { return undefined; }
    }
    return null;
  }

  async function verify(token, req) {
    _requireToken(token);
    _requireStore("verify");
    var fpResult = _computeFingerprint(req);
    if (!fpResult.ok) {
      _emitObs("session.device.refused", { reason: fpResult.reason });
      _emitAudit("session.device.refused", _hashTokenForAudit(token), "denied",
        { reason: fpResult.reason, stage: "verify" }, req);
      return { ok: false, reason: fpResult.reason };
    }
    var stored = await _readBound(token);
    if (stored === undefined) {
      _emitObs("session.device.refused", { reason: "store-error" });
      _emitAudit("session.device.refused", _hashTokenForAudit(token), "denied",
        { reason: "store-error", stage: "verify" }, req);
      return { ok: false, reason: "store-error" };
    }
    if (stored === null) {
      _emitObs("session.device.refused", { reason: "missing-bind" });
      _emitAudit("session.device.refused", _hashTokenForAudit(token), "denied",
        { reason: "missing-bind", stage: "verify" }, req);
      return { ok: false, reason: "missing-bind" };
    }
    if (!Buffer.isBuffer(stored) || stored.length !== fpResult.fingerprint.length ||
        !bCrypto.timingSafeEqual(stored, fpResult.fingerprint)) {
      _emitObs("session.device.drift", {});
      _emitAudit("session.device.drift", _hashTokenForAudit(token), "denied",
        { components: fpResult.components, stage: "verify" }, req);
      _emitAudit("session.device.refused", _hashTokenForAudit(token), "denied",
        { reason: "drift", components: fpResult.components, stage: "verify" }, req);
      return { ok: false, reason: "drift", components: fpResult.components };
    }
    return { ok: true, components: fpResult.components };
  }

  async function unbind(token) {
    _requireToken(token);
    _requireStore("unbind");
    if (bindingStore) {
      try { await bindingStore.del(token); } catch (_e) { /* drop-silent */ }
    }
    if (storeInSession && _canWriteBinding()) {
      try {
        await _writeBinding(token, null);
      } catch (_e) { /* drop-silent */ }
    }
    return true;
  }

  function fingerprint(req) {
    var fp = _computeFingerprint(req);
    if (!fp.ok) return null;
    return fp.fingerprint;
  }

  return {
    bind:         bind,
    verify:       verify,
    unbind:       unbind,
    fingerprint:  fingerprint,
  };
}

module.exports = {
  create:                  create,
  fingerprint:             fingerprint,
  SessionDeviceBindingError: SessionDeviceBindingError,
  DEFAULTS:                Object.freeze({
    ttlMs:        DEFAULT_TTL_MS,
    ipV4Prefix:   DEFAULT_IP_V4_PREFIX,
    ipV6Prefix:   DEFAULT_IP_V6_PREFIX,
    fingerprintBytes: FINGERPRINT_BYTES,
  }),
};
