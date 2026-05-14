"use strict";
/**
 * b.sessionDeviceBinding — bind sessions to a device fingerprint and
 * refuse-on-drift on every authenticated request.
 *
 * The fingerprint is a SHAKE256-derived digest over a stable subset of
 * request signals:
 *
 *   - User-Agent header (full string)
 *   - Accept-Language header (sorted preference list)
 *   - Accept-Encoding header (sorted set)
 *   - Client IP /24 (IPv4) or /48 (IPv6) prefix — tolerates carrier
 *     NAT churn and DHCP rotation while catching cross-region drift
 *   - WebAuthn AAGUID, when an authenticator is bound (operator passes
 *     it in via fingerprintExtras)
 *   - Operator-supplied bound key (b.auth.boundKey / mTLS cert hash /
 *     DPoP jkt) — when provided the binding is cryptographic, not
 *     just shape-based
 *
 * Operators choose the binding strength via the create-time opts:
 *
 *   var binding = b.sessionDeviceBinding.create({
 *     session:          b.session,
 *     audit:            b.audit,
 *     requireBoundKey:  true,                   // refuse if no key resolves
 *     boundKeyResolver: function (req) {
 *       // Return the cryptographic key bound to the session — DPoP
 *       // public key, mTLS cert SPKI hash, FIDO2 attestation hash.
 *       return req.dpop && req.dpop.jkt ? Buffer.from(req.dpop.jkt, "hex") : null;
 *     },
 *   });
 *
 *   // After session.create:
 *   await binding.bind(token, req);
 *
 *   // On every authenticated request:
 *   var verdict = await binding.verify(token, req);
 *   if (!verdict.ok) {
 *     // verdict.reason: "drift" | "missing-bind" | "missing-bound-key"
 *     return res.status(401).json({ error: verdict.reason });
 *   }
 *
 * Drift tolerance: the comparator does an EXACT match on UA + Accept-*,
 * a /24-IPv4 (or /48-IPv6) match on IP, and an EXACT match on the
 * bound-key when present. Operators with mobile clients that switch
 * networks can pass `ipPrefixBits: { v4: 0, v6: 0 }` to skip the IP
 * check entirely; the rest of the fingerprint still binds.
 *
 * Storage model: the fingerprint is stored under
 * `bindingStore.set(token, fingerprintBytes, { ttlMs })` — operators
 * pass any b.cache-shaped object. Without a separate store, the
 * primitive falls back to b.session.touch metadata when the operator
 * passes session=b.session AND opts in via storeInSession=true.
 *
 * Audit emissions:
 *
 *   session.device.bound      every successful bind()
 *   session.device.drift      verify() found a mismatching fingerprint
 *   session.device.refused    verify() refused (drift OR missing bind
 *                             OR missing bound-key under requireBoundKey)
 *
 * Validation policy:
 *   - create() opts → throw at config time
 *   - bind / verify  → throw on bad token / req shape (operator typo)
 *   - storage errors  → fail-CLOSED on verify (drift indistinguishable
 *                       from a wiped store, refuse rather than allow)
 *                       fail-OPEN on bind (don't lose a fresh session
 *                       to a transient cache outage)
 */

var C            = require("./constants");
var bCrypto = require("./crypto");
var nodeCrypto   = require("crypto");
var lazyRequire  = require("./lazy-require");
var requestHelpers = require("./request-helpers");
var validateOpts = require("./validate-opts");
var { SessionDeviceBindingError } = require("./framework-error");

var observability = lazyRequire(function () { return require("./observability"); });

var DEFAULT_TTL_MS         = C.TIME.days(7);
var DEFAULT_IP_V4_PREFIX   = 24; // allow:raw-byte-literal — IPv4 /24 fingerprint mask in bits
var DEFAULT_IP_V6_PREFIX   = 48; // allow:raw-byte-literal — IPv6 /48 fingerprint mask in bits
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
  if (!s || typeof s !== "object" ||
      typeof s.get !== "function" ||
      typeof s.set !== "function" ||
      typeof s.del !== "function") {
    throw new SessionDeviceBindingError("session-device-binding/bad-opt",
      "bindingStore must be a b.cache-shaped object (get/set/del)");
  }
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
  // Drop quality factors and sort tags so equivalent header orderings
  // yield the same fingerprint.
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
  // IPv6
  if (ip.indexOf(":") !== -1) {
    var v6Bits = bits;
    var groups = ip.split(":");
    // Naive expansion — keep the first ceil(v6Bits/16) groups intact
    // and zero the rest. Sufficient for fingerprint stability; not a
    // canonical IPv6 representation.
    var keepGroups = Math.ceil(v6Bits / 16); // allow:raw-byte-literal — IPv6 group width in bits
    var kept = groups.slice(0, keepGroups).join(":");
    return "v6:" + kept + "/" + v6Bits;
  }
  // IPv4
  var parts = ip.split(".");
  if (parts.length !== 4) return "v4:" + ip + "/" + bits;
  var v4Bits = bits;
  var keepOctets = Math.floor(v4Bits / 8); // allow:raw-byte-literal — IPv4 octet width in bits
  var maskedOctets = parts.slice(0, keepOctets);
  while (maskedOctets.length < 4) maskedOctets.push("0");
  return "v4:" + maskedOctets.join(".") + "/" + v4Bits;
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
  if (opts.fingerprintExtras !== undefined) _requireFunction("fingerprintExtras", opts.fingerprintExtras);

  var requireBoundKey = !!opts.requireBoundKey;
  if (requireBoundKey && typeof opts.boundKeyResolver !== "function") {
    throw new SessionDeviceBindingError("session-device-binding/bad-opt",
      "requireBoundKey requires opts.boundKeyResolver");
  }

  var ipBits = opts.ipPrefixBits || {};
  var v4Bits = typeof ipBits.v4 === "number" && isFinite(ipBits.v4) && ipBits.v4 >= 0 && ipBits.v4 <= 32 // allow:raw-byte-literal — IPv4 max prefix length in bits
    ? ipBits.v4 : DEFAULT_IP_V4_PREFIX;
  var v6Bits = typeof ipBits.v6 === "number" && isFinite(ipBits.v6) && ipBits.v6 >= 0 && ipBits.v6 <= 128 // allow:raw-byte-literal — IPv6 max prefix length in bits
    ? ipBits.v6 : DEFAULT_IP_V6_PREFIX;

  var ttlMs = opts.ttlMs !== undefined ? opts.ttlMs : DEFAULT_TTL_MS;
  if (typeof ttlMs !== "number" || !isFinite(ttlMs) || ttlMs <= 0) {
    throw new SessionDeviceBindingError("session-device-binding/bad-opt",
      "ttlMs must be a positive finite number, got " + JSON.stringify(ttlMs));
  }

  var storeInSession = !!opts.storeInSession;
  if (!storeInSession && !opts.bindingStore) {
    throw new SessionDeviceBindingError("session-device-binding/bad-opt",
      "either bindingStore (b.cache-shaped) or storeInSession=true must be set");
  }
  if (opts.bindingStore) _requireBindingStore(opts.bindingStore);
  if (storeInSession && (!opts.session || typeof opts.session.touch !== "function")) {
    throw new SessionDeviceBindingError("session-device-binding/bad-opt",
      "storeInSession requires opts.session with a touch() function");
  }

  var sessionRef     = opts.session || null;
  var bindingStore   = opts.bindingStore || null;
  var auditInst      = opts.audit || null;
  var obsInst        = opts.observability || null;
  var clock          = opts.clock || Date.now;
  var boundKeyResolver = opts.boundKeyResolver || null;
  var fingerprintExtras = opts.fingerprintExtras || null;

  function _emitObs(name, labels) {
    var sink = obsInst || _safeGlobalObs();
    if (!sink) return;
    try { sink.event(name, 1, labels); } catch (_e) { /* drop-silent */ }
  }

  function _safeGlobalObs() {
    try { return observability(); } catch (_e) { return null; }
  }

  function _emitAudit(action, tokenHash, outcome, metadata, req) {
    if (!auditInst) return;
    try {
      var event = {
        action:   action,
        outcome:  outcome,
        resource: { kind: "session.device", id: tokenHash },
        metadata: metadata || {},
      };
      if (req) event.actor = requestHelpers.extractActorContext(req);
      auditInst.safeEmit(event);
    } catch (_e) { /* drop-silent */ }
  }

  function _hashTokenForAudit(token) {
    // Don't put the raw session id in the audit log. SHAKE256 to a
    // stable short label.
    return nodeCrypto.createHash("sha3-256").update("bj-session-device:" + token).digest("hex").slice(0, 16); // allow:raw-byte-literal — sha3-256 hex truncation length in chars
  }

  function _resolveBoundKey(req) {
    if (!boundKeyResolver) return null;
    var key;
    try { key = boundKeyResolver(req); }
    catch (_e) { return undefined; }  // resolver threw — distinguishable
    if (key === null || key === undefined) return null;
    if (Buffer.isBuffer(key)) return key;
    if (typeof key === "string" && key.length > 0) return Buffer.from(key, "utf8");
    if (key instanceof Uint8Array) return Buffer.from(key);
    throw new SessionDeviceBindingError("session-device-binding/bad-bound-key",
      "boundKeyResolver returned a non-Buffer / non-string value (got " + typeof key + ")");
  }

  function _resolveExtras(req) {
    if (!fingerprintExtras) return "";
    var v;
    try { v = fingerprintExtras(req); }
    catch (_e) { return ""; }
    if (v === null || v === undefined) return "";
    if (typeof v === "string") return v;
    try { return JSON.stringify(v); } catch (_e) { return ""; }
  }

  function _computeFingerprint(req) {
    _requireReq(req);
    var headers = req.headers || {};
    var ua = typeof headers["user-agent"] === "string" ? headers["user-agent"] : "";
    var al = _normalizeAcceptLanguage(headers["accept-language"]);
    var ae = _normalizeAcceptEncoding(headers["accept-encoding"]);
    var ip = "";
    try { ip = requestHelpers.clientIp(req); } catch (_e) { ip = ""; }
    var family = ip.indexOf(":") !== -1 ? "v6" : "v4";
    var ipPart = _ipPrefix(ip, family === "v6" ? v6Bits : v4Bits);
    var extras = _resolveExtras(req);

    var boundKeyMaybe = _resolveBoundKey(req);
    if (requireBoundKey && (boundKeyMaybe === null || boundKeyMaybe === undefined)) {
      return { ok: false, reason: "missing-bound-key" };
    }
    var keyPart = "";
    if (Buffer.isBuffer(boundKeyMaybe)) {
      keyPart = "k:" + nodeCrypto.createHash("sha3-256").update(boundKeyMaybe).digest("hex");
    }

    var canonical = [
      "ua=" + ua,
      "al=" + al,
      "ae=" + ae,
      "ip=" + ipPart,
      "ex=" + extras,
      keyPart,
    ].join("\n");

    var hash = nodeCrypto.createHash("shake256", { outputLength: FINGERPRINT_BYTES })
      .update(canonical)
      .digest();
    return { ok: true, fingerprint: hash, components: {
      ua: ua, al: al, ae: ae, ip: ipPart, hasBoundKey: !!keyPart,
    } };
  }

  async function bind(token, req) {
    _requireToken(token);
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
    if (!written && sessionRef && typeof sessionRef.touch === "function") {
      // Best-effort: stash the fingerprint hex on the session row via
      // touch metadata. Operators using storeInSession get this.
      try {
        await sessionRef.touch(token, {
          metadata: { deviceFingerprint: fp.fingerprint.toString("hex"), boundAt: clock() },
        });
        written = true;
      } catch (_e) { /* drop-silent */ }
    }
    _emitObs("session.device.bound", { stored: written ? "1" : "0" });
    _emitAudit("session.device.bound", _hashTokenForAudit(token), "success",
      { components: fp.components, stored: written }, req);
    return fp.fingerprint;
  }

  async function _readBound(token) {
    if (bindingStore) {
      try {
        var raw = await bindingStore.get(token);
        if (Buffer.isBuffer(raw)) return raw;
        if (typeof raw === "string" && raw.length > 0) return Buffer.from(raw, "hex");
        if (raw instanceof Uint8Array) return Buffer.from(raw);
        return null;
      } catch (_e) { return undefined; } // fail-CLOSED on verify
    }
    if (sessionRef && typeof sessionRef.verify === "function") {
      try {
        var session = await sessionRef.verify(token);
        if (session && session.data && typeof session.data.deviceFingerprint === "string") {
          return Buffer.from(session.data.deviceFingerprint, "hex");
        }
        return null;
      } catch (_e) { return undefined; }
    }
    return null;
  }

  async function verify(token, req) {
    _requireToken(token);
    var fpResult = _computeFingerprint(req);
    if (!fpResult.ok) {
      _emitObs("session.device.refused", { reason: fpResult.reason });
      _emitAudit("session.device.refused", _hashTokenForAudit(token), "denied",
        { reason: fpResult.reason, stage: "verify" }, req);
      return { ok: false, reason: fpResult.reason };
    }
    var stored = await _readBound(token);
    if (stored === undefined) {
      // store error — fail closed
      _emitObs("session.device.refused", { reason: "store-error" });
      _emitAudit("session.device.refused", _hashTokenForAudit(token), "denied",
        { reason: "store-error", stage: "verify" }, req);
      return { ok: false, reason: "store-error" };
    }
    if (stored === null) {
      // never bound — under requireBoundKey treat as refuse
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
    if (bindingStore) {
      try { await bindingStore.del(token); } catch (_e) { /* drop-silent */ }
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
  SessionDeviceBindingError: SessionDeviceBindingError,
  DEFAULTS:                Object.freeze({
    ttlMs:        DEFAULT_TTL_MS,
    ipV4Prefix:   DEFAULT_IP_V4_PREFIX,
    ipV6Prefix:   DEFAULT_IP_V6_PREFIX,
    fingerprintBytes: FINGERPRINT_BYTES,
  }),
};
