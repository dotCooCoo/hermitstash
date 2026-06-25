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
 * No store at all: create() with neither bindingStore nor storeInSession
 * still returns an instance — its stateless fingerprint(req) works (it
 * touches no store), while bind/verify/unbind throw a clear "no store
 * configured" error. Operators who only need the soft, store-free digest
 * (sealed inside a self-validating cookie / JWT that compares it itself)
 * can also skip create() entirely and call the static
 * b.sessionDeviceBinding.fingerprint(req, opts).
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
 *   - bind / verify / unbind → throw on bad token / req shape (operator
 *                      typo), and throw "no store configured" when called
 *                      on a store-free instance
 *   - storage errors  → fail-CLOSED on verify (drift indistinguishable
 *                       from a wiped store, refuse rather than allow)
 *                       fail-OPEN on bind (don't lose a fresh session
 *                       to a transient cache outage)
 */

var C            = require("./constants");
var bCrypto = require("./crypto");
var nodeCrypto   = require("node:crypto");
var lazyRequire  = require("./lazy-require");
var requestHelpers = require("./request-helpers");
var validateOpts = require("./validate-opts");
var { SessionDeviceBindingError } = require("./framework-error");

var observability = lazyRequire(function () { return require("./observability"); });

var DEFAULT_TTL_MS         = C.TIME.days(7);
var DEFAULT_IP_V4_PREFIX   = 24; // IPv4 /24 fingerprint mask in bits
var DEFAULT_IP_V6_PREFIX   = 48; // IPv6 /48 fingerprint mask in bits
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

// Mask the client IP to its fingerprint bucket. Routes through the shared
// canonical masker (requestHelpers.ipPrefix) so a `::`-shorthand address and
// its fully-expanded equivalent (2001:db8::1 vs 2001:db8:0:0:0:0:0:1), or a
// leading-zero-folded group, collapse to ONE bucket — the hand-rolled textual
// ':'-group slice this replaced hashed them differently and logged a roaming
// user out on a false drift. `bits === 0` is the documented "skip the IP check
// entirely" escape hatch (mobile clients that switch networks), so it returns
// "" before any masking. `bits` is the family-resolved configured width (cfg
// .v4Bits for a v4 client, cfg.v6Bits for v6 — default /24 + /48); pass it as
// BOTH v4Bits and v6Bits so the canonical masker applies the configured width
// to whichever family it detects, instead of ipPrefix's bare /24 + /64 default
// (which would drop the configured width AND silently tighten v6 from /48 to /64).
function _ipPrefix(ip, bits) {
  if (typeof ip !== "string" || ip.length === 0) return "";
  if (bits === 0) return "";
  return requestHelpers.ipPrefix(ip, { v4Bits: bits, v6Bits: bits });
}

// Resolve operator-supplied fingerprintExtras(req) to a stable string. A
// throwing or non-serializable extractor drops to "" — extras only sharpen the
// digest, they must never crash fingerprinting.
function _resolveExtrasFn(fn, req) {
  if (!fn) return "";
  var v;
  try { v = fn(req); } catch (_e) { return ""; }
  if (v === null || v === undefined) return "";
  if (typeof v === "string") return v;
  try { return JSON.stringify(v); } catch (_e) { return ""; }
}

// Clamp an { v4, v6 } prefix-bits opt to valid IPv4/IPv6 ranges, defaulting
// each independently.
function _resolveIpBits(ipBits) {
  ipBits = ipBits || {};
  return {
    v4: (typeof ipBits.v4 === "number" && isFinite(ipBits.v4) && ipBits.v4 >= 0 && ipBits.v4 <= 32)    // IPv4 max prefix length in bits
      ? ipBits.v4 : DEFAULT_IP_V4_PREFIX,
    v6: (typeof ipBits.v6 === "number" && isFinite(ipBits.v6) && ipBits.v6 >= 0 && ipBits.v6 <= 128)   // IPv6 max prefix length in bits
      ? ipBits.v6 : DEFAULT_IP_V6_PREFIX,
  };
}

// Pure request-shape device fingerprint — the side-effect-free core shared by
// the instance lookup and the static fingerprint() entry point. cfg: { v4Bits,
// v6Bits, extras (string), boundKey (Buffer|null) }. No store, no audit, no
// session — just headers + masked client IP (+ optional bound key) -> SHAKE256.
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
  if (opts.fingerprintExtras !== undefined) _requireFunction("fingerprintExtras", opts.fingerprintExtras);

  var requireBoundKey = !!opts.requireBoundKey;
  if (requireBoundKey && typeof opts.boundKeyResolver !== "function") {
    throw new SessionDeviceBindingError("session-device-binding/bad-opt",
      "requireBoundKey requires opts.boundKeyResolver");
  }

  var ipBits = opts.ipPrefixBits || {};
  var v4Bits = typeof ipBits.v4 === "number" && isFinite(ipBits.v4) && ipBits.v4 >= 0 && ipBits.v4 <= 32 // IPv4 max prefix length in bits
    ? ipBits.v4 : DEFAULT_IP_V4_PREFIX;
  var v6Bits = typeof ipBits.v6 === "number" && isFinite(ipBits.v6) && ipBits.v6 >= 0 && ipBits.v6 <= 128 // IPv6 max prefix length in bits
    ? ipBits.v6 : DEFAULT_IP_V6_PREFIX;

  var ttlMs = opts.ttlMs !== undefined ? opts.ttlMs : DEFAULT_TTL_MS;
  if (typeof ttlMs !== "number" || !isFinite(ttlMs) || ttlMs <= 0) {
    throw new SessionDeviceBindingError("session-device-binding/bad-opt",
      "ttlMs must be a positive finite number, got " + JSON.stringify(ttlMs));
  }

  var storeInSession = !!opts.storeInSession;
  // A no-store instance is still useful: the stateless fingerprint() reads no
  // store and is the soft device-binding building block for self-validating
  // tokens (a sealed cookie / JWT carrying the fingerprint inside). Rather than
  // refuse to construct (issue #330 — fingerprint() unreachable without a
  // store), build the instance and let the persisted bind()/verify() lifecycle
  // throw a clear "no store configured" when actually called. Operators wanting
  // ONLY the stateless digest can also use the static
  // b.sessionDeviceBinding.fingerprint(req, opts) with no create() at all.
  var hasStore = !!(storeInSession || opts.bindingStore);
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

  var _emitObs = observability().makeCounterEmitter(obsInst);

  var _emitAudit = requestHelpers.makeResourceAuditEmitter(auditInst, "session.device");

  function _hashTokenForAudit(token) {
    // Don't put the raw session id in the audit log. SHAKE256 to a
    // stable short label.
    return nodeCrypto.createHash("sha3-256").update("bj-session-device:" + token).digest("hex").slice(0, 16); // sha3-256 hex truncation length in chars
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
    _requireStore("unbind");
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
  fingerprint:             fingerprint,
  SessionDeviceBindingError: SessionDeviceBindingError,
  DEFAULTS:                Object.freeze({
    ttlMs:        DEFAULT_TTL_MS,
    ipV4Prefix:   DEFAULT_IP_V4_PREFIX,
    ipV6Prefix:   DEFAULT_IP_V6_PREFIX,
    fingerprintBytes: FINGERPRINT_BYTES,
  }),
};
