"use strict";
/**
 * Step-up elevation grant — short-lived signed tokens that record a
 * successful step-up ceremony. The grant is presented on subsequent
 * sensitive requests (within a tight TTL) so the user does not face a
 * step-up challenge on every action of a multi-step sensitive flow.
 *
 * Tokens are HMAC-SHA3-512 signed (single-key on the operator's side —
 * not asymmetric since these never leave the resource server). The
 * payload binds:
 *
 *   subject   — the authenticated user / session
 *   scope     — operator-defined string (e.g. "billing:write",
 *               "admin:bulk-update", "phi:read")
 *   acr       — the achieved ACR value at step-up time
 *   amr       — the methods that satisfied step-up (RFC 8176)
 *   evidence  — operator-supplied opaque blob (audit/forensic value
 *               only — never trust to drive policy)
 *   iat / exp / jti
 *
 * Tokens are revocable: revoke(jti) adds the jti to an in-process
 * deny-set checked by verify(). Operators with multi-node clusters
 * pass `revokedSet` opt to back the deny-set with their own KV.
 *
 * Token format: base64url(JSON-payload) + "." + base64url(HMAC).
 *
 * Per the validation-tier policy: create() throws on bad opts (config-
 * time entry-point); verify() returns structured errors (hot path).
 */

var nodeCrypto    = require("node:crypto");
var validateOpts  = require("../validate-opts");
var lazyRequire   = require("../lazy-require");
var safeJson      = require("../safe-json");
var C             = require("../constants");
var { AuthError } = require("../framework-error");

var audit         = lazyRequire(function () { return require("../audit"); });
var bCrypto      = lazyRequire(function () { return require("../crypto"); });

var DEFAULT_TTL_SEC      = C.TIME.minutes(15) / C.TIME.seconds(1);
var MAX_TTL_SEC          = C.TIME.hours(1)    / C.TIME.seconds(1);
var MIN_TTL_SEC          = C.TIME.seconds(30) / C.TIME.seconds(1);
var DEFAULT_KEY_BYTES    = C.BYTES.bytes(64);
var MAC_BYTES            = C.BYTES.bytes(64);
var MIN_KEY_BYTES        = C.BYTES.bytes(32);

// In-process state.
var _signingKey   = null;
var _revokedSet   = Object.create(null);
var _activeGrants = Object.create(null);   // jti → { exp, subject } for list()

function _ensureSigningKey() {
  if (_signingKey != null) return _signingKey;
  _signingKey = nodeCrypto.randomBytes(DEFAULT_KEY_BYTES);
  return _signingKey;
}

function setSigningKey(keyBuffer) {
  if (!Buffer.isBuffer(keyBuffer) || keyBuffer.length < MIN_KEY_BYTES) {
    throw new AuthError("auth-stepUp/bad-key",
      "auth.stepUp.grant.setSigningKey: keyBuffer must be a Buffer of >= " +
      MIN_KEY_BYTES + " bytes");
  }
  _signingKey = Buffer.from(keyBuffer);                       // copy — caller may mutate
}

function _b64url(buf) {
  return Buffer.from(buf).toString("base64url");
}

function _b64urlDecode(str) {
  if (typeof str !== "string") return null;
  try { return Buffer.from(str, "base64url"); }
  catch (_e) { return null; }
}

function _macFor(payloadB64) {
  var key = _ensureSigningKey();
  return nodeCrypto.createHmac("sha3-512", key).update(payloadB64).digest();
}

function _timingSafeEqualBuf(a, b) {
  if (!Buffer.isBuffer(a) || !Buffer.isBuffer(b)) return false;
  return bCrypto().timingSafeEqual(a, b);
}

function create(opts) {
  opts = opts || {};
  validateOpts(opts, [
    "subject", "scope", "acr", "amr", "evidence",
    "ttlSec", "audience", "now",
  ], "auth.stepUp.grant.create");
  validateOpts.requireNonEmptyString(opts.subject,
    "grant.create: subject", AuthError, "auth-stepUp/bad-grant");
  validateOpts.requireNonEmptyString(opts.scope,
    "grant.create: scope", AuthError, "auth-stepUp/bad-grant");
  if (opts.acr != null) {
    validateOpts.requireNonEmptyString(opts.acr,
      "grant.create: acr", AuthError, "auth-stepUp/bad-grant");
  }
  if (opts.amr != null) {
    if (!Array.isArray(opts.amr)) {
      throw new AuthError("auth-stepUp/bad-grant",
        "grant.create: amr must be an array — got " + typeof opts.amr);
    }
    for (var i = 0; i < opts.amr.length; i += 1) {
      if (typeof opts.amr[i] !== "string") {
        throw new AuthError("auth-stepUp/bad-grant",
          "grant.create: amr[" + i + "] must be a string");
      }
    }
  }
  if (opts.audience != null) {
    validateOpts.requireNonEmptyString(opts.audience,
      "grant.create: audience", AuthError, "auth-stepUp/bad-grant");
  }
  var ttlSec = (typeof opts.ttlSec === "number") ? opts.ttlSec : DEFAULT_TTL_SEC;
  if (!isFinite(ttlSec) || ttlSec < MIN_TTL_SEC) {
    throw new AuthError("auth-stepUp/bad-grant",
      "grant.create: ttlSec must be a finite number >= " +
      MIN_TTL_SEC + " — got " + JSON.stringify(opts.ttlSec));
  }
  if (ttlSec > MAX_TTL_SEC) {
    throw new AuthError("auth-stepUp/bad-grant",
      "grant.create: ttlSec must be <= " + MAX_TTL_SEC +
      " (1h hard ceiling) — got " + ttlSec);
  }
  var nowSec = (typeof opts.now === "number" && isFinite(opts.now))
    ? opts.now : Math.floor(Date.now() / C.TIME.seconds(1));
  var jti = bCrypto().generateBytes(C.BYTES.bytes(16)).toString("base64url");
  var payload = {
    sub:      opts.subject,
    scope:    opts.scope,
    acr:      opts.acr || null,
    amr:      Array.isArray(opts.amr) ? opts.amr.slice() : null,
    aud:      opts.audience || null,
    iat:      nowSec,
    exp:      nowSec + ttlSec,
    jti:      jti,
  };
  if (opts.evidence != null) {
    payload.evd = opts.evidence;                       // opaque pass-through
  }
  var payloadJson = JSON.stringify(payload);
  var payloadB64  = _b64url(payloadJson);
  var mac         = _macFor(payloadB64);
  var token       = payloadB64 + "." + _b64url(mac);

  _activeGrants[jti] = { exp: payload.exp, subject: opts.subject, scope: opts.scope };

  try {
    audit().safeEmit({
      action:  "auth.stepup.grant.issued",
      outcome: "success",
      actor:   { userId: opts.subject },
      metadata: {
        jti:    jti,
        scope:  opts.scope,
        acr:    opts.acr || null,
        amr:    Array.isArray(opts.amr) ? opts.amr.slice() : null,
        ttl:    ttlSec,
      },
    });
  } catch (_e) { /* drop-silent */ }

  return { token: token, expiresAt: payload.exp, jti: jti, payload: payload };
}

function verify(token, opts) {
  opts = opts || {};
  if (typeof token !== "string" || token.length === 0) {
    return { ok: false, error: "no_token", reason: "verify: token must be a non-empty string" };
  }
  validateOpts(opts, [
    "audience", "scope", "subject", "now",
  ], "auth.stepUp.grant.verify");
  var dot = token.indexOf(".");
  if (dot === -1) {
    return { ok: false, error: "malformed", reason: "verify: token missing '.' separator" };
  }
  var payloadB64 = token.slice(0, dot);
  var macB64     = token.slice(dot + 1);
  var presentedMac = _b64urlDecode(macB64);
  if (presentedMac == null || presentedMac.length !== MAC_BYTES) {
    return { ok: false, error: "malformed", reason: "verify: mac decode failed or wrong length" };
  }
  var expectedMac = _macFor(payloadB64);
  if (!_timingSafeEqualBuf(presentedMac, expectedMac)) {
    return { ok: false, error: "bad_mac", reason: "verify: mac mismatch" };
  }
  var payloadBuf = _b64urlDecode(payloadB64);
  if (payloadBuf == null) {
    return { ok: false, error: "malformed", reason: "verify: payload decode failed" };
  }
  var payload;
  try { payload = safeJson.parse(payloadBuf.toString("utf8"), { maxBytes: C.BYTES.kib(8) }); }
  catch (_e) { return { ok: false, error: "malformed", reason: "verify: payload JSON parse failed" }; }
  if (!payload || typeof payload !== "object") {
    return { ok: false, error: "malformed", reason: "verify: payload not an object" };
  }
  var nowSec = (typeof opts.now === "number" && isFinite(opts.now))
    ? opts.now : Math.floor(Date.now() / C.TIME.seconds(1));
  if (typeof payload.exp !== "number" || payload.exp < nowSec) {
    return { ok: false, error: "expired", reason: "verify: token expired (exp=" + payload.exp + ", now=" + nowSec + ")" };
  }
  if (typeof payload.iat !== "number" ||
      payload.iat > nowSec + (C.TIME.seconds(60) / C.TIME.seconds(1))) {
    return { ok: false, error: "future_iat", reason: "verify: iat is in the future" };
  }
  if (opts.audience != null && payload.aud !== opts.audience) {
    return { ok: false, error: "audience_mismatch",
             reason: "verify: audience " + JSON.stringify(payload.aud) +
                     " does not match required " + JSON.stringify(opts.audience) };
  }
  if (opts.scope != null && payload.scope !== opts.scope) {
    return { ok: false, error: "scope_mismatch",
             reason: "verify: scope " + JSON.stringify(payload.scope) +
                     " does not match required " + JSON.stringify(opts.scope) };
  }
  if (opts.subject != null && payload.sub !== opts.subject) {
    return { ok: false, error: "subject_mismatch",
             reason: "verify: subject " + JSON.stringify(payload.sub) +
                     " does not match required " + JSON.stringify(opts.subject) };
  }
  if (typeof payload.jti === "string" && _revokedSet[payload.jti] === true) {
    return { ok: false, error: "revoked", reason: "verify: jti has been revoked" };
  }

  try {
    audit().safeEmit({
      action:  "auth.stepup.grant.consumed",
      outcome: "success",
      actor:   { userId: payload.sub },
      metadata: {
        jti:   payload.jti || null,
        scope: payload.scope,
        aud:   payload.aud || null,
      },
    });
  } catch (_e) { /* drop-silent */ }

  return { ok: true, payload: payload };
}

function revoke(jti, opts) {
  opts = opts || {};
  validateOpts(opts, ["reason"], "auth.stepUp.grant.revoke");
  if (typeof jti !== "string" || jti.length === 0) {
    throw new AuthError("auth-stepUp/bad-jti",
      "grant.revoke: jti must be a non-empty string — got " + JSON.stringify(jti));
  }
  _revokedSet[jti] = true;
  var prior = _activeGrants[jti];
  delete _activeGrants[jti];

  try {
    audit().safeEmit({
      action:  "auth.stepup.grant.revoked",
      outcome: "success",
      actor:   { userId: prior && prior.subject || null },
      metadata: { jti: jti, reason: opts.reason || null },
    });
  } catch (_e) { /* drop-silent */ }

  return { ok: true, jti: jti };
}

function isRevoked(jti) {
  if (typeof jti !== "string") return false;
  return _revokedSet[jti] === true;
}

function list() {
  var nowSec = Math.floor(Date.now() / C.TIME.seconds(1));
  var out = [];
  for (var jti in _activeGrants) {
    if (Object.prototype.hasOwnProperty.call(_activeGrants, jti)) {
      var entry = _activeGrants[jti];
      if (entry.exp > nowSec && !_revokedSet[jti]) {
        out.push({ jti: jti, subject: entry.subject, scope: entry.scope, exp: entry.exp });
      }
    }
  }
  out.sort(function (a, b) { return a.exp - b.exp; });
  return out;
}

function _resetForTests() {
  _signingKey = null;
  _revokedSet = Object.create(null);
  _activeGrants = Object.create(null);
}

module.exports = {
  create:           create,
  verify:           verify,
  revoke:           revoke,
  isRevoked:        isRevoked,
  list:             list,
  setSigningKey:    setSigningKey,
  DEFAULT_TTL_SEC:  DEFAULT_TTL_SEC,
  MAX_TTL_SEC:      MAX_TTL_SEC,
  MIN_TTL_SEC:      MIN_TTL_SEC,
  _resetForTests:   _resetForTests,
};
