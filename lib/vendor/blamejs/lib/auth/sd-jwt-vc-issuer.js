"use strict";
/**
 * b.auth.sdJwtVc.issuer — operator-side SD-JWT VC issuer factory.
 *
 * Wraps the lower-level issue() function with key-management + key-id
 * (kid) + per-issuance audit emission. Operators running an issuer
 * service (EUDI Wallet provider, OIDC4VCI issuer, internal credential
 * service) instantiate one of these per signing key.
 *
 *   var issuer = b.auth.sdJwtVc.issuer.create({
 *     issuerUrl:    "https://issuer.example.com",
 *     keys: [
 *       { kid: "issuer-2026-q2", privateKey: pem, algorithm: "ES256" },
 *     ],
 *     activeKid:    "issuer-2026-q2",
 *     defaultTtlMs: C.TIME.days(90),
 *     auditOn:      true,
 *   });
 *
 *   var sdJwt = await issuer.issue({
 *     vct:           "https://example.com/vct/identity",
 *     subject:       "did:web:alice",
 *     claims: {
 *       given_name:    "Alice",
 *       family_name:   "Smith",
 *       birthdate:     "1990-01-15",
 *     },
 *     selectivelyDisclosed: ["given_name", "family_name", "birthdate"],
 *     holderKey:     holderJwk,
 *   });
 *
 *   // Key rollover (rotate to a new signing key)
 *   issuer.rotateKey({ kid: "issuer-2026-q3", privateKey: pem2 });
 *
 *   // Operator-side audit / metering
 *   var stats = issuer.stats();   // { issued, lastIssuedAt, keys: [...] }
 *
 * Audit emissions (audit namespace `auth`):
 *   auth.sdJwtVc.issued        — every successful issue() call
 *   auth.sdJwtVc.key_rotated   — every rotateKey() invocation
 */

var C = require("../constants");
var lazyRequire = require("../lazy-require");
var validateOpts = require("../validate-opts");
var { AuthError } = require("../framework-error");

// Lazy-required to avoid the issuer ↔ core circular load: sd-jwt-vc.js
// requires sd-jwt-vc-issuer.js for its module.exports surface, and
// the issuer needs sd-jwt-vc.js's issue() function for the actual
// signing path.
var sdJwtVcCore = lazyRequire(function () { return require("./sd-jwt-vc"); });

var audit = lazyRequire(function () { return require("../audit"); });
var observability = lazyRequire(function () { return require("../observability"); });

function create(opts) {
  validateOpts.requireObject(opts, "auth.sdJwtVc.issuer.create", AuthError);
  validateOpts(opts, [
    "issuerUrl", "keys", "activeKid",
    "defaultTtlMs", "defaultHashAlg", "auditOn",
  ], "auth.sdJwtVc.issuer.create");

  validateOpts.requireNonEmptyString(opts.issuerUrl,
    "issuer.create: issuerUrl", AuthError, "auth-sd-jwt-vc/bad-opts");
  if (!Array.isArray(opts.keys) || opts.keys.length === 0) {
    throw new AuthError("auth-sd-jwt-vc/no-keys",
      "issuer.create: keys must be a non-empty array");
  }
  for (var i = 0; i < opts.keys.length; i++) {
    var k = opts.keys[i];
    if (!k || typeof k !== "object") {
      throw new AuthError("auth-sd-jwt-vc/bad-key",
        "issuer.create: keys[" + i + "] must be an object");
    }
    if (typeof k.kid !== "string" || k.kid.length === 0) {
      throw new AuthError("auth-sd-jwt-vc/bad-key",
        "issuer.create: keys[" + i + "].kid is required");
    }
    if (!k.privateKey) {
      throw new AuthError("auth-sd-jwt-vc/bad-key",
        "issuer.create: keys[" + i + "].privateKey is required");
    }
  }
  validateOpts.optionalPositiveFinite(opts.defaultTtlMs,
    "issuer.create: defaultTtlMs", AuthError, "auth-sd-jwt-vc/bad-opts");

  var keysByKid = Object.create(null);
  for (var j = 0; j < opts.keys.length; j++) {
    keysByKid[opts.keys[j].kid] = opts.keys[j];
  }
  var activeKid = opts.activeKid || opts.keys[0].kid;
  if (!keysByKid[activeKid]) {
    throw new AuthError("auth-sd-jwt-vc/bad-active-kid",
      "issuer.create: activeKid \"" + activeKid + "\" is not in the keys array");
  }
  var defaultTtlMs = opts.defaultTtlMs || C.TIME.days(90);
  var defaultHashAlg = opts.defaultHashAlg || "sha-256";
  var auditOn = opts.auditOn !== false;

  var stats = {
    issued:       0,
    lastIssuedAt: null,
    keysRotated:  0,
  };

  function _emitAudit(action, outcome, metadata) {
    if (!auditOn) return;
    try {
      audit().safeEmit({
        action:   action,
        outcome:  outcome,
        metadata: metadata || {},
      });
    } catch (_e) { /* drop-silent */ }
  }

  function _emitMetric(verb) {
    try { observability().safeEvent("auth.sdJwtVc.issuer." + verb, 1, {}); }
    catch (_e) { /* drop-silent */ }
  }

  async function issue(spec) {
    if (!spec || typeof spec !== "object") {
      throw new AuthError("auth-sd-jwt-vc/bad-spec",
        "issuer.issue: spec must be an object");
    }
    if (typeof spec.vct !== "string") {
      throw new AuthError("auth-sd-jwt-vc/bad-spec",
        "issuer.issue: vct is required");
    }
    var key = keysByKid[activeKid];
    var issued = sdJwtVcCore().issue({
      issuer:               opts.issuerUrl,
      subject:              spec.subject || null,
      vct:                  spec.vct,
      claims:               spec.claims || {},
      selectivelyDisclosed: spec.selectivelyDisclosed || [],
      issuerKey:            key.privateKey,
      algorithm:            key.algorithm || "ES256",
      hashAlg:              spec.hashAlg || defaultHashAlg,
      ttlMs:                spec.ttlMs || defaultTtlMs,
      holderKey:            spec.holderKey || null,
      issuedAt:             spec.issuedAt,
      extraHeader:          { kid: activeKid },
    });
    stats.issued += 1;
    stats.lastIssuedAt = Date.now();
    _emitAudit("auth.sdJwtVc.issued", "success", {
      kid:       activeKid,
      vct:       spec.vct,
      subject:   spec.subject || null,
      disclosed: (spec.selectivelyDisclosed || []).length,
    });
    _emitMetric("issued");
    return issued;
  }

  function rotateKey(newKey) {
    if (!newKey || typeof newKey !== "object" ||
        typeof newKey.kid !== "string" || !newKey.privateKey) {
      throw new AuthError("auth-sd-jwt-vc/bad-key",
        "rotateKey: must pass { kid, privateKey, algorithm? }");
    }
    keysByKid[newKey.kid] = newKey;
    activeKid = newKey.kid;
    stats.keysRotated += 1;
    _emitAudit("auth.sdJwtVc.key_rotated", "success", {
      newKid: newKey.kid,
    });
    _emitMetric("key_rotated");
  }

  function listKids() { return Object.keys(keysByKid); }

  function statsSnapshot() {
    return {
      issued:       stats.issued,
      lastIssuedAt: stats.lastIssuedAt,
      keysRotated:  stats.keysRotated,
      activeKid:    activeKid,
      kids:         listKids(),
    };
  }

  return {
    issue:      issue,
    rotateKey:  rotateKey,
    listKids:   listKids,
    stats:      statsSnapshot,
    issuerUrl:  opts.issuerUrl,
  };
}

module.exports = {
  create: create,
};
