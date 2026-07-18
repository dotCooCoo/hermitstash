// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module     b.auth.openidFederation
 * @nav        Identity
 * @title      OpenID Federation 1.0
 * @order      360
 * @card       OpenID Federation 1.0 trust-chain primitive — fetches +
 *             verifies a chain of entity statements from a leaf (RP /
 *             OP / wallet) up to one of the operator's trust anchors,
 *             then applies the federation's metadata policy to produce
 *             the effective metadata for the leaf.
 *
 * @intro
 *   OpenID Federation 1.0 (OIDF) replaces ad-hoc client registration
 *   with a JWS-signed delegation chain. Every entity in the federation
 *   publishes an *entity configuration* at
 *   `<entity_id>/.well-known/openid-federation` (a self-signed JWT
 *   listing the entity's keys + metadata + which superiors are
 *   allowed to sign subordinate statements about it via
 *   `authority_hints`).
 *
 *   Each *intermediate* publishes *subordinate statements* signed
 *   over the entity directly below — these statements pin the
 *   subordinate's JWKS plus an optional `metadata_policy` that
 *   adjusts the subordinate's claimed metadata (default values,
 *   required claims, allowed-value sets, etc.). The *trust anchor*
 *   sits at the top — its public key is operator-configured (out-of-
 *   band, baked into the deployment).
 *
 *   The verifier walks: leaf entity-config → leaf's authority_hints
 *   → fetch subordinate-statement-about-leaf from each authority →
 *   verify the JWS using that authority's keys → ascend to that
 *   authority's entity config → repeat until a trust anchor is
 *   reached. The chain must close at a trust anchor; a chain that
 *   doesn't is refused.
 *
 *   Surface:
 *
 *     b.auth.openidFederation.parseEntityStatement(jwt) → claims
 *     b.auth.openidFederation.verifyEntityStatement(jwt, jwks) → claims
 *     b.auth.openidFederation.buildTrustChain({ leafEntityId, trustAnchors, fetcher? })
 *       → [{jwt, claims, role}]   (leaf-first)
 *     b.auth.openidFederation.applyMetadataPolicy(metadata, chain) → effective metadata
 *     b.auth.openidFederation.resolveLeaf({ leafEntityId, trustAnchors, ... })
 *       → { effectiveMetadata, chain, trustAnchor }
 *
 *   The framework does NOT publish entity configurations — that's a
 *   route the operator's RP code stands up. Verification + chain
 *   construction is the framework's job; serving is operator-side.
 *
 *   Metadata-policy operators implemented (per OpenID Federation 1.0
 *   §6.2): value, add, default, one_of, subset_of, superset_of,
 *   essential. Unknown operators refuse loudly so a misconfigured
 *   policy doesn't silently let unauthorized metadata through.
 */

var lazyRequire  = require("../lazy-require");
var validateOpts = require("../validate-opts");
var safeJson     = require("../safe-json");
var pick         = require("../pick");
var nodeCrypto   = require("node:crypto");
var bCrypto      = require("../crypto");
var C            = require("../constants");
// Shared JOSE defenses (CVE-2026-22817 alg/kty cross-check +
// CVE-2026-23552 constant-time iss compare). Top-of-file per project
// convention §3; no circular load — jwt-external requires nothing from
// openid-federation.
var jwtExternal  = require("./jwt-external");
var { AuthError } = require("../framework-error");

// Default federation-statement clock-skew tolerance in seconds. OIDC
// Federation 1.0 doesn't fix a value; 60s matches the framework-wide
// default applied to ID tokens. Operators tune via
// verifyEntityStatement(jwt, jwks, { maxClockSkewSec }).
var DEFAULT_FEDERATION_CLOCK_SKEW_SEC = C.TIME.minutes(1) / C.TIME.seconds(1);

var httpClient = lazyRequire(function () { return require("../http-client"); });
var audit      = lazyRequire(function () { return require("../audit"); });
var observability = lazyRequire(function () { return require("../observability"); });
var emit = validateOpts.makeNamespacedEmitters("auth.openidFederation", { audit: audit, observability: observability });

var _emitAudit  = emit.audit;
var _emitMetric = emit.metric;

var SUPPORTED_ALGS = ["ES256", "ES384", "ES512", "PS256", "PS384", "PS512", "RS256", "EdDSA"];
var MAX_STATEMENT_BYTES = 64 * 1024;
var MAX_CHAIN_DEPTH = 10;                                                                       // federation chain depth ceiling

function _b64uDecodeStr(s) { return Buffer.from(s, "base64url").toString("utf8"); }

function _hashByAlg(alg) {
  return { ES256: "sha256", ES384: "sha384", ES512: "sha512",
           PS256: "sha256", PS384: "sha384", PS512: "sha512",
           RS256: "sha256", EdDSA: null }[alg];
}

/**
 * @primitive b.auth.openidFederation.parseEntityStatement
 * @signature b.auth.openidFederation.parseEntityStatement(jwt)
 * @since     0.8.62
 *
 * Decode (without verifying) an entity statement / configuration
 * JWT and return its header + claims. Used to look up the right
 * verification key BEFORE the signature check.
 *
 * @example
 *   var parsed = b.auth.openidFederation.parseEntityStatement(entityConfigJwt);
 *   // → { header: { typ, alg, kid }, claims: { iss, sub, iat, exp, jwks, ... } }
 */
function parseEntityStatement(jwt) {
  if (typeof jwt !== "string" || jwt.length === 0 || jwt.length > MAX_STATEMENT_BYTES) {
    throw new AuthError("auth-openid-federation/bad-statement",
      "entity statement empty or exceeds " + MAX_STATEMENT_BYTES + " bytes");
  }
  var parts = jwt.split(".");
  if (parts.length !== 3) {
    throw new AuthError("auth-openid-federation/malformed",
      "entity statement must be a 3-segment JWS");
  }
  var header, payload;
  try {
    header  = safeJson.parse(_b64uDecodeStr(parts[0]), { maxBytes: 4096 });                     // header cap
    payload = safeJson.parse(_b64uDecodeStr(parts[1]), { maxBytes: MAX_STATEMENT_BYTES });
  } catch (e) {
    throw new AuthError("auth-openid-federation/bad-decode",
      "entity statement decode failed: " + ((e && e.message) || String(e)));
  }
  if (header.typ !== "entity-statement+jwt") {
    throw new AuthError("auth-openid-federation/wrong-typ",
      "entity statement header.typ must be \"entity-statement+jwt\" (got \"" + header.typ + "\")");
  }
  if (!header.alg || SUPPORTED_ALGS.indexOf(header.alg) === -1) {
    throw new AuthError("auth-openid-federation/unsupported-alg",
      "entity statement alg \"" + header.alg + "\" not supported");
  }
  return { header: header, claims: payload, parts: parts };
}

/**
 * @primitive b.auth.openidFederation.verifyEntityStatement
 * @signature b.auth.openidFederation.verifyEntityStatement(jwt, jwks, vopts)
 * @since     0.8.62
 *
 * Verify a single entity statement's JWS signature using the
 * provided JWKS. Returns the parsed claims on success; throws on
 * any failure (malformed / wrong typ / unsupported alg / no
 * matching kid / bad signature / iat-future / expired).
 *
 * @opts
 *   maxClockSkewSec: number   // tolerance for iat / exp; default: 60
 *   now:             number   // override Date.now() for tests
 *
 * @example
 *   var claims = b.auth.openidFederation.verifyEntityStatement(jwt, anchorJwks);
 *   // → { iss, sub, iat, exp, jwks, metadata, authority_hints, ... }
 */
function verifyEntityStatement(jwt, jwks, vopts) {
  vopts = vopts || {};
  var parsed = parseEntityStatement(jwt);
  if (!jwks || !Array.isArray(jwks.keys) || jwks.keys.length === 0) {
    throw new AuthError("auth-openid-federation/no-keys",
      "verifyEntityStatement: jwks must include a keys[] array");
  }
  var key = null;
  if (parsed.header.kid) {
    for (var i = 0; i < jwks.keys.length; i++) {
      if (jwks.keys[i].kid === parsed.header.kid) { key = jwks.keys[i]; break; }
    }
    if (!key) {
      throw new AuthError("auth-openid-federation/no-matching-kid",
        "verifyEntityStatement: no JWKS key matches kid \"" + parsed.header.kid + "\"");
    }
  } else {
    // Refuse kid-less entity statements unless the operator
    // explicitly opts in. JWKS rotation creates a window where the
    // rotated-out key is still cached but the rotated-in key is already
    // published; a kid-less statement during that window gets the
    // lone-key path silently. Modern federations always emit kid; the
    // gap that oauth + jwt-external closed in v0.9.4 applies here too.
    if (jwks.keys.length === 1 && vopts.allowKidlessJwks === true) {
      key = jwks.keys[0];
    } else {
      throw new AuthError("auth-openid-federation/kid-required",
        "verifyEntityStatement: header.kid absent — framework refuses kid-less " +
        "entity statements to defend against JWKS-rotation key-pick attacks " +
        "(pass vopts.allowKidlessJwks: true to opt out)");
    }
  }

  // CVE-2026-22817 — cross-check the JWK key type against the JWS alg
  // BEFORE verifying. Without this an attacker-controlled entity-config
  // can declare `alg: "ES256"` while supplying an RSA `kty: "RSA"` JWK;
  // Node will silently use the RSA key with SHA-256 and the signature
  // verify either always-fails (PSS) or succeeds against a payload the
  // attacker crafted (alg/key-type confusion). Routed through the
  // shared helper so every JWT verifier in the framework enforces the
  // same check.
  jwtExternal._assertAlgKtyMatch(parsed.header.alg, key);

  var keyObj = bCrypto.importPublicJwk(key, {
    errorClass:    AuthError,
    code:          "auth-openid-federation/bad-jwk",
    messagePrefix: "verifyEntityStatement: JWK is not parseable: ",
  });

  var hash = _hashByAlg(parsed.header.alg);
  var verifyOpts = { key: keyObj };
  if (parsed.header.alg.indexOf("ES") === 0) verifyOpts.dsaEncoding = "ieee-p1363";
  if (parsed.header.alg.indexOf("PS") === 0) {
    verifyOpts.padding = nodeCrypto.constants.RSA_PKCS1_PSS_PADDING;
    verifyOpts.saltLength = nodeCrypto.constants.RSA_PSS_SALTLEN_DIGEST;
  }
  var signingInput = parsed.parts[0] + "." + parsed.parts[1];
  var sig = Buffer.from(parsed.parts[2], "base64url");
  var ok = nodeCrypto.verify(hash, Buffer.from(signingInput, "ascii"), verifyOpts, sig);
  if (!ok) {
    throw new AuthError("auth-openid-federation/bad-signature",
      "verifyEntityStatement: signature verification failed");
  }

  var nowSec = Math.floor(Date.now() / C.TIME.seconds(1));
  // Operator-tunable clock skew (sibling primitives accept
  // tunable). Default matches the prior fixed 60s.
  var skew = (typeof vopts.maxClockSkewSec === "number" && isFinite(vopts.maxClockSkewSec) && vopts.maxClockSkewSec >= 0)
    ? vopts.maxClockSkewSec
    : DEFAULT_FEDERATION_CLOCK_SKEW_SEC;
  if (typeof parsed.claims.iat !== "number" || parsed.claims.iat > nowSec + skew) {
    throw new AuthError("auth-openid-federation/iat-future",
      "verifyEntityStatement: iat is in the future or missing");
  }
  if (typeof parsed.claims.exp !== "number" || parsed.claims.exp < nowSec - skew) {
    throw new AuthError("auth-openid-federation/expired",
      "verifyEntityStatement: statement expired");
  }
  if (typeof parsed.claims.iss !== "string" || typeof parsed.claims.sub !== "string") {
    throw new AuthError("auth-openid-federation/missing-iss-sub",
      "verifyEntityStatement: iss + sub required");
  }
  return parsed.claims;
}

// ---- Metadata-policy set-ops + cross-level merge (OIDF 1.0 section 6.1.5) ----

// Union of two arrays (dedupe, first-seen order). The single array set-op the
// `add` / `superset_of` operators and the cross-level merge both compose,
// rather than hand-rolling the shape per call site.
function _arrayUnion(a, b) {
  var out = Array.isArray(a) ? a.slice() : [];
  if (Array.isArray(b)) {
    b.forEach(function (v) { if (out.indexOf(v) === -1) out.push(v); });
  }
  return out;
}

// Intersection of two arrays (values in both, a's order). The narrowing op the
// merge uses for `one_of` / `subset_of`: a subordinate can only narrow.
function _arrayIntersect(a, b) {
  if (!Array.isArray(a) || !Array.isArray(b)) return [];
  return a.filter(function (v) { return b.indexOf(v) !== -1; });
}

// a is a subset of b: every element of `a` is present in `b`. The set-op the
// OIDF 1.0 section 6.1.3 combination-consistency rules compose (add within
// subset_of, default within subset_of, superset_of within subset_of, ...).
function _arraySubset(a, b) {
  if (!Array.isArray(a) || !Array.isArray(b)) return false;
  return a.every(function (v) { return b.indexOf(v) !== -1; });
}

// View a metadata value as an array for the array policy operators. OAuth
// `scope` (and similar parameters) is a space-delimited string that OIDF 1.0
// section 6.1.3.1.8 processes as a string array, so a string is split on
// whitespace; an array is returned as-is; anything else yields null (the
// caller decides whether an absent / malformed value is a violation).
function _coerceOperandArray(val) {
  if (Array.isArray(val)) return val;
  if (typeof val === "string") return val.split(/\s+/).filter(Boolean);
  return null;
}

// OIDF 1.0 section 6.1.3 fixed operator processing order: the value-MODIFICATION
// operators (value, add, default) run first to produce the value, then the
// value-CHECK operators (one_of, subset_of, superset_of, essential) validate it.
var _OP_ORDER = ["value", "add", "default", "one_of", "subset_of", "superset_of", "essential"];

// Validate a merged claim's operator set for the two cross-level cases the
// fixed-order apply step cannot catch on its own. The apply step already runs
// every merged CHECK operator (one_of / subset_of / superset_of / essential)
// against the FINAL value the MODIFIER operators (value / add / default)
// produced -- coercing a space-delimited scope string to an array -- so a
// value, add, or default inconsistent with a co-present constraint is refused
// there against the merged (most-restrictive) constraint. This adds only what
// apply cannot see:
//   (1) `value` + `add` where `add` would WIDEN the exact pin -- the union
//       escapes `value`, and with no constraint operator present the apply step
//       has nothing to reject it. `add` already within `value` is a no-op,
//       allowed (OIDF 1.0 section 6.1.3.1.1).
//   (2) a `one_of` whose cross-level intersection is EMPTY -- no value can ever
//       satisfy the chain, a policy error per section 6.1.3.1.4 rather than a
//       silent accept-when-absent.
// Same-operator value/default equality is checked during the merge itself.
function _assertPolicyCombination(claim, acc) {
  function has(op) { return Object.prototype.hasOwnProperty.call(acc, op); }
  function conflict(why) {
    throw new AuthError("auth-openid-federation/policy-merge-conflict",
      "metadata_policy['" + claim + "']: " + why +
      " (a subordinate cannot widen a superior's constraint)");
  }
  if (has("value") && has("add")) {
    var pinned = _coerceOperandArray(acc.value) || [acc.value];
    if (!_arraySubset(acc.add, pinned)) {
      conflict("`add` would widen the pinned `value`");
    }
  }
  if (has("one_of") && acc.one_of.length === 0) {
    conflict("`one_of` values are disjoint across the chain (no allowed value remains)");
  }
}

// Combine the metadata_policy blocks from EVERY chain level into ONE policy per
// OIDF 1.0 section 6.1.5.3, so a subordinate can only NARROW a superior's
// constraint, never override it, and the combined policy is applied ONCE. Two
// levels pinning a DIFFERENT `value` (or `default`) is a cross-level conflict
// that makes the chain invalid and throws -- the pre-merge sequential apply let
// a leaf-ward `value` silently OVERWRITE the anchor's pinned value, a trust
// downgrade (e.g. token_endpoint_auth_method private_key_jwt -> none) the anchor
// forbade. `blocks` are ordered superior-first (anchor policy first).
function _mergeMetadataPolicies(blocks) {
  var merged = Object.create(null);
  blocks.forEach(function (block) {
    Object.keys(block).forEach(function (claim) {
      if (pick.isPoisonedKey(claim)) {
        throw new AuthError("auth-openid-federation/poisoned-policy-key",
          "metadata_policy claim name \"" + claim + "\" is a prototype-pollution vector");
      }
      var rules = block[claim];
      if (!rules || typeof rules !== "object") {
        throw new AuthError("auth-openid-federation/bad-policy-rules",
          "metadata_policy['" + claim + "'] must be an object");
      }
      var acc = merged[claim] || (merged[claim] = {});
      Object.keys(rules).forEach(function (op) {
        var v = rules[op];
        if (op === "value" || op === "default") {
          if (Object.prototype.hasOwnProperty.call(acc, op) &&
              JSON.stringify(acc[op]) !== JSON.stringify(v)) {
            throw new AuthError("auth-openid-federation/policy-merge-conflict",
              "metadata_policy['" + claim + "']." + op + " conflicts across the chain (" +
              JSON.stringify(acc[op]) + " vs " + JSON.stringify(v) +
              "): a subordinate cannot override a superior's pinned " + op);
          }
          acc[op] = v;
        } else if (op === "add" || op === "superset_of") {
          if (!Array.isArray(v)) {
            throw new AuthError("auth-openid-federation/bad-policy-" + (op === "add" ? "add" : "superset-of"),
              "metadata_policy['" + claim + "']." + op + " requires an array");
          }
          acc[op] = _arrayUnion(acc[op], v);
        } else if (op === "one_of" || op === "subset_of") {
          if (!Array.isArray(v)) {
            throw new AuthError("auth-openid-federation/bad-policy-" + (op === "one_of" ? "one-of" : "subset-of"),
              "metadata_policy['" + claim + "']." + op + " requires an array");
          }
          acc[op] = Object.prototype.hasOwnProperty.call(acc, op) ? _arrayIntersect(acc[op], v) : v.slice();
        } else if (op === "essential") {
          acc[op] = acc[op] === true || v === true;
        } else {
          throw new AuthError("auth-openid-federation/unknown-policy-op",
            "metadata_policy['" + claim + "'] unknown operator \"" + op + "\"");
        }
      });
    });
  });
  Object.keys(merged).forEach(function (claim) { _assertPolicyCombination(claim, merged[claim]); });
  return merged;
}

/**
 * Apply an already-merged metadata_policy block to a metadata object and
 * return the resulting object. Pure — never mutates input. Operators are
 * applied in the OIDF 1.0 §6.1.3 fixed order (value, add, default, one_of,
 * subset_of, superset_of, essential) so the value-CHECK operators validate the
 * value the value-MODIFICATION operators produced; the combined policy's
 * operator combination was validated during the merge (_assertPolicyCombination).
 *
 * Operators per OIDF 1.0 §6.1.3:
 *   value      — set claim to a fixed value (overrides subordinate)
 *   add        — array claim: append values not already present
 *   default    — provide a default if the claim is absent
 *   one_of     — claim must be one of the listed values (else throw)
 *   subset_of  — claim's array values must be a subset of the listed (else throw)
 *   superset_of — claim's array values must include every listed value (else throw)
 *   essential  — claim must be present (else throw)
 */
function _applyOnePolicy(metadata, policy) {
  // Build the working copy from own, non-prototype-polluting keys only -- a
  // metadata object carrying a "__proto__" / "constructor" / "prototype" own
  // key (e.g. from JSON.parse) would otherwise set out's prototype via
  // assignment; the merged policy's claim names are already poison-guarded.
  var out = {};
  Object.keys(metadata).forEach(function (mk) {
    if (!pick.isPoisonedKey(mk)) out[mk] = metadata[mk];
  });
  Object.keys(policy).forEach(function (claimName) {
    if (pick.isPoisonedKey(claimName)) return;
    var rules = policy[claimName];
    if (!rules || typeof rules !== "object") {
      throw new AuthError("auth-openid-federation/bad-policy-rules",
        "metadata_policy['" + claimName + "'] must be an object");
    }
    // Apply operators in the OIDF 1.0 section 6.1.3 fixed order so the
    // value-CHECK operators (one_of/subset_of/superset_of/essential) validate
    // the value AFTER the value-MODIFICATION operators (value/add/default) have
    // produced it -- Object.keys order let a check run before the value it must
    // guard was set. Any operator outside the fixed set is refused first.
    Object.keys(rules).forEach(function (op) {
      if (_OP_ORDER.indexOf(op) === -1) {
        throw new AuthError("auth-openid-federation/unknown-policy-op",
          "metadata_policy['" + claimName + "'] unknown operator \"" + op + "\"");
      }
    });
    _OP_ORDER.forEach(function (op) {
      if (!Object.prototype.hasOwnProperty.call(rules, op)) return;
      var v = rules[op];
      switch (op) {
        case "value":
          out[claimName] = v;
          break;
        case "default":
          if (out[claimName] === undefined) out[claimName] = v;
          break;
        case "add":
          if (!Array.isArray(v)) {
            throw new AuthError("auth-openid-federation/bad-policy-add",
              "metadata_policy['" + claimName + "'].add requires an array");
          }
          var _addResult = _arrayUnion(_coerceOperandArray(out[claimName]) || [], v);
          out[claimName] = typeof out[claimName] === "string" ? _addResult.join(" ") : _addResult;
          break;
        case "one_of":
          if (!Array.isArray(v)) {
            throw new AuthError("auth-openid-federation/bad-policy-one-of",
              "metadata_policy['" + claimName + "'].one_of requires an array");
          }
          if (out[claimName] !== undefined && v.indexOf(out[claimName]) === -1) {
            throw new AuthError("auth-openid-federation/policy-one-of-failed",
              "metadata_policy['" + claimName + "'].one_of: value \"" +
              JSON.stringify(out[claimName]) + "\" not in " + JSON.stringify(v));
          }
          break;
        case "subset_of":
          if (!Array.isArray(v)) {
            throw new AuthError("auth-openid-federation/bad-policy-subset-of",
              "metadata_policy['" + claimName + "'].subset_of requires an array");
          }
          if (out[claimName] !== undefined && out[claimName] !== null) {
            var _subArr = _coerceOperandArray(out[claimName]);
            if (_subArr === null) {
              throw new AuthError("auth-openid-federation/policy-subset-of-failed",
                "metadata_policy['" + claimName + "']: value " + JSON.stringify(out[claimName]) +
                " is neither an array nor a space-delimited string; subset_of constrains an array-valued claim");
            }
            _subArr.forEach(function (val) {
              if (v.indexOf(val) === -1) {
                throw new AuthError("auth-openid-federation/policy-subset-of-failed",
                  "metadata_policy['" + claimName + "']: value \"" + JSON.stringify(val) +
                  "\" not in subset_of " + JSON.stringify(v));
              }
            });
          }
          break;
        case "superset_of":
          if (!Array.isArray(v)) {
            throw new AuthError("auth-openid-federation/bad-policy-superset-of",
              "metadata_policy['" + claimName + "'].superset_of requires an array");
          }
          var _supArr = _coerceOperandArray(out[claimName]) || [];
          v.forEach(function (req) {
            if (_supArr.indexOf(req) === -1) {
              throw new AuthError("auth-openid-federation/policy-superset-of-failed",
                "metadata_policy['" + claimName + "']: missing required value \"" + req + "\"");
            }
          });
          break;
        case "essential":
          if (v === true && (out[claimName] === undefined || out[claimName] === null)) {
            throw new AuthError("auth-openid-federation/policy-essential-failed",
              "metadata_policy['" + claimName + "'].essential=true but claim is absent");
          }
          break;
        default:
          throw new AuthError("auth-openid-federation/unknown-policy-op",
            "metadata_policy['" + claimName + "'] unknown operator \"" + op + "\"");
      }
    });
  });
  return out;
}

/**
 * @primitive b.auth.openidFederation.applyMetadataPolicy
 * @signature b.auth.openidFederation.applyMetadataPolicy(metadata, chain, kind)
 * @since     0.8.62
 *
 * Apply the federation's metadata_policy (top-down) to the leaf's
 * declared metadata for the given entity-kind ("openid_relying_party"
 * / "openid_provider" / "federation_entity" / etc.) and return the
 * effective metadata. Throws on any policy violation.
 *
 * Per OpenID Federation 1.0 §6.2, an entity's metadata_policy comes
 * from the SUPERIOR-SIGNED subordinate statement about that entity
 * (`chain[i].subordinate.metadata_policy`), NOT from the entity's own
 * self-published configuration. An entity cannot self-declare the
 * policy that constrains it — that would let a leaf widen or drop the
 * trust anchor's value / subset_of / essential constraints. The leaf's
 * own self-config metadata_policy is therefore ignored.
 *
 * The chain is leaf-first; each `chain[i].subordinate` is the statement
 * signed by the superior directly above entity `i`; every level's policy
 * is merged into ONE combined policy so a subordinate can only NARROW a
 * superior's constraint (a leaf-ward level pinning a different
 * value/default refuses the chain as a trust downgrade), then applied
 * once (OIDF 1.0 §6.1.5.3).
 *
 * @example
 *   var effective = b.auth.openidFederation.applyMetadataPolicy(
 *     leafClaims.metadata.openid_relying_party,
 *     chain,
 *     "openid_relying_party"
 *   );
 *   // → metadata with default / one_of / subset_of constraints applied
 */
function applyMetadataPolicy(metadata, chain, kind) {
  if (!metadata || typeof metadata !== "object") {
    throw new AuthError("auth-openid-federation/bad-metadata",
      "applyMetadataPolicy: metadata must be an object");
  }
  if (!Array.isArray(chain)) {
    throw new AuthError("auth-openid-federation/bad-chain",
      "applyMetadataPolicy: chain must be an array");
  }
  Object.keys(metadata).forEach(function (mk) {
    if (pick.isPoisonedKey(mk)) {
      throw new AuthError("auth-openid-federation/poisoned-metadata-key",
        "applyMetadataPolicy: metadata key \"" + mk + "\" is a prototype-pollution vector");
    }
  });
  // Gather each SUPERIOR-SIGNED subordinate statement's policy for this kind,
  // superior-first (anchor policy first; the anchor node terminates the chain
  // with no .subordinate, and the leaf's own self-config policy is never read),
  // then MERGE every level into ONE combined policy so a subordinate can only
  // NARROW a superior's constraint (OIDF 1.0 section 6.1.5.3) -- a leaf-ward
  // level pinning a different value/default is a conflict that refuses the
  // chain -- and apply the merged policy ONCE.
  var blocks = [];
  for (var i = chain.length - 1; i >= 0; i--) {
    var stmt = chain[i];
    if (!stmt || !stmt.subordinate) continue;
    var mp = stmt.subordinate.metadata_policy;
    if (mp && mp[kind]) blocks.push(mp[kind]);
  }
  return _applyOnePolicy(Object.assign({}, metadata), _mergeMetadataPolicies(blocks));
}

async function _defaultFetcher(url) {
  var hc = httpClient();
  var res = await hc.request({ url: url, method: "GET", headers: { Accept: "application/entity-statement+jwt" } });
  if (res.statusCode < 200 || res.statusCode >= 300) {
    throw new AuthError("auth-openid-federation/fetch-failed",
      "fetch " + url + " returned " + res.statusCode);
  }
  if (!res.body) {
    throw new AuthError("auth-openid-federation/empty-response",
      "fetch " + url + " returned empty body");
  }
  return res.body.toString("utf8");
}

/**
 * @primitive b.auth.openidFederation.buildTrustChain
 * @signature b.auth.openidFederation.buildTrustChain(opts)
 * @since     0.8.62
 *
 * Construct + verify a leaf-to-anchor trust chain.
 *
 * @opts
 *   {
 *     leafEntityId:   string,                          // the entity to verify
 *     trustAnchors:   { [entityId]: jwks },            // operator-configured anchors
 *     fetcher?:       async fn(url)→jwt,               // override the default httpClient fetch
 *     fetchSubordinate?: async fn(authority, sub)→jwt, // optional explicit fetcher; default = `<authority>/fetch?iss=<authority>&sub=<sub>`
 *     maxDepth?:      number,                          // chain cap (default 10)
 *   }
 *
 * Returns `[{ jwt, claims, role }]` leaf-first. Each element has
 * `role` ∈ {"leaf", "intermediate", "trust_anchor"}.
 *
 * @example
 *   var chain = await b.auth.openidFederation.buildTrustChain({
 *     leafEntityId: "https://rp.example",
 *     trustAnchors: { "https://anchor.example": anchorJwks },
 *   });
 *   // → [{ role: "leaf", ... }, { role: "intermediate", ... }, { role: "trust_anchor", ... }]
 */
async function buildTrustChain(opts) {
  validateOpts.requireObject(opts, "buildTrustChain", AuthError);
  validateOpts.requireNonEmptyString(opts.leafEntityId, "leafEntityId", AuthError, "auth-openid-federation/no-leaf");
  if (!opts.trustAnchors || typeof opts.trustAnchors !== "object" || Object.keys(opts.trustAnchors).length === 0) {
    throw new AuthError("auth-openid-federation/no-anchors",
      "buildTrustChain: trustAnchors must be a non-empty { entityId: jwks } map");
  }
  var fetcher = opts.fetcher || _defaultFetcher;
  var fetchSubordinate = opts.fetchSubordinate || async function (authority, sub) {
    var disc = await fetcher(authority.replace(/\/$/, "") + "/.well-known/openid-federation");
    var entityCfg = parseEntityStatement(disc).claims;
    if (typeof entityCfg.federation_fetch_endpoint !== "string") {
      throw new AuthError("auth-openid-federation/no-fetch-endpoint",
        "authority \"" + authority + "\" has no federation_fetch_endpoint");
    }
    var url = entityCfg.federation_fetch_endpoint + "?iss=" +
              encodeURIComponent(authority) + "&sub=" + encodeURIComponent(sub);
    return await fetcher(url);
  };
  var maxDepth = opts.maxDepth || MAX_CHAIN_DEPTH;

  // ---- Phase 1: collect the chain bottom-up (leaf → anchor) ----------
  // Fetch each entity's self-config + the superior-signed subordinate
  // statement about it, but DEFER cryptographic chain verification to
  // Phase 2. The signature on a subordinate statement must be checked
  // against the keys ATTESTED for the signing authority by ITS superior
  // — flowing down from the operator-pinned anchor — not against the
  // authority's own self-published config jwks. Verifying eagerly here
  // (against self-published keys) is a fetch-time TOCTOU: an attacker
  // controlling the authority's endpoint can serve attacker jwks to the
  // statement-verify fetch while serving genuine config elsewhere, and
  // the only operator-pinned trust (the anchor key) never gates the
  // subordinate links.
  var chain = [];
  var current = opts.leafEntityId;
  var depth = 0;
  // Visited-set cycle guard. The maxDepth cap alone caps the
  // loop count but doesn't distinguish "long chain" from "cyclic
  // chain"; a hostile authority that lists itself in authority_hints
  // walks the verifier until depth runs out and then surfaces as
  // chain-too-deep, masking the actual misuse pattern. Tracking
  // visited entities + refusing on revisit surfaces the cycle as a
  // distinct fault class so operators alerting on chain-cycle see
  // hostile-federation probes immediately.
  var visited = Object.create(null);
  visited[current] = true;
  var reachedAnchor = false;
  while (depth < maxDepth) {
    var entityConfigUrl = current.replace(/\/$/, "") + "/.well-known/openid-federation";
    var entityConfigJwt = await fetcher(entityConfigUrl);
    var parsedEC = parseEntityStatement(entityConfigJwt);
    if (parsedEC.claims.iss !== current || parsedEC.claims.sub !== current) {
      throw new AuthError("auth-openid-federation/bad-self-statement",
        "entity configuration for \"" + current + "\" must have iss==sub==entity_id");
    }
    // Self-statement integrity: a well-formed entity config is self-signed
    // over its own jwks. This proves the document isn't truncated/garbled
    // — it is NOT the trust decision. Trust flows from the anchor through
    // the subordinate statements verified top-down in Phase 2.
    verifyEntityStatement(entityConfigJwt, parsedEC.claims.jwks || {});

    // Is this entity a trust anchor?
    if (Object.prototype.hasOwnProperty.call(opts.trustAnchors, current)) {
      // Verify the anchor's self-statement using the operator-pinned
      // JWKS — defends against a compromised anchor key by trusting
      // the configured one over what the anchor publishes today. The
      // pinned keys become the root of the top-down verification.
      verifyEntityStatement(entityConfigJwt, opts.trustAnchors[current]);
      chain.push({ jwt: entityConfigJwt, claims: parsedEC.claims, role: "trust_anchor" });
      reachedAnchor = true;
      break;
    }
    // Not the anchor — add to chain, ascend via authority_hints.
    chain.push({
      jwt:    entityConfigJwt,
      claims: parsedEC.claims,
      role:   depth === 0 ? "leaf" : "intermediate",
    });
    if (!Array.isArray(parsedEC.claims.authority_hints) ||
        parsedEC.claims.authority_hints.length === 0) {
      throw new AuthError("auth-openid-federation/no-authority-hints",
        "entity \"" + current + "\" has no authority_hints; cannot ascend to a trust anchor");
    }
    // Pick the FIRST authority_hint that yields a fetchable subordinate
    // statement with matching iss/sub. We continue past 404 / fetch /
    // parse errors (acceptable "try the next hint") and surface every
    // failure reason on `no-ascent` rather than masking it — silently
    // swallowing `catch (_e) {}` lets a hostile intermediate that serves
    // a malformed-then-valid pair shape-walk the verifier. Cryptographic
    // verification is NOT done here; the selected statement is verified
    // against the superior-attested keys in Phase 2, so a forged
    // signature fails the whole chain regardless of which hint picked it.
    var ascended = false;
    var ascentErrors = [];
    for (var ai = 0; ai < parsedEC.claims.authority_hints.length; ai++) {
      var authority = parsedEC.claims.authority_hints[ai];
      try {
        var subordinateJwt = await fetchSubordinate(authority, current);
        var parsedSub = parseEntityStatement(subordinateJwt);
        if (parsedSub.claims.iss !== authority || parsedSub.claims.sub !== current) {
          ascentErrors.push({ authority: authority, code: "iss-sub-mismatch" });
          continue;
        }
        // Refuse revisit. A trust anchor terminates the loop before
        // re-entry, so a revisit here ALWAYS means a cyclic
        // authority_hints graph.
        if (visited[authority]) {
          throw new AuthError("auth-openid-federation/chain-cycle",
            "buildTrustChain: authority \"" + authority + "\" already visited — " +
            "cyclic authority_hints graph refused");
        }
        // Stash the superior-signed subordinate statement on the entity
        // it is ABOUT. Phase 2 verifies its signature against the
        // attested keys for `authority` and applies its metadata_policy.
        chain[chain.length - 1].subordinateJwt = subordinateJwt;
        chain[chain.length - 1].subordinate    = parsedSub.claims;
        visited[authority] = true;
        current = authority;
        ascended = true;
        break;
      } catch (err) {
        // A cycle refusal is a hard stop, not a "try next hint" signal.
        if (err && err.code === "auth-openid-federation/chain-cycle") throw err;
        var errCode = (err && err.code) || "unknown";
        ascentErrors.push({ authority: authority, code: errCode, message: (err && err.message) || String(err) });
      }
    }
    if (!ascended) {
      throw new AuthError("auth-openid-federation/no-ascent",
        "entity \"" + current + "\" has authority_hints but none yielded a fetchable subordinate statement: " +
        JSON.stringify(ascentErrors));
    }
    depth += 1;
  }
  if (!reachedAnchor) {
    throw new AuthError("auth-openid-federation/chain-too-deep",
      "buildTrustChain: max depth " + maxDepth + " exceeded; refused");
  }

  // ---- Phase 2: verify top-down against attested keys ----------------
  // Trust flows from the operator-pinned anchor downward. Each
  // subordinate statement is signed by the superior directly above the
  // entity it describes, and pins that entity's jwks. We start with the
  // anchor's pinned keys and, for each step down, verify the subordinate
  // statement with the keys attested for its SIGNER (never the signer's
  // self-published config), then adopt the statement's attested jwks as
  // the trusted keys for the next step. This closes the fetch-time TOCTOU
  // and makes the anchor key gate every link, not just the anchor's own
  // self-config.
  var anchorEntityId = chain[chain.length - 1].claims.iss;
  var attestedJwks = opts.trustAnchors[anchorEntityId];
  for (var ci = chain.length - 2; ci >= 0; ci--) {
    var node = chain[ci];
    if (!node.subordinate || !node.subordinateJwt) {
      // Every non-anchor node must carry the superior-signed statement
      // collected in Phase 1; its absence is an internal invariant break.
      throw new AuthError("auth-openid-federation/no-subordinate",
        "buildTrustChain: entity \"" + node.claims.iss + "\" has no superior-signed subordinate statement");
    }
    // Verify against the SIGNER's attested keys (flowed down), not the
    // signer's self-published config jwks.
    verifyEntityStatement(node.subordinateJwt, attestedJwks || {});
    // The subordinate statement pins this entity's jwks — adopt the
    // attested keys for the next link down, and reflect them on the node.
    if (node.subordinate.jwks && Array.isArray(node.subordinate.jwks.keys)) {
      // Bind the entity's OWN self-configuration to the superior-attested
      // keys. resolveLeaf reads the effective metadata from the entity's
      // self-config (chain[i].claims.metadata), and Phase 1 verified that
      // config only against its OWN self-published jwks — which proves the
      // document isn't garbled, NOT that a federation-attested key signed
      // it. An attacker who controls the entity's .well-known endpoint (but
      // not its attested signing key) can serve a self-signed config that
      // carries forged metadata + attacker jwks and sails through the Phase 1
      // self-verify; without this check the pinned keys never gate the very
      // document whose metadata is trusted. Re-verify the config against the
      // pinned keys so a config not signed by an attested key fails the whole
      // chain (OIDF 1.0 §9 — the leaf/intermediate Entity Configuration is
      // verified with the jwks pinned by its superior's Subordinate
      // Statement, never with the config's self-declared jwks).
      verifyEntityStatement(node.jwt, node.subordinate.jwks);
      node.claims.jwks = node.subordinate.jwks;
      attestedJwks = node.subordinate.jwks;
    } else {
      // A subordinate statement that pins no keys cannot attest the next
      // link — refuse rather than fall back to self-published keys.
      throw new AuthError("auth-openid-federation/no-attested-jwks",
        "subordinate statement for \"" + node.claims.iss + "\" pins no jwks; cannot attest the chain downward");
    }
  }

  _emitAudit("chain_built", "success", {
    leaf: opts.leafEntityId, depth: chain.length, anchor: anchorEntityId,
  });
  _emitMetric("chain-built");
  return chain;
}

/**
 * @primitive b.auth.openidFederation.resolveLeaf
 * @signature b.auth.openidFederation.resolveLeaf(opts)
 * @since     0.8.62
 *
 * One-shot helper: build the trust chain for a leaf entity, apply
 * the federation's metadata policy, and return the effective
 * metadata for the requested entity-kind (`opts.kind` —
 * "openid_relying_party", "openid_provider", "federation_entity",
 * "oauth_resource", etc.). Throws on any chain / policy failure.
 *
 * @opts
 *   {
 *     leafEntityId:     string,
 *     trustAnchors:     { [entityId: string]: object },
 *     kind:             string,                              // e.g. "openid_relying_party"
 *     fetcher?:         async fn(url) -> jwt,
 *     fetchSubordinate?: async fn(authority, sub) -> jwt,
 *     maxDepth?:        number,
 *   }
 *
 * @example
 *   var resolved = await b.auth.openidFederation.resolveLeaf({
 *     leafEntityId: "https://rp.example",
 *     trustAnchors: { "https://anchor.example": anchorJwks },
 *     kind:         "openid_relying_party",
 *   });
 *   // → { chain, trustAnchor, effectiveMetadata, leafEntityId }
 */
async function resolveLeaf(opts) {
  validateOpts.requireObject(opts, "resolveLeaf", AuthError);
  validateOpts.requireNonEmptyString(opts.kind, "kind", AuthError, "auth-openid-federation/no-kind");
  var chain = await buildTrustChain(opts);
  var leafClaims = chain[0].claims;
  var meta = (leafClaims.metadata && leafClaims.metadata[opts.kind]) || {};
  var effective = applyMetadataPolicy(meta, chain, opts.kind);
  return {
    chain:              chain,
    trustAnchor:        chain[chain.length - 1].claims.iss,
    effectiveMetadata:  effective,
    leafEntityId:       opts.leafEntityId,
  };
}

module.exports = {
  parseEntityStatement:   parseEntityStatement,
  verifyEntityStatement:  verifyEntityStatement,
  buildTrustChain:        buildTrustChain,
  applyMetadataPolicy:    applyMetadataPolicy,
  resolveLeaf:            resolveLeaf,
};
