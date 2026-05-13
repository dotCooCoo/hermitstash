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
var nodeCrypto   = require("node:crypto");
var { AuthError } = require("../framework-error");

var httpClient = lazyRequire(function () { return require("../http-client"); });
var audit      = lazyRequire(function () { return require("../audit"); });
var observability = lazyRequire(function () { return require("../observability"); });
var emit = validateOpts.makeNamespacedEmitters("auth.openidFederation", { audit: audit, observability: observability });

var _emitAudit  = emit.audit;
var _emitMetric = emit.metric;

var SUPPORTED_ALGS = ["ES256", "ES384", "ES512", "PS256", "PS384", "PS512", "RS256", "EdDSA"];
var MAX_STATEMENT_BYTES = 64 * 1024;                                                            // allow:raw-byte-literal — entity-statement size cap
var MAX_CHAIN_DEPTH = 10;                                                                       // allow:raw-byte-literal — federation chain depth ceiling

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
    header  = safeJson.parse(_b64uDecodeStr(parts[0]), { maxBytes: 4096 });                     // allow:raw-byte-literal — header cap
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
 * @signature b.auth.openidFederation.verifyEntityStatement(jwt, jwks)
 * @since     0.8.62
 *
 * Verify a single entity statement's JWS signature using the
 * provided JWKS. Returns the parsed claims on success; throws on
 * any failure (malformed / wrong typ / unsupported alg / no
 * matching kid / bad signature / iat-future / expired).
 *
 * @example
 *   var claims = b.auth.openidFederation.verifyEntityStatement(jwt, anchorJwks);
 *   // → { iss, sub, iat, exp, jwks, metadata, authority_hints, ... }
 */
function verifyEntityStatement(jwt, jwks) {
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
  } else if (jwks.keys.length === 1) {
    key = jwks.keys[0];
  }
  if (!key) {
    throw new AuthError("auth-openid-federation/no-matching-kid",
      "verifyEntityStatement: no JWKS key matches kid \"" + parsed.header.kid + "\"");
  }

  // Cross-check the JWK key type against the JWS `alg` header BEFORE
  // verifying. Without this an attacker-controlled entity-config can
  // declare `alg: "ES256"` while supplying an RSA `kty: "RSA"` JWK;
  // Node will silently use the RSA key with SHA-256 and the signature
  // verify either always-fails (if PSS) or succeeds against a payload
  // the attacker crafted to match the wrong primitive (algorithm/key-
  // type confusion). (Audit 2026-05-11.)
  var expectedKty = null;
  if (parsed.header.alg.indexOf("ES") === 0)        expectedKty = "EC";
  else if (parsed.header.alg.indexOf("PS") === 0 || parsed.header.alg.indexOf("RS") === 0) expectedKty = "RSA";
  else if (parsed.header.alg === "EdDSA")           expectedKty = "OKP";
  if (expectedKty && key.kty !== expectedKty) {
    throw new AuthError("auth-openid-federation/alg-kty-mismatch",
      "verifyEntityStatement: JWS header alg=\"" + parsed.header.alg + "\" requires " +
      "JWK kty=\"" + expectedKty + "\" but the resolved JWK has kty=\"" + key.kty + "\"");
  }

  var keyObj;
  try { keyObj = nodeCrypto.createPublicKey({ key: key, format: "jwk" }); }
  catch (e) {
    throw new AuthError("auth-openid-federation/bad-jwk",
      "verifyEntityStatement: JWK is not parseable: " + ((e && e.message) || String(e)));
  }

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

  var nowSec = Math.floor(Date.now() / 1000);                                                   // allow:raw-byte-literal — ms→s
  var skew = 60;                                                                                // allow:raw-time-literal — clock-skew tolerance 60s
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

/**
 * Apply a single metadata_policy block to a metadata object and
 * return the resulting object. Pure — never mutates input.
 *
 * Operators per OIDF §6.2.1:
 *   value      — set claim to a fixed value (overrides subordinate)
 *   add        — array claim: append values not already present
 *   default    — provide a default if the claim is absent
 *   one_of     — claim must be one of the listed values (else throw)
 *   subset_of  — claim's array values must be a subset of the listed (else throw)
 *   superset_of — claim's array values must include every listed value (else throw)
 *   essential  — claim must be present (else throw)
 */
function _applyOnePolicy(metadata, policy) {
  var out = Object.assign({}, metadata);
  Object.keys(policy).forEach(function (claimName) {
    var rules = policy[claimName];
    if (!rules || typeof rules !== "object") {
      throw new AuthError("auth-openid-federation/bad-policy-rules",
        "metadata_policy['" + claimName + "'] must be an object");
    }
    Object.keys(rules).forEach(function (op) {
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
          if (!Array.isArray(out[claimName])) out[claimName] = [];
          v.forEach(function (val) { if (out[claimName].indexOf(val) === -1) out[claimName].push(val); });
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
          if (Array.isArray(out[claimName])) {
            out[claimName].forEach(function (val) {
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
          v.forEach(function (req) {
            if (!Array.isArray(out[claimName]) || out[claimName].indexOf(req) === -1) {
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
 * Apply every metadata_policy in the chain (top-down) to the leaf's
 * declared metadata for the given entity-kind ("openid_relying_party"
 * / "openid_provider" / "federation_entity" / etc.) and return the
 * effective metadata. Throws on any policy violation.
 *
 * The chain is leaf-first; we reverse for top-down application so
 * the trust anchor's policy applies first, then each intermediate's,
 * then the leaf's claimed metadata is the starting object.
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
  var out = Object.assign({}, metadata);
  // Walk top-down (anchor last in leaf-first array).
  for (var i = chain.length - 1; i >= 0; i--) {
    var stmt = chain[i];
    if (!stmt || !stmt.claims) continue;
    if (stmt.claims.metadata_policy && stmt.claims.metadata_policy[kind]) {
      out = _applyOnePolicy(out, stmt.claims.metadata_policy[kind]);
    }
  }
  return out;
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

  var chain = [];
  var current = opts.leafEntityId;
  var depth = 0;
  while (depth < maxDepth) {
    var entityConfigUrl = current.replace(/\/$/, "") + "/.well-known/openid-federation";
    var entityConfigJwt = await fetcher(entityConfigUrl);
    var parsedEC = parseEntityStatement(entityConfigJwt);
    if (parsedEC.claims.iss !== current || parsedEC.claims.sub !== current) {
      throw new AuthError("auth-openid-federation/bad-self-statement",
        "entity configuration for \"" + current + "\" must have iss==sub==entity_id");
    }
    // Self-signed: verify with its own jwks.
    verifyEntityStatement(entityConfigJwt, parsedEC.claims.jwks || {});

    // Is this entity a trust anchor?
    if (Object.prototype.hasOwnProperty.call(opts.trustAnchors, current)) {
      // Verify the anchor's self-statement using the operator-pinned
      // JWKS — defends against a compromised anchor key by trusting
      // the configured one over what the anchor publishes today.
      verifyEntityStatement(entityConfigJwt, opts.trustAnchors[current]);
      chain.push({ jwt: entityConfigJwt, claims: parsedEC.claims, role: "trust_anchor" });
      _emitAudit("chain_built", "success", {
        leaf: opts.leafEntityId, depth: chain.length, anchor: current,
      });
      _emitMetric("chain-built");
      return chain;
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
    // Pick the FIRST authority_hint that resolves to a trust anchor,
    // OR the first that returns a valid subordinate statement. Real
    // operators with multiple federations usually have one anchor
    // active; we walk in order and pick the first success.
    // Track every per-authority failure reason and surface them on
    // `no-ascent` rather than masking. Audit 2026-05-11 — silently
    // swallowing `catch (_e) {}` lets a hostile intermediate that
    // serves a malformed-then-valid pair shape-walk the verifier.
    // We continue past 404 / fetch errors but refuse on
    // signature-verify failure (cryptographic refusal is a hard stop).
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
        var authorityCfgJwt = await fetcher(authority.replace(/\/$/, "") + "/.well-known/openid-federation");
        var authorityCfgClaims = parseEntityStatement(authorityCfgJwt).claims;
        // Cryptographic verification — any throw here is a hard
        // refusal, NOT a "try next authority" signal. A malformed-
        // signature subordinate from an authority listed by the
        // entity means that authority is hostile or compromised;
        // moving on lets a chain-shaping attacker bypass the gate.
        verifyEntityStatement(subordinateJwt, authorityCfgClaims.jwks || {});
        chain[chain.length - 1].claims.jwks = parsedSub.claims.jwks || chain[chain.length - 1].claims.jwks;
        chain[chain.length - 1].subordinateJwt = subordinateJwt;
        chain[chain.length - 1].subordinate    = parsedSub.claims;
        current = authority;
        ascended = true;
        break;
      } catch (err) {
        var errCode = (err && err.code) || "unknown";
        // Network / 404 / parse errors at the AUTHORITY-fetch step
        // are acceptable "try the next hint" signals. Verify-side
        // failures (crypto) are NOT — surface them and abort.
        if (/^auth-openid-federation\/(?:bad-jwk|alg-kty-mismatch|bad-signature|signature-failed)$/.test(errCode)) {
          throw err;
        }
        ascentErrors.push({ authority: authority, code: errCode, message: (err && err.message) || String(err) });
      }
    }
    if (!ascended) {
      throw new AuthError("auth-openid-federation/no-ascent",
        "entity \"" + current + "\" has authority_hints but none yielded a verifiable subordinate statement: " +
        JSON.stringify(ascentErrors));
    }
    depth += 1;
  }
  throw new AuthError("auth-openid-federation/chain-too-deep",
    "buildTrustChain: max depth " + maxDepth + " exceeded; refused");
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
