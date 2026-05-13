"use strict";
/**
 * @module     b.auth.oid4vp
 * @nav        Identity
 * @title      OpenID4VP (verifier)
 * @order      350
 * @card       OpenID for Verifiable Presentations 1.0 — verifier side
 *             with DCQL (Digital Credentials Query Language) support.
 *             Builds presentation requests, parses vp_token responses,
 *             and routes each presentation through the SD-JWT VC
 *             verifier with the right audience + nonce binding.
 *
 * @intro
 *   This module is the verifier counterpart to `b.auth.oid4vci`. The
 *   relying party (verifier) builds an authorization request asking
 *   the wallet for one or more verifiable presentations; the wallet
 *   replies with a `vp_token` carrying the SD-JWT VC presentations
 *   plus a `presentation_submission` (legacy Presentation Exchange
 *   2.0) OR no submission when DCQL is used.
 *
 *   DCQL (OpenID4VP 1.0 §6) is the JSON-shaped query language that
 *   replaces Presentation Exchange's JSONPath-soup. Two top-level
 *   keys:
 *
 *     credentials: [
 *       {
 *         id:     "id-card",
 *         format: "vc+sd-jwt",
 *         meta:   { vct_values: ["https://example.com/vct/identity"] },
 *         claims: [
 *           { path: ["given_name"] },
 *           { path: ["birthdate"], values: ["1990-01-15"] },
 *         ],
 *       },
 *     ],
 *     credential_sets: [
 *       { options: [["id-card"], ["passport"]], required: true },
 *     ]
 *
 *   The verifier-side primitives:
 *
 *     b.auth.oid4vp.verifier.create({ ... })
 *       .createRequest({ dcql, audience, nonce, responseUri })
 *       .verifyResponse({ vpToken, dcql, audience, nonce })
 *       .matchDcql(presentations, dcql)         // structural-only check
 *
 *   `verifyResponse` composes `b.auth.sdJwtVc.verify` (with
 *   `requireKeyBinding: true` and the DCQL-claim filter applied to the
 *   disclosed-claim set), then runs `matchDcql` to confirm the
 *   wallet's selection satisfies the query.
 */

var lazyRequire  = require("../lazy-require");
var validateOpts = require("../validate-opts");
var { generateToken } = require("../crypto");
var { AuthError } = require("../framework-error");

var sdJwtVcCore   = lazyRequire(function () { return require("./sd-jwt-vc"); });
var audit         = lazyRequire(function () { return require("../audit"); });
var observability = lazyRequire(function () { return require("../observability"); });
var emit = validateOpts.makeNamespacedEmitters("auth.oid4vp", { audit: audit, observability: observability });

var _emitAudit  = emit.audit;
var _emitMetric = emit.metric;

/**
 * Validate a DCQL query against the spec shape. Refuses unknown
 * top-level keys, missing credential id, missing claim paths, or
 * malformed credential_sets options. Throws AuthError on first
 * failure (config-time validation — the verifier author is the one
 * who needs to see the error).
 */
function _validateDcql(dcql) {
  if (!dcql || typeof dcql !== "object" || Array.isArray(dcql)) {
    throw new AuthError("auth-oid4vp/bad-dcql",
      "DCQL: query must be a plain object");
  }
  if (!Array.isArray(dcql.credentials) || dcql.credentials.length === 0) {
    throw new AuthError("auth-oid4vp/no-credentials",
      "DCQL: query.credentials must be a non-empty array");
  }
  var seenIds = new Set();
  dcql.credentials.forEach(function (cred, i) {
    if (!cred || typeof cred !== "object") {
      throw new AuthError("auth-oid4vp/bad-credential-query",
        "DCQL: credentials[" + i + "] must be an object");
    }
    if (typeof cred.id !== "string" || cred.id.length === 0) {
      throw new AuthError("auth-oid4vp/no-credential-id",
        "DCQL: credentials[" + i + "].id is required");
    }
    if (seenIds.has(cred.id)) {
      throw new AuthError("auth-oid4vp/duplicate-id",
        "DCQL: credentials[" + i + "].id \"" + cred.id + "\" duplicated");
    }
    seenIds.add(cred.id);
    if (typeof cred.format !== "string" || cred.format.length === 0) {
      throw new AuthError("auth-oid4vp/no-format",
        "DCQL: credentials['" + cred.id + "'].format is required");
    }
    if (cred.claims !== undefined) {
      if (!Array.isArray(cred.claims)) {
        throw new AuthError("auth-oid4vp/bad-claims",
          "DCQL: credentials['" + cred.id + "'].claims must be an array");
      }
      cred.claims.forEach(function (claim, ci) {
        if (!claim || typeof claim !== "object" || !Array.isArray(claim.path) || claim.path.length === 0) {
          throw new AuthError("auth-oid4vp/bad-claim-path",
            "DCQL: credentials['" + cred.id + "'].claims[" + ci + "].path must be a non-empty array");
        }
        claim.path.forEach(function (segment) {
          if (typeof segment !== "string" && typeof segment !== "number" && segment !== null) {
            throw new AuthError("auth-oid4vp/bad-claim-segment",
              "DCQL: claim path segments must be string|number|null");
          }
        });
        if (claim.values !== undefined && !Array.isArray(claim.values)) {
          throw new AuthError("auth-oid4vp/bad-claim-values",
            "DCQL: claim.values must be an array if present");
        }
      });
    }
  });
  if (dcql.credential_sets !== undefined) {
    if (!Array.isArray(dcql.credential_sets)) {
      throw new AuthError("auth-oid4vp/bad-credential-sets",
        "DCQL: credential_sets must be an array if present");
    }
    dcql.credential_sets.forEach(function (set, si) {
      if (!set || typeof set !== "object" || !Array.isArray(set.options) || set.options.length === 0) {
        throw new AuthError("auth-oid4vp/bad-set-options",
          "DCQL: credential_sets[" + si + "].options must be a non-empty array");
      }
      set.options.forEach(function (option, oi) {
        if (!Array.isArray(option) || option.length === 0) {
          throw new AuthError("auth-oid4vp/bad-set-option",
            "DCQL: credential_sets[" + si + "].options[" + oi + "] must be a non-empty array");
        }
        option.forEach(function (id) {
          if (!seenIds.has(id)) {
            throw new AuthError("auth-oid4vp/unknown-set-id",
              "DCQL: credential_sets[" + si + "] references unknown credential id \"" + id + "\"");
          }
        });
      });
    });
  }
}

/**
 * Walk the path against the resolved-claim object the SD-JWT VC
 * verifier produced. Returns { found, value }.
 *   path = ["address", "country"]    → claims.address.country
 *   path = ["array", 0]              → claims.array[0]
 *   null = "any element" (DCQL §6.4.2 array path semantics) — for
 *     v1-defensible we don't dispatch on null; refuse with a clear
 *     error so the operator knows the gap.
 */
function _resolvePath(claims, path) {
  var node = claims;
  for (var i = 0; i < path.length; i++) {
    var seg = path[i];
    if (seg === null) {
      // DCQL §6.4.2: null means "any element of the array at this
      // depth". Not in v1 — refuse loudly so it doesn't silently
      // match nothing.
      throw new AuthError("auth-oid4vp/null-path-segment-not-supported",
        "DCQL: null path segment (any-element) not supported in v1; supply a numeric index");
    }
    if (node === undefined || node === null) return { found: false, value: undefined };
    node = node[seg];
  }
  return { found: node !== undefined, value: node };
}

function _matchClaim(claims, claimQuery) {
  var resolved = _resolvePath(claims, claimQuery.path);
  if (!resolved.found) return false;
  if (claimQuery.values && claimQuery.values.length > 0) {
    return claimQuery.values.some(function (v) {
      return v === resolved.value || JSON.stringify(v) === JSON.stringify(resolved.value);
    });
  }
  return true;
}

function _matchCredentialQuery(presentation, query) {
  // Format match
  if (presentation.format !== query.format) return false;
  // vct match (SD-JWT VC specific meta filter)
  if (query.meta && Array.isArray(query.meta.vct_values)) {
    var vct = presentation.claims && presentation.claims.vct;
    if (!vct || query.meta.vct_values.indexOf(vct) === -1) return false;
  }
  // Issuer match
  if (query.meta && Array.isArray(query.meta.issuer_values)) {
    var iss = presentation.claims && presentation.claims.iss;
    if (!iss || query.meta.issuer_values.indexOf(iss) === -1) return false;
  }
  // Per-claim filters
  if (Array.isArray(query.claims)) {
    for (var i = 0; i < query.claims.length; i++) {
      if (!_matchClaim(presentation.claims, query.claims[i])) return false;
    }
  }
  return true;
}

/**
 * @primitive b.auth.oid4vp.matchDcql
 * @signature b.auth.oid4vp.matchDcql(presentations, dcql)
 * @since     0.8.62
 * @status    stable
 * @related   b.auth.oid4vp.verifier.create
 *
 * Structural matcher: confirms the wallet's selected presentations
 * (each with its DCQL `id` + verified `claims`) satisfy the DCQL
 * query. Returns `{ valid, matched, errors }`. Operators wanting to
 * implement their own verifier transport call this directly after
 * SD-JWT VC verification.
 *
 * @example
 *   var match = b.auth.oid4vp.matchDcql([
 *     { id: "id-card", format: "vc+sd-jwt", claims: { vct: "...", given_name: "Alice" } }
 *   ], dcqlQuery);
 *   if (!match.valid) throw new Error(match.errors.join(", "));
 */
function matchDcql(presentations, dcql) {
  _validateDcql(dcql);
  if (!Array.isArray(presentations)) {
    return { valid: false, matched: {}, errors: ["presentations must be an array"] };
  }
  var byId = {};
  for (var i = 0; i < presentations.length; i++) {
    if (!presentations[i] || typeof presentations[i].id !== "string") {
      return { valid: false, matched: {}, errors: ["presentation[" + i + "] missing id"] };
    }
    byId[presentations[i].id] = presentations[i];
  }
  var matched = {};
  var errors = [];
  // Match every credential_query
  dcql.credentials.forEach(function (cq) {
    var pres = byId[cq.id];
    if (!pres) {
      // Will be enforced by credential_sets if `required` — pure
      // credentials[] without a set is required by default per spec.
      return;
    }
    if (_matchCredentialQuery(pres, cq)) {
      matched[cq.id] = pres;
    } else {
      errors.push("credential '" + cq.id + "' presented but does not satisfy filters");
    }
  });
  // Apply credential_sets — at least one option per set must be
  // satisfied. A set is required by default per spec; `required:
  // false` makes it optional.
  if (Array.isArray(dcql.credential_sets)) {
    dcql.credential_sets.forEach(function (set, si) {
      var optional = set.required === false;
      var ok = set.options.some(function (option) {
        return option.every(function (id) { return matched[id]; });
      });
      if (!ok && !optional) {
        errors.push("credential_set[" + si + "] not satisfied (none of " +
          JSON.stringify(set.options) + " fully matched)");
      }
    });
  } else {
    // No credential_sets — every entry in credentials[] is required.
    dcql.credentials.forEach(function (cq) {
      if (!matched[cq.id]) {
        errors.push("credential '" + cq.id + "' missing from presentation");
      }
    });
  }
  return { valid: errors.length === 0, matched: matched, errors: errors };
}

/**
 * @primitive b.auth.oid4vp.verifier.create
 * @signature b.auth.oid4vp.verifier.create(opts)
 * @since     0.8.62
 * @status    stable
 * @related   b.auth.oid4vp.matchDcql
 *
 * Build an OID4VP verifier. Returns helpers for emitting an
 * authorization request with a DCQL query and parsing the wallet's
 * signed vp_token response.
 *
 * @opts
 *   {
 *     clientId:           string,     // required
 *     responseUri:        string,     // where the wallet POSTs vp_token (RP-side)
 *     issuerKeyResolver:  fn(header)→keyOrJwk,  // resolves SD-JWT VC issuer signing key
 *     audience?:          string,     // override aud claim (defaults to clientId)
 *     keyAttestationVerifier?: fn,
 *   }
 *
 * @example
 *   var verifier = b.auth.oid4vp.verifier.create({
 *     clientId:          "verifier-1",
 *     responseUri:       "https://verifier.example/vp",
 *     issuerKeyResolver: async function (header) { return jwksByKid[header.kid]; },
 *   });
 */
function create(opts) {
  validateOpts.requireObject(opts, "auth.oid4vp.verifier.create", AuthError);
  validateOpts.requireNonEmptyString(opts.clientId, "verifier.create: clientId", AuthError, "auth-oid4vp/no-client-id");
  validateOpts.requireNonEmptyString(opts.responseUri, "verifier.create: responseUri", AuthError, "auth-oid4vp/no-response-uri");
  if (typeof opts.issuerKeyResolver !== "function") {
    throw new AuthError("auth-oid4vp/no-resolver",
      "verifier.create: issuerKeyResolver is required");
  }

  var audience = opts.audience || opts.clientId;

  /**
   * @primitive b.auth.oid4vp.verifier.createRequest
   * @signature b.auth.oid4vp.verifier.createRequest(opts)
   * @since     0.8.62
   *
   * Build the OID4VP authorization request body. Operators sign + post
   * the JWT (via PAR) or render it as an `openid4vp://` deep-link.
   *
   * @opts
   *   {
   *     dcql:           object,      // DCQL query — required
   *     responseMode?:  string,      // default "direct_post"
   *     nonce?:         string,
   *     state?:         string,
   *     aud?:           string,
   *   }
   *
   * @example
   *   var rv = verifier.createRequest({
   *     dcql: {
   *       credentials: [{ id: "id-card", format: "vc+sd-jwt", claims: [{ path: ["given_name"] }] }],
   *     },
   *   });
   *   // → { request, nonce, state }
   */
  function createRequest(ropts) {
    ropts = ropts || {};
    if (!ropts.dcql) {
      throw new AuthError("auth-oid4vp/no-dcql",
        "createRequest: dcql is required");
    }
    _validateDcql(ropts.dcql);
    var nonce = ropts.nonce || generateToken(16);                                                // allow:raw-byte-literal — 128-bit nonce
    var state = ropts.state || generateToken(16);                                                // allow:raw-byte-literal — 128-bit state
    var request = {
      response_type:     "vp_token",
      response_mode:     ropts.responseMode || "direct_post",
      client_id:         opts.clientId,
      response_uri:      opts.responseUri,
      nonce:             nonce,
      state:             state,
      dcql_query:        ropts.dcql,
    };
    if (ropts.aud) request.aud = ropts.aud;
    _emitAudit("request_created", "success", { state: state });
    _emitMetric("request-created");
    return { request: request, nonce: nonce, state: state };
  }

  /**
   * @primitive b.auth.oid4vp.verifier.verifyResponse
   * @signature b.auth.oid4vp.verifier.verifyResponse(opts)
   * @since     0.8.62
   *
   * Parse the wallet's vp_token response, verify each SD-JWT VC
   * presentation (signature + KB-JWT + nonce + audience), and run
   * the DCQL matcher. Returns
   *   { valid, presentations: [{ id, claims, ... }], matched, errors }
   *
   * The vp_token may be a single string OR an array of strings. The
   * legacy Presentation Exchange `presentation_submission` is
   * accepted but not consumed — DCQL is the canonical query path.
   *
   * @opts
   *   {
   *     vpToken:                object|string,
   *     dcql:                   object,
   *     nonce:                  string,
   *     requireKeyAttestation?: boolean,
   *   }
   *
   * @example
   *   var result = await verifier.verifyResponse({
   *     vpToken: req.body.vp_token,
   *     dcql:    storedDcql,
   *     nonce:   storedNonce,
   *   });
   *   // → { valid, presentations, matched, errors }
   */
  async function verifyResponse(vopts) {
    vopts = vopts || {};
    if (!vopts.dcql) {
      throw new AuthError("auth-oid4vp/no-dcql",
        "verifyResponse: dcql required");
    }
    if (typeof vopts.nonce !== "string" || vopts.nonce.length === 0) {
      throw new AuthError("auth-oid4vp/no-nonce",
        "verifyResponse: nonce required (must equal the value passed to createRequest)");
    }
    _validateDcql(vopts.dcql);

    // OID4VP §7.1: vp_token is a JSON object whose keys are DCQL
    // credential_query ids and whose values are credential
    // presentations (string or array of strings). Operators that
    // received the legacy single-string vp_token path through PE 2.0
    // can pass it via `legacyVpToken`; we wrap it as
    // `{ <first-cred-id>: <token> }` for downstream uniformity.
    var vp = vopts.vpToken;
    if (typeof vp === "string") {
      // Legacy single-string vp_token — bind to the first
      // credential_query id. Refuse if there's more than one.
      if (vopts.dcql.credentials.length !== 1) {
        throw new AuthError("auth-oid4vp/legacy-multi-credential",
          "verifyResponse: string vp_token only valid for single-credential queries");
      }
      var k = vopts.dcql.credentials[0].id;
      var tmp = {}; tmp[k] = vp; vp = tmp;
    }
    if (!vp || typeof vp !== "object" || Array.isArray(vp)) {
      throw new AuthError("auth-oid4vp/bad-vp-token",
        "verifyResponse: vp_token must be a JSON object keyed by DCQL credential id");
    }

    var presentations = [];
    var verifyErrors = [];
    var queriesById = {};
    vopts.dcql.credentials.forEach(function (cq) { queriesById[cq.id] = cq; });

    var ids = Object.keys(vp);
    for (var i = 0; i < ids.length; i++) {
      var id = ids[i];
      var cq = queriesById[id];
      if (!cq) {
        verifyErrors.push("vp_token contains key '" + id + "' not present in DCQL query");
        continue;
      }
      var token = vp[id];
      // Multiple presentations under one id — verify each.
      var tokens = Array.isArray(token) ? token : [token];
      for (var ti = 0; ti < tokens.length; ti++) {
        var t = tokens[ti];
        if (typeof t !== "string") {
          verifyErrors.push("vp_token['" + id + "'][" + ti + "] is not a string");
          continue;
        }
        try {
          // Per-presentation vct enforcement (audit 2026-05-11): when
          // DCQL's `vct_values` has 1 entry, `expectedVct` pins it.
          // With 2+ entries the verifier's expectedVct opt can't hold
          // a list, so we verify-without-expected and then validate
          // the actual vct against the DCQL list manually — over-
          // disclosure defense (a holder presenting a vct outside
          // the DCQL filter would previously slip through).
          var dcqlVctValues = cq.meta && Array.isArray(cq.meta.vct_values) ? cq.meta.vct_values : null;
          var expectedVct = dcqlVctValues && dcqlVctValues.length === 1
            ? dcqlVctValues[0] : undefined;
          var verified = await sdJwtVcCore().verify(t, {
            issuerKeyResolver:      opts.issuerKeyResolver,
            audience:               audience,
            nonce:                  vopts.nonce,
            requireKeyBinding:      true,
            requireKeyAttestation:  vopts.requireKeyAttestation === true,
            keyAttestationVerifier: opts.keyAttestationVerifier || null,
            expectedVct:            expectedVct,
          });
          if (dcqlVctValues && dcqlVctValues.length > 1) {
            if (!verified.claims || dcqlVctValues.indexOf(verified.claims.vct) === -1) {
              verifyErrors.push("vp_token['" + id + "'][" + ti + "] vct '" +
                ((verified.claims && verified.claims.vct) || "<missing>") +
                "' is not in DCQL vct_values [" + dcqlVctValues.join(", ") + "]");
              continue;
            }
          }
          presentations.push({
            id:                   id,
            format:               cq.format,
            claims:               verified.claims,
            issuerHeader:         verified.issuerHeader,
            holderKey:            verified.holderKey,
            keyAttestationClaims: verified.keyAttestationClaims,
          });
        } catch (e) {
          verifyErrors.push("vp_token['" + id + "'][" + ti + "] verify failed: " +
            ((e && e.message) || String(e)));
        }
      }
    }

    var matchResult = matchDcql(presentations, vopts.dcql);

    if (verifyErrors.length > 0 || !matchResult.valid) {
      _emitAudit("verify_failed", "failure", {
        verifyErrors: verifyErrors.length,
        matchErrors:  matchResult.errors.length,
      });
    } else {
      _emitAudit("verify_succeeded", "success", {
        presentations: presentations.length,
      });
    }
    _emitMetric(verifyErrors.length === 0 && matchResult.valid ? "verify-succeeded" : "verify-failed");

    return {
      valid:          verifyErrors.length === 0 && matchResult.valid,
      presentations:  presentations,
      matched:        matchResult.matched,
      errors:         verifyErrors.concat(matchResult.errors),
    };
  }

  return {
    createRequest:  createRequest,
    verifyResponse: verifyResponse,
    matchDcql:      matchDcql,
    clientId:       opts.clientId,
    responseUri:    opts.responseUri,
  };
}

module.exports = {
  verifier:  { create: create },
  matchDcql: matchDcql,
};
