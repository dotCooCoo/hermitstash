"use strict";
/**
 * @module b.auth.jar
 * @nav    Identity
 * @title  JWT-Secured Authorization Request (JAR)
 *
 * @intro
 *   RFC 9101 JWT-Secured Authorization Request — the authorization-
 *   server side of the request object, the counterpart to the JARM
 *   response handling in <code>b.auth.oauth</code>. A plain OAuth
 *   authorization request passes its parameters as URL query string,
 *   where they can be tampered with in the browser or leaked into
 *   proxy / referer logs. JAR packs the parameters into a JWT signed
 *   by the client (the "request object") so the authorization server
 *   can verify they arrived exactly as the client sent them.
 *
 *   <code>b.auth.jar.parse(jar, opts)</code> verifies an incoming
 *   request object: the signature is checked through
 *   <code>b.auth.jwt.verifyExternal</code> (mandatory <code>algorithms</code>
 *   allowlist — no <code>alg: "none"</code>, no HMAC-vs-RSA confusion,
 *   no JWE-on-a-JWS-verifier), <code>iss</code> is pinned to the
 *   expected <code>clientId</code>, <code>aud</code> to this server's
 *   issuer identifier, the request object's <code>client_id</code>
 *   claim must match the client, and the authorization parameters are
 *   returned with the JWT envelope claims stripped.
 *
 *   <strong>Anti-nesting (RFC 9101 §6.3):</strong> a request object
 *   may not itself carry a <code>request</code> or <code>request_uri</code>
 *   parameter — <code>parse</code> refuses it, closing the recursion /
 *   confused-deputy vector.
 *
 *   The signature verification — the security-critical step — is
 *   delegated to <code>verifyExternal</code>, which already enforces
 *   the alg allowlist and refuses the alg-confusion / JWE-bypass
 *   shapes against a JWKS public-key trust source. JAR adds the
 *   request-object-specific bindings on top.
 *
 *   <strong>Emitting</strong> a request object (the client side) is
 *   deferred-with-condition: it requires signing with the client's
 *   key under a classical JWS algorithm (RS256 / ES256 / EdDSA), and
 *   the framework's own JWT signer (<code>b.auth.jwt.sign</code>) is
 *   PQC-only (ML-DSA / SLH-DSA) for the tokens the framework itself
 *   issues — a PQC-signed request object would not interoperate with
 *   any standard authorization server today. blamejs sits on the
 *   authorization-server side here (it verifies client request
 *   objects); client-side emission re-opens when a classical
 *   <code>b.auth.jws.sign</code> primitive lands or operators surface
 *   the need. Until then clients sign their request objects with
 *   their existing JOSE tooling.
 *
 * @card
 *   RFC 9101 JWT-Secured Authorization Request (server side) — verify
 *   the OAuth request object with mandatory alg allowlist, iss +
 *   client_id binding, audience pinning, and anti-nesting.
 */

var jwtExternal = require("./jwt-external");
var validateOpts = require("../validate-opts");
var { defineClass } = require("../framework-error");

var AuthJarError = defineClass("AuthJarError", { alwaysPermanent: true });

var JAR_TYP = "oauth-authz-req+jwt";

// JWT-standard claims that are request-object envelope metadata, not
// OAuth authorization parameters — stripped from the returned params.
var ENVELOPE_CLAIMS = ["iss", "aud", "exp", "iat", "nbf", "jti"];

/**
 * @primitive b.auth.jar.parse
 * @signature b.auth.jar.parse(jar, opts)
 * @since     0.12.31
 * @status    stable
 * @compliance soc2
 * @related   b.auth.oauth.parseJarmResponse
 *
 * Verify an RFC 9101 request object and return its authorization
 * parameters. The signature is checked via
 * <code>b.auth.jwt.verifyExternal</code> (mandatory <code>algorithms</code>
 * allowlist), <code>iss</code> is pinned to <code>opts.clientId</code>,
 * <code>aud</code> to <code>opts.audience</code>, and the request
 * object's <code>client_id</code> claim must equal
 * <code>opts.clientId</code>. A request object carrying a nested
 * <code>request</code> / <code>request_uri</code> is refused
 * (RFC 9101 §6.3). Returns <code>{ params, claims }</code> where
 * <code>params</code> is the authorization parameters with the JWT
 * envelope claims removed.
 *
 * @opts
 *   {
 *     clientId:     string,    // required — expected client (iss + client_id pin)
 *     audience:     string,    // required — this server's issuer identifier (aud pin)
 *     algorithms:   string[],  // required — accepted signature algorithms (allowlist)
 *     jwks?:        object,    // one of jwks / jwksUri / keyResolver (the client's key)
 *     jwksUri?:     string,
 *     keyResolver?: function,
 *     clockSkewMs?: number,
 *   }
 *
 * @example
 *   var out = await b.auth.jar.parse(jar, {
 *     clientId:   "s6BhdRkqt3",
 *     audience:   "https://as.example.com",
 *     algorithms: ["ES256"],
 *     jwks:       clientJwks,
 *   });
 *   // → { params: { response_type: "code", redirect_uri: "...", ... }, claims: {...} }
 */
async function parse(jar, opts) {
  if (typeof jar !== "string" || jar.length === 0) {
    throw new AuthJarError("auth-jar/no-jar", "jar.parse: jar must be a non-empty string");
  }
  validateOpts.requireObject(opts, "jar.parse", AuthJarError);
  validateOpts(opts, [
    "clientId", "audience", "algorithms", "jwks", "jwksUri", "keyResolver", "clockSkewMs",
  ], "jar.parse");
  validateOpts.requireNonEmptyString(opts.clientId, "jar.parse: clientId", AuthJarError, "auth-jar/bad-client-id");
  validateOpts.requireNonEmptyString(opts.audience, "jar.parse: audience", AuthJarError, "auth-jar/bad-audience");

  // Delegate signature + alg-allowlist + iss/aud/exp verification to
  // verifyExternal (the hardened JWS verifier). It throws on alg
  // confusion / none / JWE / bad signature / iss / aud / expiry and
  // returns `{ header, claims }`.
  var verified = await jwtExternal.verifyExternal(jar, {
    algorithms:  opts.algorithms,
    jwks:        opts.jwks,
    jwksUri:     opts.jwksUri,
    keyResolver: opts.keyResolver,
    issuer:      opts.clientId,
    audience:    opts.audience,
    clockSkewMs: opts.clockSkewMs,
  });
  // RFC 9101 §10.8 — the request object MUST be explicitly typed so a JWT
  // minted for another purpose (id_token / access-token / logout-token)
  // and signed by the same client key cannot be replayed here as a request
  // object (cross-JWT confusion). Require the registered media type, with or
  // without the "application/" prefix; an absent or mismatched typ is refused.
  var jarTyp = verified.header && verified.header.typ;
  if (jarTyp !== JAR_TYP && jarTyp !== "application/" + JAR_TYP) {
    throw new AuthJarError("auth-jar/bad-typ",
      "jar.parse: request object header.typ must be \"" + JAR_TYP +
      "\" (RFC 9101 §10.8 — cross-JWT-confusion defense)");
  }
  var payload = verified.claims;

  // RFC 9101 §5.2 — the request object MUST carry a client_id claim,
  // and it MUST match the client. verifyExternal already pinned
  // iss === clientId, but client_id is a distinct REQUIRED claim;
  // accepting its absence would let a JAR pass on the strength of an
  // outer (attacker-controllable) query-param client_id alone, so a
  // missing client_id is refused rather than waved through.
  if (payload.client_id === undefined) {
    throw new AuthJarError("auth-jar/missing-client-id",
      "jar.parse: request object is missing the required client_id claim (RFC 9101 §5.2)");
  }
  if (payload.client_id !== opts.clientId) {
    throw new AuthJarError("auth-jar/client-id-mismatch",
      "jar.parse: request object client_id does not match the expected client");
  }
  // RFC 9101 §6.3 — a request object must not nest another request /
  // request_uri (recursion / confused-deputy vector).
  if (payload.request !== undefined || payload.request_uri !== undefined) {
    throw new AuthJarError("auth-jar/nested-request",
      "jar.parse: request object must not carry `request` or `request_uri` (RFC 9101 §6.3)");
  }

  var params = {};
  var keys = Object.keys(payload);
  for (var i = 0; i < keys.length; i++) {
    if (ENVELOPE_CLAIMS.indexOf(keys[i]) === -1) params[keys[i]] = payload[keys[i]];
  }
  return { params: params, claims: payload };
}

module.exports = {
  parse:        parse,
  JAR_TYP:      JAR_TYP,
  AuthJarError: AuthJarError,
};
