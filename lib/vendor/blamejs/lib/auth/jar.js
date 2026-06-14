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
 *   request object (the authorization-server side): the signature is
 *   checked through <code>b.auth.jwt.verifyExternal</code> (mandatory
 *   <code>algorithms</code> allowlist — no <code>alg: "none"</code>, no
 *   HMAC-vs-RSA confusion, no JWE-on-a-JWS-verifier), <code>iss</code>
 *   is pinned to the expected <code>clientId</code>, <code>aud</code> to
 *   this server's issuer identifier, the request object's
 *   <code>client_id</code> claim must match the client, and the
 *   authorization parameters are returned with the JWT envelope claims
 *   stripped.
 *
 *   <code>b.auth.jar.build(params, opts)</code> mints a request object
 *   (the client side): the authorization-request parameters become
 *   claims of a JWT signed with the client's classical key via
 *   <code>b.auth.jws.sign</code> (RS/PS/ES/EdDSA — the interop algs an
 *   authorization server accepts), typed <code>oauth-authz-req+jwt</code>,
 *   with <code>iss</code>/<code>aud</code> pinned and a short FAPI-2
 *   <code>exp</code>. <code>build</code> and <code>parse</code>
 *   round-trip. The framework's own tokens stay PQC-signed
 *   (<code>b.auth.jwt</code>); JAR signs classically only because no
 *   standard authorization server verifies a PQC request object today.
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
 *   The request object is signed with a classical JWS algorithm
 *   (RS/PS/ES/EdDSA) because no standard authorization server verifies a
 *   PQC-signed request object today; the framework's own JWT signer
 *   (<code>b.auth.jwt.sign</code>) stays PQC-only (ML-DSA / SLH-DSA) for
 *   the tokens blamejs itself issues. <code>build</code> composes
 *   <code>b.auth.jws.sign</code> for the classical signature — the
 *   client-side emission this module previously left to the operator's
 *   own JOSE tooling now ships in-framework.
 *
 * @card
 *   RFC 9101 JWT-Secured Authorization Request — build the client
 *   request object (classical JWS, typed, iss/aud-pinned, short exp) and
 *   verify it on the server with mandatory alg allowlist, client_id
 *   binding, and anti-nesting.
 */

var jwtExternal = require("./jwt-external");
var validateOpts = require("../validate-opts");
var C = require("../constants");
var bCrypto = require("../crypto");
var { defineClass } = require("../framework-error");

var AuthJarError = defineClass("AuthJarError", { alwaysPermanent: true });

var JAR_TYP = "oauth-authz-req+jwt";

// RFC 9101 §4 — a request object MUST carry response_type + client_id as
// claims (they are REQUIRED OAuth 2.0 authorization-request parameters).
var REQUIRED_REQUEST_PARAMS = ["response_type", "client_id"];

// Claims the builder sets itself from opts (iss = client_id, aud =
// audience) plus the JWT lifetime claims it mints (exp/nbf/iat/jti).
// Operator params colliding with iss / aud are refused so a params.iss
// can't shadow the builder-pinned issuer; the lifetime claims are owned by
// the builder's exp/nbf/jti opts, not by free-form params.
var BUILDER_OWNED_CLAIMS = ["iss", "aud", "exp", "nbf", "iat", "jti"];

// Default request-object lifetime. FAPI-2 message-signing wants a short
// window; 5 minutes mirrors the attestation-PoP floor and is overridable
// via opts.expiresInMs.
var DEFAULT_JAR_EXPIRES_MS = C.TIME.minutes(5);

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

  // Authorization parameters = every claim minus the JWT envelope.
  // assignOwnEnumerable skips the prototype-pollution sentinel keys — a
  // verified-but-hostile request object carrying a `__proto__` claim
  // (JSON.parse materializes it as an own key) must not graft onto the
  // returned params object's prototype chain (CWE-1321).
  var params = validateOpts.assignOwnEnumerable({}, payload, ENVELOPE_CLAIMS);
  return { params: params, claims: payload };
}

/**
 * @primitive b.auth.jar.build
 * @signature b.auth.jar.build(params, opts)
 * @since     0.14.22
 * @status    stable
 * @compliance soc2
 * @related   b.auth.jar.parse, b.auth.jws.sign
 *
 * Mint an RFC 9101 request object — the client side of JWT-Secured
 * Authorization Requests. The authorization-request parameters in
 * <code>params</code> become claims of a JWT signed with the client's
 * classical key, ready to send as the <code>request</code> parameter (or
 * pushed through PAR). The inverse of <code>b.auth.jar.parse</code>; the
 * two round-trip.
 *
 * The protected header carries <code>typ: "oauth-authz-req+jwt"</code>
 * (RFC 9101 §10.8 — explicit typing closes the cross-JWT-confusion vector
 * where a token minted for another purpose is replayed as a request
 * object). <code>iss</code> is set to <code>opts.clientId</code> and
 * <code>aud</code> to <code>opts.audience</code> — the authorization
 * server's issuer identifier (RFC 9101 §5; the FAPI 2.0 message-signing
 * profile requires both). <code>response_type</code> and
 * <code>client_id</code> are REQUIRED claims (RFC 9101 §4); the builder
 * refuses if either is absent from <code>params</code>. A request object
 * <strong>MUST NOT</strong> nest <code>request</code> /
 * <code>request_uri</code> (RFC 9101 §4) — supplying either in
 * <code>params</code> is refused at build, the mirror of
 * <code>parse</code>'s anti-nesting check.
 *
 * <code>exp</code> defaults to 5 minutes (FAPI-2 wants a short signing
 * window; tune via <code>opts.expiresInMs</code>); <code>nbf</code> is set
 * to <code>iat</code> and a random <code>jti</code> is minted so the AS can
 * single-use the object. The signing <code>alg</code> is derived from
 * <code>opts.key</code> via <code>b.auth.jws.sign</code> (RS/PS/ES/EdDSA);
 * <code>alg: "none"</code> is impossible — the signer refuses it. This is
 * the classical-interop path: the framework's own tokens stay PQC-signed.
 *
 * @opts
 *   {
 *     clientId:      string,           // required — → iss + must equal params.client_id
 *     audience:      string,           // required — AS issuer identifier → aud
 *     key:           KeyObject|PEM|JWK, // required — client's classical signing key
 *     alg?:          string,           // JWS alg override (default inferred from the key)
 *     kid?:          string,           // protected-header kid (JWKS selection at the AS)
 *     expiresInMs?:  number,           // exp = iat + this (default: 5m; positive int)
 *   }
 *
 * @example
 *   var ro = b.auth.jar.build(
 *     { response_type: "code", client_id: "s6BhdRkqt3",
 *       redirect_uri: "https://app/cb", scope: "openid", state: "xyz" },
 *     { clientId: "s6BhdRkqt3", audience: "https://as.example.com", key: clientKey, kid: "c1" });
 *   // → "eyJhbGciOiJFUzI1NiIsInR5cCI6Im9hdXRoLWF1dGh6LXJlcStqd3QiLCJraWQiOiJjMSJ9..."
 */
function build(params, opts) {
  if (params === null || typeof params !== "object" || Array.isArray(params)) {
    throw new AuthJarError("auth-jar/bad-params",
      "jar.build: params must be a plain object of authorization-request parameters");
  }
  validateOpts.requireObject(opts, "jar.build", AuthJarError, "auth-jar/bad-opts");
  validateOpts(opts, ["clientId", "audience", "key", "alg", "kid", "expiresInMs"], "jar.build");
  validateOpts.requireNonEmptyString(opts.clientId, "jar.build: clientId", AuthJarError, "auth-jar/bad-client-id");
  validateOpts.requireNonEmptyString(opts.audience, "jar.build: audience", AuthJarError, "auth-jar/bad-audience");
  if (opts.key === undefined || opts.key === null) {
    throw new AuthJarError("auth-jar/no-key", "jar.build: key (the client's signing key) is required");
  }
  validateOpts.optionalNonEmptyString(opts.alg, "jar.build: alg", AuthJarError, "auth-jar/bad-alg");
  validateOpts.optionalNonEmptyString(opts.kid, "jar.build: kid", AuthJarError, "auth-jar/bad-kid");
  validateOpts.optionalPositiveInt(opts.expiresInMs, "jar.build: expiresInMs", AuthJarError, "auth-jar/bad-expiry");

  // RFC 9101 §4 — a request object MUST NOT itself carry request /
  // request_uri (recursion / confused-deputy vector). Refuse at build, the
  // mirror of parse's anti-nesting check.
  if (params.request !== undefined || params.request_uri !== undefined) {
    throw new AuthJarError("auth-jar/nested-request",
      "jar.build: params must not carry `request` or `request_uri` " +
      "(RFC 9101 §4 — a request object cannot nest another)");
  }
  // The builder owns iss/aud and the JWT lifetime claims — a params key
  // colliding with one would either shadow a builder-pinned binding (iss /
  // aud) or fight the exp/nbf/jti the builder mints. Refuse so the operator
  // routes lifetime through opts.expiresInMs and the identity bindings
  // through clientId / audience.
  for (var bi = 0; bi < BUILDER_OWNED_CLAIMS.length; bi += 1) {
    var owned = BUILDER_OWNED_CLAIMS[bi];
    if (Object.prototype.hasOwnProperty.call(params, owned)) {
      throw new AuthJarError("auth-jar/reserved-claim",
        "jar.build: params must not set the builder-owned claim '" + owned +
        "' (iss/aud come from clientId/audience; exp/nbf/iat/jti are minted by the builder)");
    }
  }
  // RFC 9101 §4 — response_type + client_id are REQUIRED request parameters.
  for (var ri = 0; ri < REQUIRED_REQUEST_PARAMS.length; ri += 1) {
    var req = REQUIRED_REQUEST_PARAMS[ri];
    if (params[req] === undefined || params[req] === null || params[req] === "") {
      throw new AuthJarError("auth-jar/missing-required-param",
        "jar.build: params is missing the required '" + req + "' claim (RFC 9101 §4)");
    }
  }
  // An explicit params.client_id MUST match opts.clientId — the iss the
  // builder pins. A divergence is an operator mistake that would mint an
  // object parse() then refuses on the client_id-mismatch path.
  if (params.client_id !== opts.clientId) {
    throw new AuthJarError("auth-jar/client-id-mismatch",
      "jar.build: params.client_id ('" + params.client_id + "') must equal opts.clientId ('" +
      opts.clientId + "')");
  }

  var nowSec = Math.floor(Date.now() / C.TIME.seconds(1));
  var ttlMs = typeof opts.expiresInMs === "number" ? opts.expiresInMs : DEFAULT_JAR_EXPIRES_MS;
  var claims = {
    iss: opts.clientId,                                   // RFC 9101 §5 — iss = client_id
    aud: opts.audience,                                   // RFC 9101 §5 — aud = AS issuer identifier
    iat: nowSec,
    nbf: nowSec,
    exp: nowSec + Math.floor(ttlMs / C.TIME.seconds(1)),  // FAPI-2 short window
    jti: bCrypto.toBase64Url(bCrypto.generateBytes(16)),  // single-use marker for the AS
  };
  // Every authorization-request parameter becomes a claim. Proto-pollution
  // sentinels skipped; builder-owned claims passed as reserved so a stray
  // collision (already refused above) can never shadow the minted set.
  validateOpts.assignOwnEnumerable(claims, params, BUILDER_OWNED_CLAIMS);

  // Sign through the classical-JWS primitive (b.auth.jws.sign). The typed
  // header + alg-from-key + none-refusal all live there.
  return jwtExternal.signExternal(claims, {
    privateKey: opts.key,
    alg:        opts.alg,
    kid:        opts.kid,
    typ:        JAR_TYP,
  });
}

module.exports = {
  parse:        parse,
  build:        build,
  JAR_TYP:      JAR_TYP,
  AuthJarError: AuthJarError,
};
