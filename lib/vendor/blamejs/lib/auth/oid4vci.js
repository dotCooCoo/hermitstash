"use strict";
/**
 * @module     b.auth.oid4vci
 * @nav        Identity
 * @title      OpenID4VCI (issuer)
 * @order      340
 * @card       OpenID for Verifiable Credential Issuance 1.0 — issuer side.
 *             Bridges OAuth2 token-endpoint output to a credential-
 *             issuance endpoint that mints SD-JWT VCs bound to the
 *             holder key supplied in the proof JWT.
 *
 * @intro
 *   The framework's SD-JWT VC primitive (`b.auth.sdJwtVc`) handles
 *   credential signing + sealed-claim disclosures. OID4VCI sits one
 *   layer above: it standardises HOW a wallet asks an issuer for a
 *   credential, and how the issuer announces what it can issue.
 *
 *   This module ships the issuer-side glue (issuer-initiated +
 *   wallet-initiated flows):
 *
 *     - credential_offer: issuer mints a one-shot offer +
 *       pre-authorized_code; emits a `openid-credential-offer://...`
 *       deep link the wallet scans / clicks.
 *     - /token (pre-authorized_code grant): holder POSTs the
 *       pre-auth code (+ optional tx_code) and gets an access token
 *       scoped to a specific credential identifier.
 *     - /credential: holder POSTs the access token + a `proof` JWT
 *       (signed by the holder key the wallet wants the credential
 *       bound to). The issuer mints + returns the SD-JWT VC with
 *       that key in `cnf`.
 *     - /.well-known/openid-credential-issuer: discovery metadata
 *       document describing supported credentials.
 *
 *   The issuer composes:
 *     - `b.auth.sdJwtVc.issuer` for the actual SD-JWT VC minting
 *     - `b.cache` for the pre-auth code → user-binding map (TTL
 *       defaults to 5 minutes per OID4VCI §5.1.1)
 *     - `b.crypto.verify` for the holder proof-JWT signature
 *
 *   Operators wire three routes (the framework gives the parsing +
 *   minting shape; HTTP-binding stays operator-side so the existing
 *   middleware stack — auth, rate-limit, CSRF — applies normally):
 *
 *     POST /token        → ciba-style /token shared with the OAuth
 *                          client (or a separate handler that calls
 *                          issuer.exchangePreAuthorizedCode)
 *     POST /credential   → issuer.issueCredential(req)
 *     GET /.well-known/  → issuer.metadata()
 *       openid-credential-issuer
 */

var C = require("../constants");
var lazyRequire  = require("../lazy-require");
var validateOpts = require("../validate-opts");
var safeJson     = require("../safe-json");
var nodeCrypto   = require("node:crypto");
var { generateToken, sha3Hash, timingSafeEqual } = require("../crypto");
// Shared JOSE defenses (CVE-2026-22817 alg/kty cross-check). Top-of-
// file per project convention §3; no circular load — jwt-external
// requires nothing from oid4vci.
var jwtExternal  = require("./jwt-external");
var { AuthError } = require("../framework-error");

var cache       = lazyRequire(function () { return require("../cache"); });
var audit       = lazyRequire(function () { return require("../audit"); });
var observability = lazyRequire(function () { return require("../observability"); });
var emit = validateOpts.makeNamespacedEmitters("auth.oid4vci", { audit: audit, observability: observability });

var DEFAULT_PRE_AUTH_TTL_MS  = C.TIME.minutes(5);
var DEFAULT_ACCESS_TOKEN_TTL = C.TIME.minutes(15);
var DEFAULT_C_NONCE_TTL_MS   = C.TIME.minutes(5);
var MAX_PROOF_BYTES          = 32 * 1024;
var SUPPORTED_CREDENTIAL_FORMATS = ["vc+sd-jwt", "dc+sd-jwt"];

var _emitAudit  = emit.audit;
var _emitMetric = emit.metric;

function _b64uDecodeStr(s) {
  return Buffer.from(s, "base64url").toString("utf8");
}

// Linear trailing-`=` strip (charCodeAt + slice) — a regex-based
// padding strip is polynomial-ReDoS-shaped per CodeQL
// js/polynomial-redos; mirrors lib/argon2-builtin.js. The comparison
// below is standard base64 (RFC 7515 §4.1.6), so b.crypto.toBase64Url
// would produce the wrong alphabet.
function _stripBase64Pad(s) {
  var end = s.length;
  while (end > 0 && s.charCodeAt(end - 1) === 61) end--;                           // 61 = "="
  return s.slice(0, end);
}

// RFC 7515 §4.1.6 — x5c is an array of base64 (NOT base64url) DER
// certificate strings, leaf first. Parse + shape-validate the chain into
// node:crypto X509Certificate objects; refuse a malformed array (empty,
// non-string entries, non-base64, or a leaf that won't parse) with a
// typed AuthError matching the module error style.
function _parseX5cChain(x5c) {
  if (!Array.isArray(x5c) || x5c.length === 0) {
    throw new AuthError("auth-oid4vci/bad-x5c",
      "credential issuance: proof JWT `x5c` must be a non-empty array of base64 DER certificate strings (RFC 7515 §4.1.6)");
  }
  var derBuffers = [];
  var certs = [];
  for (var i = 0; i < x5c.length; i++) {
    var entry = x5c[i];
    if (typeof entry !== "string" || entry.length === 0) {
      throw new AuthError("auth-oid4vci/bad-x5c",
        "credential issuance: proof JWT `x5c[" + i + "]` must be a non-empty base64 string");
    }
    // Standard base64 (not base64url) per RFC 7515 §4.1.6. Reject
    // entries carrying base64url-only chars or that don't round-trip.
    if (/[^A-Za-z0-9+/=]/.test(entry)) {
      throw new AuthError("auth-oid4vci/bad-x5c",
        "credential issuance: proof JWT `x5c[" + i + "]` is not valid base64 (RFC 7515 §4.1.6 mandates standard base64, not base64url)");
    }
    var der = Buffer.from(entry, "base64");
    if (der.length === 0 || _stripBase64Pad(der.toString("base64")) !== _stripBase64Pad(entry)) {
      throw new AuthError("auth-oid4vci/bad-x5c",
        "credential issuance: proof JWT `x5c[" + i + "]` is not valid base64 (RFC 7515 §4.1.6)");
    }
    var cert;
    try { cert = new nodeCrypto.X509Certificate(der); }
    catch (e) {
      throw new AuthError("auth-oid4vci/bad-x5c",
        "credential issuance: proof JWT `x5c[" + i + "]` is not a parseable DER certificate: " + ((e && e.message) || String(e)));
    }
    derBuffers.push(der);
    certs.push(cert);
  }
  return { derBuffers: derBuffers, certs: certs };
}

async function _verifyProofJwt(proofJwt, expectedAud, expectedCNonce, expectedClientId, supportedAlgs, proofMaxAgeMs, resolveKid, validateX5c) {
  // OID4VCI §7.2.1.1: the proof JWT MUST:
  //   - typ = "openid4vci-proof+jwt"
  //   - alg in supported list (issuer publishes these)
  //   - aud = credential issuer URL (this issuer's `credential_issuer`)
  //   - iat = recent
  //   - nonce = c_nonce previously issued to the wallet
  //   - jwk (inline), kid (resolved via resolveKid), OR x5c (leaf-cert
  //     SPKI) in the header pointing at the holder key to bind cnf to
  //     (RFC 7515 §4.1.3 / §4.1.4 / §4.1.6; OID4VCI §8.2.1.1)
  if (typeof proofJwt !== "string" || proofJwt.length === 0 || proofJwt.length > MAX_PROOF_BYTES) {
    throw new AuthError("auth-oid4vci/bad-proof",
      "credential issuance: proof JWT is empty or exceeds " + MAX_PROOF_BYTES + " bytes");
  }
  var parts = proofJwt.split(".");
  if (parts.length !== 3) {
    throw new AuthError("auth-oid4vci/malformed-proof",
      "credential issuance: proof JWT must have 3 dot-separated parts");
  }
  var header, payload;
  try {
    header  = safeJson.parse(_b64uDecodeStr(parts[0]), { maxBytes: 4096 });                     // proof header cap
    payload = safeJson.parse(_b64uDecodeStr(parts[1]), { maxBytes: MAX_PROOF_BYTES });
  } catch (e) {
    throw new AuthError("auth-oid4vci/bad-proof-decode",
      "credential issuance: proof JWT base64 decode failed: " + ((e && e.message) || String(e)));
  }
  if (header.typ !== "openid4vci-proof+jwt") {
    throw new AuthError("auth-oid4vci/wrong-proof-typ",
      "credential issuance: proof JWT typ must be \"openid4vci-proof+jwt\" (got \"" + header.typ + "\")");
  }
  // Alg-allowlist gate (CWE-347 / CWE-757) — refuse unknown / unsupported
  // alg BEFORE any verify-side work. The supportedAlgs list is the issuer's posture;
  // refusing here mirrors the discipline in oauth.verifyIdToken /
  // jwt-external.verifyExternal.
  if (!header.alg || supportedAlgs.indexOf(header.alg) === -1) {
    throw new AuthError("auth-oid4vci/unsupported-proof-alg",
      "credential issuance: proof JWT alg \"" + header.alg + "\" not in issuer-supported set " +
      "(alg-allowlist gate — refused before key lookup)");
  }
  // RFC 7515 §4.1.11 — refuse non-empty `crit`. Pre-v0.9.x
  // silently ignored, letting an attacker-controlled wallet declare
  // critical extensions the verifier doesn't understand.
  if (header.crit !== undefined && header.crit !== null) {
    if (!Array.isArray(header.crit) || header.crit.length > 0) {
      throw new AuthError("auth-oid4vci/unknown-crit",
        "credential issuance: proof JWT carries non-empty 'crit' header — refused per RFC 7515 §4.1.11");
    }
  }
  if (!header.jwk && !header.kid && !header.x5c) {
    throw new AuthError("auth-oid4vci/no-key-in-proof",
      "credential issuance: proof JWT header must include `jwk`, `kid`, OR `x5c` (holder key binding)");
  }
  if (payload.aud !== expectedAud) {
    throw new AuthError("auth-oid4vci/wrong-proof-aud",
      "credential issuance: proof JWT aud \"" + payload.aud + "\" mismatch (expected \"" + expectedAud + "\")");
  }
  // c_nonce expectation has three states the caller distinguishes:
  //   null      → no nonce check expected (caller deliberately skips it).
  //   string    → the c_nonce the wallet must echo (compared below).
  //   undefined → a nonce WAS expected but the store missed/expired it
  //               (cNonceStore.get returns undefined on miss/expiry, and
  //               the c_nonce TTL is shorter than the access token's).
  //               Refuse with a typed code — comparing against undefined
  //               would otherwise throw a raw TypeError from timingSafeEqual.
  if (expectedCNonce === undefined) {
    throw new AuthError("auth-oid4vci/c-nonce-expired",
      "credential issuance: c_nonce expected but missing/expired — wallet must request a fresh c_nonce (the /token response's c_nonce TTL elapsed before /credential was called)");
  }
  if (expectedCNonce !== null) {
    // Constant-time c_nonce compare — secret-shaped value vs
    // attacker-controlled wallet payload.
    if (typeof payload.nonce !== "string" ||
        !timingSafeEqual(payload.nonce, expectedCNonce)) {
      throw new AuthError("auth-oid4vci/wrong-proof-nonce",
        "credential issuance: proof JWT nonce mismatch (replay defense — wallet must use the c_nonce from the most recent issuer response)");
    }
  }
  if (typeof payload.iat !== "number") {
    throw new AuthError("auth-oid4vci/no-proof-iat",
      "credential issuance: proof JWT must include iat");
  }
  var nowSec = Math.floor(Date.now() / C.TIME.seconds(1));
  // Use C.TIME for the 60s skew tolerance rather than a bare
  // 60 literal; matches the framework's constants discipline.
  var iatSkewSec = C.TIME.seconds(60) / C.TIME.seconds(1);
  if (payload.iat > nowSec + iatSkewSec) {
    throw new AuthError("auth-oid4vci/proof-iat-future",
      "credential issuance: proof JWT iat is in the future");
  }
  // Operator-tunable proof max-age. Default 10 minutes per
  // OID4VCI §7.2.1.1; operators with longer-lived wallet flows raise.
  var effectiveMaxAgeMs = (typeof proofMaxAgeMs === "number" && isFinite(proofMaxAgeMs) && proofMaxAgeMs > 0)
    ? proofMaxAgeMs
    : C.TIME.minutes(10);
  if (payload.iat < nowSec - Math.floor(effectiveMaxAgeMs / C.TIME.seconds(1))) {
    throw new AuthError("auth-oid4vci/proof-iat-too-old",
      "credential issuance: proof JWT iat older than " +
      Math.floor(effectiveMaxAgeMs / C.TIME.seconds(1)) +
      " seconds — wallet must mint a fresh proof");
  }
  if (expectedClientId && payload.iss && payload.iss !== expectedClientId) {
    throw new AuthError("auth-oid4vci/wrong-proof-iss",
      "credential issuance: proof JWT iss does not match the access-token client_id");
  }

  // Resolve the holder key the proof is signed with. Three paths:
  //   - inline `jwk` (RFC 7515 §4.1.3) — the wallet ships the public
  //     key in the header; bind `cnf` to it directly.
  //   - `kid` (RFC 7515 §4.1.4) without inline `jwk` — the wallet
  //     references a key by identifier (EUDI-Wallet attested-key flow,
  //     OID4VCI §8.2.1.1 `key_attestation` proof). The operator
  //     supplies `resolveKid(kid, header)` to map the kid → public key.
  //     With no resolver configured the issuer keeps the clear refusal
  //     (back-compat): a kid-only proof can't be verified without one.
  //   - `x5c` (RFC 7515 §4.1.6) without inline `jwk`/`kid` — the wallet
  //     ships a base64 DER certificate chain; the LEAF cert's SPKI is
  //     the holder key (OID4VCI §8.2.1.1). Like inline `jwk`, the chain
  //     is self-asserted, so leaf-SPKI extraction at the same trust
  //     level is the correct parity — the proof signature check binds
  //     the key. Chain trust beyond that is operator policy: an optional
  //     `validateX5c(chainDerBuffers, header)` callback may throw to
  //     refuse (PKI anchoring, EKU checks, revocation, attestation-CA
  //     allowlist) before the SPKI is trusted.
  var holderKeyJwk = header.jwk || null;
  var keyObj;
  if (!holderKeyJwk && header.kid) {
    if (typeof resolveKid !== "function") {
      throw new AuthError("auth-oid4vci/kid-resolver-not-supported",
        "credential issuance: proof JWT used `kid` without inline `jwk` — supply { jwk } in the header for inline binding, or configure issuer.create({ resolveKid }) to resolve kid-referenced holder keys");
    }
    var resolved;
    try {
      resolved = await resolveKid(header.kid, header);
    } catch (e) {
      // Wrap a resolver exception in a stable AuthError code so the
      // /credential handler returns a typed refusal instead of an
      // unhandled rejection. resolveKid is operator code, so its own
      // message is allowed through for operator-side debugging.
      throw new AuthError("auth-oid4vci/kid-resolver-failed",
        "credential issuance: resolveKid threw while resolving the proof JWT kid: " + ((e && e.message) || String(e)));
    }
    if (!resolved) {
      throw new AuthError("auth-oid4vci/kid-unresolved",
        "credential issuance: resolveKid returned no key for the proof JWT kid — refused");
    }
    // Normalize to (verify KeyObject) + (cnf JWK). A KeyObject verifies
    // the signature directly; the cnf binding sdJwtIssuer.issue expects
    // a JWK, so a resolved KeyObject is exported to one. A resolved JWK
    // is used for both.
    if (resolved instanceof nodeCrypto.KeyObject) {
      try { holderKeyJwk = resolved.export({ format: "jwk" }); }
      catch (e) {
        throw new AuthError("auth-oid4vci/bad-resolved-key",
          "credential issuance: resolveKid returned a KeyObject that does not export to JWK: " + ((e && e.message) || String(e)));
      }
    } else if (typeof resolved === "object" && typeof resolved.kty === "string") {
      holderKeyJwk = resolved;
    } else {
      throw new AuthError("auth-oid4vci/bad-resolved-key",
        "credential issuance: resolveKid must return a JWK object (with kty) or a node:crypto KeyObject");
    }
    // CVE-2026-22817 — same alg/kty cross-check the inline path applies.
    // A resolver that returns an RSA key for a proof declaring an HMAC
    // alg would otherwise be verified as an HMAC secret.
    jwtExternal._assertAlgKtyMatch(header.alg, holderKeyJwk);
    try { keyObj = nodeCrypto.createPublicKey({ key: holderKeyJwk, format: "jwk" }); }
    catch (e) {
      throw new AuthError("auth-oid4vci/bad-resolved-key",
        "credential issuance: resolveKid-returned key is not importable as a public key: " + ((e && e.message) || String(e)));
    }
  } else if (!holderKeyJwk && header.x5c) {
    // RFC 7515 §4.1.6 / OID4VCI §8.2.1.1 — the wallet ships a base64 DER
    // certificate chain; the LEAF (first) cert's SPKI is the holder key.
    var chain = _parseX5cChain(header.x5c);
    // Operator chain-trust policy runs BEFORE the SPKI is trusted. A
    // throw refuses the proof (wrapped in a stable AuthError code so the
    // /credential handler returns a typed refusal rather than an
    // unhandled rejection; the callback is operator code, so its own
    // message is allowed through for operator-side debugging).
    if (typeof validateX5c === "function") {
      try {
        await validateX5c(chain.derBuffers.slice(), header);
      } catch (e) {
        if (e instanceof AuthError) throw e;
        throw new AuthError("auth-oid4vci/x5c-rejected",
          "credential issuance: validateX5c rejected the proof JWT certificate chain: " + ((e && e.message) || String(e)));
      }
    }
    // Extract the leaf SPKI as a JWK to use as the holder key, exactly
    // parallel to the inline-jwk path. publicKey is a node:crypto
    // KeyObject; export to JWK for the cnf binding sdJwtIssuer.issue
    // expects.
    try { holderKeyJwk = chain.certs[0].publicKey.export({ format: "jwk" }); }
    catch (e) {
      throw new AuthError("auth-oid4vci/bad-x5c",
        "credential issuance: proof JWT `x5c` leaf certificate public key does not export to JWK: " + ((e && e.message) || String(e)));
    }
    // CVE-2026-22817 — same alg/kty cross-check the inline path applies.
    // A leaf cert holding an RSA key against a proof declaring an HMAC
    // alg would otherwise be verified as an HMAC secret.
    jwtExternal._assertAlgKtyMatch(header.alg, holderKeyJwk);
    try { keyObj = nodeCrypto.createPublicKey({ key: holderKeyJwk, format: "jwk" }); }
    catch (e) {
      throw new AuthError("auth-oid4vci/bad-x5c",
        "credential issuance: proof JWT `x5c` leaf public key is not importable: " + ((e && e.message) || String(e)));
    }
  } else {
    if (!holderKeyJwk) {
      throw new AuthError("auth-oid4vci/no-jwk-in-header",
        "credential issuance: proof JWT must carry `jwk` for inline holder-key binding");
    }
    // CVE-2026-22817 — cross-check alg/kty before importing the holder
    // JWK. Without this an attacker-controlled `alg: "HS256"` against an
    // RSA holder JWK would have node:crypto.verify treat the RSA public
    // key as an HMAC secret. Routed through the shared helper so every
    // JWT verifier in the framework enforces the same check.
    jwtExternal._assertAlgKtyMatch(header.alg, holderKeyJwk);
    try { keyObj = nodeCrypto.createPublicKey({ key: holderKeyJwk, format: "jwk" }); }
    catch (e) {
      throw new AuthError("auth-oid4vci/bad-jwk",
        "credential issuance: proof JWT jwk is not parseable: " + ((e && e.message) || String(e)));
    }
  }

  var signingInput = parts[0] + "." + parts[1];
  var sig = Buffer.from(parts[2], "base64url");
  // Map alg → hash + verify-options shape. ES256 = sha256+ieee-p1363,
  // ES384 = sha384+ieee-p1363, EdDSA / RS256 / PS256 follow.
  var hashByAlg = { ES256: "sha256", ES384: "sha384", ES512: "sha512", PS256: "sha256",
                    PS384: "sha384", PS512: "sha512", RS256: "sha256", RS384: "sha384",
                    RS512: "sha512", EdDSA: null };
  if (!Object.prototype.hasOwnProperty.call(hashByAlg, header.alg)) {
    throw new AuthError("auth-oid4vci/unsupported-proof-alg",
      "credential issuance: proof JWT alg \"" + header.alg + "\" not in framework set");
  }
  var verifyOpts = { key: keyObj };
  if (header.alg.indexOf("ES") === 0) verifyOpts.dsaEncoding = "ieee-p1363";
  if (header.alg.indexOf("PS") === 0) {
    verifyOpts.padding = nodeCrypto.constants.RSA_PKCS1_PSS_PADDING;
    verifyOpts.saltLength = nodeCrypto.constants.RSA_PSS_SALTLEN_DIGEST;
  }
  var ok = nodeCrypto.verify(hashByAlg[header.alg], Buffer.from(signingInput, "ascii"), verifyOpts, sig);
  if (!ok) {
    throw new AuthError("auth-oid4vci/proof-bad-signature",
      "credential issuance: proof JWT signature verification failed (holder doesn't actually hold the bound key)");
  }
  return { header: header, payload: payload, jwk: holderKeyJwk };
}

/**
 * @primitive b.auth.oid4vci.issuer.create
 * @signature b.auth.oid4vci.issuer.create(opts)
 * @since     0.8.62
 * @status    stable
 * @related   b.auth.oid4vp.verifier.create, b.auth.ciba.client.create
 *
 * Build an OID4VCI issuer over a configured `b.auth.sdJwtVc.issuer`.
 * Returns route handlers for credential_offer, /token (pre-authorized
 * grant), and /credential, plus a `metadata()` accessor for the
 * /.well-known/openid-credential-issuer document.
 *
 * @opts
 *   {
 *     credentialIssuerUrl:        string,                // required — used as `iss` and proof `aud`
 *     credentialEndpoint:         string,                // public URL for the /credential endpoint
 *     tokenEndpoint:              string,                // public URL for /token (re-used by the pre-auth flow)
 *     sdJwtIssuer:                <b.auth.sdJwtVc.issuer instance>, // mints the SD-JWT VC
 *     supportedCredentials:       { [id]: { format, vct, claims, ... } },
 *     proofAlgorithms:            string[],              // default ["ES256", "ES384", "EdDSA"]
 *     resolveKid?:                function(kid, header), // resolve a kid-only proof's holder key (JWK | KeyObject); without it, kid-only proofs are refused
 *     validateX5c?:               function(chainDerBuffers, header), // x5c (RFC 7515 §4.1.6) chain-trust policy; throw to refuse. Absent → leaf-cert SPKI binds at the same self-asserted trust as inline `jwk`
 *     preAuthCodeTtlMs?:          number,                // default 5m
 *     accessTokenTtlMs?:          number,                // default 15m
 *     cNonceTtlMs?:               number,                // default 5m
 *     codeStore?:                 b.cache instance,
 *     accessTokenStore?:          b.cache instance,
 *     cNonceStore?:               b.cache instance,
 *   }
 *
 * @example
 *   var sdJwtIssuer = b.auth.sdJwtVc.issuer.create({ issuerUrl: "https://issuer.example.com", keys: [{ kid: "k1", privateKey: pem, algorithm: "ES256" }] });
 *   var oid4vci = b.auth.oid4vci.issuer.create({
 *     credentialIssuerUrl: "https://issuer.example.com",
 *     credentialEndpoint:  "https://issuer.example.com/credential",
 *     tokenEndpoint:       "https://issuer.example.com/token",
 *     sdJwtIssuer:         sdJwtIssuer,
 *     supportedCredentials: {
 *       "id-card-1": {
 *         format: "vc+sd-jwt",
 *         vct:    "https://example.com/vct/identity",
 *         claims: { given_name: {}, family_name: {}, birthdate: {} },
 *       },
 *     },
 *   });
 */
function create(opts) {
  validateOpts.requireObject(opts, "auth.oid4vci.issuer.create", AuthError);
  validateOpts.requireNonEmptyString(opts.credentialIssuerUrl,
    "issuer.create: credentialIssuerUrl", AuthError, "auth-oid4vci/no-issuer-url");
  validateOpts.requireNonEmptyString(opts.credentialEndpoint,
    "issuer.create: credentialEndpoint", AuthError, "auth-oid4vci/no-credential-endpoint");
  validateOpts.requireNonEmptyString(opts.tokenEndpoint,
    "issuer.create: tokenEndpoint", AuthError, "auth-oid4vci/no-token-endpoint");
  if (!opts.sdJwtIssuer || typeof opts.sdJwtIssuer.issue !== "function") {
    throw new AuthError("auth-oid4vci/no-sd-jwt-issuer",
      "issuer.create: sdJwtIssuer must be a b.auth.sdJwtVc.issuer instance");
  }
  if (!opts.supportedCredentials || typeof opts.supportedCredentials !== "object" ||
      Object.keys(opts.supportedCredentials).length === 0) {
    throw new AuthError("auth-oid4vci/no-supported-credentials",
      "issuer.create: supportedCredentials must be a non-empty map of { id: { format, vct, ... } }");
  }
  Object.keys(opts.supportedCredentials).forEach(function (id) {
    var spec = opts.supportedCredentials[id];
    if (!spec || typeof spec !== "object") {
      throw new AuthError("auth-oid4vci/bad-credential-spec",
        "supportedCredentials['" + id + "'] must be an object");
    }
    if (!spec.format || SUPPORTED_CREDENTIAL_FORMATS.indexOf(spec.format) === -1) {
      throw new AuthError("auth-oid4vci/unsupported-format",
        "supportedCredentials['" + id + "'].format must be one of " + SUPPORTED_CREDENTIAL_FORMATS.join(", "));
    }
    if (typeof spec.vct !== "string" || spec.vct.length === 0) {
      throw new AuthError("auth-oid4vci/no-vct",
        "supportedCredentials['" + id + "'].vct is required");
    }
  });

  var proofAlgs = Array.isArray(opts.proofAlgorithms) && opts.proofAlgorithms.length > 0
    ? opts.proofAlgorithms : ["ES256", "ES384", "EdDSA"];

  // Optional kid-resolver for kid-only proofs (EUDI-Wallet attested-key
  // flow). Config-time throw if supplied but not a function. Absent →
  // kid-only proofs keep the clear refusal (back-compat).
  var resolveKid = validateOpts.optionalFunction(opts.resolveKid,
    "issuer.create: resolveKid", AuthError, "auth-oid4vci/bad-resolve-kid");

  // Optional x5c chain-trust policy for x5c proofs (RFC 7515 §4.1.6 /
  // OID4VCI §8.2.1.1). Config-time throw if supplied but not a function.
  // Absent → the leaf-cert SPKI binds at the same self-asserted trust
  // level as an inline `jwk` (the proof signature binds the key); chain
  // anchoring beyond that is the operator's to enforce via this callback.
  var validateX5c = validateOpts.optionalFunction(opts.validateX5c,
    "issuer.create: validateX5c", AuthError, "auth-oid4vci/bad-validate-x5c");

  var preAuthTtl = opts.preAuthCodeTtlMs || DEFAULT_PRE_AUTH_TTL_MS;
  var accessTokenTtl = opts.accessTokenTtlMs || DEFAULT_ACCESS_TOKEN_TTL;
  var cNonceTtl = opts.cNonceTtlMs || DEFAULT_C_NONCE_TTL_MS;
  // Operator-tunable proof iat-too-old window. Default 10
  // minutes per OID4VCI §7.2.1.1.
  var proofMaxAgeMs = (typeof opts.proofMaxAgeMs === "number" && isFinite(opts.proofMaxAgeMs) && opts.proofMaxAgeMs > 0)
    ? opts.proofMaxAgeMs
    : C.TIME.minutes(10);
  // Access-token single-use. OID4VCI §7's credential endpoint
  // does NOT inherently make the access token single-use; pre-v0.9.x
  // c_nonce rotation alone defended against proof replay, but a stolen
  // access token combined with a fresh proof could re-mint
  // credentials. Default true; operators with batch_credential flows
  // that need access-token reuse opt out with an audited reason.
  var accessTokenSingleUse = opts.accessTokenSingleUse !== false;

  var codeStore = opts.codeStore || cache().create({
    namespace: "auth.oid4vci.preauth", ttlMs: preAuthTtl,
  });
  var atStore = opts.accessTokenStore || cache().create({
    namespace: "auth.oid4vci.access_token", ttlMs: accessTokenTtl,
  });
  var cNonceStore = opts.cNonceStore || cache().create({
    namespace: "auth.oid4vci.c_nonce", ttlMs: cNonceTtl,
  });

  /**
   * @primitive b.auth.oid4vci.issuer.createCredentialOffer
   * @signature b.auth.oid4vci.issuer.createCredentialOffer(opts)
   * @since     0.8.62
   *
   * Mint a credential_offer + pre-authorized_code bound to a specific
   * subject (the user the issuer has already authenticated out-of-
   * band — kiosk, helpdesk identity proof, etc.). Returns the
   * `openid-credential-offer://` deep link the wallet scans.
   *
   * @opts
   *   {
   *     subject:        string,
   *     credentialIds:  string[],
   *     txCode?:        { value: string, length?: number, input_mode?: string, description?: string },
   *   }
   *
   * @example
   *   var offer = await oid4vci.createCredentialOffer({
   *     subject:       "user-42",
   *     credentialIds: ["id-card-1"],
   *   });
   *   // → { offer, preAuthCode, deepLink, offerUri }
   */
  async function createCredentialOffer(coOpts) {
    coOpts = coOpts || {};
    if (typeof coOpts.subject !== "string" || coOpts.subject.length === 0) {
      throw new AuthError("auth-oid4vci/no-subject",
        "createCredentialOffer: subject is required");
    }
    if (!Array.isArray(coOpts.credentialIds) || coOpts.credentialIds.length === 0) {
      throw new AuthError("auth-oid4vci/no-credential-ids",
        "createCredentialOffer: credentialIds must be a non-empty array");
    }
    coOpts.credentialIds.forEach(function (id) {
      if (!opts.supportedCredentials[id]) {
        throw new AuthError("auth-oid4vci/unknown-credential-id",
          "createCredentialOffer: credentialId \"" + id + "\" not in supportedCredentials");
      }
    });
    var preAuthCode = generateToken(32);                                                         // 256-bit single-use pre-auth code
    var txCode = coOpts.txCode || null;
    if (txCode !== null) {
      if (typeof txCode !== "object" || typeof txCode.value !== "string") {
        throw new AuthError("auth-oid4vci/bad-tx-code",
          "createCredentialOffer: txCode must be { value: string, length?, input_mode? }");
      }
    }
    await codeStore.set(preAuthCode, {
      subject:        coOpts.subject,
      credentialIds:  coOpts.credentialIds.slice(),
      txCodeHash:     txCode ? sha3Hash("oid4vci-tx:" + txCode.value) : null,
      issuedAt:       Date.now(),
    });
    var offer = {
      credential_issuer:    opts.credentialIssuerUrl,
      credential_configuration_ids: coOpts.credentialIds.slice(),
      grants: {
        "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
          "pre-authorized_code": preAuthCode,
          tx_code: txCode ? {
            length:     typeof txCode.length === "number" ? txCode.length : 4,                  // default tx-code 4 digits
            input_mode: txCode.input_mode || "numeric",
            description: txCode.description || undefined,
          } : undefined,
        },
      },
    };
    var encoded = encodeURIComponent(JSON.stringify(offer));
    _emitAudit("offer_created", "success", {
      subject:       coOpts.subject,
      credentialIds: coOpts.credentialIds,
      hasTxCode:     !!txCode,
    });
    _emitMetric("offer-created");
    return {
      offer:        offer,
      preAuthCode:  preAuthCode,
      deepLink:     "openid-credential-offer://?credential_offer=" + encoded,
      offerUri:     opts.credentialIssuerUrl + "/credential_offer/" + preAuthCode,
    };
  }

  /**
   * @primitive b.auth.oid4vci.issuer.exchangePreAuthorizedCode
   * @signature b.auth.oid4vci.issuer.exchangePreAuthorizedCode(opts)
   * @since     0.8.62
   *
   * Token-endpoint helper for the pre-authorized_code grant. Returns
   * an access token + c_nonce the wallet uses on /credential. The
   * underlying access token's scope is the credential_configuration_ids
   * the offer was bound to.
   *
   * @opts
   *   {
   *     preAuthCode:  string,
   *     txCode?:      string,
   *   }
   *
   * @example
   *   var tokens = await oid4vci.exchangePreAuthorizedCode({
   *     preAuthCode: req.body["pre-authorized_code"],
   *     txCode:      req.body.tx_code,
   *   });
   *   // → { access_token, token_type, expires_in, c_nonce, ... }
   */
  async function exchangePreAuthorizedCode(eopts) {
    eopts = eopts || {};
    if (typeof eopts.preAuthCode !== "string" || eopts.preAuthCode.length === 0) {
      throw new AuthError("auth-oid4vci/missing-pre-auth-code",
        "exchangePreAuthorizedCode: pre-authorized_code required");
    }
    var entry = await codeStore.get(eopts.preAuthCode);
    if (!entry) {
      throw new AuthError("auth-oid4vci/invalid-pre-auth-code",
        "exchangePreAuthorizedCode: pre-authorized_code unknown / expired / already redeemed");
    }
    // Single-use: consume on success.
    if (entry.txCodeHash !== null) {
      if (typeof eopts.txCode !== "string" || eopts.txCode.length === 0) {
        throw new AuthError("auth-oid4vci/missing-tx-code",
          "exchangePreAuthorizedCode: tx_code required (offer mandates it)");
      }
      var txHash = sha3Hash("oid4vci-tx:" + eopts.txCode);
      // Constant-time compare on the hashed tx_code — `===` on a
      // hex digest leaks per-byte timing under attacker-controlled
      // input. Every framework compare against attacker-influenced
      // bytes routes through timingSafeEqual regardless of the
      // operand length being fixed.
      if (!timingSafeEqual(txHash, entry.txCodeHash)) {
        // Don't consume on failure — wallet may be retrying. Operator
        // attaches their own attempt counter / lockout via b.auth.lockout.
        _emitAudit("tx_code_mismatch", "failure", {
          subject: entry.subject,
        });
        throw new AuthError("auth-oid4vci/tx-code-mismatch",
          "exchangePreAuthorizedCode: tx_code does not match");
      }
    }
    await codeStore.del(eopts.preAuthCode);
    var accessToken = generateToken(32);                                                         // 256-bit access token
    var cNonce = generateToken(16);                                                              // 128-bit c_nonce
    var record = {
      subject:       entry.subject,
      credentialIds: entry.credentialIds,
      cNonce:        cNonce,
      issuedAt:      Date.now(),
    };
    await atStore.set(accessToken, record);
    await cNonceStore.set(accessToken, cNonce);
    _emitAudit("token_issued", "success", {
      subject:       entry.subject,
      credentialIds: entry.credentialIds,
    });
    _emitMetric("token-issued");
    return {
      access_token:  accessToken,
      token_type:    "Bearer",
      expires_in:    Math.floor(accessTokenTtl / 1000),                                          // ms→s
      c_nonce:       cNonce,
      c_nonce_expires_in: Math.floor(cNonceTtl / 1000),                                          // ms→s
      authorization_details: entry.credentialIds.map(function (id) {
        return {
          type:                          "openid_credential",
          credential_configuration_id:   id,
        };
      }),
    };
  }

  /**
   * @primitive b.auth.oid4vci.issuer.issueCredential
   * @signature b.auth.oid4vci.issuer.issueCredential(opts)
   * @since     0.8.62
   *
   * The /credential endpoint handler. Validates the access token,
   * verifies the holder proof JWT (binding the holder key the wallet
   * controls to a fresh c_nonce), mints the SD-JWT VC via the
   * configured `sdJwtIssuer`, and rotates the c_nonce so the next
   * request gets a fresh challenge. Returns the credential string +
   * the new c_nonce.
   *
   * Operators supply `claims` per call (the issuer's own user-data
   * lookup keyed off the access-token's subject); the framework
   * doesn't store user attributes itself.
   *
   * @opts
   *   {
   *     accessToken:           string,
   *     credentialIdentifier:  string,
   *     proof:                 string,            // openid4vci-proof+jwt
   *     claims:                object,            // operator-supplied user data
   *     selectivelyDisclosed?: string[],
   *     ttlMs?:                number,
   *   }
   *
   * @example
   *   var rv = await oid4vci.issueCredential({
   *     accessToken:          accessTokenFromBearerHeader,
   *     credentialIdentifier: "id-card-1",
   *     proof:                req.body.proof.jwt,
   *     claims:               { given_name: "Alice", family_name: "Smith" },
   *   });
   *   // → { format: "vc+sd-jwt", credential, c_nonce, c_nonce_expires_in }
   */
  async function issueCredential(iopts) {
    iopts = iopts || {};
    if (typeof iopts.accessToken !== "string" || iopts.accessToken.length === 0) {
      throw new AuthError("auth-oid4vci/missing-access-token",
        "issueCredential: accessToken required");
    }
    var record = await atStore.get(iopts.accessToken);
    if (!record) {
      throw new AuthError("auth-oid4vci/invalid-access-token",
        "issueCredential: access token unknown / expired");
    }
    if (typeof iopts.credentialIdentifier !== "string" ||
        record.credentialIds.indexOf(iopts.credentialIdentifier) === -1) {
      throw new AuthError("auth-oid4vci/wrong-credential-identifier",
        "issueCredential: credentialIdentifier not in this access-token's authorized set");
    }
    var spec = opts.supportedCredentials[iopts.credentialIdentifier];
    if (!spec) {
      throw new AuthError("auth-oid4vci/unknown-credential-id",
        "issueCredential: credentialIdentifier not configured");
    }

    var expectedCNonce = await cNonceStore.get(iopts.accessToken);
    var verified = await _verifyProofJwt(iopts.proof, opts.credentialIssuerUrl, expectedCNonce, null, proofAlgs, proofMaxAgeMs, resolveKid, validateX5c);

    if (!iopts.claims || typeof iopts.claims !== "object") {
      throw new AuthError("auth-oid4vci/no-claims",
        "issueCredential: claims required (operator looks up the subject's data and supplies them)");
    }
    var sdJwtToken = await opts.sdJwtIssuer.issue({
      vct:                  spec.vct,
      subject:              record.subject,
      claims:               iopts.claims,
      selectivelyDisclosed: iopts.selectivelyDisclosed || Object.keys(iopts.claims),
      holderKey:            verified.jwk,
      ttlMs:                iopts.ttlMs,
    });

    // Rotate c_nonce so a replayed proof-JWT for a follow-up
    // batch_credential request is rejected.
    var newCNonce = generateToken(16);                                                           // 128-bit c_nonce
    await cNonceStore.set(iopts.accessToken, newCNonce);

    // When single-use is on (default), DELETE the access token
    // after successful credential mint. A stolen access token paired
    // with a fresh proof would otherwise re-mint credentials; the
    // c_nonce rotation alone defends against proof replay but not
    // against an attacker who exfiltrated the access token. The
    // accompanying c_nonce entry expires with its TTL; deleting it
    // explicitly tightens cleanup.
    if (accessTokenSingleUse) {
      try {
        await atStore.del(iopts.accessToken);
        await cNonceStore.del(iopts.accessToken);
      } catch (_e) { /* drop-silent — cleanup is best-effort */ }
    }

    _emitAudit("credential_issued", "success", {
      subject:              record.subject,
      credentialIdentifier: iopts.credentialIdentifier,
      vct:                  spec.vct,
    });
    _emitMetric("credential-issued");

    return {
      format:      spec.format,
      credential:  sdJwtToken.token,
      c_nonce:     newCNonce,
      c_nonce_expires_in: Math.floor(cNonceTtl / 1000),                                          // ms→s
    };
  }

  /**
   * @primitive b.auth.oid4vci.issuer.metadata
   * @signature b.auth.oid4vci.issuer.metadata()
   * @since     0.8.62
   *
   * Returns the /.well-known/openid-credential-issuer JSON document
   * describing the issuer's supported credentials, endpoints, and
   * proof types. Operators serve the result verbatim.
   *
   * @example
   *   app.get("/.well-known/openid-credential-issuer", function (req, res) {
   *     res.setHeader("Content-Type", "application/json");
   *     res.end(JSON.stringify(oid4vci.metadata()));
   *   });
   */
  function metadata() {
    var configurations = {};
    Object.keys(opts.supportedCredentials).forEach(function (id) {
      var spec = opts.supportedCredentials[id];
      configurations[id] = {
        format: spec.format,
        vct:    spec.vct,
        claims: spec.claims || {},
        cryptographic_binding_methods_supported: spec.cryptographic_binding_methods_supported || ["jwk"],
        credential_signing_alg_values_supported: spec.credential_signing_alg_values_supported || ["ES256"],
        proof_types_supported: {
          jwt: { proof_signing_alg_values_supported: proofAlgs },
        },
        display: spec.display || undefined,
      };
    });
    return {
      credential_issuer:               opts.credentialIssuerUrl,
      credential_endpoint:             opts.credentialEndpoint,
      token_endpoint:                  opts.tokenEndpoint,
      authorization_servers:           opts.authorizationServers || [opts.credentialIssuerUrl],
      credential_configurations_supported: configurations,
    };
  }

  return {
    createCredentialOffer:      createCredentialOffer,
    exchangePreAuthorizedCode:  exchangePreAuthorizedCode,
    issueCredential:            issueCredential,
    metadata:                   metadata,
  };
}

module.exports = {
  issuer: { create: create },
};
