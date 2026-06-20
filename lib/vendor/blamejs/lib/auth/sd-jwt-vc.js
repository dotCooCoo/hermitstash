"use strict";
/**
 * b.auth.sdJwtVc — Selective Disclosure JWT for Verifiable Credentials
 * (draft-ietf-oauth-sd-jwt-vc).
 *
 * SD-JWT VC is the IETF format aligned with the EU Digital Identity
 * Wallet (EUDI Wallet) roll-out and the EU AI Act Article 50
 * disclosure requirements. It allows an issuer to mint a credential
 * containing selectively-disclosable claims; the holder presents only
 * the subset they choose to a verifier; the verifier validates the
 * issuer signature + the cryptographic binding between disclosures
 * and the issuer's `_sd` digest array.
 *
 *   // Issuer side
 *   var sdJwt = b.auth.sdJwtVc.issue({
 *     issuer:        "https://issuer.example.com",
 *     subject:       "did:web:alice.example.com",
 *     vct:           "https://credentials.example.com/identity_credential",
 *     claims: {
 *       given_name:    "Alice",
 *       family_name:   "Smith",
 *       birthdate:     "1990-01-15",
 *       nationality:   "US",
 *     },
 *     selectivelyDisclosed: ["given_name", "family_name", "birthdate"],
 *     issuerKey:     issuerPrivKeyPem,
 *     algorithm:     "ES256",
 *     ttlMs:         C.TIME.days(30),
 *     holderKey:     holderPubJwk,           // optional cnf binding
 *   });
 *
 *   // Holder presents subset
 *   var presentation = b.auth.sdJwtVc.present({
 *     sdJwt:               sdJwt.token,
 *     disclosedClaimNames: ["given_name"],     // selective release
 *     audience:            "https://verifier.example.com",
 *     nonce:               nonceFromVerifier,
 *     holderKey:           holderPrivKeyPem,    // for KB-JWT signing
 *     algorithm:           "ES256",
 *   });
 *
 *   // Verifier validates
 *   var result = await b.auth.sdJwtVc.verify(presentation, {
 *     issuerKeyResolver: async function (header) { return issuerPubKeyPem; },
 *     audience:          "https://verifier.example.com",
 *     nonce:              nonceForReplayDefense,
 *   });
 *   // → { valid: true, claims: { vct, given_name }, holderKey, kbValidated }
 *
 * Supported signature algorithms (issuer + KB-JWT):
 *   - ES256 (ECDSA + P-256 + SHA-256)         — default per spec
 *   - ES384 (ECDSA + P-384 + SHA-384)
 *   - EdDSA (Ed25519)
 *   - ML-DSA-87 (PQC; framework's default)    — draft IETF allocation
 *   - ML-DSA-65 (PQC; lighter)
 *
 * Hash algorithm for `_sd` digests: SHA-256 (spec default). Operators
 * with PQC strict deployments specify "sha3-256" or "sha-512" via
 * opts.hashAlg at issue time; verify() reads `_sd_alg` from the
 * issuer payload to know how to recompute digests.
 */

var nodeCrypto = require("node:crypto");
var bCrypto = require("../crypto");
var safeBuffer = require("../safe-buffer");
var safeJson = require("../safe-json");
var validateOpts = require("../validate-opts");

function _timingSafeEqStr(a, b) {
  if (typeof a !== "string" || typeof b !== "string") return false;
  return bCrypto.timingSafeEqual(a, b);
}
var disclosure = require("./sd-jwt-vc-disclosure");
var sdJwtVcIssuer = require("./sd-jwt-vc-issuer");
var sdJwtVcHolder = require("./sd-jwt-vc-holder");
// Shared JOSE defenses (CVE-2026-22817 alg/kty cross-check +
// CVE-2026-23552 constant-time iss compare). Top-of-file per project
// convention §3; no circular load — jwt-external requires nothing from
// sd-jwt-vc.
var jwtExternal = require("./jwt-external");
var { AuthError } = require("../framework-error");

var SUPPORTED_ALGS = Object.freeze([
  "ES256", "ES384", "EdDSA", "ML-DSA-87", "ML-DSA-65",
]);

var SUPPORTED_HASH_ALGS = Object.freeze({
  "sha-256":  "sha256",
  "sha-512":  "sha512",
  "sha3-256": "sha3-256",
  "sha3-512": "sha3-512",
});

// Defaults are PQC-first per the framework's hard rule §2 — operators
// who must interop with ES256-only verifiers today opt in via the
// `compatibilityProfile: "spec-default"` shape on the issuer/holder
// surfaces, OR pass `algorithm: "ES256"` + `hashAlg: "sha-256"`
// explicitly with an audited reason.
var DEFAULT_ALG = "ML-DSA-87";
var DEFAULT_HASH_ALG = "sha3-512";

function _b64uEncode(str) {
  return Buffer.from(str, "utf8").toString("base64url");
}

function _b64uEncodeBuf(buf) {
  return buf.toString("base64url");
}

function _b64uDecodeStr(s) {
  return Buffer.from(s, "base64url").toString("utf8");
}

function _b64uDecodeBuf(s) {
  return Buffer.from(s, "base64url");
}

function _hashDisclosure(disclosureStr, hashAlg) {
  var nodeAlg = SUPPORTED_HASH_ALGS[hashAlg];
  if (!nodeAlg) {
    throw new AuthError("auth-sd-jwt-vc/bad-hash",
      "Unsupported hash algorithm: " + hashAlg);
  }
  var h = nodeCrypto.createHash(nodeAlg);
  h.update(disclosureStr, "ascii");
  return h.digest().toString("base64url");
}

// JOSE/JWS — and EUDI wallets — require ECDSA signatures as raw r||s
// ("ieee-p1363"); node:crypto defaults to DER (ASN.1 SEQUENCE). Wrap the EC
// key so ES256/ES384 sign + verify emit/expect the JOSE encoding. Without it
// a token this library signs is rejected by every conformant verifier (and
// the library rejects their raw-r||s KB-JWTs). EdDSA / ML-DSA keys pass
// through unchanged. Mirrors oauth.js / dpop.js / jwt-external.js.
function _ecKeyParam(algorithm, key) {
  if (algorithm === "ES256" || algorithm === "ES384") {
    return { key: key, dsaEncoding: "ieee-p1363" };
  }
  return key;
}

function _signJwt(header, payload, privateKey, algorithm) {
  var headerStr = _b64uEncode(safeJson.stringify(header));
  var payloadStr = _b64uEncode(safeJson.stringify(payload));
  var signingInput = headerStr + "." + payloadStr;
  var sigAlgo = _resolveSigAlgo(algorithm);
  var sig = nodeCrypto.sign(sigAlgo, Buffer.from(signingInput, "ascii"), _ecKeyParam(algorithm, privateKey));
  return signingInput + "." + sig.toString("base64url");
}

function _verifyJwt(token, publicKey, algorithm) {
  var parts = token.split(".");
  if (parts.length !== 3) {
    throw new AuthError("auth-sd-jwt-vc/malformed-jwt",
      "JWT must have 3 dot-separated parts");
  }
  var signingInput = parts[0] + "." + parts[1];
  var sig = _b64uDecodeBuf(parts[2]);
  var sigAlgo = _resolveSigAlgo(algorithm);
  var ok = nodeCrypto.verify(sigAlgo, Buffer.from(signingInput, "ascii"), _ecKeyParam(algorithm, publicKey), sig);
  if (!ok) {
    throw new AuthError("auth-sd-jwt-vc/bad-signature",
      "JWT signature verification failed");
  }
  var headerStr = _b64uDecodeStr(parts[0]);
  var payloadStr = _b64uDecodeStr(parts[1]);
  return {
    header:  safeJson.parse(headerStr, { maxBytes: 64 * 1024 }),                    // allow:bare-json-parse — header from cryptographically-verified JWT; signature verifies the bytes // allow:raw-byte-literal — JWT header cap (64 KB)
    payload: safeJson.parse(payloadStr, { maxBytes: 1024 * 1024 }),                 // allow:bare-json-parse — payload from cryptographically-verified JWT; signature verifies the bytes // allow:raw-byte-literal — JWT payload cap (1 MB)
  };
}

function _resolveSigAlgo(algorithm) {
  // Node 24+ accepts these algorithm hints; ES256 / ES384 use the
  // EC private key's curve to dispatch. EdDSA + ML-DSA-* are
  // signature-algorithm hints handled directly by Node.js crypto.
  switch (algorithm) {
    case "ES256":      return "sha256";
    case "ES384":      return "sha384";
    case "EdDSA":      return null;       // pass-through, Node infers
    case "ML-DSA-87":  return null;
    case "ML-DSA-65":  return null;
    default:
      throw new AuthError("auth-sd-jwt-vc/unsupported-alg",
        "Unsupported algorithm: " + algorithm);
  }
}

// ---- issue ----

function issue(opts) {
  validateOpts.requireObject(opts, "auth.sdJwtVc.issue", AuthError);
  validateOpts(opts, [
    "issuer", "subject", "vct", "claims",
    "selectivelyDisclosed", "issuerKey", "algorithm",
    "hashAlg", "ttlMs", "issuedAt",
    "holderKey", "extraHeader",
  ], "auth.sdJwtVc.issue");

  validateOpts.requireNonEmptyString(opts.issuer,
    "issue: issuer", AuthError, "auth-sd-jwt-vc/bad-opts");
  validateOpts.requireNonEmptyString(opts.vct,
    "issue: vct", AuthError, "auth-sd-jwt-vc/bad-opts");
  if (!opts.claims || typeof opts.claims !== "object" || Array.isArray(opts.claims)) {
    throw new AuthError("auth-sd-jwt-vc/bad-opts",
      "issue: claims must be a plain object");
  }

  var algorithm = opts.algorithm || DEFAULT_ALG;
  if (SUPPORTED_ALGS.indexOf(algorithm) === -1) {
    throw new AuthError("auth-sd-jwt-vc/unsupported-alg",
      "issue: algorithm must be one of " + SUPPORTED_ALGS.join(", "));
  }
  var hashAlg = opts.hashAlg || DEFAULT_HASH_ALG;
  if (!SUPPORTED_HASH_ALGS[hashAlg]) {
    throw new AuthError("auth-sd-jwt-vc/bad-hash",
      "issue: hashAlg must be one of " + Object.keys(SUPPORTED_HASH_ALGS).join(", "));
  }

  if (!opts.issuerKey) {
    throw new AuthError("auth-sd-jwt-vc/no-key", "issue: issuerKey required");
  }

  var sdNames = Array.isArray(opts.selectivelyDisclosed)
    ? opts.selectivelyDisclosed.slice() : [];
  var unknownSdNames = sdNames.filter(function (n) {
    return !(n in opts.claims);
  });
  if (unknownSdNames.length > 0) {
    throw new AuthError("auth-sd-jwt-vc/unknown-claim",
      "issue: selectivelyDisclosed includes claim(s) not present in claims: " +
      unknownSdNames.join(", "));
  }

  // Build disclosures + digest array
  var disclosures = [];
  var sdDigests = [];
  var plainClaims = {};
  var allClaimNames = Object.keys(opts.claims);
  for (var i = 0; i < allClaimNames.length; i++) {
    var name = allClaimNames[i];
    var value = opts.claims[name];
    if (sdNames.indexOf(name) !== -1) {
      var d = disclosure.encode(name, value);
      disclosures.push(d);
      sdDigests.push(_hashDisclosure(d, hashAlg));
    } else {
      plainClaims[name] = value;
    }
  }
  // Spec: shuffle digests so order doesn't leak claim order
  sdDigests.sort();

  var now = (typeof opts.issuedAt === "number" && isFinite(opts.issuedAt))
    ? Math.floor(opts.issuedAt / 1000) : Math.floor(Date.now() / 1000);             // ms→s conversion factor
  var ttlSec = opts.ttlMs ? Math.floor(opts.ttlMs / 1000) : 30 * 24 * 60 * 60;       // ms→s conversion + 30-day default in seconds

  var payload = Object.assign({}, plainClaims, {
    iss:       opts.issuer,
    iat:       now,
    exp:       now + ttlSec,
    vct:       opts.vct,
    _sd:       sdDigests,
    _sd_alg:   hashAlg,
  });
  if (opts.subject) payload.sub = opts.subject;
  if (opts.holderKey) {
    // Holder binding via cnf claim per draft §4.2.2
    if (typeof opts.holderKey !== "object" || !opts.holderKey.kty) {
      throw new AuthError("auth-sd-jwt-vc/bad-cnf",
        "issue: holderKey must be a JWK with kty");
    }
    payload.cnf = { jwk: opts.holderKey };
  }
  var header = Object.assign({}, opts.extraHeader || {}, {
    alg: algorithm,
    typ: "vc+sd-jwt",
  });

  var jwt = _signJwt(header, payload, opts.issuerKey, algorithm);
  var token = jwt + "~" + disclosures.join("~") + "~";
  return {
    token:        token,
    jwt:          jwt,
    disclosures:  disclosures,
    payload:      payload,
    header:       header,
  };
}

// ---- present (holder side) ----

function present(opts) {
  validateOpts.requireObject(opts, "auth.sdJwtVc.present", AuthError);
  validateOpts(opts, [
    "sdJwt", "disclosedClaimNames", "audience",
    "nonce", "holderKey", "algorithm", "issuedAt",
    "keyAttestation",
  ], "auth.sdJwtVc.present");

  validateOpts.requireNonEmptyString(opts.sdJwt,
    "present: sdJwt", AuthError, "auth-sd-jwt-vc/no-token");
  var parts = opts.sdJwt.split("~");
  if (parts.length < 2) {
    throw new AuthError("auth-sd-jwt-vc/malformed",
      "present: sdJwt must contain at least one ~-separator");
  }
  var jwt = parts[0];
  var allDisclosures = parts.slice(1).filter(function (p) { return p.length > 0; });

  // Decode the issuer JWT payload to read its declared `_sd_alg` —
  // KB-JWT `sd_hash` MUST be computed with the SAME hash algorithm
  // the credential's `_sd` digests use (IETF SD-JWT draft §4.1.1).
  // Hardcoded sha256 here previously diverged from the verifier when
  // an issuer used a non-default hash, producing sd-hash-mismatch on
  // valid presentations.
  //
  // Defense-in-depth: this pre-parse runs on the holder side
  // (presentation builder) and reads `_sd_alg` from UNSIGNED bytes,
  // because the holder needs to know which hash to use BEFORE the
  // verifier sees the presentation. The presentation itself carries
  // the JWS-signed issuer JWT verbatim; verify() re-parses the
  // payload from the cryptographically-verified signing input. That
  // post-verify decode is the source of truth — a holder who tampers
  // with `_sd_alg` here only breaks their own KB-JWT digest, since
  // the verifier recomputes from the signed bytes. No security
  // boundary is crossed by reading the value here.
  var _issuerPayload = null;
  var _jwtParts = jwt.split(".");
  if (_jwtParts.length === 3) {
    try {
      _issuerPayload = safeJson.parse(_b64uDecodeStr(_jwtParts[1]),
        { maxBytes: 64 * 1024 });                                                                  // allow:bare-json-parse — payload only read to pull _sd_alg; final auth happens in verify() // allow:raw-byte-literal — JWT payload cap (64 KB)
    } catch (_e) { _issuerPayload = null; }
  }
  var _sdAlg = (_issuerPayload && typeof _issuerPayload._sd_alg === "string")
    ? _issuerPayload._sd_alg : "sha-256";
  var _sdNodeHash = SUPPORTED_HASH_ALGS[_sdAlg];
  if (!_sdNodeHash) {
    throw new AuthError("auth-sd-jwt-vc/bad-hash",
      "present: issuer credential declares _sd_alg \"" + _sdAlg +
      "\" which this framework version does not support");
  }

  var disclosedNames = Array.isArray(opts.disclosedClaimNames)
    ? opts.disclosedClaimNames.slice() : [];
  var releasedDisclosures = [];
  for (var i = 0; i < allDisclosures.length; i++) {
    try {
      var decoded = disclosure.decode(allDisclosures[i]);
      if (decoded && disclosedNames.indexOf(decoded.name) !== -1) {
        releasedDisclosures.push(allDisclosures[i]);
      }
    } catch (_e) { /* malformed — skip */ }
  }

  // Build presentation
  var presentation = jwt + "~";
  if (releasedDisclosures.length > 0) {
    presentation += releasedDisclosures.join("~") + "~";
  }

  // Optional Key Binding JWT
  if (opts.audience && opts.nonce && opts.holderKey) {
    var algorithm = opts.algorithm || DEFAULT_ALG;
    if (SUPPORTED_ALGS.indexOf(algorithm) === -1) {
      throw new AuthError("auth-sd-jwt-vc/unsupported-alg",
        "present: algorithm must be one of " + SUPPORTED_ALGS.join(", "));
    }
    var now = (typeof opts.issuedAt === "number" && isFinite(opts.issuedAt))
      ? Math.floor(opts.issuedAt / 1000) : Math.floor(Date.now() / 1000);           // ms→s conversion factor
    // The KB-JWT's hash binds it to the specific SD-JWT + presentation
    var kbHashInput = presentation;     // jwt~d1~d2~ (without KB)
    // sd_hash uses the SAME hash algorithm the credential's _sd
    // digests use (computed at top of present() from issuer payload).
    // Matches the verifier's expectation in lib/auth/sd-jwt-vc.js
    // verify() — both ends MUST agree on the algorithm.
    var sdHash = nodeCrypto.createHash(_sdNodeHash)
                           .update(kbHashInput, "ascii")
                           .digest()
                           .toString("base64url");
    var kbPayload = {
      nonce:    opts.nonce,
      aud:      opts.audience,
      iat:      now,
      sd_hash:  sdHash,
    };
    var kbHeader = { alg: algorithm, typ: "kb+jwt" };
    if (typeof opts.keyAttestation === "string" && opts.keyAttestation.length > 0) {
      // OpenID4VCI key-attestation extension. The attestation JWT
      // travels in the KB-JWT header so a verifier with no extra
      // round-trip can validate the holder-key provenance (TEE /
      // hardware-backed key) alongside the cnf-bound key-binding
      // signature. Operators wanting per-presentation freshness
      // mint a new attestation per audience+nonce on the holder
      // device and pass it via opts.keyAttestation.
      kbHeader.key_attestation = opts.keyAttestation;
    }
    var kbJwt = _signJwt(kbHeader, kbPayload, opts.holderKey, algorithm);
    presentation += kbJwt;
  }

  return {
    presentation: presentation,
    jwt:          jwt,
    disclosures:  releasedDisclosures,
  };
}

// ---- verify ----

async function verify(presentation, opts) {
  validateOpts.requireObject(opts, "auth.sdJwtVc.verify", AuthError);
  validateOpts(opts, [
    "issuerKeyResolver", "audience", "nonce",
    "now", "expectedVct", "maxClockSkewSec",
    "requireKeyBinding",
    "keyAttestationVerifier", "requireKeyAttestation",
  ], "auth.sdJwtVc.verify");

  if (typeof presentation !== "string" || presentation.length === 0) {
    throw new AuthError("auth-sd-jwt-vc/no-token",
      "verify: presentation must be a non-empty string");
  }
  if (typeof opts.issuerKeyResolver !== "function") {
    throw new AuthError("auth-sd-jwt-vc/no-resolver",
      "verify: issuerKeyResolver must be an async function");
  }
  var parts = presentation.split("~");
  if (parts.length < 2) {
    throw new AuthError("auth-sd-jwt-vc/malformed",
      "verify: presentation must contain at least one ~-separator");
  }
  var jwt = parts[0];
  // Last part is empty (trailing ~) or KB-JWT (3-dot-separated)
  var maybeKbJwt = null;
  var lastPart = parts[parts.length - 1];
  if (lastPart && lastPart.split(".").length === 3) {
    maybeKbJwt = lastPart;
  }
  var disclosureParts = parts.slice(1, parts.length - (maybeKbJwt ? 1 : 0))
                             .filter(function (p) { return p.length > 0; });

  // 1. Verify issuer JWT signature
  var jwtParts = jwt.split(".");
  if (jwtParts.length !== 3) {
    throw new AuthError("auth-sd-jwt-vc/malformed-jwt",
      "verify: JWT must have 3 dot-separated parts");
  }
  var headerObj;
  try { headerObj = safeJson.parse(_b64uDecodeStr(jwtParts[0]), { maxBytes: 64 * 1024 }); }  // allow:bare-json-parse — pre-verify header parse to look up the key resolver; checked again post-signature // allow:raw-byte-literal — JWT header cap (64 KB)
  catch (e) {
    throw new AuthError("auth-sd-jwt-vc/bad-header",
      "verify: malformed JWT header: " + e.message);
  }
  var alg = headerObj.alg;
  // Alg-allowlist gate (CWE-347 / CWE-757) — refuse unknown / unsupported
  // alg BEFORE any key resolution. The shared `_assertAlgKtyMatch` helper repeats this
  // check after the issuer key is resolved; doing it here too closes
  // the gap where an issuerKeyResolver with side effects (network
  // fetch, audit emit) would run even when the alg is unsupported.
  if (typeof alg !== "string" || SUPPORTED_ALGS.indexOf(alg) === -1) {
    throw new AuthError("auth-sd-jwt-vc/unsupported-alg",
      "verify: header alg \"" + alg + "\" not in supported set " +
      "(alg-allowlist gate — refused before key lookup)");
  }
  // draft-ietf-oauth-sd-jwt-vc §3.1 — typ MUST be `vc+sd-jwt` (or
  // `dc+sd-jwt` for digital-credential profile). Pre-v0.9.x the absent-
  // typ short-circuit accepted any token without typ, contradicting
  // the spec MUST. Refuse absent typ; drop the legacy JWT allowance —
  // verifyExternal handles generic JWT, sd-jwt-vc handles only the
  // typ'd shape.
  var typ = headerObj.typ;
  if (typeof typ !== "string" || (typ !== "vc+sd-jwt" && typ !== "dc+sd-jwt")) {
    throw new AuthError("auth-sd-jwt-vc/bad-typ",
      "verify: header typ must be \"vc+sd-jwt\" or \"dc+sd-jwt\" (got " +
      (typ === undefined ? "<absent>" : "\"" + typ + "\"") +
      ") — draft-ietf-oauth-sd-jwt-vc §3.1 MUST");
  }
  // RFC 7515 §4.1.11 — refuse non-empty `crit` header. Every other
  // verifier in the framework refuses critical extensions; sd-jwt-vc
  // previously silently ignored, letting an attacker-controlled issuer
  // declare critical extensions the verifier doesn't understand.
  if (headerObj.crit !== undefined && headerObj.crit !== null) {
    if (!Array.isArray(headerObj.crit) || headerObj.crit.length > 0) {
      throw new AuthError("auth-sd-jwt-vc/unknown-crit",
        "verify: header carries 'crit' extension list — sd-jwt-vc does not " +
        "support any critical extensions and refuses per RFC 7515 §4.1.11");
    }
  }

  var issuerKey = await opts.issuerKeyResolver(headerObj);
  if (!issuerKey) {
    throw new AuthError("auth-sd-jwt-vc/key-not-found",
      "verify: issuerKeyResolver returned no key");
  }
  // CVE-2026-22817 — when issuerKeyResolver returns a JWK object,
  // cross-check the issuer JWS alg/kty BEFORE handing it to
  // node:crypto.verify. KeyObject / PEM shapes can't surface kty, so this
  // guard only fires when the resolver hands back a JWK (the common path).
  // The holder KB-JWT path applies its OWN _assertAlgKtyMatch against the
  // cnf.jwk below — note that the holder key is issuer-ATTESTED (it comes
  // from the cryptographically-verified issuer payload's cnf claim), not
  // header-resolved, so the two cross-checks defend different trust edges.
  if (typeof issuerKey === "object" &&
      !(issuerKey instanceof nodeCrypto.KeyObject) &&
      !Buffer.isBuffer(issuerKey) &&
      typeof issuerKey.kty === "string") {
    jwtExternal._assertAlgKtyMatch(alg, issuerKey);
  }
  var jwtParsed = _verifyJwt(jwt, issuerKey, alg);
  // Post-verify header compare. Pre-verify we parsed the
  // header bytes to look up the key; _verifyJwt parses again from the
  // cryptographically-verified signing input. Both decodes MUST yield
  // the same JSON; a mismatch indicates a JWS-canonicalization or
  // duplicate-key issue and refuses defense-in-depth.
  if (safeJson.stringify(headerObj) !== safeJson.stringify(jwtParsed.header)) {
    throw new AuthError("auth-sd-jwt-vc/header-roundtrip-mismatch",
      "verify: pre-verify header bytes do not round-trip equal to post-verify " +
      "header bytes — refusing potential JWS canonicalization smuggle");
  }

  // 2. Validate iss / iat / exp / vct
  var nowSec = (typeof opts.now === "number" && isFinite(opts.now))
    ? Math.floor(opts.now / 1000) : Math.floor(Date.now() / 1000);                  // ms→s conversion factor
  var skew = (typeof opts.maxClockSkewSec === "number") ? opts.maxClockSkewSec : 60; // allow:raw-time-literal — default 60s clock-skew tolerance
  if (typeof jwtParsed.payload.iat === "number" && jwtParsed.payload.iat > nowSec + skew) {
    throw new AuthError("auth-sd-jwt-vc/iat-future",
      "verify: iat is in the future (clock skew?)");
  }
  if (typeof jwtParsed.payload.exp === "number" && jwtParsed.payload.exp < nowSec - skew) {
    throw new AuthError("auth-sd-jwt-vc/expired",
      "verify: token is expired");
  }
  if (opts.expectedVct && jwtParsed.payload.vct !== opts.expectedVct) {
    throw new AuthError("auth-sd-jwt-vc/wrong-vct",
      "verify: vct mismatch (got \"" + jwtParsed.payload.vct +
      "\", expected \"" + opts.expectedVct + "\")");
  }
  // CVE-2026-23552 — optional explicit iss check with constant-time
  // compare. Operators with a known-issuer trust scope pass
  // `opts.expectedIssuer`; absence preserves the existing
  // issuerKeyResolver-only trust model.
  if (opts.expectedIssuer) {
    if (typeof jwtParsed.payload.iss !== "string" ||
        !jwtExternal._issuerMatches(jwtParsed.payload.iss, opts.expectedIssuer)) {
      throw new AuthError("auth-sd-jwt-vc/iss-mismatch",
        "verify: iss '" + jwtParsed.payload.iss + "' does not match expected '" +
        opts.expectedIssuer + "' (CVE-2026-23552 — cross-realm refused)");
    }
  }

  // 3. Reconstruct disclosed claims from disclosures
  // IETF SD-JWT default `_sd_alg` is `sha-256` (draft-ietf-oauth-
  // selective-disclosure-jwt §4.1.1). Earlier the framework defaulted
  // to its own DEFAULT_HASH_ALG (`sha3-512`) which broke verification
  // against spec-conformant issuers when `_sd_alg` was omitted.
  var hashAlg = jwtParsed.payload._sd_alg || "sha-256";
  if (!SUPPORTED_HASH_ALGS[hashAlg]) {
    throw new AuthError("auth-sd-jwt-vc/bad-hash",
      "verify: _sd_alg \"" + hashAlg + "\" not supported");
  }
  var sdDigests = Array.isArray(jwtParsed.payload._sd) ? jwtParsed.payload._sd : [];
  // Protected-claim refusal: a holder-supplied disclosure with one
  // of these names would shadow the issuer-signed payload claim when
  // merged into the resolved set. Spec-protected per draft §5
  // (the issuer-signed claims are authoritative).
  var PROTECTED_CLAIM_NAMES = {
    iss: 1, sub: 1, aud: 1, iat: 1, nbf: 1, exp: 1, jti: 1,
    vct: 1, cnf: 1, _sd: 1, _sd_alg: 1, status: 1,
  };
  var seenDigests = Object.create(null);
  var disclosedClaims = {};
  for (var i = 0; i < disclosureParts.length; i++) {
    var d = disclosure.decode(disclosureParts[i]);
    if (!d) continue;
    var digest = _hashDisclosure(disclosureParts[i], hashAlg);
    if (sdDigests.indexOf(digest) === -1) {
      throw new AuthError("auth-sd-jwt-vc/disclosure-mismatch",
        "verify: disclosure for claim \"" + d.name + "\" does not match any _sd digest");
    }
    // Disclosure-replay defense — a holder presenting the same _sd
    // digest twice (with the same or different values) is malformed
    // per spec and is the shape of a partial-disclosure smuggling
    // attack. Refuse on duplicate digest.
    if (seenDigests[digest]) {
      throw new AuthError("auth-sd-jwt-vc/disclosure-replay",
        "verify: disclosure digest \"" + digest.slice(0, 12) +
        "...\" appears twice — refusing replayed disclosure");
    }
    seenDigests[digest] = true;
    // Claim-shadowing defense — refuse holder-supplied disclosures
    // whose name collides with an issuer-signed top-level claim.
    if (PROTECTED_CLAIM_NAMES[d.name]) {
      throw new AuthError("auth-sd-jwt-vc/protected-claim-shadow",
        "verify: disclosure for claim \"" + d.name + "\" would shadow a " +
        "spec-protected issuer-signed claim — refused");
    }
    disclosedClaims[d.name] = d.value;
  }

  // 4. Optionally verify Key Binding JWT
  var kbValidated = false;
  var holderKey = null;
  var keyAttestationClaims = null;
  if (jwtParsed.payload.cnf && jwtParsed.payload.cnf.jwk) {
    holderKey = jwtParsed.payload.cnf.jwk;
  }
  if (maybeKbJwt) {
    if (!holderKey) {
      throw new AuthError("auth-sd-jwt-vc/no-cnf",
        "verify: KB-JWT present but issuer payload has no cnf.jwk");
    }
    // Verify KB-JWT signature
    var kbHeaderObj;
    try { kbHeaderObj = safeJson.parse(_b64uDecodeStr(maybeKbJwt.split(".")[0]), { maxBytes: 4096 }); }  // allow:bare-json-parse — kb header from validated KB-JWT; signature verifies
    catch (e) {
      throw new AuthError("auth-sd-jwt-vc/bad-kb-header",
        "verify: malformed KB-JWT header: " + e.message);
    }
    if (kbHeaderObj.typ !== "kb+jwt") {
      throw new AuthError("auth-sd-jwt-vc/bad-kb-typ",
        "verify: KB-JWT typ must be \"kb+jwt\"");
    }
    var kbAlg = kbHeaderObj.alg;
    if (SUPPORTED_ALGS.indexOf(kbAlg) === -1) {
      throw new AuthError("auth-sd-jwt-vc/unsupported-alg",
        "verify: KB-JWT alg unsupported");
    }
    // CVE-2026-22817 — cross-check the KB-JWT header alg against the holder
    // key type BEFORE importing the key / verifying. The issuer path does
    // this for issuerKey (above); the holder KB-JWT path must too. The
    // KB-JWT header alg is attacker-controllable (the holder mints the
    // KB-JWT), and holderKey is a cnf.jwk with a kty, so an alg/kty
    // mismatch (e.g. a header claiming EdDSA against an EC cnf key) is
    // refused with the precise alg-mismatch error rather than handed to
    // node:crypto.verify.
    jwtExternal._assertAlgKtyMatch(kbAlg, holderKey);
    var holderKeyObj = bCrypto.importPublicJwk(holderKey);
    var kbParsed = _verifyJwt(maybeKbJwt, holderKeyObj, kbAlg);
    // Constant-time compares: the nonce is a verifier-issued replay-defense
    // value, so a short-circuiting !== leaks a matching-prefix timing oracle.
    // Matches the sd_hash check below (the framework's hash/token discipline).
    if (opts.audience && !_timingSafeEqStr(kbParsed.payload.aud, opts.audience)) {
      throw new AuthError("auth-sd-jwt-vc/wrong-audience",
        "verify: KB-JWT aud mismatch");
    }
    if (opts.nonce && !_timingSafeEqStr(kbParsed.payload.nonce, opts.nonce)) {
      throw new AuthError("auth-sd-jwt-vc/wrong-nonce",
        "verify: KB-JWT nonce mismatch (replay defense)");
    }
    // Validate KB-JWT sd_hash matches the presentation, using the
    // credential's declared `_sd_alg`.
    var kbHashInput = jwt + "~";
    if (disclosureParts.length > 0) kbHashInput += disclosureParts.join("~") + "~";
    var kbNodeHash = SUPPORTED_HASH_ALGS[hashAlg];
    var expectedSdHash = nodeCrypto.createHash(kbNodeHash)
                                   .update(kbHashInput, "ascii")
                                   .digest()
                                   .toString("base64url");
    // Constant-time compare on the sd_hash (both fixed-width
    // base64url(SHA-*) strings; defense-in-depth even though the
    // hash is itself the integrity binding).
    if (!_timingSafeEqStr(kbParsed.payload.sd_hash, expectedSdHash)) {
      throw new AuthError("auth-sd-jwt-vc/sd-hash-mismatch",
        "verify: KB-JWT sd_hash does not match the presentation hash (presentation tampered with?)");
    }
    if (typeof kbParsed.payload.iat === "number" && kbParsed.payload.iat > nowSec + skew) {
      throw new AuthError("auth-sd-jwt-vc/kb-iat-future",
        "verify: KB-JWT iat is in the future");
    }
    kbValidated = true;

    // OpenID4VCI key-attestation extension: the holder may include
    // a key_attestation JWT in the KB-JWT header. The framework
    // surfaces it for the operator-supplied verifier callback so
    // policy decisions about TEE provenance / hardware-backed-key
    // requirement / app-attest origin / FIDO MDS3 anchor stay in
    // the operator's hands. The framework does NOT trust-anchor
    // resolve attestation issuers itself — the operator's
    // verifier picks the right anchor for the use case.
    if (typeof kbHeaderObj.key_attestation === "string" &&
        kbHeaderObj.key_attestation.length > 0) {
      if (typeof opts.keyAttestationVerifier !== "function") {
        if (opts.requireKeyAttestation === true) {
          throw new AuthError("auth-sd-jwt-vc/no-attestation-verifier",
            "verify: requireKeyAttestation=true but no keyAttestationVerifier supplied");
        }
        // No verifier — surface the raw token and let the caller
        // skip; we don't trust an attestation we can't verify.
      } else {
        try {
          keyAttestationClaims = await opts.keyAttestationVerifier({
            jwt:        kbHeaderObj.key_attestation,
            holderKey:  holderKey,
            audience:   opts.audience || null,
            nonce:      opts.nonce || null,
          });
        } catch (e) {
          throw new AuthError("auth-sd-jwt-vc/attestation-verify-failed",
            "verify: keyAttestationVerifier rejected the attestation: " +
            ((e && e.message) || String(e)));
        }
        if (!keyAttestationClaims || typeof keyAttestationClaims !== "object") {
          throw new AuthError("auth-sd-jwt-vc/attestation-empty",
            "verify: keyAttestationVerifier returned no claims (must return the verified attestation payload)");
        }
      }
    } else if (opts.requireKeyAttestation === true) {
      throw new AuthError("auth-sd-jwt-vc/missing-key-attestation",
        "verify: requireKeyAttestation=true but KB-JWT carries no key_attestation header");
    }
  } else if (opts.requireKeyBinding) {
    throw new AuthError("auth-sd-jwt-vc/missing-kb",
      "verify: KB-JWT required (requireKeyBinding=true) but not present");
  }

  // 5. Build the resolved-claim set (issuer claims + disclosed)
  var resolved = Object.assign({}, jwtParsed.payload);
  delete resolved._sd;
  delete resolved._sd_alg;
  Object.keys(disclosedClaims).forEach(function (k) {
    resolved[k] = disclosedClaims[k];
  });

  return {
    valid:                 true,
    claims:                resolved,
    disclosedClaims:       disclosedClaims,
    issuerHeader:          jwtParsed.header,
    issuerPayload:         jwtParsed.payload,
    holderKey:             holderKey,
    kbValidated:           kbValidated,
    keyAttestationClaims:  keyAttestationClaims,
  };
}

module.exports = {
  issue:               issue,
  present:             present,
  verify:              verify,
  disclosure:          disclosure,
  issuer:              sdJwtVcIssuer,
  holder:              sdJwtVcHolder,
  SUPPORTED_ALGS:      SUPPORTED_ALGS,
  SUPPORTED_HASH_ALGS: Object.freeze(Object.keys(SUPPORTED_HASH_ALGS)),
  DEFAULT_ALG:         DEFAULT_ALG,
  DEFAULT_HASH_ALG:    DEFAULT_HASH_ALG,
  // Test hooks
  _hashDisclosure:     _hashDisclosure,
  // unused-token tag so safeBuffer module isn't dropped from the
  // bundle — we keep it imported for future signature-input bound checks.
  _safeBufferRef:      safeBuffer,
};
