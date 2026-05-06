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
var safeBuffer = require("../safe-buffer");
var safeJson = require("../safe-json");
var validateOpts = require("../validate-opts");
var disclosure = require("./sd-jwt-vc-disclosure");
var sdJwtVcIssuer = require("./sd-jwt-vc-issuer");
var sdJwtVcHolder = require("./sd-jwt-vc-holder");
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

function _signJwt(header, payload, privateKey, algorithm) {
  var headerStr = _b64uEncode(safeJson.stringify(header));
  var payloadStr = _b64uEncode(safeJson.stringify(payload));
  var signingInput = headerStr + "." + payloadStr;
  var sigAlgo = _resolveSigAlgo(algorithm);
  var sig = nodeCrypto.sign(sigAlgo, Buffer.from(signingInput, "ascii"), privateKey);
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
  var ok = nodeCrypto.verify(sigAlgo, Buffer.from(signingInput, "ascii"), publicKey, sig);
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
    ? Math.floor(opts.issuedAt / 1000) : Math.floor(Date.now() / 1000);             // allow:raw-byte-literal — ms→s conversion factor
  var ttlSec = opts.ttlMs ? Math.floor(opts.ttlMs / 1000) : 30 * 24 * 60 * 60;       // allow:raw-byte-literal — ms→s conversion + 30-day default in seconds

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

  // Decode disclosures + filter by name
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
      ? Math.floor(opts.issuedAt / 1000) : Math.floor(Date.now() / 1000);           // allow:raw-byte-literal — ms→s conversion factor
    // The KB-JWT's hash binds it to the specific SD-JWT + presentation
    var kbHashInput = presentation;     // jwt~d1~d2~ (without KB)
    var sdHash = nodeCrypto.createHash("sha256")
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
  if (SUPPORTED_ALGS.indexOf(alg) === -1) {
    throw new AuthError("auth-sd-jwt-vc/unsupported-alg",
      "verify: header alg \"" + alg + "\" not in supported set");
  }
  var typ = headerObj.typ;
  if (typ && typ !== "vc+sd-jwt" && typ !== "JWT") {
    throw new AuthError("auth-sd-jwt-vc/bad-typ",
      "verify: header typ must be \"vc+sd-jwt\" (got \"" + typ + "\")");
  }

  var issuerKey = await opts.issuerKeyResolver(headerObj);
  if (!issuerKey) {
    throw new AuthError("auth-sd-jwt-vc/key-not-found",
      "verify: issuerKeyResolver returned no key");
  }
  var jwtParsed = _verifyJwt(jwt, issuerKey, alg);

  // 2. Validate iss / iat / exp / vct
  var nowSec = (typeof opts.now === "number" && isFinite(opts.now))
    ? Math.floor(opts.now / 1000) : Math.floor(Date.now() / 1000);                  // allow:raw-byte-literal — ms→s conversion factor
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

  // 3. Reconstruct disclosed claims from disclosures
  var hashAlg = jwtParsed.payload._sd_alg || DEFAULT_HASH_ALG;
  if (!SUPPORTED_HASH_ALGS[hashAlg]) {
    throw new AuthError("auth-sd-jwt-vc/bad-hash",
      "verify: _sd_alg \"" + hashAlg + "\" not supported");
  }
  var sdDigests = Array.isArray(jwtParsed.payload._sd) ? jwtParsed.payload._sd : [];
  var disclosedClaims = {};
  for (var i = 0; i < disclosureParts.length; i++) {
    var d = disclosure.decode(disclosureParts[i]);
    if (!d) continue;
    var digest = _hashDisclosure(disclosureParts[i], hashAlg);
    if (sdDigests.indexOf(digest) === -1) {
      throw new AuthError("auth-sd-jwt-vc/disclosure-mismatch",
        "verify: disclosure for claim \"" + d.name + "\" does not match any _sd digest");
    }
    disclosedClaims[d.name] = d.value;
  }

  // 4. Optionally verify Key Binding JWT
  var kbValidated = false;
  var holderKey = null;
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
    try { kbHeaderObj = safeJson.parse(_b64uDecodeStr(maybeKbJwt.split(".")[0]), { maxBytes: 4096 }); }  // allow:bare-json-parse — kb header from validated KB-JWT; signature verifies // allow:raw-byte-literal — kb-header cap (4 KB)
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
    var holderKeyObj = nodeCrypto.createPublicKey({ key: holderKey, format: "jwk" });
    var kbParsed = _verifyJwt(maybeKbJwt, holderKeyObj, kbAlg);
    if (opts.audience && kbParsed.payload.aud !== opts.audience) {
      throw new AuthError("auth-sd-jwt-vc/wrong-audience",
        "verify: KB-JWT aud mismatch");
    }
    if (opts.nonce && kbParsed.payload.nonce !== opts.nonce) {
      throw new AuthError("auth-sd-jwt-vc/wrong-nonce",
        "verify: KB-JWT nonce mismatch (replay defense)");
    }
    // Validate KB-JWT sd_hash matches the presentation
    var kbHashInput = jwt + "~";
    if (disclosureParts.length > 0) kbHashInput += disclosureParts.join("~") + "~";
    var expectedSdHash = nodeCrypto.createHash("sha256")
                                   .update(kbHashInput, "ascii")
                                   .digest()
                                   .toString("base64url");
    if (kbParsed.payload.sd_hash !== expectedSdHash) {
      throw new AuthError("auth-sd-jwt-vc/sd-hash-mismatch",
        "verify: KB-JWT sd_hash does not match the presentation hash (presentation tampered with?)");
    }
    if (typeof kbParsed.payload.iat === "number" && kbParsed.payload.iat > nowSec + skew) {
      throw new AuthError("auth-sd-jwt-vc/kb-iat-future",
        "verify: KB-JWT iat is in the future");
    }
    kbValidated = true;
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
    valid:           true,
    claims:          resolved,
    disclosedClaims: disclosedClaims,
    issuerHeader:    jwtParsed.header,
    issuerPayload:   jwtParsed.payload,
    holderKey:       holderKey,
    kbValidated:     kbValidated,
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
