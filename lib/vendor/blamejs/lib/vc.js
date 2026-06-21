"use strict";
/**
 * @module b.vc
 * @nav    Crypto
 * @title  Verifiable Credentials (W3C VCDM 2.0)
 *
 * @intro
 *   Issue and verify W3C Verifiable Credentials (VC Data Model 2.0, a
 *   W3C Recommendation) secured per "Securing Verifiable Credentials
 *   using JOSE and COSE" (VC-JOSE-COSE, also a W3C Recommendation). A
 *   verifiable credential is a tamper-evident, cryptographically-signed
 *   set of claims an issuer makes about a subject — a diploma, a
 *   membership, a license, an age assertion.
 *
 *   Two securing mechanisms are supported, both putting the credential
 *   itself (not a JWT/CWT claims wrapper) as the signed payload:
 *   <strong>JOSE</strong> produces a compact JWS with the <code>vc+jwt</code>
 *   media type (<code>typ</code> header <code>"vc+jwt"</code>), signed
 *   with the classical ES256 / 384 / 512 or EdDSA JOSE algorithms;
 *   <strong>COSE</strong> produces a COSE_Sign1 (<code>application/vc+cose</code>)
 *   over <code>b.cose</code>, adding ML-DSA-87 (PQC-forward) to that set.
 *   <code>b.vc.verify</code> auto-detects the form from the input (a
 *   compact-JWS string vs. COSE_Sign1 bytes).
 *
 *   <code>b.vc.issue(credential, opts)</code> validates the credential
 *   against the VCDM 2.0 structural rules (the <code>credentials/v2</code>
 *   context first, a <code>VerifiableCredential</code> type, an issuer,
 *   a credential subject) and signs it. <code>b.vc.verify(secured, opts)</code>
 *   verifies the signature (the algorithm allowlist is mandatory; the
 *   JOSE <code>none</code> algorithm is always refused), re-checks the
 *   structural rules, and enforces the <code>validFrom</code> /
 *   <code>validUntil</code> validity window. This is the W3C model and
 *   is distinct from the IETF SD-JWT VC at <code>b.auth.sdJwtVc</code>.
 *
 * @card
 *   W3C Verifiable Credentials 2.0 (VC-JOSE-COSE) — issue / verify a
 *   signed credential as a compact JWS (vc+jwt) or a COSE_Sign1
 *   (vc+cose), with VCDM structural + validity-window checks. Composes
 *   b.cose; the JOSE alg `none` is always refused.
 */

var nodeCrypto = require("node:crypto");
var cose = require("./cose");
var safeJson = require("./safe-json");
var validateOpts = require("./validate-opts");
var { defineClass } = require("./framework-error");

var VcError = defineClass("VcError", { alwaysPermanent: true });

var VCDM_V2_CONTEXT = "https://www.w3.org/ns/credentials/v2";
var JOSE_TYP = "vc+jwt";
var COSE_TYP = "application/vc+cose";
var COSE_CONTENT_TYPE = "application/vc";
var VP_JOSE_TYP = "vp+jwt";
var VP_COSE_TYP = "application/vp+cose";
var VP_COSE_CONTENT_TYPE = "application/vp";
var MAX_PRESENTATION_CREDENTIALS = 64;                 // bounded count of enveloped VCs per presentation
var ENVELOPED_VC_TYPE = "EnvelopedVerifiableCredential";
var HDR_COSE_TYP = 16;                                 // COSE "typ" header label (RFC 9596)

// JOSE signature algorithms (final RFC 7518 / 8037), mapped to node
// verify parameters. ECDSA uses the IEEE-P1363 fixed-width encoding JOSE
// mandates (not ASN.1 DER). There is no signing default — the caller
// names the algorithm, mirroring b.cose.
var JOSE_ALGS = {
  "ES256": { nodeHash: "sha256", dsaEncoding: "ieee-p1363" },
  "ES384": { nodeHash: "sha384", dsaEncoding: "ieee-p1363" },
  "ES512": { nodeHash: "sha512", dsaEncoding: "ieee-p1363" },
  "EdDSA": { nodeHash: null },
};

function _b64urlJson(obj) {
  return Buffer.from(JSON.stringify(obj), "utf8").toString("base64url");
}
function _toKey(key, kind) {
  if (key && typeof key === "object" && typeof key.asymmetricKeyType === "string") return key;
  try {
    return kind === "private" ? nodeCrypto.createPrivateKey(key) : nodeCrypto.createPublicKey(key);
  } catch (e) {
    throw new VcError("vc/bad-key", "vc: could not load " + kind + " key: " + ((e && e.message) || e));
  }
}

function _issuerId(cred) {
  if (typeof cred.issuer === "string") return cred.issuer;
  if (cred.issuer && typeof cred.issuer === "object" && typeof cred.issuer.id === "string") return cred.issuer.id;
  return undefined;
}

// VCDM 2.0 structural rules; temporal checks only on verify.
function _validateVcdm(cred, opts) {
  if (!cred || typeof cred !== "object" || Array.isArray(cred)) {
    throw new VcError("vc/bad-credential", "vc: credential must be a JSON object");
  }
  var ctx = cred["@context"];
  if (!Array.isArray(ctx) || ctx[0] !== VCDM_V2_CONTEXT) {
    throw new VcError("vc/bad-context",
      "vc: @context must be an array whose first element is '" + VCDM_V2_CONTEXT + "'");
  }
  var types = Array.isArray(cred.type) ? cred.type : [cred.type];
  if (types.indexOf("VerifiableCredential") === -1) {
    throw new VcError("vc/bad-type", "vc: type must include 'VerifiableCredential'");
  }
  if (_issuerId(cred) === undefined) {
    throw new VcError("vc/no-issuer", "vc: issuer is required (a URL string or an object with an id)");
  }
  if (cred.credentialSubject === undefined || cred.credentialSubject === null) {
    throw new VcError("vc/no-subject", "vc: credentialSubject is required");
  }
  // validFrom / validUntil, when present, MUST be valid XSD dateTimes
  // (VCDM 2.0 §4.9). A malformed value fails closed at both issue and
  // verify rather than silently skipping the window check.
  var vf = _parseValidityField(cred, "validFrom");
  var vu = _parseValidityField(cred, "validUntil");
  if (opts && opts.temporal) {
    var nowMs = opts.at.getTime();
    if (vf !== null && nowMs < vf) {
      throw new VcError("vc/not-yet-valid", "vc.verify: credential validFrom (" + cred.validFrom + ") is in the future");
    }
    if (vu !== null && nowMs > vu) {
      throw new VcError("vc/expired", "vc.verify: credential validUntil (" + cred.validUntil + ") has passed");
    }
  }
}

function _parseValidityField(cred, name) {
  if (cred[name] === undefined) return null;
  if (typeof cred[name] !== "string") {
    throw new VcError("vc/bad-validity", "vc: " + name + " must be an XSD dateTime string");
  }
  var ms = Date.parse(cred[name]);
  if (!isFinite(ms)) {
    throw new VcError("vc/bad-validity", "vc: " + name + " is not a valid dateTime: " + cred[name]);
  }
  return ms;
}

/**
 * @primitive b.vc.issue
 * @signature b.vc.issue(credential, opts)
 * @since     0.12.39
 * @status    experimental
 * @compliance gdpr, soc2
 * @related   b.vc.verify, b.cose.sign
 *
 * Validate a credential against the VCDM 2.0 structural rules and secure
 * it. <code>securing: "jose"</code> returns a compact JWS string (media
 * type <code>vc+jwt</code>) signed with an ES256/384/512 or EdDSA key;
 * <code>securing: "cose"</code> returns COSE_Sign1 bytes (media type
 * <code>application/vc+cose</code>) over <code>b.cose</code>, which also
 * accepts <code>"ML-DSA-87"</code>. The credential itself is the signed
 * payload — no JWT/CWT claims wrapper is added.
 *
 * @opts
 *   {
 *     securing:   string,   // "jose" (compact JWS) | "cose" (COSE_Sign1)
 *     alg:        string,   // JOSE: ES256/384/512 | EdDSA. COSE: + ML-DSA-87
 *     privateKey: object,   // matching KeyObject or PEM
 *     kid:        string,   // optional key id (header)
 *     cty:        string,   // optional JOSE cty (e.g. "vc")
 *   }
 *
 * @example
 *   var jws = await b.vc.issue(credential, { securing: "jose", alg: "ES256", privateKey: key });
 *   // → a compact JWS string with typ "vc+jwt"
 */
async function issue(credential, opts) {
  validateOpts.requireObject(opts, "vc.issue", VcError);
  validateOpts(opts, ["securing", "alg", "privateKey", "kid", "cty"], "vc.issue");
  _validateVcdm(credential, null);
  if (!opts.privateKey) throw new VcError("vc/no-key", "vc.issue: opts.privateKey is required");

  return _sign(credential, opts, JOSE_TYP, COSE_TYP, COSE_CONTENT_TYPE, "vc.issue");
}

// Secure a JSON document (credential or presentation) as a compact JWS
// (jose) or COSE_Sign1 (cose) with the given media-type headers. The
// document is the exact signed payload — no claims wrapper.
function _sign(doc, opts, joseTyp, coseTyp, coseContentType, fnName) {
  if (opts.securing === "cose") {
    var protectedHeaders = {};
    protectedHeaders[HDR_COSE_TYP] = coseTyp;
    return cose.sign(Buffer.from(JSON.stringify(doc), "utf8"), {
      alg:              opts.alg,
      privateKey:       opts.privateKey,
      kid:              opts.kid,
      contentType:      coseContentType,
      protectedHeaders: protectedHeaders,
    });
  }
  if (opts.securing === "jose") {
    var params = JOSE_ALGS[opts.alg];
    if (!params) {
      throw new VcError("vc/bad-alg", fnName + ": JOSE securing requires alg ES256/384/512 or EdDSA (got " + opts.alg + ")");
    }
    var key = _toKey(opts.privateKey, "private");
    var header = { alg: opts.alg, typ: joseTyp };
    if (typeof opts.kid === "string") header.kid = opts.kid;
    if (typeof opts.cty === "string") header.cty = opts.cty;
    var signingInput = _b64urlJson(header) + "." + _b64urlJson(doc);
    var sig = params.nodeHash === null
      ? nodeCrypto.sign(null, Buffer.from(signingInput, "ascii"), key)
      : nodeCrypto.sign(params.nodeHash, Buffer.from(signingInput, "ascii"), { key: key, dsaEncoding: params.dsaEncoding });
    return signingInput + "." + sig.toString("base64url");
  }
  throw new VcError("vc/bad-securing", fnName + ": securing must be 'jose' or 'cose'");
}

function _verifyJose(token, opts, expectedTyp) {
  var parts = token.split(".");
  if (parts.length !== 3) {
    throw new VcError("vc/malformed", "vc.verify: not a compact JWS (expected three dot-separated segments)");
  }
  var header;
  try { header = safeJson.parse(Buffer.from(parts[0], "base64url").toString("utf8")); }
  catch (_e) { throw new VcError("vc/malformed", "vc.verify: JWS header is not valid base64url-JSON"); }
  if (!header || header.typ !== expectedTyp) {
    throw new VcError("vc/bad-typ", "vc.verify: JWS typ must be '" + expectedTyp + "'");
  }
  // crit-bypass defense (RFC 7515 §4.1.11): a `crit` header marks
  // extensions the verifier MUST understand and process. This verifier
  // implements no critical extensions, so any `crit` is refused rather
  // than ignored — accepting it would mean honoring a credential under
  // weaker semantics than the issuer marked mandatory.
  if (header.crit !== undefined) {
    throw new VcError("vc/crit-unsupported",
      "vc.verify: JWS 'crit' header lists extensions this verifier does not support (RFC 7515 §4.1.11)");
  }
  if (header.alg === "none" || !Object.prototype.hasOwnProperty.call(JOSE_ALGS, header.alg)) {
    throw new VcError("vc/bad-alg", "vc.verify: unsupported or unsecured JWS alg '" + header.alg + "'");
  }
  if (opts.algorithms.indexOf(header.alg) === -1) {
    throw new VcError("vc/alg-not-allowed", "vc.verify: alg '" + header.alg + "' is not in the allowlist");
  }
  var params = JOSE_ALGS[header.alg];
  var pub = opts.publicKey ? _toKey(opts.publicKey, "public") : _toKey(opts.keyResolver(header), "public");
  var signingInput = parts[0] + "." + parts[1];
  var sig = Buffer.from(parts[2], "base64url");
  var ok = params.nodeHash === null
    ? nodeCrypto.verify(null, Buffer.from(signingInput, "ascii"), pub, sig)
    : nodeCrypto.verify(params.nodeHash, Buffer.from(signingInput, "ascii"), { key: pub, dsaEncoding: params.dsaEncoding }, sig);
  if (!ok) throw new VcError("vc/bad-signature", "vc.verify: JWS signature did not verify");
  var payload;
  try { payload = safeJson.parse(Buffer.from(parts[1], "base64url").toString("utf8")); }
  catch (_e) { throw new VcError("vc/malformed", "vc.verify: JWS payload is not valid base64url-JSON"); }
  return { payload: payload, alg: header.alg };
}

async function _verifyCose(bytes, opts, expectedTyp) {
  var algorithms = opts.algorithms.filter(function (a) { return a in cose.ALGORITHMS; });
  if (!algorithms.length) {
    throw new VcError("vc/no-cose-alg", "vc.verify: opts.algorithms has no COSE algorithm for a COSE-secured credential");
  }
  var out = await cose.verify(bytes, {
    algorithms:  algorithms,
    publicKey:   opts.publicKey,
    keyResolver: opts.keyResolver,
  });
  var typ = out.protectedHeaders.get(HDR_COSE_TYP);
  if (typ !== undefined && typ !== expectedTyp) {
    throw new VcError("vc/bad-typ", "vc.verify: COSE typ header is '" + typ + "', expected '" + expectedTyp + "'");
  }
  var payload;
  try { payload = safeJson.parse(out.payload.toString("utf8")); }
  catch (_e) { throw new VcError("vc/malformed", "vc.verify: COSE payload is not valid JSON"); }
  return { payload: payload, alg: out.alg };
}

// Verify a secured JSON document (the JOSE/COSE envelope) → { payload,
// alg, securing }. Shared by credential + presentation verification.
async function _verifySecured(secured, opts, joseTyp, coseTyp) {
  if (typeof secured === "string") {
    return Object.assign({ securing: "jose" }, _verifyJose(secured, opts, joseTyp));
  }
  if (Buffer.isBuffer(secured) || secured instanceof Uint8Array) {
    return Object.assign({ securing: "cose" }, await _verifyCose(Buffer.from(secured), opts, coseTyp));
  }
  throw new VcError("vc/bad-input", "vc.verify: secured must be a compact-JWS string or COSE_Sign1 bytes");
}

/**
 * @primitive b.vc.verify
 * @signature b.vc.verify(secured, opts)
 * @since     0.12.39
 * @status    experimental
 * @compliance gdpr, soc2
 * @related   b.vc.issue, b.cose.verify
 *
 * Verify a secured verifiable credential and return the credential. The
 * securing form is auto-detected (a compact-JWS string vs. COSE_Sign1
 * bytes); the algorithm allowlist is mandatory and the JOSE
 * <code>none</code> algorithm is always refused. After the signature,
 * the VCDM 2.0 structural rules are re-checked and the
 * <code>validFrom</code> / <code>validUntil</code> window is enforced
 * against <code>opts.at</code> (default: now).
 *
 * @opts
 *   {
 *     algorithms:      string[],  // required — accepted alg names (allowlist)
 *     publicKey:       object,    // verification key (KeyObject / PEM)
 *     keyResolver:     function,  // (header) → key  (alternative to publicKey)
 *     expectedIssuer:  string,    // require the credential issuer (id) to match
 *     at:              Date,      // validity instant (default: now); must be a valid Date
 *   }
 *
 * @example
 *   var out = await b.vc.verify(jws, { algorithms: ["ES256"], publicKey: issuerPub, expectedIssuer: "did:example:123" });
 *   // → { credential, securing: "jose", alg: "ES256", issuer: "did:example:123" }
 */
async function verify(secured, opts) {
  validateOpts.requireObject(opts, "vc.verify", VcError);
  validateOpts(opts, ["algorithms", "publicKey", "keyResolver", "expectedIssuer", "at"], "vc.verify");
  if (!Array.isArray(opts.algorithms) || opts.algorithms.length === 0) {
    throw new VcError("vc/algorithms-required", "vc.verify: opts.algorithms is required (name the accepted algorithms)");
  }
  if (!opts.publicKey && typeof opts.keyResolver !== "function") {
    throw new VcError("vc/no-key", "vc.verify: pass publicKey or keyResolver");
  }
  validateOpts.optionalDate(opts.at, "vc.verify: opts.at", VcError, "vc/bad-at");
  var at = (opts.at !== undefined && opts.at !== null) ? opts.at : new Date();

  var result = await _verifySecured(secured, opts, JOSE_TYP, COSE_TYP);

  _validateVcdm(result.payload, { temporal: true, at: at });
  var issuer = _issuerId(result.payload);
  if (opts.expectedIssuer !== undefined && issuer !== opts.expectedIssuer) {
    throw new VcError("vc/issuer-mismatch", "vc.verify: credential issuer does not match expectedIssuer");
  }
  return { credential: result.payload, securing: result.securing, alg: result.alg, issuer: issuer };
}

// VCDM 2.0 presentation structural rules.
function _validateVp(vp) {
  if (!vp || typeof vp !== "object" || Array.isArray(vp)) {
    throw new VcError("vc/bad-presentation", "vc: presentation must be a JSON object");
  }
  var ctx = vp["@context"];
  if (!Array.isArray(ctx) || ctx[0] !== VCDM_V2_CONTEXT) {
    throw new VcError("vc/bad-context", "vc: presentation @context must start with '" + VCDM_V2_CONTEXT + "'");
  }
  var types = Array.isArray(vp.type) ? vp.type : [vp.type];
  if (types.indexOf("VerifiablePresentation") === -1) {
    throw new VcError("vc/bad-type", "vc: type must include 'VerifiablePresentation'");
  }
  // verifiableCredential, when present, MUST be an array — a non-array
  // value must fail closed rather than coerce to empty (which would let
  // a holder bypass credential verification with a malformed container).
  if (vp.verifiableCredential !== undefined && !Array.isArray(vp.verifiableCredential)) {
    throw new VcError("vc/bad-presentation", "vc: verifiableCredential must be an array");
  }
}

// An enveloped VC (VC-JOSE-COSE §enveloping): a data: URI whose media
// type selects the securing and whose body is the secured credential.
function _envelopeVc(securedVc) {
  if (typeof securedVc === "string") {
    return { "@context": [VCDM_V2_CONTEXT], type: ENVELOPED_VC_TYPE, id: "data:application/vc+jwt," + securedVc };
  }
  if (Buffer.isBuffer(securedVc) || securedVc instanceof Uint8Array) {
    return { "@context": [VCDM_V2_CONTEXT], type: ENVELOPED_VC_TYPE,
      id: "data:application/vc+cose;base64," + Buffer.from(securedVc).toString("base64") };
  }
  throw new VcError("vc/bad-credential", "vc.present: each credential must be a compact-JWS string or COSE_Sign1 bytes");
}

function _parseEnvelopedVc(entry) {
  if (!entry || typeof entry !== "object" || entry.type !== ENVELOPED_VC_TYPE || typeof entry.id !== "string") {
    throw new VcError("vc/bad-enveloped", "vc.verifyPresentation: verifiableCredential entries must be EnvelopedVerifiableCredential data: URIs");
  }
  var comma = entry.id.indexOf(",");
  if (entry.id.indexOf("data:") !== 0 || comma === -1) {
    throw new VcError("vc/bad-enveloped", "vc.verifyPresentation: enveloped credential id is not a data: URI");
  }
  var meta = entry.id.slice("data:".length, comma);
  var body = entry.id.slice(comma + 1);
  if (meta.indexOf("application/vc+cose") === 0) return Buffer.from(body, "base64");
  if (meta.indexOf("application/vc+jwt") === 0) return body;
  throw new VcError("vc/bad-enveloped", "vc.verifyPresentation: unsupported enveloped media type '" + meta + "'");
}

/**
 * @primitive b.vc.present
 * @signature b.vc.present(opts)
 * @since     0.12.42
 * @status    experimental
 * @compliance gdpr, soc2
 * @related   b.vc.verifyPresentation, b.vc.issue
 *
 * Build and sign a W3C Verifiable Presentation: a holder-signed envelope
 * wrapping one or more secured credentials (each enveloped per
 * VC-JOSE-COSE). <code>securing</code> and the algorithms match
 * <code>b.vc.issue</code> (compact JWS <code>vp+jwt</code>, or COSE_Sign1
 * <code>application/vp+cose</code>). Supply <code>nonce</code> /
 * <code>audience</code> for holder-binding / replay protection — they
 * are embedded in the signed presentation and checked at verification.
 *
 * @opts
 *   {
 *     credentials: array,    // secured VCs (compact-JWS strings or COSE_Sign1 bytes)
 *     holder:      string,   // the presenter (a DID or other id)
 *     securing:    string,   // "jose" | "cose"
 *     alg:         string,   // JOSE: ES256/384/512 | EdDSA. COSE: + ML-DSA-87
 *     privateKey:  object,   // the holder's key
 *     kid:         string,   // optional key id
 *     nonce:       string,   // optional verifier challenge (embedded + checked)
 *     audience:    string,   // optional intended verifier (embedded + checked)
 *   }
 *
 * @example
 *   var vp = await b.vc.present({ credentials: [jws], holder: holderDid, securing: "jose", alg: "ES256", privateKey: holderKey, nonce: challenge });
 */
async function present(opts) {
  validateOpts.requireObject(opts, "vc.present", VcError);
  validateOpts(opts, ["credentials", "holder", "securing", "alg", "privateKey", "kid", "nonce", "audience"], "vc.present");
  if (!Array.isArray(opts.credentials) || opts.credentials.length === 0) {
    throw new VcError("vc/no-credentials", "vc.present: opts.credentials must be a non-empty array");
  }
  if (opts.credentials.length > MAX_PRESENTATION_CREDENTIALS) {
    throw new VcError("vc/too-many-credentials", "vc.present: at most " + MAX_PRESENTATION_CREDENTIALS + " credentials per presentation");
  }
  if (typeof opts.holder !== "string" || !opts.holder) {
    throw new VcError("vc/no-holder", "vc.present: opts.holder is required (the presenter id / DID)");
  }
  if (!opts.privateKey) throw new VcError("vc/no-key", "vc.present: opts.privateKey is required");

  var vp = {
    "@context": [VCDM_V2_CONTEXT],
    type: ["VerifiablePresentation"],
    holder: opts.holder,
    verifiableCredential: opts.credentials.map(_envelopeVc),
  };
  if (typeof opts.nonce === "string") vp.nonce = opts.nonce;
  if (typeof opts.audience === "string") vp.audience = opts.audience;

  return _sign(vp, opts, VP_JOSE_TYP, VP_COSE_TYP, VP_COSE_CONTENT_TYPE, "vc.present");
}

/**
 * @primitive b.vc.verifyPresentation
 * @signature b.vc.verifyPresentation(secured, opts)
 * @since     0.12.42
 * @status    experimental
 * @compliance gdpr, soc2
 * @related   b.vc.present, b.vc.verify
 *
 * Verify a Verifiable Presentation: the holder signature (auto-detected
 * jose / cose, mandatory algorithm allowlist, JOSE <code>none</code>
 * refused), the VCDM structure, and the embedded <code>nonce</code> /
 * <code>audience</code> / <code>expectedHolder</code> when given. With
 * <code>verifyCredentials: true</code> each enveloped credential is
 * verified through <code>b.vc.verify</code> (using
 * <code>opts.credentialOpts</code>) and returned.
 *
 * @opts
 *   {
 *     algorithms:      string[],  // required — holder-signature alg allowlist
 *     publicKey:       object,    // the holder verification key
 *     keyResolver:     function,  // (header) → holder key
 *     expectedHolder:  string,    // require presentation holder to match
 *     nonce:           string,    // require embedded nonce to match
 *     audience:        string,    // require embedded audience to match
 *     verifyCredentials: boolean, // verify each enveloped VC via b.vc.verify
 *     credentialOpts:  object,    // opts passed to b.vc.verify for each VC
 *   }
 *
 * @example
 *   var out = await b.vc.verifyPresentation(vp, {
 *     algorithms: ["ES256"], publicKey: holderKey, nonce: challenge,
 *     verifyCredentials: true, credentialOpts: { algorithms: ["ES256"], publicKey: issuerKey },
 *   });
 *   // → { presentation, holder, credentials: [verified VCs], securing, alg }
 */
async function verifyPresentation(secured, opts) {
  validateOpts.requireObject(opts, "vc.verifyPresentation", VcError);
  validateOpts(opts, ["algorithms", "publicKey", "keyResolver", "expectedHolder", "nonce", "audience", "verifyCredentials", "credentialOpts"], "vc.verifyPresentation");
  if (!Array.isArray(opts.algorithms) || opts.algorithms.length === 0) {
    throw new VcError("vc/algorithms-required", "vc.verifyPresentation: opts.algorithms is required");
  }
  if (!opts.publicKey && typeof opts.keyResolver !== "function") {
    throw new VcError("vc/no-key", "vc.verifyPresentation: pass publicKey or keyResolver");
  }

  var result = await _verifySecured(secured, opts, VP_JOSE_TYP, VP_COSE_TYP);
  var vp = result.payload;
  _validateVp(vp);

  if (opts.expectedHolder !== undefined && vp.holder !== opts.expectedHolder) {
    throw new VcError("vc/holder-mismatch", "vc.verifyPresentation: presentation holder does not match expectedHolder");
  }
  if (opts.nonce !== undefined && vp.nonce !== opts.nonce) {
    throw new VcError("vc/nonce-mismatch", "vc.verifyPresentation: presentation nonce does not match");
  }
  if (opts.audience !== undefined && vp.audience !== opts.audience) {
    throw new VcError("vc/audience-mismatch", "vc.verifyPresentation: presentation audience does not match");
  }

  var entries = vp.verifiableCredential || [];   // _validateVp guarantees array-or-absent
  if (entries.length > MAX_PRESENTATION_CREDENTIALS) {
    throw new VcError("vc/too-many-credentials", "vc.verifyPresentation: presentation carries more than " + MAX_PRESENTATION_CREDENTIALS + " credentials");
  }
  var credentials = [];
  if (opts.verifyCredentials) {
    var credOpts = opts.credentialOpts;
    validateOpts.requireObject(credOpts, "vc.verifyPresentation.credentialOpts", VcError);
    for (var i = 0; i < entries.length; i += 1) {
      credentials.push(await verify(_parseEnvelopedVc(entries[i]), credOpts));
    }
  }

  return { presentation: vp, holder: vp.holder, credentials: credentials, securing: result.securing, alg: result.alg };
}

module.exports = {
  issue:          issue,
  verify:         verify,
  present:        present,
  verifyPresentation: verifyPresentation,
  JOSE_ALGS:      JOSE_ALGS,
  VCDM_V2_CONTEXT: VCDM_V2_CONTEXT,
  VcError:        VcError,
};
