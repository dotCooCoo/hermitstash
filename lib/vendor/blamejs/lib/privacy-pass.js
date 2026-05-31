"use strict";
/**
 * @module b.privacyPass
 * @nav    Identity
 * @title  Privacy Pass
 *
 * @intro
 *   Origin / relying-party side of Privacy Pass (RFC 9577 HTTP
 *   authentication scheme, RFC 9578 issuance protocols) — issue a token
 *   challenge and verify a presented token without learning who the
 *   client is. An origin asks for a token with a
 *   <code>WWW-Authenticate: PrivateToken</code> challenge; the client
 *   obtains a token from an issuer and presents it; the origin verifies
 *   it cryptographically.
 *
 *   This implements the publicly verifiable token type
 *   <strong>0x0002 (Blind RSA, 2048-bit)</strong>: the token's
 *   authenticator is an RSA Blind Signature (RFC 9474) that any party
 *   holding the issuer's public key can verify with RSASSA-PSS — so the
 *   origin verifies tokens itself, with no issuer secret and no callback.
 *   The privately verifiable VOPRF type (0x0001) requires the issuer's
 *   secret key and is an issuer-side operation, not implemented here.
 *
 *   Blind RSA is the algorithm Privacy Pass defines on the wire; like
 *   the framework's DNSSEC / DANE verifiers it validates an external
 *   protocol's signatures (RSASSA-PSS, SHA-384) rather than introducing
 *   classical crypto as a framework default.
 *
 * @card
 *   Privacy Pass origin side (RFC 9577 / 9578). Issue a
 *   <code>WWW-Authenticate: PrivateToken</code> challenge and verify a
 *   presented Blind-RSA (type 0x0002) token against the issuer public
 *   key — anonymous, publicly verifiable authorization with no issuer
 *   callback.
 */

var nodeCrypto = require("node:crypto");
var bCrypto = require("./crypto");
var validateOpts = require("./validate-opts");
var { defineClass } = require("./framework-error");

var PrivacyPassError = defineClass("PrivacyPassError", { alwaysPermanent: true });

var TOKEN_TYPE_BLIND_RSA = 0x0002;
// RFC 9578 §5.3 token type 0x0002: RSABSSA-SHA384-PSS, salt length 48.
var PSS_HASH = "sha384";
var PSS_SALT_LEN = 48;                                        // RFC 9578 §5.3 PSS salt length (= SHA-384 digest size)
// Fixed-size token fields (RFC 9577 §2.2): type(2) nonce(32)
// challenge_digest(32) token_key_id(32), then the authenticator.
var TOKEN_PREFIX_LEN = 98;                                    // 2 + 32 + 32 + 32 (token_input length)

// RFC 9577 §2.1 sends the challenge / token-key auth-params as base64url
// WITH padding; Node's "base64url" output is unpadded, so pad to a
// multiple of 4 so strict clients / proxies accept the header.
function _b64urlPadded(buf) {
  var s = Buffer.from(buf).toString("base64url");
  while (s.length % 4 !== 0) s += "=";                        // base64 quantum is 4 chars
  return s;
}

function _bytes(x, what) {
  if (Buffer.isBuffer(x)) return x;
  if (x instanceof Uint8Array) return Buffer.from(x);
  if (typeof x === "string") return Buffer.from(x, "base64");
  throw new PrivacyPassError("privacy-pass/bad-bytes", "privacyPass: " + what + " must be a Buffer / Uint8Array / base64 string");
}

// Import the issuer public key and capture the SubjectPublicKeyInfo
// bytes used to derive token_key_id. When the caller supplies the
// published SPKI DER directly, hash THOSE bytes — re-exporting an
// rsa-pss KeyObject can re-encode the AlgorithmIdentifier and change the
// digest. token_key_id is SHA-256 of the issuer's distributed key
// (RFC 9577 §2.2), which is the SPKI as published.
function _importIssuerKey(k) {
  if (k && typeof k === "object" && typeof k.export === "function" && k.type === "public") {
    return { key: k, spki: k.export({ format: "der", type: "spki" }) };
  }
  try {
    if (Buffer.isBuffer(k) || k instanceof Uint8Array) {
      var der = Buffer.from(k);
      return { key: nodeCrypto.createPublicKey({ key: der, format: "der", type: "spki" }), spki: der };
    }
    // A "PUBLIC KEY" PEM body IS the SubjectPublicKeyInfo DER — decode it
    // directly so token_key_id is SHA-256 of the issuer's exact bytes,
    // not a re-encoding (Node can re-emit rsa-pss AlgorithmIdentifier
    // parameters differently on export).
    if (typeof k === "string" && /-----BEGIN PUBLIC KEY-----/.test(k)) {
      var body = k.replace(/-----BEGIN PUBLIC KEY-----/, "").replace(/-----END PUBLIC KEY-----/, "").replace(/\s+/g, "");
      var pemDer = Buffer.from(body, "base64");
      return { key: nodeCrypto.createPublicKey(k), spki: pemDer };
    }
    var key = nodeCrypto.createPublicKey(k);                  // other key spec (best-effort SPKI export)
    return { key: key, spki: key.export({ format: "der", type: "spki" }) };
  } catch (e) {
    throw new PrivacyPassError("privacy-pass/bad-key", "privacyPass: could not import issuerPublicKey: " + ((e && e.message) || e));
  }
}

/**
 * @primitive b.privacyPass.parseToken
 * @signature b.privacyPass.parseToken(token)
 * @since     0.12.52
 * @status    experimental
 * @related   b.privacyPass.verifyToken, b.privacyPass.buildChallenge
 *
 * Parse a Privacy Pass token (RFC 9577 §2.2) into its fields: the
 * <code>tokenType</code>, the client <code>nonce</code>, the
 * <code>challengeDigest</code> (SHA-256 of the TokenChallenge the token
 * answers), the <code>tokenKeyId</code> (SHA-256 of the issuer public
 * key), and the <code>authenticator</code>. Structural only — call
 * <code>verifyToken</code> to check the signature.
 *
 * @example
 *   var t = b.privacyPass.parseToken(tokenBytes);
 *   // → { tokenType: 2, nonce, challengeDigest, tokenKeyId, authenticator }
 */
function parseToken(token) {
  var b = _bytes(token, "token");
  if (b.length < TOKEN_PREFIX_LEN + 1) throw new PrivacyPassError("privacy-pass/bad-token", "privacyPass.parseToken: token too short");
  return {
    tokenType:       b.readUInt16BE(0),
    nonce:           b.slice(2, 34),
    challengeDigest: b.slice(34, 66),
    tokenKeyId:      b.slice(66, 98),
    authenticator:   b.slice(98),
    tokenInput:      b.slice(0, TOKEN_PREFIX_LEN),
  };
}

/**
 * @primitive b.privacyPass.verifyToken
 * @signature b.privacyPass.verifyToken(opts)
 * @since     0.12.52
 * @status    experimental
 * @compliance soc2
 * @related   b.privacyPass.buildChallenge, b.privacyPass.parseToken
 *
 * Verify a publicly verifiable Privacy Pass token (type 0x0002, Blind
 * RSA — RFC 9578 §8.2). The authenticator is checked as an RSASSA-PSS
 * (SHA-384, MGF1-SHA-384, 48-byte salt) signature over
 * <code>token_input = token_type ‖ nonce ‖ challenge_digest ‖
 * token_key_id</code> using the issuer's public key. The token is bound
 * to that key — its <code>token_key_id</code> must equal the SHA-256 of
 * the supplied key's SubjectPublicKeyInfo — and, when
 * <code>opts.challenge</code> is given, to that challenge (its SHA-256
 * must equal the token's <code>challenge_digest</code>), so a token
 * minted for a different origin's challenge is refused.
 *
 * @opts
 *   {
 *     token:            Buffer|base64,   // the presented token
 *     issuerPublicKey:  KeyObject|Buffer(SPKI DER)|PEM,
 *     challenge?:       Buffer|base64,   // the TokenChallenge this token must answer
 *   }
 *
 * @example
 *   var r = b.privacyPass.verifyToken({ token: tok, issuerPublicKey: issuerSpki });
 *   // → { ok: true, tokenType: 2, nonce, challengeDigest, tokenKeyId }
 */
function verifyToken(opts) {
  validateOpts.requireObject(opts, "privacyPass.verifyToken", PrivacyPassError);
  validateOpts(opts, ["token", "issuerPublicKey", "challenge"], "privacyPass.verifyToken");
  if (opts.issuerPublicKey === undefined || opts.issuerPublicKey === null) throw new PrivacyPassError("privacy-pass/bad-arg", "privacyPass.verifyToken: opts.issuerPublicKey is required");

  var parsed = parseToken(opts.token);
  if (parsed.tokenType !== TOKEN_TYPE_BLIND_RSA) {
    throw new PrivacyPassError("privacy-pass/unsupported-token-type", "privacyPass.verifyToken: only token type 0x0002 (Blind RSA) is verifiable by the origin; got 0x" + parsed.tokenType.toString(16).padStart(4, "0"));  // base-16 radix + 4-hex-digit pad, not a size
  }

  var imported = _importIssuerKey(opts.issuerPublicKey);
  var key = imported.key;
  if (key.asymmetricKeyType !== "rsa" && key.asymmetricKeyType !== "rsa-pss") {
    throw new PrivacyPassError("privacy-pass/bad-key", "privacyPass.verifyToken: issuerPublicKey must be an RSA key for token type 0x0002");
  }

  // Bind the token to the issuer key: token_key_id = SHA-256(SPKI).
  var keyId = nodeCrypto.createHash("sha256").update(imported.spki).digest();
  if (!bCrypto.timingSafeEqual(keyId, parsed.tokenKeyId)) {
    throw new PrivacyPassError("privacy-pass/key-id-mismatch", "privacyPass.verifyToken: token_key_id does not match the issuer public key");
  }

  // Bind the token to the challenge, when supplied.
  if (opts.challenge !== undefined && opts.challenge !== null) {
    var cd = nodeCrypto.createHash("sha256").update(_bytes(opts.challenge, "challenge")).digest();
    if (!bCrypto.timingSafeEqual(cd, parsed.challengeDigest)) {
      throw new PrivacyPassError("privacy-pass/challenge-mismatch", "privacyPass.verifyToken: challenge_digest does not match opts.challenge");
    }
  }

  var ok;
  try {
    ok = nodeCrypto.verify(PSS_HASH, parsed.tokenInput, { key: key, padding: nodeCrypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: PSS_SALT_LEN }, parsed.authenticator);
  } catch (e) {
    throw new PrivacyPassError("privacy-pass/verify-threw", "privacyPass.verifyToken: signature verification threw: " + ((e && e.message) || e));
  }
  if (!ok) throw new PrivacyPassError("privacy-pass/bad-authenticator", "privacyPass.verifyToken: token authenticator did not verify");
  return { ok: true, tokenType: parsed.tokenType, nonce: parsed.nonce, challengeDigest: parsed.challengeDigest, tokenKeyId: parsed.tokenKeyId };
}

/**
 * @primitive b.privacyPass.buildChallenge
 * @signature b.privacyPass.buildChallenge(opts)
 * @since     0.12.52
 * @status    experimental
 * @related   b.privacyPass.verifyToken
 *
 * Build a TokenChallenge (RFC 9577 §2.1) and the matching
 * <code>WWW-Authenticate: PrivateToken</code> header value an origin
 * returns to ask a client for a token. The challenge binds the token to
 * this issuer (and optionally this origin and a redemption context);
 * its SHA-256 is the <code>challenge_digest</code> that
 * <code>verifyToken</code> checks.
 *
 * @opts
 *   {
 *     issuerName:        string,   // the token issuer's name
 *     tokenType?:        number,   // default 0x0002 (Blind RSA)
 *     originInfo?:       string,   // origin name(s) the token is scoped to (default: any)
 *     redemptionContext?: Buffer,  // 0 or 32 bytes (default: empty)
 *     tokenKey?:         Buffer|KeyObject,  // issuer SPKI, included as token-key= when given
 *   }
 *
 * @example
 *   var c = b.privacyPass.buildChallenge({ issuerName: "issuer.example", originInfo: "origin.example" });
 *   res.setHeader("WWW-Authenticate", c.wwwAuthenticate);
 */
function buildChallenge(opts) {
  validateOpts.requireObject(opts, "privacyPass.buildChallenge", PrivacyPassError);
  validateOpts(opts, ["issuerName", "tokenType", "originInfo", "redemptionContext", "tokenKey"], "privacyPass.buildChallenge");
  if (typeof opts.issuerName !== "string" || opts.issuerName === "") throw new PrivacyPassError("privacy-pass/bad-arg", "privacyPass.buildChallenge: opts.issuerName is required");
  var tokenType = opts.tokenType === undefined ? TOKEN_TYPE_BLIND_RSA : opts.tokenType;
  if (typeof tokenType !== "number" || !Number.isInteger(tokenType) || tokenType < 0 || tokenType > 0xffff) throw new PrivacyPassError("privacy-pass/bad-arg", "privacyPass.buildChallenge: tokenType must be a uint16");

  var issuer = Buffer.from(opts.issuerName, "utf8");
  if (issuer.length > 0xffff) throw new PrivacyPassError("privacy-pass/bad-arg", "privacyPass.buildChallenge: issuerName too long");
  var origin = Buffer.alloc(0);
  if (opts.originInfo !== undefined && opts.originInfo !== null) {
    if (typeof opts.originInfo !== "string") throw new PrivacyPassError("privacy-pass/bad-arg", "privacyPass.buildChallenge: originInfo must be a string");
    origin = Buffer.from(opts.originInfo, "utf8");
    if (origin.length > 0xffff) throw new PrivacyPassError("privacy-pass/bad-arg", "privacyPass.buildChallenge: originInfo too long");
  }
  var rc = opts.redemptionContext !== undefined && opts.redemptionContext !== null ? _bytes(opts.redemptionContext, "redemptionContext") : Buffer.alloc(0);
  if (rc.length !== 0 && rc.length !== 32) throw new PrivacyPassError("privacy-pass/bad-arg", "privacyPass.buildChallenge: redemptionContext must be empty or 32 bytes");  // RFC 9577 redemption_context is 0 or 32 bytes

  var u16 = function (n) { return Buffer.from([(n >> 8) & 0xff, n & 0xff]); };
  var challenge = Buffer.concat([
    u16(tokenType),
    u16(issuer.length), issuer,
    Buffer.from([rc.length]), rc,
    u16(origin.length), origin,
  ]);

  var parts = ['PrivateToken challenge="' + _b64urlPadded(challenge) + '"'];
  if (opts.tokenKey !== undefined && opts.tokenKey !== null) {
    var spki = (opts.tokenKey && typeof opts.tokenKey.export === "function") ? opts.tokenKey.export({ format: "der", type: "spki" }) : _bytes(opts.tokenKey, "tokenKey");
    parts.push('token-key="' + _b64urlPadded(spki) + '"');
  }
  return { challenge: challenge, wwwAuthenticate: parts.join(", ") };
}

module.exports = {
  parseToken:     parseToken,
  verifyToken:    verifyToken,
  buildChallenge: buildChallenge,
  TOKEN_TYPE_BLIND_RSA: TOKEN_TYPE_BLIND_RSA,
  PrivacyPassError: PrivacyPassError,
};
