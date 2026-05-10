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
var { generateToken, sha3Hash } = require("../crypto");
var { AuthError } = require("../framework-error");

var cache       = lazyRequire(function () { return require("../cache"); });
var audit       = lazyRequire(function () { return require("../audit"); });
var observability = lazyRequire(function () { return require("../observability"); });
var emit = validateOpts.makeNamespacedEmitters("auth.oid4vci", { audit: audit, observability: observability });

var DEFAULT_PRE_AUTH_TTL_MS  = C.TIME.minutes(5);
var DEFAULT_ACCESS_TOKEN_TTL = C.TIME.minutes(15);
var DEFAULT_C_NONCE_TTL_MS   = C.TIME.minutes(5);
var MAX_PROOF_BYTES          = 32 * 1024;                                                       // allow:raw-byte-literal — proof-JWT cap
var SUPPORTED_CREDENTIAL_FORMATS = ["vc+sd-jwt", "dc+sd-jwt"];

var _emitAudit  = emit.audit;
var _emitMetric = emit.metric;

function _b64uDecodeStr(s) {
  return Buffer.from(s, "base64url").toString("utf8");
}

function _verifyProofJwt(proofJwt, expectedAud, expectedCNonce, expectedClientId, supportedAlgs) {
  // OID4VCI §7.2.1.1: the proof JWT MUST:
  //   - typ = "openid4vci-proof+jwt"
  //   - alg in supported list (issuer publishes these)
  //   - aud = credential issuer URL (this issuer's `credential_issuer`)
  //   - iat = recent
  //   - nonce = c_nonce previously issued to the wallet
  //   - jwk OR kid in header pointing at the key to bind cnf to
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
    header  = safeJson.parse(_b64uDecodeStr(parts[0]), { maxBytes: 4096 });                     // allow:raw-byte-literal — proof header cap
    payload = safeJson.parse(_b64uDecodeStr(parts[1]), { maxBytes: MAX_PROOF_BYTES });
  } catch (e) {
    throw new AuthError("auth-oid4vci/bad-proof-decode",
      "credential issuance: proof JWT base64 decode failed: " + ((e && e.message) || String(e)));
  }
  if (header.typ !== "openid4vci-proof+jwt") {
    throw new AuthError("auth-oid4vci/wrong-proof-typ",
      "credential issuance: proof JWT typ must be \"openid4vci-proof+jwt\" (got \"" + header.typ + "\")");
  }
  if (!header.alg || supportedAlgs.indexOf(header.alg) === -1) {
    throw new AuthError("auth-oid4vci/unsupported-proof-alg",
      "credential issuance: proof JWT alg \"" + header.alg + "\" not in issuer-supported set");
  }
  if (!header.jwk && !header.kid && !header.x5c) {
    throw new AuthError("auth-oid4vci/no-key-in-proof",
      "credential issuance: proof JWT header must include `jwk`, `kid`, OR `x5c` (holder key binding)");
  }
  if (payload.aud !== expectedAud) {
    throw new AuthError("auth-oid4vci/wrong-proof-aud",
      "credential issuance: proof JWT aud \"" + payload.aud + "\" mismatch (expected \"" + expectedAud + "\")");
  }
  if (expectedCNonce !== null && payload.nonce !== expectedCNonce) {
    throw new AuthError("auth-oid4vci/wrong-proof-nonce",
      "credential issuance: proof JWT nonce mismatch (replay defense — wallet must use the c_nonce from the most recent issuer response)");
  }
  if (typeof payload.iat !== "number") {
    throw new AuthError("auth-oid4vci/no-proof-iat",
      "credential issuance: proof JWT must include iat");
  }
  var nowSec = Math.floor(Date.now() / 1000);                                                   // allow:raw-byte-literal — ms→s
  if (payload.iat > nowSec + 60) {                                                              // allow:raw-time-literal — 60s skew tolerance
    throw new AuthError("auth-oid4vci/proof-iat-future",
      "credential issuance: proof JWT iat is in the future");
  }
  if (payload.iat < nowSec - Math.floor(C.TIME.minutes(10) / 1000)) {                            // allow:raw-byte-literal — ms→s
    throw new AuthError("auth-oid4vci/proof-iat-too-old",
      "credential issuance: proof JWT iat older than 10 minutes — wallet must mint a fresh proof");
  }
  if (expectedClientId && payload.iss && payload.iss !== expectedClientId) {
    throw new AuthError("auth-oid4vci/wrong-proof-iss",
      "credential issuance: proof JWT iss does not match the access-token client_id");
  }

  // Verify the JWS signature using the key embedded in the header.
  var holderKeyJwk = header.jwk || null;
  if (!holderKeyJwk && header.kid) {
    // Operators with kid-only proofs supply a resolver; until then,
    // require jwk inline. Refuse rather than silently downgrade.
    throw new AuthError("auth-oid4vci/kid-resolver-not-supported",
      "credential issuance: proof JWT used `kid` without inline `jwk` — supply { jwk } in the header for inline binding (kid-resolver path is operator-side)");
  }
  if (!holderKeyJwk) {
    throw new AuthError("auth-oid4vci/no-jwk-in-header",
      "credential issuance: proof JWT must carry `jwk` for inline holder-key binding");
  }
  var keyObj;
  try { keyObj = nodeCrypto.createPublicKey({ key: holderKeyJwk, format: "jwk" }); }
  catch (e) {
    throw new AuthError("auth-oid4vci/bad-jwk",
      "credential issuance: proof JWT jwk is not parseable: " + ((e && e.message) || String(e)));
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
 *     proofAlgorithms:            string[],              // default ["ES256", "ES384"]
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

  var preAuthTtl = opts.preAuthCodeTtlMs || DEFAULT_PRE_AUTH_TTL_MS;
  var accessTokenTtl = opts.accessTokenTtlMs || DEFAULT_ACCESS_TOKEN_TTL;
  var cNonceTtl = opts.cNonceTtlMs || DEFAULT_C_NONCE_TTL_MS;

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
    var preAuthCode = generateToken(32);                                                         // allow:raw-byte-literal — 256-bit single-use pre-auth code
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
            length:     typeof txCode.length === "number" ? txCode.length : 4,                  // allow:raw-byte-literal — default tx-code 4 digits
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
      // Constant-time-ish compare via fixed-size sha3 hash equality.
      if (txHash !== entry.txCodeHash) {
        // Don't consume on failure — wallet may be retrying. Operator
        // attaches their own attempt counter / lockout via b.auth.lockout.
        _emitAudit("tx_code_mismatch", "failure", {
          subject: entry.subject,
        });
        throw new AuthError("auth-oid4vci/tx-code-mismatch",
          "exchangePreAuthorizedCode: tx_code does not match");
      }
    }
    await codeStore.delete(eopts.preAuthCode);
    var accessToken = generateToken(32);                                                         // allow:raw-byte-literal — 256-bit access token
    var cNonce = generateToken(16);                                                              // allow:raw-byte-literal — 128-bit c_nonce
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
      expires_in:    Math.floor(accessTokenTtl / 1000),                                          // allow:raw-byte-literal — ms→s
      c_nonce:       cNonce,
      c_nonce_expires_in: Math.floor(cNonceTtl / 1000),                                          // allow:raw-byte-literal — ms→s
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
    var verified = _verifyProofJwt(iopts.proof, opts.credentialIssuerUrl, expectedCNonce, null, proofAlgs);

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
    var newCNonce = generateToken(16);                                                           // allow:raw-byte-literal — 128-bit c_nonce
    await cNonceStore.set(iopts.accessToken, newCNonce);

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
      c_nonce_expires_in: Math.floor(cNonceTtl / 1000),                                          // allow:raw-byte-literal — ms→s
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
