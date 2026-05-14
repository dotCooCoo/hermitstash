"use strict";
/**
 * @module b.acme
 * @nav    Network
 * @title  ACME
 *
 * @intro
 *   ACME RFC 8555 + RFC 9773 ARI client — CA/B 47-day cert phase-in,
 *   ARI renewal windows, account key rotation.
 *
 *   The handle owns the lifecycle: directory fetch (RFC 8555 §7.1.1),
 *   account create (§7.3), new order (§7.4), challenge dispatch
 *   (HTTP-01 / DNS-01 — operator runs the challenge response, the
 *   framework drives polling), finalize (§7.4), cert retrieve
 *   (§7.4.2). RFC 9773 ARI lets the CA push a renewal window:
 *   `renewIfDue` consults the directory's `renewalInfo` endpoint with
 *   the ACMECertID derived from the cert's AKI + serial. Before
 *   `suggestedWindow.start` the call audits `acme.cert.renew.skipped`;
 *   at or past it the verdict is `{ shouldRenew: true }` and audits
 *   `acme.cert.renewed.scheduled`. Operators wire this with
 *   `b.network.tls.expiryMonitor` so the renewal trigger composes
 *   into the existing cert-rotation flow.
 *
 *   Directory URL: NO default. Operator passes the production CA's
 *   directory URL (Let's Encrypt prod / Pebble in tests / any
 *   RFC 8555-compliant CA). The framework refuses to default to a
 *   single CA — the operator's CA choice is policy, not framework
 *   decision.
 *
 *   JWS algorithm: ES256 (P-256 + SHA-256) — RFC 8555 §6.2 mandates
 *   this for account-key signatures. ACME predates the JOSE PQC
 *   algorithm registry; until CAs publish PQC-capable directories,
 *   the wire format is classical. The framework's audit chain stays
 *   PQC-signed regardless.
 *
 *   Validation: throw at config-time on bad opts; throw on bad CA-
 *   response shape (operator-meaningful); audit on cert.* lifecycle
 *   events.
 *
 * @card
 *   ACME RFC 8555 + RFC 9773 ARI client — CA/B 47-day cert phase-in, ARI renewal windows, account key rotation.
 */

var nodeCrypto = require("node:crypto");

var C = require("./constants");
var asn1 = require("./asn1-der");
var safeUrl = require("./safe-url");
var safeJson = require("./safe-json");
var validateOpts = require("./validate-opts");
var lazyRequire = require("./lazy-require");
var httpClient = require("./http-client");
var { AcmeError } = require("./framework-error");

var _err = AcmeError.factory;

var observability = lazyRequire(function () { return require("./observability"); });

// RFC 9773 §4 — the ACMECertID is constructed as
// base64url(AuthorityKeyIdentifier.keyIdentifier) + "." +
// base64url(serialNumber bytes). The renewalInfo endpoint is the
// directory's `renewalInfo` URL plus "/<ACMECertID>".

var DEFAULT_TIMEOUT_MS  = C.TIME.seconds(30);
var DEFAULT_POLL_MS     = C.TIME.seconds(2);
var DEFAULT_POLL_CAP_MS = C.TIME.minutes(5);
var DEFAULT_BODY_CAP    = C.BYTES.mib(2);

// ---- helpers ----

function _b64u(buf) { return Buffer.from(buf).toString("base64url"); }

function _stringify(obj) {
  // RFC 8555 §6.1 — JWS payload SHOULD be the canonical JSON encoding.
  // Use stable key ordering via safeJson when available; fall back to
  // JSON.stringify(obj) for bodies that are pre-validated.
  if (safeJson && typeof safeJson.canonical === "function") {
    try { return safeJson.canonical(obj); } catch (_e) { /* fall through */ }
  }
  return JSON.stringify(obj);
}

function _emitAudit(audit, action, outcome, metadata) {
  if (!audit || typeof audit.safeEmit !== "function") return;
  try {
    audit.safeEmit({
      action:   action,
      outcome:  outcome,
      metadata: metadata,
    });
  } catch (_e) { /* audit best-effort */ }
}

function _emitObs(name, fields) {
  try { observability().safeEvent(name, 1, fields || {}); } catch (_e) { /* obs best-effort */ }
}

// JWK shape for an ES256 (P-256) public key — RFC 7518 §6.2.1.
function _publicJwkFromKeyObject(keyObject) {
  if (!keyObject || typeof keyObject.export !== "function") {
    throw _err("acme/bad-account-key", "accountKey must expose a Node KeyObject (export)", true);
  }
  var jwk;
  try { jwk = keyObject.export({ format: "jwk" }); }
  catch (e) { throw _err("acme/bad-account-key", "accountKey export(jwk) failed: " + e.message, true); }
  if (!jwk || jwk.kty !== "EC" || jwk.crv !== "P-256") {
    throw _err("acme/bad-account-key",
      "accountKey must be a P-256 EC keypair (RFC 8555 §6.2 ES256); got kty=" +
      (jwk && jwk.kty) + " crv=" + (jwk && jwk.crv), true);
  }
  // RFC 7638 thumbprint inputs MUST be sorted alphabetically + minimal-JSON.
  return Object.freeze({ crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y });
}

function _jwkThumbprint(publicJwk) {
  // RFC 7638 §3 — base64url(SHA-256(canonical JSON of required members)).
  var canon = JSON.stringify({ crv: publicJwk.crv, kty: publicJwk.kty, x: publicJwk.x, y: publicJwk.y });
  return _b64u(nodeCrypto.createHash("sha256").update(canon).digest());
}

function _signJws(privateKey, protectedHeader, payload) {
  // RFC 7515 compact JWS: <b64u(prot)>.<b64u(payload)>.<b64u(sig)>
  // For empty body POST-as-GET, payload is the empty string.
  var protB64 = _b64u(_stringify(protectedHeader));
  var payloadB64 = (payload === "" || payload === undefined || payload === null)
    ? ""
    : _b64u(_stringify(payload));
  var signingInput = protB64 + "." + payloadB64;
  var derSig;
  try {
    var sign = nodeCrypto.createSign("SHA256");
    sign.update(signingInput);
    sign.end();
    derSig = sign.sign(privateKey);
  } catch (e) {
    throw _err("acme/sign-failed", "ES256 sign failed: " + e.message, true);
  }
  // ECDSA from node:crypto returns DER-encoded (r,s); RFC 7515 requires
  // raw concatenation of r||s, each padded to the curve byte size (32
  // for P-256).
  var rawSig = _ecdsaDerToRaw(derSig, 32);                                       // allow:raw-byte-literal — RFC 7518 §3.4 ES256 signature half-length (P-256 byte size)
  return {
    protected: protB64,
    payload:   payloadB64,
    signature: _b64u(rawSig),
  };
}

function _ecdsaDerToRaw(der, partSize) {
  // SEQUENCE { INTEGER r, INTEGER s } — strip DER + left-pad to partSize.
  var seq;
  try { seq = asn1.readNode(der, 0); }
  catch (e) {
    throw _err("acme/bad-signature", "ECDSA signature DER parse failed: " + e.message, true);
  }
  if (seq.tag !== 0x10 && seq.tag !== 0x30) {
    throw _err("acme/bad-signature", "ECDSA signature is not a DER SEQUENCE", true);
  }
  var children;
  try { children = asn1.readSequence(seq.value); }
  catch (e) {
    throw _err("acme/bad-signature", "ECDSA signature SEQUENCE walk failed: " + e.message, true);
  }
  if (children.length !== 2) {
    throw _err("acme/bad-signature",
      "ECDSA signature SEQUENCE expected 2 INTEGERs, got " + children.length, true);
  }
  var r = _stripLeadingZero(children[0].value);
  var s = _stripLeadingZero(children[1].value);
  if (r.length > partSize || s.length > partSize) {
    throw _err("acme/bad-signature",
      "ECDSA signature integer exceeds " + partSize + " bytes", true);
  }
  var out = Buffer.alloc(partSize * 2);
  r.copy(out, partSize - r.length);
  s.copy(out, partSize * 2 - s.length);
  return out;
}

function _stripLeadingZero(buf) {
  if (buf.length > 1 && buf[0] === 0x00) return buf.slice(1);
  return buf;
}

// ---- AKI + serial extraction (RFC 9773 §4.1 ACMECertID) ----

function _extractAkiAndSerial(certPem) {
  if (typeof certPem !== "string" || certPem.indexOf("-----BEGIN CERTIFICATE-----") === -1) {
    throw _err("acme/bad-cert", "renewIfDue: certPem must be a PEM-encoded CERTIFICATE", true);
  }
  var x509;
  try { x509 = new nodeCrypto.X509Certificate(certPem); }
  catch (e) {
    throw _err("acme/bad-cert", "X.509 parse failed: " + e.message, true);
  }
  // Serial is exposed as a hex string; strip any leading "0x".
  var serialHex = String(x509.serialNumber || "").replace(/^0x/i, "");
  if (serialHex.length === 0 || (serialHex.length % 2) !== 0) {
    throw _err("acme/bad-cert", "X.509 serialNumber malformed", true);
  }
  var serialBytes = Buffer.from(serialHex, "hex");
  // The AuthorityKeyIdentifier extension OID is 2.5.29.35. Walk the
  // tbsCertificate to find it.
  var aki = _findAkiKeyIdentifier(x509.raw);
  if (!aki) {
    throw _err("acme/no-aki",
      "renewIfDue: cert has no AuthorityKeyIdentifier extension; " +
      "RFC 9773 §4.1 ACMECertID requires AKI keyIdentifier", true);
  }
  return { aki: aki, serial: serialBytes };
}

function _findAkiKeyIdentifier(rawDer) {
  // Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }
  var outer;
  try { outer = asn1.readNode(rawDer, 0); }
  catch (_e) { return null; }
  if (!outer || !outer.constructed) return null;
  var topChildren;
  try { topChildren = asn1.readSequence(outer.value); }
  catch (_e) { return null; }
  if (!topChildren || topChildren.length < 1) return null;
  var tbs = topChildren[0];
  if (!tbs || !tbs.constructed) return null;
  var tbsChildren;
  try { tbsChildren = asn1.readSequence(tbs.value); }
  catch (_e) { return null; }
  // tbsCertificate fields ending with extensions [3] EXPLICIT — find the
  // context-specific [3] tag (tagClass=2, tag=3).
  var extsNode = null;
  for (var i = 0; i < tbsChildren.length; i += 1) {
    var n = tbsChildren[i];
    if (n.tagClass === 2 && n.tag === 3) { extsNode = n; break; }
  }
  if (!extsNode) return null;
  // [3] EXPLICIT wraps a SEQUENCE OF Extension. Unwrap.
  var seqNode;
  try { seqNode = asn1.readNode(extsNode.value, 0); }
  catch (_e) { return null; }
  if (!seqNode || !seqNode.constructed) return null;
  var extList;
  try { extList = asn1.readSequence(seqNode.value); }
  catch (_e) { return null; }
  for (var j = 0; j < extList.length; j += 1) {
    var ext = extList[j];
    if (!ext.constructed) continue;
    var extChildren;
    try { extChildren = asn1.readSequence(ext.value); }
    catch (_e) { continue; }
    if (!extChildren || extChildren.length < 2) continue;
    var oid;
    try { oid = asn1.readOid(extChildren[0]); }
    catch (_e) { continue; }
    if (oid !== "2.5.29.35") continue;
    // extnValue is OCTET STRING containing AuthorityKeyIdentifier ::=
    // SEQUENCE { keyIdentifier [0] IMPLICIT OCTET STRING OPTIONAL, ... }
    var octet = extChildren[extChildren.length - 1];
    var akiSeq;
    try { akiSeq = asn1.readNode(octet.value, 0); }
    catch (_e) { continue; }
    if (!akiSeq.constructed) continue;
    var akiInner;
    try { akiInner = asn1.readSequence(akiSeq.value); }
    catch (_e) { continue; }
    for (var k = 0; k < akiInner.length; k += 1) {
      // [0] IMPLICIT — context-specific tag 0, primitive (OCTET STRING).
      if (akiInner[k].tagClass === 2 && akiInner[k].tag === 0) {
        return Buffer.from(akiInner[k].value);
      }
    }
    return null;
  }
  return null;
}

// ---- ACME client factory ----

/**
 * @primitive b.acme.create
 * @signature b.acme.create(opts)
 * @since     0.7.68
 * @related   b.mtlsCa.create
 *
 * Build an ACME client handle bound to the operator's chosen
 * directory URL and account key. The returned object exposes
 * `fetchDirectory`, `newAccount`, `newOrder`, `finalize`,
 * `retrieveCert`, `revokeCert`, and `renewIfDue` (RFC 9773 ARI). The
 * handle owns nonce management, JWS signing (ES256 per RFC 8555
 * §6.2), polling with an exponential backoff cap, and cert /
 * renewal-window audit emission. Throws `AcmeError` at config-time
 * on bad opts (missing directory URL, missing accountKey, malformed
 * contact list).
 *
 * @opts
 *   directory:        string,                                       // required — CA directory URL (no default)
 *   accountKey:       { privatePem, publicPem, jwk, kty, crv },     // required — ES256 P-256 key material
 *   contact:          Array<string>,                                // optional — mailto: URIs
 *   audit:            object,                                       // optional — b.audit sink for cert.* lifecycle events
 *   timeoutMs:        number,                                       // default 30s — per-HTTP-call timeout
 *   pollIntervalMs:   number,                                       // default 2s — polling interval for order / authorization status
 *   pollMaxMs:        number,                                       // default 5min — total polling cap
 *   maxBytes:         number,                                       // default 2 MiB — response body cap
 *
 * @example
 *   var nodeCrypto = require("crypto");
 *   var pair = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
 *   var acme = b.acme.create({
 *     directory:  "https://acme-staging-v02.api.letsencrypt.org/directory",
 *     accountKey: {
 *       privatePem: pair.privateKey.export({ type: "pkcs8", format: "pem" }),
 *       publicPem:  pair.publicKey.export({ type: "spki", format: "pem" }),
 *       kty:        "EC",
 *       crv:        "P-256",
 *     },
 *     contact: ["mailto:ops@example.com"],
 *   });
 *   typeof acme.fetchDirectory;
 *   // → "function"
 */
function create(opts) {
  if (!opts || typeof opts !== "object") {
    throw _err("acme/bad-opts", "acme.create: opts is required", true);
  }
  validateOpts(opts, [
    "directory", "accountKey", "audit", "contact", "timeoutMs",
    "pollIntervalMs", "pollMaxMs", "maxBytes",
  ], "acme.create");

  validateOpts.requireNonEmptyString(opts.directory,
    "acme.create: directory (the operator's RFC 8555 directory URL — no framework default)",
    AcmeError, "acme/bad-directory");
  // Refuse non-https directories — RFC 8555 §6.1 mandates HTTPS for ACME.
  var dirUrl;
  try {
    dirUrl = safeUrl.parse(opts.directory, {
      allowedProtocols: ["https:"],
      errorClass:       AcmeError,
    });
  } catch (e) {
    throw _err("acme/bad-directory",
      "acme.create: directory must be an https:// URL (RFC 8555 §6.1): " + e.message, true);
  }
  if (!opts.accountKey || typeof opts.accountKey !== "object") {
    throw _err("acme/bad-account-key",
      "acme.create: accountKey object is required (privateKey / publicJwk / KeyObject)", true);
  }

  // Accept either a Node KeyObject or a PEM/JWK and normalize. A
  // KeyObject is identified by `type === "private"` + `asymmetricKeyType`.
  var privateKey = null;
  var publicJwk = null;
  if (opts.accountKey.type === "private" && typeof opts.accountKey.export === "function") {
    privateKey = opts.accountKey;                                                  // already a KeyObject
  } else if (typeof opts.accountKey.privatePem === "string") {
    try { privateKey = nodeCrypto.createPrivateKey(opts.accountKey.privatePem); }
    catch (e) { throw _err("acme/bad-account-key", "accountKey.privatePem parse failed: " + e.message, true); }
  } else if (opts.accountKey.privateKey &&
             opts.accountKey.privateKey.type === "private" &&
             typeof opts.accountKey.privateKey.export === "function") {
    privateKey = opts.accountKey.privateKey;
  } else {
    throw _err("acme/bad-account-key",
      "acme.create: accountKey must carry a Node KeyObject or { privatePem }", true);
  }
  publicJwk = _publicJwkFromKeyObject(privateKey);

  if (opts.contact !== undefined) {
    if (!Array.isArray(opts.contact) || !opts.contact.every(function (c) {
      return typeof c === "string" && c.length > 0 && c.length <= C.BYTES.bytes(256) &&
             /^(mailto|tel):/i.test(c);
    })) {
      throw _err("acme/bad-contact",
        "acme.create: contact must be an array of mailto:/tel: URIs", true);
    }
  }
  var timeoutMs = (typeof opts.timeoutMs === "number" && isFinite(opts.timeoutMs) && opts.timeoutMs > 0)
    ? opts.timeoutMs : DEFAULT_TIMEOUT_MS;
  var pollIntervalMs = (typeof opts.pollIntervalMs === "number" && isFinite(opts.pollIntervalMs) && opts.pollIntervalMs > 0)
    ? opts.pollIntervalMs : DEFAULT_POLL_MS;
  var pollMaxMs = (typeof opts.pollMaxMs === "number" && isFinite(opts.pollMaxMs) && opts.pollMaxMs > 0)
    ? opts.pollMaxMs : DEFAULT_POLL_CAP_MS;
  var maxBytes = (typeof opts.maxBytes === "number" && isFinite(opts.maxBytes) && opts.maxBytes > 0)
    ? opts.maxBytes : DEFAULT_BODY_CAP;

  var audit = opts.audit || null;

  // Mutable state — directory entries, account URL (kid), nonce queue.
  var state = {
    directoryUrl: dirUrl.toString(),
    directory:    null,
    accountUrl:   null,
    nonces:       [],
  };

  // ---- internal: HTTP shapes ----

  async function _httpReq(method, url, body, headers) {
    headers = Object.assign({
      "User-Agent":    "blamejs-acme/1",
      "Accept":        "application/json",
    }, headers || {});
    var req = {
      method:           method,
      url:              url,
      headers:          headers,
      body:             body || undefined,
      timeoutMs:        timeoutMs,
      maxResponseBytes: maxBytes,
      allowedProtocols: ["https:"],
      errorClass:       AcmeError,
    };
    var rsp;
    try { rsp = await httpClient.request(req); }
    catch (e) {
      throw _err("acme/network",
        method + " " + url + " failed: " + (e && e.message),
        false, (e && e.statusCode) || 0);
    }
    // Stash any Replay-Nonce (RFC 8555 §6.5) for the next request.
    var nonce = rsp.headers && (rsp.headers["replay-nonce"] || rsp.headers["Replay-Nonce"]);
    if (typeof nonce === "string" && nonce.length > 0) state.nonces.push(nonce);
    return rsp;
  }

  async function _newNonce() {
    if (state.nonces.length > 0) return state.nonces.shift();
    if (!state.directory || !state.directory.newNonce) {
      throw _err("acme/no-directory",
        "_newNonce: directory must be fetched before signed requests", true);
    }
    var rsp = await _httpReq("HEAD", state.directory.newNonce, null);
    if (rsp.statusCode !== 200 && rsp.statusCode !== 204) {
      throw _err("acme/newnonce-failed",
        "newNonce HEAD returned " + rsp.statusCode, true, rsp.statusCode);
    }
    if (state.nonces.length === 0) {
      throw _err("acme/newnonce-no-header",
        "newNonce response carried no Replay-Nonce header", true, rsp.statusCode);
    }
    return state.nonces.shift();
  }

  async function _signedPost(url, payload, opts2) {
    opts2 = opts2 || {};
    var nonce = await _newNonce();
    var prot = {
      alg:   "ES256",
      nonce: nonce,
      url:   url,
    };
    if (opts2.useJwk || !state.accountUrl) {
      prot.jwk = publicJwk;
    } else {
      prot.kid = state.accountUrl;
    }
    var jws = _signJws(privateKey, prot, payload === null ? "" : payload);
    var rsp = await _httpReq("POST", url, JSON.stringify(jws), {
      "Content-Type": "application/jose+json",
    });
    return rsp;
  }

  // ---- public: directory / account ----

  async function fetchDirectory() {
    var rsp = await _httpReq("GET", state.directoryUrl, null);
    if (rsp.statusCode !== 200) {
      throw _err("acme/directory-fetch",
        "directory GET returned " + rsp.statusCode, true, rsp.statusCode);
    }
    var body = _parseJsonBody(rsp.body, "directory");
    var required = ["newNonce", "newAccount", "newOrder"];
    for (var i = 0; i < required.length; i += 1) {
      if (typeof body[required[i]] !== "string") {
        throw _err("acme/directory-shape",
          "directory missing required field: " + required[i], true);
      }
    }
    state.directory = body;
    _emitAudit(audit, "acme.directory.fetched", "success",
      { directoryUrl: state.directoryUrl, hasAri: typeof body.renewalInfo === "string" });
    _emitObs("acme.directory.fetched", { hasAri: typeof body.renewalInfo === "string" });
    return body;
  }

  async function newAccount(nopts) {
    nopts = nopts || {};
    if (!state.directory) await fetchDirectory();
    var payload = { termsOfServiceAgreed: true };
    if (Array.isArray(opts.contact) && opts.contact.length > 0) payload.contact = opts.contact.slice();
    // RFC 8555 §7.3.4 — External Account Binding (EAB). Required by
    // ZeroSSL / Buypass / Google CA / many other commercial CAs.
    // The operator obtains `kid` + `hmacKey` from the CA's account
    // dashboard and supplies them either via the `externalAccountBinding`
    // opt on newAccount() OR statically on create() opts. The EAB
    // payload is an inner-JWS over the account's public JWK signed
    // with HMAC-SHA256 keyed by the CA-supplied HMAC key.
    var eab = nopts.externalAccountBinding || opts.externalAccountBinding;
    if (eab) {
      if (typeof eab.kid !== "string" || eab.kid.length === 0) {
        throw _err("acme/eab-no-kid",
          "newAccount: externalAccountBinding.kid required (RFC 8555 §7.3.4)", true);
      }
      if (typeof eab.hmacKey !== "string" || eab.hmacKey.length === 0) {
        throw _err("acme/eab-no-hmac",
          "newAccount: externalAccountBinding.hmacKey required (base64url-encoded)", true);
      }
      var eabProtected = {
        alg:  eab.alg || "HS256",
        kid:  eab.kid,
        url:  state.directory.newAccount,
      };
      // Inner JWS: payload = the account's public JWK (RFC 8555 §7.3.4).
      var eabHeaderB64  = _b64u(Buffer.from(_stringify(eabProtected), "utf8"));
      var eabPayloadB64 = _b64u(Buffer.from(_stringify(publicJwk), "utf8"));
      var eabSigningInput = eabHeaderB64 + "." + eabPayloadB64;
      var hmacKeyRaw = Buffer.from(eab.hmacKey, "base64url");
      var hmac = require("node:crypto").createHmac("sha256", hmacKeyRaw);
      hmac.update(eabSigningInput);
      var eabSig = _b64u(hmac.digest());
      payload.externalAccountBinding = {
        protected: eabHeaderB64,
        payload:   eabPayloadB64,
        signature: eabSig,
      };
    }
    var rsp = await _signedPost(state.directory.newAccount, payload, { useJwk: true });
    if (rsp.statusCode !== 200 && rsp.statusCode !== 201) {
      _emitAudit(audit, "acme.account.registered", "failure",
        { status: rsp.statusCode, reason: _extractProblemReason(rsp.body) });
      throw _err("acme/newaccount",
        "newAccount returned " + rsp.statusCode, true, rsp.statusCode);
    }
    var loc = rsp.headers && (rsp.headers["location"] || rsp.headers["Location"]);
    if (typeof loc !== "string" || loc.length === 0) {
      throw _err("acme/newaccount-no-location",
        "newAccount response carried no Location header", true, rsp.statusCode);
    }
    state.accountUrl = loc;
    _emitAudit(audit, "acme.account.registered", "success",
      { accountUrl: loc, contact: payload.contact || [] });
    return { accountUrl: loc, body: _parseJsonBody(rsp.body, "newAccount") };
  }

  // ---- public: order lifecycle ----

  async function newOrder(orderOpts) {
    if (!state.directory) await fetchDirectory();
    if (!state.accountUrl) {
      throw _err("acme/no-account", "newOrder: call newAccount() first", true);
    }
    if (!orderOpts || !Array.isArray(orderOpts.identifiers) || orderOpts.identifiers.length === 0) {
      throw _err("acme/bad-order",
        "newOrder: identifiers[] is required (e.g. [{ type: 'dns', value: 'example.com' }])", true);
    }
    for (var i = 0; i < orderOpts.identifiers.length; i += 1) {
      var id = orderOpts.identifiers[i];
      if (!id || typeof id.type !== "string" || typeof id.value !== "string" ||
          id.type.length === 0 || id.value.length === 0 ||
          id.value.length > C.BYTES.bytes(255)) {
        throw _err("acme/bad-identifier",
          "newOrder: identifier must be { type: string, value: string<=255 }", true);
      }
    }
    var payload = { identifiers: orderOpts.identifiers.slice() };
    if (typeof orderOpts.notBefore === "string") payload.notBefore = orderOpts.notBefore;
    if (typeof orderOpts.notAfter === "string") payload.notAfter = orderOpts.notAfter;
    // draft-aaron-acme-profiles — operator-selected certificate profile.
    // The CA advertises profile names + descriptions via
    // `directory.meta.profiles`; operator passes the chosen name through
    // newOrder. CAs honoring the draft return 400 when the name isn't
    // in the advertised set; ones that haven't adopted the draft ignore
    // the field. v1-defensible scope: refuse non-string + cap length so
    // attacker-supplied profile values can't bloat the JSON payload.
    if (typeof orderOpts.profile === "string") {
      if (orderOpts.profile.length === 0 || orderOpts.profile.length > C.BYTES.bytes(64)) {
        throw _err("acme/bad-profile",
          "newOrder: profile name must be a non-empty string <= 64 bytes", true);
      }
      payload.profile = orderOpts.profile;
    } else if (orderOpts.profile !== undefined) {
      throw _err("acme/bad-profile",
        "newOrder: profile must be a string when provided", true);
    }
    var rsp = await _signedPost(state.directory.newOrder, payload);
    if (rsp.statusCode !== 201) {
      _emitAudit(audit, "acme.order.created", "failure",
        { status: rsp.statusCode, reason: _extractProblemReason(rsp.body) });
      throw _err("acme/neworder",
        "newOrder returned " + rsp.statusCode, true, rsp.statusCode);
    }
    var orderUrl = rsp.headers && (rsp.headers["location"] || rsp.headers["Location"]);
    var order = _parseJsonBody(rsp.body, "newOrder");
    order.url = orderUrl;
    _emitAudit(audit, "acme.order.created", "success",
      { orderUrl: orderUrl, identifiers: payload.identifiers });
    return order;
  }

  async function finalize(order, csrDerOrPem) {
    if (!order || typeof order !== "object" || typeof order.finalize !== "string") {
      throw _err("acme/bad-order", "finalize: order.finalize URL is required", true);
    }
    var csrDer;
    if (Buffer.isBuffer(csrDerOrPem)) {
      csrDer = csrDerOrPem;
    } else if (typeof csrDerOrPem === "string" &&
               csrDerOrPem.indexOf("-----BEGIN CERTIFICATE REQUEST-----") !== -1) {
      var b64 = csrDerOrPem
        .replace(/-----BEGIN CERTIFICATE REQUEST-----/, "")
        .replace(/-----END CERTIFICATE REQUEST-----/, "")
        .replace(/\s+/g, "");
      try { csrDer = Buffer.from(b64, "base64"); }
      catch (e) { throw _err("acme/bad-csr", "CSR base64 decode failed: " + e.message, true); }
    } else {
      throw _err("acme/bad-csr", "finalize: csr must be a DER Buffer or PEM string", true);
    }
    if (csrDer.length === 0 || csrDer.length > C.BYTES.kib(64)) {
      throw _err("acme/bad-csr",
        "finalize: CSR DER size out of range (got " + csrDer.length + " bytes)", true);
    }
    var payload = { csr: _b64u(csrDer) };
    var rsp = await _signedPost(order.finalize, payload);
    if (rsp.statusCode < 200 || rsp.statusCode >= 300) {
      _emitAudit(audit, "acme.order.finalize", "failure",
        { orderUrl: order.url, status: rsp.statusCode, reason: _extractProblemReason(rsp.body) });
      throw _err("acme/finalize",
        "finalize returned " + rsp.statusCode, true, rsp.statusCode);
    }
    var updated = _parseJsonBody(rsp.body, "finalize");
    updated.url = order.url;
    _emitAudit(audit, "acme.order.finalize", "success",
      { orderUrl: order.url, status: updated.status });
    return updated;
  }

  async function retrieveCert(order) {
    if (!order || typeof order !== "object" || typeof order.url !== "string") {
      throw _err("acme/bad-order", "retrieveCert: order.url is required", true);
    }
    var deadline = Date.now() + pollMaxMs;
    var current = order;
    while (true) {
      if (current.status === "valid" && typeof current.certificate === "string") break;
      if (current.status === "invalid") {
        _emitAudit(audit, "acme.order.poll", "failure",
          { orderUrl: current.url, status: "invalid" });
        throw _err("acme/order-invalid",
          "retrieveCert: order is invalid", true);
      }
      if (Date.now() >= deadline) {
        throw _err("acme/order-timeout",
          "retrieveCert: order did not reach 'valid' within " + pollMaxMs + "ms", true);
      }
      await _sleep(pollIntervalMs);
      var rsp = await _signedPost(current.url, null);
      if (rsp.statusCode < 200 || rsp.statusCode >= 300) {
        throw _err("acme/order-poll",
          "order poll returned " + rsp.statusCode, true, rsp.statusCode);
      }
      current = _parseJsonBody(rsp.body, "order-poll");
      current.url = order.url;
    }
    var certRsp = await _signedPost(current.certificate, null);
    if (certRsp.statusCode !== 200) {
      _emitAudit(audit, "acme.cert.issued", "failure",
        { orderUrl: order.url, status: certRsp.statusCode });
      throw _err("acme/cert-download",
        "certificate download returned " + certRsp.statusCode, true, certRsp.statusCode);
    }
    var pem = certRsp.body && certRsp.body.toString("utf8");
    if (typeof pem !== "string" || pem.indexOf("-----BEGIN CERTIFICATE-----") === -1) {
      throw _err("acme/bad-cert-bytes",
        "certificate body is not PEM-encoded", true, certRsp.statusCode);
    }
    _emitAudit(audit, "acme.cert.issued", "success",
      { orderUrl: order.url, bytes: pem.length });
    _emitObs("acme.cert.issued", { bytes: pem.length });
    return pem;
  }

  // ---- public: RFC 9773 ARI ----

  async function fetchAri(opts2) {
    // Validate cert input BEFORE any network call so misconfigured
    // operators see the bad-cert error without burning a directory
    // round-trip first.
    if (!opts2 || typeof opts2.certPem !== "string") {
      throw _err("acme/bad-ari-input", "fetchAri: certPem is required", true);
    }
    var ext = _extractAkiAndSerial(opts2.certPem);
    if (!state.directory) await fetchDirectory();
    if (typeof state.directory.renewalInfo !== "string") {
      throw _err("acme/no-ari",
        "fetchAri: directory has no renewalInfo endpoint (RFC 9773 not supported by this CA)", true);
    }
    var certId = _b64u(ext.aki) + "." + _b64u(ext.serial);
    var ariUrl = state.directory.renewalInfo.replace(/\/+$/, "") + "/" + certId;
    var rsp = await _httpReq("GET", ariUrl, null);
    if (rsp.statusCode !== 200) {
      throw _err("acme/ari-fetch",
        "ARI GET returned " + rsp.statusCode, true, rsp.statusCode);
    }
    var body = _parseJsonBody(rsp.body, "ari");
    if (!body.suggestedWindow || typeof body.suggestedWindow.start !== "string" ||
        typeof body.suggestedWindow.end !== "string") {
      throw _err("acme/ari-shape",
        "ARI response missing suggestedWindow {start,end}", true);
    }
    var startMs = Date.parse(body.suggestedWindow.start);
    var endMs   = Date.parse(body.suggestedWindow.end);
    if (!isFinite(startMs) || !isFinite(endMs) || endMs < startMs) {
      throw _err("acme/ari-shape",
        "ARI suggestedWindow timestamps malformed", true);
    }
    var retryAfterHeader = rsp.headers && (rsp.headers["retry-after"] || rsp.headers["Retry-After"]);
    return {
      suggestedWindow: { start: body.suggestedWindow.start, end: body.suggestedWindow.end,
                         startMs: startMs, endMs: endMs },
      explanationURL:  typeof body.explanationURL === "string" ? body.explanationURL : null,
      retryAfter:      typeof retryAfterHeader === "string" ? retryAfterHeader : null,
      certId:          certId,
      ariUrl:          ariUrl,
    };
  }

  async function renewIfDue(opts2) {
    var ari = await fetchAri(opts2);
    var nowMs = Date.now();
    // RFC 9773 §4.2 — when called inside the suggested window, return
    // a renewAt timestamp picked uniformly across the remaining window
    // so a fleet of operators running on the same poll cadence don't
    // cluster their renewal storms at the window-start instant. Operators
    // opt in via `{ jitter: true }`; default behavior preserves the
    // pre-0.8.83 "renew now" semantics.
    var jitter   = opts2 && opts2.jitter === true;
    var beforeWindow = nowMs < ari.suggestedWindow.startMs;
    var pastWindow   = nowMs > ari.suggestedWindow.endMs;
    var renewAtMs    = null;
    if (jitter) {
      // Uniform random point in [max(now, start), end].
      var jLo = beforeWindow ? ari.suggestedWindow.startMs : nowMs;
      var jHi = ari.suggestedWindow.endMs;
      if (jHi >= jLo) {
        // Non-crypto: RFC 9773 §4.2 fleet-scheduling jitter inside the
        // CA-suggested renewal window. Predictability is not a threat
        // here; uniform distribution across the window is the goal.
        renewAtMs = jLo + Math.floor(Math.random() * (jHi - jLo + 1));   // allow:math-random-noncrypto — RFC 9773 fleet jitter, predictability not a threat
      } else {
        // Past-window — renew immediately, no jitter.
        renewAtMs = nowMs;
      }
    }
    if (beforeWindow) {
      _emitAudit(audit, "acme.cert.renew.skipped", "success", {
        certId:         ari.certId,
        windowStart:    ari.suggestedWindow.start,
        windowEnd:      ari.suggestedWindow.end,
        nowIso:         new Date(nowMs).toISOString(),
      });
      _emitObs("acme.cert.renew.skipped", { reason: "before-window" });
      var ret = { shouldRenew: false, reason: "before-window", ari: ari };
      if (jitter) ret.renewAt = new Date(renewAtMs).toISOString();
      return ret;
    }
    if (pastWindow) {
      _emitAudit(audit, "acme.cert.renew.scheduled", "warning", {
        certId:         ari.certId,
        reason:         "past-window",
        windowEnd:      ari.suggestedWindow.end,
      });
      _emitObs("acme.cert.renew.scheduled", { reason: "past-window" });
      var rp = { shouldRenew: true, reason: "past-window", ari: ari };
      if (jitter) rp.renewAt = new Date(renewAtMs).toISOString();
      return rp;
    }
    _emitAudit(audit, "acme.cert.renew.scheduled", "success", {
      certId:         ari.certId,
      windowStart:    ari.suggestedWindow.start,
      windowEnd:      ari.suggestedWindow.end,
      renewAt:        jitter ? new Date(renewAtMs).toISOString() : null,
    });
    _emitObs("acme.cert.renew.scheduled", { reason: "in-window" });
    var ri = { shouldRenew: true, reason: "in-window", ari: ari };
    if (jitter) ri.renewAt = new Date(renewAtMs).toISOString();
    return ri;
  }

  /**
   * @primitive b.acme.create.revokeCert
   * @signature b.acme.create.revokeCert(certDerBuf, opts?)
   * @since     0.8.77
   *
   * RFC 8555 §7.6 — revoke a previously issued certificate. Accepts
   * the DER-encoded cert (base64url-encoded automatically) plus an
   * optional `reason` code per RFC 5280 §5.3.1 (0=unspecified,
   * 1=keyCompromise, 3=affiliationChanged, 4=superseded, 5=cessationOfOperation).
   * Signs with the account key by default; pass `useCertKey:true`
   * + the cert's private key to authorize via the cert's own key
   * when the account key is unavailable.
   *
   * @opts
   *   reason:          number,    // RFC 5280 §5.3.1 reason code; default 0 (unspecified)
   *   useCertKey:      boolean,   // sign with the cert's own key instead of account key
   *   certPrivateKey:  KeyObject, // required when useCertKey:true
   *
   * @example
   *   await acme.revokeCert(certDerBuffer, { reason: 4 });   // 4 = superseded
   */
  async function revokeCert(certDerBuf, ropts) {
    ropts = ropts || {};
    if (!Buffer.isBuffer(certDerBuf) && !(certDerBuf instanceof Uint8Array)) {
      throw _err("acme/revoke-bad-cert",
        "revokeCert: certDerBuf must be a Buffer / Uint8Array of the cert's DER bytes", true);
    }
    if (!state.directory) await fetchDirectory();
    if (!state.directory.revokeCert) {
      throw _err("acme/revoke-not-supported",
        "revokeCert: directory has no revokeCert endpoint", true);
    }
    var payload = { certificate: _b64u(Buffer.from(certDerBuf)) };
    if (typeof ropts.reason === "number") payload.reason = ropts.reason;
    var signedOpts = { useJwk: false };                  // account-key signed by default
    if (ropts.useCertKey === true) {
      // RFC 8555 §7.6 alternate: certificate's own key as signer. Operator
      // supplies the cert's private key via ropts.certPrivateKey; we
      // build a one-off signed-post bypassing _signedPost's state.accountUrl
      // assumption. For minimal v1 we support account-key signing only and
      // document the cert-key path as not-yet-implemented.
      throw _err("acme/revoke-cert-key-not-implemented",
        "revokeCert: cert-key signing path not yet implemented; use account-key signing", true);
    }
    var rsp = await _signedPost(state.directory.revokeCert, payload, signedOpts);
    if (rsp.statusCode !== 200) {
      _emitAudit(audit, "acme.cert.revoked", "failure",
        { status: rsp.statusCode, reason: _extractProblemReason(rsp.body) });
      throw _err("acme/revoke-failed",
        "revokeCert returned " + rsp.statusCode, true, rsp.statusCode);
    }
    _emitAudit(audit, "acme.cert.revoked", "success", { reason: ropts.reason || null });
    _emitObs("acme.cert.revoked", { reason: ropts.reason || 0 });
    return true;
  }

  /**
   * @primitive b.acme.create.accountKeyRollover
   * @signature b.acme.create.accountKeyRollover(newPrivateKey)
   * @since     0.8.77
   *
   * RFC 8555 §7.3.5 — rotate the account key. Inner JWS payload
   * commits the old + new public JWKs; outer JWS signed by old key
   * authorizes the rotation. After success, future signed-posts use
   * the new key. The instance is mutated; callers using multiple
   * acme instances must rotate each independently.
   *
   * @example
   *   var newKey = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" }).privateKey;
   *   await acme.accountKeyRollover(newKey);
   */
  async function accountKeyRollover(newPrivateKey) {
    if (!state.directory) await fetchDirectory();
    if (!state.accountUrl) {
      throw _err("acme/no-account", "accountKeyRollover: call newAccount() first", true);
    }
    if (!state.directory.keyChange) {
      throw _err("acme/key-change-not-supported",
        "accountKeyRollover: directory has no keyChange endpoint", true);
    }
    if (!newPrivateKey || typeof newPrivateKey !== "object") {
      throw _err("acme/bad-new-key", "accountKeyRollover: newPrivateKey must be a KeyObject", true);
    }
    var newPublicJwk = _publicJwkFromKeyObject(newPrivateKey);
    var innerProtected = {
      alg: opts.alg || "ES256",
      jwk: newPublicJwk,
      url: state.directory.keyChange,
    };
    var innerPayload = { account: state.accountUrl, oldKey: publicJwk };
    var innerJws = _signJws(newPrivateKey, innerProtected, _stringify(innerPayload));
    var rsp = await _signedPost(state.directory.keyChange, innerJws);
    if (rsp.statusCode !== 200) {
      _emitAudit(audit, "acme.account.key_rotated", "failure",
        { status: rsp.statusCode, reason: _extractProblemReason(rsp.body) });
      throw _err("acme/key-change-failed",
        "accountKeyRollover returned " + rsp.statusCode, true, rsp.statusCode);
    }
    // Swap the active key.
    privateKey = newPrivateKey;
    publicJwk  = newPublicJwk;
    _emitAudit(audit, "acme.account.key_rotated", "success", { accountUrl: state.accountUrl });
    _emitObs("acme.account.key_rotated", {});
    return true;
  }

  /**
   * @primitive b.acme.create.deactivateAccount
   * @signature b.acme.create.deactivateAccount()
   * @since     0.8.77
   *
   * RFC 8555 §7.3.6 — deactivate the account. The CA refuses subsequent
   * requests signed by this account key. Irreversible — operators must
   * register a new account via newAccount() afterwards.
   *
   * @example
   *   await acme.deactivateAccount();
   */
  async function deactivateAccount() {
    if (!state.accountUrl) {
      throw _err("acme/no-account", "deactivateAccount: call newAccount() first", true);
    }
    var rsp = await _signedPost(state.accountUrl, { status: "deactivated" });
    if (rsp.statusCode !== 200) {
      _emitAudit(audit, "acme.account.deactivated", "failure",
        { status: rsp.statusCode, reason: _extractProblemReason(rsp.body) });
      throw _err("acme/deactivate-failed",
        "deactivateAccount returned " + rsp.statusCode, true, rsp.statusCode);
    }
    _emitAudit(audit, "acme.account.deactivated", "success", { accountUrl: state.accountUrl });
    return true;
  }

  /**
   * @primitive b.acme.create.tlsAlpn01KeyAuthorization
   * @signature b.acme.create.tlsAlpn01KeyAuthorization(token)
   * @since     0.8.77
   *
   * RFC 8737 — TLS-ALPN-01 challenge variant. Returns the SHA-256
   * digest of the key authorization (the value the operator embeds
   * in the `acme-tls/1` SNI cert's `id-pe-acmeIdentifier` extension).
   * Operator wires the digest into a one-off cert presented during
   * the CA's ALPN-ALPN-1 probe. Pairs with HTTP-01 + DNS-01 as the
   * three RFC 8555 / RFC 8737 challenge types.
   *
   * @example
   *   var digest = acme.tlsAlpn01KeyAuthorization(challengeToken);
   *   // embed `digest` in the acme-tls/1 cert's acmeIdentifier extension.
   */
  function tlsAlpn01KeyAuthorization(token) {
    if (typeof token !== "string" || token.length === 0) {
      throw _err("acme/bad-token", "tlsAlpn01KeyAuthorization: token must be a non-empty string", true);
    }
    var keyAuth = token + "." + _jwkThumbprint(publicJwk);
    var nodeCrypto  = require("node:crypto");
    return nodeCrypto.createHash("sha256").update(keyAuth, "utf8").digest();
  }

  /**
   * @primitive b.acme.create.listProfiles
   * @signature b.acme.create.listProfiles()
   * @since     0.8.83
   * @status    experimental
   *
   * Returns the CA-advertised certificate profile catalog as
   * `{ name: description }` per draft-aaron-acme-profiles. Operators
   * pass the chosen name through `newOrder({ profile: name })`; CAs
   * use the profile to select certificate lifetime + key-usage +
   * validation rigor. As CA/B Forum 47-day cert TTLs phase in (Mar
   * 2026 ballot SC-081v3), profile-name vocabulary becomes the
   * operator-facing handle for "long-lived" vs "47-day" vs "short-
   * lived". Returns an empty object when the directory has no
   * `meta.profiles` map (CA hasn't adopted the draft). Refreshes the
   * directory cache when none has been fetched yet.
   *
   * @example
   *   await acme.fetchDirectory();
   *   var profiles = acme.listProfiles();
   *   // → { "default": "Standard 90-day certificate",
   *   //     "shortlived": "47-day certificate (CA/B Forum SC-081v3)",
   *   //     "tlsserver":  "TLS server profile with Must-Staple" }
   *
   *   await acme.newOrder({ identifiers: [{ type: "dns", value: "example.com" }],
   *                          profile: "shortlived" });
   */
  function listProfiles() {
    if (!state.directory) return {};
    var meta = state.directory.meta;
    if (!meta || typeof meta !== "object") return {};
    var profiles = meta.profiles;
    if (!profiles || typeof profiles !== "object") return {};
    var out = {};
    var keys = Object.keys(profiles);
    for (var i = 0; i < keys.length; i += 1) {
      var k = keys[i];
      var v = profiles[k];
      out[k] = typeof v === "string" ? v : "";
    }
    return out;
  }

  /**
   * @primitive b.acme.create.dnsAccount01ChallengeRecord
   * @signature b.acme.create.dnsAccount01ChallengeRecord(token, opts?)
   * @since     0.8.83
   * @status    experimental
   * @related   b.acme.create.tlsAlpn01KeyAuthorization
   *
   * Build the DNS TXT record an operator publishes to satisfy a
   * `dns-account-01` challenge per draft-ietf-acme-dns-account-label.
   * Unlike `dns-01` (record at `_acme-challenge.<host>`),
   * `dns-account-01` scopes the record by account so the same domain
   * can be validated from multiple ACME accounts without record-name
   * collisions; the record name becomes
   * `_<accountLabel>._acme-challenge.<identifier>` where
   * `accountLabel` is the SHA-256 truncated-base32 of the account URL.
   *
   * Returns `{ name, value, ttl }` where `name` is the FQDN to publish
   * the TXT record at (with operator-supplied `identifier` substituted
   * in) and `value` is the SHA-256 of the key authorization in
   * unpadded base64url (same as `dns-01`). Refuses when `newAccount`
   * has not run (no accountUrl yet); refuses non-string token /
   * identifier.
   *
   * @opts
   *   identifier: string,   // host being validated (required)
   *   ttl:        number,   // suggested DNS TTL in seconds; default: 60
   *
   * @example
   *   await acme.newAccount({ contact: ["mailto:ops@example.com"] });
   *   var rec = acme.dnsAccount01ChallengeRecord("token123", {
   *     identifier: "example.com",
   *   });
   *   // rec.name  → "_<accountLabel>._acme-challenge.example.com"
   *   // rec.value → "<base64url-of-sha256(token123.<thumbprint>)>"
   *   // rec.ttl   → 60
   */
  function dnsAccount01ChallengeRecord(token, opts2) {
    if (typeof token !== "string" || token.length === 0) {
      throw _err("acme/bad-token", "dnsAccount01ChallengeRecord: token must be a non-empty string", true);
    }
    if (!opts2 || typeof opts2 !== "object" || typeof opts2.identifier !== "string" || opts2.identifier.length === 0) {
      throw _err("acme/bad-identifier", "dnsAccount01ChallengeRecord: opts.identifier (host) is required", true);
    }
    if (opts2.identifier.length > C.BYTES.bytes(255)) {
      throw _err("acme/bad-identifier", "dnsAccount01ChallengeRecord: identifier exceeds 255 bytes", true);
    }
    if (!state.accountUrl) {
      throw _err("acme/no-account",
        "dnsAccount01ChallengeRecord: newAccount() must run first (account URL is the label seed)", true);
    }
    if (opts2.ttl !== undefined && (typeof opts2.ttl !== "number" || !isFinite(opts2.ttl) || opts2.ttl < 1 || opts2.ttl > C.TIME.hours(24) / C.TIME.seconds(1))) {
      throw _err("acme/bad-ttl",
        "dnsAccount01ChallengeRecord: ttl must be a positive integer <= 86400 seconds", true);
    }
    var nodeCrypto = require("node:crypto");
    // Account label: lowercase base32 of first 10 bytes of SHA-256(accountUrl)
    // (per draft-ietf-acme-dns-account-label §3.1 — 80-bit truncated label).
    var hash = nodeCrypto.createHash("sha256").update(state.accountUrl, "utf8").digest();
    var label = _base32lc(hash.subarray(0, 10));
    // Record value: same key-authorization digest shape as dns-01.
    var keyAuth = token + "." + _jwkThumbprint(publicJwk);
    var digest  = nodeCrypto.createHash("sha256").update(keyAuth, "utf8").digest();
    return {
      name:  "_" + label + "._acme-challenge." + opts2.identifier,
      value: _b64u(digest),
      ttl:   typeof opts2.ttl === "number" ? Math.floor(opts2.ttl) : (C.TIME.minutes(1) / C.TIME.seconds(1)),
    };
  }

  return Object.freeze({
    fetchDirectory:  fetchDirectory,
    newAccount:      newAccount,
    newOrder:        newOrder,
    finalize:        finalize,
    retrieveCert:    retrieveCert,
    fetchAri:        fetchAri,
    renewIfDue:      renewIfDue,
    revokeCert:      revokeCert,
    accountKeyRollover: accountKeyRollover,
    deactivateAccount:  deactivateAccount,
    tlsAlpn01KeyAuthorization: tlsAlpn01KeyAuthorization,
    listProfiles:    listProfiles,
    dnsAccount01ChallengeRecord: dnsAccount01ChallengeRecord,
    accountUrl:      function () { return state.accountUrl; },
    directory:       function () { return state.directory; },
    publicJwk:       function () { return Object.assign({}, publicJwk); },
    keyAuthorization: function (token) {
      // RFC 8555 §8.1 — token + "." + base64url(SHA-256(JWK thumbprint)).
      if (typeof token !== "string" || token.length === 0) {
        throw _err("acme/bad-token", "keyAuthorization: token must be a non-empty string", true);
      }
      return token + "." + _jwkThumbprint(publicJwk);
    },
  });
}

// ---- helpers ----

function _parseJsonBody(body, where) {
  if (!body) return {};
  var s = Buffer.isBuffer(body) ? body.toString("utf8") : String(body);
  if (s.length === 0) return {};
  var parsed;
  try {
    parsed = safeJson.parse(s, { maxBytes: DEFAULT_BODY_CAP });
  } catch (e) {
    throw _err("acme/bad-json", where + " response is not valid JSON: " + e.message, true);
  }
  if (parsed && typeof parsed === "object") return parsed;
  throw _err("acme/bad-json", where + " response is not a JSON object", true);
}

function _extractProblemReason(body) {
  // RFC 7807 application/problem+json
  if (!body) return null;
  try {
    var parsed = _parseJsonBody(body, "problem");
    return (typeof parsed.type === "string" ? parsed.type : null) ||
           (typeof parsed.detail === "string" ? parsed.detail : null) ||
           (typeof parsed.title === "string" ? parsed.title : null);
  } catch (_e) { return null; }
}

function _sleep(ms) {
  return new Promise(function (resolve) {
    var t = setTimeout(resolve, ms);
    if (t && typeof t.unref === "function") t.unref();
  });
}

// RFC 4648 §6 base32 lowercase (no padding) — used by
// draft-ietf-acme-dns-account-label to derive the 80-bit account label
// from SHA-256(accountUrl). 5-bit groups MSB-first.
function _base32lc(buf) {
  var alphabet = "abcdefghijklmnopqrstuvwxyz234567";
  var out = "";
  var bits = 0;
  var value = 0;
  for (var i = 0; i < buf.length; i += 1) {
    value = (value << 8) | buf[i];   // allow:raw-byte-literal — bit-shift count, byte boundary
    bits += 8;                       // allow:raw-byte-literal — bits-per-byte constant
    while (bits >= 5) {
      out += alphabet[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) {
    out += alphabet[(value << (5 - bits)) & 31];
  }
  return out;
}

module.exports = {
  create:    create,
  AcmeError: AcmeError,
};
