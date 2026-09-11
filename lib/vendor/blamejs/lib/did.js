// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module b.did
 * @nav    Crypto
 * @title  Decentralized Identifiers (DID)
 *
 * @intro
 *   Resolve W3C Decentralized Identifiers (DID Core 1.0, a W3C
 *   Recommendation) to verification keys — the missing link that lets a
 *   credential's issuer be named by a DID rather than a raw key. Resolve
 *   the issuer DID of a <code>b.vc</code> / <code>b.mdoc</code> /
 *   <code>b.scitt</code> credential to a <code>node:crypto</code>
 *   KeyObject, then hand that key to the verifier.
 *
 *   Three methods are supported. <strong>did:key</strong> encodes a
 *   public key directly in the identifier (multicodec + base58btc
 *   multibase) and <strong>did:jwk</strong> encodes it as a base64url
 *   public JWK — both resolve deterministically and offline (Ed25519,
 *   P-256, P-384, and secp256k1 round-trip). <strong>did:web</strong>
 *   places the DID document at an HTTPS URL derived from the identifier;
 *   the network fetch is the operator's to make (the same
 *   operator-supplied-input stance as the rest of the framework), and
 *   <code>resolve</code> takes the fetched document and extracts its
 *   verification methods.
 *
 *   <code>b.did.keyToDid(publicKey)</code> produces a did:key from a
 *   KeyObject (an issuer naming itself); <code>b.did.parse(did)</code>
 *   splits the identifier (and, for did:web, returns the HTTPS URL to
 *   fetch); <code>b.did.resolve(did, opts)</code> returns the DID
 *   document and its verification methods as KeyObjects. Verification
 *   methods expressed as <code>publicKeyMultibase</code> or
 *   <code>publicKeyJwk</code> are both understood.
 *
 *   <strong>Maturity.</strong> DID Core 1.0 is a Recommendation, but the
 *   method specs are deployed-stable rather than Recommendations:
 *   did:key is a W3C CCG report and did:web is a registered DID method
 *   (mandated by the EU Digital Identity Wallet). They are widely
 *   deployed and interoperable today; pin the dependency deliberately.
 *
 * @card
 *   W3C DID resolution (did:key + did:jwk + did:web) → verification
 *   KeyObjects for the credential verifiers. did:key + did:jwk are
 *   deterministic + offline (Ed25519 / P-256 / P-384 / secp256k1);
 *   did:web parses an operator-fetched DID document. Composes
 *   node:crypto; no new dep.
 */

var nodeCrypto = require("node:crypto");
var bCrypto = require("./crypto");
var safeJson = require("./safe-json");
var validateOpts = require("./validate-opts");
var { defineClass } = require("./framework-error");

var DidError = defineClass("DidError", { alwaysPermanent: true });

var B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
var B58_MAP = (function () {
  var m = {};
  for (var i = 0; i < B58_ALPHABET.length; i += 1) m[B58_ALPHABET[i]] = i;
  return m;
})();
var MAX_MULTIBASE_CHARS = 1024;
var MAX_JWK_B64_CHARS = 8192;

var MULTICODEC = {
  0xed:   { name: "Ed25519",   kind: "okp" },
  0x1200: { name: "P-256",     kind: "ec", curveOid: "1.2.840.10045.3.1.7" },
  0x1201: { name: "P-384",     kind: "ec", curveOid: "1.3.132.0.34" },
  0xe7:   { name: "secp256k1", kind: "ec", curveOid: "1.3.132.0.10" },
};
var NAME_TO_CODE = {};
Object.keys(MULTICODEC).forEach(function (c) { NAME_TO_CODE[MULTICODEC[c].name] = Number(c); });

function _b58decode(str) {
  if (str.length > MAX_MULTIBASE_CHARS) {
    throw new DidError("did/too-long", "did: multibase value exceeds the " + MAX_MULTIBASE_CHARS + "-char cap");
  }
  var bytes = [0];
  for (var i = 0; i < str.length; i += 1) {
    var v = B58_MAP[str[i]];
    if (v === undefined) throw new DidError("did/bad-base58", "did: invalid base58btc character '" + str[i] + "'");
    var carry = v;
    for (var j = 0; j < bytes.length; j += 1) {
      carry += bytes[j] * 58;
      bytes[j] = carry & 0xff;
      carry >>= 8;
    }
    while (carry > 0) { bytes.push(carry & 0xff); carry >>= 8; }
  }
  for (var k = 0; k < str.length && str[k] === "1"; k += 1) bytes.push(0);
  return Buffer.from(bytes.reverse());
}

function _b58encode(buf) {
  var digits = [0];
  for (var i = 0; i < buf.length; i += 1) {
    var carry = buf[i];
    for (var j = 0; j < digits.length; j += 1) {
      carry += digits[j] << 8;
      digits[j] = carry % 58;
      carry = (carry / 58) | 0;
    }
    while (carry > 0) { digits.push(carry % 58); carry = (carry / 58) | 0; }
  }
  var out = "";
  for (var z = 0; z < buf.length && buf[z] === 0; z += 1) out += "1";
  for (var d = digits.length - 1; d >= 0; d -= 1) out += B58_ALPHABET[digits[d]];
  return out;
}

function _readVarint(buf) {
  var value = 0, shift = 0, len = 0;
  for (var i = 0; i < buf.length && i < 4; i += 1) {
    var b = buf[i];
    value |= (b & 0x7f) << shift;
    len += 1;
    if ((b & 0x80) === 0) return { value: value >>> 0, length: len };
    shift += 7;
  }
  throw new DidError("did/bad-multicodec", "did: multicodec varint did not terminate");
}
function _encodeVarint(code) {
  var out = [];
  var n = code;
  do { var b = n & 0x7f; n >>>= 7; if (n > 0) b |= 0x80; out.push(b); } while (n > 0);
  return Buffer.from(out);
}

var ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

function _keyObjectFromMulticodec(code, keyBytes) {
  var desc = MULTICODEC[code];
  if (!desc) throw new DidError("did/unsupported-key", "did: unsupported multicodec key code 0x" + code.toString(16));
  if (desc.kind === "okp") {
    if (keyBytes.length !== 32) {
      throw new DidError("did/bad-key", "did: Ed25519 key must be 32 bytes (got " + keyBytes.length + ")");
    }
    return nodeCrypto.createPublicKey({ key: Buffer.concat([ED25519_SPKI_PREFIX, keyBytes]), format: "der", type: "spki" });
  }
  if (keyBytes.length < 2 || (keyBytes[0] !== 0x02 && keyBytes[0] !== 0x03)) {
    throw new DidError("did/bad-key", "did: EC key must be a compressed point (0x02/0x03 prefix)");
  }
  var algid = _ecAlgId(desc.curveOid);
  var bitstr = Buffer.concat([Buffer.from([0x03, keyBytes.length + 1, 0x00]), keyBytes]);
  var body = Buffer.concat([algid, bitstr]);
  var spki = Buffer.concat([Buffer.from([0x30, body.length]), body]);
  try { return nodeCrypto.createPublicKey({ key: spki, format: "der", type: "spki" }); }
  catch (e) { throw new DidError("did/bad-key", "did: could not import EC key: " + ((e && e.message) || e)); }
}

function _ecAlgId(curveOid) {
  var idEcPublicKey = Buffer.from("06072a8648ce3d0201", "hex");
  var curve = _oidDer(curveOid);
  var inner = Buffer.concat([idEcPublicKey, curve]);
  return Buffer.concat([Buffer.from([0x30, inner.length]), inner]);
}
function _oidDer(dotted) {
  var parts = dotted.split(".").map(Number);
  var bytes = [parts[0] * 40 + parts[1]];
  for (var i = 2; i < parts.length; i += 1) {
    var arc = parts[i], stack = [];
    do { stack.unshift(arc & 0x7f); arc >>>= 7; } while (arc > 0);
    for (var j = 0; j < stack.length - 1; j += 1) stack[j] |= 0x80;
    bytes = bytes.concat(stack);
  }
  return Buffer.concat([Buffer.from([0x06, bytes.length]), Buffer.from(bytes)]);
}

function _compressedPoint(jwk) {
  var x = Buffer.from(jwk.x, "base64url");
  var y = Buffer.from(jwk.y, "base64url");
  return Buffer.concat([Buffer.from([(y[y.length - 1] & 1) ? 0x03 : 0x02]), x]);
}

/**
 * @primitive b.did.parse
 * @signature b.did.parse(did)
 * @since     0.12.41
 * @status    experimental
 * @related   b.did.resolve, b.did.keyToDid
 *
 * Split a DID string into its method and method-specific id. For
 * <code>did:web</code> the HTTPS URL of the DID document is also
 * returned (host[:port][:path] → <code>https://host/path/did.json</code>,
 * or <code>/.well-known/did.json</code> with no path).
 *
 * @example
 *   b.did.parse("did:web:example.com:issuers:42");
 *   // → { method: "web", id: "example.com:issuers:42", url: "https://example.com/issuers/42/did.json" }
 */
function parse(did) {
  if (typeof did !== "string" || did.indexOf("did:") !== 0) {
    throw new DidError("did/bad-did", "did.parse: not a DID (must start with 'did:')");
  }
  var rest = did.slice(4);
  var colon = rest.indexOf(":");
  if (colon <= 0) throw new DidError("did/bad-did", "did.parse: DID is missing a method-specific id");
  var method = rest.slice(0, colon);
  var id = rest.slice(colon + 1);
  var out = { method: method, id: id };
  if (method === "web") out.url = _didWebUrl(id);
  return out;
}

function _didWebUrl(id) {
  var segs = id.split(":");
  var host = segs[0].replace(/%3[Aa]/g, ":");
  if (!host) throw new DidError("did/bad-did", "did:web: missing host");
  var path = segs.slice(1);
  var base = "https://" + host;
  return path.length ? base + "/" + path.join("/") + "/did.json" : base + "/.well-known/did.json";
}

/**
 * @primitive b.did.keyToDid
 * @signature b.did.keyToDid(publicKey, opts?)
 * @since     0.12.41
 * @status    experimental
 * @related   b.did.resolve
 *
 * Encode a public key (a <code>node:crypto</code> KeyObject or PEM) as a
 * DID — the inverse of resolution, for an issuer that names itself by
 * its key. Defaults to <code>did:key</code> (multicodec + base58btc);
 * pass <code>opts.method = "jwk"</code> for <code>did:jwk</code>
 * (base64url-encoded public JWK). Ed25519, P-256, P-384, and secp256k1
 * are supported.
 *
 * @opts
 *   {
 *     method: string,   // "key" (default) | "jwk"
 *   }
 *
 * @example
 *   var did = b.did.keyToDid(issuerPublicKey);                 // → "did:key:z6Mk…"
 *   var dj  = b.did.keyToDid(issuerPublicKey, { method: "jwk" }); // → "did:jwk:eyJr…"
 */
function keyToDid(publicKey, opts) {
  var key = (publicKey && typeof publicKey === "object" && publicKey.asymmetricKeyType)
    ? publicKey : nodeCrypto.createPublicKey(publicKey);
  var jwk = key.export({ format: "jwk" });
  if (opts && opts.method === "jwk") {
    var pub = {};
    Object.keys(jwk).forEach(function (k) { if (k !== "d") pub[k] = jwk[k]; });
    _jwkToKey(pub);
    return "did:jwk:" + Buffer.from(JSON.stringify(pub), "utf8").toString("base64url");
  }
  var code, payload;
  if (jwk.kty === "OKP" && jwk.crv === "Ed25519") {
    code = NAME_TO_CODE["Ed25519"];
    payload = Buffer.from(jwk.x, "base64url");
  } else if (jwk.kty === "EC") {
    var name = jwk.crv === "P-256" ? "P-256" : jwk.crv === "P-384" ? "P-384" : jwk.crv === "secp256k1" ? "secp256k1" : null;
    if (!name) throw new DidError("did/unsupported-key", "did.keyToDid: unsupported EC curve '" + jwk.crv + "'");
    code = NAME_TO_CODE[name];
    payload = _compressedPoint(jwk);
  } else {
    throw new DidError("did/unsupported-key", "did.keyToDid: unsupported key type '" + jwk.kty + "/" + jwk.crv + "'");
  }
  return "did:key:z" + _b58encode(Buffer.concat([_encodeVarint(code), payload]));
}

/**
 * @primitive b.did.resolve
 * @signature b.did.resolve(did, opts?)
 * @since     0.12.41
 * @status    experimental
 * @compliance soc2
 * @related   b.did.parse, b.vc.verify, b.mdoc.verifyIssuerSigned
 *
 * Resolve a DID to its document and verification methods (each with a
 * <code>node:crypto</code> public KeyObject ready for a verifier).
 * <code>did:key</code> and <code>did:jwk</code> resolve deterministically
 * and offline. <code>did:web</code> requires the operator to supply the fetched DID
 * document as <code>opts.document</code> (the network fetch is the
 * operator's; the URL to fetch is on <code>b.did.parse(did).url</code>).
 *
 * @opts
 *   {
 *     document: object,   // did:web — the fetched did.json (required for did:web)
 *   }
 *
 * @example
 *   var r = b.did.resolve("did:key:z6Mk…");
 *   var key = r.verificationMethods[0].publicKey;   // → KeyObject for b.vc.verify / b.mdoc / b.scitt
 */
function resolve(did, opts) {
  opts = opts || {};
  validateOpts.requireObject(opts, "did.resolve", DidError);
  validateOpts(opts, ["document"], "did.resolve");
  var parsed = parse(did);

  if (parsed.method === "key") {
    if (parsed.id[0] !== "z") {
      throw new DidError("did/bad-did", "did:key: method-specific id must be base58btc multibase (start with 'z')");
    }
    var raw = _b58decode(parsed.id.slice(1));
    var vh = _readVarint(raw);
    var key = _keyObjectFromMulticodec(vh.value, raw.slice(vh.length));
    var vmId = did + "#" + parsed.id;
    var vm = { id: vmId, controller: did, type: MULTICODEC[vh.value].name, publicKey: key };
    var doc = {
      "@context": ["https://www.w3.org/ns/did/v1"],
      id: did,
      verificationMethod: [{ id: vmId, controller: did, type: "Multikey", publicKeyMultibase: parsed.id }],
      assertionMethod: [vmId], authentication: [vmId],
    };
    return { didDocument: doc, verificationMethods: [vm] };
  }

  if (parsed.method === "jwk") {
    if (parsed.id.length > MAX_JWK_B64_CHARS) {
      throw new DidError("did/too-long", "did:jwk: encoded JWK exceeds the " + MAX_JWK_B64_CHARS + "-char cap");
    }
    var jwkJson = Buffer.from(parsed.id, "base64url").toString("utf8");
    var jwk;
    try { jwk = safeJson.parse(jwkJson, { maxBytes: MAX_JWK_B64_CHARS }); } catch (_e) {
      throw new DidError("did/bad-jwk", "did:jwk: method-specific id is not base64url-encoded JSON");
    }
    if (!jwk || typeof jwk !== "object" || Array.isArray(jwk)) {
      throw new DidError("did/bad-jwk", "did:jwk: decoded value is not a JWK object");
    }
    var jwkKey = _jwkToKey(jwk);
    var jwkVmId = did + "#0";
    var jwkVm = { id: jwkVmId, controller: did, type: "JsonWebKey2020", publicKey: jwkKey };
    var jwkDoc = {
      "@context": ["https://www.w3.org/ns/did/v1"],
      id: did,
      verificationMethod: [{ id: jwkVmId, controller: did, type: "JsonWebKey2020", publicKeyJwk: jwk }],
      assertionMethod: [jwkVmId], authentication: [jwkVmId],
    };
    return { didDocument: jwkDoc, verificationMethods: [jwkVm] };
  }

  if (parsed.method === "web") {
    if (!opts.document || typeof opts.document !== "object") {
      throw new DidError("did/document-required",
        "did:web: the DID document must be fetched by the operator and passed as opts.document (GET " + parsed.url + ")");
    }
    var docW = opts.document;
    if (docW.id !== did) {
      throw new DidError("did/document-mismatch", "did:web: document id '" + docW.id + "' does not match the requested DID");
    }
    return { didDocument: docW, verificationMethods: _extractVerificationMethods(docW) };
  }

  throw new DidError("did/unsupported-method", "did.resolve: unsupported DID method '" + parsed.method + "' (did:key, did:jwk, and did:web only)");
}

function _jwkToKey(jwk) {
  var ok = (jwk.kty === "OKP" && jwk.crv === "Ed25519") ||
    (jwk.kty === "EC" && (jwk.crv === "P-256" || jwk.crv === "P-384" || jwk.crv === "secp256k1"));
  if (!ok) {
    throw new DidError("did/unsupported-key",
      "did: verificationMethod publicKeyJwk has unsupported kty/crv (" + jwk.kty + "/" + jwk.crv + ")");
  }
  return bCrypto.importPublicJwk(jwk, {
    errorClass:    DidError,
    code:          "did/bad-key",
    messagePrefix: "did: verificationMethod publicKeyJwk is invalid: ",
  });
}

function _extractVerificationMethods(doc) {
  var vms = Array.isArray(doc.verificationMethod) ? doc.verificationMethod : [];
  var out = [];
  for (var i = 0; i < vms.length; i += 1) {
    var vm = vms[i];
    if (!vm || typeof vm !== "object") continue;
    var key = null;
    if (typeof vm.publicKeyMultibase === "string" && vm.publicKeyMultibase[0] === "z") {
      var raw = _b58decode(vm.publicKeyMultibase.slice(1));
      var vh = _readVarint(raw);
      key = _keyObjectFromMulticodec(vh.value, raw.slice(vh.length));
    } else if (vm.publicKeyJwk && typeof vm.publicKeyJwk === "object") {
      key = _jwkToKey(vm.publicKeyJwk);
    } else {
      continue;
    }
    out.push({ id: vm.id, controller: vm.controller, type: vm.type, publicKey: key });
  }
  if (!out.length) throw new DidError("did/no-keys", "did: document has no resolvable verification methods");
  return out;
}

module.exports = {
  parse:       parse,
  keyToDid:    keyToDid,
  resolve:     resolve,
  MULTICODEC:  MULTICODEC,
  DidError:    DidError,
};
