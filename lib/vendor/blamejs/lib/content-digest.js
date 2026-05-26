"use strict";
/**
 * @module b.contentDigest
 * @nav    HTTP
 * @title  Content-Digest
 *
 * @intro
 *   HTTP Digest Fields (RFC 9530) — emit and verify the
 *   <code>Content-Digest</code> / <code>Repr-Digest</code> fields that
 *   carry a hash of a message body so a recipient can detect corruption
 *   or tampering in transit. The field is an RFC 8941 dictionary of
 *   <code>algorithm=:base64-digest:</code> entries; this module computes
 *   and checks the modern algorithms (SHA-256, SHA-512) and ignores the
 *   legacy ones (MD5, SHA-1, the unix checksums) that RFC 9530 §6 marks
 *   insecure — refusing to accept a body whose only digest is a legacy
 *   algorithm.
 *
 *   Content-Digest is the integrity companion to HTTP Message Signatures
 *   (<code>b.httpSig</code>, RFC 9421): rather than signing a whole body,
 *   sign its <code>Content-Digest</code> and let this module bind the
 *   digest to the bytes.
 *
 * @card
 *   HTTP Content-Digest / Repr-Digest (RFC 9530). Emit and verify a
 *   SHA-256 / SHA-512 digest of a message body; legacy algorithms are
 *   ignored and a body with no modern digest is refused. Pairs with
 *   <code>b.httpSig</code> — sign the digest, not the bytes.
 */

var nodeCrypto = require("node:crypto");
var bCrypto = require("./crypto");
var structuredFields = require("./structured-fields");
var validateOpts = require("./validate-opts");
var { defineClass } = require("./framework-error");

var ContentDigestError = defineClass("ContentDigestError", { alwaysPermanent: true });

// RFC 9530 IANA "Hash Algorithms for HTTP Digest Fields": Active vs
// (insecure) deprecated. Active algorithms map to a Node hash name.
var ACTIVE = { "sha-256": "sha256", "sha-512": "sha512" };
var DEPRECATED = { "md5": 1, "sha": 1, "unixsum": 1, "unixcksum": 1, "adler": 1, "crc32c": 1 };

// Decode an RFC 8941 Byte Sequence payload as STRICT, canonical base64.
// Node's base64 decoder silently drops invalid characters and tolerates
// bad padding, so `:<digest>!!!!:` or non-canonical padding would decode
// to the same bytes and wrongly verify — a real risk when the
// Content-Digest field is itself covered by an HTTP Message Signature.
// Decoding then re-encoding and requiring the exact input back rejects
// stray characters, whitespace, wrong padding, and non-zero trailing
// bits in one canonical check (Node always re-emits canonical base64).
function _strictBase64(s, what) {
  if (typeof s !== "string" || s.length === 0) {
    throw new ContentDigestError("content-digest/bad-field", "contentDigest: " + what + " is empty");
  }
  var buf = Buffer.from(s, "base64");
  if (buf.length === 0 || buf.toString("base64") !== s) {
    throw new ContentDigestError("content-digest/bad-field", "contentDigest: " + what + " is not canonical base64");
  }
  return buf;
}

function _bodyBytes(body, what) {
  if (Buffer.isBuffer(body)) return body;
  if (body instanceof Uint8Array) return Buffer.from(body);
  if (typeof body === "string") return Buffer.from(body, "utf8");
  throw new ContentDigestError("content-digest/bad-body", "contentDigest: " + what + " must be a Buffer / Uint8Array / string");
}

/**
 * @primitive b.contentDigest.create
 * @signature b.contentDigest.create(body, opts?)
 * @since     0.12.53
 * @status    stable
 * @compliance soc2
 * @related   b.contentDigest.verify, b.httpSig
 *
 * Build a <code>Content-Digest</code> (or <code>Repr-Digest</code>) field
 * value over a message body (RFC 9530 §2): an RFC 8941 dictionary of
 * <code>algorithm=:base64(digest):</code> members. Defaults to SHA-256;
 * pass <code>algorithms</code> to emit several. Only the modern
 * algorithms are offered — the digest is over the exact body bytes.
 *
 * @opts
 *   {
 *     algorithms: string[],  // subset of ["sha-256","sha-512"]; default ["sha-256"]
 *   }
 *
 * @example
 *   b.contentDigest.create('{"hello": "world"}');
 *   // → "sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:"
 */
function create(body, opts) {
  opts = opts || {};
  validateOpts.requireObject(opts, "contentDigest.create", ContentDigestError);
  validateOpts(opts, ["algorithms"], "contentDigest.create");
  var bytes = _bodyBytes(body, "body");
  var algos = opts.algorithms === undefined ? ["sha-256"] : opts.algorithms;
  if (!Array.isArray(algos) || algos.length === 0) throw new ContentDigestError("content-digest/bad-arg", "contentDigest.create: opts.algorithms must be a non-empty array");
  var members = algos.map(function (a) {
    var name = String(a).toLowerCase();
    var nodeAlg = ACTIVE[name];
    if (!nodeAlg) {
      if (DEPRECATED[name]) throw new ContentDigestError("content-digest/insecure-algorithm", "contentDigest.create: '" + name + "' is a deprecated/insecure digest algorithm (RFC 9530 §6); use sha-256 or sha-512");
      throw new ContentDigestError("content-digest/unsupported-algorithm", "contentDigest.create: unsupported digest algorithm '" + name + "'");
    }
    var digest = nodeCrypto.createHash(nodeAlg).update(bytes).digest("base64");
    return name + "=:" + digest + ":";                       // RFC 8941 Byte Sequence value
  });
  return members.join(", ");
}

/**
 * @primitive b.contentDigest.verify
 * @signature b.contentDigest.verify(fieldValue, body, opts?)
 * @since     0.12.53
 * @status    stable
 * @compliance soc2
 * @related   b.contentDigest.create, b.httpSig
 *
 * Verify a <code>Content-Digest</code> / <code>Repr-Digest</code> field
 * value against a body (RFC 9530). Every modern (SHA-256 / SHA-512) entry
 * is recomputed over the body and compared in constant time; a mismatch
 * is refused. Legacy / unknown algorithms are ignored, but a field that
 * carries <em>no</em> modern digest is refused (so an attacker cannot
 * downgrade to an MD5-only digest). <code>opts.required</code> forces
 * specific algorithms to be present and to match.
 *
 * @opts
 *   {
 *     required: string[],   // algorithms that MUST be present and match (e.g. ["sha-256"])
 *   }
 *
 * @example
 *   b.contentDigest.verify("sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:", '{"hello": "world"}');
 *   // → { ok: true, verified: ["sha-256"] }
 */
function verify(fieldValue, body, opts) {
  opts = opts || {};
  validateOpts.requireObject(opts, "contentDigest.verify", ContentDigestError);
  validateOpts(opts, ["required"], "contentDigest.verify");
  if (typeof fieldValue !== "string" || fieldValue.trim() === "") throw new ContentDigestError("content-digest/bad-field", "contentDigest.verify: fieldValue must be a non-empty string");
  structuredFields.refuseControlBytes(fieldValue, { ErrorClass: ContentDigestError, code: "content-digest/bad-field", label: "contentDigest fieldValue" });
  var bytes = _bodyBytes(body, "body");

  var members = structuredFields.splitTopLevel(fieldValue, ",");
  var seen = Object.create(null);
  var verified = [];
  for (var i = 0; i < members.length; i++) {
    var m = members[i].trim();
    if (m === "") continue;
    var eq = m.indexOf("=");
    if (eq < 1) throw new ContentDigestError("content-digest/bad-field", "contentDigest.verify: malformed dictionary member");
    var name = m.slice(0, eq).trim().toLowerCase();
    var raw = m.slice(eq + 1).trim();
    var nodeAlg = ACTIVE[name];
    if (!nodeAlg) continue;                                  // ignore legacy / unknown entries
    if (raw.length < 2 || raw.charAt(0) !== ":" || raw.charAt(raw.length - 1) !== ":") {
      throw new ContentDigestError("content-digest/bad-field", "contentDigest.verify: '" + name + "' value is not an RFC 8941 byte sequence (:base64:)");
    }
    var claimed = _strictBase64(raw.slice(1, -1), name + " digest");
    var actual = nodeCrypto.createHash(nodeAlg).update(bytes).digest();
    if (!bCrypto.timingSafeEqual(actual, claimed)) {
      throw new ContentDigestError("content-digest/mismatch", "contentDigest.verify: " + name + " digest does not match the body");
    }
    seen[name] = 1;
    verified.push(name);
  }

  if (opts.required !== undefined && opts.required !== null) {
    if (!Array.isArray(opts.required)) throw new ContentDigestError("content-digest/bad-arg", "contentDigest.verify: opts.required must be an array");
    for (var r = 0; r < opts.required.length; r++) {
      var req = String(opts.required[r]).toLowerCase();
      if (!ACTIVE[req]) throw new ContentDigestError("content-digest/unsupported-algorithm", "contentDigest.verify: required algorithm '" + req + "' is not a modern digest");
      if (!seen[req]) throw new ContentDigestError("content-digest/missing-algorithm", "contentDigest.verify: required digest '" + req + "' is not present");
    }
  }

  if (verified.length === 0) {
    throw new ContentDigestError("content-digest/no-modern-digest", "contentDigest.verify: no modern (sha-256 / sha-512) digest present — refusing to trust a legacy-only digest");
  }
  return { ok: true, verified: verified };
}

module.exports = {
  create:             create,
  verify:             verify,
  ACTIVE_ALGORITHMS:  Object.keys(ACTIVE),
  ContentDigestError: ContentDigestError,
};
