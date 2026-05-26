"use strict";
/**
 * @module b.network.dns.dane
 * @nav    Network
 * @title  DANE / TLSA
 *
 * @intro
 *   DNS-Based Authentication of Named Entities (RFC 6698, updated by
 *   RFC 7671) — match a server certificate against a TLSA record so the
 *   DNS, not a public CA, vouches for which key a service uses. This is
 *   the payoff of DNSSEC: verify the TLSA RRset with
 *   <code>b.network.dns.dnssec</code> first, then
 *   <code>matchCertificate</code> checks the certificate against it.
 *
 *   A TLSA record carries a certificate usage (PKIX-TA 0, PKIX-EE 1,
 *   DANE-TA 2, DANE-EE 3 — RFC 7218 mnemonics), a selector (full
 *   certificate 0, or subjectPublicKeyInfo 1), and a matching type
 *   (exact 0, SHA-256 1, SHA-512 2). The selected certificate data is
 *   hashed per the matching type and compared, in constant time, to the
 *   record's association data. For DANE-EE(3) a match means the
 *   certificate IS the pinned end-entity key — no public-CA path is
 *   needed (the common SMTP-DANE case, RFC 7672). For the PKIX usages a
 *   match is necessary but the caller still performs PKIX validation.
 *
 * @card
 *   DANE / TLSA certificate matching (RFC 6698 / 7671). Pin a service's
 *   key through DNSSEC instead of a public CA — verify the TLSA RRset,
 *   then match the certificate (DANE-EE / DANE-TA / PKIX usages,
 *   full-cert or SPKI selector, SHA-256 / SHA-512).
 */

var nodeCrypto = require("node:crypto");
var bCrypto = require("./crypto");
var validateOpts = require("./validate-opts");
var { defineClass } = require("./framework-error");

var DaneError = defineClass("DaneError", { alwaysPermanent: true });

// RFC 6698 §2.1 + RFC 7218 mnemonics.
var USAGES = { 0: "PKIX-TA", 1: "PKIX-EE", 2: "DANE-TA", 3: "DANE-EE" };
var SELECTORS = { 0: "Cert", 1: "SPKI" };
// Matching types: 0 = exact match on the selected data, 1 = SHA-256,
// 2 = SHA-512. SHA-1 is not registered for TLSA, so anything else is
// refused rather than guessed.
var MATCHING = { 0: null, 1: "sha256", 2: "sha512" };

function _bytes(x, what) {
  if (Buffer.isBuffer(x)) return x;
  if (x instanceof Uint8Array) return Buffer.from(x);
  if (typeof x === "string") return Buffer.from(x, "hex");
  throw new DaneError("dane/bad-bytes", "dane: " + what + " must be a Buffer / Uint8Array / hex string");
}

function _selectedData(x509, selector) {
  if (selector === 0) return Buffer.from(x509.raw);                                   // full certificate DER
  if (selector === 1) return x509.publicKey.export({ format: "der", type: "spki" });  // subjectPublicKeyInfo DER
  throw new DaneError("dane/unsupported-selector", "dane: unsupported TLSA selector " + selector + " (0 = full cert, 1 = SPKI)");
}

function _associationOf(selected, matchingType) {
  if (matchingType === 0) return selected;
  var hashName = MATCHING[matchingType];
  if (!hashName) throw new DaneError("dane/unsupported-matching", "dane: unsupported TLSA matching type " + matchingType + " (0 = exact, 1 = SHA-256, 2 = SHA-512)");
  return nodeCrypto.createHash(hashName).update(selected).digest();
}

function _parseCert(der, what) {
  try { return new nodeCrypto.X509Certificate(_bytes(der, what)); }
  catch (e) { throw new DaneError("dane/bad-certificate", "dane: could not parse " + what + ": " + ((e && e.message) || e)); }
}

// Validate a TLSA enum field: it must be an actual integer that is an
// OWN key of the lookup table. Rejecting non-numbers stops a string like
// "1" (which coerces on key lookup but then fails the strict-=== usage
// checks below), and the own-property test stops prototype keys such as
// "__proto__" that `in` / `[x] !== undefined` would wrongly accept.
function _enumField(v, table, code, label, i) {
  if (typeof v !== "number" || !Number.isInteger(v) || !Object.prototype.hasOwnProperty.call(table, v)) {
    throw new DaneError(code, "dane: tlsa[" + i + "] " + label + " must be a numeric " + Object.keys(table).join(" / ") + " (got " + JSON.stringify(v) + ")");
  }
}
function _normaliseTlsa(rec, i) {
  if (!rec || typeof rec !== "object") throw new DaneError("dane/bad-tlsa", "dane: tlsa[" + i + "] must be an object");
  _enumField(rec.usage, USAGES, "dane/unsupported-usage", "certificate usage", i);
  _enumField(rec.selector, SELECTORS, "dane/unsupported-selector", "selector", i);
  _enumField(rec.matchingType, MATCHING, "dane/unsupported-matching", "matching type", i);
  return { usage: rec.usage, selector: rec.selector, matchingType: rec.matchingType, data: _bytes(rec.data, "tlsa[" + i + "].data") };
}

/**
 * @primitive b.network.dns.dane.matchCertificate
 * @signature b.network.dns.dane.matchCertificate(opts)
 * @since     0.12.51
 * @status    stable
 * @compliance soc2
 * @related   b.network.dns.dnssec.verifyChain, b.network.dns.dnssec.verifyRrset
 *
 * Match a server certificate against a set of (DNSSEC-verified) TLSA
 * records (RFC 6698 / 7671). For each record the selected data — the
 * full certificate DER (selector 0) or its subjectPublicKeyInfo
 * (selector 1) — is hashed per the matching type (exact / SHA-256 /
 * SHA-512) and compared, constant-time, to the record's association
 * data. End-entity usages (PKIX-EE 1, DANE-EE 3) are matched against the
 * leaf certificate; trust-anchor usages (PKIX-TA 0, DANE-TA 2) are
 * matched against the leaf and any supplied <code>chain</code>.
 *
 * Returns the matching record plus what the caller must still do: a
 * DANE-EE match is self-sufficient (the TLSA pins the key); a DANE-TA
 * match still needs chain-to-anchor verification; PKIX usages still need
 * full PKIX validation. Throws <code>dane/no-match</code> if nothing
 * matches. Verify the TLSA RRset with <code>b.network.dns.dnssec</code>
 * before trusting the records — an unauthenticated TLSA proves nothing.
 *
 * @opts
 *   {
 *     tlsa: [ { usage, selector, matchingType, data: Buffer|hex } ],  // the TLSA RRset
 *     certificate: Buffer,   // leaf certificate (DER)
 *     chain?:      Buffer[],  // intermediate / CA certs (DER), for TA usages
 *   }
 *
 * @example
 *   var r = b.network.dns.dane.matchCertificate({ tlsa: records, certificate: leafDer });
 *   // → { ok: true, matched: { usage: 3, selector: 1, matchingType: 1 }, daneAuthenticated: true, pkixRequired: false }
 */
function matchCertificate(opts) {
  validateOpts.requireObject(opts, "dane.matchCertificate", DaneError);
  validateOpts(opts, ["tlsa", "certificate", "chain"], "dane.matchCertificate");
  if (!Array.isArray(opts.tlsa) || opts.tlsa.length === 0) throw new DaneError("dane/bad-arg", "dane.matchCertificate: opts.tlsa must be a non-empty array");
  var records = opts.tlsa.map(_normaliseTlsa);
  var leaf = _parseCert(opts.certificate, "certificate");
  var chain = Array.isArray(opts.chain) ? opts.chain.map(function (c, i) { return _parseCert(c, "chain[" + i + "]"); }) : [];

  for (var i = 0; i < records.length; i++) {
    var rec = records[i];
    var eeUsage = rec.usage === 1 || rec.usage === 3;       // PKIX-EE / DANE-EE → leaf only
    var certs = eeUsage ? [leaf] : [leaf].concat(chain);    // TA usages may match a chain cert
    for (var c = 0; c < certs.length; c++) {
      var assoc = _associationOf(_selectedData(certs[c], rec.selector), rec.matchingType);
      if (bCrypto.timingSafeEqual(assoc, rec.data)) {
        return {
          ok: true,
          matched: { usage: rec.usage, usageName: USAGES[rec.usage], selector: rec.selector, matchingType: rec.matchingType },
          matchedCertIndex: c,                              // 0 = leaf, >0 = chain[c-1]
          daneAuthenticated: rec.usage === 3,               // DANE-EE: TLSA pins the key, no CA path needed
          trustAnchorMatch: rec.usage === 0 || rec.usage === 2,
          pkixRequired: rec.usage === 0 || rec.usage === 1,
        };
      }
    }
  }
  throw new DaneError("dane/no-match", "dane.matchCertificate: no TLSA record matched the certificate" + (chain.length ? " or chain" : ""));
}

module.exports = {
  matchCertificate: matchCertificate,
  USAGES:           USAGES,
  SELECTORS:        SELECTORS,
  DaneError:        DaneError,
};
