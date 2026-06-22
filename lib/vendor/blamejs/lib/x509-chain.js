"use strict";
/**
 * @module b.x509Chain
 * @nav    Crypto
 * @title  X.509 chain (CA-bit issuer test)
 *
 * @intro
 *   The basicConstraints-enforcing issuer test the framework's own
 *   certificate-chain walkers route through (<code>b.tsa.verifyToken</code>,
 *   <code>b.mail.bimi</code> VMC/CMC, <code>b.mail.crypto.smime</code>,
 *   <code>b.mdoc</code>, <code>b.contentCredentials</code>,
 *   <code>b.auth.fido</code>). It exists because node:crypto's
 *   <code>X509Certificate.checkIssued()</code> validates the issuer/subject
 *   DN match, the AKI/SKI linkage, and — only when a keyUsage extension is
 *   present — keyCertSign, but it does <strong>not</strong> enforce
 *   basicConstraints cA:TRUE. A leaf / end-entity certificate (cA:FALSE)
 *   that omits keyUsage is therefore wrongly accepted as a signing CA for
 *   the next certificate in the chain — the classic basicConstraints bypass
 *   (CVE-2002-0862 class). Every in-tree walker routes its issuer test
 *   through these helpers so the cA enforcement can never be forgotten in
 *   one walker but present in another.
 *
 *   Exposed so a consumer validating an X.509 chain <em>outside</em> a TLS
 *   handshake — an operator-uploaded CA bundle, a non-handshake PQ-signed
 *   certificate — has the same hardened, fail-closed test instead of being
 *   pushed toward the raw <code>checkIssued()</code> path this module
 *   exists to prevent. Both helpers fail closed: any malformed input or
 *   unsupported key type returns false rather than throwing.
 *
 * @card
 *   basicConstraints cA:TRUE-enforcing X.509 issuer test, fail-closed —
 *   the hardened alternative to node's checkIssued() for chains built
 *   outside a TLS handshake.
 */

/**
 * @primitive b.x509Chain.isCaCert
 * @signature b.x509Chain.isCaCert(cert)
 * @since     0.15.15
 * @status    stable
 * @related   b.x509Chain.issuerValidlyIssued
 *
 * True only when <code>cert</code> asserts basicConstraints cA:TRUE.
 * node's <code>X509Certificate</code> exposes <code>.ca</code> (a boolean);
 * a certificate with no basicConstraints extension or with cA:FALSE
 * returns false. A missing cert or a non-boolean <code>.ca</code> (parse
 * failure / unsupported runtime) fails closed to false.
 *
 * @example
 *   var crypto = require("crypto");
 *   var ca = new crypto.X509Certificate(caPem);
 *   b.x509Chain.isCaCert(ca);   // → true only if basicConstraints cA:TRUE
 */
function isCaCert(cert) {
  return !!cert && cert.ca === true;
}

/**
 * @primitive b.x509Chain.issuerValidlyIssued
 * @signature b.x509Chain.issuerValidlyIssued(issuer, subject)
 * @since     0.15.15
 * @status    stable
 * @related   b.x509Chain.isCaCert
 *
 * True when <code>issuer</code> validly issued <code>subject</code> AND is
 * itself a CA: the DN / AKI-SKI / keyUsage linkage (checkIssued), the
 * cryptographic signature (verify), and basicConstraints cA:TRUE
 * (isCaCert). The cA check runs first so a non-CA certificate is rejected
 * before the expensive signature verification. Any exception (malformed
 * cert, unsupported key type) fails closed to false.
 *
 * @example
 *   var crypto = require("crypto");
 *   var issuer  = new crypto.X509Certificate(issuerPem);
 *   var subject = new crypto.X509Certificate(leafPem);
 *   b.x509Chain.issuerValidlyIssued(issuer, subject);   // → boolean
 */
function issuerValidlyIssued(issuer, subject) {
  try {
    return isCaCert(issuer) &&
      subject.checkIssued(issuer) &&
      subject.verify(issuer.publicKey);
  } catch (_e) {
    return false;
  }
}

module.exports = {
  isCaCert:            isCaCert,
  issuerValidlyIssued: issuerValidlyIssued,
};
