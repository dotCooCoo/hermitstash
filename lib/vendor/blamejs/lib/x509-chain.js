"use strict";

// Internal X.509 path-validation helpers shared by the framework's
// certificate-chain walkers (b.tsa.verifyToken, b.mail.bimi VMC/CMC,
// b.mail.crypto.smime.verify). They exist because node:crypto's
// X509Certificate.checkIssued() validates the issuer/subject DN match,
// the AKI/SKI linkage, and — when a keyUsage extension is present —
// keyCertSign, but it does NOT enforce basicConstraints cA:TRUE. A
// leaf / end-entity certificate (cA:FALSE) that omits keyUsage is
// therefore wrongly accepted as a signing CA for the next cert in the
// chain — the classic basicConstraints bypass (CVE-2002-0862 class).
// Every chain walker routes its issuer test through these helpers so the
// cA enforcement can never be forgotten in one walker but present in
// another.

// True only when `cert` asserts basicConstraints cA:TRUE. node's
// X509Certificate exposes `.ca` (a boolean); a cert with no
// basicConstraints extension or with cA:FALSE returns false. A missing
// cert or a non-boolean `.ca` (parse failure / unsupported runtime)
// fails closed.
function isCaCert(cert) {
  return !!cert && cert.ca === true;
}

// True when `issuer` validly issued `subject` AND is itself a CA: the
// DN / AKI-SKI / keyUsage linkage (checkIssued), the cryptographic
// signature (verify), and basicConstraints cA:TRUE (isCaCert). The cA
// check runs first so a non-CA cert is rejected before the expensive
// signature verification. Any exception (malformed cert, unsupported
// key type) fails closed to false.
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
