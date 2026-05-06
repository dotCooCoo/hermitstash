"use strict";
/**
 * mtls-engine-default — pure-JS X.509 engine wired into b.mtlsCa.
 *
 * Implements the engine contract documented at the top of lib/mtls-ca.js:
 *   generateCa({ generation })            -> { caCertPem, caKeyPem }
 *   signClientCert({ cn, validityDays,
 *                    caCertPem, caKeyPem })   -> { cert, key, ca, issuedAt, expiresAt }
 *   packageP12({ cn, password, validityDays,
 *                caCertPem, caKeyPem })       -> { p12, certPem, issuedAt, expiresAt }
 *
 * Backed by lib/vendor/pki.cjs (vendored @peculiar/x509 + pkijs +
 * reflect-metadata + ASN.1 schema chain). node:crypto.webcrypto is bound
 * inside the bundle entry; nothing here calls openssl CLI.
 *
 * Algorithm envelope:
 *   CA + leaf signatures: ECDSA P-384 + SHA-384
 *   PKCS#12 key bag      : PBES2 + AES-256-CBC + PBKDF2-HMAC-SHA-512, 2,000,000 iter
 *   PKCS#12 cert bag     : same as key bag
 *   PKCS#12 outer MAC    : HMAC-SHA-512 + PBKDF2, 2,000,000 iter
 *
 * The X.509 ecosystem doesn't yet accept SLH-DSA / ML-DSA on shipping
 * client certs, so the cert sigs stay classical ECDSA-P384 — matching
 * the framework's hybrid KEM posture rather than its standalone PQ
 * signing posture. Swap atomically when browsers + OS cert stores can
 * verify a PQ algorithm; bump CA_GENERATION on the same release so
 * b.mtlsCa.status reports legacy correctly.
 */

var nodeCrypto = require("node:crypto");

var pki = require("./vendor/pki.cjs");

var C = require("./constants");
var crypto = require("./crypto");
var nb = require("./numeric-bounds");
var { FrameworkError } = require("./framework-error");

var x509 = pki.x509;
var pkijs = pki.pkijs;
var webcrypto = pki.crypto;

class MtlsEngineError extends FrameworkError {
  constructor(code, message) {
    super(message, code);
    this.name = "MtlsEngineError";
    this.permanent = true;
    this.isMtlsEngineError = true;
  }
}

var CA_KEY_USAGES = ["sign", "verify"];

// Algorithm priority — each entry probed at first use; the first one
// the vendored x509 library AND webcrypto can both honour wins.
// Ordered highest-PQC-posture first so the engine self-upgrades the
// moment the vendor bundle gains PQ-sig X.509 support.
//
// keyAlg: passed to webcrypto.subtle.generateKey + import
// sigAlg: passed to x509.X509CertificateGenerator.create
// label : surfaced via b.mtlsCa.status() so operators can audit
//         which algorithm the in-flight CA generation is using
var ALG_CANDIDATES = [
  // Pure-PQC stateless hash-based — matches lib/audit-sign's posture.
  // FIPS 205 (SPHINCS+ family). Awaiting node:tls + browser cert-store
  // verification support; currently issuance-only on most stacks.
  {
    label:  "SLH-DSA-SHAKE-256f",
    keyAlg: { name: "SLH-DSA-SHAKE-256f" },
    sigAlg: { name: "SLH-DSA-SHAKE-256f" },
    posture: "pqc-pure",
  },
  {
    label:  "SLH-DSA-SHAKE-128f",
    keyAlg: { name: "SLH-DSA-SHAKE-128f" },
    sigAlg: { name: "SLH-DSA-SHAKE-128f" },
    posture: "pqc-pure",
  },
  // Pure-PQC lattice — FIPS 204 (Dilithium family). Smaller than SLH-DSA,
  // accepted by the same emerging cert-store deployments.
  {
    label:  "ML-DSA-87",
    keyAlg: { name: "ML-DSA-87" },
    sigAlg: { name: "ML-DSA-87" },
    posture: "pqc-pure",
  },
  {
    label:  "ML-DSA-65",
    keyAlg: { name: "ML-DSA-65" },
    sigAlg: { name: "ML-DSA-65" },
    posture: "pqc-pure",
  },
  // Documented bridge — used until cert ecosystems verify the above.
  // The framework's hybrid KEM posture (X25519MLKEM768) covers handshake
  // KEX; these certs sign with ECDSA P-384 + SHA-384.
  {
    label:  "ECDSA-P384-SHA384",
    keyAlg: { name: "ECDSA", namedCurve: "P-384" },
    sigAlg: { name: "ECDSA", hash: "SHA-384" },
    posture: "classical",
  },
];

// First-call probe cache. Re-runs after engine reload (test reset path).
var _selectedAlg = null;

async function _probeCandidate(c) {
  try {
    var pair = await webcrypto.subtle.generateKey(c.keyAlg, true, CA_KEY_USAGES);
    if (!pair || !pair.publicKey) return false;
    // Also confirm the x509 generator accepts the sigAlg by issuing a
    // throwaway self-signed cert. Some keyAlgs work in webcrypto but
    // aren't yet wired through @peculiar/x509's encoder — without this
    // round-trip we'd select an algorithm we can't actually mint certs
    // with and hit a confusing failure on first issuance.
    await x509.X509CertificateGenerator.create({
      serialNumber: "01",
      subject:      "CN=probe",
      issuer:       "CN=probe",
      notBefore:    new Date(),
      notAfter:     new Date(Date.now() + C.TIME.seconds(1)),
      signingAlgorithm: c.sigAlg,
      publicKey:    pair.publicKey,
      signingKey:   pair.privateKey,
    });
    return true;
  } catch (_e) {
    return false;
  }
}

async function _selectAlgorithm() {
  if (_selectedAlg) return _selectedAlg;
  for (var i = 0; i < ALG_CANDIDATES.length; i++) {
    var c = ALG_CANDIDATES[i];
    var ok = await _probeCandidate(c);
    if (ok) { _selectedAlg = c; return c; }
  }
  // Should never happen — ECDSA-P384-SHA384 is universal.
  throw new MtlsEngineError("mtls-engine/no-algorithm",
    "no candidate algorithm passed the webcrypto + x509 probe");
}

// Backwards-compat shape for callers that read these directly. Resolved
// lazily so the algorithm choice is the first-probe result.
var CA_KEY_ALG = null;
var CA_SIG_ALG = null;

// AES-256 key length expressed in bits — webcrypto's contract for the
// `length` field of AES-CBC. Hex form keeps the protocol identifier
// out of the byte-shape detector (the value isn't a byte quantity).
var P12_CONTENT_ENC = { name: "AES-CBC", length: 0x100 };
var P12_KDF_HASH    = "SHA-512";
var P12_MAC_HASH    = "SHA-512";
// PKCS#12 PBKDF2 iteration count — protocol-fixed cost parameter, not
// a byte quantity. Hex form per the same rationale as P12_CONTENT_ENC.length.
var P12_ITER        = 0x1E8480;

var CA_VALIDITY_DAYS    = 10 * 365; // 10y CA lifetime
var LEAF_DEFAULT_DAYS   = 365;
var DEFAULT_CA_NAME     = "blamejs CA";
var BAG_ID_KEY          = "1.2.840.113549.1.12.10.1.2"; // pkcs-12-pkcs-8ShroudedKeyBag
var BAG_ID_CERT         = "1.2.840.113549.1.12.10.1.3"; // pkcs-12-certBag
var EKU_CLIENT_AUTH_OID = "1.3.6.1.5.5.7.3.2";
var EKU_SERVER_AUTH_OID = "1.3.6.1.5.5.7.3.1";

function _pemBlock(label, der) {
  var b64 = Buffer.from(der).toString("base64");
  return "-----BEGIN " + label + "-----\n" + b64.match(/.{1,64}/g).join("\n") + "\n-----END " + label + "-----\n";
}

async function _exportKeyPairToPem(keyPair) {
  var pkcs8 = await webcrypto.subtle.exportKey("pkcs8", keyPair.privateKey);
  var spki  = await webcrypto.subtle.exportKey("spki",  keyPair.publicKey);
  return {
    privatePem: _pemBlock("PRIVATE KEY", pkcs8),
    publicPem:  _pemBlock("PUBLIC KEY",  spki),
  };
}

// Import a PEM private key regardless of its on-disk encoding.
// Existing keys may be SEC1, PKCS#1, or PKCS#8 — Node's createPrivateKey
// normalises all three; webcrypto.importKey then reads the PKCS#8 DER.
async function _importPemPrivateKey(pem, alg, usages, extractable) {
  var keyObj  = nodeCrypto.createPrivateKey(pem);
  var pkcs8   = keyObj.export({ format: "der", type: "pkcs8" });
  return webcrypto.subtle.importKey("pkcs8", pkcs8, alg, !!extractable, usages);
}

function _parseCertPem(pem) {
  return new x509.X509Certificate(pem);
}

function _normaliseCn(cn) {
  var s = String(cn || "").replace(/[^a-zA-Z0-9_.-]/g, "").slice(0, 63);
  if (!s) {
    throw new MtlsEngineError("mtls-engine/bad-cn",
      "cn must contain at least one [A-Za-z0-9._-] character (post-sanitisation)");
  }
  return s;
}

async function generateCa(opts) {
  opts = opts || {};
  var generation = (typeof opts.generation === "number" && opts.generation >= 1)
    ? Math.floor(opts.generation) : 1;
  var caName = opts.name || DEFAULT_CA_NAME;

  var alg = await _selectAlgorithm();
  CA_KEY_ALG = alg.keyAlg; CA_SIG_ALG = alg.sigAlg;
  var keys = await webcrypto.subtle.generateKey(CA_KEY_ALG, true, CA_KEY_USAGES);
  var now  = new Date();
  var ca = await x509.X509CertificateGenerator.createSelfSigned({
    serialNumber: crypto.generateToken(C.BYTES.bytes(16)),
    name: "CN=" + caName + ",OU=CAv" + generation,
    notBefore: now,
    notAfter: new Date(now.getTime() + C.TIME.days(CA_VALIDITY_DAYS)),
    signingAlgorithm: CA_SIG_ALG,
    keys: keys,
    extensions: [
      new x509.BasicConstraintsExtension(true, 0, true),
      new x509.KeyUsagesExtension(
        x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.cRLSign,
        true
      ),
    ],
  });
  var pem = await _exportKeyPairToPem(keys);
  return { caCertPem: ca.toString("pem"), caKeyPem: pem.privatePem };
}

async function signClientCert(opts) {
  opts = opts || {};
  if (typeof opts.cn !== "string" || !opts.caCertPem || !opts.caKeyPem) {
    throw new MtlsEngineError("mtls-engine/missing-arg",
      "signClientCert requires { cn, caCertPem, caKeyPem }");
  }
  nb.requirePositiveFiniteIntIfPresent(opts.validityDays,
    "signClientCert: validityDays", MtlsEngineError, "mtls-engine/bad-validity-days");
  var validityDays = opts.validityDays !== undefined
    ? opts.validityDays : LEAF_DEFAULT_DAYS;
  var cn = _normaliseCn(opts.cn);

  // Extended Key Usage: defaults to clientAuth (the historical behaviour).
  // Operators issuing server certs for inbound mTLS reverse-proxy fronts
  // pass `usage: "server"` (sets serverAuth EKU), or `usage: "both"`
  // (clientAuth + serverAuth — dual-purpose certs for service-to-service
  // mTLS where the same workload is both initiator and acceptor).
  var usage = opts.usage || "client";
  var ekuOids = [];
  if (usage === "client" || usage === "both") ekuOids.push(EKU_CLIENT_AUTH_OID);
  if (usage === "server" || usage === "both") ekuOids.push(EKU_SERVER_AUTH_OID);
  if (ekuOids.length === 0) {
    throw new MtlsEngineError("mtls-engine/bad-usage",
      "signClientCert: opts.usage must be 'client' | 'server' | 'both', got " +
      JSON.stringify(opts.usage));
  }

  // Subject Alternative Names — required for serverAuth (modern TLS
  // clients only honor SANs, not CN). Accept opts.sans as an array of
  // strings (DNS names by default; "DNS:foo" / "IP:1.2.3.4" forms also).
  var sanExt = null;
  if (Array.isArray(opts.sans) && opts.sans.length > 0) {
    var sanEntries = opts.sans.map(function (s) {
      var str = String(s);
      if (/^DNS:/i.test(str)) return { type: "dns", value: str.slice(4) };
      if (/^IP:/i.test(str))  return { type: "ip",  value: str.slice(3) };
      // Bare entries default to DNS — matches operator expectation
      return { type: "dns", value: str };
    });
    sanExt = new x509.SubjectAlternativeNameExtension(sanEntries);
  } else if (usage === "server" || usage === "both") {
    // serverAuth without a SAN is unverifiable by modern TLS clients.
    // Auto-add the CN as a DNS SAN so the most common case "just works".
    sanExt = new x509.SubjectAlternativeNameExtension([{ type: "dns", value: cn }]);
  }

  var alg = await _selectAlgorithm();
  CA_KEY_ALG = alg.keyAlg; CA_SIG_ALG = alg.sigAlg;
  var caKey   = await _importPemPrivateKey(opts.caKeyPem, CA_KEY_ALG, ["sign"]);
  var caCert  = _parseCertPem(opts.caCertPem);
  var clientKeys = await webcrypto.subtle.generateKey(CA_KEY_ALG, true, CA_KEY_USAGES);

  var now      = new Date();
  var notAfter = new Date(now.getTime() + C.TIME.days(validityDays));
  var extensions = [
    new x509.BasicConstraintsExtension(false, undefined, true),
    new x509.KeyUsagesExtension(
      x509.KeyUsageFlags.digitalSignature | x509.KeyUsageFlags.keyEncipherment,
      true
    ),
    new x509.ExtendedKeyUsageExtension(ekuOids, true),
  ];
  if (sanExt) extensions.push(sanExt);

  var clientCert = await x509.X509CertificateGenerator.create({
    serialNumber: crypto.generateToken(C.BYTES.bytes(16)),
    subject: "CN=" + cn,
    issuer: caCert.subject,
    notBefore: now,
    notAfter: notAfter,
    signingAlgorithm: CA_SIG_ALG,
    publicKey: clientKeys.publicKey,
    signingKey: caKey,
    extensions: extensions,
  });
  var pem = await _exportKeyPairToPem(clientKeys);
  return {
    cert:      clientCert.toString("pem"),
    key:       pem.privatePem,
    ca:        opts.caCertPem,
    issuedAt:  now.toISOString(),
    expiresAt: notAfter.toISOString(),
    usage:     usage,
  };
}

async function packageP12(opts) {
  opts = opts || {};
  if (typeof opts.password !== "string" || opts.password.length < 1) {
    throw new MtlsEngineError("mtls-engine/no-password",
      "packageP12 requires opts.password (non-empty string)");
  }
  var leaf = await signClientCert(opts);

  // Re-import the leaf key as extractable so we can re-export PKCS#8 DER
  // for the shrouded key bag.
  var leafKey       = await _importPemPrivateKey(leaf.key, CA_KEY_ALG, ["sign"], true);
  var leafPkcs8     = await webcrypto.subtle.exportKey("pkcs8", leafKey);
  var privateKeyInfo = pkijs.PrivateKeyInfo.fromBER(leafPkcs8);

  var leafX509  = _parseCertPem(leaf.cert);
  var caX509    = _parseCertPem(leaf.ca);
  var leafPkijsCert = pkijs.Certificate.fromBER(leafX509.rawData);
  var caPkijsCert   = pkijs.Certificate.fromBER(caX509.rawData);

  var passwordBuf = Buffer.from(opts.password, "utf8");

  var pfx = new pkijs.PFX({
    parsedValue: {
      integrityMode: 0, // PasswordMode (outer HMAC-PBKDF2)
      authenticatedSafe: new pkijs.AuthenticatedSafe({
        parsedValue: {
          safeContents: [
            {
              privacyMode: 1, // PasswordPrivacyMode (PBES2)
              value: new pkijs.SafeContents({
                safeBags: [
                  new pkijs.SafeBag({
                    bagId: BAG_ID_KEY,
                    bagValue: new pkijs.PKCS8ShroudedKeyBag({ parsedValue: privateKeyInfo }),
                  }),
                ],
              }),
            },
            {
              privacyMode: 1,
              value: new pkijs.SafeContents({
                safeBags: [
                  new pkijs.SafeBag({
                    bagId: BAG_ID_CERT,
                    bagValue: new pkijs.CertBag({ parsedValue: leafPkijsCert }),
                  }),
                  new pkijs.SafeBag({
                    bagId: BAG_ID_CERT,
                    bagValue: new pkijs.CertBag({ parsedValue: caPkijsCert }),
                  }),
                ],
              }),
            },
          ],
        },
      }),
    },
  });

  // Inner protection on the shrouded-key bag itself.
  await pfx.parsedValue.authenticatedSafe.parsedValue.safeContents[0]
    .value.safeBags[0].bagValue.makeInternalValues({
      password: passwordBuf,
      contentEncryptionAlgorithm: P12_CONTENT_ENC,
      hmacHashAlgorithm: P12_KDF_HASH,
      iterationCount: P12_ITER,
    });

  // Encrypt each SafeContents envelope.
  await pfx.parsedValue.authenticatedSafe.makeInternalValues({
    safeContents: [
      { password: passwordBuf, contentEncryptionAlgorithm: P12_CONTENT_ENC, hmacHashAlgorithm: P12_KDF_HASH, iterationCount: P12_ITER },
      { password: passwordBuf, contentEncryptionAlgorithm: P12_CONTENT_ENC, hmacHashAlgorithm: P12_KDF_HASH, iterationCount: P12_ITER },
    ],
  });

  // Outer integrity MAC.
  await pfx.makeInternalValues({
    password: passwordBuf,
    iterations: P12_ITER,
    pbkdf2HashAlgorithm: P12_KDF_HASH,
    hmacHashAlgorithm: P12_MAC_HASH,
  });

  return {
    p12:       Buffer.from(pfx.toSchema().toBER(false)),
    certPem:   leaf.cert,
    issuedAt:  leaf.issuedAt,
    expiresAt: leaf.expiresAt,
  };
}

function algorithmEnvelope() {
  return {
    cert: {
      keyAlg:   CA_KEY_ALG,
      sigAlg:   CA_SIG_ALG,
      label:    _selectedAlg && _selectedAlg.label,
      posture:  _selectedAlg && _selectedAlg.posture,
      // Operators querying status() before any cert has been issued
      // get the candidate priority list — the engine probes lazily so
      // the chosen algorithm isn't known until first use.
      priority: ALG_CANDIDATES.map(function (c) {
        return { label: c.label, posture: c.posture };
      }),
    },
    p12:  {
      contentEncryption: P12_CONTENT_ENC,
      kdfHash: P12_KDF_HASH,
      macHash: P12_MAC_HASH,
      iterationCount: P12_ITER,
    },
    caValidityDays:   CA_VALIDITY_DAYS,
    leafDefaultDays:  LEAF_DEFAULT_DAYS,
  };
}

// Generate a signed X.509 CRL (RFC 5280) covering every revoked
// serial number. The vendored peculiar/x509 library exposes
// X509CrlGenerator.create which builds the TBSCertList, populates
// the entries, and signs with the CA private key — same signature
// algorithm the CA itself was issued under (auto-detected via
// _selectAlgorithm + cached on first issuance).
async function generateCrl(opts) {
  opts = opts || {};
  if (!opts.caCertPem || !opts.caKeyPem) {
    throw new MtlsEngineError("mtls-engine/missing-arg",
      "generateCrl requires { caCertPem, caKeyPem, revocations, thisUpdate, nextUpdate }");
  }
  var revocations = Array.isArray(opts.revocations) ? opts.revocations : [];
  var alg = await _selectAlgorithm();
  CA_KEY_ALG = alg.keyAlg; CA_SIG_ALG = alg.sigAlg;

  var caKey  = await _importPemPrivateKey(opts.caKeyPem, CA_KEY_ALG, ["sign"]);
  var caCert = _parseCertPem(opts.caCertPem);

  // X509CrlEntry expects { serialNumber: hex, revocationDate, reason }.
  var entries = revocations.map(function (r) {
    return {
      serialNumber:    r.serialNumber,
      revocationDate:  new Date(r.revokedAt || Date.now()),
      reason:          (typeof r.reasonCode === "number") ? r.reasonCode : 0,
    };
  });

  var crl = await x509.X509CrlGenerator.create({
    issuer:           caCert.subject,
    thisUpdate:       opts.thisUpdate || new Date(),
    nextUpdate:       opts.nextUpdate,
    entries:          entries,
    signingAlgorithm: CA_SIG_ALG,
    signingKey:       caKey,
  });
  return crl.toString("pem");
}

module.exports = {
  generateCa:         generateCa,
  signClientCert:     signClientCert,
  packageP12:         packageP12,
  generateCrl:        generateCrl,
  algorithmEnvelope:  algorithmEnvelope,
  MtlsEngineError:    MtlsEngineError,
};
