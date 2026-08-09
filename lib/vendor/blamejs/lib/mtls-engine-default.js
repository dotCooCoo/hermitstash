// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * mtls-engine-default — pure-JS X.509 engine wired into b.mtlsCa.
 *
 * Implements the engine contract documented at the top of lib/mtls-ca.js:
 *   generateCa({ generation, algorithm })     -> { caCertPem, caKeyPem }
 *   signClientCert({ cn, validityDays, usage, sans, algorithm,
 *                    caCertPem, caKeyPem })    -> { cert, key, ca, issuedAt, expiresAt }
 *   packageP12({ cn, password, validityDays, algorithm,
 *                caCertPem, caKeyPem })        -> { p12, certPem, issuedAt, expiresAt }
 *   generateCrl({ caCertPem, caKeyPem,
 *                 revocations, thisUpdate,
 *                 nextUpdate })                -> CRL PEM
 *
 * Backed by lib/vendor/blamejs-pki.cjs (@blamejs/pki — zero-dep pure-CJS
 * X.509 / CRL / PKCS#12 toolkit with a built-in WebCrypto over node:crypto).
 * No openssl CLI is invoked.
 *
 * Algorithm envelope:
 *   CA + leaf signatures: ML-DSA-87 by default (FIPS 204). node:tls verifies
 *                         ML-DSA certificate chains + CertificateVerify on the
 *                         supported Node LTS (OpenSSL 3.5), so PQC-signed mTLS
 *                         certificates complete a real mutual-auth handshake.
 *                         Operators whose peers are not yet on OpenSSL 3.5 pass
 *                         algorithm: "ECDSA-P384-SHA384" (b.mtlsCa.create({ algorithm })
 *                         threads it into both CA generation and leaf issuance)
 *                         for a universally-interoperable classical CA. A pin is
 *                         per-call: it never mutates the process-wide default, so
 *                         one classical CA cannot downgrade another CA's ML-DSA-87
 *                         default. SLH-DSA is intentionally not offered here:
 *                         OpenSSL rejects it in the TLS handshake ("unknown
 *                         certificate type").
 *   PKCS#12 key + cert bags: PBES2 + AES-256-CBC + PBKDF2-HMAC-SHA-512, 2,000,000 iter
 *   PKCS#12 outer MAC       : follows the cert tier — PBMAC1 + PBKDF2-HMAC-SHA-512
 *                             @ 2,000,000 iter (RFC 9579) for the PQC default; the
 *                             classical ECDSA-P384 bridge uses the legacy-importable
 *                             RFC 7292 App. B HMAC-SHA-512 MacData so a pre-OpenSSL-3.5
 *                             peer can verify it
 */

var nodeCrypto = require("node:crypto");
var nodeTls = require("node:tls");
var pki = require("./vendor/blamejs-pki.cjs");

var lazyRequire = require("./lazy-require");
var C = require("./constants");
var bCrypto = require("./crypto");
var ipUtils = require("./ip-utils");
var numericBounds = require("./numeric-bounds");
var safeBuffer = require("./safe-buffer");
var { FrameworkError } = require("./framework-error");
// networkTls — lazy so the outbound-TLS posture is read from live state at
// dial time (an operator's preferredGroups.set must reach the next
// connection), without pulling the TLS module into this one's boot graph.
var networkTls = lazyRequire(function () { return require("./network-tls"); });

var subtle = pki.webcrypto.subtle;

class MtlsEngineError extends FrameworkError {
  constructor(code, message) {
    super(message, code);
    this.name = "MtlsEngineError";
    this.permanent = true;
    this.isMtlsEngineError = true;
  }
}

var CA_KEY_USAGES = ["sign", "verify"];

// Algorithm priority — each entry probed at first use; the first one the
// vendored PKI toolkit AND webcrypto can both honour wins. Ordered
// highest-PQC-posture first so the engine issues post-quantum certificates
// by default. Every listed candidate has been confirmed to complete a real
// node:tls mutual-auth handshake on the supported Node LTS.
//
// keyAlg : passed to webcrypto.subtle.generateKey; the certificate signature
//          algorithm is resolved from the signing key by pki.x509.sign.
// label  : surfaced via b.mtlsCa.status() so operators can audit which
//          algorithm the in-flight CA generation is using, and passed to
//          generateCa({ algorithm }) to pin a specific one.
var ALG_CANDIDATES = [
  // Pure-PQC lattice — FIPS 204 (ML-DSA / Dilithium family). Verified end to
  // end in a node:tls mutual-auth handshake (chain + CertificateVerify).
  {
    label:  "ML-DSA-87",
    keyAlg: { name: "ML-DSA-87" },
    posture: "pqc-pure",
  },
  {
    label:  "ML-DSA-65",
    keyAlg: { name: "ML-DSA-65" },
    posture: "pqc-pure",
  },
  // Classical bridge — for peers not yet on OpenSSL 3.5. Opt in with
  // generateCa({ algorithm: "ECDSA-P384-SHA384" }).
  {
    label:  "ECDSA-P384-SHA384",
    keyAlg: { name: "ECDSA", namedCurve: "P-384" },
    posture: "classical",
    // The signature digest MUST be passed to pki.x509.sign / pki.crl.sign — the
    // toolkit defaults an EC key to SHA-256, which would silently downgrade this
    // bridge below its SHA-384 posture (and below the framework's no-SHA-256
    // default rule). ML-DSA needs no digest (it is no-prehash: the toolkit forces
    // SHA-512 and ignores an explicit digest), so only the classical entry sets it.
    digest: "sha384",
  },
];

// First-call probe cache for the process-wide DEFAULT (never written by a per-call
// pin, so a pin can't downgrade the default). Re-runs after engine reload.
var _selectedAlg = null;
// The most-recent RESOLVED algorithm (pinned OR default) — reporting only, so
// algorithmEnvelope() can describe a pinned selection accurately without poisoning
// the default cache above.
var _lastSelectedAlg = null;

async function _probeCandidate(c) {
  try {
    var pair = await subtle.generateKey(c.keyAlg, true, CA_KEY_USAGES);
    /* c8 ignore next -- defensive: webcrypto.generateKey always resolves a valid keypair here */
    if (!pair || !pair.publicKey) return false;
    // Confirm the toolkit can also mint a certificate under this key — some
    // key algorithms keygen in webcrypto but aren't wired through the X.509
    // signer, and selecting one we can't issue with would surface a
    // confusing failure on first real issuance.
    var spki = Buffer.from(await subtle.exportKey("spki", pair.publicKey));
    await pki.x509.sign({
      subject:      "probe",
      subjectPublicKey: spki,
      serialNumber: "0x01",
      notBefore:    new Date(),
      notAfter:     new Date(Date.now() + C.TIME.seconds(1)),
      extensions:   { basicConstraints: { cA: true } },
    }, { key: pair.privateKey }, { pem: true });
    return true;
  /* c8 ignore start -- probe never throws: every listed candidate algorithm is honoured by the runtime's OpenSSL 3.5+ */
  } catch (_e) {
    return false;
  }
  /* c8 ignore stop */
}

function _emitAlgorithmSelected(c, candidatesProbed) {
  setImmediate(function () {
    try {
      var auditMod = require("./audit");                                          // allow:inline-require — circular-load defense
      auditMod.safeEmit({
        action:   "mtls.engine.algorithm_selected",
        outcome:  "success",
        metadata: { label: c.label, posture: c.posture, candidatesProbed: candidatesProbed },
      });
    /* c8 ignore next -- belt-and-suspenders: audit.safeEmit is itself drop-silent, so this catch is unreachable */
    } catch (_e) { /* drop-silent */ }
  });
}

// Resolve the signing algorithm. With no argument the highest-posture
// candidate that probes clean is cached and reused. `preferredLabel` pins a
// specific candidate (the generateCa({ algorithm }) opt-in) — it must exist
// and probe clean, else the call throws rather than silently downgrading.
async function _selectAlgorithm(preferredLabel) {
  if (preferredLabel) {
    var wanted = null;
    for (var w = 0; w < ALG_CANDIDATES.length; w++) {
      if (ALG_CANDIDATES[w].label === preferredLabel || ALG_CANDIDATES[w].keyAlg.name === preferredLabel) {
        wanted = ALG_CANDIDATES[w];
        break;
      }
    }
    if (!wanted) {
      throw new MtlsEngineError("mtls-engine/unknown-algorithm",
        "unknown algorithm " + JSON.stringify(preferredLabel) + " — supported: " +
        ALG_CANDIDATES.map(function (c) { return c.label; }).join(", "));
    }
    /* c8 ignore start -- unreachable: every pinnable candidate probes clean on the runtime's OpenSSL 3.5+ */
    if (!(await _probeCandidate(wanted))) {
      throw new MtlsEngineError("mtls-engine/algorithm-unavailable",
        "algorithm " + JSON.stringify(preferredLabel) + " is not available in this runtime");
    }
    /* c8 ignore stop */
    // A pinned algorithm is per-call and MUST NOT be cached as the process
    // default. `_selectedAlg` is the shared fallback the no-argument path below
    // returns; writing a classical pin here would make a single
    // generateCa({ algorithm: "ECDSA-P384-SHA384" }) silently downgrade every
    // later default CA/leaf off the ML-DSA-87 PQC-first default in the same
    // process. Callers thread a pin explicitly through generateCa /
    // signClientCert instead (b.mtlsCa.create({ algorithm })).
    _lastSelectedAlg = wanted;   // reporting only — does NOT touch the default cache
    _emitAlgorithmSelected(wanted, 1);
    return wanted;
  }
  if (_selectedAlg) { _lastSelectedAlg = _selectedAlg; return _selectedAlg; }
  for (var i = 0; i < ALG_CANDIDATES.length; i++) {
    var c = ALG_CANDIDATES[i];
    if (await _probeCandidate(c)) {
      _selectedAlg = c;
      _lastSelectedAlg = c;
      _emitAlgorithmSelected(c, i + 1);
      return c;
    }
  }
  /* c8 ignore start -- unreachable: ECDSA-P384-SHA384 is universal, so the candidate loop always returns first */
  // Should never happen — ECDSA-P384 is universal.
  throw new MtlsEngineError("mtls-engine/no-algorithm",
    "no candidate algorithm passed the webcrypto + x509 probe");
  /* c8 ignore stop */
}

// PKCS#12 protection envelope. The cipher / PRF / MAC identifiers are
// protocol-fixed strings, and the iteration count is a cost parameter, not a
// byte quantity — hex form keeps it out of the byte-shape detector.
var P12_CIPHER   = "aes-256-cbc";
var P12_PRF      = "hmacWithSHA512";
var P12_MAC_HASH = "sha512";
var P12_ITER     = 0x1E8480; // 2,000,000 (PBMAC1 outer MAC + PBES2 bag KDF)
// The classic App. B.2 MacData KDF (RFC 7292) is a synchronous per-iteration
// hash loop, so it is capped ~10x below PBMAC1's native PBKDF2 — 1,000,000 is
// the toolkit's classic-MAC ceiling (~1s wall clock). Used only for the
// classical ECDSA-P384 bridge's legacy-importable MacData.
var P12_CLASSIC_MAC_ITER = 0xF4240; // 1,000,000

var CA_VALIDITY_DAYS    = 10 * 365; // 10y CA lifetime
var LEAF_DEFAULT_DAYS   = 365;
var DEFAULT_CA_NAME     = "blamejs CA";
// RFC 5280 removeFromCRL CRLReason — a delta-CRL un-revocation directive invalid
// in a full CRL; filtered out of full-CRL entries (see generateCrl).
var CRL_REMOVE_FROM_CRL = 8;

function _serial() {
  // pki wants a decimal or 0x-hex integer; generateToken yields hex octets.
  return "0x" + bCrypto.generateToken(C.BYTES.bytes(16));
}

function _ekuNames(usage) {
  var names = [];
  if (usage === "client" || usage === "both") names.push("clientAuth");
  if (usage === "server" || usage === "both") names.push("serverAuth");
  return names;
}

// Pack a textual IP into the DER octet form pki's iPAddress GeneralName
// expects (4 octets for IPv4, 16 for IPv6). Composes lib/ip-utils.
function _packIp(value) {
  var s = String(value);
  if (ipUtils.isIPv4(s)) {
    var quads = s.split(".");
    var buf4 = Buffer.alloc(4);
    for (var i = 0; i < 4; i++) {
      var n = parseInt(quads[i], 10);
      /* c8 ignore next -- unreachable: the IPv4 arm is entered only after isIPv4() validated each octet 0-255 */
      if (!(n >= 0 && n <= 255)) throw new MtlsEngineError("mtls-engine/bad-san", "invalid IPv4 SAN " + JSON.stringify(s));
      buf4[i] = n;
    }
    return buf4;
  }
  var groups;
  /* c8 ignore next -- unreachable: expandIpv6Groups returns null for malformed input rather than throwing */
  try { groups = ipUtils.expandIpv6Groups(s); } catch (_e) { groups = null; }
  if (Array.isArray(groups) && groups.length === 8) {
    var buf16 = Buffer.alloc(16);
    for (var g = 0; g < 8; g++) buf16.writeUInt16BE(groups[g] & 0xffff, g * 2);
    return buf16;
  }
  throw new MtlsEngineError("mtls-engine/bad-san", "invalid IP SAN " + JSON.stringify(s));
}

// Map operator SAN entries (strings, optionally "DNS:" / "IP:" prefixed) to
// pki GeneralName objects.
function _sanEntry(s) {
  var str = String(s);
  if (/^DNS:/i.test(str)) return { dNSName: str.slice(4) };
  if (/^IP:/i.test(str))  return { iPAddress: _packIp(str.slice(3)) };
  if (ipUtils.isIPv4(str)) return { iPAddress: _packIp(str) };
  // A bare IPv6 literal is an IP SAN too — auto-detect it symmetrically with
  // IPv4 (a colon-bearing literal can never be a valid DNS hostname, so it must
  // not fall through to the dNSName default and become an unmatchable SAN).
  var v6 = ipUtils.expandIpv6Groups(str);
  if (Array.isArray(v6) && v6.length === 8) return { iPAddress: _packIp(str) };
  // Bare non-IP entries default to DNS — matches operator expectation.
  return { dNSName: str };
}

function _normaliseCn(cn) {
  var s = String(cn || "").replace(/[^a-zA-Z0-9_.-]/g, "").slice(0, 63);
  if (!s) {
    throw new MtlsEngineError("mtls-engine/bad-cn",
      "cn must contain at least one [A-Za-z0-9._-] character (post-sanitisation)");
  }
  return s;
}

// The signature digest a CA private key should sign with. generateCa /
// signClientCert know their candidate's digest directly; generateCrl only has
// the CA key, so derive it: an EC (P-384) CA signs with SHA-384, matching the
// classical bridge's posture; ML-DSA is no-prehash (undefined -> the toolkit
// forces SHA-512), so return undefined for a non-EC or unparseable key.
function _digestForKey(caKeyPem) {
  try {
    return nodeCrypto.createPrivateKey(caKeyPem).asymmetricKeyType === "ec" ? "sha384" : undefined;
  /* c8 ignore next -- defensive: the default engine only signs CRLs with the CA key it just generated (always a parseable EC/ML-DSA key), so the parse never throws here */
  } catch (_e) { return undefined; }
}

async function generateCa(opts) {
  opts = opts || {};
  var generation = (typeof opts.generation === "number" && opts.generation >= 1)
    ? Math.floor(opts.generation) : 1;
  var caName = opts.name || DEFAULT_CA_NAME;

  var alg = await _selectAlgorithm(opts.algorithm);
  var keys = await subtle.generateKey(alg.keyAlg, true, CA_KEY_USAGES);
  var spki = Buffer.from(await subtle.exportKey("spki", keys.publicKey));
  var now  = new Date();

  var caCertPem = await pki.x509.sign({
    // Structured DN — a bare string subject is taken by the toolkit as the CN
    // VALUE (so "CN=name,OU=CAvN" would become a single CN literal, double-
    // encoded as CN=CN=name\,OU=CAvN with no real OU). Pass RDN objects so the
    // CN and the OU=CAv{N} generation tag are distinct attributes.
    subject:          [{ commonName: caName }, { organizationalUnitName: "CAv" + generation }],
    subjectPublicKey: spki,
    serialNumber:     _serial(),
    notBefore:        now,
    notAfter:         new Date(now.getTime() + C.TIME.days(CA_VALIDITY_DAYS)),
    extensions:       { basicConstraints: { cA: true, pathLen: 0 }, keyUsage: ["keyCertSign", "cRLSign"] },
  }, { key: keys.privateKey }, { pem: true, digestAlgorithm: alg.digest });

  var caKeyPem = await pki.key.export(keys.privateKey, { format: "pem" });
  return { caCertPem: caCertPem, caKeyPem: caKeyPem };
}

async function signClientCert(opts) {
  opts = opts || {};
  if (typeof opts.cn !== "string" || !opts.caCertPem || !opts.caKeyPem) {
    throw new MtlsEngineError("mtls-engine/missing-arg",
      "signClientCert requires { cn, caCertPem, caKeyPem }");
  }
  numericBounds.requirePositiveFiniteIntIfPresent(opts.validityDays,
    "signClientCert: validityDays", MtlsEngineError, "mtls-engine/bad-validity-days");
  var validityDays = opts.validityDays !== undefined
    ? opts.validityDays : LEAF_DEFAULT_DAYS;
  var cn = _normaliseCn(opts.cn);

  // Extended Key Usage: defaults to clientAuth (the historical behaviour).
  // usage: "server" -> serverAuth; "both" -> clientAuth + serverAuth.
  var usage = opts.usage || "client";
  var ekuNames = _ekuNames(usage);
  if (ekuNames.length === 0) {
    throw new MtlsEngineError("mtls-engine/bad-usage",
      "signClientCert: opts.usage must be 'client' | 'server' | 'both', got " +
      JSON.stringify(opts.usage));
  }

  // Subject Alternative Names — required for serverAuth (modern TLS clients
  // only honor SANs, not CN). Accept opts.sans as an array of strings.
  var sans = null;
  if (Array.isArray(opts.sans) && opts.sans.length > 0) {
    sans = opts.sans.map(_sanEntry);
  } else if (usage === "server" || usage === "both") {
    // serverAuth without a SAN is unverifiable by modern TLS clients.
    sans = [{ dNSName: cn }];
  }

  // Leaf key algorithm follows the CA's: an ML-DSA-87 default, or the classical
  // bridge when the caller pinned one (b.mtlsCa threads its create({ algorithm })
  // through here). Undefined selects the process default.
  var alg = await _selectAlgorithm(opts.algorithm);
  var clientKeys = await subtle.generateKey(alg.keyAlg, true, CA_KEY_USAGES);
  var clientSpki = Buffer.from(await subtle.exportKey("spki", clientKeys.publicKey));

  var now      = new Date();
  var notAfter = new Date(now.getTime() + C.TIME.days(validityDays));
  var extensions = {
    basicConstraints:         { cA: false },
    keyUsage:                 ["digitalSignature", "keyEncipherment"],
    extendedKeyUsage:         ekuNames,
    extendedKeyUsageCritical: true,
  };
  if (sans) extensions.subjectAltName = sans;

  var certPem = await pki.x509.sign({
    // A bare string subject is the CN VALUE (the toolkit wraps it as CN=<value>);
    // passing "CN=" + cn would double-encode to CN=CN=<cn>.
    subject:          cn,
    subjectPublicKey: clientSpki,
    serialNumber:     _serial(),
    notBefore:        now,
    notAfter:         notAfter,
    extensions:       extensions,
  }, { cert: opts.caCertPem, key: opts.caKeyPem }, { pem: true, digestAlgorithm: alg.digest });

  var keyPem = await pki.key.export(clientKeys.privateKey, { format: "pem" });
  return {
    cert:      certPem,
    key:       keyPem,
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
  // Resolve the leaf's algorithm tier so the outer MAC matches it. (signClientCert
  // resolves the same alg from opts.algorithm; undefined selects the default.)
  var alg  = await _selectAlgorithm(opts.algorithm);
  var leaf = await signClientCert(opts);

  var pbe = { password: opts.password, cipher: P12_CIPHER, iterations: P12_ITER, prf: P12_PRF };
  // The integrity MAC follows the cert's interop tier. The PQC-pure default uses
  // PBMAC1 (RFC 9579) — an ML-DSA peer already runs the OpenSSL 3.5 that supports
  // it. The classical ECDSA-P384 bridge exists FOR peers predating OpenSSL 3.5,
  // and PBMAC1 (OpenSSL 3.4+) would make the file unverifiable by exactly those
  // consumers, so it uses the universally-importable RFC 7292 App. B HMAC MacData
  // (at the classic KDF's lower iteration ceiling). PBES2 bag protection is
  // legacy-readable in both tiers, so only the MAC differs.
  var mac = alg.posture === "classical"
    ? { algorithm: "hmac",   hash: P12_MAC_HASH, iterations: P12_CLASSIC_MAC_ITER }
    : { algorithm: "pbmac1", hash: P12_MAC_HASH, iterations: P12_ITER };
  var p12 = await pki.pkcs12.build({
    safeContents: [
      { bags: [{ type: "shroudedKey", key: leaf.key, encrypt: pbe }] },
      { encrypt: pbe, bags: [
        { type: "cert", cert: leaf.cert },
        { type: "cert", cert: leaf.ca },
      ] },
    ],
  }, { password: opts.password, mac: mac });

  return {
    /* c8 ignore next -- defensive: pki.pkcs12.build always returns a Buffer, so the Buffer.from() arm is unreachable */
    p12:       Buffer.isBuffer(p12) ? p12 : Buffer.from(p12),
    certPem:   leaf.cert,
    issuedAt:  leaf.issuedAt,
    expiresAt: leaf.expiresAt,
  };
}

function algorithmEnvelope() {
  return {
    cert: {
      // Report the most-recent resolved algorithm (a pinned selection or the
      // default), so the envelope is accurate on the pinned issuance path too — not
      // just _selectedAlg (the default cache a pin deliberately never writes).
      keyAlg:   _lastSelectedAlg && _lastSelectedAlg.keyAlg,
      label:    _lastSelectedAlg && _lastSelectedAlg.label,
      posture:  _lastSelectedAlg && _lastSelectedAlg.posture,
      // Operators querying status() before any cert has been issued get the
      // candidate priority list — the engine probes lazily so the chosen
      // algorithm isn't known until first use.
      priority: ALG_CANDIDATES.map(function (c) {
        return { label: c.label, posture: c.posture };
      }),
    },
    p12: {
      contentEncryption: P12_CIPHER,       // PBES2 + AES-256-CBC bag protection (both tiers)
      kdfPrf:            P12_PRF,           // PBKDF2-HMAC-SHA-512 (both tiers)
      iterationCount:    P12_ITER,          // bag KDF iterations (both tiers)
      // The outer integrity MAC is tier-dependent: packageP12 selects it from the
      // cert algorithm's posture — PBMAC1 (RFC 9579) for the PQC default, the
      // traditional RFC 7292 HMAC MacData for the classical bridge so a
      // pre-OpenSSL-3.5 peer can verify it. Both are reported (keyed by posture)
      // so a consumer describes the archive it actually builds under either pin.
      mac: {
        "pqc-pure": { algorithm: "pbmac1", hash: P12_MAC_HASH, iterations: P12_ITER },
        classical:  { algorithm: "hmac",   hash: P12_MAC_HASH, iterations: P12_CLASSIC_MAC_ITER },
      },
    },
    caValidityDays:   CA_VALIDITY_DAYS,
    leafDefaultDays:  LEAF_DEFAULT_DAYS,
  };
}

// Generate a signed X.509 CRL (RFC 5280) covering every revoked serial
// number. pki.crl.sign builds the TBSCertList, populates the entries, and
// signs under the CA private key — the signature algorithm is resolved from
// the CA key, matching the algorithm the CA itself was issued under.
async function generateCrl(opts) {
  opts = opts || {};
  if (!opts.caCertPem || !opts.caKeyPem) {
    throw new MtlsEngineError("mtls-engine/missing-arg",
      "generateCrl requires { caCertPem, caKeyPem, revocations, thisUpdate, nextUpdate }");
  }
  var revocations = Array.isArray(opts.revocations) ? opts.revocations : [];

  var revoked = revocations.map(function (r) {
    var entry = {
      serialNumber:   _normaliseRevokedSerial(r.serialNumber),
      revocationDate: new Date(r.revokedAt || Date.now()),
    };
    // A full CRL (the only kind this CA issues) cannot carry removeFromCRL
    // (RFC 5280 code 8) — it is a delta-CRL un-revocation directive the toolkit
    // rejects, failing the ENTIRE CRL. revoke() refuses it going forward, but a
    // registry written by a pre-fix build (or hand-edited) may still hold one;
    // keep the serial revoked (it IS in the store — fail-secure) and DROP only the
    // invalid reason so one legacy entry can't block publishing every other
    // revocation.
    if (typeof r.reasonCode === "number" && r.reasonCode !== CRL_REMOVE_FROM_CRL) {
      entry.reason = r.reasonCode;
    }
    return entry;
  });

  return pki.crl.sign({
    thisUpdate: opts.thisUpdate || new Date(),
    nextUpdate: opts.nextUpdate,
    revoked:    revoked,
  }, { cert: opts.caCertPem, key: opts.caKeyPem }, { pem: true, digestAlgorithm: _digestForKey(opts.caKeyPem) });
}

// A revoked serial arrives as the hex string the engine issued (no 0x
// prefix). pki wants a decimal or 0x-hex integer, so prefix bare hex.
function _normaliseRevokedSerial(serial) {
  var s = String(serial == null ? "" : serial);
  if (/^0x/i.test(s)) return s;
  if (safeBuffer.isHex(s)) return "0x" + s;
  return s;
}

// Loopback mTLS self-test: does node:tls VERIFY a certificate chain issued
// under `label` on THIS runtime? Issuance succeeding (generateCa/signClientCert)
// does NOT prove verification — ML-DSA chains verify in node:tls only on the
// supported OpenSSL (>= 3.5), which is the property that actually gates a safe
// algorithm flip. Generates a throwaway CA + server + client leaf under the
// label and runs a real loopback mTLS handshake: the server reaching its
// secureConnection handler under requestCert+rejectUnauthorized means the
// client verified the server chain AND the server verified the client chain
// (TLS 1.3 verifies the server cert before the client sends its own). Resolves
// true only when both directions authorize; any issuance/load/handshake failure
// -> false. Never throws.
async function canVerifyInTls(label) {
  var ca, serverLeaf, clientLeaf;
  try {
    ca = await generateCa({ algorithm: label });
    var leafArgs = { caCertPem: ca.caCertPem, caKeyPem: ca.caKeyPem, usage: "both", algorithm: label, validityDays: 1 };
    serverLeaf = await signClientCert(Object.assign({ cn: "localhost" }, leafArgs));
    clientLeaf = await signClientCert(Object.assign({ cn: "mtls-tls-probe" }, leafArgs));
  } catch (_e) {
    // Can't even issue under this label on this runtime -> can't use it.
    return false;
  }
  return new Promise(function (resolve) {
    var settled = false;
    var server = null;
    var client = null;
    var serverSocket = null;
    var timer = null;
    function finish(ok) {
      if (settled) return;
      settled = true;
      if (timer) clearTimeout(timer);
      // Destroy BOTH ends before closing the listener: server.close() stops
      // accepting but does NOT tear down a live/stalled handshake, so on the
      // timeout path a client (and any accepted server) socket would otherwise
      // leak — keeping a short-lived migration command from exiting.
      try { if (client) client.destroy(); } catch (_e) { /* best-effort */ }
      try { if (serverSocket) serverSocket.destroy(); } catch (_e) { /* best-effort */ }
      try { if (server) server.close(); } catch (_e) { /* best-effort */ }
      resolve(ok === true);
    }
    try {
      server = nodeTls.createServer({
        key: serverLeaf.key, cert: serverLeaf.cert, ca: [ca.caCertPem],
        requestCert: true, rejectUnauthorized: true, minVersion: "TLSv1.3",
      }, function (socket) {
        serverSocket = socket;
        var authorized = socket.authorized === true;
        socket.on("error", function () { /* client-side close race */ });
        socket.end();
        finish(authorized);
      });
      // A client whose chain the server can't verify surfaces here, not at the
      // connection handler — fail fast instead of waiting out the timeout.
      server.on("tlsClientError", function () { finish(false); });
      server.on("error", function () { finish(false); });
      timer = setTimeout(function () { finish(false); }, 8000);
      if (typeof timer.unref === "function") timer.unref();
      server.listen(0, "127.0.0.1", function () {
        var port = server.address().port;
        client = nodeTls.connect(Object.assign({
          host: "127.0.0.1", port: port, servername: "localhost",
          key: clientLeaf.key, cert: clientLeaf.cert, ca: [ca.caCertPem],
          rejectUnauthorized: true,
        }, networkTls().outboundPosture()));
        client.on("secureConnect", function () { client.end(); });
        // Client rejected the server chain (or any transport fault) -> false.
        client.on("error", function () { finish(false); });
      });
    } catch (_e) {
      finish(false);
    }
  });
}

module.exports = {
  generateCa:         generateCa,
  signClientCert:     signClientCert,
  packageP12:         packageP12,
  generateCrl:        generateCrl,
  canVerifyInTls:     canVerifyInTls,
  algorithmEnvelope:  algorithmEnvelope,
  MtlsEngineError:    MtlsEngineError,
};
