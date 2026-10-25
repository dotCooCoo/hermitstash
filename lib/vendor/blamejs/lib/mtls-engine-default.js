// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module b.mtlsEngine
 * @nav    Crypto
 * @title  mTLS Engine
 * @slug   mtls-engine
 *
 * @intro
 *   The certificate authority behind <code>b.mtlsCa</code>: issuing the CA,
 *   signing client certificates, packaging them as PKCS#12, and publishing
 *   revocations.
 *
 *   The signature algorithm is chosen by trying the strongest candidate the
 *   runtime can actually use, starting at ML-DSA-87 and falling back through
 *   the rest. The probe generates a keypair and signs a certificate with it,
 *   so the choice is made against what the runtime does rather than what it
 *   advertises.
 *
 *   The probe stops there. It does not complete a TLS handshake, so a runtime
 *   that can sign a certificate its own TLS stack will not accept keeps the
 *   stronger candidate. <code>canVerifyInTls(label)</code> is the separate
 *   check that answers the handshake question, and a deployment that needs
 *   that guarantee calls it and pins the algorithm it reports.
 *
 *   <code>algorithmEnvelope()</code> is how that selection becomes auditable:
 *   it reports which algorithm was chosen, its posture, the whole priority
 *   list that was tried, and the PKCS#12 encryption and MAC parameters. An
 *   operator asked which algorithm their client certificates use has an answer
 *   rather than a default to look up.
 *
 * @card
 *   Issue an mTLS CA, sign client certificates and publish CRLs, choosing the
 *   strongest signature algorithm the runtime can sign with and reporting
 *   which one that was. Whether the local TLS stack will accept it is a
 *   separate check.
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

var LEAF_KEY_USAGE = Object.freeze(["digitalSignature"]);

var CA_CERT_EXTENSIONS = Object.freeze({
  basicConstraints: Object.freeze({ cA: true, pathLen: 0 }),
  keyUsage:         Object.freeze(["keyCertSign", "cRLSign"]),
});

var ALG_CANDIDATES = [
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
  {
    label:  "ECDSA-P384-SHA384",
    keyAlg: { name: "ECDSA", namedCurve: "P-384" },
    posture: "classical",
    digest: "sha384",
  },
];

var _selectedAlg = null;
var _lastSelectedAlg = null;

async function _probeCandidate(c) {
  try {
    var pair = await subtle.generateKey(c.keyAlg, true, CA_KEY_USAGES);
    /* c8 ignore next -- defensive: webcrypto.generateKey always resolves a valid keypair here */
    if (!pair || !pair.publicKey) return false;
    var spki = Buffer.from(await subtle.exportKey("spki", pair.publicKey));
    await pki.x509.sign({
      subject:      "probe",
      subjectPublicKey: spki,
      serialNumber: "0x01",
      notBefore:    new Date(),
      notAfter:     new Date(Date.now() + C.TIME.seconds(1)),
      extensions:   CA_CERT_EXTENSIONS,
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

async function _selectAlgorithm(preferredLabel) {
  if (preferredLabel !== undefined && (typeof preferredLabel !== "string" || preferredLabel === "")) {
    throw new MtlsEngineError("mtls-engine/unknown-algorithm",
      "unknown algorithm " + JSON.stringify(preferredLabel) + " — supported: " +
      ALG_CANDIDATES.map(function (c) { return c.label; }).join(", "));
  }
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
    _lastSelectedAlg = wanted;
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
  throw new MtlsEngineError("mtls-engine/no-algorithm",
    "no candidate algorithm passed the webcrypto + x509 probe");
  /* c8 ignore stop */
}

var P12_CIPHER   = "aes-256-cbc";
var P12_PRF      = "hmacWithSHA512";
var P12_MAC_HASH = "sha512";
var P12_ITER     = 0x1E8480;
var P12_CLASSIC_MAC_ITER = 0xF4240;

var CA_VALIDITY_DAYS    = 10 * 365;
var LEAF_DEFAULT_DAYS   = 365;
var CRL_DEFAULT_VALIDITY_DAYS = 7;
var DEFAULT_CA_NAME     = "blamejs CA";
var CRL_REMOVE_FROM_CRL = 8;
var MAX_DNS_NAME_OCTETS  = 253;
var MAX_DNS_LABEL_OCTETS = 63;

function _serial() {
  return "0x" + bCrypto.generateToken(C.BYTES.bytes(16));
}

function _ekuNames(usage) {
  var names = [];
  if (usage === "client" || usage === "both") names.push("clientAuth");
  if (usage === "server" || usage === "both") names.push("serverAuth");
  return names;
}

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

function _isDnsLabel(label) {
  if (label.length === 0 || label.length > MAX_DNS_LABEL_OCTETS) return false;
  if (label.charCodeAt(0) === 0x2d) return false;
  if (label.charCodeAt(label.length - 1) === 0x2d) return false;
  for (var i = 0; i < label.length; i++) {
    var cc = label.charCodeAt(i);
    var isLdh = (cc >= 0x61 && cc <= 0x7a) || (cc >= 0x41 && cc <= 0x5a) ||
                (cc >= 0x30 && cc <= 0x39) || cc === 0x2d || cc === 0x5f;
    if (!isLdh) return false;
  }
  return true;
}

function _assertDnsSanName(name) {
  var ok = typeof name === "string" && name.length > 0 &&
           name.length <= MAX_DNS_NAME_OCTETS;
  if (ok) {
    var labels = name.split(".");
    var first = labels[0] === "*" && labels.length > 1 ? 1 : 0;
    for (var i = first; i < labels.length; i++) {
      if (!_isDnsLabel(labels[i])) { ok = false; break; }
    }
  }
  if (!ok) {
    throw new MtlsEngineError("mtls-engine/bad-san",
      "invalid DNS SAN " + JSON.stringify(String(name)) + ": a dNSName is 1 to " +
      MAX_DNS_NAME_OCTETS + " octets in labels of 1 to " + MAX_DNS_LABEL_OCTETS +
      " letters, digits, '-' or '_', each label starting and ending with a " +
      "letter, digit or '_', optionally behind a single '*' label");
  }
  return name;
}

function _sanEntry(s) {
  if (typeof s !== "string") {
    throw new MtlsEngineError("mtls-engine/bad-san",
      "invalid SAN of type " + (s === null ? "null" : typeof s) +
      ": each entry must be a string");
  }
  var str = s;
  if (/^DNS:/i.test(str)) return { dNSName: _assertDnsSanName(str.slice(4)) };
  if (/^IP:/i.test(str))  return { iPAddress: _packIp(str.slice(3)) };
  if (ipUtils.isIPv4(str)) return { iPAddress: _packIp(str) };
  var v6 = ipUtils.expandIpv6Groups(str);
  if (Array.isArray(v6) && v6.length === 8) return { iPAddress: _packIp(str) };
  return { dNSName: _assertDnsSanName(str) };
}

function _normaliseCn(cn) {
  var s = String(cn || "").replace(/[^a-zA-Z0-9_.-]/g, "").slice(0, 63);
  if (!s) {
    throw new MtlsEngineError("mtls-engine/bad-cn",
      "cn must contain at least one [A-Za-z0-9._-] character (post-sanitisation)");
  }
  return s;
}

function _digestForKey(caKeyPem) {
  try {
    return nodeCrypto.createPrivateKey(caKeyPem).asymmetricKeyType === "ec" ? "sha384" : undefined;
  /* c8 ignore next -- defensive: the default engine only signs CRLs with the CA key it just generated (always a parseable EC/ML-DSA key), so the parse never throws here */
  } catch (_e) { return undefined; }
}

/**
 * @primitive b.mtlsEngine.generateCa
 * @signature b.mtlsEngine.generateCa(opts?)
 * @since     0.3.37
 * @status    stable
 * @related   b.mtlsEngine.signClientCert, b.mtlsEngine.algorithmEnvelope, b.mtlsCa.create
 *
 * Generate a CA keypair and self-signed certificate, and resolve with
 * `{ caCertPem, caKeyPem }`.
 *
 * Left to itself, the signature algorithm is selected by capability rather
 * than configuration: the strongest candidate the runtime can generate a key
 * for and sign a certificate with wins, and `algorithmEnvelope()` reports
 * which one that was. The selection does not test a TLS handshake;
 * `canVerifyInTls` does that separately.
 *
 * `algorithm` is an exact pin, not a preference. The named candidate is the
 * one used, with no fallback and no comparison against the others, so naming
 * a classical candidate issues under it even where ML-DSA is available. A name
 * outside the candidates raises `mtls-engine/unknown-algorithm` listing them,
 * and one the runtime cannot sign with raises
 * `mtls-engine/algorithm-unavailable` rather than quietly choosing something
 * else. With no `algorithm`, a runtime that can sign with none of the
 * candidates raises `mtls-engine/no-algorithm`.
 *
 * `generation` is recorded in the subject as `CAv<n>`, which is how two
 * generations of CA are told apart during a rollover while both are trusted.
 * It defaults to 1.
 *
 * @opts
 *   name:       string,   // CA common name
 *   generation: number,   // recorded as CAv<n>; default 1
 *   algorithm:  string,   // exact pin; no fallback. Omit to select by capability
 *
 * @example
 *   var b = require("@blamejs/core");
 *   var ca = await b.mtlsEngine.generateCa({ name: "Acme Internal CA" });
 *   b.mtlsEngine.algorithmEnvelope().cert.label;   // → the algorithm used
 */
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
    subject:          [{ commonName: caName }, { organizationalUnitName: "CAv" + generation }],
    subjectPublicKey: spki,
    serialNumber:     _serial(),
    notBefore:        now,
    notAfter:         new Date(now.getTime() + C.TIME.days(CA_VALIDITY_DAYS)),
    extensions:       CA_CERT_EXTENSIONS,
  }, { key: keys.privateKey }, { pem: true, digestAlgorithm: alg.digest });

  var caKeyPem = await pki.key.export(keys.privateKey, { format: "pem" });
  return { caCertPem: caCertPem, caKeyPem: caKeyPem };
}

/**
 * @primitive b.mtlsEngine.signClientCert
 * @signature b.mtlsEngine.signClientCert(opts)
 * @since     0.3.37
 * @status    stable
 * @related   b.mtlsEngine.generateCa, b.mtlsEngine.packageP12, b.mtlsEngine.generateCrl
 *
 * Sign a leaf certificate under the CA and resolve with the certificate and
 * its key.
 *
 * `cn`, `caCertPem` and `caKeyPem` are required, raising
 * `mtls-engine/missing-arg` otherwise. `usage` is `client`, `server` or `both`
 * and decides the extended key usage; anything else raises
 * `mtls-engine/bad-usage` rather than producing a certificate with no usage,
 * which a peer would reject in a way that is hard to diagnose.
 *
 * `validityDays` must be a positive integer and defaults to the leaf default,
 * which is short: a client certificate is meant to be reissued, and a long one
 * is a revocation problem waiting to happen. A value that is not raises
 * `mtls-engine/bad-validity-days`.
 *
 * A `cn` that is empty once normalized raises `mtls-engine/bad-cn`. Each entry
 * of `sans` is a string holding a hostname, an IPv4 or IPv6 address, or either
 * behind a `DNS:` or `IP:` prefix, and anything else raises
 * `mtls-engine/bad-san`, including a `null` or a number left by a
 * configuration placeholder, which would otherwise become the DNS name
 * `"null"` or `"123"`. `sans` itself has to be an array whenever it is
 * present: a bare string, or a `null` left by a configuration placeholder,
 * raises the same code rather than reading as no `sans` at all, which issued
 * a certificate for the common name instead of the identity configured. A
 * hostname
 * is 1 to 253 octets in labels of 1 to 63 letters, digits, `-` or `_`, with an
 * optional leading `*` label; a name like `"not a host"` is refused rather
 * than written into a certificate nothing can match. For `usage` `server` or
 * `both` with no `sans`, the normalized `cn` becomes the one dNSName and is
 * held to the same rule. On the algorithm:
 * `mtls-engine/unknown-algorithm` names one this build does not implement,
 * `mtls-engine/algorithm-unavailable` one the runtime will not sign with, and
 * `mtls-engine/no-algorithm` means no candidate survived the capability probe
 * at all.
 *
 * @opts
 *   cn:           string,   // required; the subject common name
 *   caCertPem:    string,   // required; the issuing CA certificate
 *   caKeyPem:     string,   // required; the issuing CA key
 *   usage:        string,   // client | server | both; default "client"
 *   validityDays: number,   // positive integer
 *   sans:         array,    // subject alternative names; must be an array
 *   algorithm:    string,   // exact pin; no fallback. Omit to select by capability
 *
 * @example
 *   var b = require("@blamejs/core");
 *   var leaf = await b.mtlsEngine.signClientCert({
 *     cn:        "worker-7",
 *     caCertPem: ca.caCertPem,
 *     caKeyPem:  ca.caKeyPem,
 *     usage:     "client",
 *   });
 */
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

  if (opts.usage !== undefined && typeof opts.usage !== "string") {
    throw new MtlsEngineError("mtls-engine/bad-usage",
      "signClientCert: opts.usage must be 'client' | 'server' | 'both', got " +
      (opts.usage === null ? "null" : typeof opts.usage) +
      ". Reading a placeholder as absent issues a clientAuth-only certificate, " +
      "which is not the identity that was configured");
  }
  var usage = opts.usage || "client";
  var ekuNames = _ekuNames(usage);
  if (ekuNames.length === 0) {
    throw new MtlsEngineError("mtls-engine/bad-usage",
      "signClientCert: opts.usage must be 'client' | 'server' | 'both', got " +
      JSON.stringify(opts.usage));
  }

  if (opts.sans !== undefined && !Array.isArray(opts.sans)) {
    throw new MtlsEngineError("mtls-engine/bad-san",
      "invalid sans of type " + (opts.sans === null ? "null" : typeof opts.sans) +
      ": opts.sans must be an array of strings");
  }
  var sans = null;
  if (Array.isArray(opts.sans) && opts.sans.length > 0) {
    sans = opts.sans.map(_sanEntry);
  } else if (usage === "server" || usage === "both") {
    sans = [{ dNSName: _assertDnsSanName(cn) }];
  }

  var alg = await _selectAlgorithm(opts.algorithm);
  var clientKeys = await subtle.generateKey(alg.keyAlg, true, CA_KEY_USAGES);
  var clientSpki = Buffer.from(await subtle.exportKey("spki", clientKeys.publicKey));

  var now      = new Date();
  var notAfter = new Date(now.getTime() + C.TIME.days(validityDays));
  var extensions = {
    basicConstraints:         { cA: false },
    keyUsage:                 LEAF_KEY_USAGE,
    extendedKeyUsage:         ekuNames,
    extendedKeyUsageCritical: true,
  };
  if (sans) extensions.subjectAltName = sans;

  var certPem = await pki.x509.sign({
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

/**
 * @primitive b.mtlsEngine.packageP12
 * @signature b.mtlsEngine.packageP12(opts)
 * @since     0.3.37
 * @status    stable
 * @related   b.mtlsEngine.signClientCert, b.mtlsEngine.algorithmEnvelope
 *
 * Sign a leaf certificate and package it with its key as PKCS#12, the format a
 * browser or an operating system keychain imports.
 *
 * It takes everything `signClientCert` takes, plus a non-empty `password`;
 * without one it raises `mtls-engine/no-password`, since an unprotected
 * PKCS#12 file is a private key in the clear.
 *
 * Because it signs the leaf itself, every refusal `signClientCert` makes
 * reaches this call too: `mtls-engine/missing-arg` for an absent `cn`,
 * `caCertPem` or `caKeyPem`, `mtls-engine/bad-cn` for a common name empty once
 * normalized, `mtls-engine/bad-usage` for a usage outside client, server and
 * both, `mtls-engine/bad-validity-days` for a validity that is not a positive
 * integer, `mtls-engine/bad-san` for a subject alternative name that is
 * neither a hostname nor an IP address, and `mtls-engine/unknown-algorithm`,
 * `mtls-engine/algorithm-unavailable` or `mtls-engine/no-algorithm` on the
 * algorithm choice.
 *
 * The MAC follows the certificate's posture: a post-quantum certificate is
 * packaged with PBMAC1, and a classical one with HMAC at a higher iteration
 * count, because an importer that understands one may not understand the
 * other. `algorithmEnvelope()` reports both parameter sets.
 *
 * @opts
 *   password:     string,   // required; protects the PKCS#12 file
 *   cn:           string,   // required; the subject common name
 *   caCertPem:    string,   // required; the issuing CA certificate
 *   caKeyPem:     string,   // required; the issuing CA key
 *   usage:        string,   // client | server | both
 *   validityDays: number,   // positive integer
 *   sans:         array,    // subject alternative names, as signClientCert takes them
 *   algorithm:    string,   // exact pin; no fallback. Omit to select by capability
 *
 * @example
 *   var b = require("@blamejs/core");
 *   var p12 = await b.mtlsEngine.packageP12({
 *     cn:        "worker-7",
 *     caCertPem: ca.caCertPem,
 *     caKeyPem:  ca.caKeyPem,
 *     password:  process.env.P12_PASSWORD,
 *   });
 */
async function packageP12(opts) {
  opts = opts || {};
  if (typeof opts.password !== "string" || opts.password.length < 1) {
    throw new MtlsEngineError("mtls-engine/no-password",
      "packageP12 requires opts.password (non-empty string)");
  }
  var alg  = await _selectAlgorithm(opts.algorithm);
  var leaf = await signClientCert(opts);

  var pbe = { password: opts.password, cipher: P12_CIPHER, iterations: P12_ITER, prf: P12_PRF };
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

/**
 * @primitive b.mtlsEngine.algorithmEnvelope
 * @signature b.mtlsEngine.algorithmEnvelope()
 * @since     0.3.37
 * @status    stable
 * @compliance soc2
 * @related   b.mtlsEngine.generateCa, b.mtlsEngine.canVerifyInTls
 *
 * Report which signature algorithm the last issuance selected, its posture,
 * the priority list that was tried, and the PKCS#12 encryption and MAC
 * parameters.
 *
 * This is the answer to "which algorithm are our client certificates signed
 * with", which is otherwise a question about what the runtime happened to
 * support. Because the choice is made by probing rather than from
 * configuration, reporting it is the only way an operator or an auditor can
 * know.
 *
 * `cert.posture` is `pqc-pure` or `classical`, and `cert.priority` is the full
 * candidate list in order, so a deployment that fell back can see what it fell
 * back from.
 *
 * @example
 *   var b = require("@blamejs/core");
 *   var env = b.mtlsEngine.algorithmEnvelope();
 *   env.cert.label;                // → e.g. "ML-DSA-87"
 *   env.cert.posture;              // → "pqc-pure" or "classical"
 */
function algorithmEnvelope() {
  return {
    cert: {
      keyAlg:   _lastSelectedAlg && _lastSelectedAlg.keyAlg,
      label:    _lastSelectedAlg && _lastSelectedAlg.label,
      posture:  _lastSelectedAlg && _lastSelectedAlg.posture,
      priority: ALG_CANDIDATES.map(function (c) {
        return { label: c.label, posture: c.posture };
      }),
    },
    p12: {
      contentEncryption: P12_CIPHER,
      kdfPrf:            P12_PRF,
      iterationCount:    P12_ITER,
      mac: {
        "pqc-pure": { algorithm: "pbmac1", hash: P12_MAC_HASH, iterations: P12_ITER },
        classical:  { algorithm: "hmac",   hash: P12_MAC_HASH, iterations: P12_CLASSIC_MAC_ITER },
      },
    },
    caValidityDays:   CA_VALIDITY_DAYS,
    leafDefaultDays:  LEAF_DEFAULT_DAYS,
  };
}

/**
 * @primitive b.mtlsEngine.generateCrl
 * @signature b.mtlsEngine.generateCrl(opts)
 * @since     0.6.45
 * @status    stable
 * @related   b.mtlsEngine.signClientCert, b.mtlsCa.create
 *
 * Sign a certificate revocation list and resolve with it.
 *
 * An absent `caCertPem` or `caKeyPem` raises `mtls-engine/missing-arg`.
 *
 * `crlNumber` must be a positive integer, raising
 * `mtls-engine/bad-crl-number` otherwise. RFC 5280 section 5.2.3 also requires
 * it to increase with every CRL an issuer signs, and that part is the caller's
 * to hold: this function keeps no record of what it issued before, so a
 * repeated or lower number is accepted. A relying party given one may keep an
 * older list, which is how a revoked certificate stays accepted, so allocate
 * the number from somewhere that cannot hand out the same one twice.
 *
 * `revocations` lists the serials and their revocation times. An omitted
 * `revocations` is a valid CRL saying nothing is revoked, which is what a
 * fresh issuer publishes, and so is an empty array; anything else present
 * there raises `mtls-engine/bad-revocations` rather than being read as that
 * empty list, since a `null` placeholder, a single unwrapped entry or a JSON
 * string would otherwise sign a list asserting that nothing is revoked.
 * `thisUpdate` and `nextUpdate` set the validity window and each has to be a
 * `Date`, raising `mtls-engine/bad-crl-date` otherwise; an epoch number, which
 * is the shape a config file or an HTTP body carries, previously reached the
 * signer and raised an uncoded `TypeError`. A relying party is entitled to
 * cache the list until `nextUpdate`.
 *
 * @opts
 *   caCertPem:   string,   // required; the issuing CA certificate
 *   caKeyPem:    string,   // required; the issuing CA key
 *   crlNumber:   number,   // required; positive, strictly increasing
 *   revocations: array,    // serials with their revocation times
 *   thisUpdate:  object,   // Date the list is issued
 *   nextUpdate:  object,   // Date the list expires
 *
 * @example
 *   var b = require("@blamejs/core");
 *   var crl = await b.mtlsEngine.generateCrl({
 *     caCertPem:   ca.caCertPem,
 *     caKeyPem:    ca.caKeyPem,
 *     crlNumber:   1,
 *     revocations: [],
 *   });
 */
async function generateCrl(opts) {
  opts = opts || {};
  if (!opts.caCertPem || !opts.caKeyPem) {
    throw new MtlsEngineError("mtls-engine/missing-arg",
      "generateCrl requires { caCertPem, caKeyPem, revocations, thisUpdate, nextUpdate, crlNumber }");
  }
  if (typeof opts.crlNumber !== "number" || !isFinite(opts.crlNumber) ||
      Math.floor(opts.crlNumber) !== opts.crlNumber || opts.crlNumber < 1) {
    throw new MtlsEngineError("mtls-engine/bad-crl-number",
      "generateCrl requires opts.crlNumber as a positive integer that increases with every CRL this issuer " +
      "signs (RFC 5280 §5.2.3), got " + JSON.stringify(opts.crlNumber));
  }
  if (opts.revocations !== undefined && !Array.isArray(opts.revocations)) {
    throw new MtlsEngineError("mtls-engine/bad-revocations",
      "generateCrl: opts.revocations must be an array of { serialNumber, revokedAt?, reasonCode? }, got " +
      (opts.revocations === null ? "null" : typeof opts.revocations) +
      ". Reading a non-array as an empty list signs a CRL asserting that nothing is revoked, " +
      "which a relying party caches until nextUpdate");
  }
  var revocations = opts.revocations || [];

  if (opts.thisUpdate !== undefined && !(opts.thisUpdate instanceof Date)) {
    throw new MtlsEngineError("mtls-engine/bad-crl-date",
      "generateCrl: opts.thisUpdate must be a Date, got " +
      (opts.thisUpdate === null ? "null" : typeof opts.thisUpdate));
  }
  if (opts.nextUpdate !== undefined && !(opts.nextUpdate instanceof Date)) {
    throw new MtlsEngineError("mtls-engine/bad-crl-date",
      "generateCrl: opts.nextUpdate must be a Date, got " +
      (opts.nextUpdate === null ? "null" : typeof opts.nextUpdate));
  }

  var revoked = revocations.map(function (r) {
    var entry = {
      serialNumber:   _normaliseRevokedSerial(r.serialNumber),
      revocationDate: new Date(r.revokedAt || Date.now()),
    };
    if (typeof r.reasonCode === "number" && r.reasonCode !== CRL_REMOVE_FROM_CRL) {
      entry.reason = r.reasonCode;
    }
    return entry;
  });

  var thisUpdate = opts.thisUpdate || new Date();
  return pki.crl.sign({
    thisUpdate: thisUpdate,
    nextUpdate: opts.nextUpdate ||
                new Date(thisUpdate.getTime() + C.TIME.days(CRL_DEFAULT_VALIDITY_DAYS)),
    revoked:    revoked,
    crlNumber:  opts.crlNumber,
  }, { cert: opts.caCertPem, key: opts.caKeyPem }, { pem: true, digestAlgorithm: _digestForKey(opts.caKeyPem) });
}

function _normaliseRevokedSerial(serial) {
  var s = String(serial == null ? "" : serial);
  if (/^0x/i.test(s)) return s;
  if (safeBuffer.isHex(s)) return "0x" + s;
  return s;
}

/**
 * @primitive b.mtlsEngine.canVerifyInTls
 * @signature b.mtlsEngine.canVerifyInTls(label)
 * @since     0.18.3
 * @status    stable
 * @related   b.mtlsEngine.algorithmEnvelope, b.mtlsEngine.generateCa
 *
 * Answer whether this runtime can complete a mutually-authenticated TLS
 * handshake using certificates signed with the named algorithm.
 *
 * It finds out by doing it: a throwaway CA and two one-day leaves are issued
 * under that algorithm and a real handshake is attempted between them. A
 * runtime that can generate a key and sign a certificate may still fail to
 * verify it during a handshake, so asking the TLS stack is the only answer
 * worth having.
 *
 * The handshake uses the live key-exchange posture: the client offers
 * `b.network.tls.outboundPosture()` and the listener takes
 * `b.network.tls.serverKeyAgreementGroups()`, so a posture narrowed with
 * `b.network.tls.preferredGroups.set(...)` is probed as configured.
 *
 * The client runs the certificate chain check every framework dial runs (see
 * `b.network.tls.applyToContext`). The answer is `true` only when the
 * listener authorizes the client and the client accepts the listener's chain.
 *
 * It answers `false` rather than raising, for any failure at any stage, which
 * is what makes it usable as the selection probe behind the algorithm choice.
 *
 * @example
 *   var b = require("@blamejs/core");
 *   await b.mtlsEngine.canVerifyInTls("ML-DSA-87");   // → true or false here
 */
async function canVerifyInTls(label) {
  var ca, serverLeaf, clientLeaf;
  try {
    ca = await generateCa({ algorithm: label });
    var leafArgs = { caCertPem: ca.caCertPem, caKeyPem: ca.caKeyPem, usage: "both", algorithm: label, validityDays: 1 };
    serverLeaf = await signClientCert(Object.assign({ cn: "localhost" }, leafArgs));
    clientLeaf = await signClientCert(Object.assign({ cn: "mtls-tls-probe" }, leafArgs));
  } catch (_e) {
    return false;
  }
  return new Promise(function (resolve) {
    var settled = false;
    var server = null;
    var client = null;
    var serverSocket = null;
    var timer = null;
    var serverAuthorized = null;
    var clientConnected = false;
    function finishWhenBothSides() {
      if (serverAuthorized !== null && clientConnected) finish(serverAuthorized);
    }
    function finish(ok) {
      if (settled) return;
      settled = true;
      if (timer) clearTimeout(timer);
      try { if (client) client.destroy(); } catch (_e) { /* best-effort */ }
      try { if (serverSocket) serverSocket.destroy(); } catch (_e) { /* best-effort */ }
      try { if (server) server.close(); } catch (_e) { /* best-effort */ }
      resolve(ok === true);
    }
    try {
      server = nodeTls.createServer({
        key: serverLeaf.key, cert: serverLeaf.cert, ca: [ca.caCertPem],
        requestCert: true, rejectUnauthorized: true, minVersion: "TLSv1.3",
        ecdhCurve: networkTls().serverKeyAgreementGroups(),
      }, function (socket) {
        serverSocket = socket;
        serverAuthorized = socket.authorized === true;
        socket.on("error", function () { /* client-side close race */ });
        socket.end();
        if (!serverAuthorized) finish(false);
        else finishWhenBothSides();
      });
      server.on("tlsClientError", function () { finish(false); });
      server.on("error", function () { finish(false); });
      timer = setTimeout(function () { finish(false); }, 8000);
      if (typeof timer.unref === "function") timer.unref();
      server.listen(0, "127.0.0.1", function () {
        var port = server.address().port;
        var trusted = [ca.caCertPem];
        client = nodeTls.connect(Object.assign({
          host: "127.0.0.1", port: port, servername: "localhost",
          key: clientLeaf.key, cert: clientLeaf.cert, ca: trusted,
          rejectUnauthorized: true,
          checkServerIdentity: networkTls()._withCompromisedChainCheck(undefined, trusted),
        }, networkTls().outboundPosture()));
        client.on("secureConnect", function () {
          clientConnected = true;
          client.end();
          finishWhenBothSides();
        });
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
