// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

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
var DEFAULT_CA_NAME     = "blamejs CA";
var CRL_REMOVE_FROM_CRL = 8;

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

function _sanEntry(s) {
  var str = String(s);
  if (/^DNS:/i.test(str)) return { dNSName: str.slice(4) };
  if (/^IP:/i.test(str))  return { iPAddress: _packIp(str.slice(3)) };
  if (ipUtils.isIPv4(str)) return { iPAddress: _packIp(str) };
  var v6 = ipUtils.expandIpv6Groups(str);
  if (Array.isArray(v6) && v6.length === 8) return { iPAddress: _packIp(str) };
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

  var usage = opts.usage || "client";
  var ekuNames = _ekuNames(usage);
  if (ekuNames.length === 0) {
    throw new MtlsEngineError("mtls-engine/bad-usage",
      "signClientCert: opts.usage must be 'client' | 'server' | 'both', got " +
      JSON.stringify(opts.usage));
  }

  var sans = null;
  if (Array.isArray(opts.sans) && opts.sans.length > 0) {
    sans = opts.sans.map(_sanEntry);
  } else if (usage === "server" || usage === "both") {
    sans = [{ dNSName: cn }];
  }

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

function _normaliseRevokedSerial(serial) {
  var s = String(serial == null ? "" : serial);
  if (/^0x/i.test(s)) return s;
  if (safeBuffer.isHex(s)) return "0x" + s;
  return s;
}

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
      }, function (socket) {
        serverSocket = socket;
        var authorized = socket.authorized === true;
        socket.on("error", function () { /* client-side close race */ });
        socket.end();
        finish(authorized);
      });
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
