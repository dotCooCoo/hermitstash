"use strict";

var tls = require("node:tls");
var fs = require("node:fs");
var path = require("node:path");
var nodeCrypto = require("node:crypto");

var C = require("./constants");
var safeBuffer = require("./safe-buffer");
var validateOpts = require("./validate-opts");
var lazyRequire = require("./lazy-require");
var safeAsync = require("./safe-async");
var { defineClass } = require("./framework-error");

var TlsTrustError = defineClass("TlsTrustError", { alwaysPermanent: true });

var observability = lazyRequire(function () { return require("./observability"); });
var audit = lazyRequire(function () { return require("./audit"); });
var asn1 = require("./asn1-der");

// STATE.tlsKeyShares is initialized to the default PQC group list at
// module load — operator setKeyShares() overrides; resetKeyShares()
// restores the default. Empty array means "fall back to Node's TLS
// default groups" (operator opt-out).
var STATE = {
  cas:             [],
  systemTrust:     false,
  baselineFingerprints: null,
  tlsKeyShares:    ["X25519MLKEM768", "X25519", "secp256r1"],
};

function _normalizePem(pem) {
  if (Buffer.isBuffer(pem)) pem = pem.toString("utf8");
  if (typeof pem !== "string") {
    throw new TlsTrustError("tls/bad-ca", "CA must be a PEM string or path, got " + typeof pem);
  }
  return pem.replace(/\r\n/g, "\n").trim();
}

function _splitPemBundle(pem) {
  var blocks = [];
  var lines = pem.split("\n");
  var current = null;
  for (var i = 0; i < lines.length; i++) {
    var line = lines[i];
    if (line.indexOf("-----BEGIN CERTIFICATE-----") === 0) {
      current = [line];
    } else if (current) {
      current.push(line);
      if (line.indexOf("-----END CERTIFICATE-----") === 0) {
        blocks.push(current.join("\n"));
        current = null;
      }
    }
  }
  return blocks;
}

function _certMetadata(pem) {
  try {
    var x = new nodeCrypto.X509Certificate(pem);
    return {
      subject:     x.subject,
      issuer:      x.issuer,
      validFrom:   x.validFrom,
      validTo:     x.validTo,
      fingerprint256: x.fingerprint256,
      serialNumber: x.serialNumber,
      isSelfSigned: x.subject === x.issuer,
    };
  } catch (e) {
    throw new TlsTrustError("tls/bad-ca-pem", "CA PEM not parseable: " + e.message);
  }
}

function _isPathLike(s) {
  if (s.indexOf("-----BEGIN") !== -1) return false;
  if (s.length > C.BYTES.kib(1)) return false;
  if (safeBuffer.hasCrlf(s)) return false;
  return true;
}

function _readPath(p) {
  var stat = fs.statSync(p);
  if (stat.isDirectory()) {
    var files = fs.readdirSync(p)
      .filter(function (f) { return /\.(pem|crt|cer)$/i.test(f); })
      .sort();
    return files.map(function (f) { return fs.readFileSync(path.join(p, f), "utf8"); }).join("\n");
  }
  return fs.readFileSync(p, "utf8");
}

function addCa(pemOrPath, opts) {
  opts = opts || {};
  validateOpts(opts, ["label", "audit"], "tls.addCa");
  var raw = pemOrPath;
  if (typeof pemOrPath === "string" && _isPathLike(pemOrPath)) {
    var stat;
    try { stat = fs.statSync(pemOrPath); } catch (_e) {
      throw new TlsTrustError("tls/empty-pem", "tls.addCa: input has no PEM marker and is not a readable path: " +
        pemOrPath);
    }
    raw = _readPath(pemOrPath);
    if (!stat) raw = "";
  }
  raw = _normalizePem(raw);
  var blocks = _splitPemBundle(raw);
  if (blocks.length === 0) {
    throw new TlsTrustError("tls/empty-pem", "no CERTIFICATE blocks found in PEM input");
  }
  var added = [];
  for (var i = 0; i < blocks.length; i++) {
    var meta = _certMetadata(blocks[i]);
    STATE.cas.push({ pem: blocks[i], meta: meta, label: opts.label || null, addedAt: Date.now() });
    added.push(meta);
  }
  _emitAuditAdd(added, opts);
  _emitObs("network.tls.ca.added", { count: added.length });
  return added;
}

function addCaBundle(p, opts) {
  return addCa(p, opts);
}

function useSystemTrust(enable) {
  STATE.systemTrust = enable !== false;
  _emitObs("network.tls.system_trust.set", { enabled: STATE.systemTrust });
}

function isSystemTrustEnabled() { return !!STATE.systemTrust; }

function getTrustStore() {
  return STATE.cas.map(function (entry) {
    return {
      label:        entry.label,
      addedAt:      entry.addedAt,
      subject:      entry.meta.subject,
      issuer:       entry.meta.issuer,
      validFrom:    entry.meta.validFrom,
      validTo:      entry.meta.validTo,
      fingerprint256: entry.meta.fingerprint256,
      serialNumber: entry.meta.serialNumber,
      isSelfSigned: entry.meta.isSelfSigned,
    };
  });
}

function _emitAuditRemove(metaList, reason) {
  var sink;
  try { sink = audit(); } catch (_e) { sink = null; }
  if (!sink || typeof sink.safeEmit !== "function") return;
  for (var i = 0; i < metaList.length; i++) {
    var m = metaList[i];
    try {
      sink.safeEmit({
        action:   "network.tls.ca.removed",
        outcome:  "success",
        metadata: {
          subject:        m.subject,
          issuer:         m.issuer,
          fingerprint256: m.fingerprint256,
          validFrom:      m.validFrom,
          validTo:        m.validTo,
          isSelfSigned:   m.isSelfSigned,
          label:          m.label,
          reason:         reason || "operator",
        },
      });
    } catch (_e) { /* audit best-effort — never break the caller */ }
  }
}

function removeCa(fingerprint256, opts) {
  if (typeof fingerprint256 !== "string" || fingerprint256.length === 0) {
    throw new TlsTrustError("tls/bad-fingerprint", "tls.removeCa: fingerprint256 must be a non-empty string");
  }
  var fp = fingerprint256.toUpperCase();
  var removed = [];
  STATE.cas = STATE.cas.filter(function (entry) {
    var entryFp = (entry.meta.fingerprint256 || "").toUpperCase();
    if (entryFp === fp) {
      removed.push(Object.assign({ label: entry.label }, entry.meta));
      return false;
    }
    return true;
  });
  if (removed.length === 0) return 0;
  if (!opts || opts.audit !== false) _emitAuditRemove(removed, "operator-remove");
  _emitObs("network.tls.ca.removed", { count: removed.length, reason: "operator" });
  return removed.length;
}

function removeCaByLabel(label, opts) {
  if (typeof label !== "string" || label.length === 0) {
    throw new TlsTrustError("tls/bad-label", "tls.removeCaByLabel: label must be a non-empty string");
  }
  var removed = [];
  STATE.cas = STATE.cas.filter(function (entry) {
    if (entry.label === label) {
      removed.push(Object.assign({ label: entry.label }, entry.meta));
      return false;
    }
    return true;
  });
  if (removed.length === 0) return 0;
  if (!opts || opts.audit !== false) _emitAuditRemove(removed, "operator-remove-by-label");
  _emitObs("network.tls.ca.removed", { count: removed.length, reason: "label" });
  return removed.length;
}

function clearAll(opts) {
  if (STATE.cas.length === 0) return 0;
  var removed = STATE.cas.map(function (e) { return Object.assign({ label: e.label }, e.meta); });
  STATE.cas = [];
  if (!opts || opts.audit !== false) _emitAuditRemove(removed, "operator-clear-all");
  _emitObs("network.tls.ca.cleared", { count: removed.length });
  return removed.length;
}

function purgeExpired(opts) {
  var nowMs = Date.now();
  var removed = [];
  STATE.cas = STATE.cas.filter(function (entry) {
    var validToMs = entry.meta.validTo ? Date.parse(entry.meta.validTo) : NaN;
    if (isFinite(validToMs) && validToMs < nowMs) {
      removed.push(Object.assign({ label: entry.label }, entry.meta));
      return false;
    }
    return true;
  });
  if (removed.length === 0) return 0;
  if (!opts || opts.audit !== false) _emitAuditRemove(removed, "expired");
  _emitObs("network.tls.ca.purged_expired", { count: removed.length });
  return removed.length;
}

function expiringSoon(windowMs) {
  if (typeof windowMs !== "number" || !isFinite(windowMs) || windowMs < 0) {
    throw new TlsTrustError("tls/bad-window", "tls.expiringSoon: windowMs must be a non-negative finite number");
  }
  var threshold = Date.now() + windowMs;
  return STATE.cas.filter(function (entry) {
    var validToMs = entry.meta.validTo ? Date.parse(entry.meta.validTo) : NaN;
    return isFinite(validToMs) && validToMs <= threshold;
  }).map(function (entry) {
    return Object.assign({ label: entry.label }, entry.meta);
  });
}

// expiryMonitor — periodic check that emits audit + observability
// events when any CA in the trust store falls inside the expiry
// window. Returns a handle with .stop() for graceful shutdown.
//
//   var mon = b.network.tls.expiryMonitor({
//     intervalMs:   C.TIME.hours(6),
//     windowMs:     C.TIME.days(30),
//     onExpiring:   function (rows) { /* operator hook — alerts */ },
//   });
//   ...
//   mon.stop();
//
// Audit emissions:
//   network.tls.ca.expiry_check  — every check, reports total + expiring count
//   network.tls.ca.expiring      — when expiringSoon(windowMs) > 0
//
// Observability event: network.tls.ca.expiring counter labeled with
// the count.
function expiryMonitor(opts) {
  opts = opts || {};
  var intervalMs = opts.intervalMs;
  var windowMs   = opts.windowMs;
  var auditOn    = opts.audit !== false;
  if (typeof intervalMs !== "number" || !isFinite(intervalMs) || intervalMs <= 0) {
    throw new TlsTrustError("tls/bad-interval",
      "tls.expiryMonitor: intervalMs must be a positive finite number");
  }
  if (typeof windowMs !== "number" || !isFinite(windowMs) || windowMs <= 0) {
    throw new TlsTrustError("tls/bad-window",
      "tls.expiryMonitor: windowMs must be a positive finite number");
  }

  function _tick() {
    var rows;
    try { rows = expiringSoon(windowMs); }
    catch (_e) { return; }
    if (auditOn) {
      try {
        audit().safeEmit({
          action:  "network.tls.ca.expiry_check",
          outcome: rows.length > 0 ? "warn" : "ok",
          metadata: { total: STATE.cas.length, expiring: rows.length, windowMs: windowMs },
        });
      } catch (_e) { /* drop-silent */ }
    }
    if (rows.length > 0) {
      try { observability().safeEvent("network.tls.ca.expiring", rows.length, {}); }
      catch (_e) { /* drop-silent */ }
      if (auditOn) {
        try {
          audit().safeEmit({
            action:  "network.tls.ca.expiring",
            outcome: "warn",
            metadata: {
              count:   rows.length,
              labels:  rows.map(function (r) { return r.label; }),
              earliestValidTo: rows.reduce(function (acc, r) {
                var ms = r.validTo ? Date.parse(r.validTo) : Infinity;
                return ms < acc ? ms : acc;
              }, Infinity),
            },
          });
        } catch (_e) { /* drop-silent */ }
      }
      if (typeof opts.onExpiring === "function") {
        try { opts.onExpiring(rows); } catch (_e) { /* operator hook */ }
      }
    }
  }

  var handle = safeAsync.repeating(_tick, intervalMs, { name: "tls-expiry-monitor" });
  return {
    stop: function () { if (handle) { handle.stop(); handle = null; } },
  };
}

function captureBaselineFingerprints() {
  STATE.baselineFingerprints = STATE.cas.map(function (e) { return e.meta.fingerprint256; });
}

function detectBaselineDrift() {
  if (!STATE.baselineFingerprints) return null;
  var current = STATE.cas.map(function (e) { return e.meta.fingerprint256; });
  var added = current.filter(function (fp) { return STATE.baselineFingerprints.indexOf(fp) === -1; });
  var removed = STATE.baselineFingerprints.filter(function (fp) { return current.indexOf(fp) === -1; });
  return { added: added, removed: removed, drifted: added.length > 0 || removed.length > 0 };
}

function applyToContext(opts) {
  opts = opts || {};
  validateOpts(opts, ["base"], "tls.applyToContext");
  var base = Object.assign({}, opts.base || {});
  var caStrings = STATE.cas.map(function (e) { return e.pem; });
  if (STATE.systemTrust) {
    var rootCAs = tls.rootCertificates;
    if (Array.isArray(rootCAs)) {
      caStrings = caStrings.concat(rootCAs);
    }
  }
  if (caStrings.length > 0) base.ca = caStrings;
  // PQC TLS handshake — apply the operator-configured key-share groups
  // (default ["X25519MLKEM768", "X25519"]) so https.Server / https.Agent
  // negotiate the hybrid KEM with peers that support it and fall back
  // to classical X25519 with peers that don't. Operators who explicitly
  // pass `groups` in their base config keep the override.
  if (base.groups === undefined && STATE.tlsKeyShares.length > 0) {
    base.groups = STATE.tlsKeyShares.join(":");
  }
  return base;
}

// ---- PQC TLS key shares (RFC draft-ietf-tls-hybrid-design) ----
//
// b.network.tls.pqc.setKeyShares(["X25519MLKEM768", "X25519"]) — set the
// TLS 1.3 key-share groups the framework's https.Server / https.Agent
// will advertise. The first listed group is the priority; the peer
// picks the first mutually supported entry. Hybrid groups
// (X25519MLKEM768) negotiate post-quantum + classical in one
// handshake so forward-secrecy survives both classical-CRQC and
// future quantum cryptanalysis.
//
//   getKeyShares()                                    → string[] (current)
//   setKeyShares(["X25519MLKEM768", "X25519"])        → string[] (after)
//   resetKeyShares()                                  → restores default

var DEFAULT_PQC_KEY_SHARES = Object.freeze([
  "X25519MLKEM768",                                                              // hybrid KEM, draft-kwiatkowski-tls-ecdhe-mlkem-02
  "X25519",                                                                      // classical fallback
  "secp256r1",                                                                   // legacy peers
]);

function _validateKeyShare(name) {
  if (typeof name !== "string" || name.length === 0 || name.length > C.BYTES.bytes(64)) {  // bound
    throw new TlsTrustError("tls/bad-key-share",
      "tls.pqc.setKeyShares: each entry must be a non-empty string up to 64 chars");
  }
  // RFC draft-ietf-tls-hybrid-design + IANA TLS Group Registry only
  // emit alphanumeric + underscore identifiers. Refuse `:` (the join
  // separator) outright so an operator can't smuggle a second entry
  // through one slot.
  if (!/^[A-Za-z0-9_]+$/.test(name)) {
    throw new TlsTrustError("tls/bad-key-share",
      "tls.pqc.setKeyShares: '" + name + "' has illegal characters " +
      "(must match [A-Za-z0-9_]+)");
  }
}

function setKeyShares(list) {
  if (!Array.isArray(list) || list.length === 0) {
    throw new TlsTrustError("tls/bad-key-shares",
      "tls.pqc.setKeyShares: must be a non-empty array of group names");
  }
  for (var i = 0; i < list.length; i += 1) _validateKeyShare(list[i]);
  STATE.tlsKeyShares = list.slice();
  return getKeyShares();
}

function getKeyShares() { return STATE.tlsKeyShares.slice(); }

function resetKeyShares() {
  STATE.tlsKeyShares = DEFAULT_PQC_KEY_SHARES.slice();
  return getKeyShares();
}

var pqc = Object.freeze({
  setKeyShares:           setKeyShares,
  getKeyShares:           getKeyShares,
  resetKeyShares:         resetKeyShares,
  DEFAULT_KEY_SHARES:     DEFAULT_PQC_KEY_SHARES,
});

function getCaPems() {
  return STATE.cas.map(function (e) { return e.pem; });
}

function _emitAuditAdd(metaList, opts) {
  if (opts.audit === false) return;
  var sink;
  try { sink = audit(); } catch (_e) { sink = null; }
  if (!sink || typeof sink.safeEmit !== "function") return;
  for (var i = 0; i < metaList.length; i++) {
    var m = metaList[i];
    try {
      sink.safeEmit({
        action:   "network.tls.ca.added",
        outcome:  "success",
        metadata: {
          subject:        m.subject,
          issuer:         m.issuer,
          fingerprint256: m.fingerprint256,
          validFrom:      m.validFrom,
          validTo:        m.validTo,
          isSelfSigned:   m.isSelfSigned,
          label:          opts.label || null,
        },
      });
    } catch (_e) { /* audit best-effort — never break the caller */ }
  }
}

function _emitObs(name, fields) {
  try { observability().emit(name, fields || {}); } catch (_e) { /* obs best-effort */ }
}

function _resetForTest() {
  STATE.cas = [];
  STATE.systemTrust = false;
  STATE.baselineFingerprints = null;
  STATE.tlsKeyShares = DEFAULT_PQC_KEY_SHARES.slice();
}

// ---- OCSP / OCSP-stapling wrappers around node:tls ----------------
//
// node:tls exposes two OCSP affordances:
//   - tls.connect({ requestOCSP: true })       → emits 'OCSPResponse' event
//   - https.createServer({ ... requestOCSP }) → server-side stapling
//
// b.network.tls.ocsp wraps these. The names reflect what the wrapper
// actually does at this stage:
//
//   - ocsp.connect(opts)        — connect with requestOCSP:true; resolve
//                                 with { authorized, ocspBytes, peerCert }.
//   - ocsp.requireStapled(opts) — refuse if peer doesn't staple an
//                                 OCSP response (presence + non-empty
//                                 byte check). DOES NOT verify the OCSP
//                                 response signature against the issuer
//                                 cert — that requires DER OCSPResponse
//                                 parsing which lands in the next patch
//                                 alongside the ASN.1 DER helper. The
//                                 honest name keeps the surface from
//                                 claiming "good" while only checking
//                                 stapling.
//
// node:tls validates the cert chain itself; OCSP staple validation is
// the application's job once the response bytes are received.

function _connectAndCheckOcsp(opts, requireStapled) {
  return new Promise(function (resolve, reject) {
    var connectOpts = Object.assign({}, opts, { requestOCSP: true });
    var sock;
    try {
      sock = tls.connect(connectOpts);
    } catch (e) {
      reject(new TlsTrustError("tls/connect-failed",
        "tls.connect threw: " + ((e && e.message) || String(e))));
      return;
    }
    var ocspResponseSeen = false;
    sock.on("OCSPResponse", function (response) {
      ocspResponseSeen = true;
      if (!response || response.length === 0) {
        if (requireStapled) {
          sock.destroy();
          reject(new TlsTrustError("tls/ocsp-empty",
            "OCSP response was empty and requireStapled is set"));
          return;
        }
      }
      // Operator can post-process the DER OCSPResponse via the resolved
      // callback; the framework doesn't parse the ASN.1 itself.
      sock.once("secureConnect", function () {
        var rv = {
          authorized: sock.authorized,
          ocspBytes:  response || null,
          peerCert:   sock.getPeerCertificate(true),
        };
        sock.destroy();
        resolve(rv);
      });
    });
    sock.on("secureConnect", function () {
      // 'OCSPResponse' fires BEFORE 'secureConnect' when the server
      // replied with stapled OCSP. If we got here without seeing an
      // OCSPResponse event AND requireStapled is set, refuse.
      if (!ocspResponseSeen) {
        if (requireStapled) {
          sock.destroy();
          reject(new TlsTrustError("tls/ocsp-not-stapled",
            "TLS peer did not staple an OCSP response and requireStapled is set"));
          return;
        }
        var rv = {
          authorized: sock.authorized,
          ocspBytes:  null,
          peerCert:   sock.getPeerCertificate(true),
        };
        sock.destroy();
        resolve(rv);
      }
    });
    sock.on("error", function (e) { reject(e); });
  });
}

// ---- OCSP response parser (RFC 6960) ----
//
// Decodes a DER OCSPResponse into:
//   {
//     status:    "successful" | "malformedRequest" | "internalError" |
//                "tryLater" | "sigRequired" | "unauthorized",
//     basic: {                  // present when status === "successful"
//       tbsResponseDataDer: Buffer,    // the bytes signed
//       signatureAlgorithmOid: string,
//       signature: Buffer,
//       responses: [{ certIdSerialHex, certStatus, thisUpdate, nextUpdate }, ...],
//     }
//   }
//
// Cherry-picks the fields the framework needs to verify the response —
// the signed bytes (tbsResponseData) + the signature + each response
// entry's status. Out of scope: ResponderID / extensions / nonce
// validation (operators relying on those wire their own parser).

var OID_BASIC_OCSP_RESPONSE = "1.3.6.1.5.5.7.48.1.1";
// OCSP nonce extension — id-pkix-ocsp-nonce.
var OID_OCSP_NONCE          = "1.3.6.1.5.5.7.48.1.2";
var OID_SHA1                = "1.3.14.3.2.26";                                   // allow:raw-byte-literal — SHA-1 algorithm OID arc
var OID_RSA_SHA256          = "1.2.840.113549.1.1.11";
var OID_RSA_SHA384          = "1.2.840.113549.1.1.12";
var OID_RSA_SHA512          = "1.2.840.113549.1.1.13";
var OID_ECDSA_SHA256        = "1.2.840.10045.4.3.2";
var OID_ECDSA_SHA384        = "1.2.840.10045.4.3.3";
var OID_ECDSA_SHA512        = "1.2.840.10045.4.3.4";

function _parseTime(node) {
  // Parse UTCTime ("YYMMDDhhmmssZ") or GeneralizedTime
  // ("YYYYMMDDhhmmssZ") into ms-since-epoch.
  var s = node.value.toString("ascii");
  var year, month, day, hour, min, sec;
  if (s.length === 13 && s.charAt(12) === "Z") {                                 // allow:raw-byte-literal — UTCTime length per X.690
    // UTCTime YYMMDDhhmmssZ — 50+ → 19xx, else 20xx (RFC 5280 §4.1.2.5).
    year  = parseInt(s.slice(0, 2), 10);
    year += year >= 50 ? 1900 : 2000;                                            // allow:raw-byte-literal allow:raw-time-literal — RFC 5280 century pivot, calendar years
    month = parseInt(s.slice(2, 4), 10);
    day   = parseInt(s.slice(4, 6), 10);
    hour  = parseInt(s.slice(6, 8), 10);                                         // allow:raw-byte-literal — UTCTime hour-byte offsets
    min   = parseInt(s.slice(8, 10), 10);                                        // allow:raw-byte-literal — UTCTime minute-byte offsets
    sec   = parseInt(s.slice(10, 12), 10);
  } else if (s.length >= 15 && s.charAt(s.length - 1) === "Z") {                 // allow:raw-byte-literal — GeneralizedTime length per X.690
    // GeneralizedTime YYYYMMDDhhmmssZ.
    year  = parseInt(s.slice(0, 4), 10);
    month = parseInt(s.slice(4, 6), 10);
    day   = parseInt(s.slice(6, 8), 10);                                         // allow:raw-byte-literal — GeneralizedTime day-byte offsets
    hour  = parseInt(s.slice(8, 10), 10);                                        // allow:raw-byte-literal — GeneralizedTime hour-byte offsets
    min   = parseInt(s.slice(10, 12), 10);
    sec   = parseInt(s.slice(12, 14), 10);
  } else {
    throw new TlsTrustError("tls/ocsp-bad-time",
      "OCSP time field is not UTCTime or GeneralizedTime: " + JSON.stringify(s));
  }
  return Date.UTC(year, month - 1, day, hour, min, sec);
}

var OCSP_RESPONSE_STATUS = {
  0: "successful",
  1: "malformedRequest",
  2: "internalError",
  3: "tryLater",
  // 4 reserved
  5: "sigRequired",
  6: "unauthorized",
};

function parseOcspResponse(der) {
  if (!Buffer.isBuffer(der) || der.length === 0) {
    throw new TlsTrustError("tls/ocsp-bad-input",
      "parseOcspResponse: expected non-empty Buffer");
  }
  var top = asn1.readNode(der);                                                  // OCSPResponse SEQUENCE
  if (top.tag !== asn1.TAG.SEQUENCE) {
    throw new TlsTrustError("tls/ocsp-bad-shape", "OCSPResponse is not a SEQUENCE");
  }
  var topChildren = asn1.readSequence(top.value);
  if (topChildren.length === 0) {
    throw new TlsTrustError("tls/ocsp-bad-shape", "OCSPResponse has no responseStatus");
  }
  var statusInt = asn1.readUnsignedInt(topChildren[0]);
  var status = OCSP_RESPONSE_STATUS[statusInt] || ("unknown:" + statusInt);
  if (status !== "successful") {
    return { status: status };
  }
  // responseBytes [0] EXPLICIT ResponseBytes
  if (topChildren.length < 2) {
    throw new TlsTrustError("tls/ocsp-bad-shape",
      "successful OCSP response missing responseBytes");
  }
  var responseBytes = asn1.unwrapExplicit(topChildren[1], 0);                   // [0] EXPLICIT
  if (responseBytes.tag !== asn1.TAG.SEQUENCE) {
    throw new TlsTrustError("tls/ocsp-bad-shape", "responseBytes is not a SEQUENCE");
  }
  var rbChildren = asn1.readSequence(responseBytes.value);
  if (rbChildren.length < 2) {
    throw new TlsTrustError("tls/ocsp-bad-shape",
      "responseBytes missing responseType or response");
  }
  var responseTypeOid = asn1.readOid(rbChildren[0]);
  if (responseTypeOid !== OID_BASIC_OCSP_RESPONSE) {
    throw new TlsTrustError("tls/ocsp-unsupported-response-type",
      "OCSP responseType is not id-pkix-ocsp-basic: " + responseTypeOid);
  }
  // The OCTET STRING wraps a DER BasicOCSPResponse.
  var basicDer = asn1.readOctetString(rbChildren[1]);
  var basic    = asn1.readNode(basicDer);
  if (basic.tag !== asn1.TAG.SEQUENCE) {
    throw new TlsTrustError("tls/ocsp-bad-shape",
      "BasicOCSPResponse is not a SEQUENCE");
  }
  var basicChildren = asn1.readSequence(basic.value);
  if (basicChildren.length < 3) {                                                // allow:raw-byte-literal — minimum BasicOCSPResponse fields (tbs + alg + sig)
    throw new TlsTrustError("tls/ocsp-bad-shape",
      "BasicOCSPResponse needs tbsResponseData + signatureAlgorithm + signature");
  }
  var tbsNode = basicChildren[0];
  var sigAlgChildren = asn1.readSequence(basicChildren[1].value);
  var sigAlgOid = asn1.readOid(sigAlgChildren[0]);
  var signatureBytes = asn1.readBitString(basicChildren[2]);

  // Slice the tbsResponseData bytes (header + value) — that's what the
  // signature covers per RFC 6960 §4.2.1. tbsResponseData is the FIRST
  // child of BasicOCSPResponse; its bytes start at basic.valueStart
  // within the raw basicDer buffer (offset 0).
  var basicValueStart = basicDer.length - basic.value.length;
  var tbsDer = basicDer.slice(basicValueStart, basicValueStart + tbsNode.totalLength);

  // Walk responseData (SEQUENCE) for the per-cert responses.
  var rdChildren = asn1.readSequence(tbsNode.value);
  // Find the SEQUENCE of SingleResponse — it's the LAST SEQUENCE before
  // optional [1] EXPLICIT extensions. Per RFC 6960:
  //   ResponseData ::= SEQUENCE {
  //     version          [0] EXPLICIT Version DEFAULT v1,
  //     responderID      ResponderID,
  //     producedAt       GeneralizedTime,
  //     responses        SEQUENCE OF SingleResponse,
  //     responseExtensions [1] EXPLICIT Extensions OPTIONAL
  //   }
  // ResponderID is itself a CHOICE (byName [1] / byKey [2]), then a
  // GeneralizedTime, then the responses SEQUENCE-OF.
  var responsesNode = null;
  var responseExtensionsNode = null;
  for (var rdi = rdChildren.length - 1; rdi >= 0; rdi -= 1) {
    var ch = rdChildren[rdi];
    if (ch.tag === asn1.TAG.SEQUENCE && ch.tagClass === asn1.TAG_CLASS.UNIVERSAL) {
      responsesNode = ch;
      break;
    }
    if (ch.tagClass === asn1.TAG_CLASS.CONTEXT_SPECIFIC && ch.tag === 1) {       // [1] EXPLICIT responseExtensions
      responseExtensionsNode = asn1.readNode(ch.value, 0);
    }
  }
  if (!responsesNode) {
    throw new TlsTrustError("tls/ocsp-bad-shape",
      "ResponseData missing responses SEQUENCE OF");
  }
  // Walk responseExtensions for the OCSP nonce (RFC 8954 / RFC 6960
  // §4.4.1). Returns the raw nonce bytes when present, or null.
  var responseNonce = null;
  if (responseExtensionsNode && responseExtensionsNode.tag === asn1.TAG.SEQUENCE) {
    var extKids = asn1.readSequence(responseExtensionsNode.value);
    for (var ei = 0; ei < extKids.length; ei += 1) {
      var ext = extKids[ei];
      if (ext.tag !== asn1.TAG.SEQUENCE) continue;
      var extChildren = asn1.readSequence(ext.value);
      if (extChildren.length === 0) continue;
      var extOid;
      try { extOid = asn1.readOid(extChildren[0]); }
      catch (_e3) { continue; }
      if (extOid !== OID_OCSP_NONCE) continue;
      var extnValue = asn1.readOctetString(extChildren[extChildren.length - 1]);
      // RFC 8954 §2.1 — the nonce extension value is the raw bytes
      // wrapped in an OCTET STRING (the value here). RFC 6960 §4.4.1
      // historically wrapped the nonce in another OCTET STRING; tolerate
      // both shapes.
      try {
        var inner = asn1.readNode(extnValue);
        if (inner.tag === asn1.TAG.OCTET_STRING) {
          responseNonce = inner.value;
        } else {
          responseNonce = extnValue;
        }
      } catch (_e4) {
        responseNonce = extnValue;
      }
      break;
    }
  }
  var singleResponses = asn1.readSequence(responsesNode.value);
  var responses = [];
  for (var sri = 0; sri < singleResponses.length; sri += 1) {
    var sr = asn1.readSequence(singleResponses[sri].value);
    if (sr.length < 3) continue;                                                 // allow:raw-byte-literal — minimum SingleResponse fields
    // sr[0] = certID SEQUENCE, sr[1] = certStatus CHOICE, sr[2] = thisUpdate.
    var certIdChildren = asn1.readSequence(sr[0].value);
    // certID = SEQUENCE { hashAlgorithm, issuerNameHash, issuerKeyHash, serialNumber }
    var serialHex = certIdChildren.length >= 4
      ? certIdChildren[3].value.toString("hex")
      : null;
    var certStatus;
    var statusNode = sr[1];
    if (statusNode.tagClass === asn1.TAG_CLASS.CONTEXT_SPECIFIC) {
      certStatus = statusNode.tag === 0 ? "good" :
                   statusNode.tag === 1 ? "revoked" :
                   statusNode.tag === 2 ? "unknown" : "unknown";
    } else if (statusNode.tag === asn1.TAG.NULL) {
      certStatus = "good";
    } else {
      certStatus = "unknown";
    }
    var thisUpdate = _parseTime(sr[2]);
    var nextUpdate = null;
    if (sr.length >= 4 && sr[3].tagClass === asn1.TAG_CLASS.CONTEXT_SPECIFIC && sr[3].tag === 0) {
      nextUpdate = _parseTime(asn1.readNode(sr[3].value, 0));
    }
    responses.push({
      certIdSerialHex: serialHex,
      certStatus:      certStatus,
      thisUpdate:      thisUpdate,
      nextUpdate:      nextUpdate,
    });
  }

  return {
    status: status,
    basic: {
      tbsResponseDataDer:    tbsDer,
      signatureAlgorithmOid: sigAlgOid,
      signature:             signatureBytes,
      responses:             responses,
      nonce:                 responseNonce,
    },
  };
}

function _verifyOcspSignature(parsed, issuerPem) {
  if (!parsed || !parsed.basic) {
    throw new TlsTrustError("tls/ocsp-not-successful",
      "OCSP response status is not 'successful' (got " +
      (parsed && parsed.status) + ")");
  }
  var algOid = parsed.basic.signatureAlgorithmOid;
  var nodeAlgo = algOid === OID_RSA_SHA256   ? "sha256" :
                 algOid === OID_RSA_SHA384   ? "sha384" :
                 algOid === OID_RSA_SHA512   ? "sha512" :
                 algOid === OID_ECDSA_SHA256 ? "sha256" :
                 algOid === OID_ECDSA_SHA384 ? "sha384" :
                 algOid === OID_ECDSA_SHA512 ? "sha512" : null;
  if (nodeAlgo === null) {
    throw new TlsTrustError("tls/ocsp-unsupported-sig-alg",
      "OCSP signatureAlgorithm OID '" + algOid + "' is not supported by the verifier");
  }
  var keyObj;
  try { keyObj = nodeCrypto.createPublicKey(issuerPem); }
  catch (e) {
    throw new TlsTrustError("tls/ocsp-bad-issuer-key",
      "issuer public key parse failed: " + ((e && e.message) || String(e)));
  }
  // ECDSA OCSP signatures use DER-encoded ECDSA-Sig-Value (the ASN.1
  // shape that node:crypto.verify accepts by default — no dsaEncoding
  // option needed).
  var verified;
  try {
    verified = nodeCrypto.verify(nodeAlgo, parsed.basic.tbsResponseDataDer, keyObj,
                                 parsed.basic.signature);
  } catch (e) {
    throw new TlsTrustError("tls/ocsp-verify-threw",
      "OCSP signature verify threw: " + ((e && e.message) || String(e)));
  }
  return verified;
}

// Operator-side OCSP response evaluator. Takes the DER bytes (from
// `ocsp.requireStapled` or any other source) plus the issuer cert PEM
// and returns a structured outcome:
//   { ok, status, certStatus, thisUpdate, nextUpdate, signatureValid, errors }
function evaluateOcspResponse(ocspDer, opts) {
  opts = opts || {};
  var issuerPem = opts.issuerPem;
  if (!issuerPem) {
    throw new TlsTrustError("tls/ocsp-missing-issuer",
      "evaluateOcspResponse requires opts.issuerPem (PEM of the cert that signed the OCSP response — typically the leaf's CA OR a delegated id-kp-OCSPSigning responder cert)");
  }
  var parsed;
  try { parsed = parseOcspResponse(ocspDer); }
  catch (e) {
    return { ok: false, status: "parse-error",
             errors: [(e && e.message) || String(e)] };
  }
  if (parsed.status !== "successful") {
    return { ok: false, status: parsed.status, errors: ["responseStatus=" + parsed.status] };
  }
  var sigOk = false;
  try { sigOk = _verifyOcspSignature(parsed, issuerPem); }
  catch (e) {
    return { ok: false, status: parsed.status,
             signatureValid: false,
             errors: [(e && e.message) || String(e)] };
  }
  if (!sigOk) {
    return { ok: false, status: parsed.status, signatureValid: false,
             errors: ["OCSP signature did not verify against the issuer key"] };
  }
  // Look up the requested cert serial in the responses; "good" wins.
  var serial = opts.serialHex || (parsed.basic.responses[0] && parsed.basic.responses[0].certIdSerialHex);
  var match = null;
  for (var i = 0; i < parsed.basic.responses.length; i += 1) {
    var r = parsed.basic.responses[i];
    if (!serial || r.certIdSerialHex === serial) { match = r; break; }
  }
  if (!match) {
    return { ok: false, status: parsed.status, signatureValid: true,
             errors: ["OCSP response has no entry for the requested cert serial"] };
  }
  // Optional nonce echo verification (RFC 8954 / RFC 6960 §4.4.1).
  // When opts.expectedNonce is supplied, the response MUST carry an
  // OCSP nonce extension equal to the expected bytes — defends against
  // replay of a stale "good" response captured before revocation.
  var nonceCheck = "n/a";
  if (opts.expectedNonce !== undefined && opts.expectedNonce !== null) {
    if (!Buffer.isBuffer(opts.expectedNonce)) {
      return { ok: false, status: parsed.status, signatureValid: true,
               errors: ["evaluateOcspResponse: opts.expectedNonce must be a Buffer when supplied"] };
    }
    if (!parsed.basic.nonce) {
      return { ok: false, status: parsed.status, signatureValid: true,
               errors: ["OCSP response missing nonce extension (expected for replay defense)"] };
    }
    if (!parsed.basic.nonce.equals(opts.expectedNonce)) {
      return { ok: false, status: parsed.status, signatureValid: true,
               errors: ["OCSP nonce mismatch — possible replay or wrong responder"] };
    }
    nonceCheck = "matched";
  } else if (parsed.basic.nonce) {
    nonceCheck = "present-not-checked";
  }
  return {
    ok:             match.certStatus === "good",
    status:         parsed.status,
    certStatus:     match.certStatus,
    thisUpdate:     match.thisUpdate,
    nextUpdate:     match.nextUpdate,
    signatureValid: true,
    nonce:          nonceCheck,
    errors:         match.certStatus === "good" ? [] :
                    ["certStatus=" + match.certStatus],
  };
}

// ---- OCSPRequest builder (RFC 6960 §4.1 + RFC 8954 nonce ext) ----
//
// Constructs a DER-encoded OCSPRequest for a single (leafCertDer,
// issuerCertDer) pair, optionally with an RFC 8954 nonce extension.
// Operators send the returned `requestDer` to the OCSP responder URL
// (e.g. via b.httpClient with `Content-Type: application/ocsp-request`)
// and pass `nonce` to `ocsp.evaluate(responseDer, { expectedNonce })`
// to defend against replay attacks.
//
// Nonce DEFAULT ON — defense in depth. RFC 6960 §4.4.1 marks nonce
// optional and some public responders (notably Let's Encrypt's) ignore
// it; operators explicitly targeting those responders opt out via
// `opts.nonce: false`. The framework default is RFC 8954 with 16 random
// bytes (RFC 8954 §2.1 floor; ceiling 32).

function _extractIssuerNameDerAndKeyBitString(certDer) {
  // From the leaf cert's tbsCertificate, pull the issuer Name (DER) +
  // the issuer's SubjectPublicKey BIT STRING content. For OCSP CertID,
  // RFC 6960 §4.1.1 specifies hash(issuerName) and hash(issuerKey).
  // This helper operates on the ISSUER cert (not the leaf): the issuer's
  // Name and SubjectPublicKey are what get hashed.
  var top = asn1.readNode(certDer);
  if (top.tag !== asn1.TAG.SEQUENCE) {
    throw new TlsTrustError("tls/ocsp-bad-issuer-cert", "issuer cert is not a SEQUENCE");
  }
  var children = asn1.readSequence(top.value);
  if (children.length === 0) {
    throw new TlsTrustError("tls/ocsp-bad-issuer-cert", "issuer cert has no children");
  }
  var tbs = children[0];
  if (tbs.tag !== asn1.TAG.SEQUENCE) {
    throw new TlsTrustError("tls/ocsp-bad-issuer-cert", "tbsCertificate is not a SEQUENCE");
  }
  var tbsKids = asn1.readSequence(tbs.value);
  // Skip optional [0] EXPLICIT version, then serialNumber, signature,
  // then issuer (the cert's own subject in a self-signed CA, or its
  // issuer field for a sub-CA — we just want THIS cert's subject).
  var idx = 0;
  if (tbsKids.length > 0 &&
      tbsKids[0].tagClass === asn1.TAG_CLASS.CONTEXT_SPECIFIC &&
      tbsKids[0].tag === 0) {                                                    // allow:raw-byte-literal — X.509 [0] EXPLICIT version tag
    idx = 1;
  }
  // After version: serialNumber, signature, issuer, validity, subject, SPKI.
  var subjectIdx = idx + 4;                                                      // allow:raw-byte-literal — X.509 TBSCertificate field count
  var spkiIdx = idx + 5;                                                         // allow:raw-byte-literal — X.509 TBSCertificate field count
  if (spkiIdx >= tbsKids.length) {
    throw new TlsTrustError("tls/ocsp-bad-issuer-cert", "issuer cert lacks SPKI field");
  }
  var subject = tbsKids[subjectIdx];
  var spki = tbsKids[spkiIdx];
  // Within SPKI: SEQUENCE { algorithm AlgorithmIdentifier, subjectPublicKey BIT STRING }
  var spkiKids = asn1.readSequence(spki.value);
  if (spkiKids.length < 2) {                                                     // allow:raw-byte-literal — minimum SPKI fields
    throw new TlsTrustError("tls/ocsp-bad-issuer-cert", "SPKI missing subjectPublicKey BIT STRING");
  }
  var keyBytes = asn1.readBitString(spkiKids[1]);
  return {
    issuerNameDer: subject.raw,                                                  // the DER of the Name SEQUENCE (header + value)
    issuerKey:     keyBytes,
  };
}

function _extractLeafSerial(leafCertDer) {
  var top = asn1.readNode(leafCertDer);
  if (top.tag !== asn1.TAG.SEQUENCE) {
    throw new TlsTrustError("tls/ocsp-bad-leaf-cert", "leaf cert is not a SEQUENCE");
  }
  var children = asn1.readSequence(top.value);
  var tbs = children[0];
  var tbsKids = asn1.readSequence(tbs.value);
  var idx = 0;
  if (tbsKids.length > 0 &&
      tbsKids[0].tagClass === asn1.TAG_CLASS.CONTEXT_SPECIFIC &&
      tbsKids[0].tag === 0) {                                                    // allow:raw-byte-literal — X.509 [0] EXPLICIT version tag
    idx = 1;
  }
  // serialNumber is the next field after the optional version.
  return tbsKids[idx].value;
}

function buildOcspRequest(opts) {
  opts = opts || {};
  if (!Buffer.isBuffer(opts.leafCertDer)) {
    throw new TlsTrustError("tls/ocsp-bad-input",
      "buildRequest: opts.leafCertDer must be a Buffer (peer cert raw DER)");
  }
  if (!Buffer.isBuffer(opts.issuerCertDer)) {
    throw new TlsTrustError("tls/ocsp-bad-input",
      "buildRequest: opts.issuerCertDer must be a Buffer (issuer cert raw DER)");
  }
  var iss = _extractIssuerNameDerAndKeyBitString(opts.issuerCertDer);
  var serial = _extractLeafSerial(opts.leafCertDer);
  // CertID hashes — SHA-1 per RFC 6960 §4.1.1 (the only universally
  // supported algorithm; SHA-256 in OCSP requests is RFC 6960 §4.3
  // optional and many responders reject).
  var nameHash = nodeCrypto.createHash("sha1").update(iss.issuerNameDer).digest();
  var keyHash  = nodeCrypto.createHash("sha1").update(iss.issuerKey).digest();
  // hashAlgorithm AlgorithmIdentifier ::= SEQUENCE { algorithm OID, NULL }
  var algId = asn1.writeSequence([asn1.writeOid(OID_SHA1), asn1.writeNull()]);
  var certId = asn1.writeSequence([
    algId,
    asn1.writeOctetString(nameHash),
    asn1.writeOctetString(keyHash),
    asn1.writeInteger(serial),
  ]);
  var requestNode = asn1.writeSequence([certId]);
  var requestList = asn1.writeSequence([requestNode]);
  var nonceBytes = null;
  var tbsChildren = [requestList];
  // Default ON per the framework security-defaults-on rule. Operators
  // talking to a responder that ignores nonces opt out via nonce: false.
  var includeNonce = opts.nonce !== false;
  if (includeNonce) {
    var nonceLen = typeof opts.nonceLen === "number" ? opts.nonceLen : 16;       // allow:raw-byte-literal — RFC 8954 §2.1 nonce length floor
    if (nonceLen < 1 || nonceLen > 32) {                                         // allow:raw-byte-literal — RFC 8954 §2.1 nonce length ceiling
      throw new TlsTrustError("tls/ocsp-bad-nonce-len",
        "nonce length out of RFC 8954 range (1..32)");
    }
    nonceBytes = nodeCrypto.randomBytes(nonceLen);
    // Extension ::= SEQUENCE { extnID OID, critical BOOL DEFAULT FALSE, extnValue OCTET STRING }
    // For nonce, extnValue is OCTET STRING wrapping the raw nonce bytes (RFC 8954 §2.1 — outer OCTET STRING only).
    var nonceExt = asn1.writeSequence([
      asn1.writeOid(OID_OCSP_NONCE),
      asn1.writeOctetString(nonceBytes),
    ]);
    var extensions = asn1.writeSequence([nonceExt]);
    tbsChildren.push(asn1.writeContextExplicit(2, extensions));                  // [2] EXPLICIT requestExtensions
  }
  var tbs = asn1.writeSequence(tbsChildren);
  var requestDer = asn1.writeSequence([tbs]);
  return { requestDer: requestDer, nonce: nonceBytes };
}

var ocsp = Object.freeze({
  // Connect with OCSP requested. Returns { authorized, ocspBytes,
  // peerCert }. requireStapled: true makes empty / not-stapled responses
  // refuse instead of resolve. NOTE: requireStapled does NOT verify the
  // OCSP response signature — pair it with evaluateOcspResponse(bytes,
  // { issuerPem }) for full verification, OR use requireGood below.
  connect: function (opts) {
    return _connectAndCheckOcsp(opts || {}, false);
  },
  requireStapled: function (opts) {
    return _connectAndCheckOcsp(opts || {}, true);
  },
  // requireGood: connect + parse + verify signature + check certStatus.
  // Operator passes opts.issuerPem (the cert that signed the OCSP
  // response — typically the leaf's CA OR a delegated OCSP responder
  // cert). Throws TlsTrustError on any failure (no-staple, parse error,
  // signature mismatch, certStatus=revoked/unknown).
  requireGood: async function (opts) {
    opts = opts || {};
    if (!opts.issuerPem) {
      throw new TlsTrustError("tls/ocsp-missing-issuer",
        "ocsp.requireGood requires opts.issuerPem (PEM of the OCSP-signing cert)");
    }
    var rv = await _connectAndCheckOcsp(opts, true);
    if (!rv.ocspBytes || rv.ocspBytes.length === 0) {
      throw new TlsTrustError("tls/ocsp-empty",
        "OCSP response was empty");
    }
    var evald = evaluateOcspResponse(rv.ocspBytes, {
      issuerPem: opts.issuerPem,
      serialHex: opts.serialHex || null,
    });
    if (!evald.ok) {
      throw new TlsTrustError("tls/ocsp-not-good",
        "OCSP evaluation failed: " + evald.errors.join("; "));
    }
    return Object.assign({}, rv, { ocspEvaluation: evald });
  },
  parseResponse:        parseOcspResponse,
  evaluate:             evaluateOcspResponse,
  // buildRequest — construct a DER-encoded OCSPRequest for a single
  // (leafCertDer, issuerCertDer) pair. RFC 8954 nonce extension is ON
  // by default (16 random bytes; opts.nonceLen overrides within RFC
  // 8954's 1..32 range; opts.nonce: false opts out for responders that
  // ignore nonces). Returns { requestDer, nonce }; pass `nonce` to
  // evaluate({ expectedNonce }).
  buildRequest:         buildOcspRequest,
  // inspectMustStaple — read the RFC 7633 TLS Feature extension on a
  // peer cert. Returns { mustStaple, features }. mustStaple === true
  // when status_request (5) is in the feature list; the cert is then
  // contractually required to ship an OCSP staple on every connection.
  inspectMustStaple: function (rawDer) {
    if (!Buffer.isBuffer(rawDer)) {
      throw new TlsTrustError("tls/ocsp-bad-input",
        "ocsp.inspectMustStaple: rawDer must be a Buffer (cert.raw)");
    }
    return _extractTlsFeatureExtensionFromCert(rawDer);
  },
  // requireMustStaple(peerCert, opts) — operator predicate. Refuses
  // when the cert advertises must-staple but no OCSP staple was
  // delivered (opts.ocspBytes empty/missing). When the cert does NOT
  // advertise must-staple, the predicate returns null (operator opted
  // in by setting opts.enforceUnconditional to also require staples
  // on certs that don't carry the extension).
  requireMustStaple: function (opts) {
    opts = opts || {};
    var enforceUnconditional = opts.enforceUnconditional === true;
    return function (peerCert, ctx) {
      if (!peerCert || !peerCert.raw) {
        return new TlsTrustError("tls/ocsp-no-cert",
          "requireMustStaple: peer cert.raw missing");
      }
      var feat = _extractTlsFeatureExtensionFromCert(peerCert.raw);
      var stapled = ctx && Buffer.isBuffer(ctx.ocspBytes) && ctx.ocspBytes.length > 0;
      if (feat.mustStaple && !stapled) {
        return new TlsTrustError("tls/ocsp-must-staple-violated",
          "cert advertises must-staple (RFC 7633) but no OCSP staple was delivered");
      }
      if (!feat.mustStaple && enforceUnconditional && !stapled) {
        return new TlsTrustError("tls/ocsp-staple-required",
          "operator policy requires OCSP staple but server did not provide one");
      }
      return null;
    };
  },
});

// ---- Certificate Transparency (RFC 6962 + RFC 9162) SCT verifier --
//
// CT requires every TLS server certificate to carry at least 2 Signed
// Certificate Timestamps (SCTs) from approved logs. Modern browsers
// (Chrome / Safari) refuse certificates without sufficient SCTs.
//
// node:tls surfaces SCTs via TLSSocket.getPeerX509Certificate() →
// X509Certificate.raw (the DER cert). The SCTs sit inside the cert as
// the OCSP-aware extension OID 1.3.6.1.4.1.11129.2.4.2.
//
// b.network.tls.ct.verify(cert, opts) checks that the cert has at
// least `minScts` SCTs and that each SCT references a log in
// `approvedLogs`. Full SCT-signature verification against the log's
// pubkey is OUT of scope for this patch — that requires log-pubkey
// distribution + ASN.1 SCT parsing. The framework provides the
// SCT-presence + log-id check; signature verification is a follow-up
// when the ASN.1 dependency lands.

// SCT extension OID per RFC 6962 §3.3.
var OID_CT_SCT_LIST = "1.3.6.1.4.1.11129.2.4.2";

// Walk a DER X.509 cert and locate the SCT extension's OCTET STRING
// content. Returns { sctListRaw } or { sctListRaw: null } when no SCT
// extension is present.
function _extractSctExtensionFromCert(certDer) {
  // Tolerant of malformed cert buffers — return null sctListRaw when
  // the ASN.1 walk fails. Callers (parseScts / verifyScts) treat that
  // as "no SCT extension" rather than throwing on broken input.
  var top;
  try { top = asn1.readNode(certDer); }
  catch (_e) { return { sctListRaw: null }; }
  if (top.tag !== asn1.TAG.SEQUENCE) return { sctListRaw: null };
  var children;
  try { children = asn1.readSequence(top.value); }
  catch (_e) { return { sctListRaw: null }; }
  if (children.length === 0) return { sctListRaw: null };
  // Cert ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signature }
  var tbs = children[0];
  if (tbs.tag !== asn1.TAG.SEQUENCE) return { sctListRaw: null };
  // tbsCertificate ::= SEQUENCE { ..., extensions [3] EXPLICIT ... }
  var tbsChildren;
  try { tbsChildren = asn1.readSequence(tbs.value); }
  catch (_e) { return { sctListRaw: null }; }
  var extensionsNode = null;
  for (var i = 0; i < tbsChildren.length; i += 1) {
    var ch = tbsChildren[i];
    if (ch.tagClass === asn1.TAG_CLASS.CONTEXT_SPECIFIC && ch.tag === 3) {       // allow:raw-byte-literal — X.509 [3] EXPLICIT extensions tag
      extensionsNode = asn1.readNode(ch.value, 0);
      break;
    }
  }
  if (!extensionsNode || extensionsNode.tag !== asn1.TAG.SEQUENCE) {
    return { sctListRaw: null };
  }
  var extensions = asn1.readSequence(extensionsNode.value);
  for (var e = 0; e < extensions.length; e += 1) {
    var ext = extensions[e];                                                     // Extension ::= SEQUENCE { extnID OID, critical BOOL OPTIONAL, extnValue OCTET STRING }
    if (ext.tag !== asn1.TAG.SEQUENCE) continue;
    var extChildren = asn1.readSequence(ext.value);
    if (extChildren.length === 0) continue;
    var extOid = asn1.readOid(extChildren[0]);
    if (extOid !== OID_CT_SCT_LIST) continue;
    // The last child is the OCTET STRING extnValue. Per RFC 6962 §3.3
    // that OCTET STRING wraps a SECOND OCTET STRING which contains the
    // raw SignedCertificateTimestampList (TLS-encoded).
    var extnValueOuter = asn1.readOctetString(extChildren[extChildren.length - 1]);
    var inner = asn1.readNode(extnValueOuter);
    if (inner.tag !== asn1.TAG.OCTET_STRING) {
      throw new TlsTrustError("tls/ct-bad-extension",
        "SCT extension extnValue does not wrap a second OCTET STRING");
    }
    return { sctListRaw: inner.value };
  }
  return { sctListRaw: null };
}

// TLS Feature extension OID per RFC 7633 §6. The extension value is
// SEQUENCE OF INTEGER; the integer 5 == status_request == "must-staple".
var OID_TLS_FEATURE = "1.3.6.1.5.5.7.1.24";
var TLS_FEATURE_STATUS_REQUEST = 5;

// Walk a DER X.509 cert and return the TLS Feature extension's
// integer list. Returns { mustStaple, features }. Tolerant of
// malformed cert input — mirrors _extractSctExtensionFromCert's
// try/catch tolerance.
function _extractTlsFeatureExtensionFromCert(certDer) {
  var none = { mustStaple: false, features: [] };
  var top;
  try { top = asn1.readNode(certDer); }
  catch (_e) { return none; }
  if (top.tag !== asn1.TAG.SEQUENCE) return none;
  var children;
  try { children = asn1.readSequence(top.value); }
  catch (_e) { return none; }
  if (children.length === 0) return none;
  var tbs = children[0];
  if (tbs.tag !== asn1.TAG.SEQUENCE) return none;
  var tbsChildren;
  try { tbsChildren = asn1.readSequence(tbs.value); }
  catch (_e) { return none; }
  var extensionsNode = null;
  for (var i = 0; i < tbsChildren.length; i += 1) {
    var ch = tbsChildren[i];
    if (ch.tagClass === asn1.TAG_CLASS.CONTEXT_SPECIFIC && ch.tag === 3) {       // allow:raw-byte-literal — X.509 [3] EXPLICIT extensions tag
      extensionsNode = asn1.readNode(ch.value, 0);
      break;
    }
  }
  if (!extensionsNode || extensionsNode.tag !== asn1.TAG.SEQUENCE) return none;
  var extensions = asn1.readSequence(extensionsNode.value);
  for (var e = 0; e < extensions.length; e += 1) {
    var ext = extensions[e];
    if (ext.tag !== asn1.TAG.SEQUENCE) continue;
    var extChildren = asn1.readSequence(ext.value);
    if (extChildren.length === 0) continue;
    var extOid;
    try { extOid = asn1.readOid(extChildren[0]); }
    catch (_e2) { continue; }
    if (extOid !== OID_TLS_FEATURE) continue;
    var extnValue = asn1.readOctetString(extChildren[extChildren.length - 1]);
    // extnValue wraps SEQUENCE OF INTEGER.
    var seq;
    try { seq = asn1.readNode(extnValue); }
    catch (_e3) { return none; }
    if (seq.tag !== asn1.TAG.SEQUENCE) return none;
    var feats = asn1.readSequence(seq.value);
    var ints = [];
    var mustStaple = false;
    for (var f = 0; f < feats.length; f += 1) {
      try {
        var n = asn1.readUnsignedInt(feats[f]);
        ints.push(n);
        if (n === TLS_FEATURE_STATUS_REQUEST) mustStaple = true;
      } catch (_e4) { /* ignore non-integer entries */ }
    }
    return { mustStaple: mustStaple, features: ints };
  }
  return none;
}

// Parse the TLS-encoded SignedCertificateTimestampList (RFC 6962 §3.3).
// Format: 2-byte length + concatenation of individual SCTs, each
// itself prefixed by a 2-byte length.
function _parseSctList(sctListRaw) {
  if (!Buffer.isBuffer(sctListRaw) || sctListRaw.length < 2) {                   // allow:raw-byte-literal — outer 2-byte length prefix
    throw new TlsTrustError("tls/ct-bad-list",
      "SCT list shorter than the outer length prefix");
  }
  var totalLen = sctListRaw.readUInt16BE(0);
  if (totalLen + 2 !== sctListRaw.length) {                                      // allow:raw-byte-literal — outer length prefix
    throw new TlsTrustError("tls/ct-bad-list",
      "SCT list outer length " + totalLen + " does not match buffer " +
      (sctListRaw.length - 2));
  }
  var pos = 2;                                                                   // allow:raw-byte-literal — past the outer prefix
  var scts = [];
  while (pos < sctListRaw.length) {
    var sctLen = sctListRaw.readUInt16BE(pos);
    pos += 2;
    if (pos + sctLen > sctListRaw.length) {
      throw new TlsTrustError("tls/ct-bad-list",
        "SCT[" + scts.length + "] declared length " + sctLen +
        " extends past the list buffer");
    }
    var sctBytes = sctListRaw.slice(pos, pos + sctLen);
    scts.push(_parseSct(sctBytes));
    pos += sctLen;
  }
  return scts;
}

// Per RFC 6962 §3.2 — a single SCT:
//   sct_version          (1 byte)         — 0 = v1
//   id (LogID)           (32 bytes)       — SHA-256 of log's pubkey
//   timestamp            (8 bytes)        — uint64 ms since epoch
//   ct_extensions        (2-byte len + N) — usually empty
//   signature            DigitallySigned  (hash + sig algo + 2-byte len + N)
function _parseSct(sctBuf) {
  if (sctBuf.length < 1 + 32 + 8 + 2 + 4) {                                      // allow:raw-byte-literal — minimum SCT v1 byte total
    throw new TlsTrustError("tls/ct-sct-too-short",
      "SCT is shorter than the minimum v1 layout (" + sctBuf.length + " bytes)");
  }
  var version = sctBuf[0];
  if (version !== 0) {
    throw new TlsTrustError("tls/ct-sct-bad-version",
      "SCT version is not 0 (v1): got " + version);
  }
  var logId = sctBuf.slice(1, 1 + 32);                                           // allow:raw-byte-literal — RFC 6962 32-byte LogID
  var timestamp = Number(sctBuf.readBigUInt64BE(1 + 32));                        // allow:raw-byte-literal — past LogID
  var extLen = sctBuf.readUInt16BE(1 + 32 + 8);                                  // allow:raw-byte-literal — past LogID + timestamp
  var pos = 1 + 32 + 8 + 2;                                                      // allow:raw-byte-literal — past extLen field
  var extensions = sctBuf.slice(pos, pos + extLen);
  pos += extLen;
  if (pos + 4 > sctBuf.length) {                                                 // allow:raw-byte-literal — DigitallySigned header (hash + alg + len)
    throw new TlsTrustError("tls/ct-sct-truncated",
      "SCT truncated before DigitallySigned");
  }
  var hashAlgo = sctBuf[pos];
  var sigAlgo  = sctBuf[pos + 1];
  pos += 2;                                                                      // allow:raw-byte-literal — past hash+alg pair
  var sigLen = sctBuf.readUInt16BE(pos);
  pos += 2;                                                                      // allow:raw-byte-literal — past sig length
  if (pos + sigLen !== sctBuf.length) {
    throw new TlsTrustError("tls/ct-sct-truncated",
      "SCT signature length " + sigLen + " does not match remaining bytes " +
      (sctBuf.length - pos));
  }
  var signature = sctBuf.slice(pos, pos + sigLen);
  return {
    version:    version,
    logId:      logId,
    logIdHex:   logId.toString("hex"),
    timestamp:  timestamp,
    extensions: extensions,
    hashAlgo:   hashAlgo,    // RFC 5246 HashAlgorithm enum (4=sha256, 5=sha384, 6=sha512)
    sigAlgo:    sigAlgo,     // RFC 5246 SignatureAlgorithm enum (1=rsa, 3=ecdsa)
    signature:  signature,
  };
}

// Build the canonical signed-entry per RFC 6962 §3.2 for X.509
// pre-cert-free chains (issued cert path):
//   sct_version (1) || signature_type (1=certificate_timestamp) ||
//   timestamp (8) || entry_type (0=x509_entry) ||
//   signed_entry (3-byte length || ASN.1 cert without SCT extension) ||
//   ct_extensions (2-byte length || N)
function _buildSctSignedEntry(certWithoutSctDer, sct) {
  var head = Buffer.alloc(1 + 1 + 8 + 2);                                        // allow:raw-byte-literal — fixed-shape header bytes
  head[0] = sct.version;
  head[1] = 0;                                                                   // signature_type = certificate_timestamp
  head.writeBigUInt64BE(BigInt(sct.timestamp), 2);                               // allow:raw-byte-literal — past version+sig-type
  head.writeUInt16BE(0, 10);                                                     // allow:raw-byte-literal — entry_type = x509_entry (2 bytes; high byte = 0, low byte = 0)
  // signed_entry: 3-byte length prefix + cert DER.
  var lenBytes = Buffer.alloc(3);                                                // allow:raw-byte-literal — RFC 6962 24-bit length prefix
  lenBytes[0] = (certWithoutSctDer.length >> 16) & 0xff;                         // allow:raw-byte-literal — base-256 length high byte
  lenBytes[1] = (certWithoutSctDer.length >> 8) & 0xff;                          // allow:raw-byte-literal — base-256 length mid byte
  lenBytes[2] = certWithoutSctDer.length & 0xff;                                 // allow:raw-byte-literal — base-256 length low byte
  // ct_extensions: 2-byte length + bytes.
  var extHead = Buffer.alloc(2);                                                 // allow:raw-byte-literal — RFC 6962 2-byte ct_extensions length prefix
  extHead.writeUInt16BE(sct.extensions.length, 0);
  return Buffer.concat([head, lenBytes, certWithoutSctDer, extHead, sct.extensions]);
}

// Strip the SCT extension from a DER cert + return the rebuilt cert
// bytes for SCT signing per RFC 6962 §3.2. The strip is byte-precise:
// walk the TBSCertificate extensions list, drop the SCT extension,
// and re-encode just enough of the chain to reproduce the original
// shape minus that one extension. This is non-trivial because the
// tbsCertificate length, certificate length, and signature-bytes
// boundaries all shift.
//
// Simpler: rebuild only the tbsCertificate extensions SEQUENCE without
// the SCT entry, recompute lengths above it, and replace the cert's
// SignedCertificate (BIT STRING) with the original's signature too —
// but that's incorrect since the original signature was computed over
// the WITH-SCT TBS. The CT log signed an entry built from the
// without-SCT pre-issuance shape, NOT the issued cert's tbs.
//
// Per RFC 6962 §3.1, log servers receive a "TBSCertificate" minus the
// SCT extension from the CA. The signed_entry the framework
// reconstructs is that pre-extension TBSCertificate. We compute it by
// removing the SCT extension at the byte level and rebuilding all
// outer length prefixes.
function _stripSctExtensionFromCert(certDer) {
  var top = asn1.readNode(certDer);
  if (top.tag !== asn1.TAG.SEQUENCE) {
    throw new TlsTrustError("tls/ct-bad-cert", "Certificate is not a SEQUENCE");
  }
  var topChildren = asn1.readSequence(top.value);
  var tbs = topChildren[0];
  if (tbs.tag !== asn1.TAG.SEQUENCE) {
    throw new TlsTrustError("tls/ct-bad-cert", "tbsCertificate is not a SEQUENCE");
  }
  // Walk tbsCertificate to find the [3] EXPLICIT extensions wrapper.
  var tbsChildren = asn1.readSequence(tbs.value);
  var newTbsChildrenBytes = [];
  var foundExtensions = false;
  for (var i = 0; i < tbsChildren.length; i += 1) {
    var ch = tbsChildren[i];
    if (ch.tagClass === asn1.TAG_CLASS.CONTEXT_SPECIFIC && ch.tag === 3) {       // allow:raw-byte-literal — [3] EXPLICIT extensions tag
      foundExtensions = true;
      // Inner SEQUENCE OF Extensions.
      var inner = asn1.readNode(ch.value, 0);
      var extList = asn1.readSequence(inner.value);
      var keptExtBytes = [];
      for (var j = 0; j < extList.length; j += 1) {
        var ext = extList[j];
        var extBytes = ext.value;
        var extDescChildren = asn1.readSequence(ext.value);
        if (extDescChildren.length > 0) {
          try {
            var oid = asn1.readOid(extDescChildren[0]);
            if (oid === OID_CT_SCT_LIST) continue;                               // drop the SCT extension
          } catch (_e) { /* not an OID — keep the extension as-is */ }
        }
        // Re-encode this extension verbatim (we have the original bytes).
        var origExt = certDer.slice(0, 0);                                       // placeholder; we rebuild from the parsed node below
        void origExt;
        keptExtBytes.push(_encodeAsn1(asn1.TAG.SEQUENCE, true, extBytes));
        void extBytes;
      }
      var newExtSeq = _encodeAsn1(asn1.TAG.SEQUENCE, true, Buffer.concat(keptExtBytes));
      var newExplicit3 = _encodeContextExplicit(3, newExtSeq);
      newTbsChildrenBytes.push(newExplicit3);
    } else {
      // Re-encode the original child verbatim by slicing its bytes from
      // the parent's value buffer.
      var childDer = _encodeAsn1FromNode(ch);
      newTbsChildrenBytes.push(childDer);
    }
  }
  if (!foundExtensions) {
    // Cert has no extensions at all — caller's SCT lookup would have
    // returned no SCT bytes, so this path shouldn't run. Surface anyway.
    throw new TlsTrustError("tls/ct-no-extensions",
      "cert has no extensions to strip from");
  }
  var newTbsValue = Buffer.concat(newTbsChildrenBytes);
  var newTbs = _encodeAsn1(asn1.TAG.SEQUENCE, true, newTbsValue);
  return newTbs;
}

// Minimal DER encoder helpers — enough to rebuild a TBS without the
// SCT extension. Tag class is universal for SEQUENCE; constructed
// flag wired explicitly.
function _encodeLength(len) {
  if (len < 0x80) return Buffer.from([len]);                                     // allow:raw-byte-literal — DER short-form length threshold
  var tmp = [];
  var n = len;
  while (n > 0) {
    tmp.unshift(n & 0xff);                                                       // allow:raw-byte-literal — base-256 byte
    n = n >>> 8;                                                                 // allow:raw-byte-literal — byte shift
  }
  return Buffer.concat([Buffer.from([0x80 | tmp.length]), Buffer.from(tmp)]);    // allow:raw-byte-literal — DER long-form length flag
}
function _encodeAsn1(tag, constructed, value) {
  var tagByte = (constructed ? 0x20 : 0x00) | tag;                               // allow:raw-byte-literal — DER constructed bit + universal tag
  return Buffer.concat([Buffer.from([tagByte]), _encodeLength(value.length), value]);
}
function _encodeContextExplicit(num, value) {
  // Context-specific class (10) + constructed (20) | tag.
  var tagByte = 0xa0 | num;                                                      // allow:raw-byte-literal — DER context-specific + constructed
  return Buffer.concat([Buffer.from([tagByte]), _encodeLength(value.length), value]);
}
function _encodeAsn1FromNode(node) {
  // Re-encode a parsed node verbatim by replaying the tag + length +
  // value. Universal-class shortcut: if class is universal, set the
  // tag byte from the universal table; if constructed, set the bit.
  // Context-specific / application / private classes get their bytes
  // restored directly. This works for the simple shapes we walk.
  var tagByte;
  if (node.tagClass === asn1.TAG_CLASS.UNIVERSAL) {
    tagByte = (node.constructed ? 0x20 : 0x00) | (node.tag & 0x1f);              // allow:raw-byte-literal — DER constructed bit + universal tag
  } else {
    var classBits = (node.tagClass & 0x03) << 6;                                 // allow:raw-byte-literal — DER tag-class bits
    tagByte = classBits | (node.constructed ? 0x20 : 0x00) | (node.tag & 0x1f);  // allow:raw-byte-literal — DER constructed bit + low-tag
  }
  return Buffer.concat([Buffer.from([tagByte]), _encodeLength(node.value.length), node.value]);
}

// SCT signature verification per RFC 6962 §3.2. opts.logKeys maps
// log_id (hex) → PEM public key. Operators populate from the Chrome
// CT log list (https://www.gstatic.com/ct/log_list/v3/log_list.json
// or equivalent) — log keys rotate, so the framework does NOT bake
// them in; that drift is the operator's to manage.
function verifyScts(certDer, opts) {
  opts = opts || {};
  if (!Buffer.isBuffer(certDer)) {
    throw new TlsTrustError("tls/ct-bad-input",
      "verifyScts: certDer must be a Buffer");
  }
  var logKeys = opts.logKeys || {};
  var minScts = typeof opts.minScts === "number" ? opts.minScts : 2;             // allow:raw-byte-literal — Chrome CT policy min-2-SCTs
  var ext = _extractSctExtensionFromCert(certDer);
  if (!ext.sctListRaw) {
    return { ok: false, reason: "no-sct-extension", scts: [] };
  }
  var scts;
  try { scts = _parseSctList(ext.sctListRaw); }
  catch (e) {
    return { ok: false, reason: "parse-error",
             error: (e && e.message) || String(e), scts: [] };
  }
  // Strip the SCT extension to compute the signed-entry per §3.2.
  var stripped;
  try { stripped = _stripSctExtensionFromCert(certDer); }
  catch (e) {
    return { ok: false, reason: "strip-failed",
             error: (e && e.message) || String(e), scts: scts };
  }
  var verifiedCount = 0;
  var perSctResults = [];
  for (var s = 0; s < scts.length; s += 1) {
    var sct = scts[s];
    var pem = logKeys[sct.logIdHex];
    if (!pem) {
      perSctResults.push({ logIdHex: sct.logIdHex, verified: false,
        reason: "log-key-missing" });
      continue;
    }
    var signedEntry;
    try { signedEntry = _buildSctSignedEntry(stripped, sct); }
    catch (e) {
      perSctResults.push({ logIdHex: sct.logIdHex, verified: false,
        reason: "build-entry-failed",
        error: (e && e.message) || String(e) });
      continue;
    }
    var nodeAlgo = sct.hashAlgo === 4 ? "sha256" :                               // allow:raw-byte-literal — TLS 1.2 HashAlgorithm enum sha256
                   sct.hashAlgo === 5 ? "sha384" :                               // allow:raw-byte-literal — TLS 1.2 HashAlgorithm enum sha384
                   sct.hashAlgo === 6 ? "sha512" :                               // allow:raw-byte-literal — TLS 1.2 HashAlgorithm enum sha512
                   null;
    if (nodeAlgo === null) {
      perSctResults.push({ logIdHex: sct.logIdHex, verified: false,
        reason: "unsupported-hash-algo", hashAlgo: sct.hashAlgo });
      continue;
    }
    var keyObj;
    try { keyObj = nodeCrypto.createPublicKey(pem); }
    catch (e) {
      perSctResults.push({ logIdHex: sct.logIdHex, verified: false,
        reason: "log-key-parse-failed",
        error: (e && e.message) || String(e) });
      continue;
    }
    var verified;
    try { verified = nodeCrypto.verify(nodeAlgo, signedEntry, keyObj, sct.signature); }
    catch (e) {
      perSctResults.push({ logIdHex: sct.logIdHex, verified: false,
        reason: "verify-threw",
        error: (e && e.message) || String(e) });
      continue;
    }
    perSctResults.push({ logIdHex: sct.logIdHex, verified: verified });
    if (verified) verifiedCount += 1;
  }
  return {
    ok:             verifiedCount >= minScts,
    reason:         verifiedCount >= minScts ? null : "insufficient-verified",
    minScts:        minScts,
    verifiedCount:  verifiedCount,
    totalScts:      scts.length,
    scts:           perSctResults,
  };
}

function _findSctOid(rawDer) {
  // Cheap presence check — used by inspect() before ASN.1 walking.
  // OID 1.3.6.1.4.1.11129.2.4.2 = 06 0A 2B 06 01 04 01 D6 79 02 04 02.
  var oidBytes = Buffer.from([
    0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0xd6, 0x79, 0x02, 0x04, 0x02,
  ]);
  return rawDer.indexOf(oidBytes) !== -1;
}

var ct = Object.freeze({
  // inspect — quick presence check for the SCT extension.
  inspect: function (rawDer) {
    if (!Buffer.isBuffer(rawDer)) {
      throw new TlsTrustError("tls/ct-bad-input",
        "ct.inspect: rawDer must be a Buffer (cert.raw)");
    }
    return {
      hasSctExtension: _findSctOid(rawDer),
      rawLength:       rawDer.length,
    };
  },
  // parseScts — full ASN.1 walk + SCT-list parse. Returns
  // [{ version, logIdHex, timestamp, signature, ... }, ...] or [] when
  // no SCT extension is present.
  parseScts: function (rawDer) {
    if (!Buffer.isBuffer(rawDer)) {
      throw new TlsTrustError("tls/ct-bad-input",
        "ct.parseScts: rawDer must be a Buffer");
    }
    var ext = _extractSctExtensionFromCert(rawDer);
    if (!ext.sctListRaw) return [];
    return _parseSctList(ext.sctListRaw);
  },
  // verifyScts — full RFC 6962 verification. opts.logKeys maps
  // log_id (hex SHA-256 of the log's pubkey) → PEM public key.
  // Operators populate from the Chrome CT log list. Returns
  // { ok, verifiedCount, totalScts, scts: [{ logIdHex, verified, ... }] }.
  verifyScts: verifyScts,
  // Operator middleware predicate: refuse a peer cert lacking SCT
  // verification. Composes verifyScts under the hood.
  requireScts: function (opts) {
    opts = opts || {};
    return function (peerCert) {
      if (!peerCert || !peerCert.raw) {
        return new TlsTrustError("tls/ct-no-cert",
          "requireScts: peer cert.raw missing");
      }
      var rv = verifyScts(peerCert.raw, opts);
      if (!rv.ok) {
        // Map verifier reason → operator-facing error code so call
        // sites can distinguish "no SCT extension at all" from
        // "extension present but verification short of minScts".
        var code = "tls/ct-not-verified";
        if (rv.reason === "no-sct-extension") code = "tls/ct-no-sct-extension";
        else if (rv.reason === "insufficient-verified") code = "tls/ct-insufficient-verified";
        return new TlsTrustError(code,
          "SCT verification failed: " + (rv.reason || "unknown") +
          " (" + rv.verifiedCount + "/" + rv.totalScts + " verified)");
      }
      return null;
    };
  },
});

module.exports = {
  addCa:               addCa,
  addCaBundle:         addCaBundle,
  removeCa:            removeCa,
  removeCaByLabel:     removeCaByLabel,
  clearAll:            clearAll,
  purgeExpired:        purgeExpired,
  expiringSoon:        expiringSoon,
  expiryMonitor:       expiryMonitor,
  useSystemTrust:      useSystemTrust,
  isSystemTrustEnabled: isSystemTrustEnabled,
  getTrustStore:       getTrustStore,
  captureBaselineFingerprints: captureBaselineFingerprints,
  detectBaselineDrift: detectBaselineDrift,
  applyToContext:      applyToContext,
  getCaPems:           getCaPems,
  ocsp:                ocsp,
  ct:                  ct,
  pqc:                 pqc,
  TlsTrustError:       TlsTrustError,
  _resetForTest:       _resetForTest,
};
