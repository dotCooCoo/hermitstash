// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

var nodeTls = require("node:tls");
var nodeFs = require("node:fs");
var nodePath = require("node:path");
var net = require("node:net");
var nodeCrypto = require("node:crypto");
var numericBounds = require("./numeric-bounds");
var atomicFile = require("./atomic-file");

var bCrypto = require("./crypto");
var C = require("./constants");
var safeBuffer = require("./safe-buffer");
var safeJson = require("./safe-json");
var validateOpts = require("./validate-opts");
var lazyRequire = require("./lazy-require");
var safeAsync = require("./safe-async");
var { defineClass } = require("./framework-error");

var TlsTrustError = defineClass("TlsTrustError", { alwaysPermanent: true });

var TLS_TRANSIENT_CODES = {
  "tls/ech-connect-failed": true,
  "tls/ech-timeout":        true,
  "tls/ech-dns-unavailable": true,
};
function _networkTlsErrorIsPermanent(code) {
  return !Object.prototype.hasOwnProperty.call(TLS_TRANSIENT_CODES, code);
}
var NetworkTlsError = defineClass("NetworkTlsError", { permanentClassifier: _networkTlsErrorIsPermanent });

var observability = lazyRequire(function () { return require("./observability"); });
var audit = lazyRequire(function () { return require("./audit"); });
var networkDns = lazyRequire(function () { return require("./network-dns"); });
var httpClient = lazyRequire(function () { return require("./http-client"); });
var asn1 = require("./asn1-der");

// tls.classical_downgrade audit. Drop-silent best-effort (§8 hot-path sink) —
function auditInsecureTls(meta) {
  meta = meta || {};
  try {
    observability().safeEvent("tls.insecure_skip_verify", 1, {
      host: meta.host || null, port: meta.port || null, source: meta.source || null,
    });
  } catch (_e) { /* drop-silent */ }
  try {
    audit().safeEmit({
      action:  "tls.insecure_skip_verify",
      outcome: "success",
      metadata: { host: meta.host || null, port: meta.port || null, source: meta.source || null },
    });
  } catch (_e) { /* drop-silent — audit best-effort, never break TLS */ }
}

var STATE = {
  cas:             [],
  systemTrust:     false,
  baselineFingerprints: null,
  tlsKeyShares:    ["X25519MLKEM768", "SecP256r1MLKEM768", "SecP384r1MLKEM1024", "X25519"],
  tlsKeySharesConfigured: false,
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
  if (safeBuffer.byteLengthOf(s) > C.BYTES.kib(1)) return false;
  if (safeBuffer.hasCrlf(s)) return false;
  return true;
}

function _readPathFile(p) {
  return atomicFile.fdSafeReadSync(p, {
    encoding:       "utf8",
    allowShortRead: true,
    errorFor:       function () { return undefined; },
  });
}

function _readPath(p) {
  var stat = nodeFs.statSync(p);
  if (stat.isDirectory()) {
    var files = nodeFs.readdirSync(p)
      .filter(function (f) { return /\.(pem|crt|cer)$/i.test(f); })
      .sort();
    return files.map(function (f) { return _readPathFile(nodePath.join(p, f)); }).join("\n");
  }
  return _readPathFile(p);
}

function addCa(pemOrPath, opts) {
  opts = opts || {};
  validateOpts(opts, ["label", "audit"], "tls.addCa");
  var raw = pemOrPath;
  if (typeof pemOrPath === "string" && _isPathLike(pemOrPath)) {
    var stat;
    try { stat = nodeFs.statSync(pemOrPath); } catch (_e) {
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
  observability().safeEvent("network.tls.ca.added", 1, { count: added.length });
  return added;
}

function addCaBundle(p, opts) {
  return addCa(p, opts);
}

function useSystemTrust(enable) {
  STATE.systemTrust = enable !== false;
  observability().safeEvent("network.tls.system_trust.set", 1, { enabled: STATE.systemTrust });
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

function _certAuditMetadata(m) {
  return {
    subject:        m.subject,
    issuer:         m.issuer,
    fingerprint256: m.fingerprint256,
    validFrom:      m.validFrom,
    validTo:        m.validTo,
    isSelfSigned:   m.isSelfSigned,
  };
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
        metadata: Object.assign(_certAuditMetadata(m), {
          label:  m.label,
          reason: reason || "operator",
        }),
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
  observability().safeEvent("network.tls.ca.removed", 1, { count: removed.length, reason: "operator" });
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
  observability().safeEvent("network.tls.ca.removed", 1, { count: removed.length, reason: "label" });
  return removed.length;
}

function clearAll(opts) {
  if (STATE.cas.length === 0) return 0;
  var removed = STATE.cas.map(function (e) { return Object.assign({ label: e.label }, e.meta); });
  STATE.cas = [];
  if (!opts || opts.audit !== false) _emitAuditRemove(removed, "operator-clear-all");
  observability().safeEvent("network.tls.ca.cleared", 1, { count: removed.length });
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
  observability().safeEvent("network.tls.ca.purged_expired", 1, { count: removed.length });
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
            outcome: "success",
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
      safeAsync.safeInvoke(opts.onExpiring, rows);
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

function pinsetDriftMonitor(opts) {
  opts = opts || {};
  var intervalMs = opts.intervalMs;
  var auditOn    = opts.audit !== false;
  if (typeof intervalMs !== "number" || !isFinite(intervalMs) || intervalMs <= 0) {
    throw new TlsTrustError("tls/bad-interval",
      "tls.pinsetDriftMonitor: intervalMs must be a positive finite number");
  }
  function _tick() {
    var drift;
    try { drift = detectBaselineDrift(); }
    catch (_e) { return; }
    if (drift === null) return;
    if (auditOn) {
      try {
        audit().safeEmit({
          action:  "network.tls.pinset.drift_check",
          outcome: drift.drifted ? "warn" : "ok",
          metadata: { added: drift.added.length, removed: drift.removed.length },
        });
      } catch (_e) { /* drop-silent */ }
    }
    if (drift.drifted) {
      try { observability().safeEvent("network.tls.pinset.drifted", 1, {}); }
      catch (_e) { /* drop-silent */ }
      if (auditOn) {
        try {
          audit().safeEmit({
            action:  "network.tls.pinset.drifted",
            outcome: "failure",
            metadata: { added: drift.added, removed: drift.removed },
          });
        } catch (_e) { /* drop-silent */ }
      }
      safeAsync.safeInvoke(opts.onDrift, drift);
    }
  }
  var handle = safeAsync.repeating(_tick, intervalMs, { name: "tls-pinset-drift-monitor" });
  return {
    stop: function () { if (handle) { handle.stop(); handle = null; } },
  };
}

function detectBaselineDrift() {
  if (!STATE.baselineFingerprints) return null;
  var current = STATE.cas.map(function (e) { return e.meta.fingerprint256; });
  var added = current.filter(function (fp) { return STATE.baselineFingerprints.indexOf(fp) === -1; });
  var removed = STATE.baselineFingerprints.filter(function (fp) { return current.indexOf(fp) === -1; });
  return { added: added, removed: removed, drifted: added.length > 0 || removed.length > 0 };
}

function _groupPreferenceString(value, where) {
  if (Array.isArray(value)) {
    if (value.length === 0) {
      throw new TlsTrustError("tls/bad-group-preference",
        where + ": group preference must name at least one group");
    }
    for (var i = 0; i < value.length; i++) {
      if (typeof value[i] !== "string" || value[i].length === 0) {
        throw new TlsTrustError("tls/bad-group-preference",
          where + "[" + i + "]: group preference entries must be non-empty strings, got " +
          (typeof value[i] === "string" ? "empty string" : typeof value[i]));
      }
    }
    return value.join(":");
  }
  if (typeof value !== "string" || value.length === 0) {
    throw new TlsTrustError("tls/bad-group-preference",
      where + ": group preference must be a non-empty string or array of group " +
      "names, got " + (typeof value === "string" ? "empty string" : typeof value));
  }
  return value;
}

var VERSION_PINNED_METHOD_RE =
  /^(?:SSLv2|SSLv23|SSLv3|TLSv1|TLSv1_1|TLSv1_2)_(?:client_|server_)?method$/;
var MAX_METHOD_NAME = 32;

function _reachesTls13(opts) {
  if (opts === null || typeof opts !== "object") return true;
  var cap = opts.maxVersion;
  if (cap !== undefined && cap !== null && cap !== "TLSv1.3") return false;
  var method = opts.secureProtocol;
  if (typeof method !== "string" || method.length > MAX_METHOD_NAME) return true;
  return !VERSION_PINNED_METHOD_RE.test(method);
}

function _stripUnreachableCertCompression(merged, caller) {
  if (!merged || typeof merged !== "object") return merged;
  if (_reachesTls13(merged)) return merged;
  if (caller && typeof caller === "object" &&
      caller.certificateCompression !== undefined) return merged;
  delete merged.certificateCompression;
  return merged;
}

function keyAgreementGroups(override, where) {
  if (override !== undefined && override !== null) {
    return _groupPreferenceString(override, where || "tls.keyAgreementGroups");
  }
  return STATE.tlsKeyShares.length > 0 ? STATE.tlsKeyShares.join(":") : null;
}

function serverKeyAgreementGroups(override, where) {
  if (override !== undefined && override !== null) {
    return _groupPreferenceString(override, where || "tls.serverKeyAgreementGroups");
  }
  var preferred = STATE.tlsKeyShares.length > 0
    ? STATE.tlsKeyShares.slice()
    : C.TLS_GROUP_PREFERENCE.slice();
  if (preferred.length === 0) return null;

  var named = preferred.map(function (g) { return String(g).toLowerCase(); });
  var fallback = STATE.tlsKeySharesConfigured ? [] :
    C.TLS_SERVER_FALLBACK_CURVES.filter(function (g) {
      return named.indexOf(String(g).toLowerCase()) === -1;
    });

  var tuples = preferred.slice();
  if (fallback.length > 0) tuples.push(fallback.join(":"));
  return tuples.join("/");
}

function applyToContext(opts) {
  opts = opts || {};
  validateOpts(opts, ["base"], "tls.applyToContext");
  var base = Object.assign({}, opts.base || {});
  var caStrings = STATE.cas.map(function (e) { return e.pem; });
  if (STATE.systemTrust) {
    var rootCAs = nodeTls.rootCertificates;
    if (Array.isArray(rootCAs)) {
      caStrings = caStrings.concat(rootCAs);
    }
  }
  if (caStrings.length > 0) base.ca = caStrings;
  var overrideKey = base.ecdhCurve !== undefined ? "ecdhCurve"
                  : base.groups    !== undefined ? "groups"
                  : null;
  if (overrideKey !== null) {
    base.ecdhCurve = _groupPreferenceString(base[overrideKey],
                                            "tls.applyToContext: base." + overrideKey);
  } else if (STATE.tlsKeyShares.length > 0) {
    base.ecdhCurve = STATE.tlsKeyShares.join(":");
  }
  if (base.groups !== undefined) delete base.groups;
  if (base.certificateCompression === undefined && _reachesTls13(base)) {
    var certAlgs = C.TLS_CERT_COMPRESSION();
    if (certAlgs.length > 0) base.certificateCompression = certAlgs.slice();
  }
  return base;
}

var DEFAULT_PQC_KEY_SHARES = Object.freeze([
  "X25519MLKEM768",
  "SecP256r1MLKEM768",
  "SecP384r1MLKEM1024",
  "X25519",
]);

function _validateKeyShare(name) {
  if (typeof name !== "string" || name.length === 0 || safeBuffer.byteLengthOf(name) > C.BYTES.bytes(64)) {
    throw new TlsTrustError("tls/bad-key-share",
      "tls.pqc.setKeyShares: each entry must be a non-empty string up to 64 chars");
  }
  if (!/^[A-Za-z0-9_]+$/.test(name)) {
    throw new TlsTrustError("tls/bad-key-share",
      "tls.pqc.setKeyShares: '" + name + "' has illegal characters " +
      "(must match [A-Za-z0-9_]+)");
  }
}

var _postureGeneration = 1;

function postureGeneration() { return _postureGeneration; }

function setKeyShares(list) {
  if (!Array.isArray(list) || list.length === 0) {
    throw new TlsTrustError("tls/bad-key-shares",
      "tls.pqc.setKeyShares: must be a non-empty array of group names");
  }
  for (var i = 0; i < list.length; i += 1) _validateKeyShare(list[i]);
  STATE.tlsKeyShares = list.slice();
  STATE.tlsKeySharesConfigured = true;
  _postureGeneration += 1;
  return getKeyShares();
}

function getKeyShares() { return STATE.tlsKeyShares.slice(); }

function resetKeyShares() {
  STATE.tlsKeyShares = DEFAULT_PQC_KEY_SHARES.slice();
  STATE.tlsKeySharesConfigured = false;
  _postureGeneration += 1;
  return getKeyShares();
}

var preferredGroups = Object.freeze({
  set:    setKeyShares,
  get:    getKeyShares,
  reset:  resetKeyShares,
  DEFAULT: DEFAULT_PQC_KEY_SHARES,
});

var pqc = Object.freeze({
  setKeyShares:           setKeyShares,
  getKeyShares:           getKeyShares,
  resetKeyShares:         resetKeyShares,
  DEFAULT_KEY_SHARES:     DEFAULT_PQC_KEY_SHARES,
});

function getCaPems() {
  return STATE.cas.map(function (e) { return e.pem; });
}

function _normalizeCaInput(ca) {
  if (ca === undefined || ca === null) return undefined;
  if (Buffer.isBuffer(ca)) return ca.toString("utf8");
  if (typeof ca === "string") return ca;
  if (!Array.isArray(ca)) {
    throw new NetworkTlsError("network-tls/bad-tls-options",
      "buildOptions: ca must be a PEM string, Buffer, or array thereof");
  }
  var parts = [];
  for (var i = 0; i < ca.length; i += 1) {
    var entry = ca[i];
    if (Buffer.isBuffer(entry)) parts.push(entry.toString("utf8"));
    else if (typeof entry === "string") parts.push(entry);
    else {
      throw new NetworkTlsError("network-tls/bad-tls-options",
        "buildOptions: ca[" + i + "] must be a PEM string or Buffer");
    }
  }
  return parts.join("\n");
}

function buildOptions(opts) {
  opts = opts || {};
  if (typeof opts !== "object" || Array.isArray(opts)) {
    throw new NetworkTlsError("network-tls/bad-tls-options",
      "buildOptions: opts must be a plain object");
  }
  validateOpts(opts,
    ["ecdhCurve", "groups", "cert", "key", "ca", "minVersion", "sni",
      "certificateCompression"],
    "network.tls.buildOptions");
  var out = {};
  var minV = opts.minVersion === undefined ? "TLSv1.3" : opts.minVersion;
  if (minV !== "TLSv1.3") {
    throw new NetworkTlsError("network-tls/bad-tls-options",
      "buildOptions: minVersion must be 'TLSv1.3' (got " +
      JSON.stringify(opts.minVersion) + ") — framework posture is " +
      "TLS-1.3-only outbound; construct tls.connect opts directly to " +
      "negotiate weaker protocol versions.");
  }
  out.minVersion = minV;

  var requested = null;
  if (Array.isArray(opts.groups)) {
    requested = opts.groups.slice();
  } else if (typeof opts.groups === "string" && opts.groups.length > 0) {
    requested = opts.groups.split(":");
  } else if (typeof opts.ecdhCurve === "string" && opts.ecdhCurve.length > 0) {
    requested = opts.ecdhCurve.split(":");
  } else if (opts.groups !== undefined || opts.ecdhCurve !== undefined) {
    throw new NetworkTlsError("network-tls/bad-tls-options",
      "buildOptions: groups must be string or string[], ecdhCurve must be string");
  }
  var preferred = STATE.tlsKeyShares.length > 0
    ? STATE.tlsKeyShares.slice()
    : DEFAULT_PQC_KEY_SHARES.slice();
  var resolved;
  if (requested === null) {
    resolved = preferred;
  } else {
    if (requested.length === 0) {
      throw new NetworkTlsError("network-tls/bad-tls-options",
        "buildOptions: groups/ecdhCurve must list at least one named group");
    }
    for (var rgi = 0; rgi < requested.length; rgi += 1) {
      if (typeof requested[rgi] !== "string" || requested[rgi].length === 0) {
        throw new NetworkTlsError("network-tls/bad-tls-options",
          "buildOptions: groups[" + rgi + "] must be a non-empty string");
      }
      if (preferred.indexOf(requested[rgi]) === -1) {
        throw new NetworkTlsError("network-tls/bad-tls-options",
          "buildOptions: group '" + requested[rgi] + "' is not in the " +
          "framework preferred list (" + preferred.join(":") + "); " +
          "construct tls.connect opts directly to negotiate weaker groups.");
      }
    }
    resolved = requested;
  }
  out.ecdhCurve = resolved.join(":");

  if (opts.cert !== undefined) {
    if (!(typeof opts.cert === "string" || Buffer.isBuffer(opts.cert) ||
          Array.isArray(opts.cert))) {
      throw new NetworkTlsError("network-tls/bad-tls-options",
        "buildOptions: cert must be a string, Buffer, or array thereof");
    }
    out.cert = opts.cert;
  }
  if (opts.key !== undefined) {
    if (!(typeof opts.key === "string" || Buffer.isBuffer(opts.key) ||
          Array.isArray(opts.key))) {
      throw new NetworkTlsError("network-tls/bad-tls-options",
        "buildOptions: key must be a string, Buffer, or array thereof");
    }
    out.key = opts.key;
  }
  if (opts.ca !== undefined) out.ca = _normalizeCaInput(opts.ca);

  if (opts.sni !== undefined) {
    validateOpts.requireNonEmptyString(opts.sni, "buildOptions: sni",
      NetworkTlsError, "network-tls/bad-tls-options");
    out.servername = opts.sni;
  }

  var supportedCompression = certificateCompressionAlgorithms();
  if (opts.certificateCompression === undefined) {
    if (supportedCompression.length > 0) out.certificateCompression = supportedCompression;
  } else {
    if (!Array.isArray(opts.certificateCompression)) {
      throw new NetworkTlsError("network-tls/bad-tls-options",
        "buildOptions: certificateCompression must be an array of algorithm " +
        "names (pass [] to advertise none)");
    }
    validateOpts.optionalNonEmptyStringArray(opts.certificateCompression,
      "buildOptions: certificateCompression", NetworkTlsError,
      "network-tls/bad-tls-options");
    opts.certificateCompression.forEach(function (name) {
      if (supportedCompression.indexOf(name) === -1) {
        throw new NetworkTlsError("network-tls/bad-tls-options",
          "buildOptions: certificateCompression algorithm " + JSON.stringify(name) +
          " is not supported by this runtime (supported: " +
          (supportedCompression.length ? supportedCompression.join(", ") : "none") + ")");
      }
    });
    if (opts.certificateCompression.length > 0) {
      out.certificateCompression = opts.certificateCompression.slice();
    }
  }
  return out;
}

/**
 * @primitive b.network.tls.certificateCompressionAlgorithms
 * @signature b.network.tls.certificateCompressionAlgorithms()
 * @since     0.18.17
 * @status    stable
 * @related   b.network.tls.connectWithEch, b.pqcAgent.create
 *
 * The RFC 8879 certificate-compression algorithms this runtime can
 * decompress, newest-runtime order, as a fresh array you own.
 *
 * Certificate compression shrinks the TLS `Certificate` message — on a
 * post-quantum deployment the largest thing on the wire during a handshake,
 * since an ML-DSA-87 signature alone runs about 4.6 KB before any public key
 * or chain. Every outbound path the framework ships already advertises this
 * list, and `b.router` advertises it inbound; call this directly only when
 * you are assembling `tls.connect` options yourself and want to narrow the
 * list or check what the runtime supports.
 *
 * Compressing the certificate is not the record-layer compression that CRIME
 * attacked: the `Certificate` message is public, fixed, and not
 * attacker-influenced, so its compressed length reveals nothing about a
 * secret and no attacker-chosen plaintext shares a compression context with
 * one.
 *
 * Returns an empty array on a runtime that does not implement the extension,
 * which reads naturally as "advertise nothing".
 *
 * @example
 *   b.network.tls.certificateCompressionAlgorithms();
 *   // -> ["zlib", "brotli", "zstd"]
 *
 *   // Narrow what an outbound connection will accept.
 *   var opts = b.network.tls.buildOptions({ certificateCompression: ["brotli"] });
 */
function certificateCompressionAlgorithms() {
  return C.TLS_CERT_COMPRESSION().slice();
}

/**
 * @primitive b.network.tls.outboundPosture
 * @signature b.network.tls.outboundPosture()
 * @since     0.18.17
 * @status    stable
 * @related   b.network.tls.certificateCompressionAlgorithms, b.pqcAgent.create
 *
 * The framework's outbound TLS posture as a fresh options object, ready to
 * merge into any `tls.connect`, `https.request` or `https.Agent` options:
 *
 *     var connectOpts = Object.assign({ host: h, port: p },
 *                                     b.network.tls.outboundPosture());
 *
 * Every protocol client the framework ships — DNS-over-HTTPS and
 * DNS-over-TLS, NTS-KE, Redis, syslog, WebSocket, proxy tunnels, the HTTP
 * client, the ECH and OCSP paths — merges this rather than listing the keys
 * itself, so raising the posture is one edit that cannot reach some outbound
 * paths and miss others.
 *
 * It reads the LIVE key-share preference, so
 * `b.network.tls.preferredGroups.set(...)` (or the `b.network.tls.pqc`
 * alias) takes effect on the next dial across every one of those clients.
 * Call it per connection rather than caching the result, or an operator's
 * later narrowing will not reach the wire.
 *
 * @example
 *   // Restrict every outbound handshake to the NIST-curve hybrids.
 *   b.network.tls.preferredGroups.set(["SecP256r1MLKEM768", "SecP384r1MLKEM1024"]);
 *   b.network.tls.outboundPosture();
 *   // → { minVersion: "TLSv1.3",
 *   //     ecdhCurve: "SecP256r1MLKEM768:SecP384r1MLKEM1024",
 *   //     certificateCompression: ["zlib", "brotli", "zstd"] }
 */
function outboundPosture() {
  var posture = { minVersion: "TLSv1.3" };
  var shares = STATE.tlsKeyShares;
  posture.ecdhCurve = (Array.isArray(shares) && shares.length > 0)
    ? shares.join(":")
    : C.TLS_GROUP_CURVE_STR;
  var certAlgs = C.TLS_CERT_COMPRESSION();
  if (certAlgs.length > 0) posture.certificateCompression = certAlgs;
  return posture;
}

/**
 * @primitive  b.network.tls.explainOutboundFailure
 * @signature  b.network.tls.explainOutboundFailure(err, ctx?)
 * @since      0.18.18
 * @status     stable
 * @related    b.network.tls.outboundPosture
 *
 * Turn a refused outbound handshake into a sentence naming the likely cause.
 *
 * OpenSSL reports a rejected ClientHello as a bare alert — `tlsv1 alert
 * protocol version` — which names neither the peer nor anything an operator
 * can act on, and reads as a problem with the request rather than with the
 * posture the client applied to it. Two of those alerts are routinely the
 * posture doing its job:
 *
 * A `protocol_version` alert against a client pinning `minVersion: "TLSv1.3"`
 * means the peer offers no TLS 1.3. That is a version refusal and has nothing
 * to do with the key-exchange groups, which is worth stating plainly: the
 * post-quantum posture is the framework's most visible property, so it draws
 * the blame for handshake failures it did not cause.
 *
 * A `handshake_failure` alert against a narrowed group list means the peer
 * shares none of the offered groups. Under the shipped preference this cannot
 * happen — the list ends in classical X25519, so a peer with no post-quantum
 * hybrid negotiates that — so it points at a list an operator has narrowed
 * past what the peer can do.
 *
 * Neither alert is exclusive to these causes, so the wording is hedged and
 * the original error text is carried through rather than replaced. Returns
 * null when the error is not one this can speak to, which callers use to fall
 * back to the original message.
 *
 * Pass `tlsOpts` — the options object the dial was made with — rather than
 * copying settings out of it. Handing the object over names every setting it
 * could carry, so the explanation stays right as the diagnosis learns to read
 * settings a caller was not thinking about when the error handler was written.
 *
 * @opts
 *   host:           string,   // peer named in the message; default: omitted
 *   port:           number,   // appended to host when both are present
 *   tlsOpts:        object,   // the options the dial used; each setting below is read from it
 *   minVersion:     string,   // the floor that was applied; default: the live posture
 *   maxVersion:     string,   // the ceiling that was applied, when a caller capped the dial below TLS 1.3
 *   secureProtocol: string,   // an OpenSSL method name, when a caller pinned one version that way
 *   ecdhCurve:      string,   // the group list that was offered; default: the live posture
 *
 * @example
 *   var why = b.network.tls.explainOutboundFailure(err, { host: "registry.example.com", port: 443 });
 *   // -> "TLS handshake refused by registry.example.com:443 - the peer most
 *   //     likely does not offer TLS 1.3, ..."
 */
var EXPLAIN_PREFIX = "TLS handshake refused";
var DIAGNOSED = "_blamejsTlsDiagnosed";

function _hasOwn(obj, key) {
  return Object.prototype.hasOwnProperty.call(obj, key);
}

function _dialSetting(ctx, key, fallback) {
  if (_hasOwn(ctx, key)) return ctx[key];
  var dialed = ctx.tlsOpts;
  if (dialed !== null && typeof dialed === "object") return dialed[key];
  return fallback;
}

function _portSuffix(port) {
  var n = typeof port === "string" && port !== "" ? Number(port) : port;
  if (typeof n !== "number" || !isFinite(n)) return "";
  return ":" + n;
}

function explainOutboundFailure(err, ctx) {
  if (!err || typeof err !== "object") return null;
  ctx = ctx || {};
  var code = typeof err.code === "string" ? err.code : "";
  var text = typeof err.message === "string" ? err.message : "";
  var posture = outboundPosture();
  var minVersion = _dialSetting(ctx, "minVersion", posture.minVersion);
  var offered = _dialSetting(ctx, "ecdhCurve", posture.ecdhCurve);

  var peer = "";
  if (typeof ctx.host === "string" && ctx.host.length > 0) {
    peer = " by " + ctx.host +
      _portSuffix(ctx.port);
  }

  var isVersion = code === "ERR_SSL_TLSV1_ALERT_PROTOCOL_VERSION" ||
                  code === "ERR_SSL_UNSUPPORTED_PROTOCOL" ||
                  code === "ERR_SSL_VERSION_TOO_LOW" ||
                  /alert protocol version|unsupported protocol|version too low/i.test(text);
  if (isVersion && minVersion === "TLSv1.3") {
    return EXPLAIN_PREFIX + peer + " - the peer most likely does not " +
      "offer TLS 1.3, which this client requires (minVersion TLSv1.3). This is " +
      "a protocol-version refusal and is unrelated to the post-quantum group " +
      "preference. Underlying error: " + text;
  }

  var list = typeof offered === "string" && offered.length > 0 ? offered.split(":") : [];
  if (list.length === 0) return null;

  var hasClassicalFallback = false;
  for (var i = 0; i < list.length; i += 1) {
    if (list[i].length > 0 && list[i].indexOf("MLKEM") === -1) hasClassicalFallback = true;
  }
  var hybridOnlyNote = hasClassicalFallback ? ""
    : " The list names only post-quantum hybrids, so a peer without one has " +
      "nothing left to negotiate.";

  if (code === "ERR_SSL_NO_SHARED_GROUP" || code === "ERR_SSL_WRONG_CURVE" ||
      /no shared group|wrong curve/i.test(text)) {
    return EXPLAIN_PREFIX + peer + " - the peer supports none of the " +
      "key-exchange groups this client offers (" + offered + ")." + hybridOnlyNote +
      " Underlying error: " + text;
  }

  if (code === "ERR_SSL_SSL/TLS_ALERT_HANDSHAKE_FAILURE" ||
      /alert handshake failure/i.test(text)) {
    var reached13 = _reachesTls13({
      maxVersion:     _dialSetting(ctx, "maxVersion", undefined),
      secureProtocol: _dialSetting(ctx, "secureProtocol", undefined),
    });
    return EXPLAIN_PREFIX + peer + " - the peer rejected the handshake with a " +
      "generic failure alert, which does not say what it objected to. With " +
      "this client's posture the usual candidates are no mutually supported " +
      "key-exchange group (it offers " + offered + "), " +
      (reached13 ? "no shared TLS 1.3 cipher suite" : "no shared cipher suite") +
      ", and certificate selection." + hybridOnlyNote +
      " Underlying error: " + text;
  }
  return null;
}

/**
 * @primitive  b.network.tls.annotateOutboundFailure
 * @signature  b.network.tls.annotateOutboundFailure(err, ctx?)
 * @since      0.18.18
 * @status     stable
 * @related    b.network.tls.explainOutboundFailure
 *
 * Rewrite a refused handshake's message in place to name the likely cause,
 * and hand the same error back.
 *
 * The error object is kept rather than replaced so `err.code`, the error
 * class and anything a caller already branches on survive untouched; only the
 * message changes, and only when there is something to say. The stack's
 * leading line is refreshed alongside it, since it embeds a copy of the
 * message captured at construction.
 *
 * Diagnosis never fails a request: any error raised while working out the
 * explanation is swallowed and the original message stands.
 *
 * @opts
 *   host:    string,   // peer named in the message
 *   port:    number,   // appended to host when both are present
 *   tlsOpts: object,   // the options the dial used; see explainOutboundFailure for the settings read from it
 *
 * @example
 *   socket.on("error", function (err) {
 *     b.network.tls.annotateOutboundFailure(err, { host: host, port: port });
 *     handle(err);
 *   });
 */
function annotateOutboundFailure(err, ctx) {
  try {
    if (!err || typeof err !== "object") return err;
    if (err[DIAGNOSED] === true) return err;
    Object.defineProperty(err, DIAGNOSED, {
      value: true, enumerable: false, writable: true, configurable: true,
    });
    var why = explainOutboundFailure(err, ctx);
    if (typeof why !== "string" || why.length === 0) return err;
    var previous = err.message;
    err.message = why;
    if (typeof err.stack === "string" && previous && err.stack.indexOf(previous) !== -1) {
      err.stack = err.stack.replace(previous, why);
    }
  } catch (_e) { /* best-effort: an unexplained error beats a masked one */ }
  return err;
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
        metadata: Object.assign(_certAuditMetadata(m), { label: opts.label || null }),
      });
    } catch (_e) { /* audit best-effort — never break the caller */ }
  }
}

function _resetForTest() {
  STATE.cas = [];
  STATE.systemTrust = false;
  STATE.baselineFingerprints = null;
  STATE.tlsKeyShares = DEFAULT_PQC_KEY_SHARES.slice();
  STATE.tlsKeySharesConfigured = false;
}

function _connectAndCheckOcsp(opts, requireStapled) {
  return new Promise(function (resolve, reject) {
    var connectOpts = Object.assign(outboundPosture(), opts,
      { requestOCSP: true });
    var sock;
    try {
      sock = nodeTls.connect(connectOpts);
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

var OID_BASIC_OCSP_RESPONSE = "1.3.6.1.5.5.7.48.1.1";
var OID_OCSP_NONCE          = "1.3.6.1.5.5.7.48.1.2";
var OID_SHA1                = "1.3.14.3.2.26";
var OCSP_CERTID_HASH_OID_TO_NODE = {
  "1.3.14.3.2.26":          "sha1",
  "2.16.840.1.101.3.4.2.1": "sha256",
  "2.16.840.1.101.3.4.2.2": "sha384",
  "2.16.840.1.101.3.4.2.3": "sha512",
};
var OID_RSA_SHA256          = "1.2.840.113549.1.1.11";
var OID_RSA_SHA384          = "1.2.840.113549.1.1.12";
var OID_RSA_SHA512          = "1.2.840.113549.1.1.13";
var OID_ECDSA_SHA256        = "1.2.840.10045.4.3.2";
var OID_ECDSA_SHA384        = "1.2.840.10045.4.3.3";
var OID_ECDSA_SHA512        = "1.2.840.10045.4.3.4";

function _parseTime(node) {
  var s = node.value.toString("ascii");
  var year, month, day, hour, min, sec;
  if (s.length === 13 && s.charAt(12) === "Z") {
    year  = parseInt(s.slice(0, 2), 10);
    year += year >= 50 ? 1900 : 2000;
    month = parseInt(s.slice(2, 4), 10);
    day   = parseInt(s.slice(4, 6), 10);
    hour  = parseInt(s.slice(6, 8), 10);
    min   = parseInt(s.slice(8, 10), 10);
    sec   = parseInt(s.slice(10, 12), 10);
  } else if (s.length >= 15 && s.charAt(s.length - 1) === "Z") {
    year  = parseInt(s.slice(0, 4), 10);
    month = parseInt(s.slice(4, 6), 10);
    day   = parseInt(s.slice(6, 8), 10);
    hour  = parseInt(s.slice(8, 10), 10);
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
  5: "sigRequired",
  6: "unauthorized",
};

function parseOcspResponse(der) {
  if (!Buffer.isBuffer(der) || der.length === 0) {
    throw new TlsTrustError("tls/ocsp-bad-input",
      "parseOcspResponse: expected non-empty Buffer");
  }
  var top = asn1.readNode(der);
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
  if (topChildren.length < 2) {
    throw new TlsTrustError("tls/ocsp-bad-shape",
      "successful OCSP response missing responseBytes");
  }
  var responseBytes = asn1.unwrapExplicit(topChildren[1], 0);
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
  var basicDer = asn1.readOctetString(rbChildren[1]);
  var basic    = asn1.readNode(basicDer);
  if (basic.tag !== asn1.TAG.SEQUENCE) {
    throw new TlsTrustError("tls/ocsp-bad-shape",
      "BasicOCSPResponse is not a SEQUENCE");
  }
  var basicChildren = asn1.readSequence(basic.value);
  if (basicChildren.length < 3) {
    throw new TlsTrustError("tls/ocsp-bad-shape",
      "BasicOCSPResponse needs tbsResponseData + signatureAlgorithm + signature");
  }
  var tbsNode = basicChildren[0];
  var sigAlgChildren = asn1.readSequence(basicChildren[1].value);
  var sigAlgOid = asn1.readOid(sigAlgChildren[0]);
  var signatureBytes = asn1.readBitString(basicChildren[2]);

  var basicValueStart = basicDer.length - basic.value.length;
  var tbsDer = basicDer.slice(basicValueStart, basicValueStart + tbsNode.totalLength);

  var rdChildren = asn1.readSequence(tbsNode.value);
  var responsesNode = null;
  var responseExtensionsNode = null;
  for (var rdi = rdChildren.length - 1; rdi >= 0; rdi -= 1) {
    var ch = rdChildren[rdi];
    if (ch.tag === asn1.TAG.SEQUENCE && ch.tagClass === asn1.TAG_CLASS.UNIVERSAL) {
      responsesNode = ch;
      break;
    }
    if (ch.tagClass === asn1.TAG_CLASS.CONTEXT_SPECIFIC && ch.tag === 1) {
      responseExtensionsNode = asn1.readNode(ch.value, 0);
    }
  }
  if (!responsesNode) {
    throw new TlsTrustError("tls/ocsp-bad-shape",
      "ResponseData missing responses SEQUENCE OF");
  }
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
    if (sr.length < 3) continue;
    var certIdChildren = asn1.readSequence(sr[0].value);
    var certIdHashAlgOid = certIdChildren.length >= 1
      ? asn1.readOid(asn1.readSequence(certIdChildren[0].value)[0]) : null;
    var issuerNameHash = certIdChildren.length >= 2
      ? asn1.readOctetString(certIdChildren[1]) : null;
    var issuerKeyHash = certIdChildren.length >= 3
      ? asn1.readOctetString(certIdChildren[2]) : null;
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
      certIdSerialHex:  serialHex,
      certIdHashAlgOid: certIdHashAlgOid,
      issuerNameHash:   issuerNameHash,
      issuerKeyHash:    issuerKeyHash,
      certStatus:       certStatus,
      thisUpdate:       thisUpdate,
      nextUpdate:       nextUpdate,
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
  var wantKeyType = (algOid === OID_RSA_SHA256 || algOid === OID_RSA_SHA384 ||
                     algOid === OID_RSA_SHA512) ? "rsa" : "ec";
  if (keyObj.asymmetricKeyType !== wantKeyType) {
    throw new TlsTrustError("tls/ocsp-sig-alg-key-mismatch",
      "OCSP signatureAlgorithm OID '" + algOid + "' declares a " + wantKeyType.toUpperCase() +
      " signature but the issuer key is " + String(keyObj.asymmetricKeyType).toUpperCase() +
      " (RFC 6960 §4.2.1 — the declared algorithm does not match the issuer key)");
  }
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

function _normOcspSerial(s) {
  var h = String(s || "").toLowerCase().replace(/[^0-9a-f]/g, "");
  return h.replace(/^0+/, "") || "0";
}

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
  if (!opts.serialHex) {
    return { ok: false, status: parsed.status, signatureValid: true,
             errors: ["OCSP evaluation requires opts.serialHex (the serial of the certificate being validated) to bind the response"] };
  }
  var wantSerial = _normOcspSerial(opts.serialHex);
  var match = null;
  for (var i = 0; i < parsed.basic.responses.length; i += 1) {
    var r = parsed.basic.responses[i];
    if (_normOcspSerial(r.certIdSerialHex) === wantSerial) { match = r; break; }
  }
  if (!match) {
    return { ok: false, status: parsed.status, signatureValid: true,
             errors: ["OCSP response has no entry for the requested cert serial"] };
  }
  if (opts.issuerCertDer) {
    if (!Buffer.isBuffer(opts.issuerCertDer)) {
      return { ok: false, status: parsed.status, signatureValid: true,
               errors: ["evaluateOcspResponse: opts.issuerCertDer must be a Buffer (issuer cert DER)"] };
    }
    if (!match.issuerNameHash || !match.issuerKeyHash) {
      return { ok: false, status: parsed.status, signatureValid: true,
               errors: ["OCSP CertID is missing issuerNameHash/issuerKeyHash — cannot bind the response to the issuer"] };
    }
    var expected;
    try { expected = _expectedOcspCertIdHashes(opts.issuerCertDer, match.certIdHashAlgOid); }
    catch (e) {
      return { ok: false, status: parsed.status, signatureValid: true,
               errors: [(e && e.message) || String(e)] };
    }
    if (expected.nameHash.length !== match.issuerNameHash.length ||
        !bCrypto.timingSafeEqual(expected.nameHash, match.issuerNameHash)) {
      return { ok: false, status: parsed.status, signatureValid: true,
               errors: ["OCSP CertID issuerNameHash does not match the issuer of the cert under validation (RFC 6960 §4.1.1 — wrong-issuer response)"] };
    }
    if (expected.keyHash.length !== match.issuerKeyHash.length ||
        !bCrypto.timingSafeEqual(expected.keyHash, match.issuerKeyHash)) {
      return { ok: false, status: parsed.status, signatureValid: true,
               errors: ["OCSP CertID issuerKeyHash does not match the issuer of the cert under validation (RFC 6960 §4.1.1 — wrong-issuer response)"] };
    }
  }
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
    if (!bCrypto.timingSafeEqual(parsed.basic.nonce, opts.expectedNonce)) {
      return { ok: false, status: parsed.status, signatureValid: true,
               errors: ["OCSP nonce mismatch — possible replay or wrong responder"] };
    }
    nonceCheck = "matched";
  } else if (parsed.basic.nonce) {
    nonceCheck = "present-not-checked";
  }
  var clockSkewMs = numericBounds.isNonNegativeFiniteInt(opts.clockSkewMs)
    ? opts.clockSkewMs : C.TIME.minutes(5);
  var now = typeof opts.now === "number" ? opts.now : Date.now();
  var thisUpdateMs = typeof match.thisUpdate === "number" ? match.thisUpdate : NaN;
  var nextUpdateMs = typeof match.nextUpdate === "number" ? match.nextUpdate : NaN;
  if (!isFinite(thisUpdateMs)) {
    return { ok: false, status: parsed.status, signatureValid: true,
             certStatus: match.certStatus,
             thisUpdate: match.thisUpdate, nextUpdate: match.nextUpdate,
             nonce: nonceCheck,
             errors: ["OCSP response missing thisUpdate (RFC 6960 §4.2.2.1)"] };
  }
  if (thisUpdateMs - clockSkewMs > now) {
    return { ok: false, status: parsed.status, signatureValid: true,
             certStatus: match.certStatus,
             thisUpdate: match.thisUpdate, nextUpdate: match.nextUpdate,
             nonce: nonceCheck,
             errors: ["OCSP thisUpdate is in the future (RFC 6960 §4.2.2.1 — possible clock skew or response replay)"] };
  }
  if (isFinite(nextUpdateMs) && nextUpdateMs + clockSkewMs < now) {
    return { ok: false, status: parsed.status, signatureValid: true,
             certStatus: match.certStatus,
             thisUpdate: match.thisUpdate, nextUpdate: match.nextUpdate,
             nonce: nonceCheck,
             errors: ["OCSP response is past nextUpdate (RFC 6960 §4.2.2.1 — stale response, possible replay)"] };
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

function _extractIssuerNameDerAndKeyBitString(certDer) {
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
  var idx = 0;
  if (tbsKids.length > 0 &&
      tbsKids[0].tagClass === asn1.TAG_CLASS.CONTEXT_SPECIFIC &&
      tbsKids[0].tag === 0) {
    idx = 1;
  }
  var subjectIdx = idx + 4;
  var spkiIdx = idx + 5;
  if (spkiIdx >= tbsKids.length) {
    throw new TlsTrustError("tls/ocsp-bad-issuer-cert", "issuer cert lacks SPKI field");
  }
  var subject = tbsKids[subjectIdx];
  var spki = tbsKids[spkiIdx];
  var spkiKids = asn1.readSequence(spki.value);
  if (spkiKids.length < 2) {
    throw new TlsTrustError("tls/ocsp-bad-issuer-cert", "SPKI missing subjectPublicKey BIT STRING");
  }
  var keyBytes = asn1.readBitString(spkiKids[1]);
  return {
    issuerNameDer: subject.raw,
    issuerKey:     keyBytes,
  };
}

function _expectedOcspCertIdHashes(issuerCertDer, certIdHashAlgOid) {
  var nodeHash = OCSP_CERTID_HASH_OID_TO_NODE[certIdHashAlgOid];
  if (!nodeHash) {
    throw new TlsTrustError("tls/ocsp-bad-certid-hash-alg",
      "OCSP CertID hashAlgorithm OID '" + certIdHashAlgOid +
      "' is not a recognized hash (RFC 6960 §4.1.1)");
  }
  var iss = _extractIssuerNameDerAndKeyBitString(issuerCertDer);
  var nameHash = nodeCrypto.createHash(nodeHash).update(iss.issuerNameDer).digest();
  var keyHash = nodeCrypto.createHash(nodeHash).update(iss.issuerKey).digest();
  return { nameHash: nameHash, keyHash: keyHash };
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
      tbsKids[0].tag === 0) {
    idx = 1;
  }
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
  var nameHash = nodeCrypto.createHash("sha1").update(iss.issuerNameDer).digest();
  var keyHash  = nodeCrypto.createHash("sha1").update(iss.issuerKey).digest();
  setImmediate(function () {
    try {
      var auditMod = require("./audit");                                            // allow:inline-require — circular-load defense (audit imports network-tls)
      auditMod.safeEmit({
        action:   "network.tls.ocsp.certid_built",
        outcome:  "success",
        metadata: { hashAlgorithm: "sha1", note: "RFC 6960 §4.1.1 — non-security-critical lookup hash" },
      });
    } catch (_e) { /* drop-silent */ }
  });
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
  var includeNonce = opts.nonce !== false;
  if (includeNonce) {
    var nonceLen = typeof opts.nonceLen === "number" ? opts.nonceLen : 16;
    if (nonceLen < 1 || nonceLen > 32) {
      throw new TlsTrustError("tls/ocsp-bad-nonce-len",
        "nonce length out of RFC 8954 range (1..32)");
    }
    nonceBytes = nodeCrypto.randomBytes(nonceLen);
    var nonceExt = asn1.writeSequence([
      asn1.writeOid(OID_OCSP_NONCE),
      asn1.writeOctetString(nonceBytes),
    ]);
    var extensions = asn1.writeSequence([nonceExt]);
    tbsChildren.push(asn1.writeContextExplicit(2, extensions));
  }
  var tbs = asn1.writeSequence(tbsChildren);
  var requestDer = asn1.writeSequence([tbs]);
  return { requestDer: requestDer, nonce: nonceBytes };
}

function _ocspResponderUrl(x509) {
  var ia = x509 && x509.infoAccess;
  if (typeof ia !== "string") return null;
  var m = ia.match(/OCSP\s*-\s*URI:(\S+)/i);
  return m ? m[1].trim() : null;
}

async function fetchOcspResponse(opts) {
  opts = opts || {};
  if (typeof opts.leafPem !== "string" || typeof opts.issuerPem !== "string") {
    throw new TlsTrustError("tls/ocsp-bad-input",
      "ocsp.fetch: opts.leafPem and opts.issuerPem (PEM strings) are required");
  }
  var leafX, issuerX;
  try {
    leafX = new nodeCrypto.X509Certificate(opts.leafPem);
    issuerX = new nodeCrypto.X509Certificate(opts.issuerPem);
  } catch (e) {
    throw new TlsTrustError("tls/ocsp-bad-cert",
      "ocsp.fetch: could not parse leaf/issuer PEM: " + ((e && e.message) || String(e)));
  }
  var responderUrl = opts.responderUrl || _ocspResponderUrl(leafX);
  if (!responderUrl) {
    throw new TlsTrustError("tls/ocsp-no-responder",
      "ocsp.fetch: cert has no AIA OCSP responder URL; pass opts.responderUrl");
  }
  var built = buildOcspRequest({
    leafCertDer: leafX.raw, issuerCertDer: issuerX.raw,
    nonce: opts.nonce, nonceLen: opts.nonceLen,
  });
  var res;
  try {
    res = await httpClient().request({
      url:          responderUrl,
      method:       "POST",
      headers:      { "content-type": "application/ocsp-request", "accept": "application/ocsp-response" },
      body:         built.requestDer,
      responseMode: "buffer",
      timeoutMs:    opts.timeoutMs || C.TIME.seconds(10),
    });
  } catch (e) {
    throw new TlsTrustError("tls/ocsp-fetch-failed",
      "ocsp.fetch: responder request to " + responderUrl + " failed: " + ((e && e.message) || String(e)));
  }
  if (res.status !== C.HTTP.STATUS.OK || !Buffer.isBuffer(res.body) || res.body.length === 0) {
    throw new TlsTrustError("tls/ocsp-fetch-bad-status",
      "ocsp.fetch: responder returned status " + res.status + " with an empty/non-buffer body");
  }
  var evald = evaluateOcspResponse(res.body, {
    issuerPem:     opts.issuerPem,
    issuerCertDer: issuerX.raw,
    serialHex:     opts.serialHex || leafX.serialNumber,
    expectedNonce: opts.nonce === false ? null : built.nonce,
  });
  if (!evald.ok) {
    throw new TlsTrustError("tls/ocsp-not-good",
      "ocsp.fetch: response is not good: " + (evald.errors || []).join("; "));
  }
  return { ocspDer: res.body, evaluation: evald, responderUrl: responderUrl };
}

var ocsp = Object.freeze({
  connect: function (opts) {
    return _connectAndCheckOcsp(opts || {}, false);
  },
  requireStapled: function (opts) {
    return _connectAndCheckOcsp(opts || {}, true);
  },
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
    var rgIssuerCertDer = Buffer.isBuffer(opts.issuerCertDer) ? opts.issuerCertDer : null;
    var evald = evaluateOcspResponse(rv.ocspBytes, {
      issuerPem: opts.issuerPem,
      issuerCertDer: rgIssuerCertDer,
      serialHex: opts.serialHex || (rv.peerCert && rv.peerCert.serialNumber) || null,
    });
    if (!evald.ok) {
      throw new TlsTrustError("tls/ocsp-not-good",
        "OCSP evaluation failed: " + evald.errors.join("; "));
    }
    return Object.assign({}, rv, { ocspEvaluation: evald });
  },
  parseResponse:        parseOcspResponse,
  evaluate:             evaluateOcspResponse,
  fetch:                fetchOcspResponse,
  buildRequest:         buildOcspRequest,
  inspectMustStaple: function (rawDer) {
    if (!Buffer.isBuffer(rawDer)) {
      throw new TlsTrustError("tls/ocsp-bad-input",
        "ocsp.inspectMustStaple: rawDer must be a Buffer (cert.raw)");
    }
    return _extractTlsFeatureExtensionFromCert(rawDer);
  },
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

var OID_CT_SCT_LIST = "1.3.6.1.4.1.11129.2.4.2";

function _extractSctExtensionFromCert(certDer) {
  var top;
  try { top = asn1.readNode(certDer); }
  catch (_e) { return { sctListRaw: null }; }
  if (top.tag !== asn1.TAG.SEQUENCE) return { sctListRaw: null };
  var children;
  try { children = asn1.readSequence(top.value); }
  catch (_e) { return { sctListRaw: null }; }
  if (children.length === 0) return { sctListRaw: null };
  var tbs = children[0];
  if (tbs.tag !== asn1.TAG.SEQUENCE) return { sctListRaw: null };
  var tbsChildren;
  try { tbsChildren = asn1.readSequence(tbs.value); }
  catch (_e) { return { sctListRaw: null }; }
  try {
    var extensionsNode = null;
    for (var i = 0; i < tbsChildren.length; i += 1) {
      var ch = tbsChildren[i];
      if (ch.tagClass === asn1.TAG_CLASS.CONTEXT_SPECIFIC && ch.tag === 3) {
        extensionsNode = asn1.readNode(ch.value, 0);
        break;
      }
    }
    if (!extensionsNode || extensionsNode.tag !== asn1.TAG.SEQUENCE) {
      return { sctListRaw: null };
    }
    var extensions = asn1.readSequence(extensionsNode.value);
    for (var e = 0; e < extensions.length; e += 1) {
      var ext = extensions[e];
      if (ext.tag !== asn1.TAG.SEQUENCE) continue;
      var extChildren = asn1.readSequence(ext.value);
      if (extChildren.length === 0) continue;
      var extOid = asn1.readOid(extChildren[0]);
      if (extOid !== OID_CT_SCT_LIST) continue;
      var extnValueOuter = asn1.readOctetString(extChildren[extChildren.length - 1]);
      var inner = asn1.readNode(extnValueOuter);
      if (inner.tag !== asn1.TAG.OCTET_STRING) return { sctListRaw: null };
      return { sctListRaw: inner.value };
    }
  } catch (_e) {
    return { sctListRaw: null };
  }
  return { sctListRaw: null };
}

var OID_TLS_FEATURE = "1.3.6.1.5.5.7.1.24";
var TLS_FEATURE_STATUS_REQUEST = 5;

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
    if (ch.tagClass === asn1.TAG_CLASS.CONTEXT_SPECIFIC && ch.tag === 3) {
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

function _parseSctList(sctListRaw) {
  if (!Buffer.isBuffer(sctListRaw) || sctListRaw.length < 2) {
    throw new TlsTrustError("tls/ct-bad-list",
      "SCT list shorter than the outer length prefix");
  }
  var totalLen = sctListRaw.readUInt16BE(0);
  if (totalLen + 2 !== sctListRaw.length) {
    throw new TlsTrustError("tls/ct-bad-list",
      "SCT list outer length " + totalLen + " does not match buffer " +
      (sctListRaw.length - 2));
  }
  var pos = 2;
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

function _parseSct(sctBuf) {
  if (sctBuf.length < 1 + 32 + 8 + 2 + 4) {
    throw new TlsTrustError("tls/ct-sct-too-short",
      "SCT is shorter than the minimum v1 layout (" + sctBuf.length + " bytes)");
  }
  var version = sctBuf[0];
  if (version !== 0) {
    throw new TlsTrustError("tls/ct-sct-bad-version",
      "SCT version is not 0 (v1): got " + version);
  }
  var logId = sctBuf.slice(1, 1 + 32);
  var timestamp = Number(sctBuf.readBigUInt64BE(1 + 32));
  var extLen = sctBuf.readUInt16BE(1 + 32 + 8);
  var pos = 1 + 32 + 8 + 2;
  var extensions = sctBuf.slice(pos, pos + extLen);
  pos += extLen;
  if (pos + 4 > sctBuf.length) {
    throw new TlsTrustError("tls/ct-sct-truncated",
      "SCT truncated before DigitallySigned");
  }
  var hashAlgo = sctBuf[pos];
  var sigAlgo  = sctBuf[pos + 1];
  pos += 2;
  var sigLen = sctBuf.readUInt16BE(pos);
  pos += 2;
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
    hashAlgo:   hashAlgo,
    sigAlgo:    sigAlgo,
    signature:  signature,
  };
}

function _ctSignedEntry(tbsOrCertDer, issuerKeyHash) {
  var lenBytes = Buffer.alloc(3);
  lenBytes.writeUIntBE(tbsOrCertDer.length, 0, 3);
  if (Buffer.isBuffer(issuerKeyHash)) {
    if (issuerKeyHash.length !== 32) {
      throw new TlsTrustError("tls/ct-bad-issuer-key-hash",
        "issuer_key_hash must be 32 bytes (SHA-256 of issuer SubjectPublicKeyInfo), got " +
        issuerKeyHash.length);
    }
    return { entryType: 1,
      signedEntry: Buffer.concat([issuerKeyHash, lenBytes, tbsOrCertDer]) };
  }
  return { entryType: 0,
    signedEntry: Buffer.concat([lenBytes, tbsOrCertDer]) };
}

function _resolveIssuerKeyHash(opts) {
  if (Buffer.isBuffer(opts.issuerKeyHash)) return opts.issuerKeyHash;
  if (Buffer.isBuffer(opts.issuerSpkiDer)) {
    return nodeCrypto.createHash("sha256").update(opts.issuerSpkiDer).digest();
  }
  if (Buffer.isBuffer(opts.issuerCertDer)) {
    var spkiDer = new nodeCrypto.X509Certificate(opts.issuerCertDer)
      .publicKey.export({ type: "spki", format: "der" });
    return nodeCrypto.createHash("sha256").update(spkiDer).digest();
  }
  return null;
}

function _buildSctSignedEntry(certWithoutSctDer, sct, issuerKeyHash) {
  var entry = _ctSignedEntry(certWithoutSctDer, issuerKeyHash);
  var head = Buffer.alloc(1 + 1 + 8 + 2);
  head[0] = sct.version;
  head[1] = 0;
  head.writeBigUInt64BE(BigInt(sct.timestamp), 2);
  head.writeUInt16BE(entry.entryType, 10);
  var extHead = Buffer.alloc(2);
  extHead.writeUInt16BE(sct.extensions.length, 0);
  return Buffer.concat([head, entry.signedEntry, extHead, sct.extensions]);
}

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
  var tbsChildren = asn1.readSequence(tbs.value);
  var newTbsChildrenBytes = [];
  var foundExtensions = false;
  for (var i = 0; i < tbsChildren.length; i += 1) {
    var ch = tbsChildren[i];
    if (ch.tagClass === asn1.TAG_CLASS.CONTEXT_SPECIFIC && ch.tag === 3) {
      foundExtensions = true;
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
            if (oid === OID_CT_SCT_LIST) continue;
          } catch (_e) { /* not an OID — keep the extension as-is */ }
        }
        keptExtBytes.push(_encodeAsn1(asn1.TAG.SEQUENCE, true, extBytes));
      }
      var newExtSeq = _encodeAsn1(asn1.TAG.SEQUENCE, true, Buffer.concat(keptExtBytes));
      var newExplicit3 = _encodeContextExplicit(3, newExtSeq);
      newTbsChildrenBytes.push(newExplicit3);
    } else {
      var childDer = _encodeAsn1FromNode(ch);
      newTbsChildrenBytes.push(childDer);
    }
  }
  if (!foundExtensions) {
    throw new TlsTrustError("tls/ct-no-extensions",
      "cert has no extensions to strip from");
  }
  var newTbsValue = Buffer.concat(newTbsChildrenBytes);
  var newTbs = _encodeAsn1(asn1.TAG.SEQUENCE, true, newTbsValue);
  return newTbs;
}

function _encodeLength(len) {
  if (len < 0x80) return Buffer.from([len]);
  var tmp = [];
  var n = len;
  while (n > 0) {
    tmp.unshift(n & 0xff);
    n = n >>> 8;
  }
  return Buffer.concat([Buffer.from([0x80 | tmp.length]), Buffer.from(tmp)]);
}
function _encodeAsn1(tag, constructed, value) {
  var tagByte = (constructed ? 0x20 : 0x00) | tag;
  return Buffer.concat([Buffer.from([tagByte]), _encodeLength(value.length), value]);
}
function _encodeContextExplicit(num, value) {
  var tagByte = 0xa0 | num;
  return Buffer.concat([Buffer.from([tagByte]), _encodeLength(value.length), value]);
}
function _encodeAsn1FromNode(node) {
  var tagByte;
  if (node.tagClass === asn1.TAG_CLASS.UNIVERSAL) {
    tagByte = (node.constructed ? 0x20 : 0x00) | (node.tag & 0x1f);
  } else {
    var classBits = (node.tagClass & 0x03) << 6;
    tagByte = classBits | (node.constructed ? 0x20 : 0x00) | (node.tag & 0x1f);
  }
  return Buffer.concat([Buffer.from([tagByte]), _encodeLength(node.value.length), node.value]);
}

function verifyScts(certDer, opts) {
  opts = opts || {};
  if (!Buffer.isBuffer(certDer)) {
    throw new TlsTrustError("tls/ct-bad-input",
      "verifyScts: certDer must be a Buffer");
  }
  var logKeys = opts.logKeys || {};
  if (opts.minScts !== undefined &&
      (typeof opts.minScts !== "number" || !isFinite(opts.minScts) ||
       opts.minScts < 1 || Math.floor(opts.minScts) !== opts.minScts)) {
    throw new TlsTrustError("tls/ct-bad-input",
      "verifyScts: minScts must be a positive integer (a policy of 0 would accept unverified certs)");
  }
  var minScts = typeof opts.minScts === "number" ? opts.minScts : 2;
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
  var issuerKeyHash;
  try { issuerKeyHash = _resolveIssuerKeyHash(opts); }
  catch (e) {
    return { ok: false, reason: "bad-issuer-key",
             error: (e && e.message) || String(e), scts: scts,
             minScts: minScts, verifiedCount: 0, totalScts: scts.length };
  }
  if (!issuerKeyHash) {
    return { ok: false, reason: "issuer-key-required", scts: [],
             minScts: minScts, verifiedCount: 0, totalScts: scts.length };
  }
  var stripped;
  try { stripped = _stripSctExtensionFromCert(certDer); }
  catch (e) {
    return { ok: false, reason: "strip-failed",
             error: (e && e.message) || String(e), scts: scts };
  }
  var verifiedLogIds = Object.create(null);
  var now = (typeof opts.now === "number" && isFinite(opts.now)) ? opts.now : Date.now();
  var futureSkewMs = (typeof opts.clockSkewMs === "number" && isFinite(opts.clockSkewMs) &&
                      opts.clockSkewMs >= 0) ? opts.clockSkewMs : C.TIME.minutes(5);
  var perSctResults = [];
  for (var s = 0; s < scts.length; s += 1) {
    var sct = scts[s];
    if (sct.timestamp > now + futureSkewMs) {
      perSctResults.push({ logIdHex: sct.logIdHex, verified: false,
        reason: "timestamp-in-future", timestamp: sct.timestamp });
      continue;
    }
    var pem = logKeys[sct.logIdHex];
    if (!pem) {
      perSctResults.push({ logIdHex: sct.logIdHex, verified: false,
        reason: "log-key-missing" });
      continue;
    }
    var signedEntry;
    try { signedEntry = _buildSctSignedEntry(stripped, sct, issuerKeyHash); }
    catch (e) {
      perSctResults.push({ logIdHex: sct.logIdHex, verified: false,
        reason: "build-entry-failed",
        error: (e && e.message) || String(e) });
      continue;
    }
    var nodeAlgo = sct.hashAlgo === 4 ? "sha256" :
                   sct.hashAlgo === 5 ? "sha384" :
                   sct.hashAlgo === 6 ? "sha512" :
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
    var configuredLogId = nodeCrypto.createHash("sha256")
      .update(keyObj.export({ type: "spki", format: "der" })).digest();
    if (!configuredLogId.equals(sct.logId)) {
      perSctResults.push({ logIdHex: sct.logIdHex, verified: false,
        reason: "log-id-key-mismatch",
        configuredKeyId: configuredLogId.toString("hex") });
      continue;
    }
    var keyType = keyObj.asymmetricKeyType;
    var sctSigAlgo = sct.sigAlgo;
    var algoOk = (sctSigAlgo === 1 && keyType === "rsa") ||
                 (sctSigAlgo === 3 && (keyType === "ec" || keyType === "ecdsa"));
    if (!algoOk) {
      perSctResults.push({ logIdHex: sct.logIdHex, verified: false,
        reason: "log-key-algo-mismatch",
        sctSignatureAlgo: sctSigAlgo, logKeyType: keyType });
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
    if (verified) verifiedLogIds[sct.logIdHex] = true;
  }
  var verifiedCount = Object.keys(verifiedLogIds).length;
  return {
    ok:             verifiedCount >= minScts,
    reason:         verifiedCount >= minScts ? null : "insufficient-verified",
    minScts:        minScts,
    verifiedCount:  verifiedCount,
    totalScts:      scts.length,
    scts:           perSctResults,
  };
}

var CT_LEAF_HASH_PREFIX  = 0x00;
var CT_INNER_HASH_PREFIX = 0x01;

function _ctSha256(buf) {
  return nodeCrypto.createHash("sha256").update(buf).digest();
}
function _ctLeafHash(leafBytes) {
  return _ctSha256(Buffer.concat([Buffer.from([CT_LEAF_HASH_PREFIX]), leafBytes]));
}
function _ctInnerHash(left, right) {
  return Buffer.concat([Buffer.from([CT_INNER_HASH_PREFIX]), left, right]);
}
function _ctInnerHashFinal(left, right) {
  return _ctSha256(_ctInnerHash(left, right));
}

function _ctVerifyInclusionPath(leafHash, leafIndex, treeSize, auditPath) {
  if (!Buffer.isBuffer(leafHash) || leafHash.length !== 32) {
    throw new TlsTrustError("tls/ct-bad-leaf-hash",
      "ct.verifyInclusion: leafHash must be a 32-byte Buffer");
  }
  if (typeof leafIndex !== "number" || leafIndex < 0 || leafIndex >= treeSize ||
      Math.floor(leafIndex) !== leafIndex) {
    throw new TlsTrustError("tls/ct-bad-index",
      "ct.verifyInclusion: leafIndex must be an integer 0..treeSize-1");
  }
  if (typeof treeSize !== "number" || treeSize < 1 || Math.floor(treeSize) !== treeSize) {
    throw new TlsTrustError("tls/ct-bad-tree-size",
      "ct.verifyInclusion: treeSize must be a positive integer");
  }
  if (!Array.isArray(auditPath)) {
    throw new TlsTrustError("tls/ct-bad-audit-path",
      "ct.verifyInclusion: auditPath must be an array of 32-byte Buffers");
  }

  var fn = leafIndex;
  var sn = treeSize - 1;
  var r = leafHash;
  var pathPos = 0;
  while (sn > 0) {
    if (pathPos >= auditPath.length) {
      throw new TlsTrustError("tls/ct-audit-path-short",
        "ct.verifyInclusion: audit path exhausted before tree root reached");
    }
    var sibling = auditPath[pathPos++];
    if (!Buffer.isBuffer(sibling) || sibling.length !== 32) {
      throw new TlsTrustError("tls/ct-bad-audit-path",
        "ct.verifyInclusion: audit path entry " + (pathPos - 1) + " is not a 32-byte Buffer");
    }
    if ((fn & 1) === 1 || fn === sn) {
      r = _ctInnerHashFinal(sibling, r);
      while ((fn & 1) === 0 && fn !== 0) { fn >>>= 1; sn >>>= 1; }
    } else {
      r = _ctInnerHashFinal(r, sibling);
    }
    fn >>>= 1;
    sn >>>= 1;
  }
  if (pathPos !== auditPath.length) {
    throw new TlsTrustError("tls/ct-audit-path-long",
      "ct.verifyInclusion: audit path has " + (auditPath.length - pathPos) +
      " trailing entries beyond the root");
  }
  return r;
}

function _ctVerifyConsistencyPath(m, n, consistencyProof, firstHash) {
  if (typeof m !== "number" || !isFinite(m) || m < 1 || Math.floor(m) !== m) {
    throw new TlsTrustError("tls/ct-bad-first-size",
      "ct.verifyConsistency: m (first tree size) must be a finite positive integer");
  }
  if (typeof n !== "number" || !isFinite(n) || n < m || Math.floor(n) !== n) {
    throw new TlsTrustError("tls/ct-bad-second-size",
      "ct.verifyConsistency: n (second tree size) must be a finite integer >= m");
  }
  if (!Buffer.isBuffer(firstHash) || firstHash.length !== 32) {
    throw new TlsTrustError("tls/ct-bad-first-hash",
      "ct.verifyConsistency: firstHash must be a 32-byte Buffer");
  }
  if (!Array.isArray(consistencyProof)) {
    throw new TlsTrustError("tls/ct-bad-consistency-proof",
      "ct.verifyConsistency: consistencyProof must be an array of Buffers");
  }
  if (m === n) {
    if (consistencyProof.length !== 0) {
      throw new TlsTrustError("tls/ct-consistency-not-empty",
        "ct.verifyConsistency: the proof for two equal tree sizes must be empty " +
        "(RFC 9162 §2.1.4), got " + consistencyProof.length + " entries");
    }
    return firstHash;
  }
  var path = consistencyProof.slice();
  var firstNode, secondNode;
  var fn = m - 1;
  var sn = n - 1;
  while ((fn & 1) === 1) { fn >>>= 1; sn >>>= 1; }

  if (fn === 0) {
    firstNode = firstHash;
  } else {
    if (path.length === 0) {
      throw new TlsTrustError("tls/ct-consistency-empty",
        "ct.verifyConsistency: consistency proof empty but first tree is not a complete subtree");
    }
    firstNode = path.shift();
  }
  secondNode = firstNode;
  while (sn > 0) {
    if (path.length === 0) {
      throw new TlsTrustError("tls/ct-consistency-short",
        "ct.verifyConsistency: consistency proof exhausted before second-tree root");
    }
    var sibling = path.shift();
    if (!Buffer.isBuffer(sibling) || sibling.length !== 32) {
      throw new TlsTrustError("tls/ct-bad-consistency-entry",
        "ct.verifyConsistency: consistency-proof entry is not a 32-byte Buffer");
    }
    if ((fn & 1) === 1 || fn === sn) {
      firstNode  = _ctInnerHashFinal(sibling, firstNode);
      secondNode = _ctInnerHashFinal(sibling, secondNode);
      while ((fn & 1) === 0 && fn !== 0) { fn >>>= 1; sn >>>= 1; }
    } else {
      secondNode = _ctInnerHashFinal(secondNode, sibling);
    }
    fn >>>= 1;
    sn >>>= 1;
  }
  if (firstNode.length !== firstHash.length ||
      !bCrypto.timingSafeEqual(firstNode, firstHash)) {
    throw new TlsTrustError("tls/ct-first-root-mismatch",
      "ct.verifyConsistency: the proof rebuilds a first-tree root that is not the one supplied " +
      "(RFC 9162 §2.1.4.2 — the proof does not connect the pinned tree to the new one)");
  }
  if (path.length !== 0) {
    throw new TlsTrustError("tls/ct-consistency-long",
      "ct.verifyConsistency: consistency proof has " + path.length +
      " trailing entries beyond the second-tree root");
  }
  return secondNode;
}

function _findSctOid(rawDer) {
  var oidBytes = Buffer.from([
    0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0xd6, 0x79, 0x02, 0x04, 0x02,
  ]);
  return rawDer.indexOf(oidBytes) !== -1;
}

var ct = Object.freeze({
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
  parseScts: function (rawDer) {
    if (!Buffer.isBuffer(rawDer)) {
      throw new TlsTrustError("tls/ct-bad-input",
        "ct.parseScts: rawDer must be a Buffer");
    }
    var ext = _extractSctExtensionFromCert(rawDer);
    if (!ext.sctListRaw) return [];
    return _parseSctList(ext.sctListRaw);
  },
  verifyScts: verifyScts,
  verifyInclusion: function (opts) {
    if (!opts || typeof opts !== "object") {
      return { valid: false, reason: "missing-opts" };
    }
    if (!opts.sct || typeof opts.sct !== "object") {
      return { valid: false, reason: "missing-sct" };
    }
    if (!Buffer.isBuffer(opts.leafCertificate)) {
      return { valid: false, reason: "missing-leaf-certificate" };
    }
    if (!opts.sthFromLog || typeof opts.sthFromLog !== "object") {
      return { valid: false, reason: "missing-sth" };
    }
    if (typeof opts.leafIndex !== "number" || !isFinite(opts.leafIndex) ||
        opts.leafIndex < 0 || Math.floor(opts.leafIndex) !== opts.leafIndex) {
      return { valid: false, reason: "bad-leaf-index" };
    }
    if (!Array.isArray(opts.auditPath)) {
      return { valid: false, reason: "bad-audit-path" };
    }

    var issuerKeyHash;
    try { issuerKeyHash = _resolveIssuerKeyHash(opts); }
    catch (e) {
      return { valid: false, reason: "bad-issuer-key",
               error: (e && e.message) || String(e) };
    }
    var signedEntryDer = opts.sct.signedEntryDer;
    if (!Buffer.isBuffer(signedEntryDer)) {
      try { signedEntryDer = _stripSctExtensionFromCert(opts.leafCertificate); }
      catch (e) {
        return { valid: false, reason: "strip-failed",
                 error: (e && e.message) || String(e) };
      }
    }

    var ts = opts.sct.timestamp;
    if (typeof ts !== "number" && typeof ts !== "bigint") {
      return { valid: false, reason: "bad-sct-timestamp" };
    }
    var tsBuf = Buffer.alloc(8);
    var tsBig = typeof ts === "bigint" ? ts : BigInt(Math.floor(ts));
    tsBuf.writeBigUInt64BE(tsBig);
    var leafEntry;
    try { leafEntry = _ctSignedEntry(signedEntryDer, issuerKeyHash); }
    catch (e) {
      return { valid: false, reason: "bad-issuer-key",
               error: (e && e.message) || String(e) };
    }
    var entryTypeBuf = Buffer.from([(leafEntry.entryType >> 8) & 0xff,
                                    leafEntry.entryType & 0xff]);
    var extensionsBuf = Buffer.from([0x00, 0x00]);
    var leafBytes = Buffer.concat([
      Buffer.from([0x00]),
      Buffer.from([0x00]),
      tsBuf,
      entryTypeBuf,
      leafEntry.signedEntry,
      extensionsBuf,
    ]);

    var leafHash = _ctLeafHash(leafBytes);
    var computedRoot;
    try {
      computedRoot = _ctVerifyInclusionPath(leafHash, opts.leafIndex,
        opts.sthFromLog.treeSize, opts.auditPath);
    } catch (e) {
      return { valid: false, reason: "inclusion-walk-failed",
               error: (e && e.message) || String(e) };
    }

    var sthRoot = opts.sthFromLog.rootHash || opts.sthFromLog.sha256RootHash;
    if (typeof sthRoot === "string") {
      try { sthRoot = Buffer.from(sthRoot, "hex"); }
      catch (_e) { return { valid: false, reason: "bad-sth-root-encoding" }; }
    }
    if (!Buffer.isBuffer(sthRoot) || sthRoot.length !== 32) {
      return { valid: false, reason: "bad-sth-root" };
    }
    if (!bCrypto.timingSafeEqual(computedRoot, sthRoot)) {
      return { valid: false, reason: "root-mismatch",
               computedRoot: computedRoot.toString("hex") };
    }

    var consistencyResult = null;
    if (opts.consistency && typeof opts.consistency === "object") {
      var firstRoot = opts.consistency.firstRoot;
      if (typeof firstRoot === "string") {
        try { firstRoot = Buffer.from(firstRoot, "hex"); }
        catch (_e) {
          return { valid: false, reason: "bad-consistency-first-root-encoding" };
        }
      }
      try {
        var computedSecond = _ctVerifyConsistencyPath(
          opts.consistency.firstSize, opts.sthFromLog.treeSize,
          opts.consistency.proof || [], firstRoot);
        var ok = bCrypto.timingSafeEqual(computedSecond, sthRoot);
        consistencyResult = {
          ok: ok,
          computedSecondRoot: computedSecond.toString("hex"),
        };
        if (!ok) {
          return { valid: false, reason: "consistency-mismatch",
                   computedRoot: computedRoot.toString("hex"),
                   consistency: consistencyResult };
        }
      } catch (e) {
        if (e && e.code === "tls/ct-first-root-mismatch") {
          return { valid: false, reason: "first-root-mismatch",
                   error: e.message || String(e) };
        }
        return { valid: false, reason: "consistency-walk-failed",
                 error: (e && e.message) || String(e) };
      }
    }

    return {
      valid:        true,
      computedRoot: computedRoot.toString("hex"),
      leafHash:     leafHash.toString("hex"),
      consistency:  consistencyResult,
    };
  },
  verifyConsistency: function (opts) {
    if (!opts || typeof opts !== "object") {
      return { valid: false, reason: "missing-opts" };
    }
    var firstRoot = opts.firstRoot;
    if (typeof firstRoot === "string") {
      try { firstRoot = Buffer.from(firstRoot, "hex"); }
      catch (_e) { return { valid: false, reason: "bad-first-root-encoding" }; }
    }
    var secondRoot = opts.secondRoot;
    if (typeof secondRoot === "string") {
      try { secondRoot = Buffer.from(secondRoot, "hex"); }
      catch (_e) { return { valid: false, reason: "bad-second-root-encoding" }; }
    }
    if (!Buffer.isBuffer(firstRoot) || firstRoot.length !== 32) {
      return { valid: false, reason: "bad-first-root" };
    }
    if (!Buffer.isBuffer(secondRoot) || secondRoot.length !== 32) {
      return { valid: false, reason: "bad-second-root" };
    }
    var computed;
    try {
      computed = _ctVerifyConsistencyPath(opts.firstSize, opts.secondSize,
        opts.proof || [], firstRoot);
    } catch (e) {
      if (e && e.code === "tls/ct-first-root-mismatch") {
        return { valid: false, reason: "first-root-mismatch",
                 error: e.message || String(e) };
      }
      return { valid: false, reason: "consistency-walk-failed",
               error: (e && e.message) || String(e) };
    }
    if (!bCrypto.timingSafeEqual(computed, secondRoot)) {
      return { valid: false, reason: "root-mismatch",
               computedRoot: computed.toString("hex") };
    }
    return { valid: true, computedRoot: computed.toString("hex") };
  },
  requireScts: function (opts) {
    opts = opts || {};
    return function (peerCert) {
      if (!peerCert || !peerCert.raw) {
        return new TlsTrustError("tls/ct-no-cert",
          "requireScts: peer cert.raw missing");
      }
      var effOpts = opts;
      if (!Buffer.isBuffer(opts.issuerKeyHash) &&
          !Buffer.isBuffer(opts.issuerSpkiDer) &&
          !Buffer.isBuffer(opts.issuerCertDer) &&
          peerCert.issuerCertificate &&
          peerCert.issuerCertificate !== peerCert &&
          Buffer.isBuffer(peerCert.issuerCertificate.raw)) {
        effOpts = Object.assign({}, opts,
          { issuerCertDer: peerCert.issuerCertificate.raw });
      }
      var rv = verifyScts(peerCert.raw, effOpts);
      if (!rv.ok) {
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

var ECH_CONFIG_VERSION_DRAFT_22 = 0xfe0d;

function _echReadU8(buf, off) {
  if (off + 1 > buf.length) {
    throw new NetworkTlsError("tls/ech-config-malformed",
      "ECHConfigList: truncated reading uint8 at offset " + off);
  }
  return buf[off];
}
function _echReadU16(buf, off) {
  if (off + 2 > buf.length) {
    throw new NetworkTlsError("tls/ech-config-malformed",
      "ECHConfigList: truncated reading uint16 at offset " + off);
  }
  return buf.readUInt16BE(off);
}
function _echReadVarOpaqueU16(buf, off) {
  var len = _echReadU16(buf, off);
  off += 2;
  if (off + len > buf.length) {
    throw new NetworkTlsError("tls/ech-config-malformed",
      "ECHConfigList: opaque vector overflows buffer (declared " + len +
      " bytes at offset " + (off - 2) + ", " + (buf.length - off) + " available)");
  }
  return { value: buf.slice(off, off + len), nextOff: off + len };
}
function _echReadVarOpaqueU8(buf, off) {
  var len = _echReadU8(buf, off);
  off += 1;
  if (off + len > buf.length) {
    throw new NetworkTlsError("tls/ech-config-malformed",
      "ECHConfigList: u8-prefixed opaque overflows buffer");
  }
  return { value: buf.slice(off, off + len), nextOff: off + len };
}

/**
 * @primitive b.network.tls.parseEchConfigList
 * @signature b.network.tls.parseEchConfigList(raw)
 * @since     0.8.53
 * @status    stable
 * @related   b.network.tls.connectWithEch, b.network.dns.queryHttps
 *
 * Parse a draft-ietf-tls-esni-22 ECHConfigList byte string (the value
 * of the `ech=` SvcParam in an SVCB or HTTPS DNS record per RFC 9460
 * paragraph 7.4.2). Accepts a `Buffer` or a strict-base64 string. Returns
 * `{ rawLength, configs: [{ version, length, keyConfig, ... }] }`.
 *
 * For each ECHConfig at the published draft-22 version (`0xfe0d`) the
 * decoded `keyConfig` carries `configId`, `kemId`, `publicKey`
 * (Buffer), and `cipherSuites` (each `{ kdfId, aeadId }`); the entry
 * also exposes `maximumNameLength`, `publicName`, and `extensions`.
 * Unknown future ECH versions surface their raw `body` Buffer so the
 * caller can forward them to a Node build that supports them.
 *
 * Throws `NetworkTlsError("tls/ech-config-malformed")` on any framing
 * violation (truncated length prefix, vector overflow, bad
 * cipher_suites stride, etc.).
 *
 * @example
 *   var b = require("@blamejs/core");
 *   var rrs = await b.network.dns.queryHttps("example.com");
 *   // `ech` is optional in an HTTPS record, and a domain can drop or rotate it
 *   // at any time — handle its absence rather than indexing into the match.
 *   var rec = rrs.find(function (r) { return r.params && r.params.ech; });
 *   if (rec) {
 *     var parsed = b.network.tls.parseEchConfigList(rec.params.ech);
 *     // parsed.configs[0].keyConfig.kemId === 0x0020 (X25519)
 *   }
 */
function parseEchConfigList(raw) {
  if (typeof raw === "string") {
    var stripped = raw.replace(/\s+/g, "");
    var decoded = Buffer.from(stripped, "base64");
    if (decoded.length === 0 || decoded.toString("base64") !== stripped) {
      throw new NetworkTlsError("tls/ech-config-malformed",
        "parseEchConfigList: input string is not strict base64");
    }
    raw = decoded;
  }
  if (!Buffer.isBuffer(raw) || raw.length === 0) {
    throw new NetworkTlsError("tls/ech-config-malformed",
      "parseEchConfigList: input must be a non-empty Buffer or base64 string");
  }
  if (raw.length < 2) {
    throw new NetworkTlsError("tls/ech-config-malformed",
      "ECHConfigList: too short for outer length prefix");
  }
  var totalLen = raw.readUInt16BE(0);
  if (2 + totalLen !== raw.length) {
    throw new NetworkTlsError("tls/ech-config-malformed",
      "ECHConfigList: outer length " + totalLen + " does not match buffer " +
      "tail length " + (raw.length - 2));
  }
  var off = 2;
  var configs = [];
  while (off < raw.length) {
    if (off + 4 > raw.length) {
      throw new NetworkTlsError("tls/ech-config-malformed",
        "ECHConfig: truncated header at offset " + off);
    }
    var version = raw.readUInt16BE(off);
    var length  = raw.readUInt16BE(off + 2);
    var bodyOff = off + 4;
    var bodyEnd = bodyOff + length;
    if (bodyEnd > raw.length) {
      throw new NetworkTlsError("tls/ech-config-malformed",
        "ECHConfig: declared length " + length + " overflows ECHConfigList");
    }
    var entry = { version: version, length: length };
    if (version === ECH_CONFIG_VERSION_DRAFT_22) {
      var p = bodyOff;
      var configId = _echReadU8(raw, p); p += 1;
      var kemId    = _echReadU16(raw, p); p += 2;
      var pkOpaque = _echReadVarOpaqueU16(raw, p); p = pkOpaque.nextOff;
      var suitesLen = _echReadU16(raw, p); p += 2;
      if (p + suitesLen > bodyEnd) {
        throw new NetworkTlsError("tls/ech-config-malformed",
          "ECHConfig: cipher_suites vector overflows config body");
      }
      if (suitesLen % 4 !== 0 || suitesLen < 4) {
        throw new NetworkTlsError("tls/ech-config-malformed",
          "ECHConfig: cipher_suites length must be a positive multiple of 4");
      }
      var suites = [];
      for (var sp = p; sp < p + suitesLen; sp += 4) {
        suites.push({
          kdfId:  raw.readUInt16BE(sp),
          aeadId: raw.readUInt16BE(sp + 2),
        });
      }
      p += suitesLen;
      var maxNameLen = _echReadU8(raw, p); p += 1;
      var publicName = _echReadVarOpaqueU8(raw, p); p = publicName.nextOff;
      var extLen = _echReadU16(raw, p); p += 2;
      if (p + extLen !== bodyEnd) {
        throw new NetworkTlsError("tls/ech-config-malformed",
          "ECHConfig: extensions vector does not consume remaining body " +
          "(extLen=" + extLen + ", remaining=" + (bodyEnd - p) + ")");
      }
      var extensions = [];
      var extEnd = p + extLen;
      while (p < extEnd) {
        var extType = _echReadU16(raw, p); p += 2;
        var extData = _echReadVarOpaqueU16(raw, p); p = extData.nextOff;
        extensions.push({ type: extType, data: extData.value });
      }
      entry.keyConfig = {
        configId:     configId,
        kemId:        kemId,
        publicKey:    pkOpaque.value,
        cipherSuites: suites,
      };
      entry.maximumNameLength = maxNameLen;
      entry.publicName        = publicName.value.toString("ascii");
      entry.extensions        = extensions;
    } else {
      entry.body = Buffer.from(raw.slice(bodyOff, bodyEnd));
    }
    configs.push(entry);
    off = bodyEnd;
  }
  return { rawLength: raw.length, configs: configs };
}

var _echFeatureProbe = null;
function _isEchSupported() {
  if (_echFeatureProbe !== null) return _echFeatureProbe;
  var supported = false;
  try {
    // allow:outbound-tls-posture — a feature probe whose lookup aborts, so it negotiates nothing and there is no posture to apply
    var probe = nodeTls.connect({
      host:    "127.0.0.1",
      port:    1,
      ech:     Buffer.alloc(0),
      lookup:  function (_h, _o, cb) { cb(new Error("probe-abort")); },
    });
    supported = true;
    try { probe.destroy(); } catch (_e) { /* probe socket */ }
  } catch (e) {
    var msg = (e && (e.code || e.message)) || "";
    if (/ech/i.test(msg) || /unknown option/i.test(msg)) supported = false;
    else supported = true;
  }
  _echFeatureProbe = supported;
  return supported;
}

/**
 * @primitive b.network.tls.connectWithEch
 * @signature b.network.tls.connectWithEch(opts)
 * @since     0.8.53
 * @status    stable
 * @related   b.network.tls.parseEchConfigList, b.network.dns.queryHttps,
 *            b.network.tls.checkServerIdentity9525
 *
 * Open a TLS-1.3 outbound connection with Encrypted Client Hello (ECH,
 * draft-ietf-tls-esni-22) when the destination publishes an `ech=`
 * SvcParam via SVCB/HTTPS records (RFC 9460 paragraph 2.4 / paragraph 9). The flow:
 *
 *   1. `b.network.dns.queryHttps(host)` to discover ECH config.
 *   2. If any record carries `ech=`, the parsed ECHConfigList is
 *      attached to `tls.connect({ ech })` so the outer ClientHello
 *      uses the published `public_name` SNI and the inner ClientHello
 *      (real SNI, ALPN, etc.) is HPKE-encrypted under the published
 *      public key.
 *   3. If no record carries `ech=`, or DNS fails, the function falls
 *      back to a normal TLS connect (still TLSv1.3-floor + framework
 *      PQC group preference). Operators get an `observability.event`
 *      so the degradation is visible.
 *   4. If the running Node build does not support the `ech` connect
 *      option, the function emits a one-shot warn and connects
 *      without ECH — never throws on missing Node-side support.
 *
 * Returns the connected `tls.TLSSocket` once `secureConnect` fires.
 * `b.httpClient` will compose this in a follow-up release; this
 * primitive is the operator escape hatch for raw outbound TLS over
 * ECH (custom protocol clients, mTLS testing, ECH validation tools).
 *
 * @opts
 *   {
 *     host:        string,
 *     port:        number,
 *     alpn:        string[],
 *     ipFamily:    4 | 6,
 *     timeoutMs:   number,
 *     servername:  string,
 *     ca:          string|Buffer|Array,
 *     checkServerIdentity: function,
 *     echOverride: Buffer|string,
 *     rejectUnauthorized: boolean,
 *   }
 *
 * @example
 *   // requires: outbound DNS for the ECH config, and a reachable peer
 *   var b = require("@blamejs/core");
 *   var sock = await b.network.tls.connectWithEch({
 *     host: "ech-target.example.com",
 *     alpn: ["h2", "http/1.1"],
 *   });
 *   sock.write("GET / HTTP/1.1\r\nHost: ech-target.example.com\r\n\r\n");
 */
function connectWithEch(opts) {
  opts = opts || {};
  if (typeof opts !== "object" || Array.isArray(opts)) {
    throw new NetworkTlsError("tls/ech-bad-opts",
      "connectWithEch: opts must be a plain object");
  }
  validateOpts(opts,
    ["host", "port", "alpn", "ipFamily", "timeoutMs", "servername", "ca",
     "checkServerIdentity", "echOverride", "rejectUnauthorized"],
    "network.tls.connectWithEch");
  validateOpts.requireNonEmptyString(opts.host, "connectWithEch: host",
    NetworkTlsError, "tls/ech-bad-opts");
  var port = opts.port === undefined ? 443 : opts.port;
  numericBounds.requirePositiveFiniteInt(port,
    "connectWithEch: port", NetworkTlsError, "tls/ech-bad-opts", { max: 65535 });
  if (opts.alpn !== undefined && !Array.isArray(opts.alpn)) {
    throw new NetworkTlsError("tls/ech-bad-opts",
      "connectWithEch: alpn must be an array of strings");
  }
  if (opts.ipFamily !== undefined && opts.ipFamily !== 4 && opts.ipFamily !== 6) {
    throw new NetworkTlsError("tls/ech-bad-opts",
      "connectWithEch: ipFamily must be 4 | 6 | undefined");
  }
  var timeoutMs = opts.timeoutMs === undefined
    ? C.TIME.seconds(30) : opts.timeoutMs;
  if (typeof timeoutMs !== "number" || !isFinite(timeoutMs) || timeoutMs < 0) {
    throw new NetworkTlsError("tls/ech-bad-opts",
      "connectWithEch: timeoutMs must be a non-negative finite number");
  }
  if (opts.echOverride !== undefined &&
      !Buffer.isBuffer(opts.echOverride) &&
      typeof opts.echOverride !== "string") {
    throw new NetworkTlsError("tls/ech-bad-opts",
      "connectWithEch: echOverride must be a Buffer or base64 string");
  }

  return new Promise(function (resolve, reject) {
    function _doConnect(echConfigBuf, sourceLabel) {
      var nodeSupportsEch = _isEchSupported();
      var connectOpts = Object.assign({
        host:       opts.host,
        port:       port,
        servername: opts.servername || opts.host,
      }, outboundPosture());
      if (Array.isArray(opts.alpn)) connectOpts.ALPNProtocols = opts.alpn.slice();
      if (opts.ipFamily !== undefined) connectOpts.family = opts.ipFamily;
      if (opts.ca !== undefined) connectOpts.ca = _normalizeCaInput(opts.ca);
      if (typeof opts.checkServerIdentity === "function") {
        connectOpts.checkServerIdentity = opts.checkServerIdentity;
      }
      var rejectUnauthorized = opts.rejectUnauthorized !== false;
      connectOpts.rejectUnauthorized = rejectUnauthorized;
      if (!rejectUnauthorized) {
        auditInsecureTls({ host: opts.host, port: port, source: "network.tls.connectWithEch" });
      }
      var echAttached = false;
      if (echConfigBuf && nodeSupportsEch) {
        connectOpts.ech = echConfigBuf;
        echAttached = true;
      } else if (echConfigBuf && !nodeSupportsEch) {
        try {
          observability().safeEvent("network.tls.ech.unsupported", 1, {
            host: opts.host, source: sourceLabel,
          });
        } catch (_e) { /* drop-silent */ }
        try {
          audit().safeEmit({
            action:  "network.tls.ech.unsupported",
            outcome: "success",
            metadata: { host: opts.host, source: sourceLabel },
          });
        } catch (_e) { /* drop-silent */ }
      }

      var sock;
      try { sock = nodeTls.connect(connectOpts); }
      catch (e) {
        reject(new NetworkTlsError("tls/ech-connect-failed",
          "connectWithEch: tls.connect threw: " + ((e && e.message) || String(e))));
        return;
      }
      var settled = false;
      var to = null;
      if (timeoutMs > 0) {
        to = setTimeout(function () {
          if (settled) return;
          settled = true;
          try { sock.destroy(); } catch (_e) { /* destroy best-effort */ }
          reject(new NetworkTlsError("tls/ech-timeout",
            "connectWithEch: handshake timed out after " + timeoutMs + "ms"));
        }, timeoutMs);
        if (typeof to.unref === "function") to.unref();
      }
      sock.once("secureConnect", function () {
        if (settled) return;
        settled = true;
        if (to) clearTimeout(to);
        try {
          observability().safeEvent("network.tls.ech.connected", 1, {
            host: opts.host, echAttached: echAttached, source: sourceLabel,
          });
        } catch (_e) { /* drop-silent */ }
        resolve(sock);
      });
      sock.once("error", function (e) {
        if (settled) return;
        settled = true;
        if (to) clearTimeout(to);
        reject(e);
      });
    }

    if (Buffer.isBuffer(opts.echOverride) || typeof opts.echOverride === "string") {
      var override;
      try {
        var bufOverride = Buffer.isBuffer(opts.echOverride)
          ? opts.echOverride
          : Buffer.from(opts.echOverride, "base64");
        parseEchConfigList(bufOverride);
        override = bufOverride;
      } catch (e) {
        reject(e);
        return;
      }
      _doConnect(override, "override");
      return;
    }

    var dnsMod;
    try { dnsMod = networkDns(); }
    catch (e) {
      reject(new NetworkTlsError("tls/ech-dns-unavailable",
        "connectWithEch: network-dns module unavailable: " +
        ((e && e.message) || String(e))));
      return;
    }
    dnsMod.queryHttps(opts.host).then(function (records) {
      var echBuf = null;
      for (var i = 0; i < records.length; i += 1) {
        var rec = records[i];
        if (rec && rec.params && Buffer.isBuffer(rec.params.ech) &&
            rec.params.ech.length > 0) {
          echBuf = rec.params.ech;
          break;
        }
      }
      _doConnect(echBuf, echBuf ? "svcb" : "no-ech-record");
    }).catch(function (e) {
      try {
        observability().safeEvent("network.tls.ech.dns_failed", 1, {
          host: opts.host, error: (e && e.message) || String(e),
        });
      } catch (_e) { /* drop-silent */ }
      _doConnect(null, "dns-failed");
    });
  });
}

function _normalizeAsciiHost(host) {
  if (typeof host !== "string" || host.length === 0) return null;
  for (var i = 0; i < host.length; i += 1) {
    var cc = host.charCodeAt(i);
    if (cc > 0x7f) return null;
  }
  var h = host.toLowerCase();
  if (h.length > 1 && h.charAt(h.length - 1) === ".") h = h.slice(0, -1);
  return h;
}

function _matchDnsNamePattern(pattern, host) {
  pattern = _normalizeAsciiHost(pattern);
  if (!pattern || !host) return false;
  if (pattern.indexOf("*") === -1) {
    return pattern === host;
  }
  var pLabels = pattern.split(".");
  var hLabels = host.split(".");
  if (pLabels.length !== hLabels.length) return false;
  if (pLabels.length < 3) return false;
  if (pLabels[0] !== "*") return false;
  for (var li = 1; li < pLabels.length; li += 1) {
    if (pLabels[li].indexOf("*") !== -1) return false;
    if (pLabels[li] !== hLabels[li]) return false;
  }
  if (hLabels[0].length === 0) return false;
  return true;
}

var _SAN_QUOTED_RE = /^"(?:[^"\\]|\\.)*"/;
function _splitEscapedAltNames(altNames) {
  var result = [];
  var current = "";
  var offset = 0;
  while (offset !== altNames.length) {
    var nextSep = altNames.indexOf(",", offset);
    var nextQuote = altNames.indexOf('"', offset);
    if (nextQuote !== -1 && (nextSep === -1 || nextQuote < nextSep)) {
      current += altNames.substring(offset, nextQuote);
      var match = _SAN_QUOTED_RE.exec(altNames.substring(nextQuote));
      if (!match) {
        throw new TlsTrustError("tls/altname-format",
          "malformed quoted subjectAltName entry");
      }
      current += safeJson.parse(match[0]);
      offset = nextQuote + match[0].length;
    } else if (nextSep !== -1) {
      current += altNames.substring(offset, nextSep);
      result.push(current);
      current = "";
      offset = nextSep + 1;
      if (altNames.charAt(offset) === " ") offset += 1;
    } else {
      current += altNames.substring(offset);
      offset = altNames.length;
    }
  }
  result.push(current);
  return result;
}

function _parseSanString(rawSubjectAltName) {
  var dns = [];
  var ips = [];
  if (typeof rawSubjectAltName !== "string" || rawSubjectAltName.length === 0) {
    return { dns: dns, ips: ips };
  }
  var entries;
  try {
    entries = _splitEscapedAltNames(rawSubjectAltName);
  } catch (_e) {
    return { dns: dns, ips: ips };
  }
  for (var i = 0; i < entries.length; i += 1) {
    var entry = entries[i];
    var colon = entry.indexOf(":");
    if (colon === -1) continue;
    var kind = entry.slice(0, colon);
    var val  = entry.slice(colon + 1);
    if (kind === "DNS") {
      dns.push(val);
    } else if (kind === "IP Address" || kind === "IP") {
      ips.push(val);
    }
  }
  return { dns: dns, ips: ips };
}

function _normalizeIpForCompare(ip) {
  if (typeof ip !== "string") return null;
  var s = ip;
  if (s.length >= 2 && s.charAt(0) === "[" && s.charAt(s.length - 1) === "]") {
    s = s.slice(1, -1);
  }
  if (net.isIPv4(s)) return { family: 4, text: s };
  if (net.isIPv6(s)) {
    var parts = s.split("%");
    var addr = parts[0];
    var bytes = _ipv6ToBytes(addr);
    if (!bytes) return null;
    return { family: 6, text: addr.toLowerCase(), bytes: bytes };
  }
  return null;
}
function _ipv6ToBytes(addr) {
  if (typeof addr !== "string") return null;
  var halves;
  var doubleIdx = addr.indexOf("::");
  if (doubleIdx === -1) {
    halves = [addr.split(":"), []];
  } else {
    var leftStr  = addr.slice(0, doubleIdx);
    var rightStr = addr.slice(doubleIdx + 2);
    halves = [
      leftStr.length  ? leftStr.split(":")  : [],
      rightStr.length ? rightStr.split(":") : [],
    ];
  }
  var left = halves[0], right = halves[1];
  var fillCount = 8 - (left.length + right.length);
  if (fillCount < 0) return null;
  var hextets = left.concat(new Array(fillCount).fill("0")).concat(right);
  if (hextets.length !== 8) return null;
  var bytes = Buffer.alloc(16);
  for (var i = 0; i < 8; i += 1) {
    var h = hextets[i];
    if (!safeBuffer.isIpv6Hextet(h)) return null;
    var v = parseInt(h, 16);
    bytes[i * 2]     = (v >> 8) & 0xff;
    bytes[i * 2 + 1] = v & 0xff;
  }
  return bytes;
}
function _ipsEqual(sanIp, hostIp) {
  var a = _normalizeIpForCompare(sanIp);
  var b = _normalizeIpForCompare(hostIp);
  if (!a || !b) return false;
  if (a.family !== b.family) return false;
  if (a.family === 4) return a.text === b.text;
  if (!a.bytes || !b.bytes) return false;
  if (a.bytes.length !== b.bytes.length) return false;
  for (var i = 0; i < a.bytes.length; i += 1) {
    if (a.bytes[i] !== b.bytes[i]) return false;
  }
  return true;
}

/**
 * @primitive b.network.tls.checkServerIdentity9525
 * @signature b.network.tls.checkServerIdentity9525(host, cert)
 * @since     0.8.53
 * @status    stable
 * @related   b.network.tls.connectWithEch
 *
 * Drop-in replacement for Node's `tls.checkServerIdentity` that
 * implements RFC 9525 paragraph 6 strictly. Operators pass it to
 * `tls.connect({ checkServerIdentity })` (or to any framework primitive
 * that exposes `pkixStrict: true`).
 *
 * Differences vs Node's default matcher:
 *
 *   - SAN-required when present is mandatory: a peer cert lacking
 *     `subjectAltName` refuses with `tls/pkix-san-required` (RFC 9525
 *     paragraph 6.4.4 forbids Common Name fallback).
 *   - CN-only legacy certs surface a distinct
 *     `tls/pkix-cn-fallback-refused` code so audit logs distinguish
 *     "missing SAN" from "ancient CN-only cert still shipping".
 *   - Wildcard matching is restricted to the entire leftmost label.
 *     `*.example.com` matches `foo.example.com` but NOT
 *     `foo.bar.example.com` and NOT `example.com`. Partial wildcards
 *     like `f*o.example.com` and middle wildcards like
 *     `foo.*.example.com` refuse.
 *   - IP literals match `iPAddress` SAN entries only — never DNS
 *     entries, never wildcards. IPv6 comparison is byte-equal after
 *     canonicalization (zone-id stripped, `::` expanded).
 *
 * Returns `Error | undefined` — the `Error` shape Node expects; when
 * undefined, the connection is permitted to proceed.
 *
 * @example
 *   var tls  = require("node:tls");
 *   var b    = require("@blamejs/core");
 *   var sock = tls.connect({
 *     host: "internal.example.com",
 *     port: 443,
 *     checkServerIdentity: b.network.tls.checkServerIdentity9525,
 *   });
 */
function checkServerIdentity9525(host, cert) {
  if (typeof host !== "string" || host.length === 0) {
    return new NetworkTlsError("tls/pkix-hostname-mismatch",
      "checkServerIdentity9525: host must be a non-empty string");
  }
  if (!cert || typeof cert !== "object") {
    return new NetworkTlsError("tls/pkix-hostname-mismatch",
      "checkServerIdentity9525: peer cert object missing");
  }
  var hostIsIp = net.isIP(host) > 0;
  var hostNorm = hostIsIp ? host : _normalizeAsciiHost(host);
  if (!hostIsIp && !hostNorm) {
    return new NetworkTlsError("tls/pkix-hostname-mismatch",
      "checkServerIdentity9525: host '" + host + "' is not a valid ASCII " +
      "DNS name (pre-convert U-labels to A-labels with punycode)");
  }
  var rawSan = cert.subjectaltname;
  if (typeof rawSan !== "string" || rawSan.length === 0) {
    var cnRefusal = _refuseCnFallback(host, cert);
    if (cnRefusal) return cnRefusal;
    return new NetworkTlsError("tls/pkix-san-required",
      "checkServerIdentity9525: certificate has no subjectAltName " +
      "extension (RFC 9525 §6.4.4 forbids Common Name fallback)");
  }
  var san = _parseSanString(rawSan);
  if (hostIsIp) {
    if (san.ips.length === 0) {
      return new NetworkTlsError("tls/pkix-hostname-mismatch",
        "checkServerIdentity9525: host '" + host + "' is an IP literal " +
        "but the certificate's SAN contains no iPAddress entries");
    }
    for (var ii = 0; ii < san.ips.length; ii += 1) {
      if (_ipsEqual(san.ips[ii], host)) return undefined;
    }
    return new NetworkTlsError("tls/pkix-hostname-mismatch",
      "checkServerIdentity9525: host IP '" + host + "' does not match " +
      "any iPAddress SAN (" + san.ips.join(", ") + ")");
  }
  if (san.dns.length === 0) {
    return new NetworkTlsError("tls/pkix-hostname-mismatch",
      "checkServerIdentity9525: certificate's SAN contains no dNSName " +
      "entries (host '" + host + "' cannot match an iPAddress-only cert)");
  }
  for (var di = 0; di < san.dns.length; di += 1) {
    if (_matchDnsNamePattern(san.dns[di], hostNorm)) return undefined;
  }
  return new NetworkTlsError("tls/pkix-hostname-mismatch",
    "checkServerIdentity9525: host '" + host + "' does not match any " +
    "dNSName SAN (" + san.dns.join(", ") + ")");
}

function _refuseCnFallback(host, cert) {
  if (cert && cert.subject && typeof cert.subject.CN === "string" &&
      cert.subject.CN.length > 0 &&
      (typeof cert.subjectaltname !== "string" || cert.subjectaltname.length === 0)) {
    return new NetworkTlsError("tls/pkix-cn-fallback-refused",
      "checkServerIdentity9525: peer cert is CN-only (CN='" +
      cert.subject.CN + "'); RFC 9525 §6.4.4 refuses CN-fallback. " +
      "Reissue the certificate with a subjectAltName extension covering " +
      "host '" + host + "'.");
  }
  return null;
}

function _checkServerIdentityStrict(host, cert) {
  var cnRefusal = _refuseCnFallback(host, cert);
  if (cnRefusal) return cnRefusal;
  return checkServerIdentity9525(host, cert);
}

function wrapSNICallback(operatorCb) {
  if (typeof operatorCb !== "function") return operatorCb;
  return function _wrappedSNICallback(servername, cb) {
    try {
      operatorCb(servername, cb);
    } catch (err) {
      try {
        audit().safeEmit({
          action:   "network.tls.sni_callback_threw",
          outcome:  "failure",
          metadata: {
            servername: typeof servername === "string" ? servername : null,
            reason:     (err && err.message) ? err.message : String(err),
          },
        });
      } catch (_auditErr) { /* drop-silent — audit best-effort */ }
      try { cb(err, null); }
      catch (_cbErr) { /* cb already invoked or unavailable */ }
    }
  };
}

module.exports = {
  auditInsecureTls:    auditInsecureTls,
  certificateCompressionAlgorithms: certificateCompressionAlgorithms,
  outboundPosture:     outboundPosture,
  explainOutboundFailure: explainOutboundFailure,
  annotateOutboundFailure: annotateOutboundFailure,
  postureGeneration:   postureGeneration,
  addCa:               addCa,
  addCaBundle:         addCaBundle,
  removeCa:            removeCa,
  removeCaByLabel:     removeCaByLabel,
  clearAll:            clearAll,
  purgeExpired:        purgeExpired,
  expiringSoon:        expiringSoon,
  expiryMonitor:       expiryMonitor,
  pinsetDriftMonitor:  pinsetDriftMonitor,
  useSystemTrust:      useSystemTrust,
  isSystemTrustEnabled: isSystemTrustEnabled,
  getTrustStore:       getTrustStore,
  captureBaselineFingerprints: captureBaselineFingerprints,
  detectBaselineDrift: detectBaselineDrift,
  applyToContext:      applyToContext,
  keyAgreementGroups:  keyAgreementGroups,
  serverKeyAgreementGroups: serverKeyAgreementGroups,
  buildOptions:        buildOptions,
  getCaPems:           getCaPems,
  ocsp:                ocsp,
  ct:                  ct,
  pqc:                 pqc,
  preferredGroups:     preferredGroups,
  parseEchConfigList:  parseEchConfigList,
  connectWithEch:      connectWithEch,
  checkServerIdentity9525: checkServerIdentity9525,
  wrapSNICallback:     wrapSNICallback,
  TlsTrustError:       TlsTrustError,
  NetworkTlsError:     NetworkTlsError,
  _resetForTest:       _resetForTest,
  _stripUnreachableCertCompression: _stripUnreachableCertCompression,
  _checkServerIdentityStrict: _checkServerIdentityStrict,
  _stripSctExtensionFromCert: _stripSctExtensionFromCert,
  _buildSctSignedEntry: _buildSctSignedEntry,
};
