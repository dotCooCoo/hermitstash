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
var validateOpts = require("./validate-opts");
var lazyRequire = require("./lazy-require");
var safeAsync = require("./safe-async");
var { defineClass } = require("./framework-error");

var TlsTrustError = defineClass("TlsTrustError", { alwaysPermanent: true });
var NetworkTlsError = defineClass("NetworkTlsError", { alwaysPermanent: true });

var observability = lazyRequire(function () { return require("./observability"); });
var audit = lazyRequire(function () { return require("./audit"); });
var networkDns = lazyRequire(function () { return require("./network-dns"); });
var httpClient = lazyRequire(function () { return require("./http-client"); });
var asn1 = require("./asn1-der");

// Audit + observability emit for an outbound TLS connection that runs with
// peer-certificate validation DISABLED (an explicit operator opt-in —
// rejectUnauthorized:false / allowInsecure — never a framework default).
// Emitted at the point the disable is HONORED so the degraded posture is
// observable (compliance evidence + incident response), parallel to the
// tls.classical_downgrade audit. Drop-silent best-effort (§8 hot-path sink) —
// an audit-sink failure must never break the TLS connect itself.
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

// STATE.tlsKeyShares is initialized to the default PQC group list at
// module load — operator setKeyShares() overrides; resetKeyShares()
// restores the default. Empty array means "fall back to Node's TLS
// default groups" (operator opt-out).
var STATE = {
  cas:             [],
  systemTrust:     false,
  baselineFingerprints: null,
  tlsKeyShares:    ["X25519MLKEM768", "SecP256r1MLKEM768", "SecP384r1MLKEM1024", "X25519"],
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

// CodeQL js/file-system-race defense — fd-based read binds the size +
// content measurement to the inode the fd holds open. The cert path is
// operator-supplied (tls.addCa) but routing through openSync + fstatSync
// + readSync narrows the race window vs the prior statSync + readFileSync
// shape, where an attacker who could swap the file in-between could
// short-circuit the PEM marker check downstream.
function _readPathFile(p) {
  // TOCTOU-safe read via atomic-file: utf8 string, slice on a short read,
  // raw ENOENT preserved (errorFor returns undefined → rethrow).
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

// _certAuditMetadata(m) — the shared cert-identity fields stamped on every
// network.tls.ca.* audit event (the add / remove emitters overlay their
// own label / reason on top via Object.assign). Distinct from
// _certMetadata(pem), which PARSES a PEM into the meta object `m`.
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

// pinsetDriftMonitor — periodic check that emits audit + observability
// events when the trust-store fingerprint set drifts from the captured
// baseline. Different intent from expiryMonitor: this fires when a
// CA is added or removed (by operator config-flip OR by a tampered
// MANIFEST / vendor refresh), not when an existing one approaches
// validity expiry.
//
//   b.network.tls.captureBaselineFingerprints();   // at boot
//   var mon = b.network.tls.pinsetDriftMonitor({
//     intervalMs:  C.TIME.minutes(15),
//     onDrift:     function (drift) { /* operator hook */ },
//   });
//
// Audit emissions:
//   network.tls.pinset.drift_check  — every check, ok / warn
//   network.tls.pinset.drifted      — when added.length || removed.length
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
    if (drift === null) return;   // baseline not captured; nothing to compare
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
      if (typeof opts.onDrift === "function") {
        try { opts.onDrift(drift); } catch (_e) { /* operator hook */ }
      }
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

// PQ/T-hybrid named-group ordering (RFC 9794 is the PQ/T-hybrid
// *terminology*; the TLS codepoints come from the IANA TLS Supported
// Groups registry + draft-kwiatkowski-tls-ecdhe-mlkem +
// draft-ietf-tls-hybrid-design). The preferred groups (the first the peer
// mutually supports wins) put the IANA-registered hybrid named groups
// ahead of the classical fallback:
//
//   X25519MLKEM768       — codepoint 0x11EC (IANA; draft-kwiatkowski-tls-ecdhe-mlkem)
//   SecP256r1MLKEM768    — codepoint 0x11EB (IANA; NIST-curve hybrid)
//                            (NIST-curve fallback for FIPS-mandated peers
//                            that refuse X25519)
//   SecP384r1MLKEM1024   — draft-kwiatkowski-tls-ecdhe-mlkem-02 codepoint
//                            0x11ED; highest-PQC hybrid; only ML-KEM-1024
//                            offering for FIPS-mandated peers wanting
//                            CNSA-2.0-aligned key strength
//   X25519               — classical fallback (modern non-PQC peers)
//
// Operators FIPS-mandated to a NIST curve set `setKeyShares([
// "SecP256r1MLKEM768", "SecP384r1MLKEM1024" ])` and drop the X25519-
// based groups. Operators on legacy peers without any PQC support set
// `setKeyShares(["X25519"])` to opt out of the hybrid groups entirely.
var DEFAULT_PQC_KEY_SHARES = Object.freeze([
  "X25519MLKEM768",
  "SecP256r1MLKEM768",
  "SecP384r1MLKEM1024",
  "X25519",
]);

function _validateKeyShare(name) {
  if (typeof name !== "string" || name.length === 0 || safeBuffer.byteLengthOf(name) > C.BYTES.bytes(64)) {  // bound
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

// preferredGroups — alias surface for the named-group list.
// `set(list)` overrides the default ordering; `get()` reads the active
// list; `reset()` restores the framework default. The setKeyShares /
// getKeyShares / resetKeyShares names are kept as the lower-level
// alias under `b.network.tls.pqc.*`.
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

// b.network.tls.buildOptions(opts) — assemble a plain options object
// suitable for tls.connect / new https.Agent(...) / https.request,
// pre-populated with the framework's PQC group preference + TLSv1.3
// floor. Operators that build their own outbound transport (custom
// https.Agent, raw tls.connect for protocol clients other than HTTP)
// route through this primitive so the same posture lands everywhere.
//
// Throws NetworkTlsError("network-tls/bad-tls-options") on invalid
// shape (config-time entry point — operator catches typo at boot).
//
//   buildOptions({ ecdhCurve, groups, cert, key, ca, minVersion, sni })
//     returns { minVersion, ecdhCurve, groups, cert, key, ca, servername }
//
// `ca` accepts a PEM string OR Buffer OR Array<string|Buffer>; arrays
// are concatenated with `\n` so Node's TLS layer parses every block.
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
    ["ecdhCurve", "groups", "cert", "key", "ca", "minVersion", "sni"],
    "network.tls.buildOptions");
  var out = {};
  // TLS-1.3 floor — matches the framework's locked posture in
  // pqc-agent. Operators may pass minVersion: "TLSv1.3" explicitly;
  // anything else fails closed.
  var minV = opts.minVersion === undefined ? "TLSv1.3" : opts.minVersion;
  if (minV !== "TLSv1.3") {
    throw new NetworkTlsError("network-tls/bad-tls-options",
      "buildOptions: minVersion must be 'TLSv1.3' (got " +
      JSON.stringify(opts.minVersion) + ") — framework posture is " +
      "TLS-1.3-only outbound; construct tls.connect opts directly to " +
      "negotiate weaker protocol versions.");
  }
  out.minVersion = minV;

  // PQC group preference. Caller may narrow (drop a group) but not
  // widen — every requested group must appear in the framework
  // preferred list. Both `groups` (alias) and `ecdhCurve`
  // (Node TLS option) are accepted; `groups` wins when both supplied.
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
  var resolvedStr = resolved.join(":");
  out.ecdhCurve = resolvedStr;
  out.groups    = resolvedStr;

  // cert / key — pass-through with light shape check. Both are
  // typically PEM strings or Buffers; arrays are valid for cert
  // bundles per Node's tls API, so allow array<string|Buffer>.
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

  // SNI override — Node spells this `servername`.
  if (opts.sni !== undefined) {
    validateOpts.requireNonEmptyString(opts.sni, "buildOptions: sni",
      NetworkTlsError, "network-tls/bad-tls-options");
    out.servername = opts.sni;
  }
  return out;
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
var OID_SHA1                = "1.3.14.3.2.26";                                   // SHA-1 algorithm OID arc
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
  if (s.length === 13 && s.charAt(12) === "Z") {                                 // UTCTime length per X.690
    // UTCTime YYMMDDhhmmssZ — 50+ → 19xx, else 20xx (RFC 5280 §4.1.2.5).
    year  = parseInt(s.slice(0, 2), 10);
    year += year >= 50 ? 1900 : 2000;
    month = parseInt(s.slice(2, 4), 10);
    day   = parseInt(s.slice(4, 6), 10);
    hour  = parseInt(s.slice(6, 8), 10);                                         // UTCTime hour-byte offsets
    min   = parseInt(s.slice(8, 10), 10);                                        // UTCTime minute-byte offsets
    sec   = parseInt(s.slice(10, 12), 10);
  } else if (s.length >= 15 && s.charAt(s.length - 1) === "Z") {                 // GeneralizedTime length per X.690
    // GeneralizedTime YYYYMMDDhhmmssZ.
    year  = parseInt(s.slice(0, 4), 10);
    month = parseInt(s.slice(4, 6), 10);
    day   = parseInt(s.slice(6, 8), 10);                                         // GeneralizedTime day-byte offsets
    hour  = parseInt(s.slice(8, 10), 10);                                        // GeneralizedTime hour-byte offsets
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
  if (basicChildren.length < 3) {                                                // minimum BasicOCSPResponse fields (tbs + alg + sig)
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
    if (sr.length < 3) continue;                                                 // minimum SingleResponse fields
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
    // Constant-time compare — module-wide consistency with the
    // Merkle-root / NTS-cookie / cert-fingerprint paths that already
    // use timingSafeEqual. Buffer.equals is constant-time on equal-
    // length inputs but fast-paths on length mismatch; not security-
    // critical here (the OCSP response is CA-signed and signature
    // already verified) but matches the project discipline.
    if (!bCrypto.timingSafeEqual(parsed.basic.nonce, opts.expectedNonce)) {
      return { ok: false, status: parsed.status, signatureValid: true,
               errors: ["OCSP nonce mismatch — possible replay or wrong responder"] };
    }
    nonceCheck = "matched";
  } else if (parsed.basic.nonce) {
    nonceCheck = "present-not-checked";
  }
  // RFC 6960 §4.2.2.1 — time-window enforcement. A "good" response is
  // valid only between thisUpdate and nextUpdate (with operator-tunable
  // skew). Without this check a stapled response is replayable forever:
  // an attacker captures a pre-revocation "good" reply, the cert later
  // gets revoked, the attacker keeps presenting the cached "good" and
  // the framework keeps accepting it. requireGood postures depend on
  // freshness — reject expired or future-dated responses outright.
  var clockSkewMs = typeof opts.clockSkewMs === "number" && opts.clockSkewMs >= 0           // allow:numeric-opt-Infinity — operator-supplied skew, default 5 min if absent or invalid
    ? opts.clockSkewMs : C.TIME.minutes(5);
  var now = typeof opts.now === "number" ? opts.now : Date.now();
  var thisUpdateMs = match.thisUpdate ? Date.parse(match.thisUpdate) : NaN;
  var nextUpdateMs = match.nextUpdate ? Date.parse(match.nextUpdate) : NaN;
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

// ---- OCSPRequest builder (RFC 6960 §4.1 + RFC 8954 nonce ext) ----
//
// Constructs a DER-encoded OCSPRequest for a single (leafCertDer,
// issuerCertDer) pair, optionally with an RFC 8954 nonce extension.
// `ocsp.fetch` composes this with `b.httpClient` to POST the request to
// the cert's responder and return a validated response; operators who
// need the raw request (custom transport, batched requests) call this
// directly and pass `nonce` to `ocsp.evaluate(responseDer, { expectedNonce })`
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
      tbsKids[0].tag === 0) {                                                    // X.509 [0] EXPLICIT version tag
    idx = 1;
  }
  // After version: serialNumber, signature, issuer, validity, subject, SPKI.
  var subjectIdx = idx + 4;                                                      // X.509 TBSCertificate field count
  var spkiIdx = idx + 5;                                                         // X.509 TBSCertificate field count
  if (spkiIdx >= tbsKids.length) {
    throw new TlsTrustError("tls/ocsp-bad-issuer-cert", "issuer cert lacks SPKI field");
  }
  var subject = tbsKids[subjectIdx];
  var spki = tbsKids[spkiIdx];
  // Within SPKI: SEQUENCE { algorithm AlgorithmIdentifier, subjectPublicKey BIT STRING }
  var spkiKids = asn1.readSequence(spki.value);
  if (spkiKids.length < 2) {                                                     // minimum SPKI fields
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
      tbsKids[0].tag === 0) {                                                    // X.509 [0] EXPLICIT version tag
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
  // optional and many responders reject). The hash isn't security-
  // critical here — it's a name/key lookup, not an integrity check —
  // but operator compliance dashboards alerting on "anywhere in the
  // framework that touches SHA-1" need a signal. Emit an audit row
  // on every OCSP request build so the algorithm choice is visible
  // in the chain.
  // lgtm[js/weak-cryptographic-algorithm] — RFC 6960 §4.1.1 CertID lookup hash over the PUBLIC issuer name; a name/key lookup, not an integrity or secrecy operation. SHA-256 CertIDs are §4.3-optional and rejected by most responders.
  var nameHash = nodeCrypto.createHash("sha1").update(iss.issuerNameDer).digest(); // lgtm[js/weak-cryptographic-algorithm]
  // lgtm[js/weak-cryptographic-algorithm] — RFC 6960 §4.1.1 CertID lookup hash over the PUBLIC issuer key; a name/key lookup, not an integrity or secrecy operation.
  var keyHash  = nodeCrypto.createHash("sha1").update(iss.issuerKey).digest(); // lgtm[js/weak-cryptographic-algorithm]
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
    var nonceLen = typeof opts.nonceLen === "number" ? opts.nonceLen : 16;       // RFC 8954 §2.1 nonce length floor
    if (nonceLen < 1 || nonceLen > 32) {                                         // RFC 8954 §2.1 nonce length ceiling
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

// _ocspResponderUrl — pull the OCSP responder URL out of a cert's
// Authority Information Access extension. node:crypto exposes it as a
// multi-line string ("OCSP - URI:http://...\nCA Issuers - URI:...\n").
function _ocspResponderUrl(x509) {
  var ia = x509 && x509.infoAccess;
  if (typeof ia !== "string") return null;
  var m = ia.match(/OCSP\s*-\s*URI:(\S+)/i);
  return m ? m[1].trim() : null;
}

// fetch — POST a freshly-built OCSPRequest to the cert's responder and
// return the validated, known-good response bytes. Composes buildRequest +
// b.httpClient + evaluate, completing the server-side-stapling fetch path
// (the response is what a TLS server staples via its 'OCSPRequest' handler).
// The responder URL is taken from the leaf cert's AIA extension unless
// opts.responderUrl overrides it. Throws TlsTrustError on any failure
// (no responder, transport error, non-good certStatus, signature mismatch);
// callers that staple should treat a throw as "no staple this cycle".
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
  if (res.status !== 200 || !Buffer.isBuffer(res.body) || res.body.length === 0) {
    throw new TlsTrustError("tls/ocsp-fetch-bad-status",
      "ocsp.fetch: responder returned status " + res.status + " with an empty/non-buffer body");
  }
  var evald = evaluateOcspResponse(res.body, {
    issuerPem:     opts.issuerPem,
    serialHex:     opts.serialHex || null,
    expectedNonce: opts.nonce === false ? null : built.nonce,
  });
  if (!evald.ok) {
    throw new TlsTrustError("tls/ocsp-not-good",
      "ocsp.fetch: response is not good: " + (evald.errors || []).join("; "));
  }
  return { ocspDer: res.body, evaluation: evald, responderUrl: responderUrl };
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
  fetch:                fetchOcspResponse,
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
    if (ch.tagClass === asn1.TAG_CLASS.CONTEXT_SPECIFIC && ch.tag === 3) {       // X.509 [3] EXPLICIT extensions tag
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
    if (ch.tagClass === asn1.TAG_CLASS.CONTEXT_SPECIFIC && ch.tag === 3) {       // X.509 [3] EXPLICIT extensions tag
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
  if (!Buffer.isBuffer(sctListRaw) || sctListRaw.length < 2) {                   // outer 2-byte length prefix
    throw new TlsTrustError("tls/ct-bad-list",
      "SCT list shorter than the outer length prefix");
  }
  var totalLen = sctListRaw.readUInt16BE(0);
  if (totalLen + 2 !== sctListRaw.length) {                                      // outer length prefix
    throw new TlsTrustError("tls/ct-bad-list",
      "SCT list outer length " + totalLen + " does not match buffer " +
      (sctListRaw.length - 2));
  }
  var pos = 2;                                                                   // past the outer prefix
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
  if (sctBuf.length < 1 + 32 + 8 + 2 + 4) {                                      // minimum SCT v1 byte total
    throw new TlsTrustError("tls/ct-sct-too-short",
      "SCT is shorter than the minimum v1 layout (" + sctBuf.length + " bytes)");
  }
  var version = sctBuf[0];
  if (version !== 0) {
    throw new TlsTrustError("tls/ct-sct-bad-version",
      "SCT version is not 0 (v1): got " + version);
  }
  var logId = sctBuf.slice(1, 1 + 32);                                           // RFC 6962 32-byte LogID
  var timestamp = Number(sctBuf.readBigUInt64BE(1 + 32));                        // past LogID
  var extLen = sctBuf.readUInt16BE(1 + 32 + 8);                                  // past LogID + timestamp
  var pos = 1 + 32 + 8 + 2;                                                      // past extLen field
  var extensions = sctBuf.slice(pos, pos + extLen);
  pos += extLen;
  if (pos + 4 > sctBuf.length) {                                                 // DigitallySigned header (hash + alg + len)
    throw new TlsTrustError("tls/ct-sct-truncated",
      "SCT truncated before DigitallySigned");
  }
  var hashAlgo = sctBuf[pos];
  var sigAlgo  = sctBuf[pos + 1];
  pos += 2;                                                                      // past hash+alg pair
  var sigLen = sctBuf.readUInt16BE(pos);
  pos += 2;                                                                      // past sig length
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
  var head = Buffer.alloc(1 + 1 + 8 + 2);                                        // fixed-shape header bytes
  head[0] = sct.version;
  head[1] = 0;                                                                   // signature_type = certificate_timestamp
  head.writeBigUInt64BE(BigInt(sct.timestamp), 2);                               // past version+sig-type
  head.writeUInt16BE(0, 10);                                                     // entry_type = x509_entry (2 bytes; high byte = 0, low byte = 0)
  // signed_entry: 3-byte length prefix + cert DER.
  var lenBytes = Buffer.alloc(3);                                                // RFC 6962 24-bit length prefix
  lenBytes[0] = (certWithoutSctDer.length >> 16) & 0xff;                         // base-256 length high byte
  lenBytes[1] = (certWithoutSctDer.length >> 8) & 0xff;                          // base-256 length mid byte
  lenBytes[2] = certWithoutSctDer.length & 0xff;                                 // base-256 length low byte
  // ct_extensions: 2-byte length + bytes.
  var extHead = Buffer.alloc(2);                                                 // RFC 6962 2-byte ct_extensions length prefix
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
    if (ch.tagClass === asn1.TAG_CLASS.CONTEXT_SPECIFIC && ch.tag === 3) {       // [3] EXPLICIT extensions tag
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
        // Re-encode this extension verbatim from its parsed bytes.
        keptExtBytes.push(_encodeAsn1(asn1.TAG.SEQUENCE, true, extBytes));
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
  if (len < 0x80) return Buffer.from([len]);                                     // DER short-form length threshold
  var tmp = [];
  var n = len;
  while (n > 0) {
    tmp.unshift(n & 0xff);                                                       // base-256 byte
    n = n >>> 8;                                                                 // byte shift
  }
  return Buffer.concat([Buffer.from([0x80 | tmp.length]), Buffer.from(tmp)]);    // DER long-form length flag
}
function _encodeAsn1(tag, constructed, value) {
  var tagByte = (constructed ? 0x20 : 0x00) | tag;                               // DER constructed bit + universal tag
  return Buffer.concat([Buffer.from([tagByte]), _encodeLength(value.length), value]);
}
function _encodeContextExplicit(num, value) {
  // Context-specific class (10) + constructed (20) | tag.
  var tagByte = 0xa0 | num;                                                      // DER context-specific + constructed
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
    tagByte = (node.constructed ? 0x20 : 0x00) | (node.tag & 0x1f);              // DER constructed bit + universal tag
  } else {
    var classBits = (node.tagClass & 0x03) << 6;                                 // DER tag-class bits
    tagByte = classBits | (node.constructed ? 0x20 : 0x00) | (node.tag & 0x1f);  // DER constructed bit + low-tag
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
  var minScts = typeof opts.minScts === "number" ? opts.minScts : 2;             // Chrome CT policy min-2-SCTs
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
    var nodeAlgo = sct.hashAlgo === 4 ? "sha256" :                               // TLS 1.2 HashAlgorithm enum sha256
                   sct.hashAlgo === 5 ? "sha384" :                               // TLS 1.2 HashAlgorithm enum sha384
                   sct.hashAlgo === 6 ? "sha512" :                               // TLS 1.2 HashAlgorithm enum sha512
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
    // RFC 6962 §2.1.4 — log-key SignatureAndHashAlgorithm pair must
    // match the SCT's signatureAlgorithm. signatureAlgo enum 1=RSA,
    // 3=ECDSA. Cross-check against the actual log-key type so a
    // malformed log-keys map can't silently accept SCTs signed
    // under one algorithm against a key registered under another.
    var keyType = keyObj.asymmetricKeyType;
    var sctSigAlgo = sct.signatureAlgo;
    var algoOk = (sctSigAlgo === 1 && keyType === "rsa") ||                       // TLS 1.2 SignatureAlgorithm rsa
                 (sctSigAlgo === 3 && (keyType === "ec" || keyType === "ecdsa")); // TLS 1.2 SignatureAlgorithm ecdsa
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

// ---- RFC 9162 §2.1 Merkle tree primitives ----
//
// CT v2 (RFC 9162) inclusion + consistency proofs operate on a binary
// Merkle tree with the following node hashes (RFC 9162 §2.1.1):
//
//   MTH(empty) = SHA-256("")                                  — empty tree
//   MTH({d})   = SHA-256(0x00 || d)                           — leaf
//   MTH(D)     = SHA-256(0x01 || MTH(D[0:k]) || MTH(D[k:n]))  — internal
//
// SHA-256 is the algorithm RFC 9162 mandates; the framework's PQC-first
// posture does not apply here because the algorithm is wire-defined
// by the CT log itself and changing it would break interop with every
// public log. A future SHA3-flavoured CT (no draft as of writing) ships
// alongside, not in place.
//
// LEAF_HASH_PREFIX  = 0x00
// INNER_HASH_PREFIX = 0x01
// k = largest power of 2 < n  (RFC 9162 §2.1.1)

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

// _ctLargestPowerOf2LessThan — k from RFC 9162 §2.1.1: the largest
// power of 2 that is strictly less than n. n must be > 1.
function _ctLargestPowerOf2LessThan(n) {
  if (n < 2) {
    throw new TlsTrustError("tls/ct-bad-tree-size",
      "ct: largest-power-of-2-less-than requires n >= 2 (got " + n + ")");
  }
  var k = 1;
  while ((k << 1) < n) k = k << 1;
  return k;
}

// _ctVerifyInclusion — RFC 9162 §2.1.3 algorithm. Walks the audit path
// from the leaf hash up to the tree's expected root using the supplied
// audit path siblings. The leafIndex (0-based) selects which side at
// each level the leaf sits on; the audit path provides the sibling
// hash for that level.
//
//   args:
//     leafHash:    Buffer (32 bytes) — MTH({d}) of the leaf
//     leafIndex:   integer 0 <= idx < treeSize
//     treeSize:    integer >= 1
//     auditPath:   Array of Buffer (each 32 bytes) — siblings bottom-up
//
//   returns: Buffer (32 bytes) — computed root hash to compare
//   throws:  TlsTrustError on shape errors
function _ctVerifyInclusionPath(leafHash, leafIndex, treeSize, auditPath) {
  if (!Buffer.isBuffer(leafHash) || leafHash.length !== 32) {                    // RFC 9162 SHA-256 digest length
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

  // Per RFC 9162 §2.1.3 — climb the tree using the audit path. fn=leafIndex,
  // sn=treeSize-1 (last index in the tree at this level). Pop one
  // sibling from the audit path per level.
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
    if (!Buffer.isBuffer(sibling) || sibling.length !== 32) {                    // RFC 9162 SHA-256 digest length
      throw new TlsTrustError("tls/ct-bad-audit-path",
        "ct.verifyInclusion: audit path entry " + (pathPos - 1) + " is not a 32-byte Buffer");
    }
    if ((fn & 1) === 1 || fn === sn) {
      r = _ctInnerHashFinal(sibling, r);
      // Right-side leaf — climb until we hit a left-side ancestor.
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

// _ctVerifyConsistency — RFC 9162 §2.1.4 consistency proof verification.
// Given a first STH (size m) and a second STH (size n, n >= m), the
// consistency proof shows the second tree contains the first tree as a
// prefix. Returns the computed roots (oldRoot, newRoot) so the caller
// can compare against the operator-supplied STHs.
function _ctVerifyConsistencyPath(m, n, consistencyProof, firstHash) {
  if (typeof m !== "number" || m < 1 || Math.floor(m) !== m) {
    throw new TlsTrustError("tls/ct-bad-first-size",
      "ct.verifyConsistency: m (first tree size) must be a positive integer");
  }
  if (typeof n !== "number" || n < m || Math.floor(n) !== n) {
    throw new TlsTrustError("tls/ct-bad-second-size",
      "ct.verifyConsistency: n (second tree size) must be an integer >= m");
  }
  if (!Buffer.isBuffer(firstHash) || firstHash.length !== 32) {                  // RFC 9162 SHA-256 digest length
    throw new TlsTrustError("tls/ct-bad-first-hash",
      "ct.verifyConsistency: firstHash must be a 32-byte Buffer");
  }
  if (!Array.isArray(consistencyProof)) {
    throw new TlsTrustError("tls/ct-bad-consistency-proof",
      "ct.verifyConsistency: consistencyProof must be an array of Buffers");
  }
  // RFC 9162 §2.1.4.2 — algorithm is the same as the inclusion-proof
  // walk, with the leaf-index seeded at the first-tree size minus 1 and
  // the special case for m being a complete subtree.
  var path = consistencyProof.slice();
  var node;
  var fn = m - 1;
  var sn = n - 1;
  // Walk past the right-side bits — the consistency proof omits the
  // path while the first tree is a complete subtree of the second.
  while ((fn & 1) === 1) { fn >>>= 1; sn >>>= 1; }

  if (fn === 0) {
    // m was a complete subtree — its root is the firstHash itself.
    node = firstHash;
  } else {
    if (path.length === 0) {
      throw new TlsTrustError("tls/ct-consistency-empty",
        "ct.verifyConsistency: consistency proof empty but first tree is not a complete subtree");
    }
    node = path.shift();
  }
  while (sn > 0) {
    if (path.length === 0) {
      throw new TlsTrustError("tls/ct-consistency-short",
        "ct.verifyConsistency: consistency proof exhausted before second-tree root");
    }
    var sibling = path.shift();
    if (!Buffer.isBuffer(sibling) || sibling.length !== 32) {                    // RFC 9162 SHA-256 digest length
      throw new TlsTrustError("tls/ct-bad-consistency-entry",
        "ct.verifyConsistency: consistency-proof entry is not a 32-byte Buffer");
    }
    if ((fn & 1) === 1 || fn === sn) {
      node = _ctInnerHashFinal(sibling, node);
      while ((fn & 1) === 0 && fn !== 0) { fn >>>= 1; sn >>>= 1; }
    } else {
      node = _ctInnerHashFinal(node, sibling);
    }
    fn >>>= 1;
    sn >>>= 1;
  }
  return node;
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
  // verifyInclusion — RFC 9162 §4.5/§5.1 inclusion-proof verifier.
  // Composes with inspect() / parseScts() / verifyScts() for the
  // signature side: an SCT proves a log promised to include the cert,
  // and verifyInclusion proves that promise was kept (the leaf actually
  // sits in the published tree).
  //
  //   opts: {
  //     sct:              { logIdHex, timestamp, signedEntryDer? } — from parseScts
  //     leafCertificate:  Buffer — leaf cert DER (the entry hashed at the leaf)
  //     leafIndex:        integer — position in the tree (from RFC 9162 §6.7 get-proof-by-hash)
  //     auditPath:        [Buffer] — the inclusion-proof siblings, bottom-up
  //     sthFromLog:       { treeSize, rootHash[, sha256RootHash] }
  //                       — operator fetched the signed tree head from the log
  //                         (RFC 9162 §6.4 get-sth) and supplies treeSize +
  //                         rootHash (32-byte Buffer or hex string)
  //     consistency:      { firstSize, firstRoot, proof } — optional
  //                       — when provided, also verifies that the supplied
  //                         STH is consistent with an earlier STH the operator
  //                         pinned (RFC 9162 §6.5 get-sth-consistency)
  //   }
  //
  //   returns: { valid: bool, reason?: string, computedRoot?: hex,
  //              consistency?: { ok, computedSecondRoot? } }
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

    // Build the leaf bytes per RFC 9162 §4.6 — TimestampedEntry.
    // entry_type = x509_entry (0); signed_entry = strip-SCT-extension(cert).
    // Operators may pass a pre-built signedEntryDer when the SCT was
    // already extracted via parseScts() + the framework has the
    // pre-issuance cert; otherwise we strip the SCT extension here.
    var signedEntryDer = opts.sct.signedEntryDer;
    if (!Buffer.isBuffer(signedEntryDer)) {
      try { signedEntryDer = _stripSctExtensionFromCert(opts.leafCertificate); }
      catch (e) {
        return { valid: false, reason: "strip-failed",
                 error: (e && e.message) || String(e) };
      }
    }

    // RFC 9162 §4.6 MerkleTreeLeaf — version (1) + leaf_type (0) +
    // timestamp (uint64) + entry_type (uint16) + signed_entry (variable-
    // length cert DER with 24-bit length prefix) + extensions (variable-
    // length, 16-bit length prefix, empty for x509_entry).
    var ts = opts.sct.timestamp;
    if (typeof ts !== "number" && typeof ts !== "bigint") {
      return { valid: false, reason: "bad-sct-timestamp" };
    }
    var tsBuf = Buffer.alloc(8);                                                 // TLS uint64 width
    var tsBig = typeof ts === "bigint" ? ts : BigInt(Math.floor(ts));
    tsBuf.writeBigUInt64BE(tsBig);
    var entryTypeBuf = Buffer.from([0x00, 0x00]);
    var lenBuf = Buffer.alloc(3);                                                // TLS uint24 length prefix
    lenBuf.writeUIntBE(signedEntryDer.length, 0, 3);
    var extensionsBuf = Buffer.from([0x00, 0x00]);                               // empty extensions vector
    var leafBytes = Buffer.concat([
      Buffer.from([0x00]),                                                       // version v1
      Buffer.from([0x00]),                                                       // leaf_type timestamped_entry
      tsBuf,
      entryTypeBuf,
      lenBuf, signedEntryDer,
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

    // sthFromLog.rootHash may be a Buffer or hex string.
    var sthRoot = opts.sthFromLog.rootHash || opts.sthFromLog.sha256RootHash;
    if (typeof sthRoot === "string") {
      try { sthRoot = Buffer.from(sthRoot, "hex"); }
      catch (_e) { return { valid: false, reason: "bad-sth-root-encoding" }; }
    }
    if (!Buffer.isBuffer(sthRoot) || sthRoot.length !== 32) {                    // RFC 9162 SHA-256 digest length
      return { valid: false, reason: "bad-sth-root" };
    }
    if (!bCrypto.timingSafeEqual(computedRoot, sthRoot)) {
      return { valid: false, reason: "root-mismatch",
               computedRoot: computedRoot.toString("hex") };
    }

    // Optional consistency proof — RFC 9162 §2.1.4.
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
  // verifyConsistency — standalone RFC 9162 §2.1.4 consistency-proof
  // verifier. Operators pinning historical tree-head fingerprints call
  // this whenever they fetch a fresh STH to confirm the log hasn't
  // forked. Returns { valid, computedRoot } / { valid:false, reason }.
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
    if (!Buffer.isBuffer(firstRoot) || firstRoot.length !== 32) {                // RFC 9162 SHA-256 digest length
      return { valid: false, reason: "bad-first-root" };
    }
    if (!Buffer.isBuffer(secondRoot) || secondRoot.length !== 32) {              // RFC 9162 SHA-256 digest length
      return { valid: false, reason: "bad-second-root" };
    }
    var computed;
    try {
      computed = _ctVerifyConsistencyPath(opts.firstSize, opts.secondSize,
        opts.proof || [], firstRoot);
    } catch (e) {
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

// ---- ECH (Encrypted Client Hello) — RFC 9460 SVCB ech= SvcParam +
//      draft-ietf-tls-esni-22 §4 ECHConfigList -----------------------
//
// ECH is a TLS 1.3 extension that encrypts the Client Hello Inner
// (SNI, ALPN, etc.) under a public key the server publishes via DNS
// SVCB/HTTPS records. A passive observer sees only the public_name
// SNI in the outer hello — the real virtual host stays confidential.
//
// Wire format reminder (uint16 lengths are big-endian throughout):
//
//   ECHConfigList = uint16 total_length || ECHConfig[]
//   ECHConfig     = uint16 version || uint16 length || contents
//   contents (v=0xfe0d) =
//     HpkeKeyConfig key_config
//     uint8         maximum_name_length
//     opaque<1..255> public_name        (with uint8 length prefix)
//     Extension     extensions<0..2^16-1>  (uint16 length prefix +
//                                           list of (uint16 ext_type,
//                                           opaque<0..2^16-1> ext_data))
//   HpkeKeyConfig =
//     uint8  config_id
//     uint16 kem_id
//     opaque public_key<1..2^16-1>      (uint16 length prefix)
//     HpkeSymmetricCipherSuite cipher_suites<4..2^16-1>
//                                       (uint16 length prefix; entries
//                                        each (uint16 kdf_id, uint16
//                                        aead_id) — 4 bytes apiece)

var ECH_CONFIG_VERSION_DRAFT_22 = 0xfe0d;                                        // draft-ietf-tls-esni-22 ECH version codepoint

function _echReadU8(buf, off) {
  if (off + 1 > buf.length) {
    throw new NetworkTlsError("tls/ech-config-malformed",
      "ECHConfigList: truncated reading uint8 at offset " + off);
  }
  return buf[off];
}
function _echReadU16(buf, off) {
  if (off + 2 > buf.length) {                                                    // uint16 width
    throw new NetworkTlsError("tls/ech-config-malformed",
      "ECHConfigList: truncated reading uint16 at offset " + off);
  }
  return buf.readUInt16BE(off);
}
function _echReadVarOpaqueU16(buf, off) {
  var len = _echReadU16(buf, off);
  off += 2;                                                                      // uint16 length-prefix width
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
 *   var rec = rrs.find(function (r) { return r.params && r.params.ech; });
 *   var parsed = b.network.tls.parseEchConfigList(rec.params.ech);
 *   // parsed.configs[0].keyConfig.kemId === 0x0020 (X25519)
 */
function parseEchConfigList(raw) {
  if (typeof raw === "string") {
    // Operators sometimes hold the SvcParam as a base64 string; accept
    // both. Reject anything that doesn't round-trip cleanly through
    // strict-base64 — Node's Buffer.from(b64, "base64") is lenient
    // (silently ignores stray bytes), so we re-encode and compare.
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
  if (raw.length < 2) {                                                          // uint16 outer length prefix
    throw new NetworkTlsError("tls/ech-config-malformed",
      "ECHConfigList: too short for outer length prefix");
  }
  var totalLen = raw.readUInt16BE(0);
  if (2 + totalLen !== raw.length) {                                             // uint16 prefix width
    throw new NetworkTlsError("tls/ech-config-malformed",
      "ECHConfigList: outer length " + totalLen + " does not match buffer " +
      "tail length " + (raw.length - 2));
  }
  var off = 2;                                                                   // uint16 prefix width
  var configs = [];
  while (off < raw.length) {
    if (off + 4 > raw.length) {                                                  // uint16 ver + uint16 len
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
      // HpkeKeyConfig
      var configId = _echReadU8(raw, p); p += 1;
      var kemId    = _echReadU16(raw, p); p += 2;                                // uint16 KEM id width
      var pkOpaque = _echReadVarOpaqueU16(raw, p); p = pkOpaque.nextOff;
      var suitesLen = _echReadU16(raw, p); p += 2;                               // uint16 length prefix width
      if (p + suitesLen > bodyEnd) {
        throw new NetworkTlsError("tls/ech-config-malformed",
          "ECHConfig: cipher_suites vector overflows config body");
      }
      if (suitesLen % 4 !== 0 || suitesLen < 4) {                                // kdf+aead = 4 bytes per suite
        throw new NetworkTlsError("tls/ech-config-malformed",
          "ECHConfig: cipher_suites length must be a positive multiple of 4");
      }
      var suites = [];
      for (var sp = p; sp < p + suitesLen; sp += 4) {                            // 4-byte cipher suite stride
        suites.push({
          kdfId:  raw.readUInt16BE(sp),
          aeadId: raw.readUInt16BE(sp + 2),
        });
      }
      p += suitesLen;
      // remainder of contents
      var maxNameLen = _echReadU8(raw, p); p += 1;
      var publicName = _echReadVarOpaqueU8(raw, p); p = publicName.nextOff;
      var extLen = _echReadU16(raw, p); p += 2;                                  // uint16 length prefix width
      if (p + extLen !== bodyEnd) {
        throw new NetworkTlsError("tls/ech-config-malformed",
          "ECHConfig: extensions vector does not consume remaining body " +
          "(extLen=" + extLen + ", remaining=" + (bodyEnd - p) + ")");
      }
      var extensions = [];
      var extEnd = p + extLen;
      while (p < extEnd) {
        var extType = _echReadU16(raw, p); p += 2;                               // uint16 ext type
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
      // Unknown future version — surface raw bytes so the caller can
      // forward them to a Node build that does support that version.
      entry.body = Buffer.from(raw.slice(bodyOff, bodyEnd));
    }
    configs.push(entry);
    off = bodyEnd;
  }
  return { rawLength: raw.length, configs: configs };
}

// Feature-detect: probe whether tls.connect accepts the `ech` option.
// Cached so repeated connect calls don't re-test on every connection.
// Strategy: tls.connect throws synchronously on a port=0 socket attempt
// when the option shape is rejected at the C++ layer with
// ERR_INVALID_ARG_TYPE / ERR_TLS_INVALID_OPTION; if it makes it past
// option-validation we destroy the half-built socket. We never actually
// open a socket — the probe runs entirely in option-parsing.
var _echFeatureProbe = null;
function _isEchSupported() {
  if (_echFeatureProbe !== null) return _echFeatureProbe;
  // The cleanest probe is to read tls.connect.toString() — but Node
  // hides option parsing in C++. Instead we attempt to construct the
  // options object via tls.checkServerIdentity-adjacent surface: call
  // tls.connect with a sentinel `ech: Buffer.alloc(0)` and an
  // immediately-destroyed socket. Any non-throwing path = supported.
  var supported = false;
  try {
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
    // ERR_INVALID_ARG_TYPE or ERR_TLS_* on `ech` = unsupported.
    if (/ech/i.test(msg) || /unknown option/i.test(msg)) supported = false;
    else supported = true;  // unrelated throw (e.g. lookup): option accepted
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
  var port = opts.port === undefined ? 443 : opts.port;                          // HTTPS default port
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
      var connectOpts = {
        host:       opts.host,
        port:       port,
        servername: opts.servername || opts.host,
        minVersion: "TLSv1.3",
      };
      if (Array.isArray(opts.alpn)) connectOpts.ALPNProtocols = opts.alpn.slice();
      if (opts.ipFamily !== undefined) connectOpts.family = opts.ipFamily;
      if (opts.ca !== undefined) connectOpts.ca = _normalizeCaInput(opts.ca);
      if (typeof opts.checkServerIdentity === "function") {
        connectOpts.checkServerIdentity = opts.checkServerIdentity;
      }
      // rejectUnauthorized defaults to true (full validation). An operator may
      // explicitly opt out — audited, never a framework default. Derived from
      // the operator's own value (operator-governed shape, mirroring mail.js /
      // log-stream-syslog.js), not a hardcoded literal.
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
        // ECHConfig present but Node build can't honor it — degrade
        // gracefully with a one-shot warn so operators know they're
        // sending an outer-only ClientHello.
        try {
          observability().safeEvent("network.tls.ech.unsupported", 1, {
            host: opts.host, source: sourceLabel,
          });
        } catch (_e) { /* drop-silent */ }
        try {
          audit().safeEmit({
            action:  "network.tls.ech.unsupported",
            outcome: "success",  // Node lacks `ech` opt — degraded to non-ECH
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
      // Operator-provided ECHConfigList — skip the SVCB lookup, validate
      // shape, then connect.
      var override;
      try {
        var bufOverride = Buffer.isBuffer(opts.echOverride)
          ? opts.echOverride
          : Buffer.from(opts.echOverride, "base64");
        parseEchConfigList(bufOverride);  // validate-only
        override = bufOverride;
      } catch (e) {
        reject(e);
        return;
      }
      _doConnect(override, "override");
      return;
    }

    // Default: SVCB/HTTPS lookup. Per RFC 9460 §2.4 the prefix `_https.`
    // is the SVCB owner-name for an HTTPS origin; modern Node honors a
    // bare HTTPS QTYPE on the apex name though, which is what
    // queryHttps does. We use queryHttps directly.
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
      // DNS failure is not fatal — fall back to non-ECH connect so the
      // operator still gets a working TLS session. Emit obs so the
      // operator sees the degradation.
      try {
        observability().safeEvent("network.tls.ech.dns_failed", 1, {
          host: opts.host, error: (e && e.message) || String(e),
        });
      } catch (_e) { /* drop-silent */ }
      _doConnect(null, "dns-failed");
    });
  });
}

// ---- RFC 9525 strict server identity verification ----------------
//
// RFC 9525 §6 — PKIX name validation:
//   §6.1   The certificate's subjectAltName extension is the
//          authoritative source of identifiers. CN-fallback is
//          forbidden when SAN is present. RFC 9525 §6.4.4 explicitly
//          deprecates CN matching outright; legacy CN-only certs
//          (no SAN) are refused under strict mode.
//   §6.4.3 Wildcard `*.example.com` matches `foo.example.com` (one
//          left-most label) but NOT `foo.bar.example.com` (deeper
//          subdomain) and NOT `example.com` (the wildcard owner
//          itself). Wildcards in the middle (`foo.*.example.com`) or
//          partial wildcards (`f*o.example.com`) are refused.
//   §6.5   IP addresses match against iPAddress entries in SAN, never
//          dNSName entries. Textual IP literals do not get DNS-style
//          wildcard treatment.
//
// Operators pass `b.network.tls.checkServerIdentity9525` to
// `tls.connect({ checkServerIdentity })` to swap Node's permissive
// default for the strict policy.

function _normalizeAsciiHost(host) {
  // RFC 9525 §6.4 — comparisons are ASCII case-insensitive on the
  // A-label form. We don't perform IDNA conversion (operators that
  // need U-label hosts must pre-convert via punycode); raw non-ASCII
  // input is refused so we never silently match across encodings.
  if (typeof host !== "string" || host.length === 0) return null;
  for (var i = 0; i < host.length; i += 1) {
    var cc = host.charCodeAt(i);
    if (cc > 0x7f) return null;                                                  // ASCII upper bound codepoint
  }
  // Strip a trailing dot (FQDN absolute form) for matching.
  var h = host.toLowerCase();
  if (h.length > 1 && h.charAt(h.length - 1) === ".") h = h.slice(0, -1);
  return h;
}

function _matchDnsNamePattern(pattern, host) {
  // Both inputs must be ASCII-normalized. `pattern` is from the SAN;
  // `host` is the operator-supplied target host.
  pattern = _normalizeAsciiHost(pattern);
  if (!pattern || !host) return false;
  if (pattern.indexOf("*") === -1) {
    return pattern === host;
  }
  // Wildcards permitted only as the entire left-most label.
  var pLabels = pattern.split(".");
  var hLabels = host.split(".");
  if (pLabels.length !== hLabels.length) return false;
  if (pLabels.length < 3) return false;  // refuse `*.tld` — too broad
  // Only the FIRST label may contain the wildcard, and it must be `*`
  // exactly (no partial like `f*o`).
  if (pLabels[0] !== "*") return false;
  for (var li = 1; li < pLabels.length; li += 1) {
    if (pLabels[li].indexOf("*") !== -1) return false;
    if (pLabels[li] !== hLabels[li]) return false;
  }
  // Left-most host label must be non-empty (no `*` matching empty).
  if (hLabels[0].length === 0) return false;
  return true;
}

function _parseSanString(rawSubjectAltName) {
  // Node exposes the SAN as a comma-separated string of typed entries:
  //   "DNS:foo.example.com, DNS:*.example.com, IP Address:198.51.100.1,
  //    IP Address:2001:db8::1"
  // The RFC 9525 verifier only consumes DNS / IP entries.
  var dns = [];
  var ips = [];
  if (typeof rawSubjectAltName !== "string" || rawSubjectAltName.length === 0) {
    return { dns: dns, ips: ips };
  }
  var entries = rawSubjectAltName.split(",");
  for (var i = 0; i < entries.length; i += 1) {
    var raw = entries[i].trim();
    var colon = raw.indexOf(":");
    if (colon === -1) continue;
    var kind = raw.slice(0, colon).trim();
    var val  = raw.slice(colon + 1).trim();
    if (kind === "DNS") {
      dns.push(val);
    } else if (kind === "IP Address" || kind === "IP") {
      ips.push(val);
    }
    // Other GeneralName types (URI / email / dirName / OID-based) are
    // outside RFC 9525's HTTPS scope.
  }
  return { dns: dns, ips: ips };
}

function _normalizeIpForCompare(ip) {
  // Lower-case + strip embedded brackets so "[::1]" / "::1" / "::0001"
  // all compare equal.
  if (typeof ip !== "string") return null;
  var s = ip.trim();
  if (s.length >= 2 && s.charAt(0) === "[" && s.charAt(s.length - 1) === "]") {
    s = s.slice(1, -1);
  }
  // For IPv6 the canonical form is what `net.isIP` accepts; we
  // round-trip through Buffer comparison via net.isIPv4 / isIPv6.
  if (net.isIPv4(s)) return { family: 4, text: s };
  if (net.isIPv6(s)) {
    // Canonicalize by expanding to bytes and re-emitting lower-case.
    var parts = s.split("%");                                                    // strip zone id
    var addr = parts[0];
    // Expand "::" then re-collapse via toString won't work in pure JS;
    // instead produce a 16-byte buffer for byte-equal comparison.
    var bytes = _ipv6ToBytes(addr);
    if (!bytes) return null;
    return { family: 6, text: addr.toLowerCase(), bytes: bytes };
  }
  return null;
}
function _ipv6ToBytes(addr) {
  // Minimal IPv6 → 16-byte parser. Splits on "::" once, parses each
  // hextet as base-16 uint16. Returns null on malformed input.
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
  var fillCount = 8 - (left.length + right.length);                              // IPv6 has 8 hextets
  if (fillCount < 0) return null;
  var hextets = left.concat(new Array(fillCount).fill("0")).concat(right);
  if (hextets.length !== 8) return null;                                         // IPv6 hextet count
  var bytes = Buffer.alloc(16);                                                  // IPv6 = 16 bytes
  for (var i = 0; i < 8; i += 1) {                                               // IPv6 hextet count
    var h = hextets[i];
    if (!safeBuffer.IPV6_HEXTET_RE.test(h)) return null;
    var v = parseInt(h, 16);                                                     // hex radix
    bytes[i * 2]     = (v >> 8) & 0xff;                                          // uint8 mask + uint16-half shift
    bytes[i * 2 + 1] = v & 0xff;                                                 // uint8 mask
  }
  return bytes;
}
function _ipsEqual(sanIp, hostIp) {
  var a = _normalizeIpForCompare(sanIp);
  var b = _normalizeIpForCompare(hostIp);
  if (!a || !b) return false;
  if (a.family !== b.family) return false;
  if (a.family === 4) return a.text === b.text;
  // family === 6 — byte compare.
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
  // Drop-in for tls.checkServerIdentity. Returns Error|undefined.
  // Node calls this with the post-handshake `cert` shape: subject,
  // subjectaltname, etc.
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
    // RFC 9525 §6.4.4 forbids CN fallback. A CN-only legacy cert (CN
    // present, no SAN) surfaces the distinct `tls/pkix-cn-fallback-refused`
    // code so audit logs can tell it apart from a cert carrying neither;
    // a cert with no SAN and no CN falls through to `tls/pkix-san-required`.
    // Both refuse — we never fall back to matching on the Common Name.
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
  // DNS host — must match a dNSName SAN entry.
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

// Detect: did the caller pass a CN-only legacy cert? Surface a
// distinct error code so operators can grep audit logs for the
// fallback-refused shape vs a generic mismatch.
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

// Explicit combined verifier kept for tests + callers that want the
// CN-fallback / SAN-required split spelled out. The exported drop-in
// `checkServerIdentity9525` already performs the CN-fallback refusal in
// its no-SAN branch, so the `_refuseCnFallback` call here is a redundant
// (idempotent) belt-and-suspenders; the more specific code wins either way.
function _checkServerIdentityStrict(host, cert) {
  var cnRefusal = _refuseCnFallback(host, cert);
  if (cnRefusal) return cnRefusal;
  return checkServerIdentity9525(host, cert);
}

// CVE-2026-21637 — Node propagates a synchronous throw from an
// operator-supplied SNICallback up through the TLS handshake listener;
// the unhandled throw on an unexpected servername crashes the
// listener. RFC 6066 §3 expects the server to abort the handshake on a
// failed callback, NOT crash the process.
//
// `wrapSNICallback(operatorCb)` returns a wrapper that:
//
//   - Calls the operator callback in a try/catch.
//   - Surface a synchronous throw via the async (err, null) callback so
//     the TLS handshake aborts cleanly. Cb is best-effort: an operator
//     callback that throws AFTER invoking the callback already (double
//     invoke) gets the throw caught here without double-invoking again.
//   - Emit an audit event so a burst of crashes-that-weren't surfaces
//     in operator review.
//   - Returns the operator's original callback unchanged if it's not a
//     function (lets the caller pass undefined through without
//     special-casing).
//
// router.js routes its operator-supplied tlsOptions.SNICallback through
// this helper before handing the options off to https.createServer.
// Any future framework primitive that takes operator SNICallback
// values does the same.
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
  _checkServerIdentityStrict: _checkServerIdentityStrict,
};
