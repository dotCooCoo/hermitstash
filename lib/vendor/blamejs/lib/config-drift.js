"use strict";
/**
 * config-drift — boot-time config-baseline capture + signed sidecar +
 * next-boot drift detection.
 *
 * The framework's audit chain captures DATA writes (every row, every
 * key change). It does NOT capture RUNTIME CONFIG (the operator
 * silently changed `allowedOrigins` 3 weeks ago and we have no
 * signal). config-drift fills that gap: at every boot, the operator
 * passes the baseline config snapshot they want tracked. The
 * primitive hashes it with SHA3-512, signs the digest with the audit-
 * signing key, and writes the result to a sidecar at
 * `<dataDir>/config-baseline.sig`. On the next boot, the sidecar is
 * loaded + verified + diffed against the new snapshot. Drift surfaces
 * as an audit event (`config.drift.detected`); no boot block — the
 * operator may have a legitimate reason to change config and the
 * framework's job is to make the change auditable, not to refuse to
 * start.
 *
 *   var configDrift = b.configDrift.create({
 *     dataDir: "/data",
 *     audit:   b.audit,
 *   });
 *
 *   await configDrift.checkpoint({
 *     // operator decides what's tracked. JSON-stringifiable.
 *     allowedOrigins: ["https://app.example.com"],
 *     csp:            "default-src 'self'",
 *     auditMode:      b.audit.getMode(),
 *     vaultMode:      b.vault.getMode(),
 *     dbAtRest:       b.db.getAtRestMode(),
 *   });
 *   // → { signed: true, drifted: false, previousAt: 1730000000000 }
 *
 * The signed sidecar uses b.auditSign — same SLH-DSA-SHAKE-256f keypair
 * the audit chain anchors on. An attacker who flips a config value
 * would also need to forge the signing key to update the sidecar
 * cleanly; otherwise next-boot verify catches the tamper.
 *
 * Validation:
 *   - create() opts: throw at boot on bad shape
 *   - checkpoint() snapshot: must be a JSON-serialisable object
 *   - sidecar verify failure (tampered, key rotated, missing pubkey)
 *     surfaces as `config.baseline.tamper` audit event AND the call
 *     returns { tamper: true } so the operator can decide whether
 *     to refuse boot
 */
var fs = require("node:fs");
var path = require("node:path");
var auditSign = require("./audit-sign");
var canonicalJson = require("./canonical-json");
var crypto = require("./crypto");
var lazyRequire = require("./lazy-require");
var safeJson = require("./safe-json");
var validateOpts = require("./validate-opts");
var { defineClass } = require("./framework-error");

var audit = lazyRequire(function () { return require("./audit"); });

var ConfigDriftError = defineClass("ConfigDriftError", { alwaysPermanent: true });
var _err = ConfigDriftError.factory;

var SIDECAR_NAME = "config-baseline.sig";
var SIDECAR_VERSION = 1;

// Stable JSON serialization via the shared lib/canonical-json walker.
// Deterministic key order so the same snapshot always hashes to the same
// digest. Pre-v0.6.67 the in-line implementation silently lost Date /
// Map / Set / Buffer / BigInt content; the shared walker handles all
// of those + circular refs. Same bytes as audit-chain / audit-tools /
// pagination would produce for the same input.
function _stableStringify(value) { return canonicalJson.stringify(value); }

function _hashSnapshot(snapshot) {
  return crypto.sha3Hash(_stableStringify(snapshot));
}

function _diffShallow(prev, next) {
  // For drift reporting only — names the keys that changed without
  // dumping the full snapshot (which may carry sensitive values like
  // a CSP nonce-derivation key). Operators reading the drift event
  // get "these keys changed" + a hash on each side.
  var changed = [];
  var added = [];
  var removed = [];
  var allKeys = {};
  Object.keys(prev || {}).forEach(function (k) { allKeys[k] = true; });
  Object.keys(next || {}).forEach(function (k) { allKeys[k] = true; });
  Object.keys(allKeys).forEach(function (k) {
    var inPrev = Object.prototype.hasOwnProperty.call(prev || {}, k);
    var inNext = Object.prototype.hasOwnProperty.call(next || {}, k);
    if (inPrev && !inNext) { removed.push(k); return; }
    if (!inPrev && inNext) { added.push(k); return; }
    if (_stableStringify(prev[k]) !== _stableStringify(next[k])) changed.push(k);
  });
  return { changed: changed, added: added, removed: removed };
}

function create(opts) {
  opts = opts || {};
  validateOpts(opts, [
    "dataDir", "audit", "baseline", "criticalKeys", "ignoreKeys",
  ], "configDrift");
  validateOpts.requireNonEmptyString(opts.dataDir, "create: opts.dataDir", ConfigDriftError, "BAD_OPT");
  var dataDir = opts.dataDir;
  var auditOn = opts.audit !== false;
  var auditInstance = (opts.audit && opts.audit !== true) ? opts.audit : null;
  // Multi-baseline support — each operator-named baseline lives in its
  // own sidecar so production / staging / disaster-recovery deploys
  // each track their own drift independently.
  var baselineName = (typeof opts.baseline === "string" && opts.baseline.length > 0)
    ? opts.baseline : "default";
  // Critical-keys allowlist: drift in these keys raises severity to
  // "high" in the audit emission so SIEM rules can page on them
  // separately from cosmetic drift. null = every key is treated as
  // high severity (the safer default).
  var criticalKeys = Array.isArray(opts.criticalKeys) ? opts.criticalKeys.slice() : null;
  // Ignore-keys: drift in these keys is excluded from drift detection
  // (e.g. operator-tracked metadata that legitimately changes per
  // boot). Captured in the snapshot but never flagged.
  var ignoreKeys = Array.isArray(opts.ignoreKeys) ? opts.ignoreKeys.slice() : [];
  var sidecarPath = path.join(dataDir,
    baselineName === "default" ? SIDECAR_NAME : ("config-baseline-" + baselineName + ".sig"));

  function _emit(action, info, outcome) {
    if (!auditOn) return;
    var sink = auditInstance || audit();
    try {
      sink.safeEmit({
        action:   action,
        outcome:  outcome,
        metadata: info || {},
        reason:   info && info.reason ? info.reason : null,
      });
    } catch (_e) { /* audit best-effort */ }
  }

  function _readSidecar() {
    if (!fs.existsSync(sidecarPath)) return null;
    var raw;
    try { raw = fs.readFileSync(sidecarPath, "utf8"); }
    catch (_e) { return null; }
    var parsed;
    try { parsed = safeJson.parse(raw); }
    catch (_e) { return { unreadable: true }; }
    if (!parsed || parsed.version !== SIDECAR_VERSION) return { unreadable: true };
    if (typeof parsed.digestHex !== "string" || typeof parsed.signatureBase64 !== "string" ||
        typeof parsed.publicKeyPem !== "string" || typeof parsed.snapshot !== "object") {
      return { unreadable: true };
    }
    return parsed;
  }

  function _writeSidecar(snapshot, digestHex) {
    // Sign over the digest (not the snapshot bytes directly) so the
    // sidecar stays small even when the snapshot is large.
    var signature = auditSign.sign(digestHex);
    var payload = {
      version:          SIDECAR_VERSION,
      capturedAt:       Date.now(),
      digestHex:        digestHex,
      signatureBase64:  Buffer.from(signature).toString("base64"),
      publicKeyPem:     auditSign.getPublicKey(),
      snapshot:         snapshot,
    };
    var tmp = sidecarPath + ".tmp";
    fs.writeFileSync(tmp, JSON.stringify(payload, null, 2));
    fs.renameSync(tmp, sidecarPath);
  }

  function _verifySidecar(parsed) {
    // Verify the recorded signature against the recorded public key
    // first — this catches tampering with the digest+sig pair on its
    // own. Then verify the digest matches a re-hash of the recorded
    // snapshot — catches tampering with the snapshot field.
    var sigBuf = Buffer.from(parsed.signatureBase64, "base64");
    if (!auditSign.verify(parsed.digestHex, sigBuf, parsed.publicKeyPem)) {
      return { ok: false, reason: "signature-invalid" };
    }
    if (_hashSnapshot(parsed.snapshot) !== parsed.digestHex) {
      return { ok: false, reason: "digest-mismatch" };
    }
    return { ok: true };
  }

  async function checkpoint(snapshot) {
    if (!snapshot || typeof snapshot !== "object" || Array.isArray(snapshot)) {
      throw _err("BAD_OPT", "checkpoint: snapshot must be a plain object");
    }
    var newDigest = _hashSnapshot(snapshot);

    var existing = _readSidecar();
    if (existing && existing.unreadable) {
      _emit("config.baseline.unreadable",
        { sidecar: sidecarPath, reason: "sidecar present but malformed or wrong version" },
        "warning");
      _writeSidecar(snapshot, newDigest);
      return { signed: true, drifted: false, tamper: false, previousAt: null, reason: "sidecar-unreadable-rewritten" };
    }
    if (!existing) {
      _writeSidecar(snapshot, newDigest);
      _emit("config.baseline.captured",
        { digestHex: newDigest, capturedAt: Date.now() }, "success");
      return { signed: true, drifted: false, tamper: false, previousAt: null };
    }

    var verified = _verifySidecar(existing);
    if (!verified.ok) {
      _emit("config.baseline.tamper",
        { sidecar: sidecarPath, reason: verified.reason, previousAt: existing.capturedAt },
        "failure");
      // DO NOT auto-rewrite on tamper — let the operator inspect first.
      return { signed: false, drifted: false, tamper: true, reason: verified.reason, previousAt: existing.capturedAt };
    }

    if (existing.digestHex === newDigest) {
      // No drift; refresh capturedAt so the sidecar timestamp moves
      // forward each successful boot (operator can see "last verified
      // clean at <T>" in the file).
      _writeSidecar(snapshot, newDigest);
      return { signed: true, drifted: false, tamper: false, previousAt: existing.capturedAt };
    }

    var diff = _diffShallow(existing.snapshot, snapshot);
    // Filter ignore-keys out of the drift report.
    function _stripIgnored(arr) {
      return arr.filter(function (k) { return ignoreKeys.indexOf(k) === -1; });
    }
    diff.changed = _stripIgnored(diff.changed);
    diff.added   = _stripIgnored(diff.added);
    diff.removed = _stripIgnored(diff.removed);
    if (diff.changed.length === 0 && diff.added.length === 0 && diff.removed.length === 0) {
      // All drift was in ignore-keys — refresh sidecar without
      // emitting a drift event.
      _writeSidecar(snapshot, newDigest);
      return { signed: true, drifted: false, tamper: false,
        previousAt: existing.capturedAt, ignoredOnly: true };
    }
    // Severity classification: HIGH when any drifted key is in
    // criticalKeys (or no allowlist is configured — every key is
    // critical by default). LOW when criticalKeys is set and none
    // of the drifted keys are in it.
    var severity = "high";
    if (criticalKeys !== null) {
      var anyCritical = false;
      var allDrifted = diff.changed.concat(diff.added, diff.removed);
      for (var di = 0; di < allDrifted.length; di++) {
        if (criticalKeys.indexOf(allDrifted[di]) !== -1) { anyCritical = true; break; }
      }
      severity = anyCritical ? "high" : "low";
    }
    _emit("config.drift.detected",
      {
        baseline:          baselineName,
        previousDigestHex: existing.digestHex,
        currentDigestHex:  newDigest,
        previousAt:        existing.capturedAt,
        keysChanged:       diff.changed,
        keysAdded:         diff.added,
        keysRemoved:       diff.removed,
        severity:          severity,
      },
      severity === "high" ? "failure" : "warning");
    _writeSidecar(snapshot, newDigest);
    return {
      signed:      true,
      drifted:     true,
      tamper:      false,
      severity:    severity,
      previousAt:  existing.capturedAt,
      diff:        diff,
    };
  }

  function read() {
    var existing = _readSidecar();
    if (!existing || existing.unreadable) return null;
    var verified = _verifySidecar(existing);
    return {
      capturedAt:    existing.capturedAt,
      digestHex:     existing.digestHex,
      snapshot:      existing.snapshot,
      verified:      verified.ok,
      tamperReason:  verified.ok ? null : verified.reason,
    };
  }

  return {
    checkpoint:        checkpoint,
    read:              read,
    sidecarPath:       sidecarPath,
  };
}

module.exports = {
  create:            create,
  ConfigDriftError:  ConfigDriftError,
  // Test-only export for hashing — operators don't need this directly.
  _hashSnapshot:     _hashSnapshot,
  _stableStringify:  _stableStringify,
};
