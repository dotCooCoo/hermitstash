// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module b.configDrift
 * @nav    Observability
 * @title  Config Drift
 *
 * @intro
 *   Monitor + alert when runtime config diverges from a declared
 *   baseline.
 *
 *   The framework's audit chain captures DATA writes (every row, every
 *   key change). It does NOT capture RUNTIME CONFIG — an operator who
 *   silently changes `allowedOrigins` three weeks ago leaves no signal.
 *   `b.configDrift` fills that gap: at every boot the operator passes
 *   the baseline snapshot they want tracked. The primitive hashes it
 *   with SHA3-512, signs the digest with the audit-signing key, and
 *   writes the result to a sidecar at `<dataDir>/config-baseline.sig`.
 *   On the next boot the sidecar is loaded, verified, and diffed
 *   against the new snapshot. Drift surfaces as an audit event
 *   (`config.drift.detected`); no boot block — the operator may have a
 *   legitimate reason to change config, and the framework's job is to
 *   make the change auditable, not to refuse to start.
 *
 *   The signed sidecar uses `b.auditSign` — same SLH-DSA-SHAKE-256f
 *   keypair the audit chain anchors on. An attacker who flips a config
 *   value would also need to forge the signing key to update the
 *   sidecar cleanly; otherwise next-boot verify catches the tamper.
 *
 *   `b.configDrift.verifyVendorIntegrity` is a sibling primitive that
 *   re-hashes every file under `lib/vendor/` against the manifest's
 *   sha256 digests at boot — catches a half-applied vendor refresh,
 *   a corrupted install, or a vendored cjs modified without a manifest
 *   update.
 *
 * @card
 *   Monitor + alert when runtime config diverges from a declared baseline.
 */
var nodePath = require("node:path");
var auditSign = require("./audit-sign");
var canonicalJson = require("./canonical-json");
var bCrypto = require("./crypto");
var lazyRequire = require("./lazy-require");
var safeJson = require("./safe-json");
var validateOpts = require("./validate-opts");
var { defineClass } = require("./framework-error");
var atomicFile = require("./atomic-file");
var C = require("./constants");

var audit = lazyRequire(function () { return require("./audit"); });
var auditEmit = require("./audit-emit");

var ConfigDriftError = defineClass("ConfigDriftError", { alwaysPermanent: true });
var _err = ConfigDriftError.factory;

var SIDECAR_NAME = "config-baseline.sig";
var SIDECAR_VERSION = 1;

// Stable JSON serialization via the shared lib/canonical-json walker.
// Deterministic key order so the same snapshot always hashes to the same
// digest. Pre-v0.6.67 the in-line implementation silently lost Date /
// Map / Set / Buffer / BigInt content; the shared walker handles all
// of those + circular renodeFs. Same bytes as audit-chain / audit-tools /
// pagination would produce for the same input.
function _stableStringify(value) { return canonicalJson.stringify(value); }

function _hashSnapshot(snapshot) {
  return bCrypto.sha3Hash(_stableStringify(snapshot));
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

/**
 * @primitive b.configDrift.create
 * @signature b.configDrift.create(opts)
 * @since     0.6.0
 * @status    stable
 * @related   b.configDrift.verifyVendorIntegrity, b.auditSign.sign, b.audit.safeEmit
 *
 * Build a per-baseline drift detector bound to a `dataDir`. Returns a
 * handle exposing `.checkpoint(snapshot)` (write or compare against the
 * signed sidecar), `.read()` (load + verify the sidecar without
 * mutating it), and `.sidecarPath` (absolute path of the sidecar file).
 *
 * Drift on a key listed in `opts.criticalKeys` surfaces as
 * `config.drift.detected` with `severity: "high"` and outcome
 * `failure`; drift in any other key surfaces as `severity: "low"` and
 * outcome `success`. When `criticalKeys` is omitted every key is
 * treated as high severity. Keys listed in `opts.ignoreKeys` are
 * captured in the snapshot but never raise a drift event.
 *
 * @opts
 *   dataDir:      string,    // directory holding the baseline sidecar (required)
 *   audit:        object,    // b.audit instance; pass false to disable
 *   baseline:     string,    // baseline name — sidecar is `config-baseline-<name>.sig`
 *   criticalKeys: string[],  // keys whose drift raises severity to "high"
 *   ignoreKeys:   string[],  // keys excluded from drift detection
 *
 * @example
 *   var fakeAudit = { safeEmit: function () {} };
 *   var detector = b.configDrift.create({
 *     dataDir:      "/tmp/blamejs-drift-demo",
 *     audit:        fakeAudit,
 *     criticalKeys: ["allowedOrigins", "csp"],
 *     ignoreKeys:   ["bootCount"],
 *   });
 *   detector.sidecarPath;
 *   // → "/tmp/blamejs-drift-demo/config-baseline.sig"
 *
 *   var first = await detector.checkpoint({
 *     allowedOrigins: ["https://app.example.com"],
 *     csp:            "default-src 'self'",
 *     bootCount:      1,
 *   });
 *   first.signed;     // → true
 *   first.drifted;    // → false
 *   first.previousAt; // → null
 */
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
  var sidecarPath = nodePath.join(dataDir,
    baselineName === "default" ? SIDECAR_NAME : ("config-baseline-" + baselineName + ".sig"));

  var _emit = auditEmit.gatedReasonEmitter({ audit: auditOn, sink: auditInstance });

  function _readSidecar() {
    // Capped fd-bound read (no existsSync check-then-read window): the signed
    // config-baseline sidecar is parsed + verified, so a tampered multi-GB file
    // would OOM the reader before signature verify. refuseSymlink stays OFF: the
    // data dir may be a symlink-mounted volume (k8s PVC). Any read failure
    // (missing / too-large) → null, the existing "no baseline yet" behavior.
    var raw;
    try { raw = atomicFile.fdSafeReadSync(sidecarPath, { maxBytes: C.BYTES.mib(1), encoding: "utf8" }); }
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
    // Atomic, symlink-refusing write. The previous hand-rolled form staged
    // into a PREDICTABLE temp name (`sidecarPath + ".tmp"`) via a plain
    // writeFileSync, so an attacker could pre-plant a symlink at that exact
    // path and have the signed sidecar written through it (CWE-59 / CWE-377).
    // writeSync uses a CSPRNG temp name opened O_EXCL | O_NOFOLLOW.
    atomicFile.writeSync(sidecarPath, JSON.stringify(payload, null, 2), { fileMode: 0o600 });
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
        "failure");
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
      severity === "high" ? "failure" : "success");
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

/**
 * @primitive b.configDrift.verifyVendorIntegrity
 * @signature b.configDrift.verifyVendorIntegrity(opts)
 * @since     0.7.39
 * @status    stable
 * @related   b.configDrift.create, b.audit.safeEmit
 *
 * At-boot integrity check over `lib/vendor/*`. MANIFEST.json carries a
 * sha256 digest per bundled file; the call re-hashes each one and
 * surfaces mismatches without throwing. Returns
 * `{ ok, checkedCount, mismatches }` and emits
 * `vendor.integrity.verified` (success) or `vendor.integrity.tampered`
 * (failure) on every invocation so a corrupted install lands in the
 * audit chain at boot, not later.
 *
 * Throws `ConfigDriftError("VENDOR_MANIFEST_MISSING")` when MANIFEST.json
 * is absent and `ConfigDriftError("VENDOR_MANIFEST_SHAPE")` when its
 * top-level `packages` map is missing — operators see a hard fail
 * instead of a silent zero-files-checked pass.
 *
 * @opts
 *   libVendorDir: string,  // absolute path to the lib/vendor tree to verify; default: the framework's own (cwd-independent). Per-file manifest paths resolve under this directory.
 *   manifestPath: string,  // absolute path to MANIFEST.json (defaults under libVendorDir)
 *
 * @example
 *   try {
 *     var result = b.configDrift.verifyVendorIntegrity({
 *       libVendorDir: "/srv/app/lib/vendor",
 *     });
 *     result.ok;            // → true
 *     result.checkedCount;  // → 42
 *     result.mismatches;    // → []
 *   } catch (e) {
 *     e.code; // → "VENDOR_MANIFEST_MISSING"
 *   }
 */
function verifyVendorIntegrity(opts) {
  opts = opts || {};
  // Default to the framework's OWN vendor directory (this module lives in
  // lib/, so __dirname/vendor is lib/vendor) — the tree actually loaded at
  // runtime. The previous cwd-relative default made the check cwd-dependent:
  // run from another directory it read-failed every entry, and under a crafted
  // cwd that happened to hold a clean vendor tree it could hash a DIFFERENT
  // tree than the one loaded. Operators verifying a deployed tree elsewhere
  // pass libVendorDir explicitly; per-file resolution honors it below.
  var libVendorDir  = opts.libVendorDir  || nodePath.join(__dirname, "vendor");
  var manifestPath  = opts.manifestPath  || nodePath.join(libVendorDir, "MANIFEST.json");
  var raw;
  // Capped fd-bound read of the vendor MANIFEST.json (operator-bundled, install-
  // time). refuseSymlink OFF — the vendored tree ships read-only and an install
  // may symlink lib/. The cap precedes the alloc.
  try { raw = atomicFile.fdSafeReadSync(manifestPath, { maxBytes: C.BYTES.mib(4), encoding: "utf8" }); }
  catch (_e) {
    throw _err("VENDOR_MANIFEST_MISSING",
      "vendor MANIFEST.json missing at " + manifestPath, true);
  }
  var manifest = safeJson.parse(raw);
  if (!manifest || typeof manifest.packages !== "object") {
    throw _err("VENDOR_MANIFEST_SHAPE",
      "vendor MANIFEST.json missing `packages` map", true);
  }
  var mismatches = [];
  var checkedCount = 0;
  Object.keys(manifest.packages).forEach(function (pkgName) {
    var pkg = manifest.packages[pkgName];
    var files = (pkg && pkg.files) || {};
    var hashes = (pkg && pkg.hashes) || {};
    Object.keys(files).forEach(function (kind) {
      var rel = files[kind];
      var expected = hashes[kind];
      if (typeof rel !== "string" || typeof expected !== "string") return;
      // Manifest paths are stored repo-root-relative (e.g. "lib/vendor/x.cjs").
      // Resolve each one UNDER libVendorDir (the tree being verified), not
      // process.cwd(), so the check hashes the actual loaded files regardless
      // of the working directory. Strip the leading lib/vendor/ so the join
      // doesn't double it; a manifest that already stored a vendor-relative
      // path resolves the same way.
      var relInVendor = rel.replace(/^lib[\\/]+vendor[\\/]+/, "");
      var abs = nodePath.isAbsolute(rel) ? rel : nodePath.join(libVendorDir, relInVendor);
      var actual;
      try {
        // Capped fd-bound read (raw bytes — hashing, no encoding). Sanity ceiling
        // so a corrupted/huge vendored file is a read-failed mismatch (caught
        // below) rather than an OOM in the boot integrity loop. NO refuseSymlink
        // (vendored tree ships read-only; installs may symlink lib/).
        var bytes = atomicFile.fdSafeReadSync(abs, { maxBytes: C.BYTES.mib(64) });
        actual = "sha256:" + require("node:crypto")
          .createHash("sha256").update(bytes).digest("hex");
      } catch (_e) {
        mismatches.push({ pkg: pkgName, kind: kind, path: rel, expected: expected, actual: "<read-failed>" });
        return;
      }
      checkedCount += 1;
      if (actual !== expected) {
        mismatches.push({ pkg: pkgName, kind: kind, path: rel, expected: expected, actual: actual });
      }
    });
  });
  var ok = mismatches.length === 0;
  try {
    audit().safeEmit({
      action: ok ? "vendor.integrity.verified" : "vendor.integrity.tampered",
      outcome: ok ? "success" : "failure",
      metadata: { checkedCount: checkedCount, mismatchCount: mismatches.length },
    });
  } catch (_e) { /* audit best-effort */ }
  return { ok: ok, checkedCount: checkedCount, mismatches: mismatches };
}

module.exports = {
  create:                  create,
  verifyVendorIntegrity:   verifyVendorIntegrity,
  ConfigDriftError:        ConfigDriftError,
  // Test-only export for hashing — operators don't need this directly.
  _hashSnapshot:           _hashSnapshot,
  _stableStringify:        _stableStringify,
};
