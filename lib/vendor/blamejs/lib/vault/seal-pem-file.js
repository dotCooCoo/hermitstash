"use strict";
/**
 * vault/seal-pem-file — seal a PEM file at rest with file-watch auto-
 * reseal.
 *
 * Operator workflow this primitive solves: ACME / Let's Encrypt
 * renewals run on a 30-60 day cadence, write fresh certbot output to
 * `/etc/letsencrypt/live/<domain>/privkey.pem`, and signal the
 * application to reload. The fresh PEM lives unencrypted on disk
 * between the renewal write and the next operator-driven re-seal.
 * Auto-reseal closes that window: every renewal writes the plaintext
 * PEM, the framework's watcher sees the mtime change, re-seals on the
 * spot, and the in-process key material rotates without human
 * intervention.
 *
 * Surface:
 *
 *   var watcher = b.vault.sealPemFile({
 *     source:       "/etc/letsencrypt/live/example.com/privkey.pem",
 *     destination:  "/var/lib/blamejs/server.key.sealed",
 *     audit:        true,                 // default
 *     pollInterval: b.constants.TIME.seconds(2),  // fs.watchFile cadence
 *     onResealed:   function (info) { ... }, // { srcPath, destPath, bytes,
 *                                                resealedAt, generation }
 *     onError:      function (err)  { ... }, // sealing failed
 *   });
 *   // watcher.stop()
 *   // watcher.generation        — monotonically increases per reseal
 *   // watcher.lastResealedAt    — Unix-ms of most recent successful reseal
 *   // watcher.lastError         — most recent failure, or null
 *
 * Crash-safe write protocol:
 *
 *   1. Write `<destination>.tmp` with mode 0o600, fsync.
 *   2. Create `<destination>.rewriting` marker (operator-visible).
 *   3. Rename `<destination>.tmp` → `<destination>` (atomic on POSIX).
 *   4. Remove `<destination>.rewriting` marker.
 *
 * If the framework crashes between steps 2 and 4, the marker remains
 * on disk and the next sealPemFile() call detects it. Recovery: the
 * sealedPath is either complete (rename happened) or still .tmp
 * (rename did not happen). The recovery routine re-runs the seal from
 * source — idempotent because the source PEM is the source of truth.
 *
 * fs.watchFile semantics:
 *
 * Node's fs.watchFile is a polling stat() loop with the configured
 * pollInterval. It fires on mtime / size change. fs.watch (the
 * inotify / kqueue backend) is more efficient but inconsistent across
 * platforms — single rename events surface as multiple change events
 * on Linux (events fire on the directory entry, the file, and the
 * inode), and not at all on macOS for renamed-into files. Polling
 * with watchFile is consistent everywhere and the latency cost (one
 * pollInterval) is acceptable for renewal cadences measured in days.
 */

var nodeFs = require("node:fs");
var nodePath = require("node:path");
var atomicFile = require("../atomic-file");
var C = require("../constants");
var lazyRequire = require("../lazy-require");
var safeBuffer = require("../safe-buffer");
var validateOpts = require("../validate-opts");
var { defineClass } = require("../framework-error");
var { boot } = require("../log");

var vault = lazyRequire(function () { return require("./index"); });
var audit = lazyRequire(function () { return require("../audit"); });

var log = boot("vault-seal-pem");

var SealPemFileError = defineClass("SealPemFileError", { alwaysPermanent: true });

// Default poll cadence balances latency against syscall pressure.
// At 2s, ACME renewals (which happen every ~60 days) experience a
// 2-second worst-case re-seal latency — negligible against the
// renewal cadence. Operators with sub-second-sensitive use cases
// override via opts.pollInterval.
// H6 #6 — fs.watchFile default cadence reduced from 2s to 500ms so a
// fast renewal-then-revert (mtime bump then second bump within ~2s)
// doesn't sneak past the watcher. Operators with extremely-quiet
// renewal cycles can override via opts.pollInterval; the cost of
// 500ms polling on an idle PEM file is ~2 stat() syscalls/sec.
var DEFAULT_POLL_MS = 500;

// PEM files are tiny — 4 KiB for an ECDSA key, ~8 KiB for a 4096-bit
// RSA key, ~64 KiB for a long cert chain. Cap at 1 MiB so an operator
// with write access to source can't present a 10 GiB file and OOM the
// host. Operators with genuinely larger inputs override via
// opts.maxSourceBytes.
var DEFAULT_MAX_SOURCE_BYTES = C.BYTES.mib(1);

/**
 * @primitive b.vault.sealPemFile
 * @signature b.vault.sealPemFile(opts)
 * @since     0.8.42
 * @related   b.vault.seal, b.vault.init, b.vaultRotate.rotate
 *
 * Watches a plaintext PEM file (typically certbot's
 * `/etc/letsencrypt/live/<domain>/privkey.pem` after an ACME renewal)
 * and re-seals it to a destination path under the vault keypair on
 * every mtime / size change. Closes the renewal-window gap where a
 * fresh PEM lives unencrypted on disk between certbot's write and
 * the next operator-driven re-seal.
 *
 * Crash-safe write protocol: write `<destination>.tmp` at mode
 * `0o600`, fsync, create a `<destination>.rewriting` marker, atomic
 * rename, fsync the destination directory, remove the marker. If
 * the framework crashes between marker create and marker remove,
 * the next `sealPemFile()` start re-seals from source idempotently.
 *
 * Refuses to seal in place (source === destination), refuses to
 * follow a symlinked source (TOCTOU defense), and refuses when the
 * destination's parent directory is group- or other-writable on
 * POSIX. Source size is capped (`maxSourceBytes`, default 1 MiB)
 * so an attacker with write access to source can't OOM the host
 * with a 10 GiB file.
 *
 * Returns a watcher handle: `start` (auto-called by the constructor
 * unless overridden), `stop`, `forceReseal({ actorId, reason })`,
 * plus read-only `generation` / `lastResealedAt` / `lastError` /
 * `watching` properties.
 *
 * @opts
 *   {
 *     source:         string,    // plaintext PEM path (required)
 *     destination:    string,    // sealed-output path (required, must differ from source)
 *     audit:          boolean,   // emit b.audit events on every reseal (default true)
 *     pollInterval:   number,    // fs.watchFile cadence in ms (default 500)
 *     onResealed:     function,  // (info) => void — { srcPath, destPath, bytes, resealedAt, generation }
 *     onError:        function,  // (err)  => void — sealing failed
 *     maxSourceBytes: number,    // refuse source larger than this (default 1 MiB)
 *   }
 *
 * @example
 *   await b.vault.init({ dataDir: "/var/lib/blamejs", mode: "wrapped" });
 *
 *   var watcher = b.vault.sealPemFile({
 *     source:       "/etc/letsencrypt/live/example.com/privkey.pem",
 *     destination:  "/var/lib/blamejs/server.key.sealed",
 *     pollInterval: b.constants.TIME.seconds(2),
 *     onResealed:   function (info) {
 *       console.log("resealed", info.bytes, "bytes, gen", info.generation);
 *     },
 *     onError:      function (err) {
 *       console.error("reseal failed:", err.message);
 *     },
 *   });
 *
 *   watcher.generation;        // → 1   (initial seal completed)
 *   typeof watcher.lastResealedAt; // → "number"
 *
 *   // Force a reseal after a manual ACME renewal — captured in audit.
 *   watcher.forceReseal({ actorId: "ops-bot", reason: "manual-renewal" });
 *
 *   // Stop watching at shutdown.
 *   watcher.stop();
 */
function sealPemFile(opts) {
  opts = opts || {};
  validateOpts(opts, [
    "source", "destination", "audit", "pollInterval",
    "onResealed", "onError", "maxSourceBytes",
  ], "vault.sealPemFile");

  validateOpts.requireNonEmptyString(opts.source,
    "vault.sealPemFile: source must be a non-empty path",
    SealPemFileError, "seal-pem-file/bad-source");
  validateOpts.requireNonEmptyString(opts.destination,
    "vault.sealPemFile: destination must be a non-empty path",
    SealPemFileError, "seal-pem-file/bad-destination");
  if (opts.source === opts.destination) {
    throw new SealPemFileError("seal-pem-file/same-path",
      "vault.sealPemFile: source and destination must differ — sealing in place would overwrite the plaintext");
  }
  validateOpts.optionalPositiveFinite(opts.pollInterval,
    "vault.sealPemFile: pollInterval", SealPemFileError, "seal-pem-file/bad-poll-interval");
  validateOpts.optionalFunction(opts.onResealed,
    "vault.sealPemFile: onResealed", SealPemFileError, "seal-pem-file/bad-on-resealed");
  validateOpts.optionalFunction(opts.onError,
    "vault.sealPemFile: onError", SealPemFileError, "seal-pem-file/bad-on-error");

  var source        = opts.source;
  var destination   = opts.destination;
  // optionalPositiveFinite above already threw on a bad-shaped opts.pollInterval;
  // here only undefined / null / valid-positive-finite remain.
  var pollInterval  = opts.pollInterval || DEFAULT_POLL_MS;
  var onResealed    = typeof opts.onResealed === "function" ? opts.onResealed : null;
  var onError       = typeof opts.onError === "function" ? opts.onError : null;
  validateOpts.optionalPositiveFinite(opts.maxSourceBytes,
    "vault.sealPemFile: maxSourceBytes", SealPemFileError, "seal-pem-file/bad-max-source-bytes");
  var maxSourceBytes = opts.maxSourceBytes || DEFAULT_MAX_SOURCE_BYTES;

  var generation       = 0;
  var lastResealedAt   = null;
  var lastError        = null;
  var watching         = false;
  var listener         = null;
  var resealing        = false;
  var pendingMtime     = null;

  var _emitAudit = audit().namespaced("vault.seal_pem_file", opts.audit);

  function _writeSealed(plaintextBytes) {
    // atomicFile.writeSync already does the .tmp + fsync + rename +
    // fsyncDir sequence atomically. The marker is the framework's
    // operator-visible crash-detection signal — created BEFORE the
    // atomic rename, removed AFTER. If the framework crashes between
    // marker create and marker remove, the marker remains on disk
    // and _recoverIfNeeded() detects it on the next start().
    var markerPath = destination + ".rewriting";
    var destDir    = nodePath.dirname(destination);
    atomicFile.ensureDir(destDir);
    // H6 #4 — assert parent-dir mode. If the directory is world-
    // writable, an attacker can swap the destination file or the
    // .rewriting marker between our writeFileSync and the atomic
    // rename. Refuse on group-/other-writable parent dirs (POSIX
    // mode bits 0o022). On Windows the stat mode is synthetic;
    // skip the check there.
    if (process.platform !== "win32") {
      try {
        var dirStat = nodeFs.statSync(destDir);
        if ((dirStat.mode & 0o022) !== 0) {                                       // POSIX mode mask
          throw new SealPemFileError("seal-pem-file/parent-dir-writable",
            "destination parent dir '" + destDir + "' is group/other-writable " +
            "(mode " + (dirStat.mode & 0o777).toString(8) +                       // POSIX mode mask
            ") — refuse to seal; chmod 0700 the dir");
        }
      } catch (e) {
        if (e && e.code === "seal-pem-file/parent-dir-writable") throw e;
        // stat itself failing is not fatal — the writeFileSync below will surface it.
      }
    }
    var sealed = vault().seal(plaintextBytes);
    // Atomic, symlink-refusing marker write (matches the destination write
    // just below) — a bare writeFileSync would follow a symlink planted at
    // markerPath (CWE-59).
    atomicFile.writeSync(markerPath, String(Date.now()), { fileMode: 0o600 });   // POSIX file mode
    try {
      atomicFile.writeSync(destination, sealed, { fileMode: 0o600 });    // POSIX file mode
    } catch (e) {
      try { nodeFs.unlinkSync(markerPath); } catch (_e) { /* best-effort */ }
      throw e;
    }
    try { nodeFs.unlinkSync(markerPath); } catch (_e) { /* marker cleanup best-effort */ }
    // H6 #5 — fsync the destination directory so the rename + marker
    // unlink survive a power loss. Crash + backup-snapshot edge case:
    // without dir-fsync, a journaled fs may have the new file inode
    // but not the directory entry update by the time the snapshot
    // reads.
    try {
      var dirFd = nodeFs.openSync(destDir, "r");
      try { nodeFs.fsyncSync(dirFd); }
      finally { nodeFs.closeSync(dirFd); }
    } catch (_e) { /* dir fsync best-effort — Windows / non-POSIX may refuse */ }
  }

  function _resealNow(actor) {
    if (resealing) return;
    resealing = true;
    var plaintext = null;
    try {
      // H6 #1 — bounded read. nodeFs.readFileSync without a size cap on a
      // file the operator's renewal process writes is an OOM vector.
      // H6 #3 — symlink TOCTOU defense. Open the file via nodeFs.openSync
      // with O_NOFOLLOW where possible; lstat first to verify the
      // source isn't a symlink we don't expect, then read via fd so
      // a swap-after-stat doesn't change which bytes we read.
      try {
        // TOCTOU-safe read via atomic-file with the strongest guards:
        // symlink refusal + inode-equality + a byte cap. The bespoke
        // SealPemFileError codes/messages are preserved via errorFor; this
        // call sits inside the outer try/catch that wraps any failure into
        // seal-pem-file/source-read-failed + audit + the onError callback.
        plaintext = atomicFile.fdSafeReadSync(source, {
          refuseSymlink: true,
          inodeCheck:    true,
          maxBytes:      maxSourceBytes,
          errorFor: function (kind, detail) {
            if (kind === "symlink") {
              return new SealPemFileError("seal-pem-file/symlink-refused",
                "source is a symlink (refused; follow + re-stat opens TOCTOU)");
            }
            if (kind === "too-large") {
              return new SealPemFileError("seal-pem-file/source-too-large",
                "source size " + detail.size + " exceeds maxSourceBytes " + maxSourceBytes);
            }
            if (kind === "toctou") {
              return new SealPemFileError("seal-pem-file/toctou-detected",
                "source mutated between lstat and open (TOCTOU defense)");
            }
            if (kind === "short-read") {
              return new SealPemFileError("seal-pem-file/short-read",
                "short read: " + detail.read + " of " + detail.size + " bytes");
            }
            return undefined;
          },
        });
      }
      catch (e) {
        var err = new SealPemFileError("seal-pem-file/source-read-failed",
          "vault.sealPemFile: failed to read source '" + source + "': " + e.message);
        lastError = err;
        _emitAudit("read_failed", "failure", { source: source, error: e.message });
        if (onError) {
          try { onError(err); }
          catch (cbErr) {
            // H6 #7 — operator callback throw is captured in audit
            // rather than dropped silently.
            _emitAudit("on_error_callback_failed", "failure",
              { error: cbErr && cbErr.message });
          }
        }
        return;
      }
      try {
        _writeSealed(plaintext);
      } catch (e2) {
        var err2 = new SealPemFileError("seal-pem-file/seal-failed",
          "vault.sealPemFile: failed to seal '" + source + "' to '" + destination + "': " + e2.message);
        lastError = err2;
        _emitAudit("seal_failed", "failure", {
          source: source, destination: destination, error: e2.message,
        });
        if (onError) {
          try { onError(err2); }
          catch (cbErr) {
            _emitAudit("on_error_callback_failed", "failure",
              { error: cbErr && cbErr.message });
          }
        }
        return;
      }
      generation += 1;
      lastResealedAt = Date.now();
      lastError = null;
      _emitAudit("resealed", "success", {
        source:     source,
        destination: destination,
        bytes:      plaintext.length,
        generation: generation,
        // H6 #8 — actor is captured when forceReseal({ actor }) is
        // called explicitly. Watcher-driven resealings record actor=null
        // (the kernel's mtime-change notification has no operator).
        actor:      (actor && actor.actorId) || null,
        actorReason: (actor && actor.reason) || null,
      });
      if (onResealed) {
        try {
          onResealed({
            srcPath:    source,
            destPath:   destination,
            bytes:      plaintext.length,
            resealedAt: lastResealedAt,
            generation: generation,
          });
        } catch (cbErr) {
          // H6 #7 — operator callback throw lands in audit.
          _emitAudit("on_resealed_callback_failed", "failure",
            { error: cbErr && cbErr.message });
        }
      }
    } finally {
      // H6 #2 — zero plaintext PEM bytes from the heap. V8 may have
      // copied the buffer internally (string interning, GC compaction)
      // but the explicit zero ensures the operator-visible buffer no
      // longer holds the secret.
      if (plaintext) { try { safeBuffer.secureZero(plaintext); } catch (_e) { /* best-effort */ } }
      resealing = false;
      if (pendingMtime) {
        // A change event arrived while we were resealing — reseal again
        // so the latest source bytes land. Single-flight: only one
        // pending reseal is queued.
        pendingMtime = null;
        setImmediate(_resealNow);
      }
    }
  }

  // Recover from a prior crash: if the marker is present, the previous
  // reseal was interrupted. Re-seal from source idempotently.
  function _recoverIfNeeded() {
    var markerPath = destination + ".rewriting";
    if (nodeFs.existsSync(markerPath)) {
      log.info("vault.sealPemFile: recovery — marker '" + markerPath +
        "' present from prior crashed reseal; re-sealing from source");
      _emitAudit("recovery_started", "success", {
        source: source, destination: destination,
      });
      // Don't unlink the marker yet — _writeSealed will rewrite it
      // and remove it as part of the normal sequence.
    }
  }

  function start() {
    if (watching) return;
    _recoverIfNeeded();
    // Initial seal — operator gets the destination populated on
    // start() even if the source's mtime never changes.
    _resealNow();
    listener = function (curr, prev) {
      // mtime change OR the source appearing for the first time.
      if (curr.mtimeMs !== prev.mtimeMs || curr.size !== prev.size) {
        if (resealing) { pendingMtime = curr.mtimeMs; return; }
        _resealNow();
      }
    };
    nodeFs.watchFile(source, { persistent: false, interval: pollInterval }, listener);
    watching = true;
    _emitAudit("watch_started", "success", {
      source:       source,
      destination:  destination,
      pollInterval: pollInterval,
    });
  }

  function stop() {
    if (!watching) return;
    nodeFs.unwatchFile(source, listener);
    listener = null;
    watching = false;
    _emitAudit("watch_stopped", "success", {
      source:      source,
      destination: destination,
      generation:  generation,
    });
  }

  // Auto-start so the operator's `var watcher = sealPemFile(...)` call
  // produces a populated destination immediately. Operators wiring it
  // into a deferred lifecycle override by passing autoStart: false —
  // not yet a frequent enough use case to surface, opens cleanly when
  // the first operator surfaces it.
  start();

  return {
    stop:                  stop,
    get generation()       { return generation; },
    get lastResealedAt()   { return lastResealedAt; },
    get lastError()        { return lastError; },
    get watching()         { return watching; },
    // Force a reseal — useful for tests and operator-triggered rotations
    // (e.g. after a manual ACME renewal). Idempotent: produces an
    // updated destination from the current source bytes. Accepts
    // { actorId, reason } for forensic audit-trail capture (H6 #8).
    forceReseal:           function (actorOpts) {
      _resealNow(actorOpts && typeof actorOpts === "object" ? actorOpts : null);
    },
  };
}

module.exports = {
  sealPemFile:        sealPemFile,
  SealPemFileError:   SealPemFileError,
  DEFAULT_POLL_MS:    DEFAULT_POLL_MS,
};
