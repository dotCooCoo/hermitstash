// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

var nodeFs = require("node:fs");
var nodePath = require("node:path");
var atomicFile = require("../atomic-file");
var C = require("../constants");
var lazyRequire = require("../lazy-require");
var safeAsync = require("../safe-async");
var safeBuffer = require("../safe-buffer");
var validateOpts = require("../validate-opts");
var { defineClass } = require("../framework-error");
var { boot } = require("../log");

var vault = lazyRequire(function () { return require("./index"); });
var audit = lazyRequire(function () { return require("../audit"); });

var log = boot("vault-seal-pem");

var SealPemFileError = defineClass("SealPemFileError", { alwaysPermanent: true });

var DEFAULT_POLL_MS = 500;

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

  function _auditCallbackFailure(cbErr) {
    _emitAudit("on_error_callback_failed", "failure", { error: cbErr && cbErr.message });
  }

  function _writeSealed(plaintextBytes) {
    var markerPath = destination + ".rewriting";
    var destDir    = nodePath.dirname(destination);
    atomicFile.ensureDir(destDir);
    if (process.platform !== "win32") {
      try {
        var dirStat = nodeFs.statSync(destDir);
        if ((dirStat.mode & 0o022) !== 0) {
          throw new SealPemFileError("seal-pem-file/parent-dir-writable",
            "destination parent dir '" + destDir + "' is group/other-writable " +
            "(mode " + (dirStat.mode & 0o777).toString(8) +
            ") — refuse to seal; chmod 0700 the dir");
        }
      } catch (e) {
        if (e && e.code === "seal-pem-file/parent-dir-writable") throw e;
      }
    }
    var sealed = vault().seal(plaintextBytes);
    atomicFile.writeSync(markerPath, String(Date.now()), { fileMode: 0o600 });
    try {
      atomicFile.writeSync(destination, sealed, { fileMode: 0o600 });
    } catch (e) {
      try { nodeFs.unlinkSync(markerPath); } catch (_e) { /* best-effort */ }
      throw e;
    }
    try { nodeFs.unlinkSync(markerPath); } catch (_e) { /* marker cleanup best-effort */ }
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
      try {
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
        safeAsync.safeInvoke(onError, err, _auditCallbackFailure);
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
        safeAsync.safeInvoke(onError, err2, _auditCallbackFailure);
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
        actor:      (actor && actor.actorId) || null,
        actorReason: (actor && actor.reason) || null,
      });
      safeAsync.safeInvoke(onResealed, {
        srcPath:    source,
        destPath:   destination,
        bytes:      plaintext.length,
        resealedAt: lastResealedAt,
        generation: generation,
      }, function (cbErr) {
        _emitAudit("on_resealed_callback_failed", "failure",
          { error: cbErr && cbErr.message });
      });
    } finally {
      if (plaintext) { try { safeBuffer.secureZero(plaintext); } catch (_e) { /* best-effort */ } }
      resealing = false;
      if (pendingMtime) {
        pendingMtime = null;
        setImmediate(_resealNow);
      }
    }
  }

  function _recoverIfNeeded() {
    var markerPath = destination + ".rewriting";
    if (nodeFs.existsSync(markerPath)) {
      log.info("vault.sealPemFile: recovery — marker '" + markerPath +
        "' present from prior crashed reseal; re-sealing from source");
      _emitAudit("recovery_started", "success", {
        source: source, destination: destination,
      });
    }
  }

  function start() {
    if (watching) return;
    _recoverIfNeeded();
    _resealNow();
    listener = function (curr, prev) {
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

  start();

  return {
    stop:                  stop,
    get generation()       { return generation; },
    get lastResealedAt()   { return lastResealedAt; },
    get lastError()        { return lastError; },
    get watching()         { return watching; },
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
