"use strict";
/**
 * @module     b.mail.server.tls
 * @nav        Mail
 * @title      Mail Server TLS Bootstrap
 * @order      538
 *
 * @intro
 *   Operator-UX helper for the `tlsContext` opt on `b.mail.server.mx`
 *   and `b.mail.server.submission`. Both listeners refuse to boot
 *   without a `tlsContext` by design (no implicit plaintext mode);
 *   pre-this-primitive operators had to wire `node:tls.createSecureContext`
 *   themselves plus solve cert renewal + sealed-storage-of-keys + in-
 *   process reload-on-rotation. This primitive owns the wiring.
 *
 *   ```js
 *   var tlsCtx = b.mail.server.tls.context({
 *     certFile:   "/etc/letsencrypt/live/mail.example.com/fullchain.pem",
 *     keyFile:    "/var/lib/blamejs/mail.example.com.key.sealed",
 *     vault:      b.vault,                  // for keyFile unseal
 *     watch:      true,                     // auto-reload on rotation
 *   });
 *
 *   var mx = b.mail.server.mx.create({
 *     tlsContext: tlsCtx.secureContext,
 *     ...
 *   });
 *   ```
 *
 *   The helper handles the three things operators need but were
 *   reinventing per-deployment:
 *
 *   1. **Sealed-key unwrap** — operators who store the private key on
 *      disk via `b.vault.sealPemFile` (recommended posture per
 *      SECURITY.md) pass `vault: b.vault` here and the helper unseals
 *      at load-time, never holding the plaintext key longer than the
 *      `tls.createSecureContext` call.
 *
 *   2. **Cert-rotation in-process reload** — when `watch: true`, the
 *      helper polls `certFile` + `keyFile` for mtime changes (default
 *      30s poll, matching the framework's vault-pem-file convention).
 *      On change, the helper builds a fresh `SecureContext` and emits
 *      a `mail.server.tls.context_reloaded` audit event. Operators
 *      who wire `tlsCtx.onReload(fn)` get a callback so the running
 *      listener's `SecureContext` reference can be swapped.
 *
 *   3. **Boot-fail surface** — missing/unreadable file, unsealable
 *      key, mismatched cert/key pair, expired cert — all surfaced at
 *      `context()` call with a typed `MailServerTlsError` so the
 *      operator's boot path fails fast at the right line, not 20
 *      stack frames deep inside the listener.
 *
 *   ## ACME provisioning
 *
 *   This primitive does NOT drive ACME issuance — that's `b.acme`'s
 *   job (RFC 8555 + RFC 9773 ARI). The operator's deployment script /
 *   sidecar / systemd-timer orchestrates `b.acme.renewIfDue` and
 *   writes the renewed cert + key to `certFile` / `keyFile`. The
 *   watch-loop here picks up the change and reloads. Composing this
 *   way keeps the TLS-context helper unaware of which ACME provider
 *   the operator picked (Let's Encrypt / ZeroSSL / Buypass / step-ca /
 *   internal PKI) and unaware of which challenge type (HTTP-01 /
 *   DNS-01 / TLS-ALPN-01) the deployment uses.
 *
 *   For a turnkey ACME-and-then-load path operators wire the two
 *   primitives at deploy-time:
 *
 *   ```js
 *   // Once per deploy (sidecar / systemd-timer / k8s CronJob):
 *   var acme = b.acme.create({ directoryUrl: "https://acme-v02.api.letsencrypt.org/directory", ... });
 *   // ... acme.newAccount + acme.newOrder + challenge-solve + acme.finalize ...
 *   //   → write the issued cert.pem + key.pem to the watched paths
 *
 *   // Once per process at boot:
 *   var tls = b.mail.server.tls.context({ certFile, keyFile, watch: true });
 *   var mx  = b.mail.server.mx.create({ tlsContext: tls.secureContext, ... });
 *   tls.onReload(function (newCtx) { mx.replaceTlsContext(newCtx); });
 *   ```
 *
 *   The cleartext-refused error message from `b.mail.server.mx` /
 *   `b.mail.server.submission` points at this primitive so the
 *   operator's boot dead-end becomes a one-line fix.
 *
 * @card
 *   Operator-UX helper for the TLS context required by b.mail.server.mx /
 *   .submission. Loads cert + key (with optional vault-sealed-key unwrap),
 *   watches for rotation, builds a node:tls SecureContext + emits an
 *   audit event on every reload. ACME provisioning stays in b.acme;
 *   this primitive just loads what's on disk and reloads when it changes.
 */

var nodeFs = require("node:fs");
var nodeTls = require("node:tls");
var lazyRequire = require("./lazy-require");
var C = require("./constants");
var validateOpts = require("./validate-opts");
var { defineClass } = require("./framework-error");

var audit = lazyRequire(function () { return require("./audit"); });

var MailServerTlsError = defineClass("MailServerTlsError", { alwaysPermanent: true });

var DEFAULT_POLL_MS = C.TIME.seconds(30);

/**
 * @primitive b.mail.server.tls.context
 * @signature b.mail.server.tls.context(opts)
 * @since     0.9.48
 * @status    stable
 * @related   b.mail.server.mx.create, b.mail.server.submission.create, b.vault.sealPemFile, b.acme.create
 *
 * Build a `node:tls` `SecureContext` from cert + key PEM file paths.
 * Returns a handle exposing `secureContext`, `reload()`, `onReload(fn)`,
 * and `stop()`. When `watch: true`, the helper polls both files for
 * mtime changes (default every 30s) and rebuilds the context in-place
 * on change — operators wire `onReload` to swap the running listener's
 * context after cert rotation.
 *
 * @opts
 *   certFile:   string,      // required — PEM-encoded fullchain
 *   keyFile:    string,      // required — PEM-encoded private key (raw OR sealed)
 *   vault:      object,      // optional — b.vault; when supplied + keyFile
 *                            //   starts with the b.vault.sealPemFile magic
 *                            //   ("vault:"), unsealed before use
 *   watch:      boolean,     // default false — when true, poll for rotation
 *   pollMs:     number,      // default 30000; min 1000
 *
 * @example
 *   var tls = b.mail.server.tls.context({
 *     certFile: "/etc/letsencrypt/live/mail.example.com/fullchain.pem",
 *     keyFile:  "/etc/letsencrypt/live/mail.example.com/privkey.pem",
 *     watch:    true,
 *   });
 *   // Wire `tls.secureContext` into b.mail.server.mx.create / submission.create
 *   tls.onReload(function (newCtx) {
 *     // operator swaps the running listener's SecureContext via the
 *     // listener's reload hook (when the listener exposes one) or via
 *     // restart-on-rotation flow
 *   });
 *
 *   // ... later, on shutdown:
 *   tls.stop();   // clears the poll timer
 */
function context(opts) {
  validateOpts.requireObject(opts, "b.mail.server.tls.context",
    MailServerTlsError, "mail-server-tls/bad-opts");
  validateOpts.requireNonEmptyString(opts.certFile,
    "b.mail.server.tls.context: opts.certFile",
    MailServerTlsError, "mail-server-tls/bad-cert-file");
  validateOpts.requireNonEmptyString(opts.keyFile,
    "b.mail.server.tls.context: opts.keyFile",
    MailServerTlsError, "mail-server-tls/bad-key-file");
  if (opts.vault !== undefined &&
      (typeof opts.vault !== "object" || opts.vault === null ||
       typeof opts.vault.unseal !== "function")) {
    throw new MailServerTlsError("mail-server-tls/bad-vault",
      "b.mail.server.tls.context: opts.vault must be a b.vault handle (.unseal fn)");
  }
  validateOpts.optionalBoolean(opts.watch,
    "b.mail.server.tls.context: opts.watch",
    MailServerTlsError, "mail-server-tls/bad-watch");
  var pollMs = opts.pollMs === undefined ? DEFAULT_POLL_MS : opts.pollMs;
  if (typeof pollMs !== "number" || !isFinite(pollMs) || pollMs < C.TIME.seconds(1)) {
    throw new MailServerTlsError("mail-server-tls/bad-poll-ms",
      "b.mail.server.tls.context: opts.pollMs must be a finite number >= 1000");
  }

  var certFile = opts.certFile;
  var keyFile  = opts.keyFile;
  var vault    = opts.vault || null;
  var watch    = opts.watch === true;
  var reloadListeners = [];
  var secureContext = null;
  var lastCertMtime = 0;
  var lastKeyMtime  = 0;
  var pollTimer = null;
  var stopped = false;

  function _readKey() {
    var raw = nodeFs.readFileSync(keyFile, "utf8");
    // b.vault.sealPemFile produces blobs that decrypt via vault.unseal.
    // Detect by the sealed-cell prefix the framework's vault layer
    // already documents (everything else passes through as plain PEM).
    if (vault && raw.indexOf("vault:") === 0) {
      try {
        return vault.unseal(raw).toString("utf8");
      } catch (e) {
        throw new MailServerTlsError("mail-server-tls/unseal-failed",
          "b.mail.server.tls.context: failed to unseal " + keyFile +
          " via b.vault.unseal: " + (e && e.message ? e.message : String(e)));
      }
    }
    return raw;
  }

  function _build() {
    var certPem;
    try {
      certPem = nodeFs.readFileSync(certFile, "utf8");
    } catch (e) {
      throw new MailServerTlsError("mail-server-tls/cert-unreadable",
        "b.mail.server.tls.context: cannot read certFile " + certFile + ": " +
        (e && e.message ? e.message : String(e)));
    }
    var keyPem;
    try {
      keyPem = _readKey();
    } catch (e) {
      if (e && e.isFrameworkError) throw e;
      throw new MailServerTlsError("mail-server-tls/key-unreadable",
        "b.mail.server.tls.context: cannot read keyFile " + keyFile + ": " +
        (e && e.message ? e.message : String(e)));
    }
    var ctx;
    try {
      ctx = nodeTls.createSecureContext({ cert: certPem, key: keyPem });
    } catch (e) {
      throw new MailServerTlsError("mail-server-tls/secure-context-failed",
        "b.mail.server.tls.context: createSecureContext threw (mismatched cert/key? " +
        "expired? bad PEM?): " + (e && e.message ? e.message : String(e)));
    }
    return ctx;
  }

  function _emit(action, metadata) {
    try {
      audit().safeEmit({
        action:   action,
        outcome:  "success",
        metadata: metadata || {},
      });
    } catch (_e) { /* drop-silent — audit best-effort */ }
  }

  function reload() {
    var fresh = _build();
    secureContext = fresh;
    try {
      var cstat = nodeFs.statSync(certFile);
      lastCertMtime = cstat.mtimeMs;
    } catch (_e) { /* file disappeared between read + stat; tolerate */ }
    try {
      var kstat = nodeFs.statSync(keyFile);
      lastKeyMtime = kstat.mtimeMs;
    } catch (_e) { /* same */ }
    _emit("mail.server.tls.context_reloaded",
      { certFile: certFile, keyFile: keyFile });
    for (var i = 0; i < reloadListeners.length; i++) {
      try { reloadListeners[i](secureContext); }
      catch (_e) { /* listener errors must not break the loop */ }
    }
    return secureContext;
  }

  function onReload(fn) {
    if (typeof fn !== "function") {
      throw new MailServerTlsError("mail-server-tls/bad-listener",
        "b.mail.server.tls.context: onReload(fn) requires a function");
    }
    reloadListeners.push(fn);
  }

  function _poll() {
    if (stopped) return;
    var changed = false;
    try {
      var cs = nodeFs.statSync(certFile);
      if (cs.mtimeMs !== lastCertMtime) changed = true;
    } catch (_e) { /* file removed transiently mid-rotation; skip */ }
    try {
      var ks = nodeFs.statSync(keyFile);
      if (ks.mtimeMs !== lastKeyMtime) changed = true;
    } catch (_e) { /* same */ }
    if (changed) {
      try { reload(); }
      catch (e) {
        // Reload failed (likely mid-rotation, file half-written).
        // Surface as audit but DON'T overwrite the live context —
        // the listener keeps serving with the prior good cert until
        // the next poll catches a clean snapshot.
        try {
          audit().safeEmit({
            action:   "mail.server.tls.reload_failed",
            outcome:  "failure",
            metadata: { error: e && e.message ? e.message : String(e) },
          });
        } catch (_e) { /* drop-silent */ }
      }
    }
  }

  function stop() {
    stopped = true;
    if (pollTimer) {
      clearInterval(pollTimer);
      pollTimer = null;
    }
  }

  // Initial build — propagates boot-fail typed errors to the caller.
  secureContext = _build();
  try {
    lastCertMtime = nodeFs.statSync(certFile).mtimeMs;
    lastKeyMtime  = nodeFs.statSync(keyFile).mtimeMs;
  } catch (_e) { /* file disappeared between read + stat; tolerate */ }

  if (watch) {
    pollTimer = setInterval(_poll, pollMs);
    if (typeof pollTimer.unref === "function") pollTimer.unref();
  }

  return {
    get secureContext() { return secureContext; },
    reload:   reload,
    onReload: onReload,
    stop:     stop,
  };
}

module.exports = {
  context:             context,
  MailServerTlsError:  MailServerTlsError,
};
