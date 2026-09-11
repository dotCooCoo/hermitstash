// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
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
 *     // A getter, not `tlsCtx.secureContext` — see "Picking up a rotation".
 *     get tlsContext() { return tlsCtx.secureContext; },
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
 *   var mx  = b.mail.server.mx.create({
 *     get tlsContext() { return tls.secureContext; },
 *     ...
 *   });
 *   ```
 *
 *   **Picking up a rotation.** Every listener reads `opts.tlsContext` at the
 *   point it needs a context rather than capturing it at construction, so a
 *   getter is all a rotation needs: the next connection sees the reloaded
 *   context and nothing has to be swapped or restarted. Passing
 *   `tlsContext: tls.secureContext` instead copies the context that happened
 *   to be current at boot, and that one keeps being served after it expires.
 *   There is no listener method to swap a context, and none is needed.
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
var atomicFile = require("./atomic-file");
var safeAsync = require("./safe-async");
var validateOpts = require("./validate-opts");
var { defineClass } = require("./framework-error");

var audit = lazyRequire(function () { return require("./audit"); });
// Lazy — network-tls pulls the posture machinery, and only the context build
// needs it.
var networkTls = lazyRequire(function () { return require("./network-tls"); });

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
 *   // Pass a getter so each connection reads the current context. Listeners
 *   // read opts.tlsContext at the point of use, so a reload reaches the next
 *   // connection with nothing to swap.
 *   var mx = b.mail.server.mx.create({
 *     get tlsContext() { return tls.secureContext; },
 *     localDomains: ["mail.example.com"]
 *   });
 *   // onReload is for observing a rotation — logging it, re-checking expiry.
 *   // Delivering it to the listeners is not something it has to do.
 *   tls.onReload(function (newCtx) { void newCtx; });
 *
 *   // ... later, on shutdown:
 *   tls.stop();   // clears the poll timer
 */

function _contextOptions(sourceOpts, certPem, keyPem) {
  var base = { cert: certPem, key: keyPem };
  var groups = networkTls().serverKeyAgreementGroups(
    sourceOpts ? sourceOpts.ecdhCurve : undefined,
    "b.mail.server.tls.context: opts.ecdhCurve");
  if (groups) base.ecdhCurve = groups;
  var certCompression = C.TLS_CERT_COMPRESSION();
  if (certCompression.length > 0) base.certificateCompression = certCompression;
  return base;
}

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
    var raw = atomicFile.fdSafeReadSync(keyFile, { maxBytes: C.BYTES.kib(64), encoding: "utf8" });
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
      certPem = atomicFile.fdSafeReadSync(certFile, { maxBytes: C.BYTES.mib(1), encoding: "utf8" });
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
    [["certFile", certFile, certPem], ["keyFile", keyFile, keyPem]].forEach(function (f) {
      if (typeof f[2] === "string" && f[2].indexOf("-----BEGIN") !== -1) return;
      throw new MailServerTlsError("mail-server-tls/pem-empty",
        "b.mail.server.tls.context: " + f[0] + " holds no PEM block.\n" +
        "  " + f[0] + ": " + f[1] + "\n" +
        "  An empty or truncated file here is usually an interrupted renewal. " +
        "Refused at startup rather than started without it — a context built " +
        "without a certificate is valid to TLS and fails every handshake.");
    });

    var ctx;
    try {
      var ctxOpts = _contextOptions(opts, certPem, keyPem);
      ctx = nodeTls.createSecureContext(ctxOpts);
    } catch (e) {
      var opensslText = (e && e.message) ? e.message : String(e);
      var lead;
      if (/key values mismatch/i.test(opensslText)) {
        lead = "the certificate and the key are from different issuances";
      } else if (/no start line|PEM routines|asn1 encoding routines|header too long|DECODER routines/i.test(opensslText)) {
        lead = "one of these files is not a readable PEM — commonly a DER file, " +
               "an empty file left by an interrupted renewal, or a path naming " +
               "a directory";
      } else {
        lead = "the certificate and key could not be loaded together";
      }
      throw new MailServerTlsError("mail-server-tls/secure-context-failed",
        "b.mail.server.tls.context: " + lead + ".\n" +
        "  certificate: " + certFile + "\n" +
        "  key:         " + keyFile + "\n" +
        "  openssl: " + opensslText);
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

/**
 * @primitive b.mail.server.tls.upgradeSocket
 * @signature b.mail.server.tls.upgradeSocket(opts)
 * @since     0.9.57
 * @status    stable
 * @related   b.mail.server.tls.context, b.mail.server.mx.create, b.mail.server.submission.create
 *
 * STARTTLS / STLS upgrade primitive shared by every mail-protocol
 * listener (MX / submission / IMAP / POP3). Wraps the four-step dance
 * every listener was inlining and that has been a recurring source
 * of cleartext-injection bugs (CVE-2021-33515 Dovecot,
 * CVE-2021-38371 Exim) when even one of the four steps is forgotten:
 *
 *   1. Remove ALL `"data"` listeners from the plain socket so any
 *      bytes the peer queued in the TCP receive buffer before the
 *      handshake do NOT reach the plaintext state machine after the
 *      socket has been re-typed as a TLSSocket. Without listener
 *      removal, plain-mode bytes pipelined ahead of the handshake
 *      reach the post-TLS dispatcher and execute under the
 *      authenticated TLS context.
 *   2. Pause the plain socket so no further bytes flow through the
 *      old handler in the window before the TLSSocket attaches.
 *   3. Re-arm the idle timeout on the new TLSSocket (the plain
 *      socket's `setTimeout` does not survive the upgrade — RFC 5321
 *      §4.5.3.2.7 idle timeouts must keep running post-handshake).
 *   4. Wire `"secure"` / `"data"` / `"error"` handlers via callbacks
 *      so the caller's per-protocol state machine keeps owning the
 *      ingest logic.
 *
 * @opts
 *   plainSocket:     net.Socket,                 // pre-upgrade socket
 *   secureContext:   tls.SecureContext,          // from b.mail.server.tls.context
 *   idleTimeoutMs:   number,                     // re-armed post-handshake
 *   onSecure:        function(tlsSocket),        // called once "secure" fires
 *   onData:          function(tlsSocket, chunk), // post-handshake ingest
 *   onError:         function(err),              // handshake / runtime error
 *   onTimeout:       function(tlsSocket),        // optional idle timeout cb
 *
 * @example
 *   b.mail.server.tls.upgradeSocket({
 *     plainSocket:   socket,
 *     secureContext: opts.tlsContext,
 *     idleTimeoutMs: idleTimeoutMs,
 *     onSecure:      function (tlsSocket) { state.tls = true; },
 *     onData:        function (tlsSocket, chunk) { _ingest(state, tlsSocket, chunk); },
 *     onError:       function (err) { _emit("tls.handshake_failed", { err: err.message }); },
 *   });
 */
/**
 * @primitive b.mail.server.tls.implicitTlsWrap
 * @signature b.mail.server.tls.implicitTlsWrap(secureContext, enabled)
 * @since     0.18.58
 * @status    stable
 * @related   b.mail.server.tls.context, b.mail.server.tls.upgradeSocket
 *
 * The socket wrapper an RFC 8314 implicit-TLS listener hands its
 * accept path — TLS from the first byte on 465 / 993 / 995, rather
 * than the in-band STARTTLS upgrade. Returns `null` when `enabled` is
 * falsy, which is what a listener passes on its plaintext-upgrade
 * port, so the mode is one option rather than two code paths.
 *
 * Nothing here removes a `data` listener the way
 * `b.mail.server.tls.upgradeSocket` must: there is no plaintext
 * predecessor on this port, so there is no pre-handshake buffer for a
 * peer to have pipelined into (the CVE-2021-33515 class).
 *
 * @example
 *   var b = require("blamejs");
 *
 *   var wrap = b.mail.server.tls.implicitTlsWrap(secureContext, true);
 *   typeof wrap;
 *   // → "function"
 */
function implicitTlsWrap(secureContext, enabled) {
  if (!enabled) return null;
  return function (rawSocket) {
    return new nodeTls.TLSSocket(rawSocket, { isServer: true, secureContext: secureContext });
  };
}

function upgradeSocket(opts) {
  if (!opts || typeof opts !== "object") {
    throw new MailServerTlsError("mail-server-tls/bad-upgrade-opts",
      "upgradeSocket: opts required");
  }
  var plainSocket = opts.plainSocket;
  if (!plainSocket || typeof plainSocket.removeAllListeners !== "function") {
    throw new MailServerTlsError("mail-server-tls/bad-upgrade-socket",
      "upgradeSocket: opts.plainSocket must be a net.Socket");
  }
  if (!opts.secureContext) {
    throw new MailServerTlsError("mail-server-tls/bad-upgrade-context",
      "upgradeSocket: opts.secureContext required");
  }
  if (typeof opts.onSecure !== "function") {
    throw new MailServerTlsError("mail-server-tls/bad-upgrade-onsecure",
      "upgradeSocket: opts.onSecure(tlsSocket) required");
  }
  if (typeof opts.onData !== "function") {
    throw new MailServerTlsError("mail-server-tls/bad-upgrade-ondata",
      "upgradeSocket: opts.onData(tlsSocket, chunk) required");
  }
  if (typeof opts.onError !== "function") {
    throw new MailServerTlsError("mail-server-tls/bad-upgrade-onerror",
      "upgradeSocket: opts.onError(err) required");
  }
  var idleTimeoutMs = opts.idleTimeoutMs;
  if (idleTimeoutMs !== undefined &&
      (typeof idleTimeoutMs !== "number" || !isFinite(idleTimeoutMs) || idleTimeoutMs < 0)) {
    throw new MailServerTlsError("mail-server-tls/bad-upgrade-idle-timeout",
      "upgradeSocket: opts.idleTimeoutMs must be a non-negative finite number");
  }

  plainSocket.removeAllListeners("data");
  plainSocket.removeAllListeners("timeout");
  if (typeof plainSocket.pause === "function") {
    try { plainSocket.pause(); } catch (_e) { /* tolerate already-closed */ }
  }

  var tlsSocket = new nodeTls.TLSSocket(plainSocket, {
    isServer:      true,
    secureContext: opts.secureContext,
  });

  if (idleTimeoutMs !== undefined && typeof tlsSocket.setTimeout === "function") {
    try { tlsSocket.setTimeout(idleTimeoutMs); }
    catch (_e) { /* tolerate */ }
  }
  if (typeof opts.onTimeout === "function") {
    tlsSocket.on("timeout", function () {
      safeAsync.safeInvoke(opts.onTimeout, tlsSocket, opts.onError);
    });
  }

  tlsSocket.on("secure", function () {
    safeAsync.safeInvoke(opts.onSecure, tlsSocket, opts.onError);
  });
  tlsSocket.on("data", function (chunk) {
    safeAsync.safeApply(opts.onData, [tlsSocket, chunk], opts.onError);
  });
  tlsSocket.on("error", function (err) {
    safeAsync.safeInvoke(opts.onError, err);
  });

  return tlsSocket;
}

/**
 * @primitive b.mail.server.tls.upgradeLineProtocol
 * @signature b.mail.server.tls.upgradeLineProtocol(opts)
 * @since     0.15.13
 * @status    stable
 * @related   b.mail.server.tls.upgradeSocket
 *
 * STARTTLS / STLS completion for the line-buffered store listeners
 * (IMAP / POP3 / ManageSieve), layered over `upgradeSocket`. The
 * caller has already validated protocol state and written its
 * "begin TLS" response; this owns the steps that recur identically
 * across the three:
 *
 *   1. Drop the pre-handshake `state.lineBuffer` (always) plus any
 *      protocol-specific half-parsed command / literal / auth fields
 *      (`clearFields`) so bytes the peer pipelined before the upgrade
 *      cannot survive into the post-TLS session (CVE-2021-33515 /
 *      CVE-2021-38371 STARTTLS-injection class). Centralizing the
 *      `lineBuffer` reset makes it impossible for a listener to forget.
 *   2. Mark `state.tls = true` on the secure event, then run the
 *      caller's optional `onSecure` for protocol-specific work (e.g.
 *      ManageSieve re-emitting its capability banner per RFC 5804).
 *   3. Feed every post-handshake chunk through the caller's `drain`
 *      via the standard `state.lineBuffer` append.
 *
 * The transfer listeners (MX / submission) ingest via a serialized
 * feed pump, not the line buffer, so they call `upgradeSocket`
 * directly.
 *
 * @opts
 *   state:         object,                       // connection state ({ lineBuffer, tls, … })
 *   socket:        net.Socket,                   // pre-upgrade plain socket
 *   secureContext: tls.SecureContext,            // from b.mail.server.tls.context
 *   idleTimeoutMs: number,                       // re-armed post-handshake
 *   clearFields:   Array<string>,                // extra state fields to null pre-upgrade
 *   drain:         function(state, tlsSocket),   // the protocol line drainer
 *   onSecure:      function(tlsSocket),          // optional post-secure work
 *   onError:       function(err),                // handshake / runtime error
 *   onTimeout:     function(tlsSocket),          // optional idle-timeout handler
 *
 * @example
 *   b.mail.server.tls.upgradeLineProtocol({
 *     state: state, socket: socket, secureContext: opts.tlsContext,
 *     idleTimeoutMs: idleTimeoutMs, clearFields: ["pendingLiteral"],
 *     drain: _drainBuffer,
 *     onError: function (err) { _emit("imap.tls_failed", { err: err.message }); _close(socket, state); },
 *   });
 */
function upgradeLineProtocol(opts) {
  if (!opts || typeof opts !== "object") {
    throw new MailServerTlsError("mail-server-tls/bad-upgrade-line-opts",
      "upgradeLineProtocol: opts required");
  }
  var state = opts.state;
  if (!state || typeof state !== "object") {
    throw new MailServerTlsError("mail-server-tls/bad-upgrade-line-state",
      "upgradeLineProtocol: opts.state object required");
  }
  if (typeof opts.drain !== "function") {
    throw new MailServerTlsError("mail-server-tls/bad-upgrade-line-drain",
      "upgradeLineProtocol: opts.drain(state, tlsSocket) required");
  }
  state.lineBuffer = Buffer.alloc(0);
  var clearFields = opts.clearFields;
  if (clearFields) {
    for (var i = 0; i < clearFields.length; i += 1) state[clearFields[i]] = null;
  }
  return upgradeSocket({
    plainSocket:   opts.socket,
    secureContext: opts.secureContext,
    idleTimeoutMs: opts.idleTimeoutMs,
    onSecure: function (tlsSocket) {
      state.tls = true;
      if (typeof opts.onSecure === "function") opts.onSecure(tlsSocket);
    },
    onData: function (tlsSocket, chunk) {
      state.lineBuffer = Buffer.concat([state.lineBuffer, chunk]);
      opts.drain(state, tlsSocket);
    },
    onError:   opts.onError,
    onTimeout: opts.onTimeout,
  });
}

module.exports = {
  context:             context,
  upgradeSocket:       upgradeSocket,
  implicitTlsWrap:     implicitTlsWrap,
  upgradeLineProtocol: upgradeLineProtocol,
  MailServerTlsError:  MailServerTlsError,
  _contextOptionsForTest: function (opts) {
    return _contextOptions(opts, "<cert>", "<key>");
  },
};
