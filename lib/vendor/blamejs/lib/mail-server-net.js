// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

// mail-server-net — the TCP-listener lifecycle shared by the mailbox / transfer
// servers (b.mail.server.imap / pop3 / mx / managesieve / submission). Each of
// those keeps its OWN connection set and close() drain because those diverge:
// the store servers (IMAP/POP3/ManageSieve) await a Promise-wrapped
// tcpServer.close(), while the transfer servers (MX/Submission) send an SMTP
// 421 to every live socket and drain with a timeout. What every server shares
// verbatim is the bind: refuse a double-listen, resolve the default port (never
// falling back off an explicit port 0 — the ephemeral test-bind path), create
// the listener, and arm a one-shot "error"→reject so a bind failure (EADDRINUSE,
// EACCES) rejects the listen promise instead of crashing the process. That, plus
// the listening/server state, is what createTcpListener owns.

// createTcpListener(net, cfg) — build a listener lifecycle.
//   cfg.defaultPort      port used when listenOpts.port is omitted (an explicit
//                        0 is honored, for an ephemeral test bind).
//   cfg.handleConnection (socket) => void — the server's per-connection handler.
//   cfg.errorFactory     (code, message) => Error — builds the typed
//                        "<prefix>/already-listening" double-listen error.
//   cfg.emit             (action, metadata) => void — the server's audit emitter.
//   cfg.listeningEvent   the "...listening" audit action.
//   cfg.listeningExtra   optional () => object merged onto the listening event
//                        payload (Submission reports implicitTls).
// Returns { listen, getServer, isListening, markClosed } — the server wires its
// own close() through getServer()/isListening()/markClosed().
function createTcpListener(net, cfg) {
  var server = null;
  var listening = false;

  function listen(listenOpts) {
    listenOpts = listenOpts || {};
    if (listening) {
      throw cfg.errorFactory("already-listening", "listen: already listening");
    }
    var port = listenOpts.port === undefined ? cfg.defaultPort : listenOpts.port;
    var address = listenOpts.address || "0.0.0.0";
    server = net.createServer(function (socket) { cfg.handleConnection(socket); });
    return new Promise(function (resolve, reject) {
      server.once("error", reject);
      server.listen(port, address, function () {
        listening = true;
        server.removeListener("error", reject);
        var payload = { port: port, address: address };
        if (cfg.listeningExtra) {
          var extra = cfg.listeningExtra();
          for (var k in extra) {
            if (Object.prototype.hasOwnProperty.call(extra, k)) payload[k] = extra[k];
          }
        }
        cfg.emit(cfg.listeningEvent, payload);
        resolve({ port: server.address().port, address: address });
      });
    });
  }

  // closeSimple(closeCfg) — the store-server shutdown (IMAP / POP3 / ManageSieve):
  // mark closed, destroy every live socket immediately, then await the listener's
  // own close before emitting the "...closed" audit. The transfer servers
  // (MX / Submission) do NOT use this — they run a graceful SMTP-421 drain with a
  // timeout, so they own their close() and drive it through markClosed()/getServer().
  //   closeCfg.connections  the server's live-socket Set (destroyed + cleared).
  //   closeCfg.emit         the server's audit emitter.
  //   closeCfg.closedEvent  the "...closed" audit action.
  function closeSimple(closeCfg) {
    if (!listening) return Promise.resolve();
    listening = false;
    for (var s of closeCfg.connections) { try { s.destroy(); } catch (_e) { /* idempotent */ } }
    closeCfg.connections.clear();
    return new Promise(function (resolve) {
      server.close(function () {
        closeCfg.emit(closeCfg.closedEvent, {});
        resolve();
      });
    });
  }

  return {
    listen:      listen,
    closeSimple: closeSimple,
    getServer:   function () { return server; },
    isListening: function () { return listening; },
    markClosed:  function () { listening = false; },
  };
}

// createStoreServer(net, cfg) — the COMPLETE lifecycle of a mailbox store server
// (b.mail.server.imap / pop3 / managesieve): compose createTcpListener with the
// destroy-then-await closeSimple shutdown and return the { listen, close } a
// store server exposes. The three store servers are byte-identical here, varying
// only in port, error class, error-code prefix, and audit-event base — so the
// wiring lives here once. The transfer servers (MX / Submission) do NOT use this:
// they run a graceful SMTP-421 drain close + a richer return ({ connectionCount,
// _portForTest, ... }), so they call createTcpListener directly.
//   cfg.defaultPort      port used when listen() omits one (explicit 0 honored).
//   cfg.handleConnection (socket) => void — the per-connection handler.
//   cfg.errorClass       the server's typed error constructor (code, message).
//   cfg.errorCodePrefix  prepended to the double-listen error code
//                        (e.g. "mail-server-imap/").
//   cfg.emit             (action, metadata) => void — the server's audit emitter.
//   cfg.connections      the live-socket Set (destroyed + cleared on close).
//   cfg.eventBase        the audit-action base; listeningEvent = eventBase +
//                        ".listening", closedEvent = eventBase + ".closed".
// Returns { listen, close }.
function createStoreServer(net, cfg) {
  var ErrorClass = cfg.errorClass;
  var listener = createTcpListener(net, {
    defaultPort:      cfg.defaultPort,
    handleConnection: cfg.handleConnection,
    errorFactory:     function (code, message) { return new ErrorClass(cfg.errorCodePrefix + code, message); },
    emit:             cfg.emit,
    listeningEvent:   cfg.eventBase + ".listening",
  });
  function close() {
    return listener.closeSimple({
      connections: cfg.connections,
      emit:        cfg.emit,
      closedEvent: cfg.eventBase + ".closed",
    });
  }
  return { listen: listener.listen, close: close };
}

// admitConnection(socket, rateLimit, emit, cfg) — the per-connection rate-limit
// gate every mail listener's _handleConnection opens with: resolve the remote
// IP, admit it via the shared b.mail.server.rateLimit, or refuse it with a
// protocol-specific line + a "<...>.rate_limit_refused" audit (outcome "denied")
// and tear the socket down. Returns the remote address on admit, or null when
// refused — the caller does `if (addr === null) return;` then runs its own
// (protocol-specific) close handler, connection-id, tracking-set insert, and
// state machine, none of which this touches.
//   cfg.refusedEvent  the "<...>.rate_limit_refused" audit action.
//   cfg.refusalLine   the wire bytes written before destroy (IMAP "* BAD …",
//                     POP3 "-ERR …", SMTP "421 4.7.0 …", ManageSieve 'NO "…"').
function admitConnection(socket, rateLimit, emit, cfg) {
  var remoteAddress = socket.remoteAddress || "0.0.0.0";
  var admit = rateLimit.admitConnection(remoteAddress);
  if (!admit.ok) {
    emit(cfg.refusedEvent, { remoteAddress: remoteAddress, reason: admit.reason }, "denied");
    try { socket.write(cfg.refusalLine); } catch (_e) { /* socket may be down */ }
    try { socket.destroy(); } catch (_e2) { /* idempotent */ }
    return null;
  }
  return remoteAddress;
}

// validateDomainHardened(d, label, cfg) — the hardened-domain check the MX and
// Submission transfer servers run on every HELO / MAIL FROM / RCPT TO domain.
// When a guardDomain profile is configured it validates the domain and, on
// refusal, emits a "<refusedEvent>" audit (the only per-server difference — MX
// vs Submission) before returning the verdict; with no profile it passes
// through { ok: true }. Sharing it keeps the two servers' domain-validation
// posture identical (a divergence would be a silent spoofing / IDN-homograph
// gap on one server).
//   cfg.guardDomainProfile  the b.guardDomain profile (falsy = validation off).
//   cfg.guardDomain         the b.guardDomain module (its validate(d, profile)).
//   cfg.emit                (action, metadata, outcome) => void audit emitter.
//   cfg.refusedEvent        the "<...>.domain_refused" audit action.
function validateDomainHardened(d, label, cfg) {
  if (!cfg.guardDomainProfile) return { ok: true };
  var verdict = cfg.guardDomain.validate(d, cfg.guardDomainProfile);
  if (!verdict.ok) {
    cfg.emit(cfg.refusedEvent, {
      reason: verdict.issues && verdict.issues[0] && verdict.issues[0].kind,
      domain: d,
      label:  label,
    }, "denied");
  }
  return verdict;
}

module.exports = {
  createTcpListener: createTcpListener,
  createStoreServer: createStoreServer,
  admitConnection:   admitConnection,
  validateDomainHardened: validateDomainHardened,
};
