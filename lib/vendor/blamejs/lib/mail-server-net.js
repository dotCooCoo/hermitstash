// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

var C              = require("./constants");
var codepointClass = require("./codepoint-class");
var bCrypto        = require("./crypto");
var safeAsync      = require("./safe-async");

var DEFAULT_MAX_CONNECTIONS = 1024;

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
    server.maxConnections = cfg.maxConnections || DEFAULT_MAX_CONNECTIONS;
    server.on("drop", function (info) {
      if (typeof cfg.emit !== "function") return;
      cfg.emit(cfg.ceilingRefusedEvent || "listener.max_connections_refused", {
        remoteAddress:  (info && info.remoteAddress) || null,
        reason:         "listener-at-capacity",
        maxConnections: server.maxConnections,
      }, "denied");
    });
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

function createStoreServer(net, cfg) {
  var ErrorClass = cfg.errorClass;
  var listener = createTcpListener(net, {
    defaultPort:      cfg.defaultPort,
    maxConnections:   cfg.maxConnections,
    handleConnection: cfg.handleConnection,
    errorFactory:     function (code, message) { return new ErrorClass(cfg.errorCodePrefix + code, message); },
    emit:             cfg.emit,
    listeningEvent:   cfg.eventBase + ".listening",
    ceilingRefusedEvent: cfg.eventBase + ".max_connections_refused",
    listeningExtra:   cfg.listeningExtra,
  });
  function close() {
    return listener.closeSimple({
      connections: cfg.connections,
      emit:        cfg.emit,
      closedEvent: cfg.eventBase + ".closed",
    });
  }
  return {
    listen:          listener.listen,
    close:           close,
    connectionCount: function () { return cfg.connections.size; },
  };
}

function trackConnection(socket, cfg) {
  cfg.connections.add(socket);
  var source = cfg.closeSource || socket;
  source.once("close", function () {
    cfg.rateLimit.releaseConnection(cfg.remoteAddress);
    cfg.connections.delete(socket);
  });
}

function announcedLiteralBytes(lineBuffer, cfg) {
  if (cfg.pending) {
    return Math.max(0, cfg.pending.size - cfg.pending.body.length);
  }
  var pos = 0;
  while (pos <= cfg.maxPipelinedBytes) {
    var rest = lineBuffer.subarray(pos);
    var crlf = rest.indexOf("\r\n");
    if (crlf === -1 || crlf > cfg.maxLineBytes) return 0;
    var announced = cfg.openerBytes(rest.subarray(0, crlf).toString("utf8"));
    pos += crlf + 2;
    if (announced === null || announced === undefined) continue;
    if (typeof announced !== "number" || !isFinite(announced) || announced < 0) return 0;
    return Math.min(announced, Math.max(0, lineBuffer.length - pos));
  }
  return 0;
}

var CLOSE_FLUSH_GRACE_MS = C.TIME.seconds(5);

function destroySocketAfterFlush(socket, cfg) {
  var graceMs = (cfg && cfg.graceMs) || CLOSE_FLUSH_GRACE_MS;
  var torn = false;
  var timer = null;
  function hardDestroy() {
    if (torn) return;
    torn = true;
    // allow:handrolled-debounce-oneshot-grace-clear — armed once when the flush starts and cleared when it finishes; nothing re-arms it
    if (timer !== null) { clearTimeout(timer); timer = null; }
    try { socket.destroy(); } catch (_e) { /* idempotent */ }
  }
  timer = setTimeout(hardDestroy, graceMs);
  if (typeof timer.unref === "function") timer.unref();
  try {
    socket.once("close", hardDestroy);
    socket.end(hardDestroy);
  } catch (_e2) {
    hardDestroy();
  }
}

function wireLineSocket(socket, cfg) {
  socket.setTimeout(cfg.idleTimeoutMs);
  socket.on("timeout", function () {
    if (typeof cfg.onIdleTimeout === "function") cfg.onIdleTimeout();
    cfg.close();
  });
  socket.on("error", function (err) {
    if (typeof cfg.onError === "function") cfg.onError(err);
  });
  socket.on("close", function () { cfg.close(); });
  if (typeof cfg.drain !== "function") return;
  socket.on("data", function (chunk) {
    cfg.state.lineBuffer = Buffer.concat([cfg.state.lineBuffer, chunk]);
    cfg.drain(cfg.state, socket);
  });
}

function createBodyRateWindow(rateLimit) {
  var windowStart = 0;
  var windowBytes = 0;
  return {
    start: function (now, bytesSeen) {
      windowStart = now;
      windowBytes = bytesSeen || 0;
    },
    starved: function (bytesSeen, now) {
      var elapsed = now - windowStart;
      if (rateLimit.bodyRateStarved(bytesSeen - windowBytes, elapsed)) return true;
      if (elapsed >= rateLimit.bodyRateWindowMs()) {
        windowStart = now;
        windowBytes = bytesSeen;
      }
      return false;
    },
  };
}

function acceptConnection(rawSocket, cfg) {
  var remoteAddress = admitConnection(rawSocket, cfg.rateLimit, cfg.emit, {
    refusedEvent: cfg.refusedEvent,
    refusalLine:  cfg.refusalLine,
    implicitTls:  !!cfg.wrap,
  });
  if (remoteAddress === null) return null;
  var socket = cfg.wrap ? cfg.wrap(rawSocket) : rawSocket;
  trackConnection(socket, {
    connections:   cfg.connections,
    rateLimit:     cfg.rateLimit,
    remoteAddress: remoteAddress,
    closeSource:   socket === rawSocket ? null : rawSocket,
  });
  if (typeof cfg.onClose === "function") {
    var closed = false;
    var fire = function () {
      if (closed) return;
      closed = true;
      cfg.onClose();
    };
    socket.once("close", fire);
    if (socket !== rawSocket) rawSocket.once("close", fire);
  }
  return {
    socket:        socket,
    remoteAddress: remoteAddress,
    connectionId:  cfg.idPrefix + bCrypto.generateToken(8),
  };
}

function admitConnection(socket, rateLimit, emit, cfg) {
  var remoteAddress = socket.remoteAddress || "0.0.0.0";
  var admit = rateLimit.admitConnection(remoteAddress);
  if (!admit.ok) {
    emit(cfg.refusedEvent, { remoteAddress: remoteAddress, reason: admit.reason }, "denied");
    if (!cfg.implicitTls) {
      try { socket.write(cfg.refusalLine); } catch (_e) { /* socket may be down */ }
    }
    try { socket.destroy(); } catch (_e2) { /* idempotent */ }
    return null;
  }
  return remoteAddress;
}

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

function saslChallengeOrNull(challenge) {
  if (typeof challenge !== "string") return null;
  return codepointClass.firstLineInjectionCharOffset(challenge) === -1 ? challenge : null;
}

function replyTextOrFallback(text, fallback) {
  if (typeof text !== "string" || text.length === 0) return fallback;
  return codepointClass.firstLineInjectionCharOffset(text) === -1 ? text : fallback;
}

function foldSubaddress(address, delimiter) {
  if (typeof address !== "string" || address.length === 0) return "";
  var at = address.lastIndexOf("@");
  var lower = at <= 0 ? address : address.slice(0, at) + address.slice(at).toLowerCase();
  if (typeof delimiter !== "string" || delimiter.length === 0) return lower;
  var sep = delimiter;
  if (at <= 0) return lower;
  var local = lower.slice(0, at);
  if (local.charAt(0) === "\"") return lower;
  var tag = local.indexOf(sep);
  if (tag <= 0) return lower;
  return local.slice(0, tag) + lower.slice(at);
}

function agentRefusalReply(err, fallbackText) {
  var code = _refusalCode(err && err.smtpCode);
  var cls = code.charAt(0);
  var status = _enhancedStatusForCode(err && err.enhancedStatus, code);
  var text = replyTextOrFallback(err && err.replyText,
    code === DEFAULT_REFUSAL_CODE ? fallbackText : DEFAULT_REFUSAL_TEXT_BY_CLASS[cls]);
  return { code: code, text: status + " " + text };
}

var DEFAULT_REFUSAL_CODE   = "451";
var DEFAULT_REFUSAL_STATUS = "4.3.0";
var DEFAULT_REFUSAL_TEXT_BY_CLASS = { "4": "Message not accepted, try again later",
                                      "5": "Message refused" };

function _refusalCode(supplied) {
  if (typeof supplied === "number" && Number.isInteger(supplied)) supplied = String(supplied);
  if (typeof supplied !== "string") return DEFAULT_REFUSAL_CODE;
  return /^[45][0-9][0-9]$/.test(supplied) ? supplied : DEFAULT_REFUSAL_CODE;
}

function _enhancedStatusForCode(supplied, code) {
  if (typeof supplied === "string" && /^[45]\.[0-9]{1,3}\.[0-9]{1,3}$/.test(supplied) &&
      supplied.charAt(0) === code.charAt(0)) {
    return supplied;
  }
  return code === DEFAULT_REFUSAL_CODE ? DEFAULT_REFUSAL_STATUS : code.charAt(0) + ".0.0";
}

// so they DROP SILENT — a consumer throwing inside one would otherwise take
function fireConsumerHook(fn, args, cfg) {
  if (typeof fn !== "function") return;
  safeAsync.safeApply(fn, args, function (e) {
    cfg.emit(cfg.event,
      { connectionId: cfg.connectionId, error: (e && e.message) || String(e) }, "failure");
  });
}

function runSaslStep(cfg) {
  var ex = cfg.exchange;
  if (ex.abandoned) {
    cfg.onFailure({ reason: "pipelined-sasl-response" });
    return Promise.resolve();
  }
  if (ex.inFlight) {
    ex.abandoned = true;
    cfg.onFailure({ reason: "pipelined-sasl-response" });
    return Promise.resolve();
  }
  ex.inFlight = true;
  return Promise.resolve()
    .then(function () {
      var creds = { step: ex.step, clientResponse: cfg.clientResponse };
      if (cfg.credentials) {
        Object.keys(cfg.credentials).forEach(function (k) { creds[k] = cfg.credentials[k]; });
      }
      return cfg.verify(ex.mech, creds);
    })
    .then(function (result) {
      ex.inFlight = false;
      if (ex.abandoned) return;
      ex.step += 1;
      if (result && result.pending && typeof result.challenge === "string") {
        if (cfg.writeChallenge(result.challenge)) return;
        cfg.onChallengeUnsafe();
        return;
      }
      if (result && result.ok === true && result.actor) { return cfg.onSuccess(result); }
      return cfg.onFailure(result);
    })
    .catch(function (err) {
      ex.inFlight = false;
      if (ex.abandoned) return;
      cfg.onError(err);
    });
}

module.exports = {
  createTcpListener: createTcpListener,
  runSaslStep:       runSaslStep,
  createStoreServer: createStoreServer,
  admitConnection:   admitConnection,
  trackConnection:   trackConnection,
  acceptConnection:  acceptConnection,
  createBodyRateWindow: createBodyRateWindow,
  wireLineSocket:    wireLineSocket,
  destroySocketAfterFlush: destroySocketAfterFlush,
  announcedLiteralBytes: announcedLiteralBytes,
  DEFAULT_MAX_CONNECTIONS: DEFAULT_MAX_CONNECTIONS,
  validateDomainHardened: validateDomainHardened,
  saslChallengeOrNull: saslChallengeOrNull,
  replyTextOrFallback:  replyTextOrFallback,
  agentRefusalReply:    agentRefusalReply,
  foldSubaddress:       foldSubaddress,
  fireConsumerHook:     fireConsumerHook,
};
