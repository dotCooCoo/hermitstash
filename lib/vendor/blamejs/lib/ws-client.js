"use strict";
/**
 * b.wsClient — outbound WebSocket client (RFC 6455).
 *
 * Companion to b.websocket (server-side). Operators dial out to peer
 * WebSocket endpoints from Node — webhooks, pubsub bridges, integration
 * with external realtime services — without reaching for `ws` from
 * npm.
 *
 *   var client = b.wsClient.connect("wss://stream.example.com/v1", {
 *     subprotocols: ["json-stream-v1"],
 *     headers:      { "Authorization": "Bearer " + token },
 *     reconnect:    { maxAttempts: 10, baseMs: 500, maxMs: 30000 },
 *     pingMs:       30000,
 *     pongMs:       60000,
 *     maxMessageBytes: b.constants.BYTES.mib(8),
 *   });
 *
 *   client.on("open",    function () { client.send({ subscribe: ["orders"] }); });
 *   client.on("message", function (data, isBinary) { ... });
 *   client.on("close",   function (code, reason) { ... });
 *   client.on("error",   function (err) { ... });
 *
 *   client.send("text frame");
 *   client.send(Buffer.from("binary frame"));
 *   client.close(1000, "bye");
 *
 * Frame layer is the same RFC 6455 implementation b.websocket already
 * ships — we reuse `FrameParser` and `serializeFrame` from
 * lib/websocket.js. The client adds:
 *
 *   - Outbound HTTP/1.1 Upgrade with Sec-WebSocket-Key generation.
 *   - Sec-WebSocket-Accept verification (rejects on hash mismatch).
 *   - Subprotocol + permessage-deflate negotiation.
 *   - Client-side frame masking (RFC 6455 §5.3 — required for outbound).
 *   - TLS via b.network.tls.pqc (X25519MLKEM768 hybrid handshake).
 *   - Heartbeat: ping every `pingMs`, drop the connection if pong not
 *     received within `pongMs`.
 *   - Auto-reconnect with exponential backoff + jitter.
 *
 * Per the validation-tier policy: connect() throws on bad opts at
 * config time; runtime errors flow through 'error' events.
 *
 * Per the security-defaults stance: TLS verification ON by default
 * (operator opts in to mTLS via tlsOpts). HSTS-style, no soft-fail.
 */

var net          = require("node:net");
var nodeUrl      = require("node:url");
var nodeCrypto   = require("node:crypto");
var { EventEmitter } = require("node:events");

var lazyRequire    = require("./lazy-require");
var validateOpts   = require("./validate-opts");
var safeAsync      = require("./safe-async");
var safeBuffer     = require("./safe-buffer");
var bCrypto        = lazyRequire(function () { return require("./crypto"); });
var websocket      = lazyRequire(function () { return require("./websocket"); });
var audit          = lazyRequire(function () { return require("./audit"); });
var networkTls     = lazyRequire(function () { return require("./network-tls"); });
var safeJson       = lazyRequire(function () { return require("./safe-json"); });
var ssrfGuard      = require("./ssrf-guard");
var structuredFields = require("./structured-fields");
var C              = require("./constants");
var { defineClass } = require("./framework-error");

// Codes that are TRANSIENT — a consumer's reconnect loop (and the client's own
// auto-reconnect) SHOULD retry. Everything else is terminal: a bad URL / config
// error, a 4xx handshake rejection, an accept-mismatch, or a protocol-violation
// / oversized / malicious frame, where redialing the same hopeless target
// forever is the worse failure. bad-status is split by status below (5xx
// transient, 4xx terminal). Default-terminal so a new/forgotten code fails
// closed (no infinite redial) rather than open.
var WS_TRANSIENT_CODES = {
  "ws-client/handshake-timeout": true,   // server slow to complete the upgrade
  "ws-client/pong-timeout":      true,   // keepalive lapse on an otherwise-live link
};

function _wsErrorIsPermanent(code, statusCode) {
  if (code === "ws-client/bad-status") {
    // 5xx handshake rejection is transient (server overloaded / restarting);
    // 4xx (and any non-5xx) is terminal (auth / bad request / not-found).
    return !(typeof statusCode === "number" && statusCode >= 500 && statusCode < 600);
  }
  // hasOwnProperty membership so a code of "__proto__" / "constructor" can't
  // index the prototype and be misread as transient.
  return !Object.prototype.hasOwnProperty.call(WS_TRANSIENT_CODES, code);
}

// permanent is DERIVED per-error from the code (+ status) at every construction
// — so err.permanent is a usable terminal/transient signal for a consumer's
// reconnect loop, not a blanket sentinel. Constructor: (code, message, status).
var WsClientError = defineClass("WsClientError", { permanentClassifier: _wsErrorIsPermanent });

var WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";   // RFC 6455 §1.3

var DEFAULT_PING_MS    = C.TIME.seconds(30);
var DEFAULT_PONG_MS    = C.TIME.seconds(60);
var DEFAULT_MAX_BYTES  = C.BYTES.mib(8);
var DEFAULT_MAX_FRAME  = C.BYTES.mib(8);
var DEFAULT_HANDSHAKE_TIMEOUT_MS = C.TIME.seconds(15);
var DEFAULT_RECONNECT_BASE_MS    = C.TIME.seconds(1) / 2;
var DEFAULT_RECONNECT_MAX_MS     = C.TIME.seconds(30);
var DEFAULT_RECONNECT_MAX_ATTEMPTS = 10;

var OPCODE_CONT   = 0x00;                                // RFC 6455 opcode
var OPCODE_TEXT   = 0x01;                                // RFC 6455 opcode
var OPCODE_BINARY = 0x02;                                // RFC 6455 opcode
var OPCODE_CLOSE  = 0x08;                                // RFC 6455 opcode
var OPCODE_PING   = 0x09;                                // RFC 6455 opcode
var OPCODE_PONG   = 0x0A;                                // RFC 6455 opcode

var CLOSE_NORMAL          = 1000;                        // RFC 6455 close code
var CLOSE_GOING_AWAY      = 1001;                        // RFC 6455 close code
var CLOSE_ABNORMAL        = 1006;                        // RFC 6455 close code (synthetic — never on wire)

// Permanent vs transient classifier for the reconnect logic. WsClientError now
// carries a per-code permanent flag (see _wsErrorIsPermanent), so this reads it
// directly. A raw socket error (ECONNRESET / ECONNREFUSED mid-dial, no
// .permanent) is treated as transient — the connection dropped, retrying (up to
// reconnect.maxAttempts) is correct. Previously WsClientError was alwaysPermanent
// so this returned true for EVERY framework error, silently disabling the
// advertised auto-reconnect for transient handshake/keepalive failures.
function _isPermanentError(err) {
  return !!(err && err.permanent === true);
}

// Synchronous bounded inflate — runs zlib.inflateRawSync with
// `maxOutputLength` set to maxBytes + 1, so Node aborts the inflate
// when the output would exceed the cap. Defends against a malicious
// server sending a tiny compressed frame that expands to GBs.
function _inflateRawCappedSync(zlib, compressed, maxBytes, windowBits) {
  try {
    return zlib.inflateRawSync(compressed, {
      maxOutputLength: maxBytes + 1,
      windowBits:      windowBits,
    });
  } catch (e) {
    if (e && (e.code === "ERR_BUFFER_TOO_LARGE" ||
              /maxOutputLength|maxOutput/.test(String(e.message)))) {
      throw new WsClientError("ws-client/decompression-bomb",
        "decompression-bomb defense: inflated output > " + maxBytes + " bytes");
    }
    throw e;
  }
}

function _generateKey() {
  return bCrypto().generateBytes(C.BYTES.bytes(16)).toString("base64");
}

function _expectedAccept(secKey, handshakeGuid) {
  return nodeCrypto.createHash("sha1").update(secKey + (handshakeGuid || WS_GUID)).digest("base64");
}

function _parseUrl(target) {
  var parsed;
  try { parsed = new nodeUrl.URL(target); }
  catch (e) {
    throw new WsClientError("ws-client/bad-url",
      "wsClient.connect: url is malformed - " + e.message);
  }
  var proto = parsed.protocol;
  if (proto !== "ws:" && proto !== "wss:") {
    throw new WsClientError("ws-client/bad-url",
      "wsClient.connect: url must start with ws:// or wss:// - got " + JSON.stringify(proto));
  }
  return parsed;
}

function connect(target, opts) {
  opts = opts || {};
  validateOpts(opts, [
    "subprotocols", "headers", "tlsOpts", "pingMs", "pongMs",
    "maxMessageBytes", "maxFrameBytes",
    "handshakeTimeoutMs", "reconnect",
    "permessageDeflate", "audit", "origin",
    "handshakeGuid", "allowInternal",
    "parse", "parser",
    "urlFor", "tlsOptsFor",
  ], "wsClient.connect");

  // Per-dial state-injection callbacks. Both fire on every connect
  // attempt (initial + each reconnect) so operators can rotate
  // bearer tokens, DNS targets, or TLS material between hops without
  // tearing the client down.
  //   urlFor(attempt) -> string                — overrides target URL
  //   tlsOptsFor(attempt) -> object            — overrides TLS opts
  // attempt is a 0-based hop index; 0 is the initial dial.
  if (opts.urlFor != null && typeof opts.urlFor !== "function") {
    throw new WsClientError("ws-client/bad-url-for",
      "wsClient.connect: urlFor must be a function");
  }
  if (opts.tlsOptsFor != null && typeof opts.tlsOptsFor !== "function") {
    throw new WsClientError("ws-client/bad-tls-opts-for",
      "wsClient.connect: tlsOptsFor must be a function");
  }

  // Operators with a non-RFC-6455 GUID (private protocols on top of
  // the WebSocket framing layer, framework-specific handshake variants)
  // pass a custom handshakeGuid. The server-side b.websocket already
  // supports it; this is the symmetric client-side knob. Defaults to
  // the RFC 6455 §1.3 GUID `258EAFA5-E914-47DA-95CA-C5AB0DC85B11`.
  var handshakeGuid = WS_GUID;
  if (opts.handshakeGuid != null) {
    validateOpts.requireNonEmptyString(opts.handshakeGuid,
      "wsClient.connect: handshakeGuid", WsClientError, "ws-client/bad-handshake-guid");
    handshakeGuid = opts.handshakeGuid;
  }

  var parsed = _parseUrl(target);

  var subprotocols = Array.isArray(opts.subprotocols) ? opts.subprotocols.slice() : [];
  for (var sp = 0; sp < subprotocols.length; sp += 1) {
    if (typeof subprotocols[sp] !== "string" || subprotocols[sp].length === 0) {
      throw new WsClientError("ws-client/bad-subprotocol",
        "wsClient.connect: subprotocols[" + sp + "] must be a non-empty string");
    }
  }
  var pingMs = (typeof opts.pingMs === "number" && opts.pingMs > 0)              // allow:numeric-opt-Infinity
    ? opts.pingMs : DEFAULT_PING_MS;
  var pongMs = (typeof opts.pongMs === "number" && opts.pongMs > 0)              // allow:numeric-opt-Infinity
    ? opts.pongMs : DEFAULT_PONG_MS;
  var maxMessageBytes = (typeof opts.maxMessageBytes === "number" && opts.maxMessageBytes > 0)   // allow:numeric-opt-Infinity
    ? opts.maxMessageBytes : DEFAULT_MAX_BYTES;
  var maxFrameBytes = (typeof opts.maxFrameBytes === "number" && opts.maxFrameBytes > 0)         // allow:numeric-opt-Infinity
    ? opts.maxFrameBytes : DEFAULT_MAX_FRAME;
  var handshakeTimeoutMs = (typeof opts.handshakeTimeoutMs === "number" && opts.handshakeTimeoutMs > 0)  // allow:numeric-opt-Infinity
    ? opts.handshakeTimeoutMs : DEFAULT_HANDSHAKE_TIMEOUT_MS;

  var reconnectOpts = _normaliseReconnect(opts.reconnect);
  var permessageDeflate = opts.permessageDeflate !== false;
  var auditOn = opts.audit !== false;

  var client = new WsClient({
    target:             target,
    parsedUrl:          parsed,
    subprotocols:       subprotocols,
    headers:            opts.headers || {},
    tlsOpts:            opts.tlsOpts || null,
    origin:             opts.origin || null,
    pingMs:             pingMs,
    pongMs:             pongMs,
    maxMessageBytes:    maxMessageBytes,
    maxFrameBytes:      maxFrameBytes,
    handshakeTimeoutMs: handshakeTimeoutMs,
    reconnectOpts:      reconnectOpts,
    permessageDeflate:  permessageDeflate,
    auditOn:            auditOn,
    handshakeGuid:      handshakeGuid,
    allowInternal:      opts.allowInternal,
    parse:              opts.parse || null,
    parser:             typeof opts.parser === "function" ? opts.parser : null,
    urlFor:             typeof opts.urlFor === "function" ? opts.urlFor : null,
    tlsOptsFor:         typeof opts.tlsOptsFor === "function" ? opts.tlsOptsFor : null,
  });
  // SSRF gate — refuse private / loopback / link-local / cloud-metadata /
  // reserved IP destinations by default. Symmetric to b.httpClient. The
  // validated `ips` are pinned through tls.connect / net.connect so the
  // actual TCP connect targets the validated address (closes the DNS-
  // rebinding TOCTOU window). Cloud-metadata IPs are unconditional
  // hard-deny — `allowInternal: true` does not bypass them. _prepareDial
  // performs the (async) check + pinning before the dial and reruns it on
  // every reconnect, so a urlFor-swapped target is validated too.
  client._prepareDial().then(function () {
    client._dial();
  }).catch(function (e) {
    setImmediate(function () { client._handleSocketError(e); });
  });
  return client;
}

function _normaliseReconnect(input) {
  if (input === false || input == null) {
    return { enabled: false, maxAttempts: 0,
             baseMs: DEFAULT_RECONNECT_BASE_MS,
             maxMs:  DEFAULT_RECONNECT_MAX_MS };
  }
  if (typeof input !== "object") {
    throw new WsClientError("ws-client/bad-reconnect",
      "wsClient.connect: reconnect must be false / null / object");
  }
  validateOpts(input, ["maxAttempts", "baseMs", "maxMs", "enabled"], "wsClient.connect.reconnect");
  return {
    enabled:     input.enabled !== false,
    maxAttempts: (typeof input.maxAttempts === "number" && input.maxAttempts >= 0)            // allow:numeric-opt-Infinity
      ? input.maxAttempts : DEFAULT_RECONNECT_MAX_ATTEMPTS,
    baseMs:      (typeof input.baseMs === "number" && input.baseMs > 0)                       // allow:numeric-opt-Infinity
      ? input.baseMs : DEFAULT_RECONNECT_BASE_MS,
    maxMs:       (typeof input.maxMs === "number" && input.maxMs > 0)                         // allow:numeric-opt-Infinity
      ? input.maxMs : DEFAULT_RECONNECT_MAX_MS,
  };
}

class WsClient extends EventEmitter {
  constructor(opts) {
    super();
    this._opts            = opts;
    this._socket          = null;
    this._parser          = null;
    this._readyState      = "connecting";
    this._reconnectAttempt = 0;
    this._reconnectTimer   = null;
    this._handshakeTimer   = null;
    this._pingTimer        = null;
    this._pongDeadline     = 0;
    this._fragmentChunks   = [];
    this._fragmentOpcode   = null;
    this._fragmentRsv1     = false;
    this._closed           = false;
    this._negotiatedSubprotocol = null;
    this._negotiatedDeflate = false;
    this._negotiatedWindowBits = 15;                    // RFC 7692 default
    this._bytesSent        = 0;
    this._bytesReceived    = 0;
  }

  get readyState()             { return this._readyState; }
  get subprotocol()            { return this._negotiatedSubprotocol; }
  get url()                    { return this._opts.target; }

  // Resolve the dial target and re-validate it BEFORE any socket opens.
  // urlFor may swap the URL and tlsOptsFor may rotate TLS material every
  // dial (including reconnects). The resolved target is re-checked through
  // ssrfGuard — AWAITED, because checkUrl is async: the prior code called it
  // synchronously inside _dial and discarded the Promise, so a urlFor that
  // pointed at a private / cloud-metadata address mid-reconnect was connected
  // anyway (the SSRF rejection surfaced only as an unhandled rejection) and
  // the connect was never pinned. Returns a Promise; sync throws from
  // urlFor / tlsOptsFor become rejections (async fn) handled by the caller.
  async _prepareDial() {
    var opts = this._opts;
    var attempt = this._reconnectAttempt || 0;
    var dialParsed = opts.parsedUrl;
    if (typeof opts.urlFor === "function") {
      var nextTarget = opts.urlFor(attempt);
      if (typeof nextTarget === "string" && nextTarget.length > 0 && nextTarget !== opts.target) {
        dialParsed = _parseUrl(nextTarget);
      }
    }
    var dialTlsOpts = opts.tlsOpts;
    if (typeof opts.tlsOptsFor === "function") {
      var override = opts.tlsOptsFor(attempt);
      if (override && typeof override === "object") {
        dialTlsOpts = Object.assign({}, opts.tlsOpts || {}, override);
      }
    }
    var probeProto = dialParsed.protocol === "wss:" ? "https:" : "http:";
    var probeUrl = new nodeUrl.URL(probeProto + "//" + dialParsed.host + dialParsed.pathname + dialParsed.search);
    var probe = await ssrfGuard.checkUrl(probeUrl, {
      allowInternal: opts.allowInternal,
      errorClass:    WsClientError,
    });
    this._ssrfPinnedIps = probe && probe.ips ? probe.ips : null;
    this._dialParsed    = dialParsed;
    this._dialTlsOpts   = dialTlsOpts;
  }

  _dial() {
    var self = this;
    this._readyState = "connecting";

    // Target + TLS material were resolved and SSRF-validated by _prepareDial.
    var parsed = this._dialParsed || this._opts.parsedUrl;
    var dialTlsOpts = this._dialTlsOpts || this._opts.tlsOpts;
    var port = parsed.port ? parseInt(parsed.port, 10) :
               (parsed.protocol === "wss:" ? 443 : 80);                                  // TLS / HTTP default port
    var host = parsed.hostname;

    function _onError(err) { self._handleSocketError(err); }

    // Pin the connect to the SSRF-validated IPs returned by
    // ssrfGuard.checkUrl — closes the DNS-rebinding TOCTOU window where
    // the gate resolves a public IP and the kernel re-resolves to a
    // private one between the check and the connect.
    var pinnedIps = self._ssrfPinnedIps || null;
    var lookup = null;
    if (pinnedIps && pinnedIps.length > 0) {
      lookup = function (h, lookupOpts, cb) {
        // Node's lookup callback signatures:
        //   (err, address, family) for legacy { all: false } (default)
        //   (err, addresses)        for { all: true }
        if (typeof lookupOpts === "function") { cb = lookupOpts; lookupOpts = {}; }
        var first = pinnedIps[0];
        if (lookupOpts && lookupOpts.all) {
          return cb(null, pinnedIps.map(function (ip) {
            return { address: ip.address, family: ip.family };
          }));
        }
        return cb(null, first.address, first.family);
      };
    }

    var socket;
    if (parsed.protocol === "wss:") {
      var tls = require("node:tls");                                                          // allow:inline-require — node:tls only on TLS path
      var tlsOpts = Object.assign({
        host:         host,
        port:         port,
        servername:   host,
        rejectUnauthorized: true,
        minVersion:   "TLSv1.3",
      }, dialTlsOpts || {});
      if (lookup) tlsOpts.lookup = lookup;
      try {
        var pqcShares = networkTls().pqc.getKeyShares();
        if (Array.isArray(pqcShares) && pqcShares.length > 0 && !tlsOpts.curves) {
          tlsOpts.curves = pqcShares.join(":");
        }
      } catch (_e) { /* drop-silent — tls module pre-init or non-Node */ }
      socket = tls.connect(tlsOpts);
    } else {
      var netOpts = { host: host, port: port };
      if (lookup) netOpts.lookup = lookup;
      socket = net.connect(netOpts);
    }
    this._socket = socket;
    socket.on("error", _onError);

    var connectEvent = parsed.protocol === "wss:" ? "secureConnect" : "connect";
    socket.once(connectEvent, function () {
      try { self._sendHandshake(); }
      catch (e) { self._handleSocketError(e); }
    });

    this._handshakeTimer = setTimeout(function () {
      self._handleSocketError(new WsClientError("ws-client/handshake-timeout",
        "Handshake exceeded " + self._opts.handshakeTimeoutMs + "ms"));
    }, self._opts.handshakeTimeoutMs);
    if (typeof this._handshakeTimer.unref === "function") this._handshakeTimer.unref();
  }

  _sendHandshake() {
    var opts = this._opts;
    var self = this;
    var parsed = opts.parsedUrl;
    var key = _generateKey();
    this._secKey = key;

    var hostHeader = parsed.host;
    var pathStr = parsed.pathname + (parsed.search || "");
    if (!pathStr) pathStr = "/";

    var lines = [
      "GET " + pathStr + " HTTP/1.1",
      "Host: " + hostHeader,
      "Upgrade: websocket",
      "Connection: Upgrade",
      "Sec-WebSocket-Key: " + key,
      "Sec-WebSocket-Version: 13",                                                       // RFC 6455 §1.9
    ];
    if (opts.origin) {
      if (safeBuffer.hasCrlf(opts.origin)) {
        throw new WsClientError("ws-client/bad-header",
          "Origin header value contains CR/LF (injection refused)");
      }
      lines.push("Origin: " + opts.origin);
    }
    if (opts.subprotocols.length > 0) {
      lines.push("Sec-WebSocket-Protocol: " + opts.subprotocols.join(", "));
    }
    if (opts.permessageDeflate) {
      lines.push("Sec-WebSocket-Extensions: permessage-deflate; client_max_window_bits");
    }
    var customHeaders = opts.headers || {};
    var forbidden = ["host", "upgrade", "connection", "sec-websocket-key",
                     "sec-websocket-version", "sec-websocket-protocol",
                     "sec-websocket-extensions", "sec-websocket-accept"];
    for (var hkey in customHeaders) {
      if (!Object.prototype.hasOwnProperty.call(customHeaders, hkey)) continue;
      if (forbidden.indexOf(hkey.toLowerCase()) !== -1) continue;
      var v = customHeaders[hkey];
      if (typeof v !== "string") continue;
      if (safeBuffer.hasCrlf(v)) {
        throw new WsClientError("ws-client/bad-header",
          "header " + JSON.stringify(hkey) + ": value contains CR/LF (injection refused)");
      }
      lines.push(hkey + ": " + v);
    }
    lines.push("");
    lines.push("");
    var request = lines.join("\r\n");
    this._handshakeBuf = Buffer.alloc(0);
    this._socket.write(request);
    this._socket.on("data", function (chunk) {
      if (self._readyState === "connecting") {
        self._consumeHandshake(chunk);
      } else {
        self._consumeFrames(chunk);
      }
    });
  }

  _consumeHandshake(chunk) {
    // allow:handrolled-buffer-collect-bounded-framing — handshake header capped at 64 KiB below; once handshake parses we switch to FrameParser
    this._handshakeBuf = Buffer.concat([this._handshakeBuf, chunk]);
    var headerEnd = this._handshakeBuf.indexOf("\r\n\r\n");
    if (headerEnd === -1) {
      if (safeBuffer.byteLengthOf(this._handshakeBuf) > C.BYTES.kib(64)) {
        this._handleSocketError(new WsClientError("ws-client/handshake-too-large",
          "handshake response exceeded 64 KiB before CRLFCRLF"));
      }
      return;
    }
    var headerSection = this._handshakeBuf.subarray(0, headerEnd).toString("utf8");
    var rest = this._handshakeBuf.subarray(headerEnd + 4);

    var lines = headerSection.split("\r\n");
    var statusLine = lines[0] || "";
    var match = statusLine.match(/^HTTP\/1\.\d (\d{3})/);
    if (!match) {
      this._handleSocketError(new WsClientError("ws-client/bad-status-line",
        "handshake response status line malformed: " + JSON.stringify(statusLine)));
      return;
    }
    var status = parseInt(match[1], 10);
    if (status !== 101) {                                                                 // HTTP 101
      // Body bytes after the header section are the server's
      // explanation. Surface them on the error so callers can branch
      // on the status code and inspect the body without re-parsing
      // the message string.
      var bodyText = "";
      try { bodyText = rest.toString("utf8"); } catch (_e) { /* drop-silent */ }
      // Pass status as the 3rd arg so the classifier derives permanent from it
      // (4xx terminal, 5xx transient) and statusCode is set; keep .status as the
      // pre-existing alias callers may already read.
      var statusErr = new WsClientError("ws-client/bad-status",
        "handshake response status was " + status + " (expected 101 Switching Protocols)", status);
      statusErr.status = status;
      statusErr.body = bodyText;
      this._handleSocketError(statusErr);
      return;
    }

    var headers = Object.create(null);
    var hkvps = structuredFields.parseKeyValuePieces(lines, 1, ":");
    structuredFields.forEachKeyValue(hkvps, function (key, value) {
      headers[key] = value;
    });

    if ((headers["upgrade"] || "").toLowerCase() !== "websocket" ||
        (headers["connection"] || "").toLowerCase().indexOf("upgrade") === -1) {
      this._handleSocketError(new WsClientError("ws-client/bad-upgrade",
        "handshake response missing Upgrade: websocket / Connection: Upgrade"));
      return;
    }

    var accept = headers["sec-websocket-accept"] || "";
    var expected = _expectedAccept(this._secKey, this._opts.handshakeGuid);
    if (accept !== expected) {
      this._handleSocketError(new WsClientError("ws-client/accept-mismatch",
        "handshake response Sec-WebSocket-Accept mismatch: peer responded with a key " +
        "that does not match the SHA-1(key+RFC-6455-GUID) hash"));
      return;
    }

    var negotiatedSubprotocol = headers["sec-websocket-protocol"] || null;
    if (negotiatedSubprotocol && this._opts.subprotocols.indexOf(negotiatedSubprotocol) === -1) {
      this._handleSocketError(new WsClientError("ws-client/bad-subprotocol",
        "server selected subprotocol " + JSON.stringify(negotiatedSubprotocol) +
        " not in client offer"));
      return;
    }
    this._negotiatedSubprotocol = negotiatedSubprotocol;

    this._negotiatedDeflate = false;
    this._negotiatedWindowBits = 15;                                                      // RFC 7692 default windowBits
    if (this._opts.permessageDeflate &&
        (headers["sec-websocket-extensions"] || "").indexOf("permessage-deflate") !== -1) {
      this._negotiatedDeflate = true;
      // Parse server_max_window_bits from the response — server may
      // narrow the window vs the default 15. We honour anything in
      // [8, 15]; outside that range we treat the response as malformed
      // and refuse the extension (RFC 7692 §7.1.2.1).
      var extLine = headers["sec-websocket-extensions"];
      var smwbMatch = extLine.match(/server_max_window_bits\s*=\s*"?(\d+)"?/);             // allow:regex-no-length-cap — bounded by header line + RFC 7692 §7.1
      if (smwbMatch) {
        var smwb = parseInt(smwbMatch[1], 10);
        if (smwb < 8 || smwb > 15) {                                                      // RFC 7692 windowBits range
          this._handleSocketError(new WsClientError("ws-client/deflate-error",
            "server_max_window_bits=" + smwb + " is outside RFC 7692 range [8, 15]"));
          return;
        }
        this._negotiatedWindowBits = smwb;
      }
    }

    if (this._handshakeTimer) {
      clearTimeout(this._handshakeTimer);
      this._handshakeTimer = null;
    }

    var fp = websocket().FrameParser;
    this._parser = new fp({ maxFrameBytes: this._opts.maxFrameBytes });
    this._readyState = "open";
    this._reconnectAttempt = 0;
    this._fragmentChunks = [];
    this._fragmentOpcode = null;
    this._fragmentBytes = 0;

    this._startHeartbeat();
    if (this._opts.auditOn) {
      try {
        audit().safeEmit({
          action:  "wsclient.connected",
          outcome: "success",
          actor:   null,
          metadata: {
            host:               this._opts.parsedUrl.host,
            subprotocol:        negotiatedSubprotocol,
            deflate:            this._negotiatedDeflate,
            serverWindowBits:   this._negotiatedWindowBits,
            tls:                this._opts.parsedUrl.protocol === "wss:",
            attempt:            this._reconnectAttempt,
            peerCertFingerprint: this._captureCertFingerprint(),
          },
        });
      } catch (_e) { /* drop-silent */ }
    }
    this.emit("open");

    if (rest.length > 0) this._consumeFrames(rest);
  }

  _consumeFrames(chunk) {
    if (!this._parser) return;
    try {
      var frames = this._parser.push(chunk) || [];
      for (var fi = 0; fi < frames.length; fi += 1) {
        this._handleFrame(frames[fi]);
      }
    } catch (e) {
      this._handleSocketError(e);
    }
  }

  _handleFrame(frame) {
    // Once the connection has been torn down (e.g. a prior frame in the same
    // parsed batch tripped maxMessageBytes and called _teardown, which sets
    // _closed synchronously), drop any remaining buffered frames — processing
    // them would emit a spurious cascade of protocol errors (a stray
    // continuation after the fragment state reset). A graceful close keeps
    // _closed false until the handshake completes, so the peer's CLOSE frame
    // is still processed and the normal close code surfaces.
    if (this._closed) return;
    // RFC 6455 §5.5: control frames MUST be <= 125 bytes AND non-fragmented.
    var isControl = frame.opcode === OPCODE_PING ||
                    frame.opcode === OPCODE_PONG ||
                    frame.opcode === OPCODE_CLOSE;
    if (isControl) {
      if (frame.payload.length > 125) {                                                   // RFC 6455 §5.5 control-frame cap
        this._handleSocketError(new WsClientError("ws-client/control-too-big",
          "control-frame payload exceeds 125 bytes (RFC 6455 §5.5)"));
        return;
      }
      if (frame.fin === false) {
        this._handleSocketError(new WsClientError("ws-client/control-fragmented",
          "control frame must have FIN=1 (RFC 6455 §5.5)"));
        return;
      }
    }
    // Fail the connection on any opcode outside the six RFC 6455 §5.2-defined
    // values (CONT/TEXT/BINARY/CLOSE/PING/PONG). Without this, a reserved
    // opcode (0x3-0x7, 0xB-0xF) from a malicious server fell through every
    // branch to the FIN block and emitted a (stale/empty) message — a
    // fragmented-message desync / frame-injection lever.
    if (frame.opcode !== OPCODE_CONT && frame.opcode !== OPCODE_TEXT &&
        frame.opcode !== OPCODE_BINARY && !isControl) {
      this._handleSocketError(new WsClientError("ws-client/reserved-opcode",
        "reserved/unknown WebSocket opcode 0x" + frame.opcode.toString(16) + " (RFC 6455 §5.2)"));
      return;
    }
    // Continuation frames MUST NOT carry rsv1 (RFC 7692 §6.1) — only
    // the first frame of a compressed message sets rsv1.
    if (frame.opcode === OPCODE_CONT && frame.rsv1) {
      this._handleSocketError(new WsClientError("ws-client/rsv1-on-continuation",
        "RSV1 set on continuation frame (RFC 7692 §6.1)"));
      return;
    }
    if (frame.opcode === OPCODE_PING) {
      this._sendFrame(OPCODE_PONG, frame.payload, { fin: true });
      return;
    }
    if (frame.opcode === OPCODE_PONG) {
      this._pongDeadline = Date.now() + this._opts.pongMs;
      return;
    }
    if (frame.opcode === OPCODE_CLOSE) {
      var code = CLOSE_NORMAL, reason = "";
      if (frame.payload.length >= 2) {
        code = frame.payload.readUInt16BE(0);
        var reasonBytes = frame.payload.subarray(2);                                      // RFC 6455 close-frame layout
        try {
          reason = new TextDecoder("utf-8", { fatal: true }).decode(reasonBytes);
        } catch (_e) {
          this._handleSocketError(new WsClientError("ws-client/invalid-utf8",
            "close-frame reason is not valid UTF-8 (RFC 6455 §5.6 + §7.4.1)"));
          return;
        }
      }
      this._readyState = "closing";
      this._sendFrame(OPCODE_CLOSE, frame.payload, { fin: true });
      this._teardown(code, reason, false);
      return;
    }
    if (frame.opcode === OPCODE_TEXT || frame.opcode === OPCODE_BINARY) {
      if (this._fragmentOpcode != null) {
        this._handleSocketError(new WsClientError("ws-client/protocol-error",
          "received non-continuation opcode mid-fragmented-message"));
        return;
      }
      this._fragmentOpcode = frame.opcode;
      this._fragmentRsv1   = frame.rsv1 === true;
      this._fragmentChunks = [frame.payload];
      this._fragmentBytes  = safeBuffer.byteLengthOf(frame.payload);
    } else if (frame.opcode === OPCODE_CONT) {
      if (this._fragmentOpcode == null) {
        this._handleSocketError(new WsClientError("ws-client/protocol-error",
          "received continuation opcode with no prior text/binary frame"));
        return;
      }
      this._fragmentChunks.push(frame.payload);
      this._fragmentBytes += safeBuffer.byteLengthOf(frame.payload);
    }
    // Enforce maxMessageBytes on the RUNNING fragment total, not only at FIN:
    // a peer that streams continuation frames and never sets FIN would
    // otherwise grow _fragmentChunks without bound, one maxFrameBytes-sized
    // frame at a time (CWE-770 / CWE-400). The per-frame parser cap bounds a
    // single frame, never the sum.
    if (this._fragmentOpcode != null && this._fragmentBytes > this._opts.maxMessageBytes) {
      this._fragmentChunks = [];
      this._fragmentOpcode = null;
      this._fragmentRsv1   = false;
      this._fragmentBytes  = 0;
      this._handleSocketError(new WsClientError("ws-client/message-too-big",
        "incoming message exceeds maxMessageBytes (" + this._opts.maxMessageBytes + ")"));
      return;
    }
    if (frame.fin) {
      var fullPayload = Buffer.concat(this._fragmentChunks);                              // allow:handrolled-buffer-collect-bounded-framing — bounded by maxMessageBytes below
      if (safeBuffer.byteLengthOf(fullPayload) > this._opts.maxMessageBytes) {
        this._handleSocketError(new WsClientError("ws-client/message-too-big",
          "incoming message exceeds maxMessageBytes (" + this._opts.maxMessageBytes + ")"));
        return;
      }
      var isBinary = this._fragmentOpcode === OPCODE_BINARY;
      var firstFrameRsv1 = this._fragmentRsv1 === true;
      this._fragmentChunks = [];
      this._fragmentOpcode = null;
      this._fragmentRsv1 = false;
      this._fragmentBytes = 0;
      if (this._negotiatedDeflate && firstFrameRsv1) {
        try {
          var zlib = require("node:zlib");                                                     // allow:inline-require — zlib only on deflate-negotiated path
          var compressed = Buffer.concat([fullPayload, Buffer.from([0x00, 0x00, 0xff, 0xff])]); // RFC 7692 §7.2.2 deflate trailer
          // Decompression-bomb defense: zlib.inflateRawSync's
          // `maxOutputLength` aborts the inflate the moment the
          // output would exceed maxMessageBytes — never decode GBs
          // from a 100-byte compressed frame.
          var inflated = _inflateRawCappedSync(zlib, compressed, this._opts.maxMessageBytes,
            this._negotiatedWindowBits);
          fullPayload = inflated;
        } catch (e) {
          this._handleSocketError(new WsClientError("ws-client/deflate-error",
            "permessage-deflate inflate failed or exceeded maxMessageBytes: " + e.message));
          return;
        }
      }
      this._bytesReceived += fullPayload.length;
      var data;
      if (isBinary) {
        data = fullPayload;
      } else {
        try {
          data = new TextDecoder("utf-8", { fatal: true }).decode(fullPayload);
        } catch (_e) {
          this._handleSocketError(new WsClientError("ws-client/invalid-utf8",
            "text frame is not valid UTF-8 (RFC 6455 §5.6)"));
          return;
        }
      }
      // Auto-parse text frames as JSON when the operator opted in via
      // `parse: "json"` or supplied `parser: fn`. JSON-only protocols
      // (most modern WS APIs) get a typed message argument without a
      // wrapper layer; parse failures surface as 'error' events
      // rather than crashing the message handler.
      var parsed = data;
      var parsedOk = true;
      if (!isBinary && this._opts.parse === "json") {
        try { parsed = safeJson().parse(data, { maxBytes: this._opts.maxMessageBytes }); }
        catch (e) {
          parsedOk = false;
          this.emit("error", new WsClientError("ws-client/json-parse",
            "text frame is not valid JSON: " + ((e && e.message) || String(e))));
        }
      } else if (!isBinary && typeof this._opts.parser === "function") {
        try { parsed = this._opts.parser(data); }
        catch (e) {
          parsedOk = false;
          this.emit("error", new WsClientError("ws-client/parser-failed",
            "operator parser threw: " + ((e && e.message) || String(e))));
        }
      }
      if (parsedOk) this.emit("message", parsed, isBinary);
    }
  }

  _sendFrame(opcode, payload, opts) {
    if (!this._socket || this._socket.destroyed) return;
    var serialize = websocket().serializeFrame;
    var frame = serialize(opcode, payload, Object.assign({ mask: true }, opts || {}));
    this._bytesSent += frame.length;
    this._socket.write(frame);
  }

  _captureCertFingerprint() {
    try {
      if (this._socket && typeof this._socket.getPeerCertificate === "function") {
        var cert = this._socket.getPeerCertificate(false);
        if (cert && cert.fingerprint256) return cert.fingerprint256;
      }
    } catch (_e) { /* drop-silent */ }
    return null;
  }

  send(data, opts) {
    if (this._readyState !== "open") {
      throw new WsClientError("ws-client/not-open",
        "send: socket is not open (readyState=" + this._readyState + ")");
    }
    opts = opts || {};
    var isBinary = Buffer.isBuffer(data);
    var payload;
    if (isBinary) {
      payload = data;
    } else if (typeof data === "string") {
      payload = Buffer.from(data, "utf8");
    } else {
      payload = Buffer.from(JSON.stringify(data), "utf8");
    }
    if (safeBuffer.byteLengthOf(payload) > this._opts.maxMessageBytes) {
      throw new WsClientError("ws-client/payload-too-big",
        "send: payload exceeds maxMessageBytes (" + this._opts.maxMessageBytes + ")");
    }
    this._sendFrame(isBinary ? OPCODE_BINARY : OPCODE_TEXT, payload, { fin: true });
  }

  ping(payload) {
    if (this._readyState !== "open") return;
    this._sendFrame(OPCODE_PING, payload || Buffer.alloc(0), { fin: true });
  }

  close(code, reason) {
    // Operator-initiated close cancels any pending reconnect — once
    // close() is called, the operator wants this client retired.
    this._cancelReconnect();
    if (this._readyState === "closed" || this._readyState === "closing") {
      // Even when already closed, ensure we mark as fully retired so
      // a previously-scheduled reconnect can't fire after close().
      this._closed = true;
      return;
    }
    code = (typeof code === "number") ? code : CLOSE_NORMAL;
    reason = (typeof reason === "string") ? reason : "";
    // RFC 6455 §5.5: control frames must be <= 125 bytes total. The
    // close payload is 2 status bytes + UTF-8 reason; that gives us
    // 123 bytes for the reason. Truncate at the BYTE level rather
    // than character level since a 123-byte UTF-8 sequence might end
    // mid-codepoint — to be RFC-safe we truncate at code-point
    // boundaries.
    var rb = Buffer.from(reason, "utf8");
    if (rb.length > 123) {                                                                // RFC 6455 §5.5 (125 - 2)
      // Truncate at last complete codepoint within 123 bytes. Use a
      // fatal TextDecoder to validate; back off one byte at a time
      // until the slice decodes cleanly. Bounded by [123 - 3, 123]
      // since a single UTF-8 codepoint is at most 4 bytes.
      var fatal = new TextDecoder("utf-8", { fatal: true });
      var truncated = rb.subarray(0, 123);                                                // RFC 6455 §5.5
      for (var bi = 0; bi < 4; bi += 1) {                                                 // max UTF-8 codepoint width
        try { fatal.decode(truncated); break; }
        catch (_e) { truncated = truncated.subarray(0, truncated.length - 1); }
      }
      rb = truncated;
    }
    var payload = Buffer.alloc(2 + rb.length);                                            // RFC 6455 close-frame layout
    payload.writeUInt16BE(code, 0);
    rb.copy(payload, 2);                                                                  // RFC 6455 close-frame layout
    this._readyState = "closing";
    this._sendFrame(OPCODE_CLOSE, payload, { fin: true });
    var self = this;
    setTimeout(function () { self._teardown(code, reason, false); }, 1000).unref();       // graceful close grace window
  }

  _teardown(code, reason, willReconnect) {
    if (this._closed && !willReconnect) return;
    this._closed = !willReconnect;
    if (this._socket && !this._socket.destroyed) {
      try { this._socket.destroy(); } catch (_e) { /* drop-silent */ }
    }
    if (this._pingTimer)      { try { this._pingTimer.stop(); } catch (_e) { /* drop-silent */ } this._pingTimer = null; }
    if (this._handshakeTimer) { clearTimeout(this._handshakeTimer); this._handshakeTimer = null; }
    this._readyState = "closed";
    this._parser = null;
    this._fragmentChunks = [];
    this._fragmentOpcode = null;
    if (this._opts.auditOn) {
      try {
        audit().safeEmit({
          action:  "wsclient.closed",
          outcome: "success",
          actor:   null,
          metadata: { code: code, reason: reason, host: this._opts.parsedUrl.host },
        });
      } catch (_e) { /* drop-silent */ }
    }
    this.emit("close", code, reason);
    if (willReconnect) this._scheduleReconnect();
  }

  _handleSocketError(err) {
    // Swallow post-close socket errors. After a consumer-initiated
    // close() the framework waits for the server to send back its
    // close frame; if the server tears down its end with an
    // ECONNRESET / EPIPE / "premature close" instead of a graceful
    // close frame, the underlying socket emits an error that bubbles
    // up here. From the consumer's perspective the close already
    // happened — surfacing a "socket error" event after `close` was
    // called is noise that hides real bugs.
    if (this._closed && err && (
        err.code === "ECONNRESET" || err.code === "EPIPE" ||
        err.code === "ECONNABORTED" || err.code === "ERR_STREAM_PREMATURE_CLOSE")) {
      return;
    }
    var permanent = _isPermanentError(err);
    if (this._opts.auditOn) {
      try {
        audit().safeEmit({
          action:  "wsclient.error",
          outcome: "failure",
          actor:   null,
          metadata: {
            host:     this._opts.parsedUrl.host,
            code:     err && err.code || "unknown",
            message:  err && err.message || String(err),
            attempt:  this._reconnectAttempt,
            bytesSent:     this._bytesSent,
            bytesReceived: this._bytesReceived,
            permanent:     permanent,
          },
        });
      } catch (_e) { /* drop-silent */ }
    }
    this.emit("error", err);
    var rOpts = this._opts.reconnectOpts;
    var willReconnect = rOpts.enabled &&
                        !permanent &&
                        this._reconnectAttempt < rOpts.maxAttempts &&
                        !this._closed;
    this._teardown(CLOSE_ABNORMAL, err.message || "error", willReconnect);
  }

  _scheduleReconnect() {
    var rOpts = this._opts.reconnectOpts;
    this._reconnectAttempt += 1;
    var attempt = Math.min(this._reconnectAttempt, 30);                                   // clamp 2^attempt overflow
    var ceiling = Math.min(rOpts.maxMs, rOpts.baseMs * Math.pow(2, attempt - 1));
    var delay   = Math.floor(Math.random() * ceiling);                                    // allow:math-random-noncrypto-jitter-sampling — backoff jitter, not security
    var self = this;
    this._reconnectTimer = setTimeout(function () {
      self._reconnectTimer = null;
      if (self._closed) return;                                                           // operator-cancelled in flight
      // Re-resolve + re-validate the target (urlFor swap, DNS rebind) before
      // reconnecting — awaited, so a now-private/metadata address is refused.
      self._prepareDial().then(function () {
        if (self._closed) return;
        self._dial();
      }).catch(function (e) { self._handleSocketError(e); });
    }, delay);
    if (typeof this._reconnectTimer.unref === "function") this._reconnectTimer.unref();
    this.emit("reconnecting", { attempt: this._reconnectAttempt, delayMs: delay });
  }

  _cancelReconnect() {
    if (this._reconnectTimer) {
      try { clearTimeout(this._reconnectTimer); } catch (_e) { /* drop-silent */ }
      this._reconnectTimer = null;
    }
  }

  // Operator-facing API — cancel any pending reconnect AND mark the
  // client closed so future scheduling is also blocked. Pairs with
  // `close()` for "I want this client done, even mid-reconnect".
  cancelReconnect() {
    this._cancelReconnect();
    this._closed = true;
    return this;
  }

  _startHeartbeat() {
    var self = this;
    this._pongDeadline = Date.now() + this._opts.pongMs;
    this._pingTimer = safeAsync.repeating(function () { self._heartbeat(); }, this._opts.pingMs);
  }

  _heartbeat() {
    if (this._readyState !== "open") return;
    if (Date.now() > this._pongDeadline) {
      this._handleSocketError(new WsClientError("ws-client/pong-timeout",
        "no pong received within " + this._opts.pongMs + "ms"));
      return;
    }
    this._sendFrame(OPCODE_PING, Buffer.alloc(0), { fin: true });
  }
}

module.exports = {
  connect:       connect,
  WsClientError: WsClientError,
  OPCODE_TEXT:   OPCODE_TEXT,
  OPCODE_BINARY: OPCODE_BINARY,
  CLOSE_NORMAL:  CLOSE_NORMAL,
  CLOSE_GOING_AWAY: CLOSE_GOING_AWAY,
  WS_GUID:       WS_GUID,
};
