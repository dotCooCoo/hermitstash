"use strict";
/**
 * @module b.tlsExporter
 * @nav    Crypto
 * @title  TLS Exporter
 *
 * @intro
 *   RFC 5705 / RFC 9266 TLS Exporter for binding application-layer
 *   keys and tokens to the live TLS session. The exporter is a
 *   deterministic byte-string derived from the TLS 1.3 master secret
 *   (RFC 8446 §7.5) — pulling 32 bytes under the
 *   `EXPORTER-Channel-Binding` label gives the RFC 9266
 *   "tls-exporter" channel-binding identifier.
 *
 *   Operators bind bearer tokens, FAPI 2.0 access-token-bound proofs,
 *   DPoP `cnf.tbh` claims, mTLS-derived auth headers, and session
 *   cookies to the exporter so a captured token cannot be replayed
 *   across a different TLS session — even if a downstream proxy
 *   re-terminates TLS (RFC 8705). The matching node primitive is
 *   `tls.TLSSocket#exportKeyingMaterial(length, label[, context])`.
 *
 *   Validation throws at the call site for sockets that aren't TLS
 *   (channel binding has no meaning over plaintext), sockets whose
 *   protocol is not TLS 1.3 (RFC 9266 §4 conformance), or
 *   out-of-range `length` values. Mismatched bindings on
 *   `verifyTokenBinding` return `false` rather than throwing —
 *   token-binding mismatch is a normal request-time outcome, not a
 *   config bug.
 *
 * @card
 *   RFC 5705 / RFC 9266 TLS Exporter for binding application-layer keys and tokens to the live TLS session.
 */

var bCrypto = require("./crypto");
var C = require("./constants");
var lazyRequire = require("./lazy-require");
var numericBounds = require("./numeric-bounds");
var { TlsExporterError } = require("./framework-error");

var _err = TlsExporterError.factory;

var observability = lazyRequire(function () { return require("./observability"); });

var EXPORTER_LABEL = "EXPORTER-Channel-Binding";
var EXPORTER_LENGTH = C.BYTES.bytes(32);

// _resolveTlsSocket — accept either a TLSSocket directly OR an http2/
// http(s) request whose .socket property is the TLSSocket. Operators
// almost always pass req.socket; the helper normalizes to the
// underlying socket so the exportKeyingMaterial call lands on the
// right object.
function _resolveTlsSocket(socketOrReq) {
  if (!socketOrReq) {
    throw _err("BAD_INPUT", "tlsExporter: socket or request object required");
  }
  // Express/Node http req → req.socket is the TLSSocket
  var sock = socketOrReq;
  if (typeof socketOrReq.exportKeyingMaterial !== "function" &&
      socketOrReq.socket &&
      typeof socketOrReq.socket.exportKeyingMaterial === "function") {
    sock = socketOrReq.socket;
  }
  if (typeof sock.exportKeyingMaterial !== "function") {
    throw _err("NOT_TLS",
      "tlsExporter: socket has no exportKeyingMaterial — channel binding requires TLS");
  }
  // Per RFC 9266 §4 the exporter is only defined for TLS 1.3. Older
  // protocol versions on the same API would technically return bytes
  // but the channel-binding semantics are NOT RFC 9266 conformant —
  // refuse so an operator-built check doesn't silently fall back to a
  // weaker binding.
  if (typeof sock.getProtocol === "function") {
    var proto = sock.getProtocol();
    if (proto && proto !== "TLSv1.3") {
      throw _err("NOT_TLS_1_3",
        "tlsExporter: TLS protocol is " + proto + ", RFC 9266 requires TLS 1.3");
    }
  }
  return sock;
}

/**
 * @primitive b.tlsExporter.fromSocket
 * @signature b.tlsExporter.fromSocket(socketOrReq, opts)
 * @since     0.7.45
 * @status    stable
 * @related   b.tlsExporter.bindToken, b.tlsExporter.verifyTokenBinding
 *
 * Extracts a TLS exporter from `socketOrReq` (either a `TLSSocket`
 * directly or an HTTP/HTTP/2 request whose `.socket` is the
 * `TLSSocket`). Defaults match RFC 9266 §4 — 32-byte length, label
 * `EXPORTER-Channel-Binding`, no context — yielding the canonical
 * "tls-exporter" channel-binding identifier. Custom labels and
 * lengths pass through for applications defining their own exporter-
 * derived identifiers; `length` is bounded 16..255 bytes per the
 * keying-material range Node enforces. Throws when the socket is not
 * TLS 1.3 or when the export call fails.
 *
 * @opts
 *   {
 *     label?:   string,    // default "EXPORTER-Channel-Binding"
 *     length?:  number,    // default 32; bounded 16..255 bytes
 *     context?: Buffer     // default null (RFC 8446 §7.5 "no context")
 *   }
 *
 * @example
 *   var b = require("blamejs").create();
 *   var server = b.https.createServer({ key: KEY, cert: CERT }, function (req, res) {
 *     var exporter = b.tlsExporter.fromSocket(req, { length: 32 });
 *     res.end("exporter bytes: " + exporter.length);
 *     // → "exporter bytes: 32"
 *   });
 *   server.listen(0);
 */
function fromSocket(socketOrReq, opts) {
  opts = opts || {};
  var label = typeof opts.label === "string" && opts.label.length > 0
    ? opts.label : EXPORTER_LABEL;
  // length is operator-tunable; validate-when-present via numeric-bounds
  // so a non-finite / negative / NaN input surfaces with the same error
  // shape every other framework primitive uses for numeric opts.
  numericBounds.requirePositiveFiniteIntIfPresent(opts.length,
    "tlsExporter.fromSocket: length", TlsExporterError, "BAD_LENGTH");
  var length = opts.length !== undefined ? opts.length : EXPORTER_LENGTH;
  if (length < C.BYTES.bytes(16) || length > C.BYTES.bytes(255)) {
    throw _err("BAD_LENGTH",
      "tlsExporter.fromSocket: length must be 16..255 bytes (got " + length + ")");
  }
  var context = opts.context;
  if (context !== undefined && context !== null && !Buffer.isBuffer(context)) {
    throw _err("BAD_CONTEXT",
      "tlsExporter.fromSocket: context must be Buffer or null");
  }

  var sock = _resolveTlsSocket(socketOrReq);
  var bytes;
  try {
    // Node's exportKeyingMaterial signature: (length, label, [context]).
    // Passing context=null (the default) corresponds to the RFC 8446
    // §7.5 "no context" case which RFC 9266 §4 mandates for channel
    // binding.
    bytes = context
      ? sock.exportKeyingMaterial(length, label, context)
      : sock.exportKeyingMaterial(length, label);
  } catch (e) {
    throw _err("EXPORT_FAILED",
      "tlsExporter.fromSocket: exportKeyingMaterial threw: " + e.message);
  }
  if (!Buffer.isBuffer(bytes) || bytes.length !== length) {
    throw _err("EXPORT_SHORT",
      "tlsExporter.fromSocket: short exporter (got " + (bytes && bytes.length) + " bytes, want " + length + ")");
  }

  try { observability().safeEvent("tlsExporter.fromSocket", 1, { outcome: "success" }); }
  catch (_e) { /* drop-silent */ }
  return bytes;
}

/**
 * @primitive b.tlsExporter.bindToken
 * @signature b.tlsExporter.bindToken(socketOrReq, token)
 * @since     0.7.45
 * @status    stable
 * @related   b.tlsExporter.fromSocket, b.tlsExporter.verifyTokenBinding
 *
 * Binds an opaque token (string or Buffer) to the current TLS session
 * by hashing `SHA3-512(label || exporter || token)`, where `label` is
 * `"blamejs/tls-exporter/bind/v1"`. The framework label keeps the
 * resulting digest distinct from any other place the same exporter +
 * token bytes might be hashed (audit-chain rows, derived-hash columns,
 * etc.) so a binding cannot be reinterpreted across primitives.
 * Operators store the returned hex digest alongside the token and
 * compare via `verifyTokenBinding` on the next request.
 *
 * @example
 *   var b = require("blamejs").create();
 *   b.https.createServer({ key: KEY, cert: CERT }, function (req, res) {
 *     var binding = b.tlsExporter.bindToken(req, "session-token-abc123");
 *     binding.length;
 *     // → 128 (SHA3-512 hex digest, 64 bytes × 2 hex chars)
 *     res.end("ok");
 *   }).listen(0);
 */
function bindToken(socketOrReq, token) {
  if (typeof token !== "string" && !Buffer.isBuffer(token)) {
    throw _err("BAD_TOKEN",
      "tlsExporter.bindToken: token must be a string or Buffer");
  }
  var exporter = fromSocket(socketOrReq);
  var tokenBuf = Buffer.isBuffer(token) ? token : Buffer.from(token, "utf8");
  // SHA3-512 of (label || exporter || token). The label binds the
  // hash to "tls-exporter binding" so the same token + exporter pair
  // does NOT produce the same hash if used in another framework
  // primitive (e.g., the audit-chain row hash).
  var labelBuf = Buffer.from("blamejs/tls-exporter/bind/v1", "utf8");
  return bCrypto.sha3Hash(Buffer.concat([labelBuf, exporter, tokenBuf]));
}

/**
 * @primitive b.tlsExporter.verifyTokenBinding
 * @signature b.tlsExporter.verifyTokenBinding(socketOrReq, token, claimedBinding)
 * @since     0.7.45
 * @status    stable
 * @related   b.tlsExporter.fromSocket, b.tlsExporter.bindToken
 *
 * Constant-time compare of a previously-issued `bindToken` digest
 * against a fresh binding computed from the current TLS session.
 * Returns `true` when the digests match (token belongs to this TLS
 * session) and `false` on any mismatch — token-binding mismatch is a
 * normal request-time outcome, so this primitive never throws on
 * mismatch. Throws only when `socketOrReq` is not TLS 1.3 or when
 * the input shape is wrong.
 *
 * @example
 *   var b = require("blamejs").create();
 *   b.https.createServer({ key: KEY, cert: CERT }, function (req, res) {
 *     var stored = b.tlsExporter.bindToken(req, "session-token-abc123");
 *     var ok = b.tlsExporter.verifyTokenBinding(req, "session-token-abc123", stored);
 *     ok;
 *     // → true
 *     res.end(ok ? "bound" : "mismatch");
 *   }).listen(0);
 */
function verifyTokenBinding(socketOrReq, token, claimedBinding) {
  var actual = bindToken(socketOrReq, token);
  if (typeof claimedBinding !== "string" || claimedBinding.length === 0) {
    return false;
  }
  return bCrypto.timingSafeEqual(actual, claimedBinding);
}

module.exports = {
  fromSocket:           fromSocket,
  bindToken:            bindToken,
  verifyTokenBinding:   verifyTokenBinding,
  EXPORTER_LABEL:       EXPORTER_LABEL,
  EXPORTER_LENGTH:      EXPORTER_LENGTH,
  TlsExporterError:     TlsExporterError,
};
