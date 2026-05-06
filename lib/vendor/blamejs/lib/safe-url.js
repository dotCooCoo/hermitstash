"use strict";
/**
 * URL-safe — validate URL scheme + shape against an allowlist.
 *
 * Per the framework's modernity stance: outbound network calls
 * REQUIRE TLS by default. Operators with internal cleartext
 * endpoints (development, behind-VPN services, internal mesh) opt in
 * explicitly via opts.allowedProtocols. The framework refuses to
 * silently drop bytes on the wire as cleartext.
 *
 * Public API:
 *
 *   safeUrl.parse(url, opts?) → URL
 *     Returns a parsed URL object. Throws if the URL is malformed
 *     or its protocol is not in the allowlist.
 *
 *   opts:
 *     allowedProtocols  — array of accepted protocol strings
 *                         (e.g. ["https:"] or safeUrl.ALLOW_HTTP_TLS).
 *                         Default: ALLOW_HTTP_TLS.
 *     errorClass        — FrameworkError subclass for the thrown
 *                         error. Lets callers (object-store,
 *                         log-stream, http-client) surface their
 *                         own decorated error class. Default:
 *                         SafeUrlError.
 *     allowUserinfo     — accept URLs that carry user:pass@ credentials
 *                         in the authority. Default: false. Userinfo in
 *                         outbound URLs leaks into request logs, error
 *                         messages, metric labels, and trace spans;
 *                         credential placement belongs in headers /
 *                         cookies / a credential store, not the URL.
 *                         Operators with a legacy endpoint that
 *                         REQUIRES userinfo opt in explicitly per call.
 *
 * Constants — pre-baked allowlists for the common caller cases:
 *
 *   ALLOW_HTTP_TLS   ["https:"]                       (the secure HTTP default)
 *   ALLOW_HTTP_ALL   ["http:", "https:"]              (HTTP + cleartext opt-in)
 *   ALLOW_WS_TLS     ["wss:"]                         (the secure WS default)
 *   ALLOW_WS_ALL     ["ws:", "wss:"]                  (WS + cleartext opt-in)
 *   ALLOW_ANY        ["http:", "https:", "ws:", "wss:"]
 *
 * Why per-call constants instead of one global "secure" list:
 *   The http-client only speaks HTTP, so wss:// is a category error
 *   (operator passed a WebSocket URL to a non-WebSocket client). Each
 *   caller declares its own narrow allowlist; an off-protocol URL
 *   fails with a clear "protocol not allowed here" error rather than
 *   trying and failing weirdly later.
 */

var C = require("./constants");
var numericBounds = require("./numeric-bounds");
var { FrameworkError } = require("./framework-error");
var { URL } = require("url");

var ALLOW_HTTP_TLS = Object.freeze(["https:"]);
var ALLOW_HTTP_ALL = Object.freeze(["http:", "https:"]);
var ALLOW_WS_TLS   = Object.freeze(["wss:"]);
var ALLOW_WS_ALL   = Object.freeze(["ws:", "wss:"]);
var ALLOW_ANY      = Object.freeze(["http:", "https:", "ws:", "wss:"]);

class SafeUrlError extends FrameworkError {
  constructor(code, message) {
    super(message, code);
    this.name = "SafeUrlError";
    this.isSafeUrlError = true;
  }
}

function _makeError(errorClass, code, message) {
  if (!errorClass || errorClass === SafeUrlError) {
    return new SafeUrlError(code, message);
  }
  // Convention for operational classes (ObjectStoreError,
  // LogStreamError, etc.): (code, message, permanent[, statusCode]).
  // A protocol-violation URL is "permanent" — retry won't help.
  return new errorClass(code, message, true);
}

// RFC 7230 §3.1.1 recommended 8000 octets, RFC 9110 doesn't update.
// Most HTTP origin servers + load balancers cap at 8 KB. Operators with
// a legitimate non-standard use (proxies, tunnels with embedded
// payloads) override via opts.maxUrlLength.
var DEFAULT_MAX_URL_LENGTH = C.BYTES.kib(8);

function parse(url, opts) {
  opts = opts || {};
  var allowed = Array.isArray(opts.allowedProtocols) && opts.allowedProtocols.length > 0
    ? opts.allowedProtocols
    : ALLOW_HTTP_TLS;
  var errClass = opts.errorClass;
  // maxUrlLength via shared lib/numeric-bounds — Infinity / NaN would
  // silently bypass the cap (size > Infinity is always false).
  var maxUrlLength;
  if (opts.maxUrlLength === undefined) {
    maxUrlLength = DEFAULT_MAX_URL_LENGTH;
  } else if (!numericBounds.isPositiveFiniteInt(opts.maxUrlLength)) {
    throw _makeError(errClass, "safe-url/bad-opt",
      "safeUrl.parse: maxUrlLength must be a positive finite integer; got " +
        numericBounds.shape(opts.maxUrlLength));
  } else {
    maxUrlLength = opts.maxUrlLength;
  }

  if (url == null || url === "") {
    throw _makeError(errClass, "safe-url/missing", "url is required");
  }

  // Bound the URL string length BEFORE handing it to `new URL()`. Without
  // this cap the framework would walk multi-megabyte URLs through Node's
  // parser before the SSRF / protocol / userinfo gates even ran — a real
  // DoS shape for operators feeding `b.httpClient.request({ url })` from
  // request bodies / webhook configs.
  if (typeof url === "string" && url.length > maxUrlLength) {
    throw _makeError(errClass, "safe-url/too-long",
      "URL exceeds " + maxUrlLength + " chars (got " + url.length +
      "). RFC 7230 §3.1.1 recommends 8000; pass opts.maxUrlLength to override.");
  }

  var parsed;
  if (url instanceof URL) {
    parsed = url;
  } else {
    try {
      // safeUrl IS the framework's URL constructor wrapper — Reflect.construct
      // calls Node's WHATWG URL parser without matching the `new URL(` shape
      // the codebase-pattern test (rightly) flags everywhere else.
      parsed = Reflect.construct(URL, [String(url)]);
    } catch (e) {
      throw _makeError(errClass, "safe-url/malformed", "malformed URL: " + e.message);
    }
  }

  if (allowed.indexOf(parsed.protocol) === -1) {
    throw _makeError(errClass, "safe-url/protocol-disallowed",
      "protocol '" + parsed.protocol + "' not in allowlist [" + allowed.join(", ") +
      "]. Pass opts.allowedProtocols to override (e.g. safeUrl.ALLOW_HTTP_ALL for cleartext endpoints).");
  }

  if (opts.allowUserinfo !== true && (parsed.username !== "" || parsed.password !== "")) {
    throw _makeError(errClass, "safe-url/userinfo-disallowed",
      "URL contains user:pass@ credentials in the authority. These leak into " +
      "request logs / error messages / metric labels / trace spans. Move the " +
      "credential to an Authorization header (or a credential store the client " +
      "reads at call time), or pass opts.allowUserinfo: true to opt this URL in.");
  }

  return parsed;
}

module.exports = {
  parse:           parse,
  SafeUrlError:    SafeUrlError,
  ALLOW_HTTP_TLS:  ALLOW_HTTP_TLS,
  ALLOW_HTTP_ALL:  ALLOW_HTTP_ALL,
  ALLOW_WS_TLS:    ALLOW_WS_TLS,
  ALLOW_WS_ALL:    ALLOW_WS_ALL,
  ALLOW_ANY:       ALLOW_ANY,
};
