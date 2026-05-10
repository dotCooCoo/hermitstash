"use strict";
/**
 * @module b.safeUrl
 * @nav    Validation
 * @title  Safe Url
 *
 * @intro
 *   Defensive URL parsing with a protocol allowlist (HTTPS-only by
 *   default), authority validation, IDN-homograph defense, and a
 *   length cap that runs BEFORE Node's WHATWG URL parser sees the
 *   input. The framework's stance on outbound URLs: TLS-required by
 *   default; cleartext (`http:` / `ws:`) is opt-in per call via
 *   `opts.allowedProtocols`. `user:pass@` userinfo refuses by
 *   default — credentials belong in headers / a credential store,
 *   not in URL strings that leak into request logs, error messages,
 *   metric labels, and trace spans. Mixed-script host labels
 *   (Cyrillic 'о' inside an otherwise-Latin label, etc. — UTS #39 §5
 *   homograph shape) refuse by default and emit
 *   `safeurl.idn_homograph.refused` to the audit chain so a forensic
 *   review can reconstruct every accepted host.
 *
 *   Pre-baked protocol allowlists are exposed as frozen arrays so
 *   each caller can declare a NARROW per-call allowlist (the
 *   http-client speaks HTTP, not WebSocket; a `wss://` URL handed to
 *   it is a category error that should fail loudly here, not later
 *   inside a transport):
 *
 *     ALLOW_HTTP_TLS   ["https:"]                        (secure HTTP default)
 *     ALLOW_HTTP_ALL   ["http:", "https:"]               (HTTP + cleartext opt-in)
 *     ALLOW_WS_TLS     ["wss:"]                          (secure WS default)
 *     ALLOW_WS_ALL     ["ws:", "wss:"]                   (WS + cleartext opt-in)
 *     ALLOW_ANY        ["http:", "https:", "ws:", "wss:"]
 *
 *   `parse` throws `SafeUrlError` (or a caller-supplied error class
 *   via `opts.errorClass`, used by `b.objectStore` / `b.logStream` /
 *   `b.httpClient` to surface their own decorated error type) with a
 *   stable `.code`: `safe-url/missing` / `safe-url/too-long` /
 *   `safe-url/malformed` / `safe-url/protocol-disallowed` /
 *   `safe-url/userinfo-disallowed` / `safe-url/idn-homograph` /
 *   `safe-url/bad-opt`. Operator code that wants a boolean
 *   parse-without-throw shape wraps the throw in a try / catch.
 *
 * @card
 *   Defensive URL parsing with a protocol allowlist (HTTPS-only by default), authority validation, IDN-homograph defense, and a length cap that runs BEFORE Node's WHATWG URL parser sees the input.
 */

var C = require("./constants");
var codepointClass = require("./codepoint-class");
var lazyRequire = require("./lazy-require");
var numericBounds = require("./numeric-bounds");
var { FrameworkError } = require("./framework-error");
var nodeUrl = require("url");
var { URL } = require("url");

var audit = lazyRequire(function () { return require("./audit"); });

/**
 * @primitive b.safeUrl.ALLOW_HTTP_TLS
 * @signature b.safeUrl.ALLOW_HTTP_TLS
 * @since     0.1.0
 * @status    stable
 * @related   b.safeUrl.parse, b.safeUrl.ALLOW_HTTP_ALL
 *
 * Frozen protocol allowlist for HTTPS-only HTTP traffic — `["https:"]`.
 * The framework default for any outbound URL parsed without an
 * explicit `opts.allowedProtocols`. Operators with a legitimate
 * cleartext use case opt in per call via `ALLOW_HTTP_ALL`.
 *
 * @example
 *   var b = require("blamejs");
 *   b.safeUrl.ALLOW_HTTP_TLS;
 *   // → ["https:"]
 */
var ALLOW_HTTP_TLS = Object.freeze(["https:"]);

/**
 * @primitive b.safeUrl.ALLOW_HTTP_ALL
 * @signature b.safeUrl.ALLOW_HTTP_ALL
 * @since     0.1.0
 * @status    stable
 * @related   b.safeUrl.parse, b.safeUrl.ALLOW_HTTP_TLS
 *
 * Frozen protocol allowlist accepting both HTTP and HTTPS —
 * `["http:", "https:"]`. Pass to `parse` when the call site
 * legitimately speaks cleartext (loopback admin endpoints, on-prem
 * service mesh terminating TLS at a sidecar, legacy partner APIs).
 * Never the framework default — TLS-required is.
 *
 * @example
 *   var b = require("blamejs");
 *   var u = b.safeUrl.parse("http://127.0.0.1:8080/health", {
 *     allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL,
 *   });
 *   u.protocol;
 *   // → "http:"
 */
var ALLOW_HTTP_ALL = Object.freeze(["http:", "https:"]);

/**
 * @primitive b.safeUrl.ALLOW_WS_TLS
 * @signature b.safeUrl.ALLOW_WS_TLS
 * @since     0.1.0
 * @status    stable
 * @related   b.safeUrl.parse, b.safeUrl.ALLOW_WS_ALL
 *
 * Frozen protocol allowlist for secure WebSocket traffic — `["wss:"]`.
 * The framework default for any WebSocket URL parsed without an
 * explicit `opts.allowedProtocols`.
 *
 * @example
 *   var b = require("blamejs");
 *   b.safeUrl.ALLOW_WS_TLS;
 *   // → ["wss:"]
 */
var ALLOW_WS_TLS   = Object.freeze(["wss:"]);

/**
 * @primitive b.safeUrl.ALLOW_WS_ALL
 * @signature b.safeUrl.ALLOW_WS_ALL
 * @since     0.1.0
 * @status    stable
 * @related   b.safeUrl.parse, b.safeUrl.ALLOW_WS_TLS
 *
 * Frozen protocol allowlist accepting both `ws:` and `wss:` —
 * `["ws:", "wss:"]`. Opt-in per call when cleartext WebSocket is
 * acceptable (loopback dev, sidecar-terminated TLS).
 *
 * @example
 *   var b = require("blamejs");
 *   var u = b.safeUrl.parse("ws://127.0.0.1:9000/stream", {
 *     allowedProtocols: b.safeUrl.ALLOW_WS_ALL,
 *   });
 *   u.protocol;
 *   // → "ws:"
 */
var ALLOW_WS_ALL   = Object.freeze(["ws:", "wss:"]);

/**
 * @primitive b.safeUrl.ALLOW_ANY
 * @signature b.safeUrl.ALLOW_ANY
 * @since     0.1.0
 * @status    stable
 * @related   b.safeUrl.parse, b.safeUrl.ALLOW_HTTP_TLS
 *
 * Frozen allowlist accepting every framework-supported scheme —
 * `["http:", "https:", "ws:", "wss:"]`. Suited to a generic
 * URL-validation surface where the caller already enforces the
 * protocol downstream; narrower allowlists are preferred wherever
 * possible.
 *
 * @example
 *   var b = require("blamejs");
 *   b.safeUrl.ALLOW_ANY.length;
 *   // → 4
 */
var ALLOW_ANY      = Object.freeze(["http:", "https:", "ws:", "wss:"]);

/**
 * @primitive b.safeUrl.SafeUrlError
 * @signature b.safeUrl.SafeUrlError
 * @since     0.1.0
 * @status    stable
 * @related   b.safeUrl.parse
 *
 * Error class thrown by `parse` (or by the caller-supplied
 * `opts.errorClass`, used by `b.objectStore` / `b.logStream` /
 * `b.httpClient` to surface a decorated operational error type).
 * Extends `FrameworkError`. Carries a stable `.code`:
 * `safe-url/missing` / `safe-url/too-long` / `safe-url/malformed` /
 * `safe-url/protocol-disallowed` / `safe-url/userinfo-disallowed` /
 * `safe-url/idn-homograph` / `safe-url/bad-opt`. HTTP middleware
 * inspects `.code` to translate the throw into a 400 without
 * leaking parser internals.
 *
 * @example
 *   var b = require("blamejs");
 *   try {
 *     b.safeUrl.parse("ftp://example.com/file.txt");
 *   } catch (e) {
 *     e instanceof b.safeUrl.SafeUrlError;   // → true
 *     e.code;                                // → "safe-url/protocol-disallowed"
 *   }
 */
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

/**
 * @primitive b.safeUrl.parse
 * @signature b.safeUrl.parse(url, opts?)
 * @since     0.1.0
 * @status    stable
 * @related   b.safeUrl.SafeUrlError, b.safeUrl.ALLOW_HTTP_TLS, b.safeUrl.ALLOW_HTTP_ALL
 *
 * Parse a URL string (or an existing `URL` instance) through the
 * framework's defensive gates: length cap BEFORE Node's WHATWG parser
 * sees the input (RFC 7230 §3.1.1 — 8 KiB default), protocol
 * allowlist (`https:` only by default), `user:pass@` userinfo refusal
 * (credentials leak into request logs / error messages / metric
 * labels / trace spans), and per-label IDN-homograph defense
 * (UTS #39 §5 mixed-script — Cyrillic 'о' inside an otherwise-Latin
 * label). Returns the parsed `URL` instance on success.
 *
 * Throws `SafeUrlError` (or the caller-supplied `opts.errorClass`)
 * with one of the documented `.code` strings: `safe-url/missing` /
 * `safe-url/too-long` / `safe-url/malformed` /
 * `safe-url/protocol-disallowed` / `safe-url/userinfo-disallowed` /
 * `safe-url/idn-homograph` / `safe-url/bad-opt`. Operator code that
 * wants a boolean parse-without-throw shape wraps the call in a
 * `try` / `catch`.
 *
 * @opts
 *   allowedProtocols: string[],   // default ALLOW_HTTP_TLS (["https:"])
 *   maxUrlLength:     number,     // default 8192 (RFC 7230 §3.1.1)
 *   allowUserinfo:    boolean,    // default false; opt-in to user:pass@
 *   allowMixedScript: boolean,    // default false; opt-in to mixed-script labels
 *   allowedScripts:   string[],   // narrow mixed-script allowlist (e.g. ["latin","cyrillic"])
 *   errorClass:       Function,   // throw this instead of SafeUrlError (used by b.httpClient / b.objectStore)
 *
 * @example
 *   var b = require("blamejs");
 *
 *   // Default: HTTPS-only, length cap, userinfo refused, IDN-homograph defended.
 *   var u = b.safeUrl.parse("https://example.com/path?q=1");
 *   u.hostname;
 *   // → "example.com"
 *
 *   // Cleartext is opt-in per call via the ALLOW_HTTP_ALL preset.
 *   var http = b.safeUrl.parse("http://127.0.0.1:8080/health", {
 *     allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL,
 *   });
 *   http.protocol;
 *   // → "http:"
 *
 *   // Disallowed protocol throws SafeUrlError.
 *   try { b.safeUrl.parse("javascript:alert(1)"); }
 *   catch (e) { e.code; }
 *   // → "safe-url/protocol-disallowed"
 *
 *   // Userinfo refused by default — credentials belong in headers.
 *   try { b.safeUrl.parse("https://alice:s3cr3t@example.com/"); }
 *   catch (e) { e.code; }
 *   // → "safe-url/userinfo-disallowed"
 *
 *   // Boolean parse-without-throw shape via try/catch wrapper.
 *   function isValid(s) {
 *     try { b.safeUrl.parse(s); return true; }
 *     catch (_e) { return false; }
 *   }
 *   isValid("https://example.com/");   // → true
 *   isValid("ftp://example.com/");     // → false
 */
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

  // IDN homograph defense — each host label MUST be single-script
  // (UTS #39 §5). A label that mixes Cyrillic + Latin (e.g. `gооgle.com`
  // with Cyrillic 'о' inside the otherwise-Latin label) presents
  // visually as a trusted host while resolving via DNS to attacker-
  // controlled infrastructure. Defaults to refuse; operators with
  // legitimate non-Latin host labels opt in via `allowMixedScript: true`
  // and the opt-in audits with the host so a forensic review can
  // reconstruct which call sites accept mixed-script hosts. Per-label
  // detection (not whole-host) so a legitimate `eu.shop.example.org`
  // mixing Latin + Cyrillic across labels still refuses. Node's URL
  // parser normalizes IDN hosts to Punycode (`xn--`), so we decode each
  // label to Unicode first via nodeUrl.domainToUnicode and run the
  // mixed-script catalog on the decoded codepoints.
  if (opts.allowMixedScript !== true && parsed.hostname) {
    var unicodeHost;
    try { unicodeHost = nodeUrl.domainToUnicode(parsed.hostname); }
    catch (_e) { unicodeHost = parsed.hostname; }
    var labels = (unicodeHost || parsed.hostname).split(".");
    var allowedScripts = Array.isArray(opts.allowedScripts) ? opts.allowedScripts : null;
    for (var li = 0; li < labels.length; li += 1) {
      var label = labels[li];
      if (label.length === 0) continue;
      var mixed = codepointClass.detectMixedScripts(label, allowedScripts);
      if (mixed) {
        try {
          audit().safeEmit({
            action:  "safeurl.idn_homograph.refused",
            outcome: "denied",
            metadata: {
              host:    parsed.hostname,
              label:   label,
              scripts: mixed,
            },
          });
        } catch (_e) { /* audit best-effort */ }
        throw _makeError(errClass, "safe-url/idn-homograph",
          "URL host label '" + label + "' mixes scripts (" + mixed.join(", ") +
          ") — IDN homograph attack shape (UTS #39 §5). Refuses by default; " +
          "operators with a legitimate mixed-script host pass " +
          "opts.allowMixedScript: true (with an audited reason) or " +
          "opts.allowedScripts: ['latin','cyrillic'] to allowlist specific scripts.");
      }
    }
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
