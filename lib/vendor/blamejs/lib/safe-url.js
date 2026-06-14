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
var nodeUrl = require("node:url");
var { URL } = require("node:url");

var audit = lazyRequire(function () { return require("./audit"); });
// ssrf-guard requires safe-url at top of file (the SSRF gate parses through
// the framework's defensive URL parser); lazyRequire breaks that cycle so the
// canonicalizer can reuse ssrf-guard's IP-literal canonicalization without an
// at-load circular require.
var ssrfGuard = lazyRequire(function () { return require("./ssrf-guard"); });

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
 * `safe-url/idn-homograph` / `safe-url/uncanonicalizable` /
 * `safe-url/bad-opt`. HTTP middleware inspects `.code` to translate
 * the throw into a 400 without leaking parser internals.
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

// RFC 3986 §6.2.2 percent-encoding normalization applied CONSERVATIVELY to a
// path segment string: uppercase the two hex digits of every valid escape
// (§6.2.2.2) and decode an escape of an unreserved character to its literal
// (§6.2.2.3). A malformed escape (`%`, `%g`, `%4`) is passed through verbatim
// so no information is invented. Query and fragment are NOT touched —
// reordering / re-decoding there can change application semantics (a `%26`
// inside a value is NOT the same as a literal `&`).
function _normalizePctPath(path) {
  if (typeof path !== "string" || path.indexOf("%") === -1) return path;
  var out = "";
  for (var i = 0; i < path.length; i += 1) {
    var ch = path.charAt(i);
    if (ch === "%") {
      // The escape's two hex digits — sliced to a fixed two-char window so
      // the regex test runs on a length-bounded string (no ReDoS surface).
      var pair = path.slice(i + 1, i + 3);
      if (pair.length === 2 && codepointClass.HEX_PAIR_RE.test(pair)) {
        var cc = parseInt(pair, 16);
        if (codepointClass.isUnreserved(cc)) {
          out += String.fromCharCode(cc);
        } else {
          out += "%" + pair.toUpperCase();
        }
        i += 2;
        continue;
      }
    }
    out += ch;
  }
  return out;
}

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

/**
 * @primitive b.safeUrl.format
 * @signature b.safeUrl.format(url)
 * @since     0.10.0
 * @status    stable
 *
 * Defensive wrapper around URL formatting that translates the
 * assertion-class throw documented in [CVE-2026-21712](https://nvd.nist.gov/vuln/detail/CVE-2026-21712)
 * (IDN crash via legacy `url.format()`) into a typed
 * `safe-url/format-failed` refusal. Accepts either a string URL or a
 * `URL` instance; returns the canonical string form.
 *
 * @example
 *   var out = b.safeUrl.format("https://example.com/a?q=1");
 *   // → "https://example.com/a?q=1"
 */
function format(url) {
  try {
    if (url instanceof URL) {
      return url.href;
    }
    if (typeof url !== "string") {
      throw new SafeUrlError("safe-url/format-bad-input",
        "safeUrl.format: url must be a string or URL instance");
    }
    // Constructing URL() is the path that surfaces the IDN-crash on
    // older Node — wrap so the listener never crashes.
    var u = new URL(url);   // allow:raw-new-url — safeUrl.format wraps URL ctor for CVE-2026-21712; this IS the safe wrapper.
    return u.href;
  } catch (e) {
    if (e && e.isSafeUrlError) throw e;
    throw new SafeUrlError("safe-url/format-failed",
      "safeUrl.format refused: " + ((e && e.message) || String(e)));
  }
}

/**
 * @primitive b.safeUrl.canonicalize
 * @signature b.safeUrl.canonicalize(input, opts?)
 * @since     0.15.6
 * @status    stable
 * @related   b.safeUrl.parse, b.ssrfGuard.canonicalizeHost, b.ssrfGuard.checkUrl
 *
 * Return the single canonical, comparable form of a URL so two
 * spellings of the same destination compare equal as strings. The use
 * cases are host allowlists, dedup / cache keys, and SSRF pre-checks —
 * exactly the places an attacker reaches for an obfuscated host
 * (`http://0177.0.0.1/`, `http://2130706433/`, `http://[::ffff:7f00:1]/`,
 * an IDN homograph, a trailing-dot or default-port variation) to slip
 * past a naive `===` allowlist. Routing every comparison through one
 * audited canonicalizer closes that class instead of leaving each
 * caller to re-derive normalization (which is how the bypasses happen).
 *
 * The canonical form is built from `parse`'s defensive gates plus the
 * security-relevant normalization set:
 *
 *   - Scheme and host lowercased (the WHATWG URL parser does this).
 *   - Host IDN labels emitted as their punycode `xn--` A-label; a
 *     mixed-script / confusable host label THROWS exactly as
 *     `parse` does (a homograph is never silently passed) unless the
 *     caller opts in via `allowMixedScript` / `allowedScripts`.
 *   - A trailing dot on the host is removed (`example.com.` →
 *     `example.com`) — DNS-equivalent but breaks string comparison.
 *   - An IP-literal host in ANY notation collapses to one canonical
 *     string via `b.ssrfGuard.canonicalizeHost` (the SAME byte parser
 *     the SSRF classifier matches on): IPv4 decimal / octal / hex /
 *     shorthand → dotted-quad; IPv6 (incl. IPv4-mapped + any
 *     zero-compression) → RFC 5952 lower-hex, bracketed.
 *   - The default port for the scheme is stripped (`:80` http/ws,
 *     `:443` https/wss — the parser does this).
 *   - Path `.` / `..` segments resolved (WHATWG), then RFC 3986 §6.2.2
 *     percent-normalization applied to the path: hex digits uppercased,
 *     escapes of unreserved characters decoded. Query and fragment are
 *     left BYTE-FOR-BYTE as parsed — reordering or re-decoding there can
 *     change application semantics.
 *
 * Throws `SafeUrlError` (or `opts.errorClass`): the `parse` codes for a
 * missing / too-long / malformed / disallowed-scheme / userinfo /
 * homograph input, plus `safe-url/uncanonicalizable` when a parsed URL
 * cannot be reduced to a safe canonical form. This is a config /
 * entry-point validator — it THROWS on bad input, it does NOT return a
 * best-effort string.
 *
 * @opts
 *   allowedSchemes:   string[],   // default ALLOW_ANY (http/https/ws/wss); canonicalize is a compare tool, not a fetch gate
 *   allowUserinfo:    boolean,    // default false; opt-in to keep user:pass@ (still discouraged)
 *   allowMixedScript: boolean,    // default false; opt-in to mixed-script host labels
 *   allowedScripts:   string[],   // narrow mixed-script allowlist (e.g. ["latin","cyrillic"])
 *   maxUrlLength:     number,     // default 8192 (RFC 7230 §3.1.1)
 *   errorClass:       Function,   // throw this instead of SafeUrlError
 *
 * @example
 *   var b = require("blamejs");
 *
 *   // Every obfuscated loopback spelling collapses to one string.
 *   b.safeUrl.canonicalize("http://0177.0.0.1/");      // → "http://127.0.0.1/"
 *   b.safeUrl.canonicalize("http://2130706433/");      // → "http://127.0.0.1/"
 *   b.safeUrl.canonicalize("http://127.1/");           // → "http://127.0.0.1/"
 *
 *   // Case, default port, trailing dot, and `..` all normalize.
 *   b.safeUrl.canonicalize("https://Example.COM:443/a/../b");
 *   // → "https://example.com/b"
 *
 *   // A disallowed scheme throws SafeUrlError.
 *   try { b.safeUrl.canonicalize("ftp://example.com/"); }
 *   catch (e) { e.code; }   // → "safe-url/protocol-disallowed"
 */
function canonicalize(input, opts) {
  opts = opts || {};
  var allowedSchemes = Array.isArray(opts.allowedSchemes) && opts.allowedSchemes.length > 0
    ? opts.allowedSchemes
    : ALLOW_ANY;

  // Route through parse — it owns the length cap, the scheme allowlist,
  // userinfo refusal, and the IDN-homograph defense. A parse throw (with
  // its stable .code) propagates unchanged so callers branch on the same
  // codes parse documents.
  var parsed = parse(input, {
    allowedProtocols: allowedSchemes,
    maxUrlLength:     opts.maxUrlLength,
    allowUserinfo:    opts.allowUserinfo,
    allowMixedScript: opts.allowMixedScript,
    allowedScripts:   opts.allowedScripts,
    errorClass:       opts.errorClass,
  });

  try {
    // The parser already lowercased the scheme + host, stripped the
    // default port, emitted IDN as punycode, and resolved `.`/`..`. The
    // canonicalizer adds: IP-literal collapse (shared with the SSRF
    // classifier), trailing-dot removal, and path percent-normalization.
    var scheme = parsed.protocol;                 // e.g. "https:"
    var rawHost = parsed.hostname;                // already lowercase / punycode / default-port-free
    var canonHost = ssrfGuard().canonicalizeHost(rawHost);
    // canonicalizeHost returns IPv6 UNbracketed; a URL authority needs the
    // brackets back. net.isIP via the colon is a sufficient discriminator
    // (a DNS label can't contain a colon).
    var host = canonHost.indexOf(":") !== -1 ? "[" + canonHost + "]" : canonHost;

    // Userinfo (`user:pass@`) is deliberately DROPPED from the canonical form.
    // The canonical string is built to be compared, used as a dedup / cache
    // key, or logged; carrying a credential into any of those leaks it, and
    // the username/password are not part of the resource's target identity for
    // an allowlist / SSRF decision. parse() already refuses userinfo unless
    // allowUserinfo:true; even then, the canonical output omits it (never reads
    // parsed.password), so two URLs that differ only in credentials canonicalize
    // equal.

    var port = parsed.port !== "" ? ":" + parsed.port : "";
    var path = _normalizePctPath(parsed.pathname);
    // Query + fragment: byte-for-byte as the parser emitted them. Reordering
    // a query or re-decoding a value changes semantics — out of scope for a
    // safe canonicalizer.
    var query = parsed.search;
    var fragment = parsed.hash;

    return scheme + "//" + host + port + path + query + fragment;
  } catch (e) {
    if (e && e.isSafeUrlError) throw e;
    throw _makeError(opts.errorClass, "safe-url/uncanonicalizable",
      "safeUrl.canonicalize could not reduce the URL to a canonical form: " +
        ((e && e.message) || String(e)));
  }
}

module.exports = {
  parse:           parse,
  format:          format,
  canonicalize:    canonicalize,
  SafeUrlError:    SafeUrlError,
  ALLOW_HTTP_TLS:  ALLOW_HTTP_TLS,
  ALLOW_HTTP_ALL:  ALLOW_HTTP_ALL,
  ALLOW_WS_TLS:    ALLOW_WS_TLS,
  ALLOW_WS_ALL:    ALLOW_WS_ALL,
  ALLOW_ANY:       ALLOW_ANY,
};
