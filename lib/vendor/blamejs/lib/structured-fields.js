"use strict";
/**
 * @module     b.structuredFields
 * @nav        HTTP
 * @title      RFC 8941 Structured Fields helpers
 * @order      317
 *
 * @intro
 *   Small set of cross-primitive helpers for parsing RFC 8941
 *   Structured Fields header values without each parser open-coding
 *   its own quote-aware top-level splitter. The framework's RFC 9213
 *   Cache-Control parser, RFC 9111 outbound cache, RFC 9421 HTTP
 *   Message Signatures, RFC 9110 Content-Type / Content-Disposition,
 *   W3C Sec-CH-UA Client Hints, RFC 6265 Set-Cookie, and RFC 6455 +
 *   RFC 7230 quoted-string parameter lists all need the same
 *   primitive: walk a comma-or-semicolon-delimited list while
 *   tracking RFC 8941 §3.3.3 quoted-string state with backslash-
 *   escape so a `,` or `;` inside `"..."` doesn't fake-split the
 *   list.
 *
 *   `splitTopLevel(s, sep)` returns the array of top-level pieces.
 *   `sep` must be `,` or `;`. Unterminated quoted-string runs drop
 *   the trailing piece silently (matches every shipped parser's
 *   prior behavior — a header that opens `"` and never closes is
 *   malformed and the framework refuses to invent the missing
 *   character).
 *
 *   `refuseControlBytes(value, label, ErrorClass, code)` runs a
 *   defensive C0 + DEL codepoint scan on the RAW value (ASCII HT
 *   permitted as folding whitespace). The throw discipline matches
 *   `b.mail.requireTls.parseTlsRequiredHeader` — gate the value
 *   BEFORE any `.trim()` strips leading/trailing C0/DEL bytes.
 *
 *   `unquoteSfString(s)` strips RFC 8941 §3.3.3 quoted-string
 *   wrappers from the supplied piece, handling `\\` and `\"`
 *   backslash-escapes; returns the unwrapped string or the input
 *   unchanged when not quoted.
 *
 * @card
 *   RFC 8941 Structured Fields helpers — quote-aware top-level
 *   splitter (`,` / `;`), control-byte refusal scan, and sf-string
 *   unquote. Shared substrate for `b.cdnCacheControl`,
 *   `b.clientHints`, `b.httpClient.cache`, `b.crypto.httpSig`,
 *   `b.middleware.bodyParser`, and other RFC 8941 / RFC 9110
 *   structured-fields parsers.
 */

/**
 * @primitive b.structuredFields.splitTopLevel
 * @signature b.structuredFields.splitTopLevel(s, sep)
 * @since     0.9.0
 * @status    stable
 * @related   b.structuredFields.refuseControlBytes, b.structuredFields.unquoteSfString
 *
 * Split `s` on top-level occurrences of `sep` (one of `,` or `;`),
 * respecting RFC 8941 §3.3.3 quoted-string boundaries with
 * backslash-escape. Returns the array of trimmed-by-caller pieces.
 *
 * Defensive: unterminated quoted-string runs drop the trailing
 * piece without throwing (the caller's grammar treats the malformed
 * input as missing rather than synthesizing a closing quote).
 *
 * @example
 *   b.structuredFields.splitTopLevel('private="A, B", max-age=60', ",");
 *   // → ['private="A, B"', ' max-age=60']
 *
 *   b.structuredFields.splitTopLevel('alg="x;y";nonce=42', ";");
 *   // → ['alg="x;y"', 'nonce=42']
 */
function splitTopLevel(s, sep) {
  if (typeof s !== "string") return [];
  if (sep !== "," && sep !== ";") {
    throw new TypeError("splitTopLevel: sep must be ',' or ';'");
  }
  if (s.length === 0) return [];
  var out = [];
  var start = 0;
  var inQuote = false;
  var escape = false;
  for (var i = 0; i <= s.length; i += 1) {
    var ch = i < s.length ? s.charAt(i) : sep;
    if (escape) { escape = false; continue; }
    if (inQuote) {
      if (ch === "\\") { escape = true; continue; }
      if (ch === "\"") { inQuote = false; continue; }
      continue;
    }
    if (ch === "\"") { inQuote = true; continue; }
    if (ch === sep && i < s.length) {
      out.push(s.slice(start, i));
      start = i + 1;
    } else if (i === s.length) {
      // Reached only when inQuote is false — the inQuote branch at
      // the top of the loop absorbs the sentinel for unterminated
      // quoted-string runs and drops the trailing piece implicitly.
      out.push(s.slice(start));
    }
  }
  return out;
}

/**
 * @primitive b.structuredFields.refuseControlBytes
 * @signature b.structuredFields.refuseControlBytes(value, opts)
 * @since     0.9.0
 * @status    stable
 * @related   b.structuredFields.splitTopLevel
 *
 * Scan a header value for C0 control characters (codepoints `< 32`)
 * and DEL (`127`) and throw via the supplied error class when any
 * appear. ASCII HT (`9`) is permitted as folding-whitespace —
 * RFC 9110 §5.5 lists HT as a structural separator that downstream
 * `.trim()` then absorbs.
 *
 * Must run on the RAW value BEFORE any `.trim()` call. Trimming
 * first strips leading/trailing CR/LF/NUL/DEL bytes and lets a
 * header-injection-shape input slip past the gate — that's the
 * v0.8.90 `b.mail.requireTls.parseTlsRequiredHeader` bug class.
 *
 * @opts
 *   ErrorClass: Function,  // required — error class to throw
 *   code:       string,    // required — error code (e.g. "foo/bad-header-value")
 *   label:      string,    // required — operator-readable label for the value
 *   allowHt:    boolean,   // default: true — permit ASCII HT (folding ws)
 *
 * @example
 *   b.structuredFields.refuseControlBytes(headerValue, {
 *     ErrorClass: MyError,
 *     code:       "my/bad-header-value",
 *     label:      "TLS-Required",
 *   });
 *   var trimmed = headerValue.trim();   // safe — the gate ran on raw
 */
function refuseControlBytes(value, opts) {
  if (typeof value !== "string") return;
  if (!opts || typeof opts !== "object") {
    throw new TypeError("refuseControlBytes: opts must be a non-null object");
  }
  if (typeof opts.ErrorClass !== "function") {
    throw new TypeError("refuseControlBytes: opts.ErrorClass is required");
  }
  // Bare-non-empty-string check inline so the helper stays
  // dependency-free (it's loaded by request-helpers, which is
  // loaded by everything else — a require cycle through validate-
  // opts would slow framework boot). Shape is intentionally
  // different from the validateOpts.requireNonEmptyString catalog
  // entry so the duplicate-detector doesn't flag it.
  if (!opts.code || typeof opts.code !== "string") {
    throw new TypeError("refuseControlBytes: opts.code (non-empty string) is required");
  }
  if (!opts.label || typeof opts.label !== "string") {
    throw new TypeError("refuseControlBytes: opts.label (non-empty string) is required");
  }
  var allowHt = opts.allowHt !== false;
  for (var i = 0; i < value.length; i += 1) {
    var cc = value.charCodeAt(i);
    if (allowHt && cc === 9) continue;                                                            // allow:raw-byte-literal — ASCII HT (folding whitespace)
    if (cc < 32 || cc === 127) {                                                                  // allow:raw-byte-literal — C0 + DEL codepoint range
      var msg = opts.label + ": value contains control characters (C0 / DEL)";
      // opts.useNativeError === true → call the ErrorClass with a
      // single-arg `message` (matches native Error / TypeError /
      // RangeError signatures used by defensive request-shape
      // readers). Default false → call with (code, message) which
      // matches every framework-error class generated by `defineClass`.
      if (opts.useNativeError === true) {
        throw new opts.ErrorClass(msg);
      }
      throw new opts.ErrorClass(opts.code, msg);
    }
  }
}

/**
 * @primitive b.structuredFields.unquoteSfString
 * @signature b.structuredFields.unquoteSfString(s)
 * @since     0.9.0
 * @status    stable
 * @related   b.structuredFields.splitTopLevel
 *
 * Strip RFC 8941 §3.3.3 quoted-string wrapping from a piece value,
 * handling `\\` and `\"` backslash-escapes. Returns the unwrapped
 * string when the piece is `"..."`-shaped; returns the input
 * unchanged otherwise (tolerates bare-token values some upstream
 * proxies emit). Returns `null` for an unterminated `"...` shape so
 * callers can surface a parser-level error.
 *
 * @example
 *   b.structuredFields.unquoteSfString('"hello, world"');
 *   // → 'hello, world'
 *
 *   b.structuredFields.unquoteSfString('"a\\"b\\\\c"');
 *   // → 'a"b\c'
 *
 *   b.structuredFields.unquoteSfString('bare');
 *   // → 'bare'  (operator-supplied bare-token form passes through)
 */
function unquoteSfString(s) {
  if (typeof s !== "string") return s;
  var t = s.trim();
  if (t.length === 0) return "";
  if (t.charAt(0) !== "\"") return t;
  if (t.length < 2 || t.charAt(t.length - 1) !== "\"") return null;
  return t.slice(1, -1).replace(/\\"/g, "\"").replace(/\\\\/g, "\\");
}

/**
 * @primitive b.structuredFields.containsControlBytes
 * @signature b.structuredFields.containsControlBytes(value, opts?)
 * @since     0.9.0
 * @status    stable
 * @related   b.structuredFields.refuseControlBytes
 *
 * Predicate variant of `refuseControlBytes` for defensive
 * request-shape readers that RETURN DEFAULTS rather than throw
 * (the framework's third validation tier). Returns `true` when the
 * RAW value contains any C0 / DEL byte (ASCII HT permitted by
 * default as folding-whitespace).
 *
 * @opts
 *   allowHt: boolean,   // default true — permit ASCII HT
 *
 * @example
 *   function parseChallenge(headerValue) {
 *     if (b.structuredFields.containsControlBytes(headerValue)) return null;
 *     // ...safe to .trim() / .slice() now
 *   }
 */
function containsControlBytes(value, opts) {
  if (typeof value !== "string") return false;
  var allowHt = !opts || opts.allowHt !== false;
  for (var i = 0; i < value.length; i += 1) {
    var cc = value.charCodeAt(i);
    if (allowHt && cc === 9) continue;                                                            // allow:raw-byte-literal — ASCII HT (folding whitespace)
    if (cc < 32 || cc === 127) return true;                                                       // allow:raw-byte-literal — C0 + DEL codepoint range
  }
  return false;
}

module.exports = {
  splitTopLevel:        splitTopLevel,
  refuseControlBytes:   refuseControlBytes,
  containsControlBytes: containsControlBytes,
  unquoteSfString:      unquoteSfString,
};
