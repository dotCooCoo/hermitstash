// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module     b.structuredFields
 * @nav        HTTP
 * @title      RFC 9651 Structured Fields
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
// node:util is a builtin (no lib require cycle) — used for strict UTF-8
// validation of RFC 9651 Display Strings.
var TextDecoder = require("node:util").TextDecoder;
var codepointClass = require("./codepoint-class");

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
 * @primitive b.structuredFields.splitUnquoted
 * @signature b.structuredFields.splitUnquoted(s, sep)
 * @since     0.15.13
 * @status    stable
 * @related   b.structuredFields.splitTopLevel
 *
 * Split `s` on every `sep` that falls OUTSIDE a `"..."` quoted run — the
 * iCalendar / vCard variant of the quote-aware splitter. A `"` toggles the
 * quoted state and there is NO backslash escaping of the quote (RFC 5545
 * 3.1.1 / RFC 6350 3.3 QSAFE-CHAR excludes DQUOTE, so a `"` always opens or
 * closes a run). This is deliberately simpler than `splitTopLevel`, which
 * honours HTTP structured-field backslash-quote escapes; the two are NOT
 * interchangeable. Accepts any single-character separator.
 *
 * @example
 *   b.structuredFields.splitUnquoted('a;b="x;y";c', ";");
 *   // returns ['a', 'b="x;y"', 'c']
 */
function splitUnquoted(s, sep) {
  var out = [];
  var inQ = false;
  var start = 0;
  for (var i = 0; i < s.length; i++) {
    var c = s.charAt(i);
    if (c === '"') { inQ = !inQ; continue; }
    if (c === sep && !inQ) {
      out.push(s.slice(start, i));
      start = i + 1;
    }
  }
  out.push(s.slice(start));
  return out;
}

/**
 * @primitive b.structuredFields.stripDoubleQuotes
 * @signature b.structuredFields.stripDoubleQuotes(s)
 * @since     0.15.13
 * @status    stable
 * @related   b.structuredFields.splitUnquoted, b.structuredFields.unquoteSfString
 *
 * Strip ONE layer of surrounding `"` from `s` when both ends are a double
 * quote (length ≥ 2), otherwise return `s` unchanged. The plain DQUOTE
 * unwrap used by the iCal / vCard parsers for a quoted parameter value —
 * no backslash-escape processing (RFC 5545 3.1 / RFC 6350 5: a quoted
 * param value is QSAFE-CHAR, which excludes DQUOTE, so there is nothing to
 * unescape). Distinct from `unquoteSfString`, which decodes HTTP
 * structured-field `\"` / `\\` escapes.
 *
 * @example
 *   b.structuredFields.stripDoubleQuotes('"a;b"');
 *   // returns 'a;b'
 *
 *   b.structuredFields.stripDoubleQuotes('plain');
 *   // returns 'plain'
 */
function stripDoubleQuotes(s) {
  if (s.length >= 2 && s.charAt(0) === '"' && s.charAt(s.length - 1) === '"') {
    return s.slice(1, -1);
  }
  return s;
}

/**
 * @primitive b.structuredFields.unfoldHeaderContinuations
 * @signature b.structuredFields.unfoldHeaderContinuations(value)
 * @since     0.15.13
 * @status    stable
 * @related   b.structuredFields.parseTagList
 *
 * Collapse RFC 5322 folding whitespace — a CRLF (or bare LF) followed by one
 * or more spaces/tabs — back to a single space, reversing the line folding a
 * header value may carry in transit. Used before parsing DKIM / ARC /
 * Authentication-Results tag lists, where a folded `b=` / `bh=` value must be
 * rejoined before its base64 is read.
 *
 * @example
 *   b.structuredFields.unfoldHeaderContinuations("v=DKIM1;\r\n  k=rsa");
 *   // returns "v=DKIM1; k=rsa"
 */
function unfoldHeaderContinuations(value) {
  return String(value).replace(/\r?\n[ \t]+/g, " ");
}

/**
 * @primitive b.structuredFields.parseKeyValuePiece
 * @signature b.structuredFields.parseKeyValuePiece(piece, kvSep?, lowerKey?)
 * @since     0.15.13
 * @status    stable
 * @related   b.structuredFields.parseTagList, b.structuredFields.splitTopLevel
 *
 * Parse ONE already-split list piece into a `{ key, value }` pair: `key` is the
 * text before the first `kvSep` (default "="), trimmed and — unless `lowerKey`
 * is `false` — lower-cased; `value` is the raw remainder (the caller trims /
 * unquotes / sf-string-parses it per its own grammar). A piece with NO `kvSep`
 * is a "bare" item — `value` is null — which the caller handles per its grammar
 * (skip it, or treat as a flag-style directive).
 *
 * The shared per-pair step behind every `key=value` list parser: the naive
 * `parseTagList` loop AND the quote-aware parsers that first `splitTopLevel`
 * then parse each piece (Cache-Control directives, Client-Hints brand params,
 * Content-Type parameters). `lowerKey:false` serves the rare grammar whose key
 * is case-sensitive (a verbatim tag-list passthrough).
 *
 * @example
 *   b.structuredFields.parseKeyValuePiece("Max-Age=60");   // → { key: "max-age", value: "60" }
 *   b.structuredFields.parseKeyValuePiece("no-store");      // → { key: "no-store", value: null }
 *   b.structuredFields.parseKeyValuePiece("Key=a=b", "=", false); // → { key: "Key", value: "a=b" }
 */
function parseKeyValuePiece(piece, kvSep, lowerKey) {
  var sep = kvSep || "=";
  var at = piece.indexOf(sep);
  var rawKey = (at === -1 ? piece : piece.slice(0, at)).trim();
  var key = lowerKey === false ? rawKey : rawKey.toLowerCase();
  return { key: key, value: at === -1 ? null : piece.slice(at + sep.length) };
}

/**
 * @primitive b.structuredFields.parseTagList
 * @signature b.structuredFields.parseTagList(input, opts?)
 * @since     0.15.13
 * @status    stable
 * @related   b.structuredFields.splitTopLevel
 *
 * Parse a NAIVE delimited `key<kvSep>value` tag list into an ordered
 * array of `[key, value]` pairs. This is the non-quote-aware sibling
 * of `splitTopLevel`: it is for grammars whose RFC forbids the DQUOTE
 * structured-string form, so a bare `split` is correct and a
 * quote-aware walk would be wrong — DKIM (RFC 6376 §3.2), DMARC
 * (RFC 7489 §6.4), ARC (RFC 8617 §4), BIMI (RFC 9091 §4), and the
 * MTA-STS policy grammar (RFC 8461, line/colon delimited).
 *
 * Pairs are returned (not a map) so a caller whose grammar permits a
 * repeated key — MTA-STS `mx:` lines list one host each — keeps every
 * occurrence; a caller wanting last-wins map semantics folds the
 * pairs into a plain object itself. Order is preserved, so a caller
 * that throws on a malformed value throws at the same point it would
 * have mid-loop.
 *
 * Entries that are empty after trimming, or carry no `kvSep`, are
 * skipped (matching every shipped parser's prior behavior).
 *
 * @opts
 *   sep:          string|RegExp,  // entry separator. default: ";"  (MTA-STS uses /\r?\n/)
 *   kvSep:        string,         // key/value separator. default: "="  (MTA-STS uses ":")
 *   unfold:       boolean,        // collapse CRLF+WSP folds to a space first (DKIM FWS). default: false
 *   stripValueWs: boolean,        // strip all whitespace inside each value (DKIM/ARC FWS). default: false
 *   lowerKey:     boolean,        // lower-case each key. default: true (set false to preserve case)
 *
 * @example
 *   b.structuredFields.parseTagList("v=DKIM1; k=rsa; p=MIGf");
 *   // → [ ["v", "DKIM1"], ["k", "rsa"], ["p", "MIGf"] ]
 *
 *   b.structuredFields.parseTagList("version:STSv1\nmx:a.example\nmx:b.example",
 *     { sep: /\r?\n/, kvSep: ":" });
 *   // → [ ["version","STSv1"], ["mx","a.example"], ["mx","b.example"] ]
 */
function parseTagList(input, opts) {
  opts = opts || {};
  var sep = opts.sep === undefined ? ";" : opts.sep;
  var kvSep = opts.kvSep === undefined ? "=" : opts.kvSep;
  var s = String(input);
  if (opts.unfold) s = unfoldHeaderContinuations(s);
  var kvps = parseKeyValuePieces(s.split(sep), 0, kvSep, opts.lowerKey);
  var out = [];
  forEachKeyValue(kvps, function (key, val) {
    if (opts.stripValueWs) val = val.replace(/\s+/g, "");
    out.push([key, val]);
  });
  return out;
}

/**
 * @primitive b.structuredFields.parseKeyValuePieces
 * @signature b.structuredFields.parseKeyValuePieces(pieces, startIndex?, kvSep?, lowerKey?)
 * @since     0.15.13
 * @status    stable
 * @related   b.structuredFields.parseKeyValuePiece, b.structuredFields.parseTagList
 *
 * Iterate an already-split list of structured-field pieces, trimming each,
 * dropping empties, and parsing the survivors into `{ key, value }` records
 * via `parseKeyValuePiece`. `startIndex` skips a leading non-pair token (the
 * media type in a `Content-Type`, the brand in a `Sec-CH-UA` member); `kvSep`
 * overrides the default `"="`; `lowerKey:false` preserves key case for a
 * case-sensitive grammar.
 *
 * The split is left to the caller because the boundary discipline differs by
 * grammar — `splitTopLevel` honours quotes/parens for RFC 8941 lists, while a
 * plain `String(value).split(";")` is right where inner separators cannot be
 * quoted. Per-piece dispatch (unquote, numeric coercion, poisoned-key drops)
 * stays with the caller; this owns only the uniform iterate-trim-skip-parse
 * spine the parsers shared verbatim.
 *
 * @opts
 *   startIndex: number,   // default: 0 — first piece treated as a key/value pair
 *   kvSep:      string,   // default: "=" — key/value separator within a piece
 *   lowerKey:   boolean,  // default: true — lower-case each parsed key
 *
 * @example
 *   var kvps = b.structuredFields.parseKeyValuePieces(
 *     b.structuredFields.splitTopLevel("max-age=600, immutable", ","));
 *   // → [ { key: "max-age", value: "600" }, { key: "immutable", value: null } ]
 */
function parseKeyValuePieces(pieces, startIndex, kvSep, lowerKey) {
  var out = [];
  for (var i = startIndex || 0; i < pieces.length; i += 1) {
    var p = pieces[i].trim();
    if (p.length === 0) continue;
    out.push(parseKeyValuePiece(p, kvSep, lowerKey));
  }
  return out;
}

/**
 * @primitive b.structuredFields.forEachKeyValue
 * @signature b.structuredFields.forEachKeyValue(kvps, handler)
 * @since     0.15.13
 * @status    stable
 * @related   b.structuredFields.parseKeyValuePieces, b.structuredFields.parseTagList
 *
 * Consume the `{ key, value }` records from `parseKeyValuePieces`: skip
 * the bare entries (those with a `null` value — a key that carried no
 * separator), trim each surviving value, and invoke
 * `handler(key, trimmedValue, index)`. The mirror of
 * `parseKeyValuePieces` on the consuming side — that primitive owns the
 * parse spine, this owns the iterate-skip-bare-trim spine every header
 * parser repeated verbatim before dispatching.
 *
 * Per-key dispatch (sf-string unquoting, numeric coercion, poisoned-key
 * drops, building a typed result) stays in the handler — a handler that
 * `return`s skips the current entry, exactly like a `continue`. Parsers
 * that instead treat a bare key as meaningful (a value-less directive)
 * iterate the records directly rather than calling this.
 *
 * @example
 *   var b = require("blamejs");
 *
 *   var out = {};
 *   var kvps = b.structuredFields.parseKeyValuePieces("a=1; b=2".split(";"));
 *   b.structuredFields.forEachKeyValue(kvps, function (key, value) {
 *     out[key] = value;
 *   });
 *   // out → { a: "1", b: "2" }
 */
function forEachKeyValue(kvps, handler) {
  if (typeof handler !== "function") {
    throw new TypeError("structuredFields.forEachKeyValue: handler must be a function");
  }
  for (var i = 0; i < kvps.length; i += 1) {
    if (kvps[i].value === null) continue;
    handler(kvps[i].key, kvps[i].value.trim(), i);
  }
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
  var allowHt = opts.allowHt !== false;                                                            // ASCII HT (folding whitespace) permitted unless allowHt === false
  if (codepointClass.firstControlCharOffset(value, { forbidTab: !allowHt }) !== -1) {              // C0 + DEL codepoint range
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
  return unescapeSfStringBody(t.slice(1, -1));
}

/**
 * @primitive b.structuredFields.unescapeSfStringBody
 * @signature b.structuredFields.unescapeSfStringBody(body)
 * @since      0.15.12
 * @related    b.structuredFields.unquoteSfString
 *
 * Undo the RFC 8941 §3.3.3 quoted-string backslash-escapes from the BODY of
 * an sf-string (the bytes BETWEEN the surrounding double quotes). Only `\\\\`
 * and `\\"` are legal escapes; every other backslash is literal.
 *
 * This is a single left-to-right scan, NOT two chained `.replace()` passes.
 * The two-pass form (`.replace(/\\\\/g,"\\").replace(/\\"/g,'"')`, in either
 * order) is not equivalent to a single decode: whichever pass runs first can
 * rewrite a backslash the other escape sequence legitimately owns, so a lone
 * escaped backslash (`\\\\`) decodes to two backslashes instead of one. The
 * single pass consumes each escape exactly once. Non-string input passes
 * through unchanged.
 *
 * @example
 *   b.structuredFields.unescapeSfStringBody('a\\"b\\\\c');
 *   // → 'a"b\c'
 */
function unescapeSfStringBody(body) {
  if (typeof body !== "string") return body;
  var out = "";
  for (var i = 0; i < body.length; i++) {
    var c = body.charAt(i);
    if (c === "\\" && i + 1 < body.length) {
      var n = body.charAt(i + 1);
      if (n === "\\" || n === "\"") { out += n; i += 1; continue; }
    }
    out += c;
  }
  return out;
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
    if (allowHt && cc === 9) continue;                                                            // ASCII HT (folding whitespace)
    if (codepointClass.isForbiddenControlChar(cc, { forbidTab: true })) return true;                                                       // C0 + DEL codepoint range
  }
  return false;
}

// ---------------------------------------------------------------------------
// Full RFC 9651 codec (parse + serialize; RFC 9651 obsoletes RFC 8941
// and adds the Date and Display String types). The helpers above are the
// quote-aware splitters individual parsers reach for; the codec below is
// the complete grammar — Items, Lists, Dictionaries, Inner Lists,
// Parameters, and every bare-item type.
//
// Value model (RFC 9651, which obsoletes RFC 8941):
//   bare item  → number (Integer) | SfDecimal | string | boolean | SfToken
//                | SfByteSequence | SfDate | SfDisplayString
//   item       → { value: bareItem, params: Map<string, bareItem> }
//   inner list → { items: item[], params: Map<string, bareItem> }
//   list       → (item | innerList)[]
//   dictionary → Map<string, item | innerList>
// ---------------------------------------------------------------------------

// RFC 8941 §3.3.4 Token / §3.3.5 Byte Sequence are wrapped so they stay
// distinct from plain strings on both parse output and serialize input.
function SfToken(value) {
  if (!(this instanceof SfToken)) return new SfToken(value);
  this.value = String(value);
}
function SfByteSequence(value) {
  if (!(this instanceof SfByteSequence)) return new SfByteSequence(value);
  this.value = Buffer.isBuffer(value) ? value : Buffer.from(value);
}
// A Decimal preserves its type across parse → serialize even when its
// value is numerically integral ("1.0" must not serialize back to "1").
// A plain JS number serializes as an Integer when integral, a Decimal
// otherwise; wrap in SfDecimal to force the Decimal form.
function SfDecimal(value) {
  if (!(this instanceof SfDecimal)) return new SfDecimal(value);
  this.value = Number(value);
}
// RFC 9651 §3.3.7 Date (an Integer number of seconds since the Unix
// epoch) and §3.3.8 Display String (a Unicode string conveyed as
// percent-escaped UTF-8). Wrapped so they stay distinct from Integers
// and plain Strings.
function SfDate(value) {
  if (!(this instanceof SfDate)) return new SfDate(value);
  this.value = Number(value);
}
function SfDisplayString(value) {
  if (!(this instanceof SfDisplayString)) return new SfDisplayString(value);
  this.value = String(value);
}

function _sfErr(opts) {
  if (opts && typeof opts.ErrorClass === "function") {
    return function (code, msg) { return opts.useNativeError === true ? new opts.ErrorClass(msg) : new opts.ErrorClass(code, msg); };
  }
  return function (code, msg) { var e = new Error(msg); e.code = code; return e; };
}

var INT_MAX = 999999999999999;          // 15 digits (RFC 8941 §3.3.1)
var INT_MIN = -999999999999999;
function _isDigit(c) { return c >= "0" && c <= "9"; }
function _isLcAlpha(c) { return c >= "a" && c <= "z"; }
function _isAlpha(c) { return (c >= "A" && c <= "Z") || (c >= "a" && c <= "z"); }
function _isTchar(c) { return _isAlpha(c) || _isDigit(c) || "!#$%&'*+-.^_`|~".indexOf(c) !== -1; }
function _isKeyChar(c) { return _isLcAlpha(c) || _isDigit(c) || c === "_" || c === "-" || c === "." || c === "*"; }

function _parseNumber(cx, E) {
  var sign = 1, type = "integer", num = "";
  if (cx.s.charAt(cx.i) === "-") { sign = -1; cx.i += 1; }
  if (cx.i >= cx.s.length || !_isDigit(cx.s.charAt(cx.i))) throw E("structured-fields/parse", "expected a digit at index " + cx.i);
  for (;;) {
    if (cx.i >= cx.s.length) break;
    var c = cx.s.charAt(cx.i);
    if (_isDigit(c)) { num += c; cx.i += 1; }
    else if (type === "integer" && c === ".") {
      if (num.length > 12) throw E("structured-fields/parse", "integer part of a decimal exceeds 12 digits");   // RFC 8941 §4.2.4 decimal integer-part cap
      num += "."; type = "decimal"; cx.i += 1;
    } else break;
    if (type === "integer" && num.length > 15) throw E("structured-fields/parse", "integer exceeds 15 digits");  // §3.3.1 integer digit cap
    if (type === "decimal" && num.length > 16) throw E("structured-fields/parse", "decimal exceeds the digit limit");   // 12 int + "." + 3 frac
  }
  if (type === "integer") return sign * parseInt(num, 10);
  if (num.charAt(num.length - 1) === ".") throw E("structured-fields/parse", "decimal must not end with '.'");
  if (num.length - num.indexOf(".") - 1 > 3) throw E("structured-fields/parse", "decimal fraction exceeds 3 digits");
  return new SfDecimal(sign * parseFloat(num));
}

function _parseString(cx, E) {
  cx.i += 1; // opening DQUOTE
  var out = "";
  while (cx.i < cx.s.length) {
    var c = cx.s.charAt(cx.i); cx.i += 1;
    if (c === "\\") {
      if (cx.i >= cx.s.length) throw E("structured-fields/parse", "trailing backslash in string");
      var n = cx.s.charAt(cx.i); cx.i += 1;
      if (n !== "\\" && n !== "\"") throw E("structured-fields/parse", "invalid backslash escape in string");
      out += n;
    } else if (c === "\"") { return out; }
    else {
      var cc = c.charCodeAt(0);
      if (cc < 0x20 || cc > 0x7e) throw E("structured-fields/parse", "non-printable character in string");   // RFC 8941 §4.2.5 printable-ASCII range
      out += c;
    }
  }
  throw E("structured-fields/parse", "unterminated string");
}

function _parseByteSeq(cx, E) {
  cx.i += 1; // opening ":"
  var start = cx.i;
  while (cx.i < cx.s.length && cx.s.charAt(cx.i) !== ":") cx.i += 1;
  if (cx.i >= cx.s.length) throw E("structured-fields/parse", "unterminated byte sequence");
  var b64 = cx.s.slice(start, cx.i); cx.i += 1; // closing ":"
  // RFC 8941 §4.2.7 synthesizes padding, so an unpadded value like
  // `:aGVsbG8:` is valid input. Pad an unpadded value to a base64
  // quantum, then require the decoded bytes to re-encode to exactly that
  // padded text — rejecting stray characters, misplaced "=" padding, and
  // non-zero trailing bits (Node's decoder is otherwise permissive).
  var padded = b64.indexOf("=") === -1 ? b64 + "====".slice(0, (4 - (b64.length % 4)) % 4) : b64;
  var buf = Buffer.from(padded, "base64");
  if (buf.toString("base64") !== padded) throw E("structured-fields/parse", "byte sequence is not valid base64");
  return new SfByteSequence(buf);
}

function _parseBoolean(cx, E) {
  cx.i += 1; // "?"
  var c = cx.s.charAt(cx.i); cx.i += 1;
  if (c === "1") return true;
  if (c === "0") return false;
  throw E("structured-fields/parse", "boolean must be ?0 or ?1");
}

function _parseToken(cx) {
  var start = cx.i; cx.i += 1; // first char already ALPHA / "*"
  while (cx.i < cx.s.length) {
    var c = cx.s.charAt(cx.i);
    if (_isTchar(c) || c === ":" || c === "/") cx.i += 1; else break;
  }
  return new SfToken(cx.s.slice(start, cx.i));
}

var _utf8Strict = new TextDecoder("utf-8", { fatal: true });

function _parseDate(cx, E) {
  cx.i += 1; // "@"
  var n = _parseNumber(cx, E);
  if (n instanceof SfDecimal) throw E("structured-fields/parse", "date must be an integer number of seconds");
  return new SfDate(n);
}

function _parseDisplayString(cx, E) {
  cx.i += 1; // "%"
  if (cx.s.charAt(cx.i) !== "\"") throw E("structured-fields/parse", "display string must open with %\"");
  cx.i += 1;
  var bytes = [];
  while (cx.i < cx.s.length) {
    var c = cx.s.charAt(cx.i); cx.i += 1;
    if (c === "%") {
      var h = cx.s.substr(cx.i, 2);
      if (h.length !== 2 || !/^[0-9a-f]{2}$/.test(h)) throw E("structured-fields/parse", "display string escape must be %<lowercase-hex><lowercase-hex>");   // RFC 9651 §4.2.10 two-hex-digit escape
      bytes.push(parseInt(h, 16));
      cx.i += 2;
    } else if (c === "\"") {
      try { return new SfDisplayString(_utf8Strict.decode(Buffer.from(bytes))); }
      catch (_e) { throw E("structured-fields/parse", "display string is not valid UTF-8"); }
    } else {
      var cc = c.charCodeAt(0);
      if (cc < 0x20 || cc > 0x7e) throw E("structured-fields/parse", "display string contains a raw non-printable / non-ASCII character");   // RFC 9651 §4.2.10 printable-ASCII range
      bytes.push(cc);
    }
  }
  throw E("structured-fields/parse", "unterminated display string");
}

function _parseBareItem(cx, E) {
  var c = cx.s.charAt(cx.i);
  if (c === "-" || _isDigit(c)) return _parseNumber(cx, E);
  if (c === "\"") return _parseString(cx, E);
  if (c === ":") return _parseByteSeq(cx, E);
  if (c === "?") return _parseBoolean(cx, E);
  if (c === "@") return _parseDate(cx, E);
  if (c === "%") return _parseDisplayString(cx, E);
  if (c === "*" || _isAlpha(c)) return _parseToken(cx);
  throw E("structured-fields/parse", "unexpected character '" + (c || "<eof>") + "' at index " + cx.i);
}

function _parseKey(cx, E) {
  var c = cx.s.charAt(cx.i);
  if (!(c === "*" || _isLcAlpha(c))) throw E("structured-fields/parse", "key must start with lcalpha or '*'");
  var start = cx.i; cx.i += 1;
  while (cx.i < cx.s.length && _isKeyChar(cx.s.charAt(cx.i))) cx.i += 1;
  return cx.s.slice(start, cx.i);
}

function _parseParams(cx, E) {
  var params = new Map();
  while (cx.i < cx.s.length && cx.s.charAt(cx.i) === ";") {
    cx.i += 1;
    while (cx.s.charAt(cx.i) === " ") cx.i += 1;
    var key = _parseKey(cx, E);
    var val = true;
    if (cx.s.charAt(cx.i) === "=") { cx.i += 1; val = _parseBareItem(cx, E); }
    params.set(key, val);   // last value wins (RFC 8941 §4.2.3.2)
  }
  return params;
}

function _parseItem(cx, E) {
  var value = _parseBareItem(cx, E);
  return { value: value, params: _parseParams(cx, E) };
}

function _parseInnerList(cx, E) {
  cx.i += 1; // "("
  var items = [];
  for (;;) {
    while (cx.s.charAt(cx.i) === " ") cx.i += 1;
    if (cx.i >= cx.s.length) throw E("structured-fields/parse", "unterminated inner list");
    if (cx.s.charAt(cx.i) === ")") { cx.i += 1; return { items: items, params: _parseParams(cx, E) }; }
    items.push(_parseItem(cx, E));
    var c = cx.s.charAt(cx.i);
    if (c !== " " && c !== ")") throw E("structured-fields/parse", "inner-list items must be space-separated");
  }
}

function _parseItemOrInnerList(cx, E) {
  return cx.s.charAt(cx.i) === "(" ? _parseInnerList(cx, E) : _parseItem(cx, E);
}

function _skipOWS(cx) { while (cx.s.charAt(cx.i) === " " || cx.s.charAt(cx.i) === "\t") cx.i += 1; }

function _parseList(cx, E) {
  var members = [];
  if (cx.i >= cx.s.length) return members;
  for (;;) {
    members.push(_parseItemOrInnerList(cx, E));
    _skipOWS(cx);
    if (cx.i >= cx.s.length) return members;
    if (cx.s.charAt(cx.i) !== ",") throw E("structured-fields/parse", "expected ',' between list members");
    cx.i += 1; _skipOWS(cx);
    if (cx.i >= cx.s.length) throw E("structured-fields/parse", "trailing comma in list");
  }
}

function _parseDict(cx, E) {
  var dict = new Map();
  if (cx.i >= cx.s.length) return dict;
  for (;;) {
    var key = _parseKey(cx, E);
    var member;
    if (cx.s.charAt(cx.i) === "=") { cx.i += 1; member = _parseItemOrInnerList(cx, E); }
    else { member = { value: true, params: _parseParams(cx, E) }; }
    dict.set(key, member);   // last key wins (RFC 8941 §4.2.2)
    _skipOWS(cx);
    if (cx.i >= cx.s.length) return dict;
    if (cx.s.charAt(cx.i) !== ",") throw E("structured-fields/parse", "expected ',' between dictionary members");
    cx.i += 1; _skipOWS(cx);
    if (cx.i >= cx.s.length) throw E("structured-fields/parse", "trailing comma in dictionary");
  }
}

/**
 * @primitive b.structuredFields.parse
 * @signature b.structuredFields.parse(input, type, opts?)
 * @since     0.12.54
 * @status    stable
 * @related   b.structuredFields.serialize, b.structuredFields.splitTopLevel
 *
 * Parse an RFC 8941 Structured Field value. <code>type</code> is
 * <code>"item"</code>, <code>"list"</code>, or <code>"dictionary"</code>.
 * Returns the value model: an item is <code>{ value, params }</code>
 * (params is a <code>Map</code>); a list is an array of items / inner
 * lists; a dictionary is a <code>Map</code>. Tokens, byte sequences,
 * dates, and display strings come back as <code>SfToken</code> /
 * <code>SfByteSequence</code> / <code>SfDate</code> /
 * <code>SfDisplayString</code> instances so they stay distinct from
 * plain strings and integers. Strictly enforces
 * the grammar — integer / decimal digit caps, printable-ASCII strings,
 * canonical base64, no trailing characters — and throws on any malformed
 * input (pass <code>opts.ErrorClass</code> for a typed error).
 *
 * @opts
 *   ErrorClass?: Function,   // typed error class (default: native Error with .code)
 *
 * @example
 *   b.structuredFields.parse("a=1, b=(x y);q=2", "dictionary");
 *   // → Map { "a" => { value: 1, params: Map{} },
 *   //         "b" => { items: [...], params: Map{ "q" => 2 } } }
 */
function parse(input, type, opts) {
  var E = _sfErr(opts);
  if (typeof input !== "string") throw E("structured-fields/bad-input", "structuredFields.parse: input must be a string");
  var cx = { s: input, i: 0 };
  while (cx.s.charAt(cx.i) === " ") cx.i += 1;          // §4.2 discard leading SP
  var out;
  if (type === "item") out = _parseItem(cx, E);
  else if (type === "list") out = _parseList(cx, E);
  else if (type === "dictionary") out = _parseDict(cx, E);
  else throw E("structured-fields/bad-type", "structuredFields.parse: type must be 'item' | 'list' | 'dictionary'");
  while (cx.s.charAt(cx.i) === " ") cx.i += 1;          // §4.2 discard trailing SP
  if (cx.i !== cx.s.length) throw E("structured-fields/parse", "trailing characters after the field value");
  return out;
}

function _serDecimal(v, E) {
  if (!isFinite(v)) throw E("structured-fields/serialize", "cannot serialize a non-finite decimal");
  var n = Math.round(v * 1000) / 1000;                   // allow:raw-time-literal — RFC 8941 4.1.5 decimal-scale 10^3 rounding; coincidental * 1000, not a duration, C.TIME N/A
  if (Math.abs(Math.trunc(n)).toString().length > 12) throw E("structured-fields/serialize", "decimal integer part exceeds 12 digits");   // §4.1.5 cap
  var s = n.toString();
  if (s.indexOf(".") === -1) s += ".0";                  // a Decimal must carry a fractional part
  return s;
}
function _serDisplayString(s, E) {
  if (typeof s !== "string") throw E("structured-fields/serialize", "display string value must be a string");
  // RFC 9651 §4.1.10: serialize fails unless the value is a sequence of
  // Unicode scalar values. A lone UTF-16 surrogate would otherwise be
  // silently replaced with U+FFFD by Buffer.from, corrupting the output.
  if (typeof s.isWellFormed === "function" ? !s.isWellFormed() : /[\uD800-\uDFFF]/.test(s.replace(/[\uD800-\uDBFF][\uDC00-\uDFFF]/g, ""))) {
    throw E("structured-fields/serialize", "display string contains a lone surrogate (not a valid Unicode string)");
  }
  var bytes = Buffer.from(s, "utf8"), out = "%\"";
  for (var i = 0; i < bytes.length; i += 1) {
    var b = bytes[i];
    if (b >= 0x20 && b <= 0x7e && b !== 0x25 && b !== 0x22) out += String.fromCharCode(b);   // RFC 9651 §4.1.10 printable ASCII except % and "
    else out += "%" + (b < 0x10 ? "0" : "") + b.toString(16);                                // lowercase 2-hex escape
  }
  return out + "\"";
}
function _serBareItem(v, E) {
  if (v === true) return "?1";
  if (v === false) return "?0";
  if (v instanceof SfDecimal) return _serDecimal(v.value, E);
  if (v instanceof SfDate) {
    if (!Number.isInteger(v.value) || v.value > INT_MAX || v.value < INT_MIN) throw E("structured-fields/serialize", "date must be an integer in RFC 9651 range");
    return "@" + String(v.value);
  }
  if (v instanceof SfDisplayString) return _serDisplayString(v.value, E);
  if (typeof v === "number") {
    if (!isFinite(v)) throw E("structured-fields/serialize", "cannot serialize a non-finite number");
    if (Number.isInteger(v)) {
      if (v > INT_MAX || v < INT_MIN) throw E("structured-fields/serialize", "integer out of RFC 8941 range");
      return String(v);
    }
    return _serDecimal(v, E);                            // a fractional JS number serializes as a Decimal
  }
  if (typeof v === "string") {
    var out = "\"";
    for (var i = 0; i < v.length; i += 1) {
      var c = v.charAt(i), cc = v.charCodeAt(i);
      if (cc < 0x20 || cc > 0x7e) throw E("structured-fields/serialize", "string contains a non-printable character");   // §4.1.6 printable-ASCII range
      if (c === "\\" || c === "\"") out += "\\";
      out += c;
    }
    return out + "\"";
  }
  if (v instanceof SfToken) {
    var t = v.value;
    if (t.length === 0 || !(t.charAt(0) === "*" || _isAlpha(t.charAt(0)))) throw E("structured-fields/serialize", "invalid token");
    for (var j = 1; j < t.length; j += 1) { var tc = t.charAt(j); if (!(_isTchar(tc) || tc === ":" || tc === "/")) throw E("structured-fields/serialize", "invalid token character"); }
    return t;
  }
  if (v instanceof SfByteSequence) return ":" + v.value.toString("base64") + ":";
  throw E("structured-fields/serialize", "unsupported bare-item type");
}

function _serParams(params, E) {
  if (!params) return "";
  var out = "";
  params.forEach(function (val, key) {
    out += ";" + _serKey(key, E);
    if (val !== true) out += "=" + _serBareItem(val, E);
  });
  return out;
}
function _serKey(key, E) {
  if (typeof key !== "string" || key.length === 0 || !(key.charAt(0) === "*" || _isLcAlpha(key.charAt(0)))) throw E("structured-fields/serialize", "invalid parameter/dictionary key");
  for (var i = 1; i < key.length; i += 1) { if (!_isKeyChar(key.charAt(i))) throw E("structured-fields/serialize", "invalid key character"); }
  return key;
}
function _serItem(item, E) { return _serBareItem(item.value, E) + _serParams(item.params, E); }
function _serMember(m, E) {
  if (m && Array.isArray(m.items)) {
    return "(" + m.items.map(function (it) { return _serItem(it, E); }).join(" ") + ")" + _serParams(m.params, E);
  }
  return _serItem(m, E);
}

/**
 * @primitive b.structuredFields.serialize
 * @signature b.structuredFields.serialize(value, type, opts?)
 * @since     0.12.54
 * @status    stable
 * @related   b.structuredFields.parse
 *
 * Serialize a value model back to an RFC 8941 field value (the inverse
 * of <code>parse</code>). <code>type</code> is <code>"item"</code>,
 * <code>"list"</code>, or <code>"dictionary"</code>. Numbers serialize as
 * Integers when integral and Decimals (rounded to 3 fractional digits)
 * otherwise; wrap Tokens / byte strings in <code>SfToken</code> /
 * <code>SfByteSequence</code>. Throws on values outside the RFC's ranges
 * or grammar (out-of-range integers, non-printable string characters,
 * invalid tokens / keys).
 *
 * @opts
 *   ErrorClass?: Function,   // typed error class (default: native Error with .code)
 *
 * @example
 *   var sf = b.structuredFields;
 *   sf.serialize({ value: new sf.Token("gzip"), params: new Map([["q", 1]]) }, "item");
 *   // → "gzip;q=1"
 */
function serialize(value, type, opts) {
  var E = _sfErr(opts);
  if (type === "item") {
    if (!value || typeof value !== "object" || !("value" in value)) throw E("structured-fields/serialize", "item must be { value, params }");
    return _serItem(value, E);
  }
  if (type === "list") {
    if (!Array.isArray(value)) throw E("structured-fields/serialize", "list must be an array");
    return value.map(function (m) { return _serMember(m, E); }).join(", ");
  }
  if (type === "dictionary") {
    var entries = value instanceof Map ? Array.from(value.entries()) : (value && typeof value === "object" ? Object.keys(value).map(function (k) { return [k, value[k]]; }) : null);
    if (!entries) throw E("structured-fields/serialize", "dictionary must be a Map or object");
    return entries.map(function (e) {
      var key = _serKey(e[0], E), m = e[1];
      if (m && !Array.isArray(m.items) && m.value === true) return key + _serParams(m.params, E);   // bare-true member omits "=?1"
      return key + "=" + _serMember(m, E);
    }).join(", ");
  }
  throw E("structured-fields/bad-type", "structuredFields.serialize: type must be 'item' | 'list' | 'dictionary'");
}

module.exports = {
  splitTopLevel:        splitTopLevel,
  splitUnquoted:        splitUnquoted,
  stripDoubleQuotes:    stripDoubleQuotes,
  parseTagList:         parseTagList,
  unfoldHeaderContinuations: unfoldHeaderContinuations,
  parseKeyValuePiece:   parseKeyValuePiece,
  parseKeyValuePieces:  parseKeyValuePieces,
  forEachKeyValue:      forEachKeyValue,
  refuseControlBytes:   refuseControlBytes,
  containsControlBytes: containsControlBytes,
  unquoteSfString:      unquoteSfString,
  unescapeSfStringBody: unescapeSfStringBody,
  parse:                parse,
  serialize:            serialize,
  Token:                SfToken,
  ByteSequence:         SfByteSequence,
  Decimal:              SfDecimal,
  Date:                 SfDate,
  DisplayString:        SfDisplayString,
};
