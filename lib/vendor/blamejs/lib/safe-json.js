"use strict";
/**
 * @module b.safeJson
 * @featured true
 * @nav    Validation
 * @title  Safe Json
 *
 * @intro
 *   Hardened JSON parse + stringify + schema validation. Native
 *   `JSON.parse` leaves four footguns to the caller — no size cap (DoS
 *   the parser thread), no depth cap (stack-overflow downstream), no
 *   guard on `__proto__` / `constructor` / `prototype` keys (prototype
 *   pollution after any later merge/clone), and errors that report
 *   only a character offset with no surrounding context. `b.safeJson`
 *   closes all four with conservative defaults.
 *
 *   Defaults: 1 MiB body cap, depth 100, 10 000 keys per object
 *   (CVE-2026-21717 V8 HashDoS guard), poisoned keys stripped.
 *   Stringify refuses circular references unless the caller asks for
 *   the `[Circular]` placeholder. `canonical` produces RFC 8785 JCS
 *   key-sorted output for signature inputs.
 *
 *   The validator is a strict subset of JSON Schema (`type` / `enum`
 *   / `minLength` etc. / `required` / `properties` / `additionalProperties`),
 *   pluggable formats via `b.safeJson.registerFormat`, two modes:
 *   throw on first error (trust-boundary parse) or collect every
 *   error (form-style bulk validation).
 *
 *   Validation policy: opts and inputs are validated at the call site
 *   and throw `SafeJsonError`. The throw IS the security signal; HTTP
 *   middleware catches it and emits 400 with `.code` / `.path`.
 *
 * @card
 *   Hardened JSON parse + stringify + schema validation.
 */

// ---- Error class ----

var C = require("./constants");
var pick = require("./pick");
var safeBuffer = require("./safe-buffer");
var safeUrl = require("./safe-url");
var time = require("./time");
var { FrameworkError } = require("./framework-error");

/**
 * @primitive b.safeJson.SafeJsonError
 * @signature b.safeJson.SafeJsonError
 * @since     0.1.0
 * @status    stable
 * @related   b.safeJson.parse, b.safeJson.validate
 *
 * Error class thrown by every `b.safeJson` primitive on bad input,
 * cap exceedance, or schema-validation failure. Extends
 * `FrameworkError`. Carries a stable `.code` (e.g. `json/too-large`,
 * `json/syntax`, `json/validation`, `json/circular`) plus an
 * optional JSON-pointer-shaped `.path` (e.g. `$.user.email`) for
 * schema-validation errors. HTTP middleware translates these into
 * 400 responses without leaking parser internals.
 *
 * @example
 *   var b = require("blamejs");
 *   try {
 *     b.safeJson.parse("{not json");
 *   } catch (e) {
 *     e instanceof b.safeJson.SafeJsonError;   // → true
 *     e.code;                                  // → "json/syntax"
 *   }
 */
class SafeJsonError extends FrameworkError {
  constructor(message, code, path) {
    super(message);
    this.name = "SafeJsonError";
    this.code = code || "json/invalid";
    this.path = path || null;
    this.isSafeJsonError = true;
  }
}

var ABSOLUTE_MAX_BYTES = C.BYTES.mib(64);
var ABSOLUTE_MAX_DEPTH = 1_000;

// IPv6 has 8 16-bit hextets per RFC 4291; named so the call sites in
// formats.ipv6 don't carry a bare 8 integer literal.
var IPV6_HEXTET_COUNT = 0x8;
var DEFAULT_MAX_BYTES = C.BYTES.mib(1);
var DEFAULT_MAX_DEPTH = 100;
// CVE-2026-21717 — V8 HashDoS via integer-like keys. V8's object-shape
// transition cache degrades to O(n^2) when an object accumulates many
// distinct integer-string-shaped keys; a JSON body with thousands of
// `"0"`, `"1"`, ... keys spends O(n^2) CPU on the parse path itself.
// Cap object-literal-key count per node so a hostile payload cannot
// reach the degenerate shape.
var DEFAULT_MAX_KEYS = 10_000;
var ABSOLUTE_MAX_KEYS = 1_000_000;

// ---- parse ----

/**
 * @primitive b.safeJson.parse
 * @signature b.safeJson.parse(input, opts?)
 * @since     0.1.0
 * @status    stable
 * @related   b.safeJson.parseOrDefault, b.safeJson.stringify, b.safeJson.validate
 *
 * Hardened JSON parse. Accepts string / Buffer / Uint8Array,
 * normalizes to UTF-8 text, enforces the byte cap BEFORE the parser
 * sees the input, then bounds nesting depth and per-object key count
 * so a hostile body can't DoS the parse thread or trip V8's HashDoS
 * shape-cache degeneracy (CVE-2026-21717). Strips `__proto__` /
 * `constructor` / `prototype` keys via the `JSON.parse` reviver so a
 * later spread / merge / clone can't pivot into prototype pollution.
 *
 * Throws `SafeJsonError` with a documented `.code`:
 * `json/too-large` / `json/syntax` / `json/too-deep` /
 * `json/too-many-keys` / `json/wrong-input-type` /
 * `json/type-mismatch` / `json/missing-key` / `json/validation`.
 *
 * @opts
 *   maxBytes:      number,  // default 1 MiB; capped at 64 MiB
 *   maxDepth:      number,  // default 100; capped at 1000
 *   maxKeys:       number,  // default 10 000; capped at 1 000 000
 *   allowProto:    boolean, // default false; keep __proto__/constructor/prototype keys
 *   schema:        object,  // optional JSON-Schema subset; runs b.safeJson.validate
 *   collectErrors: boolean, // pair with `schema`: return { ok, value, errors[] } instead of throwing
 *   expectType:    string,  // legacy: "string"|"number"|"boolean"|"null"|"array"|"object"
 *   requiredKeys:  string[],// legacy: required top-level keys (prefer `schema.required`)
 *
 * @example
 *   var b = require("blamejs");
 *   var obj = b.safeJson.parse('{"name":"alice","age":30}');
 *   obj.name;
 *   // → "alice"
 *
 *   // Prototype-pollution payload: poisoned keys stripped silently.
 *   var clean = b.safeJson.parse('{"__proto__":{"isAdmin":true},"id":1}');
 *   Object.prototype.hasOwnProperty.call(clean, "__proto__");
 *   // → false
 *
 *   // Size cap rejects oversized input before parsing.
 *   var big = '"' + "x".repeat(2000) + '"';
 *   try { b.safeJson.parse(big, { maxBytes: 1024 }); }
 *   catch (e) { e.code; }
 *   // → "json/too-large"
 *
 *   // Depth cap bounds nesting.
 *   try { b.safeJson.parse('[[[[[[1]]]]]]', { maxDepth: 3 }); }
 *   catch (e) { e.code; }
 *   // → "json/too-deep"
 */
function parse(input, opts) {
  opts = opts || {};

  var maxBytes = _capInt(opts.maxBytes, DEFAULT_MAX_BYTES, ABSOLUTE_MAX_BYTES);
  input = safeBuffer.normalizeText(input, {
    maxBytes:    maxBytes,
    errorClass:  SafeJsonError,
    typeCode:    "json/wrong-input-type",
    sizeCode:    "json/too-large",
    typeMessage: "input must be a string, Buffer, or Uint8Array",
  });

  var maxDepth   = _capInt(opts.maxDepth, DEFAULT_MAX_DEPTH, ABSOLUTE_MAX_DEPTH);
  var maxKeys    = _capInt(opts.maxKeys, DEFAULT_MAX_KEYS, ABSOLUTE_MAX_KEYS);
  var allowProto = !!opts.allowProto;

  var parsed;
  try {
    parsed = JSON.parse(input, allowProto ? undefined : _stripProtoKeys);
  } catch (e) {
    throw new SafeJsonError("invalid JSON: " + e.message, "json/syntax");
  }

  _walkAndCheck(parsed, 0, maxDepth, allowProto, maxKeys);

  // Optional schema validation (preferred over expectType / requiredKeys)
  if (opts.schema) {
    if (opts.collectErrors) {
      var result = validate(parsed, opts.schema, { collectErrors: true });
      // Always return the same shape parse promised: a value or an
      // { ok, value, errors[] } object. Caller signals which they want
      // via opts.collectErrors.
      return result;
    }
    validate(parsed, opts.schema);
    return parsed;
  }

  // Legacy lightweight type assertion (for callers that don't supply a schema)
  if (opts.expectType) {
    var actual = _typeName(parsed);
    if (actual !== opts.expectType) {
      throw new SafeJsonError("expected " + opts.expectType + " at root, got " + actual, "json/type-mismatch");
    }
  }
  if (Array.isArray(opts.requiredKeys) && parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
    for (var i = 0; i < opts.requiredKeys.length; i++) {
      if (!Object.prototype.hasOwnProperty.call(parsed, opts.requiredKeys[i])) {
        throw new SafeJsonError("missing required key '" + opts.requiredKeys[i] + "'", "json/missing-key");
      }
    }
  }

  return parsed;
}

/**
 * @primitive b.safeJson.parseOrDefault
 * @signature b.safeJson.parseOrDefault(input, fallback, opts?)
 * @since     0.1.0
 * @status    stable
 * @related   b.safeJson.parse
 *
 * Best-effort parse: returns `fallback` on any failure (size cap,
 * syntax error, depth/key cap, schema mismatch). Useful for cache
 * thaw / config files / optional metadata where a malformed payload
 * shouldn't crash the caller. Same caps and prototype-pollution
 * defense as `parse`.
 *
 * @opts
 *   maxBytes:      number,  // default 1 MiB; capped at 64 MiB
 *   maxDepth:      number,  // default 100; capped at 1000
 *   maxKeys:       number,  // default 10 000; capped at 1 000 000
 *   allowProto:    boolean, // default false; keep __proto__/constructor/prototype keys
 *   schema:        object,  // optional JSON-Schema subset (see b.safeJson.validate)
 *
 * @example
 *   var b = require("blamejs");
 *   b.safeJson.parseOrDefault('{"x":1}', {});
 *   // → { x: 1 }
 *
 *   b.safeJson.parseOrDefault("{not json", { x: 0 });
 *   // → { x: 0 }
 *
 *   b.safeJson.parseOrDefault(null, []);
 *   // → []
 */
function parseOrDefault(input, fallback, opts) {
  try { return parse(input, opts); }
  catch (_e) { return fallback; }
}

/**
 * @primitive b.safeJson.parseStringOrObject
 * @signature b.safeJson.parseStringOrObject(input, opts?)
 * @since     0.15.29
 * @status    stable
 * @related   b.safeJson.parse
 *
 * Accept EITHER a JSON string — parsed through `parse`, so the
 * proto-pollution-key strip, depth/key caps, and size cap all apply — OR an
 * already-decoded plain object (returned unchanged). This is the recurring
 * "operator hands me a document as a JSON string or a pre-built object" surface
 * (b.openapi / b.asyncapi). Routing it here means a raw `JSON.parse` on operator
 * input — which keeps a `"__proto__"` member as an own key and imposes no size
 * bound — cannot be hand-rolled per consumer. The divergence each consumer needs
 * (its typed error class + codes + a generous document size cap) is carried as
 * data, so there is no per-consumer branch.
 *
 * @opts
 *   maxBytes:   number,    // forwarded to parse (default 1 MiB; capped 64 MiB)
 *   maxDepth:   number,    // forwarded to parse
 *   maxKeys:    number,    // forwarded to parse
 *   errorClass: function,  // typed error class to throw (else SafeJsonError)
 *   jsonCode:   string,    // error code for invalid JSON (used with errorClass)
 *   inputCode:  string,    // error code for a non-string/non-object input
 *   label:      string,    // message prefix (default "safeJson.parseStringOrObject")
 *
 * @example
 *   var doc = b.safeJson.parseStringOrObject(input, {
 *     maxBytes: C.BYTES.mib(16), errorClass: OpenApiError,
 *     jsonCode: "openapi/bad-json", inputCode: "openapi/bad-input",
 *     label: "openapi.parse",
 *   });
 */
function parseStringOrObject(input, opts) {
  opts = opts || {};
  var label = opts.label || "safeJson.parseStringOrObject";
  if (typeof input === "string") {
    try { return parse(input, opts); }
    catch (e) {
      if (typeof opts.errorClass === "function") {
        throw new opts.errorClass(opts.jsonCode, label + ": invalid JSON — " + (e && e.message));
      }
      throw e;
    }
  }
  if (input !== null && typeof input === "object" &&
      !Buffer.isBuffer(input) && !(input instanceof Uint8Array)) {
    return input;
  }
  if (typeof opts.errorClass === "function") {
    throw new opts.errorClass(opts.inputCode, label + ": input must be a JSON string or a plain object");
  }
  throw new SafeJsonError(label + ": input must be a JSON string or a plain object", "json/wrong-input-type");
}

function _stripProtoKeys(key, value) {
  if (pick.isPoisonedKey(key)) return undefined;
  return value;
}

function _walkAndCheck(value, depth, maxDepth, allowProto, maxKeys) {
  if (depth > maxDepth) {
    throw new SafeJsonError("nesting exceeds maxDepth (" + maxDepth + ")", "json/too-deep");
  }
  if (value === null || typeof value !== "object") return;
  if (Array.isArray(value)) {
    for (var i = 0; i < value.length; i++) _walkAndCheck(value[i], depth + 1, maxDepth, allowProto, maxKeys);
    return;
  }
  if (!allowProto) {
    pick.POISONED_KEYS.forEach(function (k) {
      if (Object.prototype.hasOwnProperty.call(value, k)) delete value[k];
    });
  }
  // CVE-2026-21717 — refuse object literals beyond maxKeys before V8's
  // hidden-class transition cache degrades to O(n^2) on integer-shaped
  // keys.
  var keyCount = 0;
  for (var k in value) {
    if (Object.prototype.hasOwnProperty.call(value, k)) {
      keyCount += 1;
      if (keyCount > maxKeys) {
        throw new SafeJsonError("object exceeds maxKeys (" + maxKeys + ")", "json/too-many-keys");
      }
      _walkAndCheck(value[k], depth + 1, maxDepth, allowProto, maxKeys);
    }
  }
}

function _typeName(v) {
  if (v === null)        return "null";
  if (Array.isArray(v))  return "array";
  return typeof v;
}

// ---- stringify ----

/**
 * @primitive b.safeJson.stringify
 * @signature b.safeJson.stringify(value, opts?)
 * @since     0.1.0
 * @status    stable
 * @related   b.safeJson.parse, b.safeJson.canonical
 *
 * JSON-encode a value with two safeguards `JSON.stringify` doesn't
 * provide: a documented circular-reference policy (throw, or
 * substitute every cycle with a placeholder string) and prototype-
 * key suppression so an object built from a tainted parse can't leak
 * `__proto__` / `constructor` / `prototype` keys back out.
 *
 * Throws `SafeJsonError` with `.code = "json/circular"` when
 * `onCircular: "throw"` (default) hits a cycle.
 *
 * @opts
 *   onCircular:          "throw" | "replace", // default "throw"
 *   circularReplacement: any,                 // default "[Circular]" (used when onCircular === "replace")
 *   allowProto:          boolean,             // default false; keep __proto__/constructor/prototype keys
 *   indent:              number | string,     // forwarded to JSON.stringify
 *
 * @example
 *   var b = require("blamejs");
 *   b.safeJson.stringify({ a: 1, b: 2 });
 *   // → '{"a":1,"b":2}'
 *
 *   // Cycles throw by default.
 *   var cyclic = { name: "root" };
 *   cyclic.self = cyclic;
 *   try { b.safeJson.stringify(cyclic); }
 *   catch (e) { e.code; }
 *   // → "json/circular"
 *
 *   // Opt into placeholder-substitution.
 *   var out = b.safeJson.stringify(cyclic, { onCircular: "replace" });
 *   // → '{"name":"root","self":"[Circular]"}'
 */
function stringify(value, opts) {
  opts = opts || {};
  var onCircular = opts.onCircular || "throw";
  var replacement = opts.circularReplacement !== undefined ? opts.circularReplacement : "[Circular]";
  var allowProto = !!opts.allowProto;
  var indent     = opts.indent || 0;

  // For "replace" mode, we pre-clean the tree manually because JSON.stringify
  // will throw on cycles before the replacer can rewrite them. The cleaning
  // walk uses stack-discipline (add on descend, remove on ascend) so SHARED
  // subtrees aren't falsely flagged as circular.
  var input = value;
  if (onCircular === "replace") {
    input = _cleanCycles(value, replacement, allowProto);
  }

  function replacer(key, val) {
    if (!allowProto && pick.isPoisonedKey(key)) return undefined;
    return val;
  }

  try {
    return JSON.stringify(input, replacer, indent);
  } catch (e) {
    if (e && e.isSafeJsonError) throw e;
    // JSON.stringify throws TypeError "Converting circular structure to JSON"
    // when it hits a cycle in throw mode.
    if (e instanceof TypeError && /circular/i.test(e.message)) {
      throw new SafeJsonError("circular reference: " + e.message, "json/circular");
    }
    throw new SafeJsonError("stringify failed: " + e.message, "json/stringify");
  }
}

/**
 * @primitive b.safeJson.stringifyForScript
 * @signature b.safeJson.stringifyForScript(value, opts?)
 * @since     0.15.14
 * @status    stable
 * @related   b.safeJson.stringify
 *
 * Like `b.safeJson.stringify` but safe to embed verbatim inside an
 * inline `<script>` element. Raw `JSON.stringify` does not escape `<`,
 * `>`, or `&`, so a string value containing `</script>` (or `<!--`)
 * closes the surrounding script element and injects markup; the
 * Unicode line/paragraph separators U+2028 / U+2029 are also illegal
 * unescaped in a script context on older parsers. This escapes all of
 * them to their equivalent `\uXXXX` JSON escapes — the parsed value is
 * byte-identical, but no substring can break out of a `<script>` block.
 *
 * @opts
 *   indent:    number | string,   // forwarded to b.safeJson.stringify
 *   allowProto:boolean,           // forwarded
 *
 * @example
 *   var json = b.safeJson.stringifyForScript({ url: "/a</script>x" });
 *   res.end('<script type="importmap">' + json + '</script>');
 *   // → the "</script>" inside the value is emitted as "</script>"
 */
function stringifyForScript(value, opts) {
  var json = stringify(value, opts);
  // BS is a single backslash built at runtime so this source carries no
  // escape literals (they round-trip badly through tooling). Escape < > &
  // so the JSON cannot close / comment-open the surrounding inline
  // <script>; escape U+2028 / U+2029 (illegal unescaped in a script on
  // older parsers). The parsed value is unchanged.
  var BS = String.fromCharCode(92);
  json = json.replace(/[<>&]/g, function (c) {
    if (c === "<") return BS + "u003c";
    if (c === ">") return BS + "u003e";
    return BS + "u0026";
  });
  json = json.split(String.fromCharCode(0x2028)).join(BS + "u2028");
  json = json.split(String.fromCharCode(0x2029)).join(BS + "u2029");
  return json;
}

// Walk the value, substituting any references that would create a cycle
// with `replacement`. Uses an active-stack Set so SHARED non-circular
// subtrees are preserved (only true cycles are replaced).
function _cleanCycles(value, replacement, allowProto) {
  var stack = new Set();

  function walk(v) {
    if (v === null || typeof v !== "object") return v;
    if (stack.has(v)) return replacement;
    stack.add(v);
    var out;
    if (Array.isArray(v)) {
      out = new Array(v.length);
      for (var i = 0; i < v.length; i++) out[i] = walk(v[i]);
    } else {
      out = {};
      for (var k in v) {
        if (!Object.prototype.hasOwnProperty.call(v, k)) continue;
        if (!allowProto && pick.isPoisonedKey(k)) continue;
        out[k] = walk(v[k]);
      }
    }
    stack.delete(v);
    return out;
  }

  return walk(value);
}

// ---- canonical ----

/**
 * @primitive b.safeJson.canonical
 * @signature b.safeJson.canonical(value)
 * @since     0.1.0
 * @status    stable
 * @related   b.safeJson.stringify, b.crypto.sign
 *
 * RFC 8785 (JSON Canonicalization Scheme) serialization — produces
 * deterministic output suitable as a hash / signature input. Object
 * keys are lexicographically sorted at every depth, no whitespace is
 * emitted, poisoned keys are stripped, and non-finite numbers
 * (`NaN` / `Infinity`) throw `SafeJsonError` with
 * `.code = "json/non-finite"` instead of silently round-tripping
 * through `null`. Two semantically-equal values produce byte-
 * identical output, which is what signature inputs require.
 *
 * @example
 *   var b = require("blamejs");
 *   b.safeJson.canonical({ b: 2, a: 1 });
 *   // → '{"a":1,"b":2}'
 *
 *   // Two equivalent objects produce identical bytes.
 *   var x = b.safeJson.canonical({ name: "alice", age: 30 });
 *   var y = b.safeJson.canonical({ age: 30, name: "alice" });
 *   x === y;
 *   // → true
 *
 *   // Non-finite numbers refuse to canonicalize.
 *   try { b.safeJson.canonical({ ratio: Infinity }); }
 *   catch (e) { e.code; }
 *   // → "json/non-finite"
 */
function canonical(value) {
  if (typeof value === "undefined") return "null";

  function ser(v) {
    if (v === null || typeof v === "boolean") return JSON.stringify(v);
    if (typeof v === "number") {
      if (!Number.isFinite(v)) {
        throw new SafeJsonError("non-finite number cannot be canonicalized", "json/non-finite");
      }
      return JSON.stringify(v);
    }
    if (typeof v === "string") return JSON.stringify(v);
    if (Array.isArray(v))      return "[" + v.map(ser).join(",") + "]";
    if (typeof v === "object") {
      var keys = Object.keys(v).filter(function (k) { return !pick.isPoisonedKey(k); }).sort();
      var pairs = keys.map(function (k) { return JSON.stringify(k) + ":" + ser(v[k]); });
      return "{" + pairs.join(",") + "}";
    }
    throw new SafeJsonError("cannot canonicalize value of type " + typeof v, "json/uncanonical");
  }

  return ser(value);
}

// ---- format registry ----

// Anchored and bounded — nothing here is ReDoS-prone.
/**
 * @primitive b.safeJson.formats
 * @signature b.safeJson.formats
 * @since     0.1.0
 * @status    stable
 * @related   b.safeJson.registerFormat, b.safeJson.validate
 *
 * The built-in format-validator registry consulted by `validate`
 * when a schema declares `{ format: "<name>" }` on a string field.
 * Every entry is anchored, length-bounded, and non-backtracking —
 * safe against ReDoS. Built-ins: `email` / `url` / `uuid` / `ulid`
 * / `iso8601-date` / `iso8601-datetime` / `ipv4` / `ipv6` / `ip`
 * / `hex` / `slug`. Add operator-specific formats with
 * `b.safeJson.registerFormat`.
 *
 * @example
 *   var b = require("blamejs");
 *   b.safeJson.formats.uuid("f47ac10b-58cc-4372-a567-0e02b2c3d479");
 *   // → true
 *
 *   b.safeJson.formats.email("alice@example.com");
 *   // → true
 *
 *   b.safeJson.formats.ipv4("256.0.0.1");
 *   // → false
 */
var formats = {
  // Structural-only email check (no RFC 5322 attempt). Keeps complexity O(n).
  // Length cap prevents pathological backtracking against long inputs.
  email: function (v) {
    return typeof v === "string" && v.length <= 254 &&
      /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v);
  },
  // URL must parse via WHATWG URL and use http(s)/ws(s) — adjust per app
  url: function (v) {
    if (typeof v !== "string") return false;
    try {
      var u = safeUrl.parse(v, { allowedProtocols: ["http:", "https:", "ws:", "wss:"] });
      return !!u;
    } catch (_e) { return false; }
  },
  uuid: function (v) {
    return typeof v === "string" &&
      /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(v);
  },
  // Crockford base32, 26 chars, must start with [0-7] (timestamp range)
  ulid: function (v) {
    return typeof v === "string" && /^[0-7][0-9A-HJKMNP-TV-Z]{25}$/.test(v);
  },
  "iso8601-date": function (v) {
    if (typeof v !== "string" || !/^\d{4}-\d{2}-\d{2}$/.test(v)) return false;
    var d = new Date(v);
    return !isNaN(d.getTime()) && d.toISOString().slice(0, 10) === v;
  },
  "iso8601-datetime": function (v) {
    if (typeof v !== "string") return false;
    var d = new Date(v);
    return !isNaN(d.getTime()) &&
           d.toISOString().replace(time.ISO_MS_RE, "Z") === v.replace(time.ISO_MS_RE, "Z");
  },
  ipv4: function (v) {
    if (typeof v !== "string") return false;
    var parts = v.split(".");
    if (parts.length !== 4) return false;
    for (var i = 0; i < 4; i++) {
      if (!/^\d{1,3}$/.test(parts[i])) return false;
      var n = Number(parts[i]);
      if (n < 0 || n > 255) return false;
      if (parts[i] !== String(n)) return false; // no leading zeros
    }
    return true;
  },
  // RFC 4291 / RFC 5952 IPv6 — accepts all common forms:
  //   - Full 8 groups: 2001:0db8:85a3:0000:0000:8a2e:0370:7334
  //   - Compressed:    2001:db8::1, ::1, ::, fe80::abcd
  //   - IPv4-mapped:   ::ffff:192.168.1.1
  //   - Mixed case:    2001:DB8::1
  // Rejects: multiple ::, > 8 groups, non-hex chars, groups > 4 hex digits,
  // zone IDs (%eth0 etc — not appropriate for portable data).
  ipv6: function (v) {
    if (typeof v !== "string" || v.length === 0 || v.length > 45) return false;
    if (v.indexOf("%") !== -1) return false; // zone IDs not allowed
    if (v.indexOf(":::") !== -1) return false;

    var doubleColon = v.indexOf("::");
    var hasDouble = doubleColon !== -1;
    if (hasDouble && v.indexOf("::", doubleColon + 2) !== -1) return false;

    var leftParts, rightParts;
    if (hasDouble) {
      var left = v.slice(0, doubleColon);
      var right = v.slice(doubleColon + 2);
      leftParts  = left  ? left.split(":")  : [];
      rightParts = right ? right.split(":") : [];
    } else {
      leftParts  = v.split(":");
      rightParts = [];
    }

    // IPv4-mapped suffix (::ffff:192.0.2.1, 2001:db8::192.0.2.1, etc.)
    var tail = hasDouble ? rightParts : leftParts;
    if (tail.length > 0 && tail[tail.length - 1].indexOf(".") !== -1) {
      if (!formats.ipv4(tail[tail.length - 1])) return false;
      tail.pop();
      // IPv4 is 32 bits = 2 IPv6 groups; insert two synthetic groups
      tail.push("0", "0");
    }

    var totalParts = leftParts.length + rightParts.length;
    if (hasDouble) {
      // Compressed form must replace AT LEAST ONE missing group (otherwise
      // it would be a redundant ::), so total < IPV6_HEXTET_COUNT is required.
      if (totalParts >= IPV6_HEXTET_COUNT) return false;
    } else {
      if (totalParts !== IPV6_HEXTET_COUNT) return false;
    }

    var all = leftParts.concat(rightParts);
    for (var i = 0; i < all.length; i++) {
      if (!safeBuffer.IPV6_HEXTET_RE.test(all[i])) return false;
    }
    return true;
  },
  ip: function (v) { return formats.ipv4(v) || formats.ipv6(v); },
  hex: function (v) { return safeBuffer.isHex(v); },
  // Generic non-empty token: alphanumeric + a few safe punctuation
  slug: function (v) { return typeof v === "string" && /^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(v); },
};

/**
 * @primitive b.safeJson.registerFormat
 * @signature b.safeJson.registerFormat(name, validator)
 * @since     0.1.0
 * @status    stable
 * @related   b.safeJson.formats, b.safeJson.validate
 *
 * Register an operator-supplied format validator. `name` must be
 * lowercase-kebab `[a-z][a-z0-9-]*`; `validator` is `(value) => boolean`.
 * Once registered, schemas can declare `{ type: "string", format:
 * "<name>" }` and the validator runs at every matching node.
 * Throws `SafeJsonError` (`json/bad-format-name` /
 * `json/bad-format-validator`) on invalid arguments.
 *
 * @example
 *   var b = require("blamejs");
 *   b.safeJson.registerFormat("aws-region", function (v) {
 *     return typeof v === "string" && /^[a-z]{2}-[a-z]+-\d$/.test(v);
 *   });
 *
 *   b.safeJson.formats["aws-region"]("us-east-1");
 *   // → true
 *
 *   b.safeJson.formats["aws-region"]("invalid");
 *   // → false
 */
function registerFormat(name, validator) {
  if (typeof name !== "string" || !/^[a-z][a-z0-9-]*$/.test(name)) {
    throw new SafeJsonError("format name must match [a-z][a-z0-9-]*: " + name, "json/bad-format-name");
  }
  if (typeof validator !== "function") {
    throw new SafeJsonError("format validator must be a function", "json/bad-format-validator");
  }
  formats[name] = validator;
}

// ---- validate ----

/**
 * @primitive b.safeJson.validate
 * @signature b.safeJson.validate(value, schema, opts?)
 * @since     0.1.0
 * @status    stable
 * @related   b.safeJson.parse, b.safeJson.registerFormat
 *
 * Strict-subset JSON Schema validator. Supported keywords: `type`
 * (`string` / `number` / `integer` / `boolean` / `null` / `array` /
 * `object`), `enum`, `minLength` / `maxLength` / `pattern` /
 * `format` (string), `minimum` / `maximum` / `exclusiveMinimum` /
 * `exclusiveMaximum` (number), `minItems` / `maxItems` / `items`
 * (array), `required` / `properties` / `additionalProperties`
 * (object).
 *
 * Two modes — throw on the first failure (default; ideal for trust-
 * boundary parses) or collect every error with
 * `{ collectErrors: true }` (returns `{ ok, value, errors[] }` for
 * form-style bulk validation). Errors carry a JSON-pointer-shaped
 * `.path` (e.g. `$.user.email`).
 *
 * @opts
 *   collectErrors: boolean,  // default false; collect every error instead of throwing on first
 *
 * @example
 *   var b = require("blamejs");
 *   var schema = {
 *     type: "object",
 *     required: ["email", "age"],
 *     properties: {
 *       email: { type: "string", format: "email", maxLength: 254 },
 *       age:   { type: "integer", minimum: 0, maximum: 150 },
 *     },
 *     additionalProperties: false,
 *   };
 *
 *   b.safeJson.validate({ email: "a@b.com", age: 30 }, schema);
 *   // → { email: "a@b.com", age: 30 }
 *
 *   // Throw mode: first failure throws SafeJsonError.
 *   try { b.safeJson.validate({ email: "nope", age: -1 }, schema); }
 *   catch (e) { e.code; }
 *   // → "json/validation"
 *
 *   // Collect mode: every failure surfaced.
 *   var report = b.safeJson.validate(
 *     { email: "nope", age: -1 },
 *     schema,
 *     { collectErrors: true }
 *   );
 *   report.ok;
 *   // → false
 *   report.errors.length >= 2;
 *   // → true
 */
function validate(value, schema, opts) {
  opts = opts || {};
  if (!schema || typeof schema !== "object") {
    throw new SafeJsonError("validate: schema must be an object", "json/bad-schema");
  }

  if (opts.collectErrors) {
    var errors = [];
    _validateNode(value, schema, "$", function (err) { errors.push(err); });
    if (errors.length === 0) return { ok: true, value: value, errors: [] };
    return { ok: false, value: value, errors: errors };
  }
  // Throw mode (default)
  _validateNode(value, schema, "$", function (err) { throw err; });
  return value;
}

// Core validation walker. Calls report(error) on every failure. In throw
// mode the report callback throws — control unwinds via the throw. In
// collect mode the report callback pushes; we use early-returns at fatal
// points (type mismatch on a node) to avoid noisy follow-on errors that
// would all be downstream of the same root cause.
function _validateNode(value, schema, path, report) {
  // Type check — if it fails, the value-specific constraints below would
  // produce noisy duplicate errors. Bail this node after reporting.
  if (schema.type) {
    if (schema.type === "integer") {
      if (typeof value !== "number" || !Number.isInteger(value)) {
        report(new SafeJsonError(path + ": expected integer, got " + _typeName(value), "json/validation", path));
        return;
      }
    } else if (_typeName(value) !== schema.type) {
      report(new SafeJsonError(path + ": expected " + schema.type + ", got " + _typeName(value), "json/validation", path));
      return;
    }
  }

  // Enum (independent of type)
  if (Array.isArray(schema.enum)) {
    if (schema.enum.indexOf(value) === -1) {
      report(new SafeJsonError(
        path + ": value not in enum (" + JSON.stringify(schema.enum) + ")",
        "json/validation", path
      ));
    }
  }

  // String constraints
  if (typeof value === "string") {
    if (schema.minLength != null && value.length < schema.minLength) {
      report(new SafeJsonError(path + ": string length " + value.length + " < minLength " + schema.minLength, "json/validation", path));
    }
    if (schema.maxLength != null && value.length > schema.maxLength) {
      report(new SafeJsonError(path + ": string length " + value.length + " > maxLength " + schema.maxLength, "json/validation", path));
    }
    if (schema.pattern) {
      var re = schema.pattern instanceof RegExp ? schema.pattern : new RegExp(schema.pattern);
      if (!re.test(value)) {
        report(new SafeJsonError(path + ": does not match pattern", "json/validation", path));
      }
    }
    if (schema.format) {
      var f = formats[schema.format];
      if (!f) {
        report(new SafeJsonError(path + ": unknown format '" + schema.format + "'", "json/unknown-format", path));
      } else if (!f(value)) {
        report(new SafeJsonError(path + ": does not match format '" + schema.format + "'", "json/validation", path));
      }
    }
  }

  // Number constraints
  if (typeof value === "number") {
    if (schema.minimum != null && value < schema.minimum) {
      report(new SafeJsonError(path + ": " + value + " < minimum " + schema.minimum, "json/validation", path));
    }
    if (schema.exclusiveMinimum != null && value <= schema.exclusiveMinimum) {
      report(new SafeJsonError(path + ": " + value + " <= exclusiveMinimum " + schema.exclusiveMinimum, "json/validation", path));
    }
    if (schema.maximum != null && value > schema.maximum) {
      report(new SafeJsonError(path + ": " + value + " > maximum " + schema.maximum, "json/validation", path));
    }
    if (schema.exclusiveMaximum != null && value >= schema.exclusiveMaximum) {
      report(new SafeJsonError(path + ": " + value + " >= exclusiveMaximum " + schema.exclusiveMaximum, "json/validation", path));
    }
  }

  // Array constraints
  if (Array.isArray(value)) {
    if (schema.minItems != null && value.length < schema.minItems) {
      report(new SafeJsonError(path + ": array length " + value.length + " < minItems " + schema.minItems, "json/validation", path));
    }
    if (schema.maxItems != null && value.length > schema.maxItems) {
      report(new SafeJsonError(path + ": array length " + value.length + " > maxItems " + schema.maxItems, "json/validation", path));
    }
    if (schema.items) {
      for (var i = 0; i < value.length; i++) {
        _validateNode(value[i], schema.items, path + "[" + i + "]", report);
      }
    }
  }

  // Object constraints
  if (value !== null && typeof value === "object" && !Array.isArray(value)) {
    if (Array.isArray(schema.required)) {
      for (var rk = 0; rk < schema.required.length; rk++) {
        if (!Object.prototype.hasOwnProperty.call(value, schema.required[rk])) {
          report(new SafeJsonError(path + ": missing required key '" + schema.required[rk] + "'", "json/validation", path));
        }
      }
    }
    var allowAdditional = schema.additionalProperties !== false;
    if (schema.properties) {
      for (var k in value) {
        if (!Object.prototype.hasOwnProperty.call(value, k)) continue;
        if (Object.prototype.hasOwnProperty.call(schema.properties, k)) {
          _validateNode(value[k], schema.properties[k], path + "." + k, report);
        } else if (!allowAdditional) {
          report(new SafeJsonError(path + ": unknown key '" + k + "'", "json/validation", path + "." + k));
        }
      }
    }
  }
}

// ---- helpers ----

function _capInt(value, defaultValue, ceiling) {
  if (typeof value !== "number" || !Number.isFinite(value) || value < 0) return defaultValue;
  return Math.min(Math.floor(value), ceiling);
}

/**
 * @primitive b.safeJson.DEFAULT_MAX_BYTES
 * @signature b.safeJson.DEFAULT_MAX_BYTES
 * @since     0.1.0
 * @status    stable
 * @related   b.safeJson.parse, b.safeJson.ABSOLUTE_MAX_BYTES
 *
 * Default body cap applied by `parse` when the caller doesn't pass
 * `opts.maxBytes` — 1 MiB. Keeps a hostile request from spending
 * arbitrary CPU on the parse thread before the cap kicks in.
 *
 * @example
 *   var b = require("blamejs");
 *   b.safeJson.DEFAULT_MAX_BYTES;
 *   // → 1048576
 */

/**
 * @primitive b.safeJson.DEFAULT_MAX_DEPTH
 * @signature b.safeJson.DEFAULT_MAX_DEPTH
 * @since     0.1.0
 * @status    stable
 * @related   b.safeJson.parse, b.safeJson.ABSOLUTE_MAX_DEPTH
 *
 * Default nesting-depth cap applied by `parse` when the caller
 * doesn't pass `opts.maxDepth` — 100 levels. Bounds stack-overflow
 * risk for downstream walkers (clone / merge / serializers).
 *
 * @example
 *   var b = require("blamejs");
 *   b.safeJson.DEFAULT_MAX_DEPTH;
 *   // → 100
 */

/**
 * @primitive b.safeJson.DEFAULT_MAX_KEYS
 * @signature b.safeJson.DEFAULT_MAX_KEYS
 * @since     0.1.0
 * @status    stable
 * @related   b.safeJson.parse, b.safeJson.ABSOLUTE_MAX_KEYS
 *
 * Default per-object key cap applied by `parse` when the caller
 * doesn't pass `opts.maxKeys` — 10 000 keys. Defends against
 * CVE-2026-21717 V8 HashDoS (integer-shaped keys degrading the
 * shape-transition cache to O(n^2)).
 *
 * @example
 *   var b = require("blamejs");
 *   b.safeJson.DEFAULT_MAX_KEYS;
 *   // → 10000
 */

/**
 * @primitive b.safeJson.ABSOLUTE_MAX_BYTES
 * @signature b.safeJson.ABSOLUTE_MAX_BYTES
 * @since     0.1.0
 * @status    stable
 * @related   b.safeJson.parse, b.safeJson.DEFAULT_MAX_BYTES
 *
 * Hard ceiling for `opts.maxBytes` — 64 MiB. Operator-supplied caps
 * above this clamp down silently so a typo can't disable the
 * defense entirely.
 *
 * @example
 *   var b = require("blamejs");
 *   b.safeJson.ABSOLUTE_MAX_BYTES;
 *   // → 67108864
 */

/**
 * @primitive b.safeJson.ABSOLUTE_MAX_DEPTH
 * @signature b.safeJson.ABSOLUTE_MAX_DEPTH
 * @since     0.1.0
 * @status    stable
 * @related   b.safeJson.parse, b.safeJson.DEFAULT_MAX_DEPTH
 *
 * Hard ceiling for `opts.maxDepth` — 1000 levels. Caller requests
 * above this clamp down silently.
 *
 * @example
 *   var b = require("blamejs");
 *   b.safeJson.ABSOLUTE_MAX_DEPTH;
 *   // → 1000
 */

/**
 * @primitive b.safeJson.ABSOLUTE_MAX_KEYS
 * @signature b.safeJson.ABSOLUTE_MAX_KEYS
 * @since     0.1.0
 * @status    stable
 * @related   b.safeJson.parse, b.safeJson.DEFAULT_MAX_KEYS
 *
 * Hard ceiling for `opts.maxKeys` — 1 000 000 keys per object.
 * Clamps caller-supplied caps so the HashDoS guard cannot be
 * accidentally disabled by a too-large value.
 *
 * @example
 *   var b = require("blamejs");
 *   b.safeJson.ABSOLUTE_MAX_KEYS;
 *   // → 1000000
 */

/**
 * @primitive b.safeJson.POISONED_KEYS
 * @signature b.safeJson.POISONED_KEYS
 * @since     0.1.0
 * @status    stable
 * @related   b.safeJson.parse, b.safeJson.stringify
 *
 * The list of object keys treated as prototype-pollution vectors —
 * `__proto__`, `constructor`, `prototype`. `parse` strips them on
 * the way in (unless `opts.allowProto: true`); `stringify` and
 * `canonical` strip them on the way out. Exposed as an array so
 * operator code that does its own object hygiene can reuse the
 * same canonical list.
 *
 * @example
 *   var b = require("blamejs");
 *   b.safeJson.POISONED_KEYS;
 *   // → ["__proto__", "constructor", "prototype"]
 *
 *   // Reuse for operator-side sanitization.
 *   var clean = {};
 *   Object.keys(input).forEach(function (k) {
 *     if (b.safeJson.POISONED_KEYS.indexOf(k) === -1) clean[k] = input[k];
 *   });
 */

/**
 * @primitive b.safeJson.isJsonObject
 * @signature b.safeJson.isJsonObject(value)
 * @since     0.15.14
 * @status    stable
 * @related   b.safeJson.parse
 *
 * True iff <code>value</code> is a plain JSON object — not <code>null</code>,
 * not an array, not a scalar. <code>safeJson.parse</code> accepts the literal
 * <code>null</code> and scalars / arrays (all valid JSON documents), so a
 * parsed JWS header, claims set, or document must be re-checked before its
 * fields are dereferenced. This is that check, shared so the
 * <code>!x || typeof x !== "object" || Array.isArray(x)</code> idiom isn't
 * re-rolled (and silently varied) at every call site.
 *
 * @example
 *   var b = require("blamejs");
 *   b.safeJson.isJsonObject(b.safeJson.parse('{"a":1}'));   // → true
 *   b.safeJson.isJsonObject(b.safeJson.parse("null"));      // → false
 *   b.safeJson.isJsonObject(b.safeJson.parse("[1,2]"));     // → false
 */
function isJsonObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

module.exports = {
  parse:          parse,
  parseOrDefault: parseOrDefault,
  parseStringOrObject: parseStringOrObject,
  isJsonObject:   isJsonObject,
  stringify:      stringify,
  stringifyForScript: stringifyForScript,
  canonical:      canonical,
  validate:       validate,
  registerFormat: registerFormat,
  formats:        formats,
  SafeJsonError:  SafeJsonError,
  DEFAULT_MAX_BYTES:  DEFAULT_MAX_BYTES,
  DEFAULT_MAX_DEPTH:  DEFAULT_MAX_DEPTH,
  DEFAULT_MAX_KEYS:   DEFAULT_MAX_KEYS,
  ABSOLUTE_MAX_BYTES: ABSOLUTE_MAX_BYTES,
  ABSOLUTE_MAX_DEPTH: ABSOLUTE_MAX_DEPTH,
  ABSOLUTE_MAX_KEYS:  ABSOLUTE_MAX_KEYS,
  POISONED_KEYS:      pick.POISONED_KEYS.slice(),
};
