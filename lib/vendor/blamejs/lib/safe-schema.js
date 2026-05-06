"use strict";
/**
 * safe-schema — declarative input validation, Zod-shaped surface.
 *
 * Built for: request-body validation, config validation, API payload
 * validation, anywhere operators have an `unknown` shape they need
 * to confirm before reading. Vendor-free; built on framework
 * primitives. No JIT, no codegen, no chained-Promise weirdness.
 *
 * Public API:
 *   var s = b.safeSchema;
 *
 *   var schema = s.object({
 *     email: s.string().email(),
 *     age:   s.number().int().min(0).max(120),
 *     tags:  s.array(s.string()).max(10),
 *     metadata: s.object({}).passthrough().optional(),
 *   });
 *
 *   var result = schema.parse(input);     // throws SafeSchemaError
 *   var safe   = schema.safeParse(input); // → { ok, value?, errors? }
 *
 *   // Errors carry per-field paths:
 *   //   [{ path: ["age"], code: "number/too-large", message: "must be ≤ 120" }]
 *
 * Design choices:
 *   - Schemas are immutable. Chaining returns a new schema with one
 *     additional check; the original is untouched. Cheap because
 *     checks are concat'd into a small array, not deep-copied.
 *   - parse() throws SafeSchemaError carrying the full issues array;
 *     safeParse() never throws (operator-friendly for HTTP boundaries).
 *   - .optional() means "may be undefined"; .nullable() means "may be
 *     null"; .default(v) means "if undefined, substitute v";
 *     .catch(v) means "on ANY validation failure, substitute v".
 *     These compose: optional().default(0) → "may be undefined,
 *     in which case use 0".
 *   - Objects are STRICT by default: unknown keys produce an issue.
 *     Use .passthrough() to retain unknown keys, .strict() to flip
 *     back if a parent .passthrough() set the mode.
 *
 * Surface (every schema has these chained methods unless noted):
 *
 *   Type constructors:
 *     string()      .min, .max, .length, .regex, .email, .url, .uuid,
 *                   .datetime (ISO-8601), .date (YYYY-MM-DD),
 *                   .ip, .ipv4, .ipv6, .nonempty, .startsWith, .endsWith,
 *                   .includes
 *     number()      .int, .min, .max, .gt, .lt, .positive, .negative,
 *                   .nonnegative, .nonpositive, .finite, .multipleOf
 *     boolean()
 *     literal(v)
 *     enum_([...]) | oneOf([...])
 *     null_(), undefined_(), any(), unknown()
 *
 *   Composites:
 *     object({ ... })   .strict, .passthrough, .pick, .omit, .extend,
 *                       .partial, .required (inverse of partial)
 *     array(item)       .min, .max, .length, .nonempty
 *     tuple([...])      .rest(item) for variadic tails
 *     union([...])      first matching wins
 *     discriminatedUnion(key, [...])  faster + clearer-errors variant
 *                                     for tagged unions
 *     record(value) | record(key, value)
 *     lazy(() => schema)              defer construction; for recursion
 *     preprocess(fn, schema)          run fn before validation
 *
 *   Modifiers (any schema):
 *     .optional()       value may be undefined
 *     .nullable()       value may be null
 *     .default(v|fn)    undefined → v (implies optional). Function form
 *                       is called per-parse for fresh values.
 *     .catch(v|fn)      any failure → v (escape hatch for operator
 *                       defaults; suppresses the error info, so use
 *                       sparingly)
 *     .refine(fn, opts) custom predicate — returns false to fail
 *     .transform(fn)    map the validated value to a new shape
 *     .pipe(next)       feed validated output through `next` schema
 *                       for a second round of validation
 *
 * Security guarantees:
 *   - Prototype-pollution defense: __proto__ / constructor / prototype
 *     keys are rejected at construction (object shape) and parse time
 *     (object + record input). Mirrors safe-json.js's POISONED_KEYS.
 *   - No code injection surface: regexes are static module-level
 *     constants; no string→regex parsing on the validation path; no
 *     eval/Function. Operator-supplied refine/transform fns are
 *     plain JS functions, not strings.
 *   - Predicate throws are caught: a refine() function throwing turns
 *     into a regular validation issue, not an unhandled exception.
 *   - Sync-only: no async refinements; operators await at the boundary.
 *
 * Deliberately not shipped (with structural reason):
 *   - z.bigint / z.date / z.map / z.set — no JSON representation; HTTP
 *     boundaries don't carry these. Use s.string().datetime() for
 *     ISO-8601 strings.
 *   - z.nativeEnum / z.never / z.void / z.function — TypeScript-specific.
 *   - z.coerce — loose-coercion is a security foot-gun (truthy/falsy
 *     ambiguity, "0" → 0 vs "0" → "0"). Operators do explicit
 *     s.preprocess(fn, schema) instead.
 *   - z.intersection — for object schemas use .extend(); intersections
 *     of unrelated schemas are structurally ambiguous.
 *   - z.brand — TypeScript compile-time tag with no runtime effect.
 *   - per-schema errorMap — operators chain .refine() with custom message.
 *
 * Relationship to forms.validate:
 *   forms.validate (HTML form spec validation) is a separate surface.
 *   Form specs carry HTML-specific concerns (checkbox coercion, select
 *   option allowlist) that don't belong on the general-purpose validator,
 *   so the two stay distinct rather than one wrapping the other.
 */

var C = require("./constants");
var safeJson = require("./safe-json");
var { defineClass } = require("./framework-error");

// Maximum URL length per RFC 7230 §3.1.1 guidance — also reused as the
// Base64 length cap (no protocol-fixed bound; this matches .url()).
var URL_MAX_LEN = C.BYTES.kib(8);

// Per-format defensive length caps. Each named-format regex below runs
// only after the input is bounded by these caps so a hostile payload
// can't drive the regex engine with an arbitrarily long string. Caps
// are deliberately not multiples of 8 — these are character-count
// bounds, not memory sizes, so C.BYTES.* helpers don't apply.
var EMAIL_MAX_LEN    = 254;   // RFC 5321 §4.5.3.1.3 forward-path bound
var UUID_MAX_LEN     = 50;    // RFC 4122 UUID is 36 chars; slack for whitespace edge cases
var DATE_MAX_LEN     = 30;    // YYYY-MM-DD is 10 chars
var DATETIME_MAX_LEN = 100;   // ISO-8601 with offset + fractional seconds tops near 35
var CUID_MAX_LEN     = 50;    // CUID v1/v2 is 25 chars
var ULID_MAX_LEN     = 50;    // ULID is exactly 26 chars

var SafeSchemaError = defineClass("SafeSchemaError", { alwaysPermanent: true });

// Prototype-pollution defense — these key names are rejected in object
// and record schemas regardless of mode (strict, passthrough, or lazy
// match). Mirrors safe-json.js's POISONED_KEYS set so the framework
// presents one consistent guarantee: an attacker cannot pollute
// Object.prototype by submitting a JSON body with __proto__ /
// constructor / prototype keys, even if the operator schema is
// .passthrough().
var POISONED_KEYS = new Set(["__proto__", "constructor", "prototype"]);

// Pragmatic regexes — RFC-correct is impractical without exploding the
// regex (especially email). Operators wanting deeper validation chain
// .refine() on top.
//
// All regexes are static module-level constants; nothing parses an input
// string into a regex on the validation path (no ReDoS-via-input vector,
// no dynamic regex compilation).
var EMAIL_RE    = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
var URL_RE      = /^[a-zA-Z][a-zA-Z0-9+.-]*:\/\/[^\s]+$/;
var UUID_RE     = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$/;
var DATE_RE     = /^\d{4}-\d{2}-\d{2}$/;
// ISO-8601 datetime with timezone (Z or ±HH:MM); fractional seconds optional.
var DATETIME_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/;
var IPV4_RE     = /^(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$/;
// CUID v1 / v2: 25-char base36, starts with 'c'. Common in TypeScript ecosystems.
var CUID_RE     = /^c[a-z0-9]{24}$/;
// ULID: Crockford-base32, 26 chars, time-sortable.
var ULID_RE     = /^[0-9A-HJKMNP-TV-Z]{26}$/;
// base64 (standard alphabet, with optional padding). Base64url variants
// rejected — operators chain .regex(...) for that.
var BASE64_RE   = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
// IPv6 structural pattern — full 8-hextet, every `::`-compressed shape,
// `::` and `::1` literals, IPv4-mapped (`::ffff:1.2.3.4`), and 6-prefix
// + IPv4 tail. Adapted from validator.js (Apache-2.0); zone IDs
// (`fe80::1%eth0`) are deliberately omitted — the framework rejects
// them as non-portable, matching `safe-json.formats.ipv6`. Bounded
// quantifiers, no nested-quantifier alternation, ReDoS-safe.
//
// `.ipv6()` schema method delegates to `safeJson.formats.ipv6` for
// stricter algorithmic validation; this regex is exported as a
// structural pattern for operators who want it directly.
var IPV6_RE     = /^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$/;

// ---- helpers ----

function _fail(path, code, message) {
  return { ok: false, issues: [{ path: path.slice(), code: code, message: message }] };
}

function _formatIssues(issues) {
  if (!issues || issues.length === 0) return "(no issues)";
  return issues.map(function (i) {
    var p = i.path && i.path.length > 0 ? i.path.join(".") + ": " : "";
    return p + i.message;
  }).join("; ");
}

// Run a schema's modifier-aware pipeline. Used by both root parse() and
// child-key dispatch inside object/array/etc.
function _runWithModifiers(schema, value, path) {
  // Apply default BEFORE catching, so a schema with both .default() and
  // .catch() prefers the default for undefined input (predictable).
  if (value === undefined) {
    if (schema._hasDefault) value = typeof schema._default === "function" ? schema._default() : schema._default;
    else if (schema._isOptional) return { ok: true, value: undefined };
    else return _fail(path, "required", "is required");
  }
  if (value === null) {
    if (schema._isNullable) return { ok: true, value: null };
    if (schema._hasCatch)   return { ok: true, value: schema._catch };
    return _fail(path, "type", "must not be null");
  }
  var r = schema._run(value, path);
  if (!r.ok && schema._hasCatch) {
    return { ok: true, value: typeof schema._catch === "function" ? schema._catch() : schema._catch };
  }
  return r;
}

// ---- core schema factory ----
//
// Every schema stores:
//   _kind         — for diagnostics
//   _isOptional, _isNullable, _hasDefault, _default, _hasCatch, _catch
//   _run(value, path) — type check + checks pipeline
//
// Modifier methods (optional/nullable/default/catch/refine/transform) live
// on the prototype; chained methods are added by each constructor's
// builder (string adds .min/.max etc., array adds .min/.length, etc.).

function _baseSchema(spec) {
  var s = {
    _kind:        spec.kind,
    _isOptional:  spec.isOptional   || false,
    _isNullable:  spec.isNullable   || false,
    _hasDefault:  spec.hasDefault   || false,
    _default:     spec.defaultValue,
    _hasCatch:    spec.hasCatch     || false,
    _catch:       spec.catchValue,
    _run:         spec.run,
  };

  s.parse = function (input) {
    var r = _runWithModifiers(s, input, []);
    if (r.ok) return r.value;
    var err = new SafeSchemaError(
      "safe-schema/invalid",
      "validation failed: " + _formatIssues(r.issues)
    );
    err.issues = r.issues;
    throw err;
  };

  s.safeParse = function (input) {
    var r = _runWithModifiers(s, input, []);
    if (r.ok) return { ok: true, value: r.value };
    return { ok: false, errors: r.issues };
  };

  s.optional = function () {
    return _baseSchema(_extendSpec(spec, { isOptional: true }));
  };
  s.nullable = function () {
    return _baseSchema(_extendSpec(spec, { isNullable: true }));
  };
  s.default = function (v) {
    return _baseSchema(_extendSpec(spec, { isOptional: true, hasDefault: true, defaultValue: v }));
  };
  s.catch = function (v) {
    return _baseSchema(_extendSpec(spec, { hasCatch: true, catchValue: v }));
  };
  s.refine = function (predicate, opts) {
    opts = opts || {};
    var code    = opts.code    || "refine";
    var message = opts.message || "failed custom validation";
    var inner = s;
    return _baseSchema(_extendSpec(spec, {
      run: function (value, path) {
        var r = inner._run(value, path);
        if (!r.ok) return r;
        try {
          if (!predicate(r.value)) return _fail(path, code, message);
        } catch (e) {
          return _fail(path, code,
            message + " (predicate threw: " + ((e && e.message) || String(e)) + ")");
        }
        return r;
      },
    }));
  };
  s.transform = function (fn) {
    var inner = s;
    return _baseSchema(_extendSpec(spec, {
      run: function (value, path) {
        var r = inner._run(value, path);
        if (!r.ok) return r;
        try {
          return { ok: true, value: fn(r.value) };
        } catch (e) {
          return _fail(path, "transform",
            "transform threw: " + ((e && e.message) || String(e)));
        }
      },
    }));
  };
  // .pipe(next) — feed this schema's validated output into another
  // schema for a second round of validation. Common idiom for
  // "validate input shape, transform, re-validate output shape":
  //
  //   var port = s.string().regex(/^\d+$/).transform(Number).pipe(
  //     s.number().int().min(1).max(65535)
  //   );
  s.pipe = function (next) {
    if (!next || typeof next._run !== "function") {
      throw new SafeSchemaError("safe-schema/bad-pipe",
        "pipe: argument must be a schema");
    }
    var inner = s;
    return _baseSchema(_extendSpec(spec, {
      run: function (value, path) {
        var r = inner._run(value, path);
        if (!r.ok) return r;
        return _runWithModifiers(next, r.value, path);
      },
    }));
  };

  return s;
}

function _extendSpec(spec, overrides) {
  return {
    kind:         overrides.kind         != null ? overrides.kind         : spec.kind,
    isOptional:   overrides.isOptional   != null ? overrides.isOptional   : spec.isOptional,
    isNullable:   overrides.isNullable   != null ? overrides.isNullable   : spec.isNullable,
    hasDefault:   overrides.hasDefault   != null ? overrides.hasDefault   : spec.hasDefault,
    defaultValue: overrides.hasDefault   != null ? overrides.defaultValue : spec.defaultValue,
    hasCatch:     overrides.hasCatch     != null ? overrides.hasCatch     : spec.hasCatch,
    catchValue:   overrides.hasCatch     != null ? overrides.catchValue   : spec.catchValue,
    run:          overrides.run          != null ? overrides.run          : spec.run,
  };
}

// Adds a check fn into the schema's _run pipeline by composing it on top
// of the existing _run. Used by string/number/array builders to chain
// .min/.max/etc. onto an existing schema instance.
//
// The check fn returns either:
//   { ok: true }                — pass; keep the inner value unchanged
//   { ok: true, value: newVal } — pass and mutate the value (used by
//                                 ergonomic transforms like .trim())
//   { ok: false, issues }       — fail with the given issue
function _withCheck(schema, spec, check) {
  var inner = schema;
  return _baseSchema(_extendSpec(spec, {
    run: function (value, path) {
      var r = inner._run(value, path);
      if (!r.ok) return r;
      var cr = check(r.value, path);
      if (!cr.ok) return cr;
      if (Object.prototype.hasOwnProperty.call(cr, "value")) {
        return { ok: true, value: cr.value };
      }
      return r;
    },
  }));
}

// ---- string ----

function string() {
  var spec = {
    kind: "string",
    run: function (value, path) {
      if (typeof value !== "string") return _fail(path, "type", "must be a string");
      return { ok: true, value: value };
    },
  };
  return _stringMethods(_baseSchema(spec), spec);
}

function _stringMethods(schema, spec) {
  function chain(check) {
    var next = _withCheck(schema, spec, check);
    return _stringMethods(next, _extendSpec(spec, { run: next._run }));
  }
  schema.min = function (n, msg) {
    return chain(function (v, p) {
      return v.length >= n ? { ok: true } :
        _fail(p, "string/too-short", msg || ("must be at least " + n + " characters"));
    });
  };
  schema.max = function (n, msg) {
    return chain(function (v, p) {
      return v.length <= n ? { ok: true } :
        _fail(p, "string/too-long", msg || ("must be at most " + n + " characters"));
    });
  };
  schema.length = function (n, msg) {
    return chain(function (v, p) {
      return v.length === n ? { ok: true } :
        _fail(p, "string/wrong-length", msg || ("must be exactly " + n + " characters"));
    });
  };
  schema.nonempty = function (msg) { return schema.min(1, msg || "must not be empty"); };
  schema.regex = function (re, msg) {
    return chain(function (v, p) {
      return re.test(v) ? { ok: true } :
        _fail(p, "string/regex", msg || "does not match required pattern");
    });
  };
  schema.startsWith = function (prefix, msg) {
    return chain(function (v, p) {
      return v.indexOf(prefix) === 0 ? { ok: true } :
        _fail(p, "string/starts-with", msg || "must start with '" + prefix + "'");
    });
  };
  schema.endsWith = function (suffix, msg) {
    return chain(function (v, p) {
      return v.length >= suffix.length && v.slice(-suffix.length) === suffix ? { ok: true } :
        _fail(p, "string/ends-with", msg || "must end with '" + suffix + "'");
    });
  };
  schema.includes = function (needle, msg) {
    return chain(function (v, p) {
      return v.indexOf(needle) !== -1 ? { ok: true } :
        _fail(p, "string/includes", msg || "must include '" + needle + "'");
    });
  };
  schema.email = function () {
    return chain(function (v, p) {
      // RFC 5321 §4.5.3.1.3 — max forward-path is 256 octets including
      // angle brackets, so the address itself is bounded at 254 chars.
      // Without this cap an operator chaining .email() on a request body
      // is open to a DoS shape (50 KB email -> downstream DB writes
      // unbounded string columns, log lines, etc.). Operators with a
      // legitimate non-RFC reason for longer emails skip .email() and
      // chain .regex(custom) directly.
      if (v.length > EMAIL_MAX_LEN) return _fail(p, "string/email-too-long",
        "must be a valid email address (max " + EMAIL_MAX_LEN + " chars per RFC 5321)");
      return EMAIL_RE.test(v) ? { ok: true } :
        _fail(p, "string/email", "must be a valid email address");
    });
  };
  schema.url = function () {
    return chain(function (v, p) {
      // RFC 9110 doesn't set a hard URL length, but RFC 7230 §3.1.1
      // recommended 8000 octets and most HTTP origin servers + load
      // balancers cap at 8 KB. Without this bound an operator chaining
      // .url() on a request body was open to a 50 MB URL passing
      // validation. Operators with a legitimate non-standard use
      // (tunnels, proxies with embedded payloads) skip .url() and
      // chain .regex(custom) directly.
      if (v.length > URL_MAX_LEN) return _fail(p, "string/url-too-long",
        "must be a valid URL (max " + URL_MAX_LEN + " chars per RFC 7230 §3.1.1 guidance)");
      return URL_RE.test(v) ? { ok: true } :
        _fail(p, "string/url", "must be a valid URL");
    });
  };
  schema.uuid = function () {
    return chain(function (v, p) {
      // RFC 4122 UUID is 36 chars (8-4-4-4-12 + 4 dashes); cap defensively
      // so a 50-MB string can't reach the regex engine.
      if (typeof v !== "string" || v.length > UUID_MAX_LEN || !UUID_RE.test(v)) {
        return _fail(p, "string/uuid", "must be a valid UUID");
      }
      return { ok: true };
    });
  };
  schema.date = function () {
    return chain(function (v, p) {
      // YYYY-MM-DD is 10 chars; cap defensively before the regex test.
      if (typeof v !== "string" || v.length > DATE_MAX_LEN || !DATE_RE.test(v)) {
        return _fail(p, "string/date", "must be a YYYY-MM-DD date");
      }
      return { ok: true };
    });
  };
  schema.datetime = function () {
    return chain(function (v, p) {
      // ISO-8601 with offset + fractional seconds tops out near 64 chars;
      // cap defensively before the regex test.
      if (typeof v !== "string" || v.length > DATETIME_MAX_LEN || !DATETIME_RE.test(v)) {
        return _fail(p, "string/datetime", "must be an ISO-8601 datetime with timezone");
      }
      return { ok: true };
    });
  };
  // IP-address validators delegate to safe-json's algorithmic format
  // checks rather than re-running regex matches. The algorithmic path
  // handles edge cases that pure regex misses (compressed `::` shapes,
  // IPv4-mapped `::ffff:1.2.3.4`, multi-`::` rejection, group-count
  // bounds) and keeps the framework's IP-validation behavior in one
  // tested place. IPV4_RE / IPV6_RE remain exported for operators who
  // want the structural pattern, but `.ipv4()` / `.ipv6()` / `.ip()`
  // are the canonical validation surface.
  schema.ipv4 = function () {
    return chain(function (v, p) {
      return (typeof v === "string" && safeJson.formats.ipv4(v))
        ? { ok: true }
        : _fail(p, "string/ipv4", "must be a valid IPv4 address");
    });
  };
  schema.ipv6 = function () {
    return chain(function (v, p) {
      return (typeof v === "string" && safeJson.formats.ipv6(v))
        ? { ok: true }
        : _fail(p, "string/ipv6", "must be a valid IPv6 address");
    });
  };
  schema.ip = function () {
    return chain(function (v, p) {
      return (typeof v === "string" && safeJson.formats.ip(v))
        ? { ok: true }
        : _fail(p, "string/ip", "must be a valid IP address (v4 or v6)");
    });
  };
  schema.cuid = function () {
    return chain(function (v, p) {
      // CUID v1/v2 is 25 chars; cap defensively before the regex test.
      if (typeof v !== "string" || v.length > CUID_MAX_LEN || !CUID_RE.test(v)) {
        return _fail(p, "string/cuid", "must be a valid CUID");
      }
      return { ok: true };
    });
  };
  schema.ulid = function () {
    return chain(function (v, p) {
      // ULID is exactly 26 chars; cap defensively before the regex test.
      if (typeof v !== "string" || v.length > ULID_MAX_LEN || !ULID_RE.test(v)) {
        return _fail(p, "string/ulid", "must be a valid ULID");
      }
      return { ok: true };
    });
  };
  schema.base64 = function () {
    return chain(function (v, p) {
      // Base64 has no protocol-fixed cap; bound at the same 8 KiB the
      // .url() validator uses so a hostile payload can't feed an
      // unbounded string to the regex.
      if (typeof v !== "string" || v.length > URL_MAX_LEN) {
        return _fail(p, "string/base64", "must be valid base64 (standard alphabet)");
      }
      return BASE64_RE.test(v) ? { ok: true } :
        _fail(p, "string/base64", "must be valid base64 (standard alphabet)");
    });
  };
  // Coercion-via-transform — these mutate the validated string before
  // the next check runs. Apply EARLY in the chain (before .min, .email,
  // etc.) so subsequent checks see the normalized form.
  schema.trim = function () {
    return chain(function (v) { return { ok: true, value: v.trim() }; });
  };
  schema.toLowerCase = function () {
    return chain(function (v) { return { ok: true, value: v.toLowerCase() }; });
  };
  schema.toUpperCase = function () {
    return chain(function (v) { return { ok: true, value: v.toUpperCase() }; });
  };
  return schema;
}

// ---- number ----

function number() {
  var spec = {
    kind: "number",
    run: function (value, path) {
      if (typeof value !== "number" || Number.isNaN(value)) {
        return _fail(path, "type", "must be a number");
      }
      return { ok: true, value: value };
    },
  };
  return _numberMethods(_baseSchema(spec), spec);
}

function _numberMethods(schema, spec) {
  function chain(check) {
    var next = _withCheck(schema, spec, check);
    return _numberMethods(next, _extendSpec(spec, { run: next._run }));
  }
  schema.int = function (msg) {
    return chain(function (v, p) {
      return Number.isInteger(v) ? { ok: true } :
        _fail(p, "number/not-integer", msg || "must be an integer");
    });
  };
  schema.min = function (n, msg) {
    return chain(function (v, p) {
      return v >= n ? { ok: true } : _fail(p, "number/too-small", msg || ("must be ≥ " + n));
    });
  };
  schema.max = function (n, msg) {
    return chain(function (v, p) {
      return v <= n ? { ok: true } : _fail(p, "number/too-large", msg || ("must be ≤ " + n));
    });
  };
  schema.gt = function (n, msg) {
    return chain(function (v, p) {
      return v > n ? { ok: true } : _fail(p, "number/not-gt", msg || ("must be > " + n));
    });
  };
  schema.lt = function (n, msg) {
    return chain(function (v, p) {
      return v < n ? { ok: true } : _fail(p, "number/not-lt", msg || ("must be < " + n));
    });
  };
  schema.positive    = function (msg) { return schema.gt(0,  msg || "must be positive"); };
  schema.negative    = function (msg) { return schema.lt(0,  msg || "must be negative"); };
  schema.nonnegative = function (msg) { return schema.min(0, msg || "must be non-negative"); };
  schema.nonpositive = function (msg) { return schema.max(0, msg || "must be non-positive"); };
  schema.finite = function (msg) {
    return chain(function (v, p) {
      return Number.isFinite(v) ? { ok: true } :
        _fail(p, "number/not-finite", msg || "must be a finite number");
    });
  };
  // safe() — Number.isSafeInteger range. Important for IDs that round-trip
  // through JSON (which can't represent BigInts) and need to survive without
  // precision loss.
  schema.safe = function (msg) {
    return chain(function (v, p) {
      return Number.isSafeInteger(v) ? { ok: true } :
        _fail(p, "number/not-safe", msg || "must be a safe integer (within ±2^53)");
    });
  };
  schema.multipleOf = function (n, msg) {
    return chain(function (v, p) {
      // Use modulo with fp tolerance — exact mod on floats is fragile.
      var quot = v / n;
      return Math.abs(quot - Math.round(quot)) < 1e-9 ? { ok: true } :
        _fail(p, "number/not-multiple-of", msg || ("must be a multiple of " + n));
    });
  };
  return schema;
}

// ---- boolean ----

function boolean() {
  return _baseSchema({
    kind: "boolean",
    run: function (value, path) {
      if (typeof value !== "boolean") return _fail(path, "type", "must be a boolean");
      return { ok: true, value: value };
    },
  });
}

// ---- literal ----

function literal(expected) {
  return _baseSchema({
    kind: "literal",
    run: function (value, path) {
      if (value !== expected) {
        return _fail(path, "literal", "must be exactly " + JSON.stringify(expected));
      }
      return { ok: true, value: value };
    },
  });
}

// ---- enum / oneOf ----

function enum_(values) {
  if (!Array.isArray(values) || values.length === 0) {
    throw new SafeSchemaError("safe-schema/bad-enum",
      "enum requires a non-empty array of allowed values");
  }
  var allowedSet = new Set(values);
  return _baseSchema({
    kind: "enum",
    run: function (value, path) {
      if (!allowedSet.has(value)) {
        return _fail(path, "enum",
          "must be one of: " + values.map(function (v) { return JSON.stringify(v); }).join(", "));
      }
      return { ok: true, value: value };
    },
  });
}

// ---- null / undefined / any / unknown ----

function null_() {
  return _baseSchema({
    kind: "null",
    isNullable: true,
    run: function (value, path) {
      // Modifier handler accepts null already; if we got here, value is non-null.
      return _fail(path, "type", "must be null");
    },
  });
}

function undefined_() {
  return _baseSchema({
    kind: "undefined",
    isOptional: true,
    run: function (_value, path) {
      return _fail(path, "type", "must be undefined");
    },
  });
}

function any() {
  return _baseSchema({
    kind: "any",
    isOptional: true,
    isNullable: true,
    run: function (value) { return { ok: true, value: value }; },
  });
}

function unknown() { return any(); }

// ---- object ----

function object(shape) {
  if (shape == null || typeof shape !== "object") {
    throw new SafeSchemaError("safe-schema/bad-shape",
      "object() requires a shape object mapping field name to schema");
  }
  // Use getOwnPropertyNames so an operator who built the shape via
  // Object.fromEntries / defineProperty (the only paths by which a
  // POISONED_KEYS name can appear as an own property — object-literal
  // {"__proto__": ...} syntax sets the prototype rather than creating
  // such a key) gets a refusal at construction time.
  var allOwnKeys = Object.getOwnPropertyNames(shape);
  for (var ai = 0; ai < allOwnKeys.length; ai++) {
    if (POISONED_KEYS.has(allOwnKeys[ai])) {
      throw new SafeSchemaError("safe-schema/poisoned-shape-key",
        "object shape: key '" + allOwnKeys[ai] + "' is forbidden (prototype-pollution defense)");
    }
  }
  var keys = Object.keys(shape);
  for (var k = 0; k < keys.length; k++) {
    if (!shape[keys[k]] || typeof shape[keys[k]]._run !== "function") {
      throw new SafeSchemaError("safe-schema/bad-shape",
        "object shape: '" + keys[k] + "' is not a schema");
    }
  }
  return _objectWithMode(shape, keys, "strict");
}

function _objectWithMode(shape, keys, mode) {
  var spec = {
    kind: "object",
    run: function (value, path) {
      if (typeof value !== "object" || Array.isArray(value)) {
        return _fail(path, "type", "must be an object");
      }
      var issues = [];
      var out = {};
      for (var i = 0; i < keys.length; i++) {
        var key = keys[i];
        var sub = shape[key];
        var childPath = path.concat([key]);
        var r = _runWithModifiers(sub, value[key], childPath);
        if (!r.ok) {
          for (var j = 0; j < r.issues.length; j++) issues.push(r.issues[j]);
          continue;
        }
        if (r.value !== undefined) out[key] = r.value;
      }
      var inputKeys = Object.keys(value);
      for (var ii = 0; ii < inputKeys.length; ii++) {
        var ik = inputKeys[ii];
        if (Object.prototype.hasOwnProperty.call(shape, ik)) continue;
        // Prototype-pollution defense — refuse __proto__/constructor/
        // prototype regardless of mode. .passthrough() never propagates
        // these because they are always rejected as input.
        if (POISONED_KEYS.has(ik)) {
          issues.push({
            path: path.concat([ik]),
            code: "object/poisoned-key",
            message: "key '" + ik + "' is forbidden (prototype-pollution defense)",
          });
          continue;
        }
        if (mode === "passthrough") {
          out[ik] = value[ik];
        } else {
          issues.push({
            path: path.concat([ik]),
            code: "object/unknown-key",
            message: "unknown key '" + ik + "' (use .passthrough() to allow extra keys)",
          });
        }
      }
      if (issues.length > 0) return { ok: false, issues: issues };
      return { ok: true, value: out };
    },
  };
  var schema = _baseSchema(spec);
  schema.shape = shape;
  schema.strict = function () { return _objectWithMode(shape, keys, "strict"); };
  schema.passthrough = function () { return _objectWithMode(shape, keys, "passthrough"); };

  // .pick(["a","b"]) → narrow to listed keys
  schema.pick = function (pickKeys) {
    var newShape = {};
    for (var i = 0; i < pickKeys.length; i++) {
      var k = pickKeys[i];
      if (Object.prototype.hasOwnProperty.call(shape, k)) newShape[k] = shape[k];
    }
    return _objectWithMode(newShape, Object.keys(newShape), mode);
  };
  // .omit(["a","b"]) → drop listed keys
  schema.omit = function (omitKeys) {
    var omitSet = new Set(omitKeys);
    var newShape = {};
    var newKeys = [];
    for (var i = 0; i < keys.length; i++) {
      if (!omitSet.has(keys[i])) {
        newShape[keys[i]] = shape[keys[i]];
        newKeys.push(keys[i]);
      }
    }
    return _objectWithMode(newShape, newKeys, mode);
  };
  // .extend({ ... }) → merge additional shape; new keys override
  schema.extend = function (additional) {
    if (!additional || typeof additional !== "object") {
      throw new SafeSchemaError("safe-schema/bad-extend",
        "extend() requires a shape object");
    }
    var merged = Object.assign({}, shape, additional);
    return _objectWithMode(merged, Object.keys(merged), mode);
  };
  // .partial() → mark every key optional
  schema.partial = function () {
    var newShape = {};
    var newKeys = [];
    for (var i = 0; i < keys.length; i++) {
      newShape[keys[i]] = shape[keys[i]].optional();
      newKeys.push(keys[i]);
    }
    return _objectWithMode(newShape, newKeys, mode);
  };
  // .required() — inverse of partial(). Strips optional + default + nullable
  // off every key (operators sometimes call .partial() and then peel back
  // a subset; this is the cleanest path).
  schema.required = function () {
    var newShape = {};
    var newKeys = [];
    for (var i = 0; i < keys.length; i++) {
      var inner = shape[keys[i]];
      // Strip modifiers by rebuilding without them. We don't have the
      // pre-modifier schema cached, but we can reach it: the underlying
      // _run is preserved; clone with all modifier flags off.
      newShape[keys[i]] = _baseSchema({
        kind:       inner._kind,
        isOptional: false,
        isNullable: false,
        hasDefault: false,
        hasCatch:   inner._hasCatch,
        catchValue: inner._catch,
        run:        inner._run,
      });
      newKeys.push(keys[i]);
    }
    return _objectWithMode(newShape, newKeys, mode);
  };
  return schema;
}

// ---- array ----

function array(itemSchema) {
  if (!itemSchema || typeof itemSchema._run !== "function") {
    throw new SafeSchemaError("safe-schema/bad-item",
      "array() requires an item schema");
  }
  var spec = {
    kind: "array",
    run: function (value, path) {
      if (!Array.isArray(value)) return _fail(path, "type", "must be an array");
      var issues = [];
      var out = [];
      for (var i = 0; i < value.length; i++) {
        var childPath = path.concat([i]);
        var r = _runWithModifiers(itemSchema, value[i], childPath);
        if (!r.ok) {
          for (var j = 0; j < r.issues.length; j++) issues.push(r.issues[j]);
          continue;
        }
        out.push(r.value);
      }
      if (issues.length > 0) return { ok: false, issues: issues };
      return { ok: true, value: out };
    },
  };
  return _arrayMethods(_baseSchema(spec), spec);
}

function _arrayMethods(schema, spec) {
  function chain(check) {
    var next = _withCheck(schema, spec, check);
    return _arrayMethods(next, _extendSpec(spec, { run: next._run }));
  }
  schema.min = function (n, msg) {
    return chain(function (v, p) {
      return v.length >= n ? { ok: true } :
        _fail(p, "array/too-short", msg || ("must contain at least " + n + " items"));
    });
  };
  schema.max = function (n, msg) {
    return chain(function (v, p) {
      return v.length <= n ? { ok: true } :
        _fail(p, "array/too-long", msg || ("must contain at most " + n + " items"));
    });
  };
  schema.length = function (n, msg) {
    return chain(function (v, p) {
      return v.length === n ? { ok: true } :
        _fail(p, "array/wrong-length", msg || ("must contain exactly " + n + " items"));
    });
  };
  schema.nonempty = function (msg) { return schema.min(1, msg || "must not be empty"); };
  return schema;
}

// ---- tuple ----

function tuple(items) {
  if (!Array.isArray(items) || items.length === 0) {
    throw new SafeSchemaError("safe-schema/bad-tuple",
      "tuple() requires a non-empty array of item schemas");
  }
  for (var i = 0; i < items.length; i++) {
    if (!items[i] || typeof items[i]._run !== "function") {
      throw new SafeSchemaError("safe-schema/bad-tuple",
        "tuple item " + i + " is not a schema");
    }
  }
  return _tupleWithRest(items, null);
}

function _tupleWithRest(items, restSchema) {
  var schema = _baseSchema({
    kind: "tuple",
    run: function (value, path) {
      if (!Array.isArray(value)) return _fail(path, "type", "must be an array (tuple)");
      if (restSchema === null && value.length !== items.length) {
        return _fail(path, "tuple/wrong-length",
          "tuple must contain exactly " + items.length + " items (got " + value.length + ")");
      }
      if (restSchema !== null && value.length < items.length) {
        return _fail(path, "tuple/wrong-length",
          "tuple must contain at least " + items.length + " items (got " + value.length + ")");
      }
      var issues = [];
      var out = [];
      for (var i = 0; i < items.length; i++) {
        var r = _runWithModifiers(items[i], value[i], path.concat([i]));
        if (!r.ok) {
          for (var j = 0; j < r.issues.length; j++) issues.push(r.issues[j]);
          continue;
        }
        out.push(r.value);
      }
      // Variadic tail — every extra item is checked against restSchema.
      if (restSchema !== null) {
        for (var k = items.length; k < value.length; k++) {
          var rr = _runWithModifiers(restSchema, value[k], path.concat([k]));
          if (!rr.ok) {
            for (var jj = 0; jj < rr.issues.length; jj++) issues.push(rr.issues[jj]);
            continue;
          }
          out.push(rr.value);
        }
      }
      if (issues.length > 0) return { ok: false, issues: issues };
      return { ok: true, value: out };
    },
  });
  // .rest(itemSchema) — append a variadic tail to the tuple. Common for
  // protocol shapes like [verb, ...args] or [event, payload, ...metadata].
  schema.rest = function (item) {
    if (!item || typeof item._run !== "function") {
      throw new SafeSchemaError("safe-schema/bad-tuple-rest",
        "tuple.rest(): argument must be a schema");
    }
    return _tupleWithRest(items, item);
  };
  return schema;
}

// ---- union ----

function union(options) {
  if (!Array.isArray(options) || options.length === 0) {
    throw new SafeSchemaError("safe-schema/bad-union",
      "union() requires a non-empty array of option schemas");
  }
  for (var i = 0; i < options.length; i++) {
    if (!options[i] || typeof options[i]._run !== "function") {
      throw new SafeSchemaError("safe-schema/bad-union",
        "union option " + i + " is not a schema");
    }
  }
  return _baseSchema({
    kind: "union",
    run: function (value, path) {
      var collected = [];
      for (var i = 0; i < options.length; i++) {
        var r = _runWithModifiers(options[i], value, path);
        if (r.ok) return r;
        // Collect each option's issues so the operator sees the full
        // failure surface; helpful for debugging which option matched
        // most closely.
        for (var j = 0; j < r.issues.length; j++) collected.push(r.issues[j]);
      }
      // No option matched — emit a union-level issue at the parent path
      // plus the collected per-option issues for deep diagnostics.
      var summary = _fail(path, "union",
        "did not match any of the " + options.length + " allowed shapes");
      summary.issues = summary.issues.concat(collected);
      return summary;
    },
  });
}

// ---- record ----
// record(value)               — string keys, schema-typed values
// record(keySchema, value)    — both keys and values are schema-validated

function record(a, b) {
  var keySchema, valueSchema;
  if (b === undefined) {
    keySchema = null; // any string key
    valueSchema = a;
  } else {
    keySchema = a;
    valueSchema = b;
  }
  if (!valueSchema || typeof valueSchema._run !== "function") {
    throw new SafeSchemaError("safe-schema/bad-value-schema",
      "record() requires a value schema");
  }
  if (keySchema && typeof keySchema._run !== "function") {
    throw new SafeSchemaError("safe-schema/bad-key-schema",
      "record(keySchema, valueSchema): keySchema must be a schema");
  }
  return _baseSchema({
    kind: "record",
    run: function (value, path) {
      if (typeof value !== "object" || value === null || Array.isArray(value)) {
        return _fail(path, "type", "must be a plain object (record)");
      }
      var issues = [];
      var out = {};
      var keys = Object.keys(value);
      for (var i = 0; i < keys.length; i++) {
        var k = keys[i];
        // Prototype-pollution defense — same shape as object() schema.
        if (POISONED_KEYS.has(k)) {
          issues.push({
            path: path.concat([k]),
            code: "record/poisoned-key",
            message: "key '" + k + "' is forbidden (prototype-pollution defense)",
          });
          continue;
        }
        if (keySchema) {
          var kr = _runWithModifiers(keySchema, k, path.concat([k]));
          if (!kr.ok) {
            for (var jj = 0; jj < kr.issues.length; jj++) issues.push(kr.issues[jj]);
            continue;
          }
        }
        var r = _runWithModifiers(valueSchema, value[k], path.concat([k]));
        if (!r.ok) {
          for (var j = 0; j < r.issues.length; j++) issues.push(r.issues[j]);
          continue;
        }
        if (r.value !== undefined) out[k] = r.value;
      }
      if (issues.length > 0) return { ok: false, issues: issues };
      return { ok: true, value: out };
    },
  });
}

// ---- discriminatedUnion ----
//
// Performance + ergonomics improvement over union for the common case
// of "tagged variants": a literal field on each option distinguishes
// the branches, so we dispatch on that field's value directly rather
// than trying every option in turn.
//
//   var event = s.discriminatedUnion("kind", [
//     s.object({ kind: s.literal("created"), at: s.string().datetime() }),
//     s.object({ kind: s.literal("deleted"), reason: s.string() }),
//   ]);
//
// Each option must be an object schema whose `discriminator` key is a
// literal schema. Mismatched discriminator fails fast with a clear
// "expected one of [...]" message rather than burying the operator in
// per-branch issues.
function discriminatedUnion(discriminator, options) {
  if (typeof discriminator !== "string" || discriminator.length === 0) {
    throw new SafeSchemaError("safe-schema/bad-discriminator",
      "discriminatedUnion: discriminator must be a non-empty string key name");
  }
  if (POISONED_KEYS.has(discriminator)) {
    throw new SafeSchemaError("safe-schema/poisoned-discriminator",
      "discriminatedUnion: discriminator key '" + discriminator + "' is forbidden");
  }
  if (!Array.isArray(options) || options.length === 0) {
    throw new SafeSchemaError("safe-schema/bad-union",
      "discriminatedUnion: options must be a non-empty array");
  }
  for (var i = 0; i < options.length; i++) {
    var opt = options[i];
    if (!opt || opt._kind !== "object" || !opt.shape) {
      throw new SafeSchemaError("safe-schema/bad-discriminated-option",
        "discriminatedUnion option " + i + " must be an object schema");
    }
    var disc = opt.shape[discriminator];
    if (!disc || disc._kind !== "literal") {
      throw new SafeSchemaError("safe-schema/bad-discriminated-option",
        "discriminatedUnion option " + i + ": discriminator '" + discriminator +
        "' must be a literal schema");
    }
    // The literal's expected value lives in its closure; we extract via
    // a probe rather than introspection. literal(v)._run(v) succeeds.
    // We sample by trying every option's discriminator separately at
    // dispatch time (cheap; literal._run is just a triple-equals).
  }
  return _baseSchema({
    kind: "discriminatedUnion",
    run: function (value, path) {
      if (typeof value !== "object" || value === null || Array.isArray(value)) {
        return _fail(path, "type", "must be an object (discriminated union)");
      }
      var disc = value[discriminator];
      // Find the option whose discriminator schema accepts disc.
      for (var i = 0; i < options.length; i++) {
        var opt = options[i];
        var d = opt.shape[discriminator];
        var dr = d._run(disc, path.concat([discriminator]));
        if (dr.ok) {
          return _runWithModifiers(opt, value, path);
        }
      }
      return _fail(path.concat([discriminator]), "discriminated-union/no-match",
        "discriminator '" + discriminator + "' did not match any option");
    },
  });
}

// ---- preprocess ----
//
// Run a transform BEFORE validation. Common at HTTP boundaries where
// query strings arrive as strings but the operator wants a number /
// boolean schema downstream.
//
//   var port = s.preprocess(function (v) { return Number(v); }, s.number().int().min(1).max(65535));
//
// fn errors propagate as a 'preprocess' issue at the parent path; they
// don't crash the validate call.
function preprocess(fn, inner) {
  if (typeof fn !== "function") {
    throw new SafeSchemaError("safe-schema/bad-preprocess",
      "preprocess: first arg must be a function");
  }
  if (!inner || typeof inner._run !== "function") {
    throw new SafeSchemaError("safe-schema/bad-preprocess",
      "preprocess: second arg must be a schema");
  }
  return _baseSchema({
    kind: "preprocess",
    run: function (value, path) {
      var preprocessed;
      try {
        preprocessed = fn(value);
      } catch (e) {
        return _fail(path, "preprocess",
          "preprocess fn threw: " + ((e && e.message) || String(e)));
      }
      return _runWithModifiers(inner, preprocessed, path);
    },
  });
}

// ---- lazy (recursive schemas) ----
//
// Defers schema construction until first parse. Operators wanting a
// recursive shape — comment threads, file-tree nodes, etc. — wrap the
// recursive reference in a function that returns the schema:
//
//   var commentSchema = s.object({
//     id:       s.string(),
//     replies:  s.array(s.lazy(function () { return commentSchema; })),
//   });
//
// The function is called lazily and cached per-call site; cycles in the
// returned schema are fine.
function lazy(getter) {
  if (typeof getter !== "function") {
    throw new SafeSchemaError("safe-schema/bad-lazy",
      "lazy: argument must be a function returning a schema");
  }
  var cached = null;
  return _baseSchema({
    kind: "lazy",
    run: function (value, path) {
      if (!cached) {
        cached = getter();
        if (!cached || typeof cached._run !== "function") {
          return _fail(path, "lazy",
            "lazy() function did not return a schema");
        }
      }
      return _runWithModifiers(cached, value, path);
    },
  });
}

// ---- top-level modifier helpers ----

function optional(inner) { return inner.optional(); }
function nullable(inner) { return inner.nullable(); }

module.exports = {
  // Primitives
  string:           string,
  number:           number,
  boolean:          boolean,
  literal:          literal,
  null_:            null_,
  undefined_:       undefined_,
  any:              any,
  unknown:          unknown,

  // Composites
  object:           object,
  array:            array,
  tuple:            tuple,
  union:            union,
  discriminatedUnion: discriminatedUnion,
  record:           record,
  lazy:             lazy,
  preprocess:       preprocess,

  // enum is a reserved word in some tooling — ship both names
  enum_:            enum_,
  oneOf:            enum_,

  // Modifier helpers (chained methods exist on every schema; these are
  // the equivalents for operators who prefer composition over chaining)
  optional:         optional,
  nullable:         nullable,

  // Errors
  SafeSchemaError:  SafeSchemaError,

  // Validation regexes — exported so other modules don't re-declare
  // their own copies. Pragmatic patterns; operators wanting RFC-strict
  // behavior chain `.refine()` on top of the schema instead.
  EMAIL_RE:         EMAIL_RE,
  URL_RE:           URL_RE,
  UUID_RE:          UUID_RE,
  DATE_RE:          DATE_RE,
  DATETIME_RE:      DATETIME_RE,
  IPV4_RE:          IPV4_RE,
  IPV6_RE:          IPV6_RE,
  CUID_RE:          CUID_RE,
  ULID_RE:          ULID_RE,
};
