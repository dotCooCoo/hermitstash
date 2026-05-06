"use strict";
/**
 * Security-focused, fault-tolerant JSON utilities + lightweight schema
 * validation with extensible format registry.
 *
 * Native JSON.parse leaves several footguns to the caller:
 *   - No size limit — large inputs DoS the parser thread
 *   - No depth limit — deeply nested input can stack-overflow downstream code
 *   - __proto__ / constructor / prototype keys land in the result and can be
 *     turned into prototype pollution by any later object-merge / clone
 *   - Errors include only a character position, no surrounding context
 *
 * This module fixes all of the above with conservative defaults and adds a
 * lightweight schema validator (a strict subset of JSON Schema) so apps
 * can declare what they expect at the trust boundary.
 *
 * Public API:
 *
 *   json.parse(input, opts?)               → value | throws SafeJsonError
 *                                            (with opts.collectErrors: { ok, value, errors[] })
 *   json.parseOrDefault(input, fallback, opts?) → value (no throw)
 *   json.stringify(value, opts?)           → string | throws SafeJsonError
 *   json.canonical(value, opts?)           → string (sorted keys)
 *   json.validate(value, schema, opts?)    → value | throws
 *                                            (with opts.collectErrors: { ok, value, errors[] })
 *   json.registerFormat(name, validator)   → register a custom format
 *   json.formats                           → built-in format names
 *   json.SafeJsonError                     → error class
 *
 * Validation modes (opts.collectErrors):
 *   - default (throw):    fails loudly on first error — right for trust boundaries
 *                         (HTTP body parse, sealed payload deserialize, config load).
 *                         The throw IS the security signal; HTTP middleware catches
 *                         it and emits a 400 with .path / .code.
 *   - collectErrors:true: returns { ok, value, errors[] } — right for form-style
 *                         bulk validation where the user needs to see every field
 *                         that failed in one round-trip.
 *
 * Defaults:
 *   maxBytes:    1 MiB
 *   maxDepth:    100
 *   allowProto:  false
 *   onCircular:  "throw"
 *
 * Schema dialect (JSON Schema subset):
 *   { type: 'string'|'number'|'integer'|'boolean'|'null'|'array'|'object',
 *     enum: [...],
 *     // string
 *     minLength, maxLength, pattern, format,
 *     // number
 *     minimum, maximum, exclusiveMinimum, exclusiveMaximum,
 *     // array
 *     minItems, maxItems, items: <schema>,
 *     // object
 *     required: [...], properties: { key: <schema>, ... }, additionalProperties: bool
 *   }
 *
 * Schemas are app-developer-supplied (not user-controlled); regex patterns
 * are trusted not to be ReDoS-prone. Format validators in the built-in
 * registry are anchored / bounded.
 */

// ---- Error class ----

var C = require("./constants");
var safeBuffer = require("./safe-buffer");
var safeUrl = require("./safe-url");
var time = require("./time");
var { FrameworkError } = require("./framework-error");

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

var POISONED_KEYS = new Set(["__proto__", "constructor", "prototype"]);

// ---- parse ----

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
  var allowProto = !!opts.allowProto;

  var parsed;
  try {
    parsed = JSON.parse(input, allowProto ? undefined : _stripProtoKeys);
  } catch (e) {
    throw new SafeJsonError("invalid JSON: " + e.message, "json/syntax");
  }

  _walkAndCheck(parsed, 0, maxDepth, allowProto);

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

function parseOrDefault(input, fallback, opts) {
  try { return parse(input, opts); }
  catch (_e) { return fallback; }
}

function _stripProtoKeys(key, value) {
  if (POISONED_KEYS.has(key)) return undefined;
  return value;
}

function _walkAndCheck(value, depth, maxDepth, allowProto) {
  if (depth > maxDepth) {
    throw new SafeJsonError("nesting exceeds maxDepth (" + maxDepth + ")", "json/too-deep");
  }
  if (value === null || typeof value !== "object") return;
  if (Array.isArray(value)) {
    for (var i = 0; i < value.length; i++) _walkAndCheck(value[i], depth + 1, maxDepth, allowProto);
    return;
  }
  if (!allowProto) {
    POISONED_KEYS.forEach(function (k) {
      if (Object.prototype.hasOwnProperty.call(value, k)) delete value[k];
    });
  }
  for (var k in value) {
    if (Object.prototype.hasOwnProperty.call(value, k)) {
      _walkAndCheck(value[k], depth + 1, maxDepth, allowProto);
    }
  }
}

function _typeName(v) {
  if (v === null)        return "null";
  if (Array.isArray(v))  return "array";
  return typeof v;
}

// ---- stringify ----

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
    if (!allowProto && POISONED_KEYS.has(key)) return undefined;
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
        if (!allowProto && POISONED_KEYS.has(k)) continue;
        out[k] = walk(v[k]);
      }
    }
    stack.delete(v);
    return out;
  }

  return walk(value);
}

// ---- canonical ----

function canonical(value, _opts) {
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
      var keys = Object.keys(v).filter(function (k) { return !POISONED_KEYS.has(k); }).sort();
      var pairs = keys.map(function (k) { return JSON.stringify(k) + ":" + ser(v[k]); });
      return "{" + pairs.join(",") + "}";
    }
    throw new SafeJsonError("cannot canonicalize value of type " + typeof v, "json/uncanonical");
  }

  return ser(value);
}

// ---- format registry ----

// Anchored and bounded — nothing here is ReDoS-prone.
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
      if (!/^[0-9a-fA-F]{1,4}$/.test(all[i])) return false;
    }
    return true;
  },
  ip: function (v) { return formats.ipv4(v) || formats.ipv6(v); },
  hex: function (v) { return safeBuffer.isHex(v); },
  // Generic non-empty token: alphanumeric + a few safe punctuation
  slug: function (v) { return typeof v === "string" && /^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(v); },
};

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

module.exports = {
  parse:          parse,
  parseOrDefault: parseOrDefault,
  stringify:      stringify,
  canonical:      canonical,
  validate:       validate,
  registerFormat: registerFormat,
  formats:        formats,
  SafeJsonError:  SafeJsonError,
  DEFAULT_MAX_BYTES:  DEFAULT_MAX_BYTES,
  DEFAULT_MAX_DEPTH:  DEFAULT_MAX_DEPTH,
  ABSOLUTE_MAX_BYTES: ABSOLUTE_MAX_BYTES,
  ABSOLUTE_MAX_DEPTH: ABSOLUTE_MAX_DEPTH,
  POISONED_KEYS:      Array.from(POISONED_KEYS),
};
