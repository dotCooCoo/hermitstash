// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
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

var nodeTypes = require("node:util").types;
var C = require("./constants");
var canonicalJson = require("./canonical-json");
var codepointClass = require("./codepoint-class");
var lazyRequire = require("./lazy-require");
var pick = require("./pick");
var safeBuffer = require("./safe-buffer");
var safeUrl = require("./safe-url");
var time = require("./time");
var validateOpts = require("./validate-opts");
var { FrameworkError } = require("./framework-error");
var frameworkError = require("./framework-error");

// Lazy — both pull in the pattern machinery, and safe-json is required early
// in the boot graph. Only touched by a schema that declares a `pattern`.
var regexLinear = lazyRequire(function () { return require("./regex-linear"); });
var guardRegex = lazyRequire(function () { return require("./guard-regex"); });

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

frameworkError.messageFirstFactory(SafeJsonError);

var ABSOLUTE_MAX_BYTES = C.BYTES.mib(64);
var ABSOLUTE_MAX_DEPTH = 1_000;

var IPV6_HEXTET_COUNT = 0x8;
var DEFAULT_MAX_BYTES = C.BYTES.mib(1);
var DEFAULT_MAX_DEPTH = 100;
var DEFAULT_MAX_KEYS = 10_000;
var ABSOLUTE_MAX_KEYS = 1_000_000;

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
 * Nesting is counted on the text before the parse runs, so a document
 * deeper than `maxDepth` is refused as `json/too-deep` whatever its size.
 *
 * Throws `SafeJsonError` with a documented `.code`:
 * `json/too-large` / `json/syntax` / `json/too-deep` /
 * `json/too-many-keys` / `json/wrong-input-type` /
 * `json/type-mismatch` / `json/missing-key` / `json/validation`.
 *
 * An `allowProto` that is not a boolean throws `json/bad-opt`, so the string
 * `"false"` cannot keep `__proto__` as an own key by reading as truthy. Under
 * `refuseProtoMover` a key that names the prototype setter throws
 * `json/proto-key` rather than being dropped. When a `schema` is supplied it is
 * validated too: `json/bad-schema` when the schema is not an object,
 * `json/unknown-format` for a `format` this validator does not implement, and
 * `json/bad-pattern` for a `pattern` that is unsafe to run.
 *
 * @opts
 *   maxBytes:      number,  // default 1 MiB; capped at 64 MiB
 *   maxDepth:      number,  // default 100; capped at 1000
 *   maxKeys:       number,  // default 10 000; capped at 1 000 000
 *   allowProto:    boolean, // default false; keep __proto__/constructor/prototype keys
 *   refuseProtoMover: boolean, // default false; throw json/proto-key on a __proto__ key
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
  _refuseNonBooleanAllowProto(opts.allowProto);
  var allowProto = !!opts.allowProto;
  var refuseProtoMover = !!opts.refuseProtoMover;

  if (_textNestsDeeperThan(input, maxDepth)) {
    throw new SafeJsonError("nesting exceeds maxDepth (" + maxDepth + ")", "json/too-deep");
  }

  var parsed;
  try {
    parsed = JSON.parse(input, refuseProtoMover
      ? (allowProto ? _refuseProtoMoverKey : _refuseMoverStripRest)
      : (allowProto ? undefined : _stripProtoKeys));
  } catch (e) {
    if (e instanceof SafeJsonError) throw e;
    if (e instanceof RangeError) {
      throw new SafeJsonError("nesting exceeds maxDepth (" + maxDepth + ")", "json/too-deep");
    }
    var pos = _positionFromSyntaxError(e && e.message);
    throw new SafeJsonError("invalid JSON syntax" + (pos ? " at position " + pos : ""), "json/syntax");
  }

  _walkAndCheck(parsed, 0, maxDepth, allowProto, maxKeys, refuseProtoMover);

  if (opts.schema) {
    if (opts.collectErrors) {
      var result = validate(parsed, opts.schema, { collectErrors: true });
      return result;
    }
    validate(parsed, opts.schema);
    return parsed;
  }

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
 * @primitive b.safeJson.parseTyped
 * @signature b.safeJson.parseTyped(input, opts)
 * @since     0.20.31
 * @status    stable
 * @related   b.safeJson.parse, b.safeJson.parseOrDefault
 *
 * Parse under the same caps as `parse`, and report a failure as the
 * caller's own error instead of `SafeJsonError`, so a document read at a
 * protocol boundary refuses with the code that boundary documents. The
 * message is `<label>: <the underlying reason>`. `errorClass` is built
 * through its `factory(code, message)` when it has one, and as
 * `new errorClass(code, message)` otherwise.
 *
 * @opts
 *   errorClass: Function, // required — the error class to throw
 *   code:       string,   // required — the code to carry
 *   label:      string,   // message prefix, e.g. "parse: manifest"
 *   maxBytes:   number,   // as b.safeJson.parse
 *   maxDepth:   number,
 *   maxKeys:    number,
 *   allowProto: boolean,
 *   schema:     object,
 *
 * @example
 *   b.safeJson.parseTyped('{"a":1}', {
 *     errorClass: b.backup.BackupManifestError,
 *     code:       "backup-manifest/bad-json",
 *     label:      "parse",
 *   });
 *   // → { a: 1 }
 */
function parseTyped(input, opts) {
  opts = opts || {};
  var errorClass = opts.errorClass;
  if (typeof errorClass !== "function") {
    throw new SafeJsonError("parseTyped: opts.errorClass must be a constructor", "json/bad-opts");
  }
  validateOpts.requireNonEmptyString(opts.code, "parseTyped: opts.code",
    SafeJsonError, "json/bad-opts");
  try {
    return parse(input, opts);
  } catch (e) {
    var message = (opts.label ? opts.label + ": " : "") + ((e && e.message) || String(e));
    if (typeof errorClass.factory === "function") throw errorClass.factory(opts.code, message);
    throw new errorClass(opts.code, message);
  }
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
 * already-decoded value, put through `jsonCopyUnderCap` so that the SAME
 * caps apply to it and the caller is handed the value they were measured
 * against rather than one someone else still holds. This is the recurring
 * "operator hands me a document as a JSON string or a pre-built object" surface
 * (b.openapi / b.asyncapi). Routing it here means a raw `JSON.parse` on operator
 * input — which imposes no size bound — cannot be hand-rolled per consumer. The
 * divergence each consumer needs (its typed error class + codes + a generous
 * document size cap, and whether the proto-poisoning names are keys of its
 * document or a hazard in its input) is carried as data, so there is no
 * per-consumer branch. Both forms answer alike: whichever way the document
 * arrives, the same names survive it.
 *
 * @opts
 *   maxBytes:   number,    // forwarded to parse (default 1 MiB; capped 64 MiB)
 *   maxDepth:   number,    // forwarded to parse
 *   maxKeys:    number,    // members per object, both forms (default 10,000)
 *   allowProto: boolean,   // default false; keep __proto__/constructor/prototype keys
 *   refuseProtoMover: boolean, // default false; throw json/proto-key on a __proto__ key
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
var MEASURE_BYTES_OPTS = Object.freeze({ limit: true, maxDepth: true });

var JSON_COPY_OPTS = Object.freeze({
  maxBytes: true, maxDepth: true, maxKeys: true,
  allowProto: true, refuseProtoMover: true,
});
var JSON_COPY_FLAG_OPTS = Object.freeze({ allowProto: true, refuseProtoMover: true });

function _copyOptsFrom(opts) {
  var out = {};
  Object.keys(JSON_COPY_OPTS).forEach(function (name) {
    if (opts[name] !== undefined) out[name] = opts[name];
  });
  return out;
}

function _notAnObject(label, opts) {
  var message = label + ": input must be a JSON string or a plain object, " +
    "and its JSON form must be an object";
  if (typeof opts.errorClass === "function") return new opts.errorClass(opts.inputCode, message);
  return new SafeJsonError(message, "json/wrong-input-type");
}

function parseStringOrObject(input, opts) {
  opts = opts || {};
  var label = opts.label || "safeJson.parseStringOrObject";
  if (typeof input === "string") {
    var fromText;
    try { fromText = parse(input, opts); }
    catch (e) {
      if (typeof opts.errorClass === "function") {
        if (e && e.code === "json/proto-key") {
          throw new opts.errorClass(opts.inputCode, label + ": " + e.message);
        }
        throw new opts.errorClass(opts.jsonCode, label + ": invalid JSON — " + (e && e.message));
      }
      throw e;
    }
    if (fromText === null || typeof fromText !== "object" || Array.isArray(fromText)) {
      throw _notAnObject(label, opts);
    }
    return fromText;
  }
  if (input !== null && typeof input === "object" &&
      !Buffer.isBuffer(input) && !nodeTypes.isUint8Array(input)) {
    var copy;
    var noForm = false;
    try { copy = jsonCopyUnderCap(input, _copyOptsFrom(opts)); }
    catch (e) {
      if (e && e.code === "json/wrong-input-type") noForm = true;
      else if (typeof opts.errorClass !== "function") throw e;
      else if (e && e.code === "json/proto-key") {
        throw new opts.errorClass(opts.inputCode, label + ": " + e.message);
      } else {
        throw new opts.errorClass(opts.jsonCode, label + ": invalid JSON — " + (e && e.message));
      }
    }
    if (noForm || copy === null || typeof copy !== "object" || Array.isArray(copy)) {
      throw _notAnObject(label, opts);
    }
    return copy;
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

function _refuseNonBooleanAllowProto(value) {
  if (value === undefined || value === null) return;
  if (typeof value !== "boolean") {
    throw new SafeJsonError(
      "allowProto must be a boolean; anything else was read as its truthiness, so the string " +
      "\"false\" kept __proto__ as an own key exactly as true does, got " + typeof value,
      "json/bad-opt");
  }
}

function _refuseProtoMoverKey(key, value) {
  if (pick.movesThePrototype(key)) {
    throw new SafeJsonError("key '" + key + "' names the prototype setter", "json/proto-key");
  }
  return value;
}

function _refuseMoverStripRest(key, value) {
  if (pick.movesThePrototype(key)) {
    throw new SafeJsonError("key '" + key + "' names the prototype setter", "json/proto-key");
  }
  if (pick.isPoisonedKey(key)) return undefined;
  return value;
}

function _walkAndCheck(value, depth, maxDepth, allowProto, maxKeys, refuseProtoMover) {
  if (depth > maxDepth) {
    throw new SafeJsonError("nesting exceeds maxDepth (" + maxDepth + ")", "json/too-deep");
  }
  if (value === null || typeof value !== "object") return;
  if (Array.isArray(value)) {
    for (var i = 0; i < value.length; i++) {
      _walkAndCheck(value[i], depth + 1, maxDepth, allowProto, maxKeys, refuseProtoMover);
    }
    return;
  }
  if (refuseProtoMover) {
    pick.POISONED_KEYS.forEach(function (k) {
      if (pick.movesThePrototype(k) && Object.prototype.hasOwnProperty.call(value, k)) {
        throw new SafeJsonError("key '" + k + "' names the prototype setter", "json/proto-key");
      }
    });
  }
  if (!allowProto) {
    pick.POISONED_KEYS.forEach(function (k) {
      /* c8 ignore next -- defensive second layer: when !allowProto the parse reviver already stripped every poisoned key before this walk, so the own-key delete is never reached from the public API */
      if (Object.prototype.hasOwnProperty.call(value, k)) delete value[k];
    });
  }
  var keyCount = 0;
  for (var k in value) {
    if (Object.prototype.hasOwnProperty.call(value, k)) {
      keyCount += 1;
      if (keyCount > maxKeys) {
        throw new SafeJsonError("object exceeds maxKeys (" + maxKeys + ")", "json/too-many-keys");
      }
      _walkAndCheck(value[k], depth + 1, maxDepth, allowProto, maxKeys, refuseProtoMover);
    }
  }
}

function _typeName(v) {
  if (v === null)        return "null";
  if (Array.isArray(v))  return "array";
  return typeof v;
}

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
 * `onCircular: "throw"` (default) hits a cycle, `json/too-large` when the
 * written form passes `maxBytes`, `json/stringify` carrying the original
 * message where `JSON.stringify` itself throws, as it does on a BigInt, and
 * `json/bad-opt` for an option this primitive does not accept.
 *
 * A value JSON has no form for throws `.code = "json/no-form"`, naming the
 * key, rather than being written as `{}`: a `Map`, `Set`, `WeakMap`,
 * `WeakSet`, `Promise`, `RegExp`, `ArrayBuffer` or `DataView` keeps its data
 * outside its own properties, so there is nothing for JSON to write. A value
 * defining `toJSON` is serialized by it, so a `Date` writes its ISO string.
 *
 * `maxBytes` stops a value whose JSON form runs away as it is being
 * written, which a `toJSON` hook or a getter is free to do however small
 * the value looked beforehand. The count is of the bytes the form
 * actually occupies: a key and a string by their escaped UTF-8 size, a
 * number by its written form, `false` by five and `true` by four, a
 * member `JSON.stringify` drops by nothing inside an object and by the
 * four `null` takes inside an array, a container by its two brackets,
 * and one byte for each separator after the first member. For a value
 * whose JSON form is fixed, which is plain data, that count is exact: a
 * value over the cap is refused where it passes it, a value under it is
 * never refused, and the returned string is never longer than
 * `maxBytes`. A member whose form is decided by code the value carries,
 * a `toJSON` hook, an accessor, or a boxed wrapper with its own
 * `valueOf`, can write something other than what was counted, since the
 * count and the write read it separately. No count can bound that, which
 * is why `b.safeJson.jsonCopyUnderCap` measures the finished string and
 * hands back what that one reading produced. Such a member is counted
 * the least its kind can occupy, so it is never refused early.
 * `refuseProtoMover` throws `json/proto-key` on a `__proto__` key
 * instead of writing it, for a caller that keeps the other reserved
 * names with `allowProto`. A `maxBytes` that is not a non-negative finite number
 * throws `TypeError`, and so does `maxBytes` together with `indent`,
 * whose newline and padding per member grow with a nesting depth the
 * count does not follow.
 *
 * @opts
 *   onCircular:          "throw" | "replace", // default "throw"
 *   circularReplacement: any,                 // default "[Circular]" (used when onCircular === "replace")
 *   allowProto:          boolean,             // default false; keep __proto__/constructor/prototype keys
 *   refuseProtoMover:    boolean,             // default false; throw json/proto-key on a __proto__ key
 *   indent:              number | string,     // forwarded to JSON.stringify
 *   maxBytes:            number,              // refuse with json/too-large once the form runs past this
 *   maxDepth:            number,              // refuse with json/too-deep at this nesting, before recursing further
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
function _leastBytesOf(val, budget) {
  if (typeof val === "string") return _jsonStringBytes(val, budget);
  if (typeof val === "number") return Number.isFinite(val) ? String(val).length : 4;
  if (typeof val === "boolean") return val ? 4 : 5;
  if (val === null) return 4;
  if (typeof val === "object") {
    if (JSON.isRawJSON(val)) return safeBuffer.byteLengthOf(val.rawJSON);
    if (nodeTypes.isStringObject(val))  return 2;
    if (nodeTypes.isNumberObject(val))  return 1;
    if (nodeTypes.isBooleanObject(val)) return 4;
    if (nodeTypes.isBigIntObject(val))  return 1;
    return 2;
  }
  return 1;
}

function _capGiven(label, name, given) {
  if (given === undefined) return false;
  if (typeof given !== "number" || !isFinite(given) || given < 0) {
    throw new TypeError(label + ": " + name + " must be a non-negative finite number");
  }
  return true;
}

function stringify(value, opts) {
  opts = opts || {};
  var onCircular = opts.onCircular || "throw";
  var replacement = opts.circularReplacement !== undefined ? opts.circularReplacement : "[Circular]";
  _refuseNonBooleanAllowProto(opts.allowProto);
  var allowProto = !!opts.allowProto;
  var refuseProtoMover = !!opts.refuseProtoMover;
  var indent     = opts.indent || 0;

  var capped = _capGiven("safeJson.stringify", "maxBytes", opts.maxBytes);
  var bounded = _capGiven("safeJson.stringify", "maxDepth", opts.maxDepth);
  if (capped && indent) {
    throw new TypeError(
      "safeJson.stringify: maxBytes and indent cannot be combined, because the " +
      "newline and padding written per member grow with a nesting depth the count " +
      "does not see, so the cap would not bound the string");
  }
  if ((capped || bounded || refuseProtoMover) && onCircular === "replace") {
    throw new TypeError(
      "safeJson.stringify: onCircular \"replace\" cannot be combined with maxBytes, " +
      "maxDepth or refuseProtoMover, because the cycle-free copy is built before any " +
      "of them is read, so neither the work nor the keys would be bounded by them");
  }

  var input = value;
  if (onCircular === "replace") {
    input = _cleanCycles(value, replacement, allowProto);
  }

  var maxBytes = capped ? opts.maxBytes : 0;
  var maxDepth = bounded ? opts.maxDepth : -1;
  var holders = [];
  var counting = [];
  var written = 0;
  var atRoot = true;

  function replacer(key, val) {
    if (refuseProtoMover && pick.movesThePrototype(key)) {
      throw new SafeJsonError("key '" + key + "' names the prototype setter", "json/proto-key");
    }
    if (!allowProto && pick.isPoisonedKey(key)) return undefined;
    var noForm = canonicalJson._noJsonFormName(val);
    if (noForm !== null) {
      throw new SafeJsonError(
        (key === "" ? "the value" : "'" + key + "'") + " is " + noForm +
        ", which JSON writes as {}; the value would be dropped. Convert it to a " +
        "plain object or array first", "json/no-form");
    }
    var t = typeof val;
    var omitted = t === "undefined" || t === "function" || t === "symbol";
    var reaches = !omitted || Array.isArray(this);
    if (maxDepth >= 0) {
      while (holders.length > 0 && holders[holders.length - 1] !== this) holders.pop();
      if (reaches && holders.length > maxDepth) {
        throw new SafeJsonError(
          "nesting exceeds maxDepth (" + maxDepth + ")", "json/too-deep");
      }
      if (val !== null && typeof val === "object") holders.push(val);
    }
    if (!capped) return val;
    while (counting.length > 0 && counting[counting.length - 1].holder !== this) counting.pop();
    var budget = maxBytes - written;
    if (atRoot) {
      atRoot = false;
      if (!omitted) written += _leastBytesOf(val, budget);
    } else {
      var open = counting.length > 0 ? counting[counting.length - 1] : null;
      var comma = open !== null && open.members > 0 ? 1 : 0;
      if (Array.isArray(this)) {
        written += comma + (omitted ? 4 : _leastBytesOf(val, budget));
        if (open !== null) open.members += 1;
      } else if (!omitted) {
        written += comma + _jsonStringBytes(key, budget) + 1 + _leastBytesOf(val, budget);
        if (open !== null) open.members += 1;
      }
    }
    if (val !== null && typeof val === "object") counting.push({ holder: val, members: 0 });
    if (written > maxBytes) throw _OVER_LIMIT;
    return val;
  }

  try {
    return JSON.stringify(input, replacer, indent);
  } catch (e) {
    if (e === _OVER_LIMIT) {
      throw new SafeJsonError("JSON form exceeds maxBytes (" + maxBytes + ")", "json/too-large");
    }
    if (e && e.isSafeJsonError) throw e;
    if (e instanceof TypeError && codepointClass.containsFolded(e.message, "circular")) {
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
 * A `maxBytes` is measured against the ESCAPED form the caller receives,
 * not the JSON `stringify` wrote: each `<`, `>`, `&`, U+2028 and U+2029
 * becomes six bytes here, so counting before the escape would hand a
 * caller up to six times what it asked for. Because the count that
 * decides is taken after the escape, `maxBytes` composes with `indent`
 * here, where `b.safeJson.stringify` refuses the pair. A value with no
 * JSON form is `undefined`, with or without a cap.
 *
 * @opts
 *   indent:    number | string,   // forwarded to b.safeJson.stringify
 *   allowProto:boolean,           // forwarded
 *   maxBytes:  number,            // refuse with json/too-large once escaped
 *
 * @example
 *   var json = b.safeJson.stringifyForScript({ url: "/a</script>x" });
 *   res.end('<script type="importmap">' + json + '</script>');
 *   // → the "</script>" inside the value is emitted as "</script>"
 */
function stringifyForScript(value, opts) {
  var inner = opts;
  var capped = _capGiven("safeJson.stringifyForScript", "maxBytes", opts && opts.maxBytes);
  if (capped && opts.indent) {
    inner = {};
    Object.keys(opts).forEach(function (k) { if (k !== "maxBytes") inner[k] = opts[k]; });
  }
  var json = stringify(value, inner);
  if (typeof json !== "string") return json;
  var BS = String.fromCharCode(92);
  var SCRIPT_UNSAFE = "<>&" + String.fromCharCode(0x2028) + String.fromCharCode(0x2029);
  var out = "";
  var from = 0;
  for (;;) {
    var at = codepointClass.indexOfAny(json, SCRIPT_UNSAFE, from);
    if (at === -1) break;
    var escaped = json.charCodeAt(at).toString(16);
    while (escaped.length < 4) escaped = "0" + escaped;
    out += json.slice(from, at) + BS + "u" + escaped;
    from = at + 1;
  }
  var escapedForm = from === 0 ? json : out + json.slice(from);
  if (capped && safeBuffer.byteLengthOf(escapedForm) > opts.maxBytes) {
    throw new SafeJsonError(
      "input exceeds maxBytes (" + opts.maxBytes + ") once escaped for a script element",
      "json/too-large");
  }
  return escapedForm;
}

function _textNestsDeeperThan(text, maxDepth) {
  var depth = 0;
  var inString = false;
  var escaped = false;
  for (var i = 0; i < text.length; i += 1) {
    var ch = text.charCodeAt(i);
    if (inString) {
      if (escaped) { escaped = false; continue; }
      if (ch === 0x5c) { escaped = true; continue; }
      if (ch === 0x22) inString = false;
      continue;
    }
    if (ch === 0x22) { inString = true; continue; }
    if (ch === 0x7b || ch === 0x5b) {
      depth += 1;
      if (depth > maxDepth + 1) return true;
      continue;
    }
    if (ch === 0x7d || ch === 0x5d) depth -= 1;
  }
  return false;
}

function _positionFromSyntaxError(message) {
  if (typeof message !== "string") return undefined;
  var at = message.indexOf("position ");
  if (at === -1) return undefined;
  var start = at + "position ".length;
  var end = start;
  while (end < message.length && codepointClass.isAsciiDigit(message.charCodeAt(end))) end += 1;
  return end === start ? undefined : message.slice(start, end);
}

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
        Object.defineProperty(out, k, {
          value: walk(v[k]), enumerable: true, writable: true, configurable: true,
        });
      }
    }
    stack.delete(v);
    return out;
  }

  return walk(value);
}

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
 * A value of a type the scheme cannot represent, such as a function, a symbol
 * or a BigInt, throws `json/uncanonical` naming the type, rather than dropping
 * the member: a canonical form that silently omits part of its input is not a
 * signature input.
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
var EMAIL_MAX_LENGTH = 254;
var UUID_LENGTH = 36;
var UUID_GROUP_LENGTHS = [8, 4, 4, 4, 12];
var ULID_LENGTH = 26;
var ULID_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
var ISO_DATE_LENGTH = 10;
var IPV4_OCTETS = 4;
var IPV4_OCTET_MAX = 255;

var formats = {
  email: function (v) {
    if (typeof v !== "string" || v.length > EMAIL_MAX_LENGTH) return false;
    var at = v.indexOf("@");
    if (at <= 0 || at !== v.lastIndexOf("@")) return false;
    var domain = v.slice(at + 1);
    var dot = domain.indexOf(".");
    if (dot <= 0 || dot === domain.length - 1) return false;
    return codepointClass.firstInRanges(v, codepointClass.WHITESPACE_RANGES) === -1;
  },
  url: function (v) {
    if (typeof v !== "string") return false;
    try {
      var u = safeUrl.parse(v, { allowedProtocols: ["http:", "https:", "ws:", "wss:"] });
      return !!u;
    } catch (_e) { return false; }
  },
  uuid: function (v) {
    if (typeof v !== "string" || v.length !== UUID_LENGTH) return false;
    var at = 0;
    for (var g = 0; g < UUID_GROUP_LENGTHS.length; g += 1) {
      if (g > 0 && v.charAt(at++) !== "-") return false;
      if (!safeBuffer.isHex(v.slice(at, at + UUID_GROUP_LENGTHS[g]), UUID_GROUP_LENGTHS[g])) return false;
      at += UUID_GROUP_LENGTHS[g];
    }
    return true;
  },
  ulid: function (v) {
    if (typeof v !== "string" || v.length !== ULID_LENGTH) return false;
    if (v.charAt(0) < "0" || v.charAt(0) > "7") return false;
    return codepointClass.isRunOf(v.slice(1), ULID_ALPHABET, ULID_LENGTH - 1, ULID_LENGTH - 1);
  },
  "iso8601-date": function (v) {
    if (typeof v !== "string" || v.length !== ISO_DATE_LENGTH) return false;
    if (v.charAt(4) !== "-" || v.charAt(7) !== "-") return false;
    var digits = codepointClass.ASCII_DIGITS;
    if (!codepointClass.isRunOf(v.slice(0, 4), digits, 4, 4)) return false;
    if (!codepointClass.isRunOf(v.slice(5, 7), digits, 2, 2)) return false;
    if (!codepointClass.isRunOf(v.slice(8, 10), digits, 2, 2)) return false;
    var d = new Date(v);
    return !isNaN(d.getTime()) && d.toISOString().slice(0, 10) === v;
  },
  "iso8601-datetime": function (v) {
    if (typeof v !== "string") return false;
    var d = new Date(v);
    return !isNaN(d.getTime()) &&
           time.stripIsoMilliseconds(d.toISOString()) === time.stripIsoMilliseconds(v);
  },
  ipv4: function (v) {
    if (typeof v !== "string") return false;
    var parts = v.split(".");
    if (parts.length !== IPV4_OCTETS) return false;
    for (var i = 0; i < IPV4_OCTETS; i++) {
      if (!codepointClass.isRunOf(parts[i], codepointClass.ASCII_DIGITS, 1, 3)) return false;
      var n = Number(parts[i]);
      if (n < 0 || n > IPV4_OCTET_MAX) return false;
      if (parts[i] !== String(n)) return false;
    }
    return true;
  },
  ipv6: function (v) {
    if (typeof v !== "string" || v.length === 0 || v.length > 45) return false;
    if (v.indexOf("%") !== -1) return false;
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

    var tail = hasDouble ? rightParts : leftParts;
    if (tail.length > 0 && tail[tail.length - 1].indexOf(".") !== -1) {
      if (!formats.ipv4(tail[tail.length - 1])) return false;
      tail.pop();
      tail.push("0", "0");
    }

    var totalParts = leftParts.length + rightParts.length;
    if (hasDouble) {
      if (totalParts >= IPV6_HEXTET_COUNT) return false;
    } else {
      if (totalParts !== IPV6_HEXTET_COUNT) return false;
    }

    var all = leftParts.concat(rightParts);
    for (var i = 0; i < all.length; i++) {
      if (!safeBuffer.isIpv6Hextet(all[i])) return false;
    }
    return true;
  },
  ip: function (v) { return formats.ipv4(v) || formats.ipv6(v); },
  hex: function (v) { return safeBuffer.isHex(v); },
  slug: function (v) { return _isHyphenJoined(v, LOWER_ALNUM); },
};

var LOWER_ALNUM = "0123456789abcdefghijklmnopqrstuvwxyz";

function _isHyphenJoined(text, alphabet) {
  if (typeof text !== "string" || text.length === 0) return false;
  var words = text.split("-");
  for (var i = 0; i < words.length; i += 1) {
    if (!codepointClass.isRunOf(words[i], alphabet, 1)) return false;
  }
  return true;
}

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
  if (typeof name !== "string" || name.length === 0 ||
      name.charAt(0) < "a" || name.charAt(0) > "z" ||
      !codepointClass.isRunOf(name.slice(1), LOWER_ALNUM + "-", 0)) {
    throw new SafeJsonError("format name must match [a-z][a-z0-9-]*: " + name, "json/bad-format-name");
  }
  if (typeof validator !== "function") {
    throw new SafeJsonError("format validator must be a function", "json/bad-format-validator");
  }
  formats[name] = validator;
}

var _PATTERN_CACHE = new Map();
var _PATTERN_CACHE_MAX = 256;

function _patternMatcher(pattern) {
  var isRe = nodeTypes.isRegExp(pattern);
  var source = isRe ? pattern.source : String(pattern);
  var flags = isRe
    ? pattern.flags.split("g").join("").split("y").join("")
    : "";
  var key = flags + "/" + source;
  var cached = _PATTERN_CACHE.get(key);
  if (cached !== undefined) {
    if (cached.error !== null) throw cached.error;
    return cached.matcher;
  }

  var entry = { matcher: null, error: null };
  try {
    entry.matcher = regexLinear().compile(source, flags);
  } catch (_linearRefused) {
    try {
      // eslint-disable-next-line blamejs/no-regex-in-content-safety
      var native = new RegExp(source, flags);
      try {
        guardRegex().assertSafe(native, "schema pattern");
      } catch (unsafe) {
        throw new SafeJsonError("schema pattern is a catastrophic-backtracking " +
                                "shape and cannot be run against untrusted input: " +
                                (unsafe && unsafe.message), "json/bad-pattern");
      }
      entry.matcher = native;
    } catch (e) {
      entry.error = e;
    }
  }
  if (_PATTERN_CACHE.size >= _PATTERN_CACHE_MAX) _PATTERN_CACHE.clear();
  _PATTERN_CACHE.set(key, entry);
  if (entry.error !== null) throw entry.error;
  return entry.matcher;
}

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
  _validateNode(value, schema, "$", function (err) { throw err; });
  return value;
}

function _validateNode(value, schema, path, report) {
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

  if (Array.isArray(schema.enum)) {
    if (schema.enum.indexOf(value) === -1) {
      report(new SafeJsonError(
        path + ": value not in enum (" + JSON.stringify(schema.enum) + ")",
        "json/validation", path
      ));
    }
  }

  if (typeof value === "string") {
    if (schema.minLength != null && value.length < schema.minLength) {
      report(new SafeJsonError(path + ": string length " + value.length + " < minLength " + schema.minLength, "json/validation", path));
    }
    if (schema.maxLength != null && value.length > schema.maxLength) {
      report(new SafeJsonError(path + ": string length " + value.length + " > maxLength " + schema.maxLength, "json/validation", path));
    }
    if (schema.pattern) {
      var matcher;
      try { matcher = _patternMatcher(schema.pattern); }
      catch (e) {
        report(new SafeJsonError(path + ": pattern is unsafe to run (" + e.message + ")",
                                 "json/bad-pattern", path));
        matcher = null;
      }
      if (matcher !== null && !matcher.test(value)) {
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

function _capInt(value, defaultValue, ceiling) {
  if (typeof value !== "number" || !Number.isFinite(value) || value < 0) return defaultValue;
  return Math.min(Math.floor(value), ceiling);
}

var _OVER_LIMIT = { overLimit: true };

var _SHORT_ESCAPES = Object.freeze({ 8: true, 9: true, 10: true, 12: true, 13: true });

function _jsonStringBytes(s, budget) {
  var bytes = 2;
  for (var i = 0; i < s.length; i += 1) {
    if (bytes > budget) return bytes;
    var c = s.charCodeAt(i);
    if (c === 0x22 || c === 0x5c) { bytes += 2; continue; }
    if (c < 0x20) { bytes += _SHORT_ESCAPES[c] ? 2 : 6; continue; }
    if (c < 0x80) { bytes += 1; continue; }
    if (c < 0x800) { bytes += 2; continue; }
    if (c >= 0xd800 && c <= 0xdbff && i + 1 < s.length) {
      var low = s.charCodeAt(i + 1);
      if (low >= 0xdc00 && low <= 0xdfff) { bytes += 4; i += 1; continue; }
    }
    if (c >= 0xd800 && c <= 0xdfff) { bytes += 6; continue; }
    bytes += 3;
  }
  return bytes;
}

function _addBytes(state, n) {
  state.bytes += n;
  if (state.bytes > state.limit) throw _OVER_LIMIT;
}

var _BOOLEAN_VALUE_OF = Boolean.prototype.valueOf;
var _BIGINT_VALUE_OF  = BigInt.prototype.valueOf;

function _unboxPrimitiveWrapper(value) {
  if (nodeTypes.isNumberObject(value))  return +value;
  if (nodeTypes.isStringObject(value))  return String(value);
  if (nodeTypes.isBooleanObject(value)) return _BOOLEAN_VALUE_OF.call(value);
  if (nodeTypes.isBigIntObject(value))  return _BIGINT_VALUE_OF.call(value);
  return undefined;
}

function _resolveForJson(value, key) {
  var t = typeof value;
  if ((value !== null && (t === "object" || t === "function")) || t === "bigint") {
    var hook = value.toJSON;
    if (typeof hook === "function") value = hook.call(value, key);
  }
  if (value !== null && typeof value === "object") {
    var unboxed = _unboxPrimitiveWrapper(value);
    if (unboxed !== undefined) return unboxed;
  }
  return value;
}

function _accumulate(value, state, depth, stack) {
  if (depth > state.maxDepth) {
    throw new SafeJsonError("nesting exceeds maxDepth (" + state.maxDepth + ")", "json/too-deep");
  }
  if (value === null) { _addBytes(state, 4); return true; }

  var t = typeof value;
  if (t === "boolean") { _addBytes(state, value ? 4 : 5); return true; }
  if (t === "number")  { _addBytes(state, Number.isFinite(value) ? String(value).length : 4); return true; }
  if (t === "string")  { _addBytes(state, _jsonStringBytes(value, state.limit - state.bytes)); return true; }
  if (t === "bigint") {
    throw new SafeJsonError("a BigInt has no JSON representation", "json/wrong-input-type");
  }
  if (t !== "object") return false;

  if (JSON.isRawJSON(value)) {
    _addBytes(state, safeBuffer.byteLengthOf(value.rawJSON));
    return true;
  }

  if (stack.indexOf(value) !== -1) {
    throw new SafeJsonError("converting circular structure to JSON", "json/circular");
  }
  stack.push(value);

  var i;
  if (Array.isArray(value)) {
    _addBytes(state, 2);
    var length = value.length;
    for (i = 0; i < length; i += 1) {
      if (i > 0) _addBytes(state, 1);
      if (!_accumulate(_resolveForJson(value[i], String(i)), state, depth + 1, stack)) {
        _addBytes(state, 4);
      }
    }
  } else {
    _addBytes(state, 2);
    var keys = Object.keys(value);
    var written = 0;
    for (i = 0; i < keys.length; i += 1) {
      var member = _resolveForJson(value[keys[i]], keys[i]);
      var mt = typeof member;
      if (mt === "undefined" || mt === "function" || mt === "symbol") continue;
      if (written > 0) _addBytes(state, 1);
      _addBytes(state, _jsonStringBytes(keys[i], state.limit - state.bytes) + 1);
      _accumulate(member, state, depth + 1, stack);
      written += 1;
    }
  }

  stack.pop();
  return true;
}

/**
 * @primitive b.safeJson.measureBytes
 * @signature b.safeJson.measureBytes(value, opts?)
 * @since     0.20.32
 * @status    stable
 * @related   b.safeJson.stringify, b.safeJson.parseStringOrObject
 *
 * Report how many UTF-8 bytes `value` would occupy as JSON, without
 * building the string. Returns `{ bytes, exceeded }`. The walk stops as
 * soon as the running total passes `opts.limit`, so `exceeded: true`
 * means `bytes` is a lower bound rather than the full size.
 *
 * The count follows what `JSON.stringify` would write: `toJSON` is
 * called once per value with the key it sits under, a boxed `Number`,
 * `String`, `Boolean` or `BigInt` is unboxed first, and a member whose
 * value is `undefined`, a function or a symbol is skipped in an object
 * and counted as `null` in an array.
 *
 * Throws `SafeJsonError` with `json/circular` on a cycle,
 * `json/too-deep` past `opts.maxDepth`, `json/wrong-input-type` on a
 * BigInt, matching what `JSON.stringify` refuses, and `json/bad-opts` for an
 * option this primitive does not accept, which names
 * `b.safeJson.jsonCopyUnderCap` for a caller bounding the work rather than the
 * JSON. A `toJSON` hook or a
 * wrapper coercion that throws propagates its own error, as it does
 * through `JSON.stringify`.
 *
 * The number says what the value would serialize to, and a value whose
 * members are read again later can answer differently the second time: a
 * getter, a proxy or a `toJSON` hook is free to. A caller bounding what
 * it will go on to WORK on wants `b.safeJson.jsonCopyUnderCap`, which
 * hands back the value it measured rather than a number about a value
 * someone else still holds.
 *
 * @opts
 *   limit:    number,   // stop counting past this; default 64 MiB, no ceiling
 *   maxDepth: number,   // default 100; capped at 1000
 *
 * @example
 *   b.safeJson.measureBytes({ a: 1 });
 *   // → { bytes: 7, exceeded: false }
 */
function measureBytes(value, opts) {
  opts = opts || {};
  Object.keys(opts).forEach(function (k) {
    if (MEASURE_BYTES_OPTS[k] !== true) {
      throw new SafeJsonError(
        "safeJson.measureBytes: unknown option '" + k + "'. Allowed: " +
        Object.keys(MEASURE_BYTES_OPTS).join(", ") +
        ". A caller bounding the work it is about to do, rather than the JSON " +
        "it is about to write, wants b.safeJson.jsonCopyUnderCap.",
        "json/bad-opts");
    }
  });
  var state = {
    bytes:    0,
    limit:    _capInt(opts.limit, ABSOLUTE_MAX_BYTES, Number.MAX_SAFE_INTEGER),
    maxDepth: _capInt(opts.maxDepth, DEFAULT_MAX_DEPTH, ABSOLUTE_MAX_DEPTH),
  };
  try {
    if (!_accumulate(_resolveForJson(value, ""), state, 0, [])) {
      return { bytes: 0, exceeded: false };
    }
  } catch (e) {
    if (e !== _OVER_LIMIT) throw e;
    return { bytes: state.bytes, exceeded: true };
  }
  return { bytes: state.bytes, exceeded: false };
}

/**
 * @primitive b.safeJson.jsonCopyUnderCap
 * @signature b.safeJson.jsonCopyUnderCap(value, opts?)
 * @since     0.20.32
 * @status    stable
 * @related   b.safeJson.measureBytes, b.safeJson.parseStringOrObject
 *
 * Return the JSON form of `value` as a fresh value, refusing it if that
 * form is larger than `opts.maxBytes`. Serializing and reading back is
 * what makes the answer usable as a cap: every member is read ONCE, by
 * `JSON.stringify`, and the caller is handed what that read produced.
 * The cap is applied twice over one reading of the value: a count as the
 * form is written, so a value that runs away is stopped partway rather
 * than built, and the bytes of the finished string, which is the number
 * the cap names. `maxDepth` is applied to the same pass, so a value
 * nested past it is refused where it is met rather than exhausting the
 * stack on the way down.
 *
 * Measuring a value and then handing on the original does not bound
 * anything, because the two are different objects. A getter, a proxy or
 * a `toJSON` hook answers the measurement and answers the caller
 * separately, and a property the walk skips, whether it is not
 * enumerable, is inherited, or is named so that it sits outside an
 * array's elements, is still one the caller reads by name. Each is a
 * different way to report one method call to a cap and hand ten thousand
 * to a handler, and the list has no end. A copy has no second reading to
 * differ from the first.
 *
 * Proto-poisoning keys are dropped on the way out, as `stringify` drops
 * them, and the value read back is built by `parse`, so its depth, key
 * and byte caps apply to it as they do to a body that arrived as text.
 * `allowProto: true` carries them through both halves instead, for a
 * caller whose own layer judges those names: the copy is then what
 * `JSON.parse` writes for them, an own data property on an object whose
 * prototype is untouched, and the caller refuses or admits each by name.
 *
 * A caller that names no `maxKeys` gets `parse`'s default, so one body
 * is bounded the same way whether it arrives as text or already built. A
 * consumer whose own cap is larger names it, and gets it on both. An
 * unknown option name is refused with `json/bad-opts`, because a
 * misspelled cap would otherwise be the default silently.
 *
 * Throws `SafeJsonError` with `json/too-large` past the cap,
 * `json/too-deep` past `maxDepth`, `json/wrong-input-type` for a value
 * with no JSON form at all, and whatever `stringify` and `parse` refuse
 * besides: `json/circular` on a cycle, `json/stringify` carrying the
 * original message where `JSON.stringify` itself throws, as it does on a
 * BigInt, and `json/syntax` where the round-trip cannot be read back.
 *
 * It accepts only `maxBytes`, `maxDepth`, `maxKeys`, `allowProto` and
 * `refuseProtoMover`; any other key throws `json/bad-opts`. An `allowProto`
 * that is not a boolean throws `json/bad-opt`, a copy whose key count passes
 * `maxKeys` throws `json/too-many-keys`, and under `refuseProtoMover` a key
 * naming the prototype setter throws `json/proto-key`.
 *
 * It validates nothing, because a `schema` is not an option it takes, so
 * `json/bad-schema`, `json/unknown-format`, `json/bad-pattern`,
 * `json/type-mismatch`, `json/missing-key` and `json/validation` cannot arise
 * from a copy. Validate the result separately with `b.safeJson.validate` when
 * the shape matters.
 *
 * @opts
 *   maxBytes:   number,   // default 1 MiB, capped at 64 MiB
 *   maxDepth:   number,   // forwarded to parse
 *   maxKeys:    number,   // members per object, as parse (default 10,000)
 *   allowProto: boolean,  // default false; keep __proto__/constructor/prototype keys
 *   refuseProtoMover: boolean, // default false; throw json/proto-key on a __proto__ key
 *
 * @example
 *   var body = b.safeJson.jsonCopyUnderCap(req.body, { maxBytes: 65536 });
 */
function jsonCopyUnderCap(value, opts) {
  opts = opts || {};
  Object.keys(opts).forEach(function (name) {
    if (JSON_COPY_OPTS[name] !== true) {
      throw new SafeJsonError(
        "safeJson.jsonCopyUnderCap: unknown option '" + name + "'. Allowed: " +
        Object.keys(JSON_COPY_OPTS).join(", "), "json/bad-opts");
    }
    var given = opts[name];
    if (given === undefined || JSON_COPY_FLAG_OPTS[name] === true) return;
    if (typeof given !== "number" || !isFinite(given) || given < 0) {
      throw new TypeError("safeJson.jsonCopyUnderCap: " + name +
        " must be a non-negative finite number, got " + (typeof given) + " " +
        JSON.stringify(given));
    }
  });
  var maxBytes = _capInt(opts.maxBytes, DEFAULT_MAX_BYTES, ABSOLUTE_MAX_BYTES);
  _refuseNonBooleanAllowProto(opts.allowProto);
  var allowProto = !!opts.allowProto;
  var refuseProtoMover = !!opts.refuseProtoMover;
  var text = stringify(value, {
    maxBytes:   maxBytes,
    maxDepth:   _capInt(opts.maxDepth, DEFAULT_MAX_DEPTH, ABSOLUTE_MAX_DEPTH),
    allowProto: allowProto,
    refuseProtoMover: refuseProtoMover,
  });
  if (text === undefined) {
    throw new SafeJsonError("value has no JSON form", "json/wrong-input-type");
  }
  if (safeBuffer.byteLengthOf(text) > maxBytes) {
    throw new SafeJsonError("input exceeds maxBytes (" + maxBytes + ")", "json/too-large");
  }
  return parse(text, {
    maxBytes: maxBytes, maxDepth: opts.maxDepth, maxKeys: opts.maxKeys,
    allowProto: allowProto, refuseProtoMover: refuseProtoMover,
  });
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
  parseTyped:     parseTyped,
  parseStringOrObject: parseStringOrObject,
  measureBytes:   measureBytes,
  jsonCopyUnderCap: jsonCopyUnderCap,
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
