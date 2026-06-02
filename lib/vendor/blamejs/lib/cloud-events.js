"use strict";
/**
 * @module b.cloudEvents
 * @nav    Communication
 * @title  CloudEvents
 *
 * @intro
 *   Produce and consume webhook / pubsub / queue payloads in the
 *   framework-neutral CNCF CloudEvents v1.0 schema
 *   (cloudevents.io/spec/v1.0). The spec is adopted by AWS
 *   EventBridge, Azure Event Grid, Google Eventarc, Knative, Datadog,
 *   and the wider CNCF ecosystem — wrapping outbound events at
 *   `b.webhook` / `b.pubsub` / `b.queue` boundaries lets operators
 *   interop with these consumers without each consumer learning a
 *   bespoke shape.
 *
 *   `wrap` produces a structured-mode envelope from operator-supplied
 *   `source` / `type` / `subject` / `data` (and optional `extensions`),
 *   auto-filling `id` (UUID v4) and `time` (ISO 8601). Buffer payloads
 *   are routed to the `data_base64` field with a default
 *   `application/octet-stream` content-type; non-Buffer payloads land
 *   in `data` with `application/json`. `parse` validates a received
 *   envelope against the §3.1 required-attribute set, refuses unknown
 *   `specversion` values and the illegal `data` + `data_base64`
 *   simultaneous form, decodes base64-mode payloads back to a Buffer,
 *   and surfaces operator-defined extension attributes separately so
 *   consumers can route on them without grepping the envelope.
 *
 *   Extension-attribute names follow the §3.1 naming rules
 *   (lowercase ASCII alnum, 1..20 chars). Names that collide with a
 *   spec attribute are refused.
 *
 * @card
 *   Produce and consume webhook / pubsub / queue payloads in the framework-neutral CNCF CloudEvents v1.0 schema (cloudevents.io/spec/v1.0).
 */

var nodeCrypto = require("node:crypto");
var validateOpts = require("./validate-opts");
var rfc3339 = require("./rfc3339");
var safeJson = require("./safe-json");
var safeBuffer = require("./safe-buffer");
var C = require("./constants");
var codepointClass = require("./codepoint-class");
var { defineClass } = require("./framework-error");

var CloudEventsError = defineClass("CloudEventsError", { alwaysPermanent: true });

var SPECVERSION = "1.0";
var DEFAULT_MAX_BYTES = C.BYTES.mib(1);   // fromJSON / http.decode input cap

// CloudEvents §3.1 — required string attributes.
var REQUIRED_ATTRS = ["id", "source", "specversion", "type"];

// CloudEvents §3.1 — known optional attributes (other strings get
// passed through as extension attributes if they conform to the
// naming rules).
var KNOWN_OPTIONAL_ATTRS = {
  datacontenttype: 1,
  dataschema:      1,
  subject:         1,
  time:            1,
  data:            1,
  data_base64:     1,
};

// CloudEvents §3.1 attribute naming — lowercase letters + digits,
// length 1-20.
var EXT_ATTR_NAME_RE = /^[a-z0-9]{1,20}$/;

function _isoNow() { return new Date().toISOString(); }

function _genId() {
  // RFC 4122 v4 UUID — 16 random bytes with version + variant bits.
  return nodeCrypto.randomUUID();
}

// ---- wrap ----

/**
 * @primitive b.cloudEvents.wrap
 * @signature b.cloudEvents.wrap(opts)
 * @since     0.7.45
 * @status    stable
 * @related   b.cloudEvents.parse, b.webhook.signer, b.pubsub.create
 *
 * Produces a CloudEvents v1.0 structured-mode envelope from
 * `opts.source` + `opts.type` (the only required inputs). `id` is
 * auto-filled with a UUID v4 when absent; `time` is auto-filled with
 * the current ISO 8601 timestamp. Buffer `data` is base64-encoded
 * into `data_base64` with `application/octet-stream`; non-Buffer
 * `data` lands in the `data` attribute with `application/json`.
 * Extension keys must match `[a-z0-9]{1,20}` and must not collide
 * with a spec attribute — both refusals throw `CloudEventsError` at
 * config time.
 *
 * @opts
 *   {
 *     source:           string,         // required; URI-reference per §3.1
 *     type:             string,         // required; reverse-DNS recommended
 *     id?:              string,         // default UUID v4
 *     time?:            string,         // default new Date().toISOString()
 *     subject?:         string,
 *     datacontenttype?: string,         // auto: application/json | application/octet-stream
 *     dataschema?:      string,         // URI of payload schema
 *     data?:            object|Buffer,  // Buffer routes to data_base64
 *     extensions?:      object          // keys [a-z0-9]{1,20}, no spec collisions
 *   }
 *
 * @example
 *   var b = require("blamejs").create();
 *   var ce = b.cloudEvents.wrap({
 *     source:  "/services/orders",
 *     type:    "com.example.order.created",
 *     subject: "order/o-1234",
 *     data:    { id: "o-1234", total: 4250 }
 *   });
 *   ce.specversion;
 *   // → "1.0"
 */
function wrap(opts) {
  validateOpts.requireObject(opts, "cloudEvents.wrap", CloudEventsError);
  validateOpts.requireNonEmptyString(opts.source,
    "cloudEvents.wrap: source", CloudEventsError, "cloud-events/bad-source");
  validateOpts.requireNonEmptyString(opts.type,
    "cloudEvents.wrap: type", CloudEventsError, "cloud-events/bad-type");
  validateOpts.optionalNonEmptyString(opts.id,
    "cloudEvents.wrap: id", CloudEventsError, "cloud-events/bad-id");
  validateOpts.optionalNonEmptyString(opts.subject,
    "cloudEvents.wrap: subject", CloudEventsError, "cloud-events/bad-subject");
  validateOpts.optionalNonEmptyString(opts.time,
    "cloudEvents.wrap: time", CloudEventsError, "cloud-events/bad-time");
  validateOpts.optionalNonEmptyString(opts.datacontenttype,
    "cloudEvents.wrap: datacontenttype", CloudEventsError, "cloud-events/bad-datacontenttype");
  validateOpts.optionalNonEmptyString(opts.dataschema,
    "cloudEvents.wrap: dataschema", CloudEventsError, "cloud-events/bad-dataschema");

  var out = {
    specversion: SPECVERSION,
    id:          opts.id || _genId(),
    source:      opts.source,
    type:        opts.type,
    time:        opts.time || _isoNow(),
  };
  if (opts.subject !== undefined && opts.subject !== null) out.subject = opts.subject;
  if (opts.dataschema !== undefined && opts.dataschema !== null) out.dataschema = opts.dataschema;

  // data — choose JSON vs binary based on Buffer-ness; auto-set
  // datacontenttype when caller doesn't supply one.
  if (opts.data !== undefined) {
    if (Buffer.isBuffer(opts.data)) {
      out.data_base64 = opts.data.toString("base64");
      out.datacontenttype = opts.datacontenttype || "application/octet-stream";
    } else {
      out.data = opts.data;
      out.datacontenttype = opts.datacontenttype || "application/json";
    }
  } else if (opts.datacontenttype) {
    out.datacontenttype = opts.datacontenttype;
  }

  // Extension attributes — operator-defined, must conform to the
  // §3.1 naming rules (lowercase ASCII alnum, 1-20 chars).
  if (opts.extensions !== undefined && opts.extensions !== null) {
    validateOpts.optionalPlainObject(opts.extensions,
      "cloudEvents.wrap: extensions", CloudEventsError, "cloud-events/bad-extensions");
    var extKeys = Object.keys(opts.extensions);
    for (var i = 0; i < extKeys.length; i += 1) {
      var k = extKeys[i];
      // bound BEFORE regex test — k.length > 0 && k.length <= 20
      if (typeof k !== "string" || k.length === 0 || k.length > 20 || !EXT_ATTR_NAME_RE.test(k)) {
        throw new CloudEventsError("cloud-events/bad-extension-name",
          "cloudEvents.wrap: extension '" + k + "' must match [a-z0-9]{1,20}");
      }
      if (REQUIRED_ATTRS.indexOf(k) !== -1 || KNOWN_OPTIONAL_ATTRS[k]) {
        throw new CloudEventsError("cloud-events/extension-conflicts-with-spec",
          "cloudEvents.wrap: extension '" + k + "' conflicts with a spec attribute");
      }
      out[k] = opts.extensions[k];
    }
  }
  return out;
}

// ---- parse ----

/**
 * @primitive b.cloudEvents.parse
 * @signature b.cloudEvents.parse(envelope)
 * @since     0.7.45
 * @status    stable
 * @related   b.cloudEvents.wrap, b.webhook.verifier
 *
 * Validates a received CloudEvents v1.0 envelope and returns a
 * normalized record `{ specversion, id, source, type, time, subject,
 * datacontenttype, dataschema, data, extensions }`. Throws
 * `CloudEventsError` for missing required attributes (§3.1),
 * unsupported `specversion`, the illegal simultaneous `data` +
 * `data_base64` form (§3.1.1), and base64-decoding failures.
 * Buffer-mode payloads (`data_base64`) are decoded back to a
 * `Buffer`; operator-defined extension attributes are surfaced under
 * `.extensions` so routing can branch on them without scanning the
 * envelope.
 *
 * @example
 *   var b = require("blamejs").create();
 *   var record = b.cloudEvents.parse({
 *     specversion: "1.0",
 *     id:          "evt-1",
 *     source:      "/services/orders",
 *     type:        "com.example.order.created",
 *     data:        { id: "o-1234", total: 4250 }
 *   });
 *   record.type;
 *   // → "com.example.order.created"
 */
function parse(envelope) {
  if (!envelope || typeof envelope !== "object" || Array.isArray(envelope)) {
    throw new CloudEventsError("cloud-events/bad-envelope",
      "cloudEvents.parse: envelope must be a plain object");
  }
  for (var i = 0; i < REQUIRED_ATTRS.length; i += 1) {
    var k = REQUIRED_ATTRS[i];
    if (typeof envelope[k] !== "string" || envelope[k].length === 0) {
      throw new CloudEventsError("cloud-events/missing-required",
        "cloudEvents.parse: required attribute '" + k + "' missing or empty (CloudEvents §3.1)");
    }
  }
  if (envelope.specversion !== SPECVERSION) {
    throw new CloudEventsError("cloud-events/unsupported-specversion",
      "cloudEvents.parse: specversion='" + envelope.specversion +
      "' is not supported (this primitive implements CloudEvents 1.0)");
  }
  if (envelope.data !== undefined && envelope.data_base64 !== undefined) {
    throw new CloudEventsError("cloud-events/data-conflict",
      "cloudEvents.parse: envelope has both 'data' and 'data_base64' (CloudEvents §3.1.1)");
  }

  // Decode binary data if the envelope used base64 mode.
  var decodedData = envelope.data;
  if (envelope.data_base64 !== undefined) {
    if (typeof envelope.data_base64 !== "string") {
      throw new CloudEventsError("cloud-events/bad-data-base64",
        "cloudEvents.parse: data_base64 must be a string");
    }
    try { decodedData = Buffer.from(envelope.data_base64, "base64"); }
    catch (e) {
      throw new CloudEventsError("cloud-events/bad-data-base64",
        "cloudEvents.parse: data_base64 decode failed: " + ((e && e.message) || String(e)));
    }
  }

  // Surface extension attributes separately so consumers can route on
  // operator-defined fields without grepping the envelope.
  var extensions = {};
  var keys = Object.keys(envelope);
  for (var j = 0; j < keys.length; j += 1) {
    var key = keys[j];
    if (REQUIRED_ATTRS.indexOf(key) !== -1) continue;
    if (KNOWN_OPTIONAL_ATTRS[key]) continue;
    extensions[key] = envelope[key];
  }

  return {
    specversion:     envelope.specversion,
    id:              envelope.id,
    source:          envelope.source,
    type:            envelope.type,
    time:            envelope.time || null,
    subject:         envelope.subject || null,
    datacontenttype: envelope.datacontenttype || null,
    dataschema:      envelope.dataschema || null,
    data:            decodedData,
    extensions:      extensions,
  };
}

// ---- validate / isValid (non-throwing spec check) ----

var INT_MIN = -2147483648;                                  // CloudEvents Integer type range
var INT_MAX = 2147483647;                                   // CloudEvents Integer type range
// JSON-formatted media type essence (after the parameters are stripped):
// type/json or type/anything+json. Each run is bounded by the single "/"
// separator so the match is linear (no overlapping quantifiers → no
// polynomial backtracking on hostile media-type strings).
var JSON_MEDIA_RE = /^[^/]+\/(?:[^/]+\+)?json$/i;
// Extension name MUST be lowercase ASCII alnum (the §3.1 ≤20 length is a
// SHOULD, so validate enforces only the MUST; wrap is stricter on emit).
var VALIDATE_EXT_NAME_RE = /^[a-z0-9]+$/;

function _isPlainObject(v) { return v !== null && typeof v === "object" && !Array.isArray(v) && !Buffer.isBuffer(v); }
function _isNonEmptyString(v) { return typeof v === "string" && v.length > 0; }
function _isCanonicalBase64(s) { return typeof s === "string" && s.length % 4 === 0 && safeBuffer.BASE64_RE.test(s); }
function _isJsonMedia(ct) {
  if (ct == null) return true;   // absent datacontenttype defaults to application/json
  var essence = String(ct).split(";")[0].trim();   // drop media-type parameters
  return JSON_MEDIA_RE.test(essence);   // allow:regex-no-length-cap — slash-bounded classes, linear match
}

function _extIssue(name, v) {
  if (v === null) return null;
  if (typeof v === "string" || typeof v === "boolean") return null;
  if (typeof v === "number") {
    if (!isFinite(v) || Math.floor(v) !== v) return "extension '" + name + "' must be an integer (CloudEvents has no float type)";
    if (v < INT_MIN || v > INT_MAX) return "extension '" + name + "' integer out of 32-bit range";
    return null;
  }
  return "extension '" + name + "' must be a string, integer, or boolean";
}

/**
 * @primitive b.cloudEvents.validate
 * @signature b.cloudEvents.validate(event)
 * @since     0.12.63
 * @status    stable
 * @related   b.cloudEvents.parse, b.cloudEvents.fromJSON
 *
 * Check an in-memory CloudEvents v1.0 envelope against the §3.1 spec and
 * return an array of <code>{ attribute, message }</code> issues — an empty
 * array means the event is conformant. Unlike <code>parse</code> (which
 * throws and decodes), this never throws, so it suits inspecting events of
 * unknown provenance before deciding what to do with them.
 *
 * @example
 *   b.cloudEvents.validate({ specversion: "1.0", id: "1",
 *     source: "/x", type: "com.example.t" });
 *   // → []
 */
function validate(event) {
  var issues = [];
  function bad(attribute, message) { issues.push({ attribute: attribute, message: message }); }
  if (!_isPlainObject(event)) { bad("", "event must be an object"); return issues; }

  if (event.specversion !== SPECVERSION) bad("specversion", "specversion must be the string \"" + SPECVERSION + "\"");
  if (!_isNonEmptyString(event.id)) bad("id", "id must be a non-empty string");
  if (!_isNonEmptyString(event.source)) bad("source", "source must be a non-empty URI-reference string");
  if (!_isNonEmptyString(event.type)) bad("type", "type must be a non-empty string");

  if (event.datacontenttype != null && !_isNonEmptyString(event.datacontenttype)) bad("datacontenttype", "datacontenttype, if present, must be a non-empty string");
  if (event.dataschema != null && !_isNonEmptyString(event.dataschema)) bad("dataschema", "dataschema, if present, must be a non-empty URI string");
  if (event.subject != null && !_isNonEmptyString(event.subject)) bad("subject", "subject, if present, must be a non-empty string");
  if (event.time != null && !rfc3339.isValidDateTime(event.time)) bad("time", "time, if present, must be an RFC 3339 date-time");

  if (Object.prototype.hasOwnProperty.call(event, "data") && Object.prototype.hasOwnProperty.call(event, "data_base64")) {
    bad("data", "data and data_base64 are mutually exclusive (CloudEvents §3.1.1)");
  }
  if (event.data_base64 != null && !_isCanonicalBase64(event.data_base64)) bad("data_base64", "data_base64 must be canonical RFC 4648 base64");

  Object.keys(event).forEach(function (k) {
    if (REQUIRED_ATTRS.indexOf(k) !== -1 || KNOWN_OPTIONAL_ATTRS[k]) return;
    if (!VALIDATE_EXT_NAME_RE.test(k)) { bad(k, "attribute name must match [a-z0-9]+ (lower-case letters and digits)"); return; }   // allow:regex-no-length-cap — linear class, key bounded by maxBytes
    var ei = _extIssue(k, event[k]);
    if (ei) bad(k, ei);
  });
  return issues;
}

/**
 * @primitive b.cloudEvents.isValid
 * @signature b.cloudEvents.isValid(event)
 * @since     0.12.63
 * @status    stable
 * @related   b.cloudEvents.validate
 *
 * Boolean convenience form of <code>validate</code> — <code>true</code>
 * when the event has zero conformance issues.
 *
 * @example
 *   b.cloudEvents.isValid(evt);   // → true
 */
function isValid(event) { return validate(event).length === 0; }

function _assertValid(event, label) {
  var issues = validate(event);
  if (issues.length) {
    throw new CloudEventsError("cloud-events/invalid",
      label + ": " + issues.map(function (i) { return i.message; }).join("; "));
  }
}

// ---- JSON event format ----

/**
 * @primitive b.cloudEvents.toJSON
 * @signature b.cloudEvents.toJSON(event, opts?)
 * @since     0.12.63
 * @status    stable
 * @related   b.cloudEvents.fromJSON, b.cloudEvents.toJSONBatch
 *
 * Serialize a CloudEvents envelope (as produced by <code>wrap</code>) to a
 * JSON event-format string — media type
 * <code>application/cloudevents+json</code>. The envelope is already in
 * wire shape (JSON <code>data</code> inline, binary as a
 * <code>data_base64</code> string), so this validates it and renders the
 * JSON. Throws <code>CloudEventsError</code> on a non-conformant event.
 *
 * @opts
 *   space:   number | string,   // JSON.stringify indentation (default: none)
 *
 * @example
 *   var json = b.cloudEvents.toJSON(b.cloudEvents.wrap({ source: "/x", type: "t" }));
 */
function toJSON(event, opts) {
  opts = opts || {};
  _assertValid(event, "cloudEvents.toJSON");
  return JSON.stringify(event, null, opts.space);
}

function _coerceInput(input, label, maxBytes) {
  if (!Buffer.isBuffer(input) && typeof input !== "string") {
    throw new CloudEventsError("cloud-events/bad-input", label + ": input must be a string or Buffer");
  }
  try {
    return safeJson.parse(input, { maxBytes: maxBytes });
  } catch (e) {
    if (e && e.code === "json/too-large") throw new CloudEventsError("cloud-events/too-large", label + ": input exceeds maxBytes (" + maxBytes + ")");
    throw new CloudEventsError("cloud-events/bad-json", label + ": body is not valid JSON");
  }
}

/**
 * @primitive b.cloudEvents.fromJSON
 * @signature b.cloudEvents.fromJSON(input, opts?)
 * @since     0.12.63
 * @status    stable
 * @related   b.cloudEvents.toJSON, b.cloudEvents.parse
 *
 * Parse a single JSON event-format document (string or Buffer) into a
 * validated CloudEvents envelope. Untrusted bytes route through the
 * framework's bounded, prototype-pollution-safe JSON reader. The envelope
 * is returned in wire shape (binary stays a <code>data_base64</code>
 * string); call <code>parse</code> instead when you want the
 * Buffer-decoded record. Throws <code>CloudEventsError</code> on malformed
 * or non-conformant input.
 *
 * @opts
 *   maxBytes:   number,   // default: 1 MiB — reject larger inputs
 *
 * @example
 *   var evt = b.cloudEvents.fromJSON(req.rawBody);
 */
function fromJSON(input, opts) {
  opts = opts || {};
  var maxBytes = opts.maxBytes == null ? DEFAULT_MAX_BYTES : opts.maxBytes;
  var obj = _coerceInput(input, "cloudEvents.fromJSON", maxBytes);
  if (!_isPlainObject(obj)) throw new CloudEventsError("cloud-events/invalid", "cloudEvents.fromJSON: event must be a JSON object");
  _assertValid(obj, "cloudEvents.fromJSON");
  return obj;
}

/**
 * @primitive b.cloudEvents.toJSONBatch
 * @signature b.cloudEvents.toJSONBatch(events, opts?)
 * @since     0.12.63
 * @status    stable
 * @related   b.cloudEvents.fromJSONBatch, b.cloudEvents.toJSON
 *
 * Serialize an array of CloudEvents envelopes to the JSON batch format
 * (media type <code>application/cloudevents-batch+json</code>) — a JSON
 * array of events, each rendered as by <code>toJSON</code>. An empty array
 * yields <code>"[]"</code>.
 *
 * @opts
 *   space:   number | string,   // JSON.stringify indentation (default: none)
 *
 * @example
 *   var body = b.cloudEvents.toJSONBatch([evtA, evtB]);
 */
function toJSONBatch(events, opts) {
  opts = opts || {};
  if (!Array.isArray(events)) throw new CloudEventsError("cloud-events/bad-input", "cloudEvents.toJSONBatch: events must be an array");
  events.forEach(function (event, idx) { _assertValid(event, "cloudEvents.toJSONBatch: event[" + idx + "]"); });
  return JSON.stringify(events, null, opts.space);
}

/**
 * @primitive b.cloudEvents.fromJSONBatch
 * @signature b.cloudEvents.fromJSONBatch(input, opts?)
 * @since     0.12.63
 * @status    stable
 * @related   b.cloudEvents.toJSONBatch, b.cloudEvents.fromJSON
 *
 * Parse a JSON batch (a JSON array of events) from a string or Buffer into
 * an array of validated CloudEvents envelopes. Each element is validated as
 * by <code>fromJSON</code>; an empty array is valid. A non-array body,
 * over-size input, or any non-conformant element throws
 * <code>CloudEventsError</code>.
 *
 * @opts
 *   maxBytes:   number,   // default: 1 MiB — reject larger inputs
 *
 * @example
 *   var events = b.cloudEvents.fromJSONBatch(req.rawBody);
 */
function fromJSONBatch(input, opts) {
  opts = opts || {};
  var maxBytes = opts.maxBytes == null ? DEFAULT_MAX_BYTES : opts.maxBytes;
  var arr = _coerceInput(input, "cloudEvents.fromJSONBatch", maxBytes);
  if (!Array.isArray(arr)) throw new CloudEventsError("cloud-events/invalid", "cloudEvents.fromJSONBatch: body must be a JSON array");
  arr.forEach(function (obj, idx) {
    if (!_isPlainObject(obj)) throw new CloudEventsError("cloud-events/invalid", "cloudEvents.fromJSONBatch: event[" + idx + "] must be a JSON object");
    _assertValid(obj, "cloudEvents.fromJSONBatch: event[" + idx + "]");
  });
  return arr;
}

// ---- HTTP protocol binding ----

var STRUCTURED_CT = "application/cloudevents+json; charset=UTF-8";
var BATCH_CT = "application/cloudevents-batch+json; charset=UTF-8";

// Percent-encode a header value: everything outside printable ASCII plus
// the spec-named space / double-quote / percent (HTTP binding §3.1). `s` is
// always the already-stringified value from _headerValueFor.
function _pctEncode(s) {
  var bytes = Buffer.from(s, "utf8");
  var out = "";
  for (var i = 0; i < bytes.length; i += 1) {
    var by = bytes[i];
    if (by < 0x21 || by > 0x7E || by === 0x22 || by === 0x25) {   // printable-ASCII bounds + double-quote and percent (HTTP binding header rule)
      out += "%" + bytes[i].toString(16).toUpperCase().padStart(2, "0");   // 16 is the hex radix
    } else {
      out += String.fromCharCode(by);
    }
  }
  return out;
}
function _pctDecode(s) {
  var bytes = [];
  var i = 0;
  while (i < s.length) {
    // allow:regex-no-length-cap — the slice is a fixed 2-char window
    if (s[i] === "%" && codepointClass.HEX_PAIR_RE.test(s.slice(i + 1, i + 3))) {
      bytes.push(parseInt(s.slice(i + 1, i + 3), 16));   // 16 is the hex radix
      i += 3;
    } else {
      var ch = Buffer.from(s[i], "utf8");
      for (var j = 0; j < ch.length; j += 1) bytes.push(ch[j]);
      i += 1;
    }
  }
  return Buffer.from(bytes).toString("utf8");
}
function _headerValueFor(v) { return typeof v === "boolean" ? (v ? "true" : "false") : String(v); }
function _lowerHeaders(headers) {
  var out = {};
  Object.keys(headers || {}).forEach(function (k) {
    var v = headers[k];
    out[k.toLowerCase()] = Array.isArray(v) ? v.join(",") : v;
  });
  return out;
}

/**
 * @primitive b.cloudEvents.http.encodeBinary
 * @signature b.cloudEvents.http.encodeBinary(event)
 * @since     0.12.63
 * @status    stable
 * @related   b.cloudEvents.http.decode, b.cloudEvents.http.encodeStructured
 *
 * Render a CloudEvents envelope in HTTP <em>binary</em> content mode: each
 * context attribute (and extension) becomes a <code>ce-</code>-prefixed
 * header with a percent-encoded value, <code>datacontenttype</code> maps to
 * the plain <code>Content-Type</code> header (never
 * <code>ce-datacontenttype</code>), and the payload becomes the body.
 * Returns <code>{ headers, body }</code> where <code>body</code> is a
 * Buffer (for <code>data_base64</code> payloads) or a string.
 *
 * @example
 *   var enc = b.cloudEvents.http.encodeBinary(evt);
 *   // enc.headers["ce-id"], enc.headers["content-type"], enc.body
 */
function encodeBinary(event) {
  _assertValid(event, "cloudEvents.http.encodeBinary");
  var headers = {};
  Object.keys(event).forEach(function (k) {
    if (k === "data" || k === "data_base64" || k === "datacontenttype") return;
    if (event[k] === undefined || event[k] === null) return;
    headers["ce-" + k] = _pctEncode(_headerValueFor(event[k]));
  });
  var body;
  if (event.data_base64 != null) {
    body = Buffer.from(event.data_base64, "base64");
  } else if (Object.prototype.hasOwnProperty.call(event, "data")) {
    // JSON-media payloads (including a bare string under application/json or
    // an absent content type, which defaults to JSON) must be JSON-encoded
    // so the body re-parses; a non-JSON media type carries the string as-is.
    if (_isJsonMedia(event.datacontenttype)) body = JSON.stringify(event.data);
    else body = typeof event.data === "string" ? event.data : JSON.stringify(event.data);
  } else body = "";
  if (event.datacontenttype != null) headers["content-type"] = event.datacontenttype;
  else if (_isPlainObject(event.data) || Array.isArray(event.data)) headers["content-type"] = "application/json";
  return { headers: headers, body: body };
}

/**
 * @primitive b.cloudEvents.http.encodeStructured
 * @signature b.cloudEvents.http.encodeStructured(event)
 * @since     0.12.63
 * @status    stable
 * @related   b.cloudEvents.http.decode, b.cloudEvents.http.encodeBinary
 *
 * Render a CloudEvents envelope in HTTP <em>structured</em> content mode:
 * the whole event is serialized via the JSON event format into the body,
 * with <code>Content-Type: application/cloudevents+json</code>. Returns
 * <code>{ headers, body }</code>.
 *
 * @example
 *   var enc = b.cloudEvents.http.encodeStructured(evt);
 */
function encodeStructured(event) {
  return { headers: { "content-type": STRUCTURED_CT }, body: toJSON(event) };
}

/**
 * @primitive b.cloudEvents.http.encodeBatch
 * @signature b.cloudEvents.http.encodeBatch(events)
 * @since     0.12.63
 * @status    stable
 * @related   b.cloudEvents.http.decode, b.cloudEvents.toJSONBatch
 *
 * Render an array of CloudEvents in HTTP <em>batched</em> content mode: the
 * JSON batch format in the body with <code>Content-Type:
 * application/cloudevents-batch+json</code>. Returns
 * <code>{ headers, body }</code>.
 *
 * @example
 *   var enc = b.cloudEvents.http.encodeBatch([evtA, evtB]);
 */
function encodeBatch(events) {
  return { headers: { "content-type": BATCH_CT }, body: toJSONBatch(events) };
}

/**
 * @primitive b.cloudEvents.http.decodeBinary
 * @signature b.cloudEvents.http.decodeBinary(headers, body, opts?)
 * @since     0.12.63
 * @status    stable
 * @related   b.cloudEvents.http.decode, b.cloudEvents.http.encodeBinary
 *
 * Parse an HTTP binary-mode request into a CloudEvents envelope. Headers are
 * matched case-insensitively; each <code>ce-*</code> header is
 * percent-decoded into the matching attribute, <code>Content-Type</code>
 * becomes <code>datacontenttype</code>, and the body becomes the payload
 * (parsed as JSON when the content type is JSON, kept as a
 * <code>data_base64</code> string for opaque bytes). The result is
 * validated. Binary-mode header values are strings, so extension types
 * other than String are not recovered.
 *
 * @opts
 *   maxBytes:   number,   // default: 1 MiB — reject larger bodies
 *
 * @example
 *   var evt = b.cloudEvents.http.decodeBinary(req.headers, req.rawBody);
 */
function decodeBinary(headers, body, opts) {
  opts = opts || {};
  var maxBytes = opts.maxBytes == null ? DEFAULT_MAX_BYTES : opts.maxBytes;
  var h = _lowerHeaders(headers);
  var event = {};
  Object.keys(h).forEach(function (k) {
    if (k.indexOf("ce-") !== 0) return;
    event[k.slice(3)] = _pctDecode(String(h[k]));
  });
  var ct = h["content-type"] != null ? h["content-type"] : null;
  if (ct != null) event.datacontenttype = ct;
  var raw;
  if (body == null) raw = Buffer.alloc(0);
  else if (Buffer.isBuffer(body)) raw = body;
  else if (typeof body === "string") raw = Buffer.from(body, "utf8");
  else throw new CloudEventsError("cloud-events/bad-input", "cloudEvents.http.decodeBinary: body must be a string or Buffer");
  if (raw.length > maxBytes) throw new CloudEventsError("cloud-events/too-large", "cloudEvents.http.decodeBinary: body exceeds maxBytes (" + maxBytes + ")");
  if (raw.length > 0) {
    if (_isJsonMedia(ct)) {
      try { event.data = safeJson.parse(raw, { maxBytes: maxBytes }); }
      catch (_e) { throw new CloudEventsError("cloud-events/bad-json", "cloudEvents.http.decodeBinary: JSON body is not valid JSON"); }
    } else if (typeof ct === "string" && /^text\//i.test(ct)) {
      event.data = raw.toString("utf8");
    } else {
      event.data_base64 = raw.toString("base64");
    }
  }
  _assertValid(event, "cloudEvents.http.decodeBinary");
  return event;
}

/**
 * @primitive b.cloudEvents.http.decode
 * @signature b.cloudEvents.http.decode(headers, body, opts?)
 * @since     0.12.63
 * @status    stable
 * @related   b.cloudEvents.http.decodeBinary, b.cloudEvents.http.encodeStructured
 *
 * Parse an HTTP request into a CloudEvents envelope (or array, for a batch),
 * auto-detecting the content mode exactly as a conformant receiver does: a
 * <code>Content-Type</code> beginning
 * <code>application/cloudevents-batch</code> is batched, one beginning
 * <code>application/cloudevents</code> is structured, and anything else is
 * binary mode. Returns a single envelope for binary/structured modes and an
 * array for batched mode.
 *
 * @opts
 *   maxBytes:   number,   // default: 1 MiB — reject larger bodies
 *
 * @example
 *   var evt = b.cloudEvents.http.decode(req.headers, req.rawBody);
 */
function decode(headers, body, opts) {
  var h = _lowerHeaders(headers);
  var ct = (h["content-type"] != null ? h["content-type"] : "") || "";
  if (/^application\/cloudevents-batch\b/i.test(ct)) return fromJSONBatch(body, opts);
  if (/^application\/cloudevents\b/i.test(ct)) return fromJSON(body, opts);
  return decodeBinary(headers, body, opts);
}

module.exports = {
  wrap:             wrap,
  parse:            parse,
  validate:         validate,
  isValid:          isValid,
  toJSON:           toJSON,
  fromJSON:         fromJSON,
  toJSONBatch:      toJSONBatch,
  fromJSONBatch:    fromJSONBatch,
  http: {
    encodeBinary:     encodeBinary,
    encodeStructured: encodeStructured,
    encodeBatch:      encodeBatch,
    decodeBinary:     decodeBinary,
    decode:           decode,
  },
  SPECVERSION:      SPECVERSION,
  REQUIRED_ATTRS:   REQUIRED_ATTRS,
  CloudEventsError: CloudEventsError,
};
