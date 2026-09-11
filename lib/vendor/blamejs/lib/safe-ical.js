// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module     b.safeIcal
 * @nav        Parsers
 * @title      Safe iCalendar
 * @order      125
 *
 * @intro
 *   Bounded RFC 5545 iCalendar parser. Walks the content-line grammar
 *   (`BEGIN:VCALENDAR` ... `END:VCALENDAR`) into a JSON AST that the
 *   mail / DAV / scheduling stacks can reason about without giving an
 *   attacker access to the parser's recursion / expansion machinery.
 *
 *   Substrate for the calendar storage protocol (`b.mail.dav`),
 *   delivery-time iTIP processing, and the scheduling primitives that
 *   compose against ical bytes.
 *
 *   Defends the ical4j RRULE-recursion expansion-DoS class ("Outlook
 *   calendar bomb" — a hostile RRULE with unbounded COUNT and
 *   recursive BYxxx expansion can pin a CalDAV server's CPU at 100%
 *   until the request times out). Caps:
 *
 *     - Total bytes (256 KiB strict / 1 MiB balanced / 4 MiB
 *       permissive) — refused before parsing begins.
 *     - BEGIN/END nesting depth (16 / 32 / 64) — refused when a
 *       hostile blob nests VALARM-in-VEVENT-in-VEVENT-in-… past the
 *       cap.
 *     - Total content lines (16k / 65k / 262k) — refused after
 *       line-unfolding when a hostile blob ships gigabytes of
 *       single-property repetitions.
 *     - Per-line bytes after unfolding (8 KiB strict / 32 KiB balanced
 *       / 128 KiB permissive). RFC 5545 §3.1 recommends 75 octets per
 *       unfolded segment but folding is unbounded.
 *     - RRULE COUNT cap (10000 entries) — refused regardless of
 *       profile. The recurrence expander never materializes more
 *       instances than this cap.
 *     - RRULE BYDAY / BYMONTH / BYMONTHDAY / BYHOUR / BYMINUTE /
 *       BYSECOND / BYSETPOS / BYWEEKNO / BYYEARDAY list-length cap
 *       (24 entries) — refused regardless of profile. The recursion
 *       DoS achieves expansion blow-up by stacking long BYxxx lists.
 *
 *   Header-injection / control-char defense: refuses NUL, C0 control
 *   bytes (other than TAB inside QUOTED-PRINTABLE-shaped values), and
 *   DEL (0x7F) inside property values. Defends against downstream
 *   consumers that splice ical fields into HTTP / SMTP / log headers.
 *
 *   Property allowlist: every property name in the AST must either
 *   appear in the RFC 5545 / 5546 / 7986 property registry or carry
 *   the `X-` experimental prefix per §3.8.8.2. Unknown bare property
 *   names are refused regardless of profile — that path has been a
 *   reliable detection bypass on legacy parsers.
 *
 *   The parser is purely functional — no I/O, no async, no side
 *   effects. Operators run it inside `b.workerPool` workers for any
 *   PUT body above an operator-chosen byte threshold.
 *
 *   Explicit non-goals (deferred — operator escape hatch noted):
 *
 *     - **JSCalendar (RFC 8984)** — JSON-native calendar grammar. The
 *       parser ships the AST in a JSON-shaped tree, but full
 *       JSCalendar conversion (timezone resolution, recurrence
 *       expansion to ISO 8601 instances, byday-string → enum) lights
 *       up when an operator requests it. Today's AST gives operators
 *       the raw `RRULE` / `RDATE` / `EXDATE` strings.
 *     - **VTIMEZONE inline composition** — operators reference IANA
 *       tzdb names via `TZID` and let the consuming layer resolve.
 *       Inline VTIMEZONE blocks parse (their components are walked
 *       into the AST) but the parser does not synthesize a missing
 *       VTIMEZONE from `TZID=…`.
 *     - **iTIP / iMIP (RFC 5546 / 6047)** — the SCHEDULE-AGENT /
 *       METHOD vocabulary parses fine; the cross-mail delivery hook
 *       that turns an iTIP message into a calendar update lives in
 *       the mail-server slice.
 *
 * @card
 *   Bounded RFC 5545 iCalendar parser — caps total bytes, nesting
 *   depth, RRULE COUNT and BYxxx list-lengths; refuses NUL / C0 / DEL
 *   inside property values; allowlists property names; defends the
 *   ical4j RRULE-recursion expansion-DoS class (Outlook calendar-bomb).
 */

var C = require("./constants");
var codepointClass = require("./codepoint-class");
var structuredFields = require("./structured-fields");
var { defineClass } = require("./framework-error");
var gateContract = require("./gate-contract");
var pick = require("./pick");

var SafeIcalError = defineClass("SafeIcalError", { alwaysPermanent: true });

var RRULE_MAX_COUNT      = 10000;
var RRULE_MAX_BY_ENTRIES = 24;

var PROFILES = Object.freeze({
  strict: Object.freeze({
    maxBytes:        C.BYTES.kib(256),
    maxLineBytes:    C.BYTES.kib(8),
    maxLines:        16384,
    maxNestingDepth: 16,
    maxComponents:   4096,
    maxPropertiesPerComponent: 256,
  }),
  balanced: Object.freeze({
    maxBytes:        C.BYTES.mib(1),
    maxLineBytes:    C.BYTES.kib(32),
    maxLines:        65536,
    maxNestingDepth: 32,
    maxComponents:   16384,
    maxPropertiesPerComponent: 1024,
  }),
  permissive: Object.freeze({
    maxBytes:        C.BYTES.mib(4),
    maxLineBytes:    C.BYTES.kib(128),
    maxLines:        262144,
    maxNestingDepth: 64,
    maxComponents:   65536,
    maxPropertiesPerComponent: 4096,
  }),
});

var COMPLIANCE_POSTURES = gateContract.ALL_STRICT_POSTURES;

var KNOWN_PROPERTIES = Object.freeze({
  CALSCALE: true, METHOD: true, PRODID: true, VERSION: true,
  ATTACH: true, CATEGORIES: true, CLASS: true, COMMENT: true,
  DESCRIPTION: true, GEO: true, LOCATION: true, "PERCENT-COMPLETE": true,
  PRIORITY: true, RESOURCES: true, STATUS: true, SUMMARY: true,
  COMPLETED: true, DTEND: true, DUE: true, DTSTART: true, DURATION: true,
  FREEBUSY: true, TRANSP: true,
  TZID: true, TZNAME: true, TZOFFSETFROM: true, TZOFFSETTO: true, TZURL: true,
  ATTENDEE: true, CONTACT: true, ORGANIZER: true, "RECURRENCE-ID": true,
  "RELATED-TO": true, URL: true, UID: true,
  EXDATE: true, EXRULE: true, RDATE: true, RRULE: true,
  ACTION: true, REPEAT: true, TRIGGER: true,
  CREATED: true, "DTSTAMP": true, "LAST-MODIFIED": true, SEQUENCE: true,
  "REQUEST-STATUS": true,
  NAME: true, "REFRESH-INTERVAL": true, SOURCE: true, COLOR: true, IMAGE: true,
  CONFERENCE: true,
});

var KNOWN_COMPONENTS = Object.freeze({
  VCALENDAR: true,
  VEVENT: true, VTODO: true, VJOURNAL: true, VFREEBUSY: true,
  VTIMEZONE: true, STANDARD: true, DAYLIGHT: true,
  VALARM: true,
  VAVAILABILITY: true, AVAILABLE: true,
});

/**
 * @primitive b.safeIcal.parse
 * @signature b.safeIcal.parse(text, opts?)
 * @since     0.9.81
 * @status    stable
 * @related   b.safeVcard.parse, b.mail.dav.create
 *
 * Parse RFC 5545 iCalendar text into a JSON AST. Returns
 * `{ vcalendar: { properties: {...}, vevent: [...], vtodo: [...],
 *                 vjournal: [...], vfreebusy: [...], vtimezone: [...] } }`.
 *
 * Throws `SafeIcalError` with codes:
 *   `safe-ical/oversize-bytes` /
 *   `oversize-line-bytes` / `oversize-lines` / `oversize-nesting` /
 *   `oversize-components` / `oversize-properties-per-component` /
 *   `oversize-rrule-count` / `oversize-rrule-by` /
 *   `missing-vcalendar` / `unterminated-component` /
 *   `unknown-property` / `unknown-component` /
 *   `control-char-in-value` / `bad-line` / `bad-input` / `bad-opt`.
 *
 * @opts
 *   profile:           "strict" | "balanced" | "permissive",         // default strict
 *   compliancePosture: "hipaa" | "pci-dss" | "gdpr" | "soc2",        // → strict
 *   extraProperties:   string[],   // operator-extended allowlist
 *   extraComponents:   string[],   // operator-extended allowlist
 *
 * @example
 *   var ast = b.safeIcal.parse(
 *     "BEGIN:VCALENDAR\r\n" +
 *     "VERSION:2.0\r\n" +
 *     "PRODID:-//Example//1.0//EN\r\n" +
 *     "BEGIN:VEVENT\r\n" +
 *     "UID:abc@example.com\r\n" +
 *     "DTSTAMP:20260101T120000Z\r\n" +
 *     "DTSTART:20260101T130000Z\r\n" +
 *     "SUMMARY:Team meeting\r\n" +
 *     "END:VEVENT\r\n" +
 *     "END:VCALENDAR\r\n"
 *   );
 *   ast.vcalendar.vevent[0].properties.SUMMARY[0].value;  // → "Team meeting"
 */
function parse(text, opts) {
  opts = opts || {};
  var caps = _resolveCaps(opts);
  var extraProps = _toSet(opts.extraProperties);
  var extraComps = _toSet(opts.extraComponents);

  if (typeof text !== "string" && !Buffer.isBuffer(text)) {
    throw new SafeIcalError("safe-ical/bad-input",
      "safeIcal.parse: input must be string or Buffer (got " + typeof text + ")");
  }
  var s = typeof text === "string" ? text : text.toString("utf8");
  var byteLen = Buffer.byteLength(s, "utf8");
  if (byteLen > caps.maxBytes) {
    throw new SafeIcalError("safe-ical/oversize-bytes",
      "safeIcal.parse: input " + byteLen + " bytes exceeds maxBytes=" + caps.maxBytes +
      " (calendar-bomb defense)");
  }

  var lines = _unfold(s, caps);

  var ctx = {
    caps:          caps,
    extraProps:    extraProps,
    extraComps:    extraComps,
    componentCount: 0,
  };
  var idx = 0;
  while (idx < lines.length && lines[idx].name !== "BEGIN") idx++;
  if (idx >= lines.length) {
    throw new SafeIcalError("safe-ical/missing-vcalendar",
      "safeIcal.parse: no BEGIN:VCALENDAR line found");
  }
  if (lines[idx].value !== "VCALENDAR") {
    throw new SafeIcalError("safe-ical/missing-vcalendar",
      "safeIcal.parse: first BEGIN line must be VCALENDAR (got '" + lines[idx].value + "')");
  }
  var consumed = _parseComponent(lines, idx, ctx, 0);
  var vcal = consumed.component;
  var vcalendars = [_shapeVcalendar(vcal)];
  var cursor = consumed.nextIdx;
  while (cursor < lines.length) {
    while (cursor < lines.length && lines[cursor].name !== "BEGIN") cursor++;
    if (cursor >= lines.length) break;
    if (lines[cursor].value !== "VCALENDAR") {
      throw new SafeIcalError("safe-ical/missing-vcalendar",
        "safeIcal.parse: BEGIN at line " + (lines[cursor].lineNo || cursor) +
        " must be VCALENDAR (got '" + lines[cursor].value + "')");
    }
    var more = _parseComponent(lines, cursor, ctx, 0);
    vcalendars.push(_shapeVcalendar(more.component));
    cursor = more.nextIdx;
  }
  return vcalendars.length === 1
    ? { vcalendar: vcalendars[0] }
    : { vcalendar: vcalendars[0], vcalendars: vcalendars };
}

function _resolveCaps(opts) {
  var name = "strict";
  if (typeof opts.profile === "string") {
    name = opts.profile;
  } else if (typeof opts.compliancePosture === "string") {
    name = Object.prototype.hasOwnProperty.call(COMPLIANCE_POSTURES, opts.compliancePosture)
      ? COMPLIANCE_POSTURES[opts.compliancePosture] : "strict";
  }
  if (!Object.prototype.hasOwnProperty.call(PROFILES, name)) {
    throw new SafeIcalError("safe-ical/bad-opt",
      "safeIcal.parse: unknown profile '" + name +
      "' (expected strict|balanced|permissive)");
  }
  var caps = PROFILES[name];
  return caps;
}

function _toSet(arr) {
  var set = Object.create(null);
  if (!Array.isArray(arr)) return set;
  for (var i = 0; i < arr.length; i++) {
    if (typeof arr[i] === "string") set[arr[i].toUpperCase()] = true;
  }
  return set;
}

function _unfold(s, caps) {
  var raw = codepointClass.splitLinesAny(s);
  var unfolded = [];
  for (var i = 0; i < raw.length; i++) {
    var line = raw[i];
    if (line.length === 0) {
      continue;
    }
    var firstChar = line.charCodeAt(0);
    if (firstChar === 0x20 || firstChar === 0x09) {
      if (unfolded.length === 0) {
        throw new SafeIcalError("safe-ical/bad-line",
          "safeIcal.parse: continuation line before any content line");
      }
      unfolded[unfolded.length - 1] += line.slice(1);
    } else {
      unfolded.push(line);
    }
    if (unfolded.length > caps.maxLines) {
      throw new SafeIcalError("safe-ical/oversize-lines",
        "safeIcal.parse: line count exceeds maxLines=" + caps.maxLines);
    }
  }

  var parsed = [];
  for (var j = 0; j < unfolded.length; j++) {
    var u = unfolded[j];
    if (Buffer.byteLength(u, "utf8") > caps.maxLineBytes) {
      throw new SafeIcalError("safe-ical/oversize-line-bytes",
        "safeIcal.parse: unfolded line " + (j + 1) + " exceeds maxLineBytes=" + caps.maxLineBytes);
    }
    parsed.push(_parseContentLine(u));
  }
  return parsed;
}

function _parseContentLine(line) {
  var colonIdx = _findUnquotedColon(line);
  if (colonIdx < 0) {
    throw new SafeIcalError("safe-ical/bad-line",
      "safeIcal.parse: content line missing ':' separator: " +
      _preview(line));
  }
  var head = line.slice(0, colonIdx);
  var value = line.slice(colonIdx + 1);

  var ctrlAt = codepointClass.firstControlCharOffset(value);
  if (ctrlAt !== -1) {
    throw new SafeIcalError("safe-ical/control-char-in-value",
      "safeIcal.parse: control char 0x" + value.charCodeAt(ctrlAt).toString(16) +
      " in property value (header-injection defense)");
  }

  var segs = _splitUnquoted(head, ";");
  var name = segs[0].toUpperCase();
  var params = Object.create(null);
  for (var p = 1; p < segs.length; p++) {
    var seg = segs[p];
    var eq = seg.indexOf("=");
    if (eq < 0) {
      throw new SafeIcalError("safe-ical/bad-line",
        "safeIcal.parse: malformed parameter '" + seg + "'");
    }
    var pname = seg.slice(0, eq).toUpperCase();
    var pvalue = seg.slice(eq + 1);
    if (pick.isPoisonedKey(pname)) continue;
    if (params[pname]) {
      params[pname].push(_stripDoubleQuotes(pvalue));
    } else {
      params[pname] = [_stripDoubleQuotes(pvalue)];
    }
  }
  return { name: name, params: params, value: value };
}

function _findUnquotedColon(line) {
  var inQ = false;
  for (var i = 0; i < line.length; i++) {
    var c = line.charCodeAt(i);
    if (c === 0x22) { inQ = !inQ; continue; }
    if (c === 0x3A && !inQ) return i;
  }
  return -1;
}

function _splitUnquoted(s, sep) {
  return structuredFields.splitUnquoted(s, sep);
}

function _stripDoubleQuotes(s) {
  return structuredFields.stripDoubleQuotes(s);
}

function _parseComponent(lines, startIdx, ctx, depth) {
  if (depth > ctx.caps.maxNestingDepth) {
    throw new SafeIcalError("safe-ical/oversize-nesting",
      "safeIcal.parse: nesting depth exceeds maxNestingDepth=" +
      ctx.caps.maxNestingDepth + " (calendar-bomb defense)");
  }
  ctx.componentCount += 1;
  if (ctx.componentCount > ctx.caps.maxComponents) {
    throw new SafeIcalError("safe-ical/oversize-components",
      "safeIcal.parse: component count exceeds maxComponents=" +
      ctx.caps.maxComponents);
  }
  var begin = lines[startIdx];
  if (begin.name !== "BEGIN") {
    throw new SafeIcalError("safe-ical/bad-line",
      "safeIcal.parse: expected BEGIN, got '" + begin.name + "'");
  }
  var compName = begin.value.toUpperCase();
  if (!Object.prototype.hasOwnProperty.call(KNOWN_COMPONENTS, compName) && !ctx.extraComps[compName] &&
      compName.indexOf("X-") !== 0) {
    throw new SafeIcalError("safe-ical/unknown-component",
      "safeIcal.parse: unknown component '" + compName +
      "' (extend via opts.extraComponents or use X- prefix)");
  }

  var properties = Object.create(null);
  var children = [];
  var propertyCount = 0;
  var i = startIdx + 1;
  while (i < lines.length) {
    var ln = lines[i];
    if (ln.name === "BEGIN") {
      var child = _parseComponent(lines, i, ctx, depth + 1);
      children.push(child.component);
      i = child.nextIdx;
      continue;
    }
    if (ln.name === "END") {
      if (ln.value.toUpperCase() !== compName) {
        throw new SafeIcalError("safe-ical/unterminated-component",
          "safeIcal.parse: BEGIN:" + compName + " closed by END:" + ln.value);
      }
      return {
        component: { name: compName, properties: properties, children: children },
        nextIdx:   i + 1,
      };
    }
    var pn = ln.name;
    if (!Object.prototype.hasOwnProperty.call(KNOWN_PROPERTIES, pn) && !ctx.extraProps[pn] && pn.indexOf("X-") !== 0) {
      throw new SafeIcalError("safe-ical/unknown-property",
        "safeIcal.parse: unknown property '" + pn +
        "' (extend via opts.extraProperties or use X- prefix)");
    }
    if (pn === "RRULE" || pn === "EXRULE") {
      _validateRrule(ln.value);
    }
    propertyCount += 1;
    if (propertyCount > ctx.caps.maxPropertiesPerComponent) {
      throw new SafeIcalError("safe-ical/oversize-properties-per-component",
        "safeIcal.parse: property count in " + compName +
        " exceeds maxPropertiesPerComponent=" + ctx.caps.maxPropertiesPerComponent);
    }
    if (pick.isPoisonedKey(pn)) {
      i += 1;
      continue;
    }
    if (!properties[pn]) properties[pn] = [];
    properties[pn].push({ params: ln.params, value: ln.value });
    i += 1;
  }
  throw new SafeIcalError("safe-ical/unterminated-component",
    "safeIcal.parse: BEGIN:" + compName + " never closed (missing END)");
}

function _validateRrule(value) {
  var parts = value.split(";");
  for (var i = 0; i < parts.length; i++) {
    var kv = parts[i].split("=");
    if (kv.length !== 2) continue;
    var key = kv[0].toUpperCase();
    var val = kv[1];
    if (key === "COUNT") {
      var n = parseInt(val, 10);
      if (!isFinite(n) || n < 0 || n > RRULE_MAX_COUNT) {
        throw new SafeIcalError("safe-ical/oversize-rrule-count",
          "safeIcal.parse: RRULE COUNT=" + val + " exceeds cap=" +
          RRULE_MAX_COUNT + " (calendar-bomb defense)");
      }
    } else if (key === "BYDAY" || key === "BYMONTH" || key === "BYMONTHDAY" ||
               key === "BYHOUR" || key === "BYMINUTE" || key === "BYSECOND" ||
               key === "BYSETPOS" || key === "BYWEEKNO" || key === "BYYEARDAY") {
      var entries = val.split(",");
      if (entries.length > RRULE_MAX_BY_ENTRIES) {
        throw new SafeIcalError("safe-ical/oversize-rrule-by",
          "safeIcal.parse: RRULE " + key + " list length " + entries.length +
          " exceeds cap=" + RRULE_MAX_BY_ENTRIES + " (calendar-bomb defense)");
      }
    }
  }
}

function _shapeVcalendar(comp) {
  var out = {
    properties: comp.properties,
    vevent:     [],
    vtodo:      [],
    vjournal:   [],
    vfreebusy:  [],
    vtimezone:  [],
    vavailability: [],
    other:      [],
  };
  for (var i = 0; i < comp.children.length; i++) {
    var ch = comp.children[i];
    var shaped = _shapeComponent(ch);
    switch (ch.name) {
      case "VEVENT":         out.vevent.push(shaped); break;
      case "VTODO":          out.vtodo.push(shaped); break;
      case "VJOURNAL":       out.vjournal.push(shaped); break;
      case "VFREEBUSY":      out.vfreebusy.push(shaped); break;
      case "VTIMEZONE":      out.vtimezone.push(shaped); break;
      case "VAVAILABILITY":  out.vavailability.push(shaped); break;
      default:               out.other.push(shaped); break;
    }
  }
  return out;
}

function _shapeComponent(comp) {
  var out = { name: comp.name, properties: comp.properties, children: [] };
  for (var i = 0; i < comp.children.length; i++) {
    out.children.push(_shapeComponent(comp.children[i]));
  }
  return out;
}

function _preview(s) {
  if (typeof s !== "string") s = String(s);
  return s.length > 64 ? s.slice(0, 64) + "..." : s;
}

module.exports = gateContract.defineParser({
  name:       "ical",
  entry:      parse,
  entryName:  "parse",
  errorClass: SafeIcalError,
  profiles:   PROFILES,
  postures:   COMPLIANCE_POSTURES,
  extra: {
    KNOWN_PROPERTIES: KNOWN_PROPERTIES,
    KNOWN_COMPONENTS: KNOWN_COMPONENTS,
  },
});
