"use strict";
/**
 * @module     b.safeVcard
 * @nav        Parsers
 * @title      Safe vCard
 * @order      126
 *
 * @intro
 *   Bounded RFC 6350 vCard 4.0 parser. Walks the content-line grammar
 *   (`BEGIN:VCARD` ... `END:VCARD`) into a JSON AST that the CardDAV
 *   stack stores per-tenant. Compatible with the RFC 2425 / 2426
 *   shape that legacy CardDAV clients still emit when they negotiate
 *   `VERSION:3.0`; the parser admits both versions and exposes the
 *   declared `VERSION` field on the resulting card.
 *
 *   Substrate for the contacts storage protocol (`b.mail.dav`).
 *
 *   Defense posture mirrors `b.safeIcal` — the vCard grammar shares
 *   the line-folding + property-parameter shape with iCalendar but
 *   does not carry an RRULE-class amplifier; the equivalent
 *   amplifier here is the `PHOTO` / `LOGO` / `SOUND` / `KEY`
 *   inline-embedded-binary properties which a hostile vCard can
 *   stuff with megabytes of base64 to exhaust storage.
 *
 *   Caps:
 *
 *     - Total bytes (256 KiB strict / 1 MiB balanced / 4 MiB
 *       permissive) — refused before parsing begins.
 *     - PHOTO / LOGO / SOUND / KEY inline-embed bytes (1 MiB strict
 *       / 4 MiB balanced / 16 MiB permissive) — refused when the
 *       declared property value or data: URI body exceeds the cap.
 *     - Per-line bytes after unfolding (8 KiB strict / 32 KiB
 *       balanced / 128 KiB permissive).
 *     - Total cards in a stream (16 strict / 256 balanced / 4096
 *       permissive). RFC 6350 §3.2 permits chained BEGIN:VCARD /
 *       END:VCARD pairs.
 *
 *   Header-injection / control-char defense: refuses NUL, C0 control
 *   bytes (other than TAB), and DEL (0x7F) inside property values.
 *
 *   Property allowlist: every property name must either appear in the
 *   RFC 6350 §6 property registry or carry the `X-` experimental
 *   prefix. Unknown bare names are refused.
 *
 *   Explicit non-goals (deferred — operator escape hatch noted):
 *
 *     - **vCard 4.0 to 3.0 conversion (RFC 6868)** — the parser
 *       exposes both shapes via the declared `VERSION`; round-tripping
 *       between them happens at the CardDAV layer when an old client
 *       requests a 4.0-only card.
 *     - **xCard XML / jCard JSON (RFC 6351 / 7095)** — the JSON AST
 *       this module emits is convertible to jCard but the framework
 *       does not currently ship the canonicalization.
 *     - **Vendor extensions** — operator extends via
 *       `opts.extraProperties` until the relevant slice lands.
 *
 * @card
 *   Bounded RFC 6350 vCard 4.0 parser — caps total bytes, per-card
 *   line bytes, PHOTO / LOGO / SOUND / KEY inline-embed bytes, total
 *   cards in a stream; refuses NUL / C0 / DEL in values; allowlists
 *   property names.
 */

var C = require("./constants");
var { defineClass } = require("./framework-error");

var SafeVcardError = defineClass("SafeVcardError", { alwaysPermanent: true });

var PROFILES = Object.freeze({
  strict: Object.freeze({
    maxBytes:           C.BYTES.kib(256),
    maxLineBytes:       C.BYTES.kib(8),
    maxEmbedBytes:      C.BYTES.mib(1),
    maxCards:           16,                                                                                // allow:raw-byte-literal — card count cap, not byte size
    maxPropertiesPerCard: 256,                                                                             // allow:raw-byte-literal — prop count cap, not byte size
  }),
  balanced: Object.freeze({
    maxBytes:           C.BYTES.mib(1),
    maxLineBytes:       C.BYTES.kib(32),
    maxEmbedBytes:      C.BYTES.mib(4),
    maxCards:           256,                                                                               // allow:raw-byte-literal — card count cap, not byte size
    maxPropertiesPerCard: 1024,                                                                            // allow:raw-byte-literal — prop count cap, not byte size
  }),
  permissive: Object.freeze({
    maxBytes:           C.BYTES.mib(4),
    maxLineBytes:       C.BYTES.kib(128),
    maxEmbedBytes:      C.BYTES.mib(16),
    maxCards:           4096,                                                                              // allow:raw-byte-literal — card count cap, not byte size
    maxPropertiesPerCard: 4096,                                                                            // allow:raw-byte-literal — prop count cap, not byte size
  }),
});

var COMPLIANCE_POSTURES = Object.freeze({
  hipaa:     "strict",
  "pci-dss": "strict",
  gdpr:      "strict",
  soc2:      "strict",
});

// Property-name allowlist per RFC 6350 §6 (vCard 4.0 property
// registry) + RFC 2426 §3 (legacy 3.0 properties retained for
// compatibility) + RFC 6474 (BIRTHPLACE / DEATHPLACE / DEATHDATE) +
// RFC 6715 (XML / EXPERTISE / HOBBY / INTEREST / ORG-DIRECTORY) +
// RFC 6473 (KIND extension).
var KNOWN_PROPERTIES = Object.freeze({
  // General (RFC 6350 §6.1)
  BEGIN: true, END: true, SOURCE: true, KIND: true, XML: true,
  // Identification (RFC 6350 §6.2)
  FN: true, N: true, NICKNAME: true, PHOTO: true, BDAY: true,
  ANNIVERSARY: true, GENDER: true,
  // Delivery addressing (RFC 6350 §6.3)
  ADR: true,
  // Communications (RFC 6350 §6.4)
  TEL: true, EMAIL: true, IMPP: true, LANG: true,
  // Geographical (RFC 6350 §6.5)
  TZ: true, GEO: true,
  // Organizational (RFC 6350 §6.6)
  TITLE: true, ROLE: true, LOGO: true, ORG: true, MEMBER: true,
  RELATED: true,
  // Explanatory (RFC 6350 §6.7)
  CATEGORIES: true, NOTE: true, PRODID: true, REV: true, SOUND: true,
  UID: true, CLIENTPIDMAP: true, URL: true, VERSION: true,
  // Security (RFC 6350 §6.8)
  KEY: true,
  // Calendar (RFC 6350 §6.9)
  FBURL: true, CALADRURI: true, CALURI: true,
  // RFC 6474 — birthplace / deathplace / deathdate
  BIRTHPLACE: true, DEATHPLACE: true, DEATHDATE: true,
  // RFC 6715 — vCard4 extension properties
  EXPERTISE: true, HOBBY: true, INTEREST: true, "ORG-DIRECTORY": true,
  // RFC 2426 legacy — admitted under VERSION:3.0 for round-trip
  // compatibility with older CardDAV clients.
  MAILER: true, AGENT: true, CLASS: true, PROFILE: true, NAME: true,
  LABEL: true, SORT_STRING: true, "SORT-STRING": true,
});

// Properties whose body can carry inline base64 / data: URI bytes and
// therefore enforce `maxEmbedBytes`.
var EMBED_PROPERTIES = Object.freeze({
  PHOTO: true, LOGO: true, SOUND: true, KEY: true,
});

/**
 * @primitive b.safeVcard.parse
 * @signature b.safeVcard.parse(text, opts?)
 * @since     0.9.81
 * @status    stable
 * @related   b.safeIcal.parse, b.mail.dav.create
 *
 * Parse RFC 6350 vCard 4.0 text into a JSON AST. Returns
 * `{ vcards: [{ version, properties: { FN: [{ params, value }], ... } }, ...] }`.
 *
 * Throws `SafeVcardError` with codes:
 *   `safe-vcard/oversize-bytes` /
 *   `oversize-line-bytes` / `oversize-cards` /
 *   `oversize-properties-per-card` / `oversize-embed` /
 *   `missing-vcard` / `unterminated-vcard` /
 *   `unknown-property` / `control-char-in-value` /
 *   `bad-line` / `bad-input` / `bad-opt`.
 *
 * @opts
 *   profile:           "strict" | "balanced" | "permissive",         // default strict
 *   compliancePosture: "hipaa" | "pci-dss" | "gdpr" | "soc2",        // -> strict
 *   extraProperties:   string[],   // operator-extended allowlist
 *
 * @example
 *   var ast = b.safeVcard.parse(
 *     "BEGIN:VCARD\r\n" +
 *     "VERSION:4.0\r\n" +
 *     "FN:Alice Example\r\n" +
 *     "EMAIL:alice@example.com\r\n" +
 *     "TEL;TYPE=cell:+1-555-0100\r\n" +
 *     "END:VCARD\r\n"
 *   );
 *   ast.vcards[0].properties.FN[0].value;     // -> "Alice Example"
 */
function parse(text, opts) {
  opts = opts || {};
  var caps = _resolveCaps(opts);
  var extraProps = _toSet(opts.extraProperties);

  if (typeof text !== "string" && !Buffer.isBuffer(text)) {
    throw new SafeVcardError("safe-vcard/bad-input",
      "safeVcard.parse: input must be string or Buffer (got " + typeof text + ")");
  }
  var s = typeof text === "string" ? text : text.toString("utf8");
  var byteLen = Buffer.byteLength(s, "utf8");
  if (byteLen > caps.maxBytes) {
    throw new SafeVcardError("safe-vcard/oversize-bytes",
      "safeVcard.parse: input " + byteLen + " bytes exceeds maxBytes=" + caps.maxBytes);
  }

  var lines = _unfold(s, caps);
  var vcards = [];
  var idx = 0;
  while (idx < lines.length) {
    // Skip blank or non-content lines until BEGIN:VCARD.
    while (idx < lines.length && lines[idx].name !== "BEGIN") idx++;
    if (idx >= lines.length) break;
    if (lines[idx].value.toUpperCase() !== "VCARD") {
      throw new SafeVcardError("safe-vcard/missing-vcard",
        "safeVcard.parse: BEGIN line at position " + (idx + 1) +
        " is not VCARD (got '" + lines[idx].value + "')");
    }
    var parsed = _parseVcard(lines, idx, caps, extraProps);
    vcards.push(parsed.card);
    idx = parsed.nextIdx;
    if (vcards.length > caps.maxCards) {
      throw new SafeVcardError("safe-vcard/oversize-cards",
        "safeVcard.parse: stream contains more than maxCards=" + caps.maxCards);
    }
  }
  if (vcards.length === 0) {
    throw new SafeVcardError("safe-vcard/missing-vcard",
      "safeVcard.parse: no BEGIN:VCARD found");
  }
  return { vcards: vcards };
}

/**
 * @primitive b.safeVcard.compliancePosture
 * @signature b.safeVcard.compliancePosture(name)
 * @since     0.9.81
 * @status    stable
 * @related   b.safeVcard.parse
 *
 * Map a compliance-posture name to its profile. Returns the profile
 * string for a known posture, `null` for unknown names.
 *
 * @example
 *   b.safeVcard.compliancePosture("hipaa");   // -> "strict"
 *   b.safeVcard.compliancePosture("loose");   // -> null
 */
function compliancePosture(name) {
  return COMPLIANCE_POSTURES[name] || null;
}

// ---- Internal ----

function _resolveCaps(opts) {
  var name = "strict";
  if (typeof opts.profile === "string") {
    name = opts.profile;
  } else if (typeof opts.compliancePosture === "string") {
    name = COMPLIANCE_POSTURES[opts.compliancePosture] || "strict";
  }
  var caps = PROFILES[name];
  if (!caps) {
    throw new SafeVcardError("safe-vcard/bad-opt",
      "safeVcard.parse: unknown profile '" + name +
      "' (expected strict|balanced|permissive)");
  }
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
  // RFC 6350 §3.2 — line unfolding is identical to RFC 5545 §3.1.
  var raw = s.replace(/\r\n?|\n/g, "\n").split("\n");
  var unfolded = [];
  for (var i = 0; i < raw.length; i++) {
    var line = raw[i];
    if (line.length === 0) continue;
    var firstChar = line.charCodeAt(0);
    if (firstChar === 0x20 || firstChar === 0x09) {                                                       // allow:raw-byte-literal — SPACE / HTAB fold markers per RFC 6350 §3.2
      if (unfolded.length === 0) {
        throw new SafeVcardError("safe-vcard/bad-line",
          "safeVcard.parse: continuation line before any content line");
      }
      unfolded[unfolded.length - 1] += line.slice(1);
    } else {
      unfolded.push(line);
    }
  }
  var parsed = [];
  for (var j = 0; j < unfolded.length; j++) {
    var u = unfolded[j];
    if (Buffer.byteLength(u, "utf8") > caps.maxLineBytes) {
      throw new SafeVcardError("safe-vcard/oversize-line-bytes",
        "safeVcard.parse: unfolded line " + (j + 1) +
        " exceeds maxLineBytes=" + caps.maxLineBytes);
    }
    parsed.push(_parseContentLine(u));
  }
  return parsed;
}

function _parseContentLine(line) {
  var colonIdx = _findUnquotedColon(line);
  if (colonIdx < 0) {
    throw new SafeVcardError("safe-vcard/bad-line",
      "safeVcard.parse: content line missing ':' separator: " + _preview(line));
  }
  var head = line.slice(0, colonIdx);
  var value = line.slice(colonIdx + 1);

  for (var k = 0; k < value.length; k++) {
    var cc = value.charCodeAt(k);
    if ((cc < 0x20 && cc !== 0x09) || cc === 0x7F) {                                                      // allow:raw-byte-literal — C0 + DEL refusal
      throw new SafeVcardError("safe-vcard/control-char-in-value",
        "safeVcard.parse: control char 0x" + cc.toString(16) +
        " in property value (header-injection defense)");
    }
  }

  // RFC 6350 §3.3 — property name may be prefixed by an optional
  // group token (group "."). Strip and retain the group.
  var segs = _splitUnquoted(head, ";");
  var nameRaw = segs[0];
  var group = null;
  var dotIdx = nameRaw.indexOf(".");
  if (dotIdx >= 0) {
    group = nameRaw.slice(0, dotIdx);
    nameRaw = nameRaw.slice(dotIdx + 1);
  }
  var name = nameRaw.toUpperCase();
  var params = Object.create(null);
  for (var p = 1; p < segs.length; p++) {
    var seg = segs[p];
    var eq = seg.indexOf("=");
    if (eq < 0) {
      throw new SafeVcardError("safe-vcard/bad-line",
        "safeVcard.parse: malformed parameter '" + seg + "'");
    }
    var pname = seg.slice(0, eq).toUpperCase();
    var pvalue = seg.slice(eq + 1);
    if (pname === "__proto__" || pname === "constructor" || pname === "prototype") continue;
    if (params[pname]) {
      params[pname].push(_stripDoubleQuotes(pvalue));
    } else {
      params[pname] = [_stripDoubleQuotes(pvalue)];
    }
  }
  return { name: name, group: group, params: params, value: value };
}

function _findUnquotedColon(line) {
  var inQ = false;
  for (var i = 0; i < line.length; i++) {
    var c = line.charCodeAt(i);
    if (c === 0x22) { inQ = !inQ; continue; }                                                             // allow:raw-byte-literal — DQUOTE per RFC 6350 §3.3
    if (c === 0x3A && !inQ) return i;                                                                     // allow:raw-byte-literal — colon separator per RFC 6350 §3.3
  }
  return -1;
}

function _splitUnquoted(s, sep) {
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

function _stripDoubleQuotes(s) {
  if (s.length >= 2 && s.charAt(0) === '"' && s.charAt(s.length - 1) === '"') {
    return s.slice(1, -1);
  }
  return s;
}

function _parseVcard(lines, startIdx, caps, extraProps) {
  var properties = Object.create(null);
  var version = null;
  var propertyCount = 0;
  var i = startIdx + 1;
  while (i < lines.length) {
    var ln = lines[i];
    if (ln.name === "END") {
      if (ln.value.toUpperCase() !== "VCARD") {
        throw new SafeVcardError("safe-vcard/unterminated-vcard",
          "safeVcard.parse: BEGIN:VCARD closed by END:" + ln.value);
      }
      return {
        card: { version: version || "4.0", properties: properties },
        nextIdx: i + 1,
      };
    }
    if (ln.name === "BEGIN") {
      throw new SafeVcardError("safe-vcard/bad-line",
        "safeVcard.parse: nested BEGIN inside VCARD (vCard does not support sub-components)");
    }
    var pn = ln.name;
    if (!KNOWN_PROPERTIES[pn] && !extraProps[pn] && pn.indexOf("X-") !== 0) {
      throw new SafeVcardError("safe-vcard/unknown-property",
        "safeVcard.parse: unknown property '" + pn +
        "' (extend via opts.extraProperties or use X- prefix)");
    }
    if (pn === "VERSION") version = ln.value;
    if (EMBED_PROPERTIES[pn]) {
      // RFC 6350 §6.2.4 — PHOTO/LOGO/SOUND/KEY values can be a URI
      // (including data:) or a base64 blob (3.0-style). Compute the
      // byte length of the decoded form when it is data: or pure
      // base64; otherwise apply the raw-string byte length.
      var embedBytes = _embedByteLength(ln.value);
      if (embedBytes > caps.maxEmbedBytes) {
        throw new SafeVcardError("safe-vcard/oversize-embed",
          "safeVcard.parse: " + pn + " embed " + embedBytes +
          " bytes exceeds maxEmbedBytes=" + caps.maxEmbedBytes);
      }
    }
    propertyCount += 1;
    if (propertyCount > caps.maxPropertiesPerCard) {
      throw new SafeVcardError("safe-vcard/oversize-properties-per-card",
        "safeVcard.parse: property count exceeds maxPropertiesPerCard=" +
        caps.maxPropertiesPerCard);
    }
    if (pn === "__proto__" || pn === "constructor" || pn === "prototype") {
      i += 1;
      continue;
    }
    if (!properties[pn]) properties[pn] = [];
    properties[pn].push({
      group:  ln.group,
      params: ln.params,
      value:  ln.value,
    });
    i += 1;
  }
  throw new SafeVcardError("safe-vcard/unterminated-vcard",
    "safeVcard.parse: BEGIN:VCARD never closed (missing END)");
}

function _embedByteLength(value) {
  // data:<mime>;base64,<payload> — decoded bytes are (3/4) * payload
  // length (rounding for padding).
  var dataMatch = /^data:[^;,]*;base64,(.*)$/i.exec(value);
  if (dataMatch) {
    var payload = dataMatch[1].replace(/\s+/g, "");
    return Math.floor(payload.length * 3 / 4);                                                            // allow:raw-byte-literal — base64 3/4 decode ratio per RFC 4648 §4
  }
  // ENCODING=b / ENCODING=BASE64 puts the raw base64 in the value
  // directly (the param is parsed separately upstream; we do not have
  // access here, so check whether the payload is base64-shaped).
  if (/^[A-Za-z0-9+/=\r\n\t ]+$/.test(value) && value.length > 32) {                                      // allow:raw-byte-literal — heuristic threshold for base64 detection
    var compact = value.replace(/\s+/g, "");
    if (compact.length > 0 && compact.length % 4 === 0) {
      return Math.floor(compact.length * 3 / 4);                                                          // allow:raw-byte-literal — base64 3/4 decode ratio per RFC 4648 §4
    }
  }
  return Buffer.byteLength(value, "utf8");
}

function _preview(s) {
  if (typeof s !== "string") s = String(s);
  return s.length > 64 ? s.slice(0, 64) + "..." : s;                                                       // allow:raw-byte-literal — log-preview length cap
}

module.exports = {
  parse:               parse,
  compliancePosture:   compliancePosture,
  PROFILES:            PROFILES,
  COMPLIANCE_POSTURES: COMPLIANCE_POSTURES,
  KNOWN_PROPERTIES:    KNOWN_PROPERTIES,
  EMBED_PROPERTIES:    EMBED_PROPERTIES,
  SafeVcardError:      SafeVcardError,
};
