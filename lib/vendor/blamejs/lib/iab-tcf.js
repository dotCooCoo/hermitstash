"use strict";
/**
 * @module b.iabTcf
 * @nav    Compliance
 * @title  IAB TCF
 *
 * @intro
 *   IAB Transparency & Consent Framework v2.3 — TCF string
 *   parse/encode, vendor list lookup, purpose & special-feature
 *   checks.
 *
 *   Required by TCF Policy v2.3 §III.B.5 (CMP MUST signal which
 *   vendors received disclosure regardless of consent state).
 *   Deadline 2026-02-28 is past — Google Ads + every major DSP
 *   rejects v2.2-shaped strings since that date. EU/UK adtech
 *   operators that didn't migrate are losing inventory.
 *
 *   Consent-string format (TCF v2.3 spec, §A): base64url-no-pad of
 *   segments separated by `.`:
 *   `Core | DisclosedVendors | (AllowedVendors) | PublisherTC`.
 *   Core carries cmpVersion=2, version=4 (TCF v2.3),
 *   created/lastUpdated, cmpId, vendorListVersion,
 *   policyVersion=4, special-feature-opts-in, purpose-consents,
 *   purpose-LIs, vendor-consents bitmap, vendor-LIs bitmap,
 *   publisher restrictions. DisclosedVendors is REQUIRED in v2.3.
 *
 *   The framework does NOT bundle the IAB Global Vendor List —
 *   operators fetch the versioned JSON from
 *   https://vendor-list.consensu.org/v3/vendor-list.json and use
 *   `parsed.core.vendorListVersion` to load the matching cache
 *   entry.
 *
 * @card
 *   IAB Transparency & Consent Framework v2.3 — TCF string parse/encode, vendor list lookup, purpose & special-feature checks.
 */
/*
 * Original prose retained:
 *
 * Required by TCF Policy v2.3 §III.B.5 (CMP MUST signal which vendors
 * received disclosure regardless of consent state). Deadline 2026-02-28
 * is past — Google Ads + every major DSP rejects v2.2-shaped strings
 * since that date. EU/UK adtech operators that didn't migrate are
 * losing inventory.
 *
 * Consent-string format (TCF v2.3 spec, §A):
 *   Base64URL-no-pad of segments separated by `.`:
 *     Core | DisclosedVendors | (AllowedVendors) | PublisherTC
 *
 *   Core segment carries: cmpVersion=2, version=4 (TCF v2.3),
 *   created/lastUpdated, cmpId, vendorListVersion, policyVersion=4,
 *   special-feature-opts-in, purpose-consents, purpose-LIs, vendor
 *   consents bitmap, vendor LIs bitmap, publisher restrictions.
 *
 *   DisclosedVendors segment (REQUIRED in v2.3): bitmap of every
 *   vendor disclosed to the user (regardless of consent). v2.2
 *   strings omit this segment entirely.
 *
 * Public API:
 *
 *   iabTcf.parseString(tcString) -> {
 *     core: { version, cmpId, vendorListVersion, policyVersion,
 *             createdAt, lastUpdatedAt, vendorConsents, vendorLIs,
 *             ... },
 *     disclosedVendors: { present, vendorIds: Set<int> } | null,
 *     allowedVendors:   { present, vendorIds: Set<int> } | null,
 *     publisherTC:      { present, ... } | null,
 *     errors:           Array<string>,
 *   }
 *
 *   iabTcf.requireV23Disclosed(tcString) -> void
 *     Throws iabTcf.IabTcfError on:
 *       - missing DisclosedVendors segment (v2.2 string)
 *       - core.version !== 4 (TCF v2.3 = version 4 in the spec
 *         encoding; v2.2 = version 2 or 3 depending on revision —
 *         the framework refuses anything not v=4 under v2.3 posture)
 *       - core.policyVersion !== 4 (TCF Policy v2.3 = policyVersion 4)
 *
 *   iabTcf.checkVendor(parsed, vendorId) -> {
 *     consented: bool,        — vendor id in vendorConsents
 *     legitimate: bool,       — vendor id in vendorLIs
 *     disclosed: bool,        — vendor id in disclosedVendors
 *   }
 *
 * Operator workflow:
 *   var parsed = b.iabTcf.parseString(tcString);
 *   b.iabTcf.requireV23Disclosed(tcString);   // refuses v2.2
 *   var verdict = b.iabTcf.checkVendor(parsed, 755); // Google
 *   if (!verdict.consented && !verdict.legitimate) refuseAdRequest();
 *
 * The framework does NOT bundle the IAB Global Vendor List (it's a
 * versioned JSON published at https://vendor-list.consensu.org/v3/
 * vendor-list.json that operators fetch and refresh themselves).
 * `parsed.core.vendorListVersion` is the version the consent string
 * was signed against — operators load that version from their cache.
 */

var audit = require("./audit");
var bCrypto = require("./crypto");
var numericBounds = require("./numeric-bounds");
var { defineClass } = require("./framework-error");
var IabTcfError = defineClass("IabTcfError", { alwaysPermanent: true });

// TCF v2.3 spec values.
var TCF_V23_CORE_VERSION   = 4;                                                                // TCF spec version, not bytes
var TCF_V23_POLICY_VERSION = 4;                                                                // TCF policy version, not bytes
// SEGMENT_TYPE_CORE = 0 documented but not declared as a const — the
// core segment is identified positionally (segment[0]) not by the
// 3-bit type prefix the secondary segments use.
var SEGMENT_TYPE_DISCLOSED_VENDORS = 1;                                                        // TCF segment-type marker, not bytes
var SEGMENT_TYPE_ALLOWED_VENDORS   = 2;                                                        // TCF segment-type marker, not bytes
var SEGMENT_TYPE_PUBLISHER_TC      = 3;                                                        // TCF segment-type marker, not bytes
var MAX_TC_STRING_BYTES = 64 * 1024;

// base64url decode (no padding) → Buffer.
function _b64urlDecode(s) {
  var padded = s.replace(/-/g, "+").replace(/_/g, "/");
  var pad = padded.length % 4;
  if (pad === 2) padded += "==";
  else if (pad === 3) padded += "=";
  else if (pad === 1) throw IabTcfError.factory("iab-tcf/bad-base64",
    "iabTcf: base64url segment has invalid length");
  return Buffer.from(padded, "base64");
}

// Bit-level reader over a Buffer.
function _bitReader(buf) {
  var bitOffset = 0;
  var totalBits = buf.length * 8;                                                             // bits per byte
  function read(n) {
    if (bitOffset + n > totalBits) {
      throw IabTcfError.factory("iab-tcf/bad-length",
        "iabTcf: read past end of segment (offset=" + bitOffset + " want=" + n + " total=" + totalBits + ")");
    }
    // Accumulate with `* 2`, not `<< 1`: the Created / LastUpdated fields are
    // 36 bits and their deciseconds values exceed 2^31 for any real date, so a
    // 32-bit shift would silently truncate them. `* 2 + bit` stays exact up to
    // 2^53, well above the widest TCF field.
    var v = 0;
    for (var i = 0; i < n; i += 1) {
      var byteIdx = (bitOffset + i) >> 3;
      var bitIdx  = 7 - ((bitOffset + i) & 7);                                                  // high-bit-first ordering
      v = (v * 2) + ((buf[byteIdx] >> bitIdx) & 1);
    }
    bitOffset += n;
    return v;
  }
  function readBitField(n) {
    // Returns Set<int> of 1-based positions where the bit is set.
    var ids = new Set();
    for (var i = 0; i < n; i += 1) {
      if (read(1) === 1) ids.add(i + 1);
    }
    return ids;
  }
  function pos() { return bitOffset; }
  function setPos(n) { bitOffset = n; }
  function remaining() { return totalBits - bitOffset; }
  return { read: read, readBitField: readBitField, pos: pos, setPos: setPos, remaining: remaining, totalBits: totalBits };
}

function _parseCore(buf) {
  var r = _bitReader(buf);
  var version            = r.read(6);                                                          // TCF spec field width, not bytes
  var createdRaw         = r.read(36);                                                         // TCF spec field width
  var lastUpdatedRaw     = r.read(36);                                                         // TCF spec field width
  var cmpId              = r.read(12);                                                         // TCF spec field width
  var cmpVersion         = r.read(12);                                                         // TCF spec field width
  var consentScreen      = r.read(6);                                                          // TCF spec field width
  // ConsentLanguage (12 bits = 2 chars × 6 bits, ASCII A-Z mapped 0-25)
  var lang0 = r.read(6);                                                                       // TCF spec field width
  var lang1 = r.read(6);                                                                       // TCF spec field width
  var consentLanguage = String.fromCharCode(0x41 + lang0) + String.fromCharCode(0x41 + lang1); // ASCII 'A' offset
  var vendorListVersion  = r.read(12);                                                         // TCF spec field width
  var policyVersion      = r.read(6);                                                          // TCF spec field width
  var isServiceSpecific  = r.read(1) === 1;
  var useNonStandardStacks = r.read(1) === 1;
  var specialFeatureOptins = r.readBitField(12);                                               // TCF spec field width
  var purposesConsent      = r.readBitField(24);                                               // TCF spec field width
  var purposesLI           = r.readBitField(24);                                               // TCF spec field width
  var purposeOneTreatment  = r.read(1) === 1;
  var publisherCC          = String.fromCharCode(0x41 + r.read(6)) + String.fromCharCode(0x41 + r.read(6)); // TCF spec field width
  // MaxVendorIdConsent + ranged fields skipped for compactness — the
  // framework's defensive parse only extracts the top-level shape +
  // the vendorConsents/LIs bitmaps when present.
  var vendorConsents = _parseVendorSection(r);
  var vendorLIs      = _parseVendorSection(r);
  var publisherRestrictions = _parsePublisherRestrictions(r);
  return {
    version:               version,
    createdAt:             createdRaw * 100,
    lastUpdatedAt:         lastUpdatedRaw * 100,
    cmpId:                 cmpId,
    cmpVersion:            cmpVersion,
    consentScreen:         consentScreen,
    consentLanguage:       consentLanguage,
    vendorListVersion:     vendorListVersion,
    policyVersion:         policyVersion,
    isServiceSpecific:     isServiceSpecific,
    useNonStandardStacks:  useNonStandardStacks,
    specialFeatureOptins:  specialFeatureOptins,
    purposesConsent:       purposesConsent,
    purposesLI:            purposesLI,
    purposeOneTreatment:   purposeOneTreatment,
    publisherCC:           publisherCC,
    vendorConsents:        vendorConsents,
    vendorLIs:             vendorLIs,
    publisherRestrictions: publisherRestrictions,
  };
}

// Publisher restrictions follow the two core vendor sections:
// NumPubRestrictions (12 bits) then, per restriction, PurposeId (6) +
// RestrictionType (2) + a range list of vendor ids. NumPubRestrictions is
// mandatory even when zero, so a core that ends before it is truncated — the
// reader's bounds check throws rather than treating the gap as "no
// restrictions", which would let a malformed string validate.
function _parsePublisherRestrictions(r) {
  var out = [];
  var num = r.read(12);                                                                         // TCF spec field width
  for (var i = 0; i < num; i += 1) {
    var purposeId       = r.read(6);                                                            // TCF spec field width
    var restrictionType = r.read(2);
    var numEntries      = r.read(12);                                                           // TCF spec field width
    var vendorIds = [];
    for (var e = 0; e < numEntries; e += 1) {
      var isRange       = r.read(1) === 1;
      var startVendorId = r.read(16);                                                           // TCF spec field width
      if (isRange) {
        var endVendorId = r.read(16);                                                           // TCF spec field width
        for (var v = startVendorId; v <= endVendorId; v += 1) vendorIds.push(v);
      } else {
        vendorIds.push(startVendorId);
      }
    }
    out.push({ purposeId: purposeId, restrictionType: restrictionType, vendorIds: vendorIds });
  }
  return out;
}

// PublisherTC segment (type 3): publisher purpose consent + LI bit-fields
// then a custom-purpose count and its two bit-fields.
function _parsePublisherTC(buf) {
  var r = _bitReader(buf);
  r.read(3);                                                                                    // segment-type prefix
  var pubPurposesConsent = r.readBitField(24);                                                  // TCF spec field width
  var pubPurposesLI      = r.readBitField(24);                                                  // TCF spec field width
  var numCustomPurposes  = r.read(6);                                                           // TCF spec field width
  var customConsent      = r.readBitField(numCustomPurposes);
  var customLI           = r.readBitField(numCustomPurposes);
  return {
    present:                      true,
    pubPurposesConsent:           pubPurposesConsent,
    pubPurposesLITransparency:    pubPurposesLI,
    numCustomPurposes:            numCustomPurposes,
    customPurposesConsent:        customConsent,
    customPurposesLITransparency: customLI,
  };
}

// Vendor section: MaxVendorId (16 bits) + IsRangeEncoding (1 bit) +
// either bitmap (MaxVendorId bits) or RangeEntries.
function _parseVendorSection(r) {
  var maxVendorId    = r.read(16);                                                             // TCF spec field width
  var isRangeEncoding = r.read(1) === 1;
  var ids = new Set();
  if (isRangeEncoding) {
    var numEntries = r.read(12);                                                               // TCF spec field width
    for (var i = 0; i < numEntries; i += 1) {
      var isRange = r.read(1) === 1;
      var startVendorId = r.read(16);                                                          // TCF spec field width
      if (isRange) {
        var endVendorId = r.read(16);                                                          // TCF spec field width
        for (var v = startVendorId; v <= endVendorId; v += 1) ids.add(v);
      } else {
        ids.add(startVendorId);
      }
    }
  } else {
    for (var b = 0; b < maxVendorId; b += 1) {
      if (r.read(1) === 1) ids.add(b + 1);
    }
  }
  return { maxVendorId: maxVendorId, ids: ids };
}

// DisclosedVendors / AllowedVendors segments share the same shape:
// SegmentType (3 bits) + MaxVendorId + IsRangeEncoding + section.
function _parseSecondaryVendorSegment(buf, expectedType) {
  var r = _bitReader(buf);
  var segType = r.read(3);                                                                     // TCF spec field width
  if (segType !== expectedType) {
    throw IabTcfError.factory("iab-tcf/bad-segment-type",
      "iabTcf: expected segment type " + expectedType + ", got " + segType);
  }
  return _parseVendorSection(r);
}

/**
 * @primitive b.iabTcf.parseString
 * @signature b.iabTcf.parseString(tcString)
 * @since     0.8.0
 * @status    stable
 * @compliance iab-tcf
 * @related   b.iabTcf.requireV23Disclosed, b.iabTcf.checkVendor
 *
 * Defensively parse a TCF v2.3 consent string (Core + optional
 * DisclosedVendors / AllowedVendors / PublisherTC segments).
 * Refuses non-string input, refuses payloads above 64 KiB, and
 * caps every bit-field to spec-declared widths. Returns a
 * structured object; per-segment decode failures land in
 * `errors[]` instead of throwing so a partial parse still serves.
 *
 * @example
 *   var parsed = b.iabTcf.parseString("CPXxRfAPXxRfAAfKABENB-CgAP_AAH_AAA");
 *   parsed.core.version;
 *   // → 4
 *   parsed.errors;
 *   // → []
 */
function parseString(tcString) {
  if (typeof tcString !== "string" || tcString.length === 0) {
    throw IabTcfError.factory("iab-tcf/bad-input",
      "iabTcf.parseString: tcString must be a non-empty string");
  }
  if (tcString.length > MAX_TC_STRING_BYTES) {
    throw IabTcfError.factory("iab-tcf/input-too-large",
      "iabTcf.parseString: tcString exceeds " + MAX_TC_STRING_BYTES + " bytes");
  }
  var segments = tcString.split(".");
  var coreBuf;
  try { coreBuf = _b64urlDecode(segments[0]); }
  catch (e) {
    throw IabTcfError.factory("iab-tcf/bad-core",
      "iabTcf.parseString: core segment base64url decode failed: " + e.message);
  }
  var core = _parseCore(coreBuf);

  var disclosedVendors = null;
  var allowedVendors   = null;
  var publisherTC      = null;
  var errors           = [];

  for (var i = 1; i < segments.length; i += 1) {
    var segBuf;
    try { segBuf = _b64urlDecode(segments[i]); }
    catch (e) {
      errors.push("segment[" + i + "] base64 decode: " + e.message);
      continue;
    }
    if (segBuf.length === 0) continue;
    var segType = (segBuf[0] >> 5) & 0x07;                                                     // TCF segment-type lives in top 3 bits
    try {
      if (segType === SEGMENT_TYPE_DISCLOSED_VENDORS) {
        disclosedVendors = { present: true, vendorIds: _parseSecondaryVendorSegment(segBuf, SEGMENT_TYPE_DISCLOSED_VENDORS).ids };
      } else if (segType === SEGMENT_TYPE_ALLOWED_VENDORS) {
        allowedVendors = { present: true, vendorIds: _parseSecondaryVendorSegment(segBuf, SEGMENT_TYPE_ALLOWED_VENDORS).ids };
      } else if (segType === SEGMENT_TYPE_PUBLISHER_TC) {
        publisherTC = _parsePublisherTC(segBuf);
      } else {
        errors.push("segment[" + i + "] unknown type: " + segType);
      }
    } catch (e) {
      errors.push("segment[" + i + "] parse: " + e.message);
    }
  }

  return {
    core:             core,
    disclosedVendors: disclosedVendors,
    allowedVendors:   allowedVendors,
    publisherTC:      publisherTC,
    errors:           errors,
  };
}

/**
 * @primitive b.iabTcf.requireV23Disclosed
 * @signature b.iabTcf.requireV23Disclosed(tcString, opts)
 * @since     0.8.0
 * @status    stable
 * @compliance iab-tcf
 * @related   b.iabTcf.parseString, b.iabTcf.checkVendor
 *
 * Hard gate the operator wires upstream of every ad-bidder
 * forward. Throws `IabTcfError` when the core/policy version is
 * not 4 (i.e. a v2.2 string), when the DisclosedVendors segment
 * is absent (mandatory since 2026-02-28 per TCF Policy v2.3
 * §III.B.5), or when base64url decoding fails. Emits
 * `iabtcf.refused` / `iabtcf.accepted` to the audit chain so the
 * regulator-facing record exists per request.
 *
 * @opts
 *   audit: boolean,   // default true — emit accept/refuse audit events
 *
 * @example
 *   try {
 *     var parsed = b.iabTcf.requireV23Disclosed("CPXxRfAPXxRfAAfKABENB-CgAP_AAH_AAA");
 *     parsed.disclosedVendors.present;
 *     // → true
 *   } catch (e) {
 *     // refuse the ad request
 *   }
 */
function requireV23Disclosed(tcString, opts) {
  opts = opts || {};
  var auditOn = opts.audit !== false;
  var parsed;
  try { parsed = parseString(tcString); }
  catch (e) {
    if (auditOn) {
      audit.safeEmit({
        action:   "iabtcf.refused",
        outcome:  "denied",
        reason:   "parse_failure",
        metadata: { error: e.message },
      });
    }
    throw e;
  }
  if (parsed.core.version !== TCF_V23_CORE_VERSION) {
    if (auditOn) {
      audit.safeEmit({
        action:   "iabtcf.refused",
        outcome:  "denied",
        reason:   "wrong_core_version",
        metadata: { coreVersion: parsed.core.version, required: TCF_V23_CORE_VERSION },
      });
    }
    throw IabTcfError.factory("iab-tcf/wrong-core-version",
      "iabTcf: core version " + parsed.core.version + " not v2.3 (required " +
      TCF_V23_CORE_VERSION + ")");
  }
  if (parsed.core.policyVersion !== TCF_V23_POLICY_VERSION) {
    if (auditOn) {
      audit.safeEmit({
        action:   "iabtcf.refused",
        outcome:  "denied",
        reason:   "wrong_policy_version",
        metadata: { policyVersion: parsed.core.policyVersion, required: TCF_V23_POLICY_VERSION },
      });
    }
    throw IabTcfError.factory("iab-tcf/wrong-policy-version",
      "iabTcf: policy version " + parsed.core.policyVersion + " not v2.3 (required " +
      TCF_V23_POLICY_VERSION + ")");
  }
  if (!parsed.disclosedVendors || !parsed.disclosedVendors.present) {
    if (auditOn) {
      audit.safeEmit({
        action:   "iabtcf.refused",
        outcome:  "denied",
        reason:   "missing_disclosed_vendors",
        metadata: {},
      });
    }
    throw IabTcfError.factory("iab-tcf/missing-disclosed-vendors",
      "iabTcf: TC string lacks DisclosedVendors segment (TCF v2.3 §III.B.5 — REQUIRED since 2026-02-28)");
  }
  if (auditOn) {
    audit.safeEmit({
      action:   "iabtcf.accepted",
      outcome:  "success",
      metadata: {
        cmpId:               parsed.core.cmpId,
        vendorListVersion:   parsed.core.vendorListVersion,
        disclosedVendorCount: parsed.disclosedVendors.vendorIds.size,
      },
    });
  }
  return parsed;
}

/**
 * @primitive b.iabTcf.checkVendor
 * @signature b.iabTcf.checkVendor(parsed, vendorId)
 * @since     0.8.0
 * @status    stable
 * @compliance iab-tcf
 * @related   b.iabTcf.parseString, b.iabTcf.requireV23Disclosed
 *
 * Lookup a vendor id in a parsed TCF object. Returns three flags:
 * `consented` (vendor in `vendorConsents`), `legitimate` (vendor
 * in `vendorLIs`), `disclosed` (vendor in DisclosedVendors).
 * Throws `IabTcfError` for malformed `parsed` or non-positive
 * vendorId.
 *
 * @example
 *   var parsed = b.iabTcf.parseString("CPXxRfAPXxRfAAfKABENB-CgAP_AAH_AAA");
 *   var verdict = b.iabTcf.checkVendor(parsed, 755);
 *   verdict.consented;
 *   // → false
 *   verdict.disclosed;
 *   // → false
 */
function checkVendor(parsed, vendorId) {
  if (!parsed || !parsed.core) {
    throw IabTcfError.factory("iab-tcf/bad-parsed",
      "iabTcf.checkVendor: parsed object required (call parseString first)");
  }
  if (typeof vendorId !== "number" || !isFinite(vendorId) || vendorId < 1 ||
      Math.floor(vendorId) !== vendorId) {
    throw IabTcfError.factory("iab-tcf/bad-vendor-id",
      "iabTcf.checkVendor: vendorId must be a positive integer");
  }
  return {
    consented:   parsed.core.vendorConsents.ids.has(vendorId),
    legitimate:  parsed.core.vendorLIs.ids.has(vendorId),
    disclosed:   parsed.disclosedVendors && parsed.disclosedVendors.vendorIds.has(vendorId) || false,
  };
}

// ---- encode ----------------------------------------------------------------

// Accept a Set, an array, or a parsed `{ ids: Set }` / `{ vendorIds: Set }`
// section as an id collection, and return a sorted unique array of positive
// integers.
function _idArray(x) {
  var src = x;
  if (x && typeof x === "object" && !Array.isArray(x) && !(x instanceof Set)) {
    src = x.ids != null ? x.ids : x.vendorIds;
  }
  var list = src instanceof Set ? Array.from(src) : (Array.isArray(src) ? src : []);
  var seen = Object.create(null);
  var out = [];
  list.forEach(function (id) {
    if (!numericBounds.isPositiveFiniteInt(id)) {
      throw IabTcfError.factory("iab-tcf/bad-value", "iabTcf.encode: vendor/purpose ids must be positive integers, got " + id);
    }
    if (!seen[id]) { seen[id] = 1; out.push(id); }
  });
  out.sort(function (a, b) { return a - b; });
  return out;
}

// Collapse a sorted unique id array into [start, end] runs for range encoding.
function _idRuns(ids) {
  var runs = [];
  for (var i = 0; i < ids.length; i += 1) {
    var start = ids[i];
    var end = start;
    while (i + 1 < ids.length && ids[i + 1] === end + 1) { end = ids[i + 1]; i += 1; }
    runs.push([start, end]);
  }
  return runs;
}

function _decisec(t) {
  var ms = t instanceof Date ? t.getTime() : (t == null ? Date.now() : Number(t));
  if (!isFinite(ms) || ms < 0) throw IabTcfError.factory("iab-tcf/bad-value", "iabTcf.encode: timestamp must be a Date or non-negative epoch-ms");
  return Math.round(ms / 100);
}

// Bit writer mirroring _bitReader: bits are packed high-bit-first, then the
// stream is right-padded to a whole number of bytes (byte-oriented base64url,
// matching the reference CMP encoders and this module's own reader).
function _bitWriter() {
  var bits = "";
  function writeInt(v, n) {
    if (!numericBounds.isNonNegativeFiniteInt(v)) throw IabTcfError.factory("iab-tcf/bad-value", "iabTcf.encode: expected a non-negative integer, got " + v);
    if (v >= Math.pow(2, n)) throw IabTcfError.factory("iab-tcf/value-overflow", "iabTcf.encode: " + v + " does not fit in " + n + " bits");
    bits += v.toString(2).padStart(n, "0");
  }
  function writeBool(flag) { bits += flag ? "1" : "0"; }
  function writeBitField(ids, n) {
    var set = Object.create(null);
    _idArray(ids).forEach(function (id) { set[id] = 1; });
    for (var i = 1; i <= n; i += 1) writeBool(set[i] === 1);
  }
  function writeVendorSection(ids) {
    var clean = _idArray(ids);
    var maxVendorId = clean.length ? clean[clean.length - 1] : 0;
    writeInt(maxVendorId, 16);                                                                  // TCF spec field width
    if (maxVendorId === 0) { writeBool(false); return; }
    var runs = _idRuns(clean);
    var rangeBits = 1 + 12;                                                                     // TCF spec field width
    runs.forEach(function (run) { rangeBits += 1 + 16 + (run[0] === run[1] ? 0 : 16); });       // TCF spec field width
    var bitfieldBits = 1 + maxVendorId;
    if (rangeBits < bitfieldBits) {
      writeBool(true);
      writeInt(runs.length, 12);                                                                // TCF spec field width
      runs.forEach(function (run) {
        if (run[0] === run[1]) { writeBool(false); writeInt(run[0], 16); }                      // TCF spec field width
        else { writeBool(true); writeInt(run[0], 16); writeInt(run[1], 16); }                   // TCF spec field width
      });
    } else {
      writeBool(false);
      writeBitField(clean, maxVendorId);
    }
  }
  function toBuffer() {
    var padded = bits + "0".repeat((8 - (bits.length % 8)) % 8);                                // pad to whole bytes
    var byteLen = padded.length / 8;                                                            // bits per byte
    var out = Buffer.alloc(byteLen);
    for (var i = 0; i < byteLen; i += 1) out[i] = parseInt(padded.slice(i * 8, i * 8 + 8), 2);  // bits per byte
    return out;
  }
  return { writeInt: writeInt, writeBool: writeBool, writeBitField: writeBitField, writeVendorSection: writeVendorSection, toBuffer: toBuffer };
}

function _b64urlEncode(buf) {
  return bCrypto.toBase64Url(buf);
}

function _writeLetters(w, s, label) {
  var str = String(s).toUpperCase();
  if (str.length !== 2) throw IabTcfError.factory("iab-tcf/bad-value", "iabTcf.encode: " + label + " must be a 2-letter code, got '" + s + "'");
  for (var i = 0; i < 2; i += 1) {
    var v = str.charCodeAt(i) - 0x41;                                                           // ASCII 'A' offset
    if (v < 0 || v > 25) throw IabTcfError.factory("iab-tcf/bad-value", "iabTcf.encode: '" + str.charAt(i) + "' is not an A-Z letter");
    w.writeInt(v, 6);                                                                           // TCF spec field width
  }
}

function _encodePublisherTC(pub) {
  var w = _bitWriter();
  w.writeInt(SEGMENT_TYPE_PUBLISHER_TC, 3);                                                     // segment-type prefix
  w.writeBitField(pub.pubPurposesConsent || [], 24);                                            // TCF spec field width
  w.writeBitField(pub.pubPurposesLITransparency || [], 24);                                     // TCF spec field width
  var custom = _idArray(pub.customPurposesConsent || []);
  var customLI = _idArray(pub.customPurposesLITransparency || []);
  var n = pub.numCustomPurposes != null
    ? pub.numCustomPurposes
    : Math.max(custom.length ? custom[custom.length - 1] : 0, customLI.length ? customLI[customLI.length - 1] : 0);
  w.writeInt(n, 6);                                                                             // TCF spec field width
  w.writeBitField(custom, n);
  w.writeBitField(customLI, n);
  return _b64urlEncode(w.toBuffer());
}

/**
 * @primitive b.iabTcf.encode
 * @signature b.iabTcf.encode(obj)
 * @since     0.13.1
 * @status    stable
 * @compliance iab-tcf
 * @related   b.iabTcf.parseString, b.iabTcf.isValid
 *
 * Serialise a TCF object — in the shape `parseString` returns — back into a
 * TC string. Vendor and purpose collections may be `Set`s, arrays of ids, or
 * the parsed `{ ids }` / `{ vendorIds }` sections. Vendor sections are written
 * with whichever of the bit-field and range forms is smaller, matching the
 * reference CMP encoders, so a parsed string round-trips to an equivalent
 * signal. Pass `disclosedVendors` / `allowedVendors` / `publisherTC` to append
 * those segments. Throws `IabTcfError` on a value that does not fit its field.
 *
 * @example
 *   var s = b.iabTcf.encode({
 *     core: { version: 2, cmpId: 5, vendorListVersion: 100, consentLanguage: "EN",
 *             purposesConsent: [1, 2, 3], vendorConsents: [1, 28, 100], publisherCC: "DE" },
 *     disclosedVendors: [1, 28, 100],
 *   });
 */
function encode(obj) {
  if (!obj || typeof obj !== "object" || !obj.core || typeof obj.core !== "object") {
    throw IabTcfError.factory("iab-tcf/bad-input", "iabTcf.encode: obj must have a 'core' object");
  }
  var c = obj.core;
  var w = _bitWriter();
  w.writeInt(c.version != null ? c.version : TCF_V23_CORE_VERSION, 6);                          // TCF spec field width
  w.writeInt(_decisec(c.createdAt), 36);                                                        // TCF spec field width
  w.writeInt(_decisec(c.lastUpdatedAt != null ? c.lastUpdatedAt : c.createdAt), 36);            // TCF spec field width
  w.writeInt(c.cmpId || 0, 12);                                                                 // TCF spec field width
  w.writeInt(c.cmpVersion || 0, 12);                                                            // TCF spec field width
  w.writeInt(c.consentScreen || 0, 6);                                                          // TCF spec field width
  _writeLetters(w, c.consentLanguage || "EN", "consentLanguage");
  w.writeInt(c.vendorListVersion || 0, 12);                                                     // TCF spec field width
  w.writeInt(c.policyVersion != null ? c.policyVersion : TCF_V23_POLICY_VERSION, 6);            // TCF spec field width
  w.writeBool(c.isServiceSpecific !== false);
  w.writeBool(c.useNonStandardStacks === true);
  w.writeBitField(c.specialFeatureOptins || [], 12);                                            // TCF spec field width
  w.writeBitField(c.purposesConsent || [], 24);                                                 // TCF spec field width
  w.writeBitField(c.purposesLI || [], 24);                                                      // TCF spec field width
  w.writeBool(c.purposeOneTreatment === true);
  _writeLetters(w, c.publisherCC || "AA", "publisherCC");
  w.writeVendorSection(c.vendorConsents || []);
  w.writeVendorSection(c.vendorLIs || []);
  var restrictions = c.publisherRestrictions || [];
  w.writeInt(restrictions.length, 12);                                                          // TCF spec field width
  restrictions.forEach(function (pr) {
    w.writeInt(pr.purposeId, 6);                                                                // TCF spec field width
    w.writeInt(typeof pr.restrictionType === "number" ? pr.restrictionType : 0, 2);
    var runs = _idRuns(_idArray(pr.vendorIds || []));
    w.writeInt(runs.length, 12);                                                                // TCF spec field width
    runs.forEach(function (run) {
      if (run[0] === run[1]) { w.writeBool(false); w.writeInt(run[0], 16); }                    // TCF spec field width
      else { w.writeBool(true); w.writeInt(run[0], 16); w.writeInt(run[1], 16); }               // TCF spec field width
    });
  });
  var segs = [_b64urlEncode(w.toBuffer())];

  if (obj.disclosedVendors != null) {
    var dw = _bitWriter();
    dw.writeInt(SEGMENT_TYPE_DISCLOSED_VENDORS, 3);                                              // segment-type prefix
    dw.writeVendorSection(obj.disclosedVendors);
    segs.push(_b64urlEncode(dw.toBuffer()));
  }
  if (obj.allowedVendors != null) {
    var aw = _bitWriter();
    aw.writeInt(SEGMENT_TYPE_ALLOWED_VENDORS, 3);                                                // segment-type prefix
    aw.writeVendorSection(obj.allowedVendors);
    segs.push(_b64urlEncode(aw.toBuffer()));
  }
  if (obj.publisherTC != null && obj.publisherTC.present !== false) {
    segs.push(_encodePublisherTC(obj.publisherTC));
  }
  return segs.join(".");
}

/**
 * @primitive b.iabTcf.isValid
 * @signature b.iabTcf.isValid(tcString)
 * @since     0.13.1
 * @status    stable
 * @compliance iab-tcf
 * @related   b.iabTcf.parseString
 *
 * Return `true` if the string parses as a well-formed TCF Core segment,
 * `false` otherwise. A total predicate — never throws. Note this checks
 * structural validity only; use `requireV23Disclosed` for the v2.3 policy gate.
 *
 * @example
 *   b.iabTcf.isValid("CQSbk4AQSbk4ANwAAAENAwCgAAAAAAAAAAYgACPAAAAA");  // → true
 *   b.iabTcf.isValid("nonsense");                                      // → false
 */
function isValid(tcString) {
  try { parseString(tcString); return true; } catch (_e) { return false; }
}

module.exports = {
  parseString:           parseString,
  encode:                encode,
  isValid:               isValid,
  requireV23Disclosed:   requireV23Disclosed,
  checkVendor:           checkVendor,
  IabTcfError:           IabTcfError,
  TCF_V23_CORE_VERSION:  TCF_V23_CORE_VERSION,
  TCF_V23_POLICY_VERSION: TCF_V23_POLICY_VERSION,
};
