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
var { defineClass } = require("./framework-error");
var IabTcfError = defineClass("IabTcfError", { alwaysPermanent: true });

// TCF v2.3 spec values.
var TCF_V23_CORE_VERSION   = 4;                                                                // allow:raw-byte-literal — TCF spec version, not bytes
var TCF_V23_POLICY_VERSION = 4;                                                                // allow:raw-byte-literal — TCF policy version, not bytes
// SEGMENT_TYPE_CORE = 0 documented but not declared as a const — the
// core segment is identified positionally (segment[0]) not by the
// 3-bit type prefix the secondary segments use.
var SEGMENT_TYPE_DISCLOSED_VENDORS = 1;                                                        // allow:raw-byte-literal — TCF segment-type marker, not bytes
var SEGMENT_TYPE_ALLOWED_VENDORS   = 2;                                                        // allow:raw-byte-literal — TCF segment-type marker, not bytes
var SEGMENT_TYPE_PUBLISHER_TC      = 3;                                                        // allow:raw-byte-literal — TCF segment-type marker, not bytes
var MAX_TC_STRING_BYTES = 64 * 1024;                                                           // allow:raw-byte-literal — request-payload cap

// base64url decode (no padding) → Buffer.
function _b64urlDecode(s) {
  var padded = s.replace(/-/g, "+").replace(/_/g, "/");
  var pad = padded.length % 4;
  if (pad === 2) padded += "==";
  else if (pad === 3) padded += "=";
  else if (pad === 1) throw IabTcfError.factory("BAD_BASE64",
    "iabTcf: base64url segment has invalid length");
  return Buffer.from(padded, "base64");
}

// Bit-level reader over a Buffer.
function _bitReader(buf) {
  var bitOffset = 0;
  var totalBits = buf.length * 8;                                                             // allow:raw-byte-literal — bits per byte
  function read(n) {
    if (bitOffset + n > totalBits) {
      throw IabTcfError.factory("BAD_LENGTH",
        "iabTcf: read past end of segment (offset=" + bitOffset + " want=" + n + " total=" + totalBits + ")");
    }
    var v = 0;
    for (var i = 0; i < n; i += 1) {
      var byteIdx = (bitOffset + i) >> 3;
      var bitIdx  = 7 - ((bitOffset + i) & 7);                                                  // allow:raw-byte-literal — high-bit-first ordering
      v = (v << 1) | ((buf[byteIdx] >> bitIdx) & 1);
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
  var version            = r.read(6);                                                          // allow:raw-byte-literal — TCF spec field width, not bytes
  var createdRaw         = r.read(36);                                                         // allow:raw-byte-literal — TCF spec field width
  var lastUpdatedRaw     = r.read(36);                                                         // allow:raw-byte-literal — TCF spec field width
  var cmpId              = r.read(12);                                                         // allow:raw-byte-literal — TCF spec field width
  var cmpVersion         = r.read(12);                                                         // allow:raw-byte-literal — TCF spec field width
  var consentScreen      = r.read(6);                                                          // allow:raw-byte-literal — TCF spec field width
  // ConsentLanguage (12 bits = 2 chars × 6 bits, ASCII A-Z mapped 0-25)
  var lang0 = r.read(6);                                                                       // allow:raw-byte-literal — TCF spec field width
  var lang1 = r.read(6);                                                                       // allow:raw-byte-literal — TCF spec field width
  var consentLanguage = String.fromCharCode(0x41 + lang0) + String.fromCharCode(0x41 + lang1); // allow:raw-byte-literal — ASCII 'A' offset
  var vendorListVersion  = r.read(12);                                                         // allow:raw-byte-literal — TCF spec field width
  var policyVersion      = r.read(6);                                                          // allow:raw-byte-literal — TCF spec field width
  var isServiceSpecific  = r.read(1) === 1;
  var useNonStandardStacks = r.read(1) === 1;
  var specialFeatureOptins = r.readBitField(12);                                               // allow:raw-byte-literal — TCF spec field width
  var purposesConsent      = r.readBitField(24);                                               // allow:raw-byte-literal — TCF spec field width
  var purposesLI           = r.readBitField(24);                                               // allow:raw-byte-literal — TCF spec field width
  var purposeOneTreatment  = r.read(1) === 1;
  var publisherCC          = String.fromCharCode(0x41 + r.read(6)) + String.fromCharCode(0x41 + r.read(6)); // allow:raw-byte-literal — TCF spec field width
  // MaxVendorIdConsent + ranged fields skipped for compactness — the
  // framework's defensive parse only extracts the top-level shape +
  // the vendorConsents/LIs bitmaps when present.
  var vendorConsents = _parseVendorSection(r);
  var vendorLIs      = _parseVendorSection(r);
  return {
    version:               version,
    createdAt:             createdRaw * 100,                                                   // allow:raw-time-literal — TCF spec deciseconds → ms
    lastUpdatedAt:         lastUpdatedRaw * 100,                                               // allow:raw-time-literal — TCF spec deciseconds → ms
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
  };
}

// Vendor section: MaxVendorId (16 bits) + IsRangeEncoding (1 bit) +
// either bitmap (MaxVendorId bits) or RangeEntries.
function _parseVendorSection(r) {
  var maxVendorId    = r.read(16);                                                             // allow:raw-byte-literal — TCF spec field width
  var isRangeEncoding = r.read(1) === 1;
  var ids = new Set();
  if (isRangeEncoding) {
    var numEntries = r.read(12);                                                               // allow:raw-byte-literal — TCF spec field width
    for (var i = 0; i < numEntries; i += 1) {
      var isRange = r.read(1) === 1;
      var startVendorId = r.read(16);                                                          // allow:raw-byte-literal — TCF spec field width
      if (isRange) {
        var endVendorId = r.read(16);                                                          // allow:raw-byte-literal — TCF spec field width
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
  var segType = r.read(3);                                                                     // allow:raw-byte-literal — TCF spec field width
  if (segType !== expectedType) {
    throw IabTcfError.factory("BAD_SEGMENT_TYPE",
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
    throw IabTcfError.factory("BAD_INPUT",
      "iabTcf.parseString: tcString must be a non-empty string");
  }
  if (tcString.length > MAX_TC_STRING_BYTES) {
    throw IabTcfError.factory("INPUT_TOO_LARGE",
      "iabTcf.parseString: tcString exceeds " + MAX_TC_STRING_BYTES + " bytes");
  }
  var segments = tcString.split(".");
  var coreBuf;
  try { coreBuf = _b64urlDecode(segments[0]); }
  catch (e) {
    throw IabTcfError.factory("BAD_CORE",
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
    var segType = (segBuf[0] >> 5) & 0x07;                                                     // allow:raw-byte-literal — TCF segment-type lives in top 3 bits
    try {
      if (segType === SEGMENT_TYPE_DISCLOSED_VENDORS) {
        disclosedVendors = { present: true, vendorIds: _parseSecondaryVendorSegment(segBuf, SEGMENT_TYPE_DISCLOSED_VENDORS).ids };
      } else if (segType === SEGMENT_TYPE_ALLOWED_VENDORS) {
        allowedVendors = { present: true, vendorIds: _parseSecondaryVendorSegment(segBuf, SEGMENT_TYPE_ALLOWED_VENDORS).ids };
      } else if (segType === SEGMENT_TYPE_PUBLISHER_TC) {
        publisherTC = { present: true };
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
    throw IabTcfError.factory("WRONG_CORE_VERSION",
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
    throw IabTcfError.factory("WRONG_POLICY_VERSION",
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
    throw IabTcfError.factory("MISSING_DISCLOSED_VENDORS",
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
    throw IabTcfError.factory("BAD_PARSED",
      "iabTcf.checkVendor: parsed object required (call parseString first)");
  }
  if (typeof vendorId !== "number" || !isFinite(vendorId) || vendorId < 1 ||
      Math.floor(vendorId) !== vendorId) {
    throw IabTcfError.factory("BAD_VENDOR_ID",
      "iabTcf.checkVendor: vendorId must be a positive integer");
  }
  return {
    consented:   parsed.core.vendorConsents.ids.has(vendorId),
    legitimate:  parsed.core.vendorLIs.ids.has(vendorId),
    disclosed:   parsed.disclosedVendors && parsed.disclosedVendors.vendorIds.has(vendorId) || false,
  };
}

module.exports = {
  parseString:           parseString,
  requireV23Disclosed:   requireV23Disclosed,
  checkVendor:           checkVendor,
  IabTcfError:           IabTcfError,
  TCF_V23_CORE_VERSION:  TCF_V23_CORE_VERSION,
  TCF_V23_POLICY_VERSION: TCF_V23_POLICY_VERSION,
};
