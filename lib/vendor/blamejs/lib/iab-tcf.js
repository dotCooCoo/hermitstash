// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
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

var audit = require("./audit");
var bCrypto = require("./crypto");
var numericBounds = require("./numeric-bounds");
var { defineClass } = require("./framework-error");
var IabTcfError = defineClass("IabTcfError", { alwaysPermanent: true });

var TCF_V23_CORE_VERSION   = 4;
var TCF_V23_POLICY_VERSION = 4;
var SEGMENT_TYPE_DISCLOSED_VENDORS = 1;
var SEGMENT_TYPE_ALLOWED_VENDORS   = 2;
var SEGMENT_TYPE_PUBLISHER_TC      = 3;
var MAX_TC_STRING_BYTES = 64 * 1024;

function _b64urlDecode(s) {
  var padded = s.replace(/-/g, "+").replace(/_/g, "/");
  var pad = padded.length % 4;
  if (pad === 2) padded += "==";
  else if (pad === 3) padded += "=";
  else if (pad === 1) throw IabTcfError.factory("iab-tcf/bad-base64",
    "iabTcf: base64url segment has invalid length");
  return Buffer.from(padded, "base64");
}

function _bitReader(buf) {
  var bitOffset = 0;
  var totalBits = buf.length * 8;
  function read(n) {
    if (bitOffset + n > totalBits) {
      throw IabTcfError.factory("iab-tcf/bad-length",
        "iabTcf: read past end of segment (offset=" + bitOffset + " want=" + n + " total=" + totalBits + ")");
    }
    var v = 0;
    for (var i = 0; i < n; i += 1) {
      var byteIdx = (bitOffset + i) >> 3;
      var bitIdx  = 7 - ((bitOffset + i) & 7);
      v = (v * 2) + ((buf[byteIdx] >> bitIdx) & 1);
    }
    bitOffset += n;
    return v;
  }
  function readBitField(n) {
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
  var version            = r.read(6);
  var createdRaw         = r.read(36);
  var lastUpdatedRaw     = r.read(36);
  var cmpId              = r.read(12);
  var cmpVersion         = r.read(12);
  var consentScreen      = r.read(6);
  var lang0 = r.read(6);
  var lang1 = r.read(6);
  var consentLanguage = String.fromCharCode(0x41 + lang0) + String.fromCharCode(0x41 + lang1);
  var vendorListVersion  = r.read(12);
  var policyVersion      = r.read(6);
  var isServiceSpecific  = r.read(1) === 1;
  var useNonStandardStacks = r.read(1) === 1;
  var specialFeatureOptins = r.readBitField(12);
  var purposesConsent      = r.readBitField(24);
  var purposesLI           = r.readBitField(24);
  var purposeOneTreatment  = r.read(1) === 1;
  var publisherCC          = String.fromCharCode(0x41 + r.read(6)) + String.fromCharCode(0x41 + r.read(6));
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

function _parsePublisherRestrictions(r) {
  var out = [];
  var num = r.read(12);
  for (var i = 0; i < num; i += 1) {
    var purposeId       = r.read(6);
    var restrictionType = r.read(2);
    var numEntries      = r.read(12);
    var vendorIds = [];
    for (var e = 0; e < numEntries; e += 1) {
      var isRange       = r.read(1) === 1;
      var startVendorId = r.read(16);
      if (isRange) {
        var endVendorId = r.read(16);
        for (var v = startVendorId; v <= endVendorId; v += 1) vendorIds.push(v);
      } else {
        vendorIds.push(startVendorId);
      }
    }
    out.push({ purposeId: purposeId, restrictionType: restrictionType, vendorIds: vendorIds });
  }
  return out;
}

function _parsePublisherTC(buf) {
  var r = _bitReader(buf);
  r.read(3);
  var pubPurposesConsent = r.readBitField(24);
  var pubPurposesLI      = r.readBitField(24);
  var numCustomPurposes  = r.read(6);
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

function _parseVendorSection(r) {
  var maxVendorId    = r.read(16);
  var isRangeEncoding = r.read(1) === 1;
  var ids = new Set();
  if (isRangeEncoding) {
    var numEntries = r.read(12);
    for (var i = 0; i < numEntries; i += 1) {
      var isRange = r.read(1) === 1;
      var startVendorId = r.read(16);
      if (isRange) {
        var endVendorId = r.read(16);
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

function _parseSecondaryVendorSegment(buf, expectedType) {
  var r = _bitReader(buf);
  var segType = r.read(3);
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
    var segType = (segBuf[0] >> 5) & 0x07;
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
    writeInt(maxVendorId, 16);
    if (maxVendorId === 0) { writeBool(false); return; }
    var runs = _idRuns(clean);
    var rangeBits = 1 + 12;
    runs.forEach(function (run) { rangeBits += 1 + 16 + (run[0] === run[1] ? 0 : 16); });
    var bitfieldBits = 1 + maxVendorId;
    if (rangeBits < bitfieldBits) {
      writeBool(true);
      writeInt(runs.length, 12);
      runs.forEach(function (run) {
        if (run[0] === run[1]) { writeBool(false); writeInt(run[0], 16); }
        else { writeBool(true); writeInt(run[0], 16); writeInt(run[1], 16); }
      });
    } else {
      writeBool(false);
      writeBitField(clean, maxVendorId);
    }
  }
  function toBuffer() {
    var padded = bits + "0".repeat((8 - (bits.length % 8)) % 8);
    var byteLen = padded.length / 8;
    var out = Buffer.alloc(byteLen);
    for (var i = 0; i < byteLen; i += 1) out[i] = parseInt(padded.slice(i * 8, i * 8 + 8), 2);
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
    var v = str.charCodeAt(i) - 0x41;
    if (v < 0 || v > 25) throw IabTcfError.factory("iab-tcf/bad-value", "iabTcf.encode: '" + str.charAt(i) + "' is not an A-Z letter");
    w.writeInt(v, 6);
  }
}

function _encodePublisherTC(pub) {
  var w = _bitWriter();
  w.writeInt(SEGMENT_TYPE_PUBLISHER_TC, 3);
  w.writeBitField(pub.pubPurposesConsent || [], 24);
  w.writeBitField(pub.pubPurposesLITransparency || [], 24);
  var custom = _idArray(pub.customPurposesConsent || []);
  var customLI = _idArray(pub.customPurposesLITransparency || []);
  var n = pub.numCustomPurposes != null
    ? pub.numCustomPurposes
    : Math.max(custom.length ? custom[custom.length - 1] : 0, customLI.length ? customLI[customLI.length - 1] : 0);
  w.writeInt(n, 6);
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
 * Serialize a TCF object, in the shape `parseString` returns, back into a
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
  w.writeInt(c.version != null ? c.version : TCF_V23_CORE_VERSION, 6);
  w.writeInt(_decisec(c.createdAt), 36);
  w.writeInt(_decisec(c.lastUpdatedAt != null ? c.lastUpdatedAt : c.createdAt), 36);
  w.writeInt(c.cmpId || 0, 12);
  w.writeInt(c.cmpVersion || 0, 12);
  w.writeInt(c.consentScreen || 0, 6);
  _writeLetters(w, c.consentLanguage || "EN", "consentLanguage");
  w.writeInt(c.vendorListVersion || 0, 12);
  w.writeInt(c.policyVersion != null ? c.policyVersion : TCF_V23_POLICY_VERSION, 6);
  w.writeBool(c.isServiceSpecific !== false);
  w.writeBool(c.useNonStandardStacks === true);
  w.writeBitField(c.specialFeatureOptins || [], 12);
  w.writeBitField(c.purposesConsent || [], 24);
  w.writeBitField(c.purposesLI || [], 24);
  w.writeBool(c.purposeOneTreatment === true);
  _writeLetters(w, c.publisherCC || "AA", "publisherCC");
  w.writeVendorSection(c.vendorConsents || []);
  w.writeVendorSection(c.vendorLIs || []);
  var restrictions = c.publisherRestrictions || [];
  w.writeInt(restrictions.length, 12);
  restrictions.forEach(function (pr) {
    w.writeInt(pr.purposeId, 6);
    w.writeInt(typeof pr.restrictionType === "number" ? pr.restrictionType : 0, 2);
    var runs = _idRuns(_idArray(pr.vendorIds || []));
    w.writeInt(runs.length, 12);
    runs.forEach(function (run) {
      if (run[0] === run[1]) { w.writeBool(false); w.writeInt(run[0], 16); }
      else { w.writeBool(true); w.writeInt(run[0], 16); w.writeInt(run[1], 16); }
    });
  });
  var segs = [_b64urlEncode(w.toBuffer())];

  if (obj.disclosedVendors != null) {
    var dw = _bitWriter();
    dw.writeInt(SEGMENT_TYPE_DISCLOSED_VENDORS, 3);
    dw.writeVendorSection(obj.disclosedVendors);
    segs.push(_b64urlEncode(dw.toBuffer()));
  }
  if (obj.allowedVendors != null) {
    var aw = _bitWriter();
    aw.writeInt(SEGMENT_TYPE_ALLOWED_VENDORS, 3);
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
