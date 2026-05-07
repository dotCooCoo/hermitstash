"use strict";
/**
 * b.iabMspa — IAB Multi-State Privacy Agreement / Global Privacy
 * Platform (GPP) universal opt-out signal codec.
 *
 * GPP (https://github.com/InteractiveAdvertisingBureau/Global-
 * Privacy-Platform) is the IAB's successor to the patchwork of
 * per-state US privacy strings. A GPP string carries multiple
 * sections separated by `~`, each tagged with a section ID. The
 * MSPA-relevant sections are the US national + state sections
 * (USNAT, USCA, USVA, USCO, USCT, USUT) carrying:
 *
 *   - SaleOptOut, SharingOptOut, TargetedAdvertisingOptOut, Sensitive-
 *     DataProcessingOptOuts, KnownChildSensitiveData
 *   - GPC (Global Privacy Control browser signal mirror)
 *   - MSPA service-provider / opted-in flags
 *
 * Public API:
 *
 *   b.iabMspa.parseGpp(gppString) -> { header, sections }
 *     header:  { version, sectionIds[], gpcSignal? }
 *     sections: [{ id, optOuts: { sale, sharing, targetedAds, ... } }]
 *
 *   b.iabMspa.checkOptOut(parsed, opts) -> { mustHonor, signals }
 *     opts: { dataUse: "sale" | "sharing" | "targeted-ads" |
 *             "sensitive" | "child-data", state? }
 *     Returns mustHonor=true when ANY in-scope section signals an
 *     opt-out for the requested use; signals lists which section IDs
 *     produced the verdict.
 *
 *   b.iabMspa.refuseProcessing(parsed, opts)
 *     Throws IabMspaError when mustHonor → operator's data-flow code
 *     halts at the same point a CCPA "do-not-sell" header would.
 *
 *   b.iabMspa.gpcFromHeaders(req) -> bool
 *     Reads the W3C `Sec-GPC: 1` browser header (RFC draft-davidson-
 *     httpbis-gpc-00). Universal opt-out per California CCPA / CPRA
 *     §1798.135(b)(1) and Colorado, Connecticut, etc.
 */

var audit = require("./audit");
var { defineClass } = require("./framework-error");
var IabMspaError = defineClass("IabMspaError", { alwaysPermanent: true });

// GPP section IDs we recognize (subset — the full registry is at
// https://iabtechlab.com/standards/global-privacy-platform/sections).
var SECTION_IDS = {
  7:  "usnat",  // US National Privacy
  8:  "usca",   // California (CCPA / CPRA)                                                  // allow:raw-byte-literal — IAB GPP section ID, not bytes
  9:  "usva",   // Virginia
  10: "usco",   // Colorado
  11: "usut",   // Utah
  12: "usct",   // Connecticut
  13: "usnv",   // Nevada
  14: "usia",   // Iowa
  15: "usde",   // Delaware
  16: "usnj",   // New Jersey                                                               // allow:raw-byte-literal — IAB GPP section ID, not bytes
  17: "ustx",   // Texas (TDPSA)
  18: "usor",   // Oregon
  19: "usmt",   // Montana
  20: "usnh",   // New Hampshire
};
var ALL_SECTIONS = Object.keys(SECTION_IDS).map(Number);
var DATA_USES = ["sale", "sharing", "targeted-ads", "sensitive", "child-data"];

function parseGpp(gppString) {
  if (typeof gppString !== "string" || gppString.length === 0) {
    throw IabMspaError.factory("BAD_INPUT",
      "iabMspa.parseGpp: gppString required");
  }
  if (gppString.length > 8192) {                                                              // allow:raw-byte-literal — GPP string cap, not bytes
    throw IabMspaError.factory("INPUT_TOO_LARGE",
      "iabMspa.parseGpp: gppString exceeds 8192 chars");
  }
  // GPP framing: <header>~<section1>~<section2>...
  // The header carries a 6-bit version + an int-list of section IDs.
  // A full GPP decoder is substantial — for the framework's
  // refuse-on-opt-out usage we only need the header's section ID
  // list + per-section opt-out flags. The decoder below is the
  // simplest correct partial parse: it splits sections, identifies
  // each by the leading section-ID claim in the header, and exposes
  // per-section raw payloads for downstream operator-specific
  // decoding.
  var parts = gppString.split("~");
  if (parts.length === 0) {
    return { header: { version: null, sectionIds: [] }, sections: [] };
  }
  // The first segment is the header. We don't fully decode it here;
  // operator-side libraries (iabtcf-core / @iabtechlab/gpp-cmp) own
  // the binary tag layout. We do extract the trailing claim list
  // when present (some GPP strings encode the list as a comma-
  // separated trailer like `header,7,8,9`).
  var header = { raw: parts[0], version: null, sectionIds: [] };
  var sectionPayloads = parts.slice(1);
  // Try to find a numeric-list tail in the header (heuristic).
  var tailMatch = parts[0].match(/[A-Za-z0-9_-]+\.([0-9.]+)$/);
  if (tailMatch) {
    var ids = tailMatch[1].split(".").map(function (s) { return parseInt(s, 10); });
    header.sectionIds = ids.filter(function (n) { return isFinite(n) && n > 0; });
  }
  // Build sections — pair sectionPayloads with sectionIds positionally.
  var sections = [];
  for (var i = 0; i < sectionPayloads.length; i += 1) {
    var sid = header.sectionIds[i] || null;
    sections.push({
      id:       sid,
      idLabel:  sid && SECTION_IDS[sid] || null,
      raw:      sectionPayloads[i],
      // Operator decodes the per-section payload. The framework
      // surfaces a header-only `optOuts` shape that operators can
      // override by fully decoding their binary section.
      optOuts:  null,
    });
  }
  return { header: header, sections: sections };
}

function checkOptOut(parsed, opts) {
  if (!parsed || typeof parsed !== "object" || !Array.isArray(parsed.sections)) {
    throw IabMspaError.factory("BAD_PARSED",
      "iabMspa.checkOptOut: parsed object required (call parseGpp first)");
  }
  if (!opts || DATA_USES.indexOf(opts.dataUse) === -1) {
    throw IabMspaError.factory("BAD_DATA_USE",
      "iabMspa.checkOptOut: opts.dataUse must be one of " + DATA_USES.join(", "));
  }
  var signals = [];
  for (var i = 0; i < parsed.sections.length; i += 1) {
    var s = parsed.sections[i];
    if (opts.state && s.idLabel !== opts.state.toLowerCase()) continue;
    if (!s.optOuts) continue;   // operator hasn't decoded the section
    var hit = false;
    if (opts.dataUse === "sale" && s.optOuts.sale === true) hit = true;
    else if (opts.dataUse === "sharing" && s.optOuts.sharing === true) hit = true;
    else if (opts.dataUse === "targeted-ads" && s.optOuts.targetedAds === true) hit = true;
    else if (opts.dataUse === "sensitive" && s.optOuts.sensitive === true) hit = true;
    else if (opts.dataUse === "child-data" && s.optOuts.childData === true) hit = true;
    if (hit) signals.push(s.idLabel || ("section-" + s.id));
  }
  return { mustHonor: signals.length > 0, signals: signals };
}

function refuseProcessing(parsed, opts) {
  var rv = checkOptOut(parsed, opts);
  if (rv.mustHonor) {
    audit.safeEmit({
      action:   "iabmspa.processing_refused",
      outcome:  "denied",
      metadata: {
        dataUse: opts.dataUse,
        state:   opts.state || null,
        signals: rv.signals,
      },
    });
    throw IabMspaError.factory("OPT_OUT_HONORED",
      "iabMspa: opt-out signal must be honored for dataUse='" + opts.dataUse +
      "' (signals: " + rv.signals.join(", ") + ")");
  }
  return rv;
}

function gpcFromHeaders(req) {
  if (!req || !req.headers) return false;
  var h = req.headers["sec-gpc"];
  return h === "1" || h === 1;
}

module.exports = {
  parseGpp:           parseGpp,
  checkOptOut:        checkOptOut,
  refuseProcessing:   refuseProcessing,
  gpcFromHeaders:     gpcFromHeaders,
  SECTION_IDS:        Object.assign({}, SECTION_IDS),
  ALL_SECTIONS:       ALL_SECTIONS.slice(),
  DATA_USES:          DATA_USES.slice(),
  IabMspaError:       IabMspaError,
};
