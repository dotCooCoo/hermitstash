"use strict";
/**
 * @module b.iabMspa
 * @nav    Compliance
 * @title  IAB MSPA
 *
 * @intro
 *   IAB Multi-State Privacy Agreement signal — encode/decode opt-out
 *   preferences for state privacy laws (CCPA, CPA, etc.).
 *
 *   The IAB Global Privacy Platform (GPP) is the successor to the
 *   patchwork of per-state US privacy strings. A GPP string carries
 *   multiple sections separated by `~`, each tagged with a section
 *   ID. The MSPA-relevant sections cover the US national + state
 *   regimes (USNAT, USCA, USVA, USCO, USCT, USUT, plus 2025-26
 *   additions) and carry sale / sharing / targeted-ads /
 *   sensitive-data / child-data opt-out flags alongside the W3C
 *   `Sec-GPC` browser-signal mirror.
 *
 *   The framework ships a partial-correct decoder (the binary tag
 *   layout is operator-side via the IAB's gpp-cmp libraries), an
 *   opt-out evaluator that returns `mustHonor` across in-scope
 *   sections, a throw-on-must-honor refusal helper, and a header
 *   reader for the `Sec-GPC: 1` universal opt-out signal.
 *
 * @card
 *   IAB Multi-State Privacy Agreement signal — encode/decode opt-out preferences for state privacy laws (CCPA, CPA, etc.).
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

/**
 * @primitive b.iabMspa.parseGpp
 * @signature b.iabMspa.parseGpp(gppString)
 * @since     0.8.44
 * @related   b.iabMspa.checkOptOut, b.iabMspa.refuseProcessing
 *
 * Parse the framing of a GPP string into `{ header, sections }`. The
 * decoder splits on `~`, identifies each section by its positional
 * claim in the header's section-ID list, and exposes the per-section
 * raw payloads. The framework deliberately does not decode the
 * binary section layout — operator-side libraries
 * (`@iabtechlab/gpp-cmp`) own that surface and populate
 * `section.optOuts`. Throws on missing input or strings exceeding
 * the 8192-char defensive cap.
 *
 * @example
 *   var parsed = b.iabMspa.parseGpp("DBABBg.7.8");
 *   parsed.header.sectionIds;     // → [7, 8]
 *   parsed.sections.length;       // → 0  (no payload segments yet)
 */
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

/**
 * @primitive b.iabMspa.checkOptOut
 * @signature b.iabMspa.checkOptOut(parsed, opts)
 * @since     0.8.44
 * @related   b.iabMspa.parseGpp, b.iabMspa.refuseProcessing
 *
 * Walk the parsed GPP sections and return `{ mustHonor, signals }`
 * for the requested data-use category. `mustHonor` is `true` when
 * ANY in-scope section signals an opt-out for that use; `signals`
 * lists the section labels that produced the verdict. Operators
 * narrow the search to a specific state by passing `opts.state`.
 * Sections whose `optOuts` field hasn't been populated by an
 * operator-side decoder are skipped (no false positives from
 * missing data).
 *
 * @opts
 *   dataUse: "sale" | "sharing" | "targeted-ads" | "sensitive" | "child-data",
 *   state:   string,                       // optional GPP section label
 *
 * @example
 *   var parsed = {
 *     header: { sectionIds: [8] },
 *     sections: [
 *       { id: 8, idLabel: "usca", raw: "",
 *         optOuts: { sale: true, sharing: false, targetedAds: true } },
 *     ],
 *   };
 *   var verdict = b.iabMspa.checkOptOut(parsed, { dataUse: "sale" });
 *   verdict.mustHonor;   // → true
 *   verdict.signals;     // → ["usca"]
 */
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

/**
 * @primitive b.iabMspa.refuseProcessing
 * @signature b.iabMspa.refuseProcessing(parsed, opts)
 * @since     0.8.44
 * @related   b.iabMspa.checkOptOut, b.iabMspa.parseGpp
 *
 * Throw `IabMspaError` when `checkOptOut` returns `mustHonor:true`
 * — wires the framework's opt-out signal into the operator's
 * data-flow code at the same point a CCPA do-not-sell header would
 * halt processing. Audits the refusal under
 * `iabmspa.processing_refused` before throwing. Returns the verdict
 * object on the no-opt-out path so the caller can inspect signals.
 *
 * @opts
 *   dataUse: "sale" | "sharing" | "targeted-ads" | "sensitive" | "child-data",
 *   state:   string,                       // optional GPP section label
 *
 * @example
 *   var parsed = { header: { sectionIds: [] }, sections: [] };
 *   var verdict = b.iabMspa.refuseProcessing(parsed, { dataUse: "sale" });
 *   verdict.mustHonor;   // → false  (no signals → no throw)
 */
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

/**
 * @primitive b.iabMspa.gpcFromHeaders
 * @signature b.iabMspa.gpcFromHeaders(req)
 * @since     0.8.44
 * @related   b.iabMspa.checkOptOut, b.iabMspa.refuseProcessing
 *
 * Read the W3C `Sec-GPC: 1` browser header from an inbound request.
 * Returns `true` when the user's browser is asserting the universal
 * opt-out signal (mandatory under California CCPA / CPRA
 * §1798.135(b)(1) and Colorado, Connecticut, etc.). Defensive
 * against missing `req`/`headers` shapes — never throws.
 *
 * @example
 *   var req = { headers: { "sec-gpc": "1" } };
 *   b.iabMspa.gpcFromHeaders(req);              // → true
 *   b.iabMspa.gpcFromHeaders({ headers: {} });  // → false
 *   b.iabMspa.gpcFromHeaders(null);             // → false
 */
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
