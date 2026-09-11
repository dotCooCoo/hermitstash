// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
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

var SECTION_IDS = {
  7:  "usnat",
  8:  "usca",
  9:  "usva",
  10: "usco",
  11: "usut",
  12: "usct",
  13: "usnv",
  14: "usia",
  15: "usde",
  16: "usnj",
  17: "ustx",
  18: "usor",
  19: "usmt",
  20: "usnh",
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

function _numericTail(s) {
  var len = s.length;
  if (len < 3) return null;
  var i = len;
  while (i > 0) {
    var c = s.charCodeAt(i - 1);
    if (c === 46 || (c >= 48 && c <= 57)) i -= 1; else break;
  }
  for (var d = i; d < len - 1; d += 1) {
    if (s.charCodeAt(d) !== 46 || d === 0) continue;
    var p = s.charCodeAt(d - 1);
    if ((p >= 48 && p <= 57) || (p >= 65 && p <= 90) ||
        (p >= 97 && p <= 122) || p === 95 || p === 45) {
      return s.slice(d + 1);
    }
  }
  return null;
}

function parseGpp(gppString) {
  if (typeof gppString !== "string" || gppString.length === 0) {
    throw IabMspaError.factory("iab-mspa/bad-input",
      "iabMspa.parseGpp: gppString required");
  }
  if (gppString.length > 8192) {
    throw IabMspaError.factory("iab-mspa/input-too-large",
      "iabMspa.parseGpp: gppString exceeds 8192 chars");
  }
  var parts = gppString.split("~");
  if (parts.length === 0) {
    return { header: { version: null, sectionIds: [] }, sections: [] };
  }
  var header = { raw: parts[0], version: null, sectionIds: [] };
  var sectionPayloads = parts.slice(1);
  var tail = _numericTail(parts[0]);
  if (tail !== null) {
    var ids = tail.split(".").map(function (s) { return parseInt(s, 10); });
    header.sectionIds = ids.filter(function (n) { return isFinite(n) && n > 0; });
  }
  var sections = [];
  for (var i = 0; i < sectionPayloads.length; i += 1) {
    var sid = header.sectionIds[i] || null;
    sections.push({
      id:       sid,
      idLabel:  sid && SECTION_IDS[sid] || null,
      raw:      sectionPayloads[i],
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
    throw IabMspaError.factory("iab-mspa/bad-parsed",
      "iabMspa.checkOptOut: parsed object required (call parseGpp first)");
  }
  if (!opts || DATA_USES.indexOf(opts.dataUse) === -1) {
    throw IabMspaError.factory("iab-mspa/bad-data-use",
      "iabMspa.checkOptOut: opts.dataUse must be one of " + DATA_USES.join(", "));
  }
  var signals = [];
  for (var i = 0; i < parsed.sections.length; i += 1) {
    var s = parsed.sections[i];
    if (opts.state && s.idLabel !== opts.state.toLowerCase()) continue;
    if (!s.optOuts) continue;
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
    throw IabMspaError.factory("iab-mspa/opt-out-honored",
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
