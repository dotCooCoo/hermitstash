"use strict";
/**
 * b.iabMspa — IAB MSPA / GPP universal opt-out signal codec.
 */

var helpers = require("../helpers");
var b     = helpers.b;
var check = helpers.check;

async function run() {
  check("parseGpp is fn",         typeof b.iabMspa.parseGpp === "function");
  check("checkOptOut is fn",      typeof b.iabMspa.checkOptOut === "function");
  check("refuseProcessing is fn", typeof b.iabMspa.refuseProcessing === "function");
  check("gpcFromHeaders is fn",   typeof b.iabMspa.gpcFromHeaders === "function");
  check("IabMspaError is fn",     typeof b.iabMspa.IabMspaError === "function");
  check("DATA_USES",              Array.isArray(b.iabMspa.DATA_USES) && b.iabMspa.DATA_USES.length === 5);
  check("SECTION_IDS",            typeof b.iabMspa.SECTION_IDS === "object" && b.iabMspa.SECTION_IDS[7] === "usnat");

  // gpcFromHeaders
  check("gpc=1 detected",     b.iabMspa.gpcFromHeaders({ headers: { "sec-gpc": "1" } }) === true);
  check("gpc absent → false", b.iabMspa.gpcFromHeaders({ headers: {} }) === false);
  check("null req → false",   b.iabMspa.gpcFromHeaders(null) === false);

  // parseGpp — well-formed minimal string
  var parsed = b.iabMspa.parseGpp("DBABMA~CLAAAAAAFsA.QA");
  check("parseGpp returns header + sections", parsed.header && Array.isArray(parsed.sections));

  // checkOptOut returns mustHonor=false on undecoded sections
  var rv = b.iabMspa.checkOptOut(parsed, { dataUse: "sale" });
  check("checkOptOut mustHonor false on undecoded", rv.mustHonor === false);

  // checkOptOut with operator-decoded section
  var withDecode = {
    header:   { version: 1, sectionIds: [8] },
    sections: [
      { id: 8, idLabel: "usca", optOuts: { sale: true, sharing: false, targetedAds: true } },
    ],
  };
  var verdict = b.iabMspa.checkOptOut(withDecode, { dataUse: "sale" });
  check("decoded sale opt-out detected", verdict.mustHonor === true && verdict.signals[0] === "usca");

  var sharingVerdict = b.iabMspa.checkOptOut(withDecode, { dataUse: "sharing" });
  check("decoded sharing not opted-out", sharingVerdict.mustHonor === false);

  // refuseProcessing throws
  var threw = null;
  try { b.iabMspa.refuseProcessing(withDecode, { dataUse: "sale" }); }
  catch (e) { threw = e; }
  check("refuseProcessing throws on opt-out", threw && threw.code === "OPT_OUT_HONORED");

  // Validation
  function rejects(label, fn, code) {
    var t = null;
    try { fn(); } catch (e) { t = e; }
    check(label, t && t.code === code);
  }
  rejects("parseGpp refuses non-string",
    function () { b.iabMspa.parseGpp(null); }, "BAD_INPUT");
  rejects("checkOptOut refuses bad dataUse",
    function () { b.iabMspa.checkOptOut(parsed, { dataUse: "marketing" }); }, "BAD_DATA_USE");
}

module.exports = { run: run };
