"use strict";
/**
 * b.darkPatterns — FTC click-to-cancel UX-parity attestation.
 */

var helpers = require("../helpers");
var b     = helpers.b;
var check = helpers.check;

async function run() {
  check("darkPatterns.recordSignupFlow is fn", typeof b.darkPatterns.recordSignupFlow === "function");
  check("darkPatterns.recordCancelFlow is fn", typeof b.darkPatterns.recordCancelFlow === "function");
  check("darkPatterns.assertParity is fn",     typeof b.darkPatterns.assertParity === "function");
  check("darkPatterns.attest is fn",            typeof b.darkPatterns.attest === "function");
  check("darkPatterns.middleware is fn",        typeof b.darkPatterns.middleware === "function");
  check("darkPatterns.DarkPatternsError is fn", typeof b.darkPatterns.DarkPatternsError === "function");

  var s = b.darkPatterns.recordSignupFlow({
    channel: "web", clickCount: 2, cta: { text: "Subscribe", fontWeight: 600, contrastRatio: 7 },
    confirmations: 1, resourceId: "plan-1",
  });
  check("recordSignupFlow shape", s.kind === "signup" && s.resourceId === "plan-1");

  var c = b.darkPatterns.recordCancelFlow({
    channel: "web", clickCount: 5, cta: { text: "Cancel", fontWeight: 400, contrastRatio: 3 },
    confirmations: 2, resourceId: "plan-1",
  });
  var v = b.darkPatterns.assertParity(s, c, { posture: "ftc-2024" });
  check("assertParity: breaches detected",        v.ok === false && v.breaches.length >= 3);
  check("assertParity: click-count breach",       v.breaches.some(function (b) { return b.kind === "click-count"; }));
  check("assertParity: contrast breach",          v.breaches.some(function (b) { return b.kind === "contrast-degradation"; }));

  // Clean parity
  var s2 = b.darkPatterns.recordSignupFlow({
    channel: "web", clickCount: 3, cta: { text: "Sign up", fontWeight: 600, contrastRatio: 7 },
    confirmations: 1, resourceId: "plan-2",
  });
  var c2 = b.darkPatterns.recordCancelFlow({
    channel: "web", clickCount: 3, cta: { text: "Cancel", fontWeight: 600, contrastRatio: 7 },
    confirmations: 1, resourceId: "plan-2",
  });
  var v2 = b.darkPatterns.assertParity(s2, c2);
  check("assertParity: clean",  v2.ok === true);

  // attest one-shot
  var att = b.darkPatterns.attest({
    signup: { channel:"web", clickCount:2, cta:{text:"Sub",fontWeight:600,contrastRatio:7}, confirmations:1, resourceId:"plan-3" },
    cancel: { channel:"web", clickCount:2, cta:{text:"Can",fontWeight:600,contrastRatio:7}, confirmations:1, resourceId:"plan-3" },
    audit: false,
  });
  check("attest: ok", att.verdict.ok === true);

  // Bad opts
  var threw = null;
  try { b.darkPatterns.recordSignupFlow({ channel: "fax", clickCount: 1, cta: {}, confirmations: 0, resourceId: "x" }); }
  catch (e) { threw = e; }
  check("recordSignupFlow refuses bad channel", threw && threw.code === "BAD_CHANNEL");

  // Resource ID mismatch
  threw = null;
  try { b.darkPatterns.assertParity(s, { kind: "cancel", resourceId: "different" }); }
  catch (e) { threw = e; }
  check("assertParity refuses resource mismatch", threw && threw.code === "RESOURCE_MISMATCH");
}

module.exports = { run: run };
