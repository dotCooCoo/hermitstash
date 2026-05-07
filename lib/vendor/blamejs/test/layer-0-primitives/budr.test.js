"use strict";
/**
 * b.budr — RTO/RPO declaration primitive.
 */

var helpers = require("../helpers");
var b     = helpers.b;
var check = helpers.check;

async function run() {
  check("budr.declare is fn", typeof b.budr.declare === "function");
  check("budr.BudrError is fn", typeof b.budr.BudrError === "function");
  check("budr.list is fn",    typeof b.budr.list === "function");
  check("budr.get is fn",     typeof b.budr.get === "function");
  check("budr.TIERS",         Array.isArray(b.budr.TIERS) && b.budr.TIERS.length === 4);

  b.budr._resetForTest();

  var d = b.budr.declare({
    service:     "checkout-api",
    rtoMs:       4 * 60 * 60 * 1000,                                                          // 4 hours
    rpoMs:       15 * 60 * 1000,                                                              // 15 min
    tier:        "gold",
    criticality: "high",
    owner:       "platform-sre",
    citations:   ["dora-art-11", "iso-22301:2019"],
    audit:       false,
  });
  check("declare returns frozen object", Object.isFrozen(d));
  check("declare records targets",       d.rtoMs === 14400000 && d.rpoMs === 900000);
  check("declare list lookup",           b.budr.get("checkout-api") === d);

  b.budr.declare({ service: "billing-worker", rtoMs: 1000, rpoMs: 1000, audit: false });
  check("list contains 2 declarations",  b.budr.list().length === 2);

  // Bad service shape
  var threw = null;
  try { b.budr.declare({ service: "", rtoMs: 1, rpoMs: 1 }); }
  catch (e) { threw = e; }
  check("declare refuses empty service", threw && threw.code === "BAD_SERVICE");

  // Missing rtoMs
  threw = null;
  try { b.budr.declare({ service: "x", rpoMs: 1 }); }
  catch (e) { threw = e; }
  check("declare refuses missing rtoMs", threw && threw.code === "BAD_TARGETS");

  // Bad tier
  threw = null;
  try { b.budr.declare({ service: "x", rtoMs: 1, rpoMs: 1, tier: "platinum-99" }); }
  catch (e) { threw = e; }
  check("declare refuses bad tier", threw && threw.code === "BAD_TIER");
}

module.exports = { run: run };
