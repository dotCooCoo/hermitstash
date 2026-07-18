// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
var helpers = require("../helpers");
var b = helpers.b;
var check = helpers.check;

function run() {
  var ropa = b.gdpr.ropa.create({
    audit: false,
    controller: { name: "Acme", contact: "dpo@acme.example" },
  });
  ropa.register({
    id: "crm",
    name: "CRM tracking",
    purposes: ["lead-tracking"],
    legalBasis: "legitimate-interests",
    dataCategories: ["contact-info"],
  });
  check("ropa.register stored",      ropa.list().length === 1);
  check("ropa.get returns record",   ropa.get("crm").name === "CRM tracking");

  var json = ropa["export"]({ format: "json" });
  check("ropa.export json carries activities", json.activities.length === 1);
  check("ropa.export json includes regulation", json.regulation.indexOf("GDPR") !== -1);

  var md = ropa["export"]({ format: "markdown" });
  check("ropa.export markdown includes title", md.indexOf("Article 30") !== -1);

  var threwBadBasis = false;
  try {
    ropa.register({ id: "x", name: "x", purposes: ["x"], legalBasis: "made-up", dataCategories: ["x"] });
  } catch (e) { threwBadBasis = e.code === "gdpr-ropa/bad-legal-basis"; }
  check("ropa refuses bad legalBasis", threwBadBasis);

  ropa.update("crm", { retentionPeriod: "5y" });
  check("ropa.update merges patch", ropa.get("crm").retentionPeriod === "5y");

  // update() must validate legalBasis with the SAME rigor as register().
  // register() rejects a falsy-but-invalid legalBasis (""/0/false/undefined);
  // update() must too — otherwise a required Article 30 field can be silently
  // corrupted to a value the VALID_LEGAL_BASES enum would reject. A truthiness
  // guard (`if (patch.legalBasis && ...)`) skipped validation whenever the
  // incoming value was falsy, so an empty string sailed through where the enum
  // check would have caught "made-up".
  var basisRopa = b.gdpr.ropa.create({
    audit: false, controller: { name: "Acme", contact: "dpo@acme.example" },
  });
  basisRopa.register({ id: "a1", name: "A1", purposes: ["p"], legalBasis: "consent", dataCategories: ["c"] });

  var updEmptyRejected = false;
  try { basisRopa.update("a1", { legalBasis: "" }); }
  catch (e) { updEmptyRejected = e.code === "gdpr-ropa/bad-legal-basis"; }
  check("ropa.update rejects empty-string legalBasis (parity with register)", updEmptyRejected);
  check("ropa.update leaves legalBasis intact after rejecting empty",
        basisRopa.get("a1").legalBasis === "consent");

  var updZeroRejected = false;
  try { basisRopa.update("a1", { legalBasis: 0 }); }
  catch (e) { updZeroRejected = e.code === "gdpr-ropa/bad-legal-basis"; }
  check("ropa.update rejects falsy numeric legalBasis", updZeroRejected);
  check("ropa.update leaves legalBasis intact after rejecting 0",
        basisRopa.get("a1").legalBasis === "consent");

  // A valid legalBasis update still succeeds (fix must not over-reject).
  basisRopa.update("a1", { legalBasis: "contract" });
  check("ropa.update accepts a valid legalBasis change", basisRopa.get("a1").legalBasis === "contract");

  ropa.remove("crm", { reason: "deprecated", actor: "dpo" });
  check("ropa.remove deletes",       ropa.list().length === 0);

  console.log("OK — gdpr.ropa tests");
}

module.exports = { run: run };
if (require.main === module) run();
