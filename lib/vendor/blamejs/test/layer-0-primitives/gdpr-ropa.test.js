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

  ropa.remove("crm", { reason: "deprecated", actor: "dpo" });
  check("ropa.remove deletes",       ropa.list().length === 0);

  console.log("OK — gdpr.ropa tests");
}

module.exports = { run: run };
if (require.main === module) run();
