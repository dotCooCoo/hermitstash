"use strict";
var helpers = require("../helpers");
var b = helpers.b;
var check = helpers.check;

(async function run() {
  var captured = null;
  var hire = b.ai.adverseDecision.wrap({
    audit: false,
    name:        "hire-screening",
    model:       "screening-v3.1",
    legalBasis:  "ecoa-1002.9",
    decide:      function (subject) {
      return {
        outcome:          subject.score < 0.5 ? "adverse" : "favorable",
        score:            subject.score,
        principalReasons: subject.score < 0.5 ? ["insufficient-credit-history"] : [],
      };
    },
    onAdverse: function (subject, decision) { captured = decision; },
  });

  var favorable = await hire({ id: "good-1", score: 0.9 });
  check("favorable has no adverseNotice", favorable.adverseNotice === undefined);

  var adverse = await hire({ id: "bad-1", score: 0.1 });
  check("adverse has adverseNotice",                  adverse.adverseNotice !== undefined);
  check("adverseNotice carries subject id",           adverse.adverseNotice.subjectId === "bad-1");
  check("adverseNotice carries principal reasons",    adverse.adverseNotice.principalReasons.length === 1);
  check("adverseNotice carries regulation",           adverse.adverseNotice.regulation.indexOf("ECOA") !== -1);
  check("adverseNotice consumerRights.requestData",   adverse.adverseNotice.consumerRights.requestData === true);
  check("onAdverse hook fired",                       captured && captured.outcome === "adverse");

  var threwBadLegal = false;
  try {
    b.ai.adverseDecision.wrap({
      audit: false, name: "x", model: "x", legalBasis: "",
      decide: function () { return { outcome: "favorable" }; },
    });
  } catch (e) { threwBadLegal = e.code === "ai-adverse/bad-legal-basis"; }
  check("ai.adverseDecision refuses missing legalBasis", threwBadLegal);

  console.log("OK — ai.adverseDecision tests");
})().catch(function (e) { console.error(e); process.exit(1); });
