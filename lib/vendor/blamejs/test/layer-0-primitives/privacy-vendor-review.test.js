// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
// b.privacy.vendorReview + b.privacy.listVendorReviewClauses — FERPA / SOPIPA
// EdTech vendor-review attestation builder (pure; no DB).

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

var ALL_TRUE = {
  educationalPurposeOnly: true, noTargetedAdvertising: true, noCommercialProfiling: true,
  noSaleOfStudentData:    true, securitySafeguards:    true, deletionOnRequest:     true,
  subProcessorsCurrent:   true, breachNotification:    true, schoolOfficialDesignation: true,
};

function run() {
  check("vendorReview is a function",               typeof b.privacy.vendorReview === "function");
  check("listVendorReviewClauses is a function",    typeof b.privacy.listVendorReviewClauses === "function");
  check("PrivacyError exposed on b.frameworkError", typeof b.frameworkError.PrivacyError === "function");
  check("b.privacy.PrivacyError is the same constructor",
        b.privacy.PrivacyError === b.frameworkError.PrivacyError);

  var clauses = b.privacy.listVendorReviewClauses();
  check("clauses: frozen array",                    Array.isArray(clauses) && Object.isFrozen(clauses));
  check("clauses: >= 9 entries",                    clauses.length >= 9);
  check("clauses: each has id + citation + required boolean",
        clauses.every(function (c) { return typeof c.id === "string" && typeof c.citation === "string" && typeof c.required === "boolean"; }));
  check("clauses: educationalPurposeOnly is required",
        clauses.some(function (c) { return c.id === "educationalPurposeOnly" && c.required === true; }));

  // All required clauses true → attested, no gaps, 365-day next review clock.
  var reviewedAt = 1700000000000;
  var ok = b.privacy.vendorReview({ vendorName: "Acme LMS", reviewedAt: reviewedAt, clauses: ALL_TRUE });
  check("vendorReview: attested when all required true", ok.attested === true);
  check("vendorReview: no gaps",                         ok.gaps.length === 0);
  check("vendorReview: nextReviewDueAt = reviewedAt + 365 days",
        ok.nextReviewDueAt === reviewedAt + b.constants.TIME.days(365));
  check("vendorReview: report frozen",                   Object.isFrozen(ok));
  check("vendorReview: vendorName carried",              ok.vendorName === "Acme LMS");
  check("vendorReview: coversPeriod is the prior year",  ok.coversPeriod.to === reviewedAt && ok.coversPeriod.from === reviewedAt - b.constants.TIME.days(365));

  // One required clause false → not attested + the gap is named.
  var partial = Object.assign({}, ALL_TRUE, { noSaleOfStudentData: false });
  var gap = b.privacy.vendorReview({ vendorName: "Acme", reviewedAt: reviewedAt, clauses: partial });
  check("vendorReview: not attested on a required gap",  gap.attested === false);
  check("vendorReview: gap names the failed clause",     gap.gaps.indexOf("noSaleOfStudentData") !== -1);

  // The one optional clause omitted still attests.
  check("vendorReview: optional clause omitted still attests",
        b.privacy.vendorReview({ vendorName: "A", reviewedAt: reviewedAt, clauses: ALL_TRUE }).attested === true);

  // Config-time throws (rule §5 — entry-point tier).
  function expectCode(label, fn, code) {
    var threw = null;
    try { fn(); } catch (e) { threw = e; }
    check(label, threw && (threw.code || "") === code);
  }
  expectCode("missing vendorName throws",
             function () { b.privacy.vendorReview({ reviewedAt: reviewedAt, clauses: ALL_TRUE }); }, "privacy/bad-vendor");
  expectCode("non-boolean clause value throws",
             function () { b.privacy.vendorReview({ vendorName: "A", reviewedAt: reviewedAt, clauses: { noSaleOfStudentData: "yes" } }); }, "privacy/bad-clause-value");
  expectCode("unknown clause key throws",
             function () { b.privacy.vendorReview({ vendorName: "A", reviewedAt: reviewedAt, clauses: { bogusClause: true } }); }, "privacy/unknown-clause");
  expectCode("missing reviewedAt throws",
             function () { b.privacy.vendorReview({ vendorName: "A", clauses: ALL_TRUE }); }, "privacy/bad-reviewed-at");
  expectCode("non-object opts throws",
             function () { b.privacy.vendorReview("nope"); }, "privacy/bad-opts");
}

module.exports = { run: run };
