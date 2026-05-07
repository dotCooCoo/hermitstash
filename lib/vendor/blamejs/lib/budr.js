"use strict";
/**
 * b.budr — backup, disaster-recovery, RTO/RPO declaration primitive.
 *
 * Operators in regulated environments (HIPAA / DORA / ISO 22301:2019 /
 * NIST SP 800-34) must declare their Recovery Time Objective (RTO,
 * how long systems can be down before unacceptable impact) and
 * Recovery Point Objective (RPO, max acceptable data loss). The
 * declaration is auditor-facing — regulators want it on file as part
 * of business-continuity / disaster-recovery documentation.
 *
 * The framework can't enforce RTO/RPO end-to-end (those depend on
 * downstream backup cadence, replication topology, restore testing).
 * What it can do: capture the operator's declared targets in a
 * tamper-evident audit row + expose them to dashboards.
 *
 * Public API:
 *
 *   b.budr.declare(opts) -> declaration
 *     opts:
 *       service:        operator-named service identifier (string).
 *       rtoMs:          Recovery Time Objective in milliseconds.
 *       rpoMs:          Recovery Point Objective in milliseconds.
 *       tier:           "platinum" / "gold" / "silver" / "bronze"
 *                       (BCDR criticality classification — platinum
 *                       most-critical).
 *       criticality:    "critical" / "high" / "medium" / "low".
 *       owner:          operator-named accountable owner (team / role).
 *       reviewedAt:     timestamp of the most recent operator review.
 *       citations:      array of regulatory citations (e.g. ["dora-art-11", "iso-22301:2019"]).
 *       audit:          bool, default true.
 *
 *   b.budr.list() -> Array<declaration>
 *
 *   b.budr.get(service) -> declaration | null
 */

var nb = require("./numeric-bounds");
var validateOpts = require("./validate-opts");
var audit = require("./audit");
var { defineClass } = require("./framework-error");
var BudrError = defineClass("BudrError", { alwaysPermanent: true });

var SERVICE_MAX = 128;                                                                        // allow:raw-byte-literal — string-length cap, not bytes
var SERVICE_RE = /^[a-zA-Z0-9._:/-]{1,128}$/;                                                 // allow:raw-byte-literal — string-length cap; not bytes
var TIERS = ["platinum", "gold", "silver", "bronze"];
var CRITICALITIES = ["critical", "high", "medium", "low"];

var declarations = new Map();

function declare(opts) {
  if (!opts || typeof opts !== "object") {
    throw BudrError.factory("BAD_OPTS", "budr.declare: opts required");
  }
  if (typeof opts.service !== "string" || opts.service.length === 0 ||
      opts.service.length > SERVICE_MAX || !SERVICE_RE.test(opts.service)) {
    throw BudrError.factory("BAD_SERVICE",
      "budr.declare: service must match " + SERVICE_RE);
  }
  nb.requirePositiveFiniteIntIfPresent(opts.rtoMs, "budr.declare: rtoMs", BudrError, "BAD_RTO");
  nb.requirePositiveFiniteIntIfPresent(opts.rpoMs, "budr.declare: rpoMs", BudrError, "BAD_RPO");
  if (typeof opts.rtoMs !== "number" || typeof opts.rpoMs !== "number") {
    throw BudrError.factory("BAD_TARGETS",
      "budr.declare: rtoMs and rpoMs are required positive integer milliseconds");
  }
  if (opts.tier !== undefined && TIERS.indexOf(opts.tier) === -1) {
    throw BudrError.factory("BAD_TIER",
      "budr.declare: tier must be one of " + TIERS.join(", "));
  }
  if (opts.criticality !== undefined && CRITICALITIES.indexOf(opts.criticality) === -1) {
    throw BudrError.factory("BAD_CRITICALITY",
      "budr.declare: criticality must be one of " + CRITICALITIES.join(", "));
  }
  validateOpts.optionalNonEmptyString(opts.owner,
    "budr.declare: owner", BudrError, "BAD_OWNER");
  if (opts.citations !== undefined && !Array.isArray(opts.citations)) {
    throw BudrError.factory("BAD_CITATIONS",
      "budr.declare: citations must be an array of strings");
  }

  var declaration = Object.freeze({
    service:     opts.service,
    rtoMs:       opts.rtoMs,
    rpoMs:       opts.rpoMs,
    tier:        opts.tier         || null,
    criticality: opts.criticality  || null,
    owner:       opts.owner        || null,
    citations:   Array.isArray(opts.citations) ? opts.citations.slice() : [],
    declaredAt:  Date.now(),
    reviewedAt:  typeof opts.reviewedAt === "number" ? opts.reviewedAt : Date.now(),
  });
  declarations.set(opts.service, declaration);

  if (opts.audit !== false) {
    audit.safeEmit({
      action:   "budr.declared",
      outcome:  "success",
      metadata: {
        service:     declaration.service,
        rtoMs:       declaration.rtoMs,
        rpoMs:       declaration.rpoMs,
        tier:        declaration.tier,
        criticality: declaration.criticality,
        owner:       declaration.owner,
        citations:   declaration.citations,
      },
    });
  }
  return declaration;
}

function get(service) {
  if (typeof service !== "string") return null;
  var rec = declarations.get(service);
  return rec === undefined ? null : rec;
}

function list() {
  return Array.from(declarations.values());
}

function _resetForTest() { declarations.clear(); }

module.exports = {
  declare:        declare,
  get:            get,
  list:           list,
  TIERS:          TIERS.slice(),
  CRITICALITIES:  CRITICALITIES.slice(),
  BudrError:      BudrError,
  _resetForTest:  _resetForTest,
};
