"use strict";
/**
 * @module b.budr
 * @nav    Production
 * @title  BC/DR
 *
 * @intro
 *   Backup / Disaster-Recovery RTO/RPO declaration primitive for
 *   regulated workloads (HIPAA / DORA / ISO 22301:2019 / NIST
 *   SP 800-34). Operators declare their Recovery Time Objective (max
 *   acceptable downtime) and Recovery Point Objective (max acceptable
 *   data loss) per service; the framework captures the targets in a
 *   tamper-evident audit row and exposes them via `list()` / `get()`
 *   for dashboard / regulator-export use.
 *
 *   The framework cannot enforce end-to-end RTO/RPO — those depend on
 *   downstream backup cadence, replication topology, and restore
 *   testing the operator owns. What it does enforce is the shape of
 *   the declaration (typed targets, BCDR tier vocabulary, regulator
 *   citation list) so the auditor-facing record stays consistent
 *   across services.
 *
 * @card
 *   Backup / Disaster-Recovery RTO/RPO declaration primitive for regulated workloads (HIPAA / DORA / ISO 22301:2019 / NIST SP 800-34).
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

/**
 * @primitive b.budr.declare
 * @signature b.budr.declare(opts)
 * @since     0.8.0
 * @status    stable
 * @compliance hipaa, dora, soc2
 * @related   b.budr.get, b.budr.list, b.dora.create
 *
 * Register a service's Recovery Time Objective + Recovery Point
 * Objective targets. Each call replaces the previous declaration for
 * the same `service` and emits a `budr.declared` audit row carrying
 * the typed targets, BCDR tier, criticality, owner, and regulator
 * citations. Throws `BudrError` on bad opts (unknown tier, missing
 * targets, citation list not an array).
 *
 * @opts
 *   service:     string (1..128 chars, [A-Za-z0-9._:/-]),
 *   rtoMs:       number  (positive finite integer milliseconds),
 *   rpoMs:       number  (positive finite integer milliseconds),
 *   tier:        "platinum" | "gold" | "silver" | "bronze",
 *   criticality: "critical" | "high" | "medium" | "low",
 *   owner:       string  (team / role accountable for restore),
 *   reviewedAt:  number  (ms-since-epoch of last operator review),
 *   citations:   Array<string>  (e.g. ["dora-art-11", "iso-22301:2019"]),
 *   audit:       boolean         (default true; set false to skip audit emit),
 *
 * @example
 *   var dec = b.budr.declare({
 *     service:     "payments-gateway",
 *     rtoMs:       60 * 60 * 1000,
 *     rpoMs:       5 * 60 * 1000,
 *     tier:        "platinum",
 *     criticality: "critical",
 *     owner:       "team-payments",
 *     citations:   ["dora-art-11", "iso-22301:2019"],
 *   });
 *   dec.tier;     // → "platinum"
 *   dec.rtoMs;    // → 3600000
 */
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

/**
 * @primitive b.budr.get
 * @signature b.budr.get(service)
 * @since     0.8.0
 * @status    stable
 * @related   b.budr.declare, b.budr.list
 *
 * Look up the registered declaration for `service`. Returns the
 * frozen declaration object on hit, `null` on miss or non-string
 * input. Cheap — purely an in-memory Map lookup.
 *
 * @example
 *   b.budr.declare({
 *     service: "core-ledger", rtoMs: 1800000, rpoMs: 60000,
 *     tier: "platinum", criticality: "critical",
 *   });
 *   var dec = b.budr.get("core-ledger");
 *   dec.rpoMs;                    // → 60000
 *   b.budr.get("not-registered"); // → null
 */
function get(service) {
  if (typeof service !== "string") return null;
  var rec = declarations.get(service);
  return rec === undefined ? null : rec;
}

/**
 * @primitive b.budr.list
 * @signature b.budr.list()
 * @since     0.8.0
 * @status    stable
 * @related   b.budr.declare, b.budr.get
 *
 * Snapshot of every registered declaration in insertion order.
 * Returns a fresh array — mutating it does not affect the registry.
 * Use this to drive a dashboard table or to export the operator's
 * BCDR posture for an auditor.
 *
 * @example
 *   b.budr.declare({
 *     service: "payments-gateway", rtoMs: 3600000, rpoMs: 300000,
 *     tier: "platinum", criticality: "critical",
 *   });
 *   b.budr.declare({
 *     service: "reporting", rtoMs: 14400000, rpoMs: 3600000,
 *     tier: "silver", criticality: "medium",
 *   });
 *   var all = b.budr.list();
 *   all.length;                   // → 2
 *   all[0].service;               // → "payments-gateway"
 */
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
