// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.middleware.gpc — Sec-GPC (Global Privacy Control) middleware.
 *
 * Reads the `Sec-GPC: 1` request header (W3C Privacy Sandbox / IETF
 * draft-doty-gpc-header) and, when present, sets `req.gpcOptOut =
 * true` for downstream consumers. Optionally records the opt-out
 * via `b.consent` (when wired) so the operator's data-flow primitives
 * can refuse `sale`/`share`/`targeted-ads`/`profiling` purposes for
 * this session.
 *
 * Echoes a `Sec-GPC-Status: honored` response header per the
 * California Privacy Protection Agency's recommended posture so the
 * client UA can confirm honoring (and so audits show the
 * acknowledgement).
 *
 * Compliance context — Sec-GPC is **legally required** by:
 *   - California (CCPA / CPRA) — effective Jan 1 2024
 *   - Colorado, Connecticut, Texas, Oregon, Delaware, Montana, Iowa,
 *     Nebraska, New Hampshire, New Jersey, Maryland, Minnesota — effective
 *     dates vary; most by Jan 1 2026
 *
 * Operators handling US user traffic without honoring Sec-GPC face
 * regulator-action exposure (CPPA fines up to $7,500 per intentional
 * violation). The framework's posture is to honor by default; operators
 * who legitimately don't process the listed purposes still emit the
 * acknowledgement header so audits trace correctly.
 *
 *   var gpc = b.middleware.gpc({
 *     audit:   b.audit,
 *     consent: b.consent,           // optional — auto-records purpose-withdrawal
 *     mode:    "enforce",            // "enforce" | "audit-only"
 *   });
 *   app.use(gpc);
 *
 *   app.get("/api/data", function (req, res) {
 *     if (req.gpcOptOut) {
 *       // Don't serve targeted ads, don't share with data brokers, etc.
 *     }
 *   });
 */

var lazyRequire = require("../lazy-require");

var observability = lazyRequire(function () { return require("../observability"); });
void observability;

// Purposes the operator must NOT process when Sec-GPC: 1 is set, per
// CCPA/CPRA + the multi-state cohort. Operators consuming `req.gpcOptOut`
// gate these specific purposes.
var GPC_OPTOUT_PURPOSES = Object.freeze([
  "sale",
  "share",
  "targeted-ads",
  "cross-context-behavioral-advertising",
  "profiling",
]);

function _emitAudit(audit, action, outcome, metadata) {
  if (!audit || typeof audit.safeEmit !== "function") return;
  try {
    audit.safeEmit({
      action:   action,
      actor:    metadata.actor || { kind: "framework", id: "middleware/gpc" },
      outcome:  outcome,
      metadata: metadata,
    });
  } catch (_e) { /* drop-silent */ }
}

/**
 * @primitive b.middleware.gpc
 * @signature b.middleware.gpc(opts)
 * @since     0.1.0
 * @compliance ccpa, modpa
 * @related   b.middleware.cookies
 *
 * Sec-GPC (Global Privacy Control) handler. Reads the `Sec-GPC: 1`
 * inbound header and sets `req.gpcOptOut = true` for downstream
 * consumers. Echoes `Sec-GPC-Status: honored` so the UA + auditors
 * see the acknowledgement. Honoring Sec-GPC is legally required in
 * California (CCPA/CPRA) and a growing list of US states; operators
 * who don't process the listed purposes (`sale`, `share`,
 * `targeted-ads`, `cross-context-behavioral-advertising`,
 * `profiling`) still emit the acknowledgement so audits trace.
 * Optional `consent` integration auto-records purpose withdrawal.
 *
 * @opts
 *   {
 *     mode:         "enforce"|"audit-only",   // default "enforce"
 *     consent:      object,                    // b.consent instance
 *     statusHeader: boolean,                   // default true
 *     audit:        object,
 *   }
 *
 * @example
 *   var b = require("@blamejs/core");
 *   var app = b.router.create();
 *   app.use(b.middleware.gpc({ mode: "enforce" }));
 *   app.get("/api/data", function (req, res) {
 *     res.end(req.gpcOptOut ? "minimal" : "full");
 *   });
 */
function create(opts) {
  opts = opts || {};
  var mode = opts.mode || "enforce";
  var audit = opts.audit || null;
  var consentApi = opts.consent || null;
  var statusHeader = opts.statusHeader !== false;

  return function gpcMiddleware(req, res, next) {
    var rawHeader = (req.headers && req.headers["sec-gpc"]) || "";
    var optOut = rawHeader === "1";
    req.gpcOptOut = optOut;

    if (optOut) {
      // Stamp the acknowledgement header so the UA + auditors see we
      // honored.
      if (statusHeader && typeof res.setHeader === "function") {
        res.setHeader("Sec-GPC-Status", mode === "audit-only" ? "audit-only" : "honored");
      }

      // Optional integration with b.consent — record purpose
      // withdrawal so downstream consumers see the GPC signal as a
      // structured opt-out.
      if (consentApi && typeof consentApi.recordOptOut === "function") {
        try {
          consentApi.recordOptOut({
            req:       req,
            purposes:  GPC_OPTOUT_PURPOSES,
            source:    "sec-gpc",
            mode:      mode,
          });
        } catch (e) {
          _emitAudit(audit, "middleware.gpc.consent-error", "audit", {
            error: (e && e.message) || String(e),
          });
        }
      }

      _emitAudit(audit, "middleware.gpc.opt-out-honored", "success", {
        mode:     mode,
        purposes: GPC_OPTOUT_PURPOSES.slice(),
      });
    }
    return next();
  };
}

module.exports = {
  create:                create,
  GPC_OPTOUT_PURPOSES:   GPC_OPTOUT_PURPOSES,
};
