"use strict";
/**
 * b.audit.export({ format: "cadf" }) / b.auditTools.exportCadf —
 * CADF (Cloud Auditing Data Federation, ISO/IEC 19395:2017) envelope.
 * Covers F-RFC-2.
 */

var helpers = require("../helpers");
var b     = helpers.b;
var check = helpers.check;

async function run() {
  check("audit.export is fn",            typeof b.audit.export === "function");
  check("auditTools.exportCadf is fn",   typeof b.auditTools.exportCadf === "function");
  check("auditTools.exportAudit is fn",  typeof b.auditTools.exportAudit === "function");

  // Inject our own readRows to avoid coupling to the live audit chain.
  var fakeRows = [
    {
      _id:              "log-1",
      monotonicCounter: 1,
      recordedAt:       Date.UTC(2026, 4, 1, 12, 0, 0),
      action:           "user.login",
      outcome:          "success",
      actorUserId:      "alice",
      actorUserIdHash:  "h-alice",
      actorIp:          "10.0.0.5",
      actorSessionId:   "s-1",
      resourceKind:     "session",
      resourceId:       "s-1",
      reason:           null,
      metadata:         JSON.stringify({ method: "password" }),
      prevHash:         "00".repeat(64),
      rowHash:          "ab".repeat(64),
    },
    {
      _id:              "log-2",
      monotonicCounter: 2,
      recordedAt:       Date.UTC(2026, 4, 1, 12, 0, 5),
      action:           "subject.export",
      outcome:          "denied",
      actorUserId:      "bob",
      actorUserIdHash:  "h-bob",
      actorIp:          "10.0.0.6",
      resourceKind:     "subject",
      resourceId:       "u-42",
      reason:           "rate-limit",
      metadata:         null,
      prevHash:         "ab".repeat(64),
      rowHash:          "cd".repeat(64),
    },
  ];
  async function readRows(_criteria) { return fakeRows; }

  var bundle = await b.auditTools.exportCadf({
    from:     Date.UTC(2026, 4, 1),
    to:       Date.UTC(2026, 4, 2),
    readRows: readRows,
  });
  check("bundle has CADF batch typeURI",
    bundle.typeURI === "http://schemas.dmtf.org/cloud/audit/1.0/event-batch");
  check("bundle declares blamejs framework",
    bundle.framework === "blamejs");
  check("bundle has 2 events", bundle.events.length === 2);

  var ev0 = bundle.events[0];
  check("event has CADF event typeURI",
    ev0.typeURI === "http://schemas.dmtf.org/cloud/audit/1.0/event");
  check("event eventType=activity",         ev0.eventType === "activity");
  check("event preserves action verb",      ev0.action === "user.login");
  check("event maps success outcome",       ev0.outcome === "success");
  check("event initiator carries hash id",  ev0.initiator.id === "h-alice");
  check("event observer is blamejs",        ev0.observer.id.indexOf("blamejs:") === 0);
  check("event has chain anchor",           ev0["blamejs:chain"].monotonicCounter === 1);

  var ev1 = bundle.events[1];
  check("denied → CADF failure",            ev1.outcome === "failure");
  check("reason carried as reasonCode",     ev1.reason && ev1.reason.reasonCode === "rate-limit");

  // Dispatcher accepts format="cadf"
  var via = await b.audit.export({
    format:   "cadf",
    from:     Date.UTC(2026, 4, 1),
    readRows: readRows,
  });
  check("audit.export dispatch produces same shape",
    via.typeURI === "http://schemas.dmtf.org/cloud/audit/1.0/event-batch");

  // Bad format refused
  var threw = null;
  try { await b.audit.export({ format: "splunk-hec", readRows: readRows }); }
  catch (e) { threw = e; }
  check("unknown format → AuditToolsError",
    threw && (threw.code === "audit-tools/bad-format" || threw.isAuditToolsError));
}

module.exports = { run: run };
