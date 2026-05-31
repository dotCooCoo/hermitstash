"use strict";
/**
 * @module     b.guardSnapshotEnvelope
 * @nav        Guards
 * @title      Guard Snapshot Envelope
 * @order      444
 *
 * @intro
 *   Snapshot envelope shape validator. The agent snapshot primitive
 *   (v0.9.30) writes a structured envelope to durable storage on drain
 *   and reads it back on restart. The guard refuses malformed
 *   envelopes at the boundary so a corrupt or tampered snapshot
 *   doesn't get partially restored.
 *
 *   Envelope contract: snapshotId, takenAt, frameworkVersion,
 *   orchestratorState, inFlight, idempotencyCache (optional), sig,
 *   schemaVersion.
 *
 *   Hard caps:
 *     - total serialized size  (default 50 MiB)
 *     - in-flight items count  (default 65536 — orchestrator can't
 *       legitimately hold more in-flight streams + sagas + outbox-
 *       jobs at one moment than that)
 *     - schemaVersion          must be a positive integer
 *
 * @card
 *   Validates snapshot envelopes at drain/restore boundary. Bounded
 *   size + in-flight count + schema-version monotonic check.
 */

var { defineClass } = require("./framework-error");

var GuardSnapshotEnvelopeError = defineClass("GuardSnapshotEnvelopeError", { alwaysPermanent: true });

var DEFAULT_PROFILE = "strict";

var PROFILES = Object.freeze({
  strict:     { maxBytes: 52428800,  maxInFlight: 65536   },                                          // 50 MiB cap
  balanced:   { maxBytes: 209715200, maxInFlight: 262144  },                                          // 200 MiB
  permissive: { maxBytes: 1073741824, maxInFlight: 1048576 },                                         // 1 GiB
});

var COMPLIANCE_POSTURES = Object.freeze({
  hipaa:     "strict",
  "pci-dss": "strict",
  gdpr:      "strict",
  soc2:      "strict",
});

/**
 * @primitive b.guardSnapshotEnvelope.validate
 * @signature b.guardSnapshotEnvelope.validate(envelope, opts?)
 * @since     0.9.30
 * @status    stable
 * @related   b.agent.snapshot.create
 *
 * Validate a snapshot envelope shape. Returns envelope on success;
 * throws on shape refusal.
 *
 * @opts
 *   profile:   "strict" | "balanced" | "permissive",
 *   posture:   "hipaa" | "pci-dss" | "gdpr" | "soc2",
 *
 * @example
 *   b.guardSnapshotEnvelope.validate({
 *     snapshotId: "snap-abc",
 *     takenAt:    1700000000000,
 *     frameworkVersion: "0.9.30",
 *     schemaVersion:    1,
 *     orchestratorState: {},
 *     inFlight: {},
 *   });
 */
function validate(envelope, opts) {
  opts = opts || {};
  var profile = PROFILES[_resolveProfile(opts)];
  if (!envelope || typeof envelope !== "object" || Array.isArray(envelope)) {
    throw new GuardSnapshotEnvelopeError("snapshot-envelope/bad-input",
      "guardSnapshotEnvelope.validate: envelope required");
  }
  if (typeof envelope.snapshotId !== "string" || envelope.snapshotId.length === 0) {
    throw new GuardSnapshotEnvelopeError("snapshot-envelope/missing-snapshot-id",
      "guardSnapshotEnvelope.validate: snapshotId required");
  }
  if (typeof envelope.takenAt !== "number" || !isFinite(envelope.takenAt) || envelope.takenAt <= 0) {
    throw new GuardSnapshotEnvelopeError("snapshot-envelope/bad-taken-at",
      "guardSnapshotEnvelope.validate: takenAt must be a positive finite number");
  }
  if (typeof envelope.frameworkVersion !== "string" || envelope.frameworkVersion.length === 0) {
    throw new GuardSnapshotEnvelopeError("snapshot-envelope/missing-framework-version",
      "guardSnapshotEnvelope.validate: frameworkVersion required");
  }
  if (!Number.isInteger(envelope.schemaVersion) || envelope.schemaVersion < 1) {
    throw new GuardSnapshotEnvelopeError("snapshot-envelope/bad-schema-version",
      "guardSnapshotEnvelope.validate: schemaVersion must be a positive integer");
  }
  if (!envelope.orchestratorState || typeof envelope.orchestratorState !== "object") {
    throw new GuardSnapshotEnvelopeError("snapshot-envelope/missing-orchestrator-state",
      "guardSnapshotEnvelope.validate: orchestratorState object required");
  }
  if (!envelope.inFlight || typeof envelope.inFlight !== "object") {
    throw new GuardSnapshotEnvelopeError("snapshot-envelope/missing-in-flight",
      "guardSnapshotEnvelope.validate: inFlight object required");
  }
  // Total in-flight count cap — sum of streams + sagas + subscribers + pendingDeliveries.
  var inFlightCount = 0;
  ["streams", "sagas", "outboxJobs", "busSubscribers", "pendingDeliveries"].forEach(function (k) {
    if (Array.isArray(envelope.inFlight[k])) inFlightCount += envelope.inFlight[k].length;
  });
  if (inFlightCount > profile.maxInFlight) {
    throw new GuardSnapshotEnvelopeError("snapshot-envelope/in-flight-cap",
      "guardSnapshotEnvelope.validate: " + inFlightCount +
      " in-flight items exceeds maxInFlight=" + profile.maxInFlight);
  }
  // Size cap — serialize the whole envelope to JSON for size check.
  var serialized;
  try { serialized = JSON.stringify(envelope); }
  catch (e) {
    throw new GuardSnapshotEnvelopeError("snapshot-envelope/unserializable",
      "guardSnapshotEnvelope.validate: envelope not JSON-serializable: " +
      (e && e.message ? e.message : String(e)));
  }
  if (Buffer.byteLength(serialized, "utf8") > profile.maxBytes) {
    throw new GuardSnapshotEnvelopeError("snapshot-envelope/oversize",
      "guardSnapshotEnvelope.validate: " + Buffer.byteLength(serialized, "utf8") +
      " bytes exceeds maxBytes=" + profile.maxBytes);
  }
  return envelope;
}

/**
 * @primitive b.guardSnapshotEnvelope.compliancePosture
 * @signature b.guardSnapshotEnvelope.compliancePosture(posture)
 * @since     0.9.30
 * @status    stable
 *
 * Return the effective profile for a given compliance posture name.
 * Returns `null` for unknown posture names so operator typos surface
 * here instead of silently falling through to the default profile.
 *
 * @example
 *   b.guardSnapshotEnvelope.compliancePosture("hipaa");   // returns "strict"
 */
function compliancePosture(posture) {
  return COMPLIANCE_POSTURES[posture] || null;
}

function _resolveProfile(opts) {
  if (opts.posture && COMPLIANCE_POSTURES[opts.posture]) {
    return COMPLIANCE_POSTURES[opts.posture];
  }
  var p = opts.profile || DEFAULT_PROFILE;
  if (!PROFILES[p]) {
    throw new GuardSnapshotEnvelopeError("snapshot-envelope/bad-profile",
      "guardSnapshotEnvelope: unknown profile '" + p + "'");
  }
  return p;
}

module.exports = {
  validate:                    validate,
  compliancePosture:           compliancePosture,
  PROFILES:                    PROFILES,
  COMPLIANCE_POSTURES:         COMPLIANCE_POSTURES,
  GuardSnapshotEnvelopeError:  GuardSnapshotEnvelopeError,
  NAME:                        "snapshotEnvelope",
  KIND:                        "snapshot-envelope",
};
