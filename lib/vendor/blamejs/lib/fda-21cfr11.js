"use strict";
/**
 * b.fda21cfr11 — FDA 21 CFR Part 11 audit-content + electronic-signature
 * shape primitives.
 *
 * Part 11 governs electronic records + electronic signatures for any
 * FDA-regulated activity (drugs, biologics, medical devices, food
 * safety, tobacco). The framework's audit chain already satisfies
 * §11.10(a)/(c)/(d)/(g) (validation, secure protected storage,
 * limited access, signed audit trail). This module closes the
 * remaining shape-of-content gaps:
 *
 *   §11.10(e) — Use of secure, computer-generated, time-stamped audit
 *               trails to independently record the date and time of
 *               operator entries and actions that create, modify, or
 *               delete electronic records.  RECORD MUST CARRY before /
 *               after / actor / reason / timestamp.
 *
 *   §11.50(b) — Signed electronic record must carry the printed name
 *               of the signer, the date and time when the signature
 *               was executed, and the meaning (such as review,
 *               approval, responsibility, or authorship) associated
 *               with the signature.
 *
 *   §11.70    — Electronic signatures and handwritten signatures
 *               executed to electronic records shall be linked to
 *               their respective electronic records to ensure that
 *               the signatures cannot be excised, copied, or otherwise
 *               transferred to falsify an electronic record by
 *               ordinary means.
 *
 * The primitive doesn't generate signatures itself — it produces the
 * §11.50(b) shape and binds it to an electronic record via SHA3-512
 * hash. Operators with a HSM-backed signer wire signatures through
 * `signWith(payload) → Buffer`. Without `signWith` the primitive
 * still produces the §11.50(b) shape; the operator's own signature
 * apparatus carries the binding.
 *
 *   var fda = b.fda21cfr11.posture({ audit: b.audit, signWith: signer });
 *   var sig = fda.electronicSignature.create({
 *     printedName:        "Jane Doe, M.D.",
 *     signatureMeaning:   "approval",
 *     predicateRule:      "21 CFR 312.62 — investigator records",
 *     boundRecord:        recordBytes,
 *   });
 *   // → { printedName, dateTimeUtc, signatureMeaning, signatureRecord,
 *   //     predicateRule, recordHash, signature? }
 *
 *   // §11.10(e) shape assertion against an audit row (or row-shaped
 *   // object with metadata.before / metadata.after).
 *   fda.assertGxpAudit(row);
 *
 * Posture interceptor — when wired, intercepts audit.safeEmit on
 * GxP-namespace events (default: namespaces listed in opts.gxpNamespaces
 * or any action under the "subject" / "consent" / "db" namespaces) and
 * refuses any event missing the §11.10(e) shape. Refused events are
 * audited as `fda21cfr11.audit.refused` so the violation is visible.
 *
 * Audit emissions:
 *   fda21cfr11.signature.created   — every electronicSignature.create
 *   fda21cfr11.signature.verified  — every electronicSignature.verify
 *   fda21cfr11.audit.refused       — every interceptor refusal
 *   fda21cfr11.posture.installed   — when posture interceptor wired
 *   fda21cfr11.gxp.assert_failed   — every assertGxpAudit failure
 */

var lazyRequire = require("./lazy-require");
var safeJson = require("./safe-json");
var validateOpts = require("./validate-opts");
var { sha3Hash } = require("./crypto");
var { Fda21Cfr11Error } = require("./framework-error");

var audit = lazyRequire(function () { return require("./audit"); });

// §11.50(b) signature meanings — operators may extend via opts.meanings
// at posture creation. The set below covers the verbiage FDA reviewers
// expect on Part 11-regulated records.
var DEFAULT_SIGNATURE_MEANINGS = Object.freeze([
  "review",
  "approval",
  "responsibility",
  "authorship",
  "verification",
  "release",
  "rejected",
  "witness",
]);

// Audit namespaces that the framework defaults to treating as "GxP-
// regulated" — every emit on these namespaces under fda-21cfr11 posture
// must carry §11.10(e) shape. Operators add more via opts.gxpNamespaces.
var DEFAULT_GXP_NAMESPACES = Object.freeze(["subject", "consent", "db", "breakglass"]);

// §11.10(e) — every modification audit must carry timestamp, actor,
// before/after pair, and a reason. The framework's audit row shape
// already carries `recordedAt` (timestamp) + `actorUserId` + `reason`;
// the gap is `metadata.before` and `metadata.after` — operators were
// putting them in by convention. Now enforced.
function _hasRequiredAuditShape(row) {
  if (!row || typeof row !== "object") {
    return { ok: false, reason: "row is not an object" };
  }
  // recordedAt may be raw ms or ISO; presence is what §11.10(e) asks.
  if (row.recordedAt === undefined || row.recordedAt === null) {
    return { ok: false, reason: "row missing recordedAt timestamp (§11.10(e))" };
  }
  // actor-binding — actorUserId or a sub-actor object that carries one
  // (the audit chain row has actorUserId; pre-emit shapes have actor.userId).
  var actorPresent = (row.actorUserId !== undefined && row.actorUserId !== null) ||
    (row.actor && typeof row.actor === "object" && row.actor.userId);
  if (!actorPresent) {
    return { ok: false, reason: "row missing actor identification (§11.10(e))" };
  }
  if (!row.action || typeof row.action !== "string") {
    return { ok: false, reason: "row missing action verb (§11.10(e))" };
  }
  // Modification-shaped events (verbs containing "update" / "modif" /
  // "delete" / "rectif" / "erase" / "set") must carry before/after.
  var verb = row.action.toLowerCase();
  var modShape = /\.(update|updated|modif|modified|delete|deleted|rectif|rectified|erase|erased|set|setrole|put|patched)\b/.test(verb) ||
    /\.(update|delete|modif|set|put|patch|rectif|erase)/.test(verb);
  if (modShape) {
    var meta = row.metadata;
    // Audit chain stores metadata as a JSON string when read back —
    // accept both raw object + JSON-string form.
    if (typeof meta === "string") {
      try { meta = safeJson.parse(meta); } catch (_e) { meta = null; }
    }
    if (!meta || typeof meta !== "object") {
      return { ok: false, reason: "row missing metadata.before/after for modification verb (§11.10(e))" };
    }
    if (meta.before === undefined) {
      return { ok: false, reason: "row missing metadata.before for modification verb (§11.10(e))" };
    }
    if (meta.after === undefined) {
      return { ok: false, reason: "row missing metadata.after for modification verb (§11.10(e))" };
    }
    if (!row.reason && (!meta.reason)) {
      return { ok: false, reason: "row missing reason for modification verb (§11.10(e))" };
    }
  }
  return { ok: true };
}

// ---- Signature shape ----

function _toRecordHash(record) {
  if (record === undefined || record === null) return null;
  if (Buffer.isBuffer(record)) return sha3Hash(record);
  if (typeof record === "string") return sha3Hash(Buffer.from(record, "utf8"));
  if (typeof record === "object") return sha3Hash(Buffer.from(JSON.stringify(record), "utf8"));
  throw new Fda21Cfr11Error("fda21cfr11/bad-bound-record",
    "electronicSignature.create: boundRecord must be Buffer|string|object");
}

function _validateSignatureInput(input, meanings) {
  if (!input || typeof input !== "object") {
    throw new Fda21Cfr11Error("fda21cfr11/bad-signature-input",
      "electronicSignature.create: input must be an object");
  }
  if (typeof input.printedName !== "string" || input.printedName.length === 0) {
    throw new Fda21Cfr11Error("fda21cfr11/missing-printed-name",
      "electronicSignature.create: printedName is required (§11.50(b))");
  }
  if (typeof input.signatureMeaning !== "string" || meanings.indexOf(input.signatureMeaning) === -1) {
    throw new Fda21Cfr11Error("fda21cfr11/bad-signature-meaning",
      "electronicSignature.create: signatureMeaning must be one of " +
      meanings.join(", ") + " (§11.50(b))");
  }
  if (typeof input.predicateRule !== "string" || input.predicateRule.length === 0) {
    throw new Fda21Cfr11Error("fda21cfr11/missing-predicate-rule",
      "electronicSignature.create: predicateRule is required (e.g. '21 CFR 312.62')");
  }
}

// ---- Public surface ----

function posture(opts) {
  opts = opts || {};
  validateOpts(opts, [
    "audit", "signWith", "verifyWith", "meanings", "gxpNamespaces",
    "interceptAudit", "now",
  ], "fda21cfr11.posture");
  validateOpts.auditShape(opts.audit, "fda21cfr11.posture",
    Fda21Cfr11Error, "fda21cfr11/bad-audit");
  validateOpts.optionalFunction(opts.signWith,
    "fda21cfr11.posture: signWith", Fda21Cfr11Error, "fda21cfr11/bad-signer");
  validateOpts.optionalFunction(opts.verifyWith,
    "fda21cfr11.posture: verifyWith", Fda21Cfr11Error, "fda21cfr11/bad-verifier");
  validateOpts.optionalFunction(opts.now,
    "fda21cfr11.posture: now", Fda21Cfr11Error, "fda21cfr11/bad-now");

  var auditMod = opts.audit && typeof opts.audit.safeEmit === "function" ? opts.audit : null;
  var signWith = typeof opts.signWith === "function" ? opts.signWith : null;
  var verifyWith = typeof opts.verifyWith === "function" ? opts.verifyWith : null;
  var meanings = Array.isArray(opts.meanings) && opts.meanings.length > 0
    ? opts.meanings.slice() : DEFAULT_SIGNATURE_MEANINGS.slice();
  var gxpNamespaces = Array.isArray(opts.gxpNamespaces) && opts.gxpNamespaces.length > 0
    ? opts.gxpNamespaces.slice() : DEFAULT_GXP_NAMESPACES.slice();
  var interceptAudit = opts.interceptAudit !== false;
  var now = typeof opts.now === "function" ? opts.now : Date.now;

  function _emit(action, metadata, outcome) {
    if (!auditMod) return;
    try {
      auditMod.safeEmit({
        action:   action,
        outcome:  outcome || "success",
        metadata: metadata || {},
      });
    } catch (_e) { /* audit best-effort */ }
  }

  function createSignature(input) {
    _validateSignatureInput(input, meanings);
    var ts = now();
    var dateTimeUtc = new Date(ts).toISOString();
    var recordHash = _toRecordHash(input.boundRecord);
    var payload = {
      printedName:      input.printedName,
      dateTimeUtc:      dateTimeUtc,
      signatureMeaning: input.signatureMeaning,
      predicateRule:    input.predicateRule,
      recordHash:       recordHash,
    };
    var signedPayload = JSON.stringify(payload);
    var signatureRecord = sha3Hash(Buffer.from(signedPayload, "utf8"));
    var sig = signWith ? signWith(Buffer.from(signedPayload, "utf8")) : null;
    var sigB64 = sig ? (Buffer.isBuffer(sig) ? sig.toString("base64") : String(sig)) : null;
    var out = {
      printedName:      payload.printedName,
      dateTimeUtc:      payload.dateTimeUtc,
      signatureMeaning: payload.signatureMeaning,
      predicateRule:    payload.predicateRule,
      recordHash:       payload.recordHash,
      signatureRecord:  signatureRecord,
      signature:        sigB64,
    };
    _emit("fda21cfr11.signature.created", {
      printedName:      out.printedName,
      signatureMeaning: out.signatureMeaning,
      predicateRule:    out.predicateRule,
      recordHash:       out.recordHash,
      signatureRecord:  out.signatureRecord,
    });
    return out;
  }

  function verifySignature(signed, boundRecord) {
    if (!signed || typeof signed !== "object") {
      throw new Fda21Cfr11Error("fda21cfr11/bad-verify-input",
        "electronicSignature.verify: signed must be a signature object");
    }
    var expectedHash = _toRecordHash(boundRecord);
    if (signed.recordHash !== expectedHash) {
      _emit("fda21cfr11.signature.verified", {
        printedName: signed.printedName, ok: false,
        reason: "record-hash-mismatch",
      }, "denied");
      return { ok: false, reason: "record-hash-mismatch" };
    }
    if (verifyWith && signed.signature) {
      var sigBuf = Buffer.from(signed.signature, "base64");
      var payload = JSON.stringify({
        printedName:      signed.printedName,
        dateTimeUtc:      signed.dateTimeUtc,
        signatureMeaning: signed.signatureMeaning,
        predicateRule:    signed.predicateRule,
        recordHash:       signed.recordHash,
      });
      var ok;
      try { ok = !!verifyWith(Buffer.from(payload, "utf8"), sigBuf); }
      catch (_e) { ok = false; }
      _emit("fda21cfr11.signature.verified", {
        printedName: signed.printedName, ok: ok,
      }, ok ? "success" : "denied");
      return { ok: ok, reason: ok ? null : "signature-verify-failed" };
    }
    _emit("fda21cfr11.signature.verified", {
      printedName: signed.printedName, ok: true,
    });
    return { ok: true };
  }

  function assertGxpAudit(row) {
    var rv = _hasRequiredAuditShape(row);
    if (!rv.ok) {
      _emit("fda21cfr11.gxp.assert_failed", {
        action: row && row.action, reason: rv.reason,
      }, "denied");
      throw new Fda21Cfr11Error("fda21cfr11/gxp-shape-violation",
        "21 CFR 11.10(e) audit shape violation: " + rv.reason);
    }
    return true;
  }

  function checkGxpAudit(row) {
    return _hasRequiredAuditShape(row);
  }

  // Posture interceptor — wraps b.audit.safeEmit so events on GxP
  // namespaces refuse-with-audit when their shape is incomplete.
  // Returns an `{ uninstall }` handle so tests / operator teardown
  // can detach.
  var _installed = false;
  var _originalSafeEmit = null;

  function install() {
    if (_installed) return { uninstall: uninstall };
    if (!interceptAudit) return { uninstall: function () {} };
    var auditMod = audit();
    _originalSafeEmit = auditMod.safeEmit;
    auditMod.safeEmit = function _gxpInterceptedSafeEmit(event) {
      if (!event || typeof event !== "object" || typeof event.action !== "string") {
        return _originalSafeEmit.call(auditMod, event);
      }
      var ns = event.action.split(".")[0];
      if (gxpNamespaces.indexOf(ns) === -1) {
        return _originalSafeEmit.call(auditMod, event);
      }
      var rv = _hasRequiredAuditShape(event);
      if (rv.ok) {
        return _originalSafeEmit.call(auditMod, event);
      }
      // Refusal — audit the refusal so the chain shows the violation,
      // but DON'T propagate the malformed event into the chain.
      try {
        _originalSafeEmit.call(auditMod, {
          action:   "fda21cfr11.audit.refused",
          outcome:  "denied",
          metadata: {
            attempted: event.action,
            reason:    rv.reason,
          },
        });
      } catch (_e) { /* drop-silent */ }
    };
    _installed = true;
    _emit("fda21cfr11.posture.installed", { gxpNamespaces: gxpNamespaces });
    return { uninstall: uninstall };
  }

  function uninstall() {
    if (!_installed || !_originalSafeEmit) return;
    var auditMod = audit();
    auditMod.safeEmit = _originalSafeEmit;
    _originalSafeEmit = null;
    _installed = false;
  }

  return {
    electronicSignature: {
      create: createSignature,
      verify: verifySignature,
      MEANINGS: meanings.slice(),
    },
    assertGxpAudit:  assertGxpAudit,
    checkGxpAudit:   checkGxpAudit,
    install:         install,
    uninstall:       uninstall,
    gxpNamespaces:   gxpNamespaces.slice(),
  };
}

// Module-level convenience for operators who don't need a posture
// instance — wires audit.safeEmit + Date.now and exposes the same
// surface via the singleton form.
var _singleton = null;
function _getSingleton() {
  if (_singleton) return _singleton;
  _singleton = posture({ audit: audit(), interceptAudit: false });
  return _singleton;
}

function _resetForTest() {
  if (_singleton) {
    try { _singleton.uninstall(); } catch (_e) { /* best-effort */ }
  }
  _singleton = null;
}

module.exports = {
  posture: posture,
  electronicSignature: {
    create: function (input) { return _getSingleton().electronicSignature.create(input); },
    verify: function (signed, record) { return _getSingleton().electronicSignature.verify(signed, record); },
    MEANINGS: DEFAULT_SIGNATURE_MEANINGS.slice(),
  },
  assertGxpAudit:           function (row) { return _getSingleton().assertGxpAudit(row); },
  checkGxpAudit:            function (row) { return _getSingleton().checkGxpAudit(row); },
  DEFAULT_SIGNATURE_MEANINGS: DEFAULT_SIGNATURE_MEANINGS,
  DEFAULT_GXP_NAMESPACES:     DEFAULT_GXP_NAMESPACES,
  Fda21Cfr11Error:            Fda21Cfr11Error,
  _resetForTest:              _resetForTest,
};
