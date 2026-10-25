// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module b.fda21cfr11
 * @nav    Compliance
 * @title  FDA 21 CFR Part 11
 * @slug   fda-21cfr11
 *
 * @intro
 *   What 21 CFR Part 11 asks of a system keeping electronic records and
 *   accepting electronic signatures, enforced rather than described.
 *
 *   An electronic signature under 11.50 is not a signature unless it records
 *   who signed, when, and what the signing meant, so one is built with a
 *   meaning from the permitted set and is refused without it. The signature is
 *   bound to a digest of the record, which makes it a signature of that record
 *   rather than a note attached to it.
 *
 *   The 11.10(e) audit requirement is checked on the events themselves. Every
 *   event in a GxP namespace has to carry <code>recordedAt</code>, an actor as
 *   either <code>actorUserId</code> or <code>actor.userId</code>, and a string
 *   <code>action</code>.
 *
 *   An action whose last segment is not a reading verb is a modification, and
 *   a modification has to say what changed: <code>metadata.before</code>,
 *   <code>metadata.after</code> and a reason, on the row or in the metadata.
 *   That is the difference between an audit trail and a log. The posture can
 *   intercept the audit sink, and an event missing any of it is then dropped
 *   instead of written, with a denied event recorded in its place. The drop is
 *   silent to the code that emitted it, so a deployment that wants the failure
 *   to reach its own code calls <code>assertGxpAudit</code> on the row first.
 *   Reads are recorded too, because under Part 11 who looked is part of the
 *   record.
 *
 * @card
 *   21 CFR Part 11 enforced in the running system: electronic signatures bound
 *   to a record digest with a declared meaning, and 11.10(e) audit shape
 *   checked as each GxP event is written.
 */

var lazyRequire = require("./lazy-require");
var safeJson = require("./safe-json");
var validateOpts = require("./validate-opts");
var { sha3Hash } = require("./crypto");
var { Fda21Cfr11Error } = require("./framework-error");

var audit = lazyRequire(function () { return require("./audit"); });

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

var DEFAULT_GXP_NAMESPACES = Object.freeze(["subject", "consent", "db", "breakglass"]);

var READ_VERBS = Object.freeze({
  read: 1, viewed: 1, view: 1, get: 1, got: 1, list: 1, listed: 1, query: 1,
  queried: 1, access: 1, accessed: 1, export: 1, exported: 1, history: 1,
  isgranted: 1, check: 1, checked: 1, verify: 1, verified: 1, lookup: 1,
  search: 1, searched: 1, fetch: 1, fetched: 1, render: 1, rendered: 1,
  download: 1, downloaded: 1,
});

function _hasRequiredAuditShape(row) {
  if (!row || typeof row !== "object") {
    return { ok: false, reason: "row is not an object" };
  }
  if (row.recordedAt === undefined || row.recordedAt === null) {
    return { ok: false, reason: "row missing recordedAt timestamp (§11.10(e))" };
  }
  var actorPresent = (row.actorUserId !== undefined && row.actorUserId !== null) ||
    (row.actor && typeof row.actor === "object" && row.actor.userId);
  if (!actorPresent) {
    return { ok: false, reason: "row missing actor identification (§11.10(e))" };
  }
  if (!row.action || typeof row.action !== "string") {
    return { ok: false, reason: "row missing action verb (§11.10(e))" };
  }
  var verb = row.action.toLowerCase();
  var lastSeg = verb.indexOf(".") === -1 ? verb : verb.slice(verb.lastIndexOf(".") + 1);
  var modShape = !Object.prototype.hasOwnProperty.call(READ_VERBS, lastSeg);
  if (modShape) {
    var meta = row.metadata;
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

/**
 * @primitive b.fda21cfr11.posture
 * @signature b.fda21cfr11.posture(opts?)
 * @since     0.8.44
 * @status    stable
 * @compliance hipaa, soc2
 * @related   b.fda21cfr11.assertGxpAudit, b.audit.record, b.auditSign.init
 *
 * Build the Part 11 posture. The returned object carries
 * `electronicSignature` with `create` and `verify`, the audit checks
 * `assertGxpAudit` and `checkGxpAudit`, and `install` / `uninstall` for the
 * audit interception.
 *
 * `meanings` is the set of signing meanings a signature may declare, and
 * defaults to review, approval, responsibility, authorship, verification,
 * release, rejected and witness. A signature declaring anything else is
 * refused, since
 * 11.50 requires the meaning to be recorded and an unconstrained string is not
 * a recorded meaning.
 *
 * `gxpNamespaces` is which audit events the 11.10(e) shape is enforced on, and
 * defaults to `subject`, `consent`, `db` and `breakglass`. With
 * `interceptAudit` left on, installing wraps the audit sink so an event in one
 * of those namespaces missing the required fields is dropped rather than
 * written, and a denied `fda21cfr11.audit.refused` naming the attempted action
 * and the missing part is written instead. `safeEmit` does not raise, so the
 * emitting code carries on; `assertGxpAudit` is the call that reports the
 * failure to the caller.
 *
 * `signWith` and `verifyWith` supply the signing and verification, so the
 * deployment's own key custody is used rather than one invented here. Both
 * receive the canonical signed payload as a Buffer, the JSON carrying the
 * printed name, timestamp, meaning, predicate rule and record digest, and not
 * a digest of it: `signWith(payload)` returns the signature, and
 * `verifyWith(payload, signature)` answers whether it holds. The payload is
 * passed whole so a signer can apply its own digest, which is what an HSM or a
 * KMS expects.
 *
 * @opts
 *   signWith:       object,   // function (payloadBuffer) returning a signature
 *   verifyWith:     object,   // function (payloadBuffer, signature) → boolean
 *   meanings:       array,    // permitted signing meanings
 *   gxpNamespaces:  array,    // audit namespaces the shape is enforced on
 *   interceptAudit: boolean,  // false leaves the audit sink alone
 *   audit:          object,   // audit instance to record to
 *   now:            object,   // function returning epoch ms; for tests
 *
 * A signature's input needs `printedName`, a `signatureMeaning` from the
 * permitted set, and `predicateRule`, the regulation the signing is made
 * under. Each has its own refusal code, because 11.50(b) requires the printed
 * name and the meaning to be part of the signed record rather than metadata
 * beside it. `boundRecord` is what the signature is a signature of: it is
 * digested into the signed payload, and `verify` recomputes that digest from
 * the record it is given, so a signature presented against different content
 * answers `record-hash-mismatch`.
 *
 * Without `signWith` and `verifyWith` the signature field is `null` and
 * `verify` only recomputes the record digest, which is unkeyed: anyone who can
 * change the record can recompute it and have the result verify. That mode is
 * for checking the shape of a record, not for signing one. A Part 11
 * signature needs both hooks wired to the deployment's signing key.
 *
 * @example
 *   var b = require("@blamejs/core");
 *   var crypto = require("node:crypto");
 *   var key = crypto.randomBytes(32);
 *   var part11 = b.fda21cfr11.posture({
 *     meanings:   ["approval", "review"],
 *     signWith:   function (payload) {
 *       return crypto.createHmac("sha3-512", key).update(payload).digest();
 *     },
 *     verifyWith: function (payload, signature) {
 *       var want = crypto.createHmac("sha3-512", key).update(payload).digest();
 *       return want.length === signature.length &&
 *         crypto.timingSafeEqual(want, signature);
 *     },
 *   });
 *   var batch = { batchId: "B-204", released: true };
 *   var signed = part11.electronicSignature.create({
 *     printedName:      "Dr. A. Chen",
 *     signatureMeaning: "approval",
 *     predicateRule:    "21 CFR 312.62",
 *     boundRecord:      batch,
 *   });
 *   part11.electronicSignature.verify(signed, batch).ok;        // → true
 *   part11.electronicSignature.verify(signed, { batchId: "B-205" }).reason;
 *   // → "record-hash-mismatch"
 */
function posture(opts) {
  opts = opts || {};
  validateOpts(opts, [
    "audit", "signWith", "verifyWith", "meanings", "gxpNamespaces",
    "interceptAudit", "now",
  ], "fda21cfr11.posture");
  validateOpts.shape(opts, {
    audit: function (value) {
      validateOpts.auditShape(value, "fda21cfr11.posture",
        Fda21Cfr11Error, "fda21cfr11/bad-audit");
    },
    signWith:       { rule: "optional-function", code: "fda21cfr11/bad-signer" },
    verifyWith:     { rule: "optional-function", code: "fda21cfr11/bad-verifier" },
    now:            { rule: "optional-function", code: "fda21cfr11/bad-now" },
    meanings:       { rule: "optional-string-array", code: "fda21cfr11/bad-meanings" },
    gxpNamespaces:  { rule: "optional-string-array", code: "fda21cfr11/bad-gxp-namespaces" },
    interceptAudit: { rule: "optional-boolean", code: "fda21cfr11/bad-intercept-audit" },
  }, "fda21cfr11.posture", Fda21Cfr11Error, "fda21cfr11/bad-opts");

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
    if (verifyWith) {
      if (!signed.signature) {
        _emit("fda21cfr11.signature.verified", {
          printedName: signed.printedName, ok: false, reason: "signature-required",
        }, "denied");
        return { ok: false, reason: "signature-required" };
      }
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

  /**
   * @primitive b.fda21cfr11.assertGxpAudit
   * @signature b.fda21cfr11.assertGxpAudit(row)
   * @since     0.8.44
   * @status    stable
   * @compliance hipaa, soc2
   * @related   b.fda21cfr11.checkGxpAudit, b.fda21cfr11.posture
   *
   * Require an audit row to carry the 11.10(e) shape, and raise
   * `fda21cfr11/gxp-shape-violation` naming the missing part otherwise.
   *
   * Every row needs `recordedAt`, an actor as `actorUserId` or
   * `actor.userId`, and a string `action`. When the action's last segment is
   * not a reading verb the row is a modification and also needs
   * `metadata.before`, `metadata.after` and a reason, as `row.reason` or
   * `metadata.reason`.
   *
   * Call this where a failure should reach the caller, which is while the row
   * is being built. The refusal is itself recorded as a denied
   * `fda21cfr11.gxp.assert_failed` event, so a rejected write leaves a trace
   * rather than disappearing.
   *
   * The installed interception does not call this. It applies the same shape
   * check inside `b.audit.safeEmit`, and a row that fails the check is dropped
   * and recorded as a denied `fda21cfr11.audit.refused` without raising:
   * `safeEmit` runs on the request path, and a throw there would fail the
   * request that was only writing an audit row. Interception keeps a malformed
   * GxP row out of the chain; it does not report back to the code that wrote
   * it.
   *
   * @example
   *   var b = require("@blamejs/core");
   *   b.fda21cfr11.assertGxpAudit({
   *     action:      "subject.consent.granted",   // a modification verb
   *     actorUserId: "dr.chen",
   *     recordedAt:  Date.now(),
   *     reason:      "signed consent form received",
   *     metadata:    { before: { consent: false }, after: { consent: true } },
   *   });                            // → true
   */
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

  /**
   * @primitive b.fda21cfr11.checkGxpAudit
   * @signature b.fda21cfr11.checkGxpAudit(row)
   * @since     0.8.44
   * @status    stable
   * @compliance hipaa, soc2
   * @related   b.fda21cfr11.assertGxpAudit, b.fda21cfr11.posture
   *
   * Answer `{ ok, reason }` for an audit row's 11.10(e) shape without raising.
   *
   * This is the form to use while building a row or while surveying rows
   * already written, where a throw would stop the survey at the first finding.
   * `assertGxpAudit` is the enforcing form.
   *
   * @example
   *   var b = require("@blamejs/core");
   *   b.fda21cfr11.checkGxpAudit({ action: "subject.read" });
   *   // → { ok: false, reason: "…the field it is missing…" }
   */
  function checkGxpAudit(row) {
    return _hasRequiredAuditShape(row);
  }

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
