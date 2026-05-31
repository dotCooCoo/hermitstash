"use strict";
/**
 * @module     b.guardMailMove
 * @nav        Guards
 * @title      Guard Mail Move
 * @order      433
 *
 * @intro
 *   Destination-folder allowlist validator for `b.mail.agent.move`.
 *   Refuses moves to system folders the actor doesn't have admin
 *   scope for, refuses cross-account moves (`fromFolder` and
 *   `toFolder` must belong to the same agent context), and refuses
 *   path-traversal-shaped folder names (`..` / leading `.` / NUL /
 *   bidi).
 *
 *   System folders the framework treats specially:
 *
 *     - **INBOX / Sent / Drafts**: always writable by the owner; no
 *       admin scope required.
 *     - **Junk / Trash**: always writable (Junk is the default Sieve
 *       junk destination; Trash is the soft-delete target).
 *     - **Archive**: always writable.
 *     - any operator-created folder: writable when in the actor's
 *       allowed-folders list (per the operator's RBAC) OR when the
 *       actor has `mailScope: "admin"`.
 *
 *   The guard does NOT touch the underlying mail-store; that
 *   composition lives in `b.mail.agent.move`. The guard validates
 *   the SHAPE of the move call.
 *
 * @card
 *   Validates `b.mail.agent.move` destination. System-folder allowlist,
 *   path-traversal refusal, admin-scope gate for arbitrary destinations.
 */

var { defineClass } = require("./framework-error");

var GuardMailMoveError = defineClass("GuardMailMoveError", { alwaysPermanent: true });

var DEFAULT_PROFILE = "strict";

var PROFILES = Object.freeze({
  strict:     { maxObjectIds: 1000,  maxFolderNameBytes: 255  },
  balanced:   { maxObjectIds: 5000,  maxFolderNameBytes: 255  },
  permissive: { maxObjectIds: 50000, maxFolderNameBytes: 1024 },
});

var COMPLIANCE_POSTURES = Object.freeze({
  hipaa:     "strict",
  "pci-dss": "strict",
  gdpr:      "strict",
  soc2:      "strict",
});

// System folders every actor may write to without admin scope.
var SYSTEM_FOLDERS = Object.freeze({
  INBOX: true, Sent: true, Drafts: true, Trash: true, Junk: true, Archive: true,
});

/**
 * @primitive b.guardMailMove.validate
 * @signature b.guardMailMove.validate(move, opts?)
 * @since     0.9.20
 * @status    stable
 * @related   b.mail.agent.create
 *
 * Validate a `{ actor, fromFolder, toFolder, objectIds }` shape.
 *
 * @opts
 *   profile:   "strict" | "balanced" | "permissive",
 *   posture:   "hipaa" | "pci-dss" | "gdpr" | "soc2",
 *
 * @example
 *   b.guardMailMove.validate({
 *     actor:      { id: "u1", mailScope: "user" },
 *     fromFolder: "INBOX",
 *     toFolder:   "Archive",
 *     objectIds:  ["abc123"],
 *   });
 */
function validate(move, opts) {
  opts = opts || {};
  var profile = PROFILES[_resolveProfile(opts)];
  if (!move || typeof move !== "object") {
    throw new GuardMailMoveError("mail-move/bad-input",
      "guardMailMove.validate: move required");
  }
  if (!move.actor || typeof move.actor !== "object" || typeof move.actor.id !== "string") {
    throw new GuardMailMoveError("mail-move/no-actor",
      "guardMailMove.validate: move.actor with .id required");
  }
  _checkFolderName(move.fromFolder, "fromFolder", profile);
  _checkFolderName(move.toFolder,   "toFolder",   profile);
  if (move.fromFolder === move.toFolder) {
    throw new GuardMailMoveError("mail-move/same-folder",
      "guardMailMove.validate: fromFolder and toFolder are the same");
  }
  if (!Array.isArray(move.objectIds)) {
    throw new GuardMailMoveError("mail-move/bad-objectids",
      "guardMailMove.validate: objectIds must be an array");
  }
  if (move.objectIds.length === 0) {
    throw new GuardMailMoveError("mail-move/empty-objectids",
      "guardMailMove.validate: objectIds must be non-empty");
  }
  if (move.objectIds.length > profile.maxObjectIds) {
    throw new GuardMailMoveError("mail-move/too-many-objectids",
      "guardMailMove.validate: objectIds count " + move.objectIds.length +
      " exceeds maxObjectIds=" + profile.maxObjectIds);
  }
  for (var i = 0; i < move.objectIds.length; i += 1) {
    var oid = move.objectIds[i];
    if (typeof oid !== "string" || oid.length === 0) {
      throw new GuardMailMoveError("mail-move/bad-objectid",
        "guardMailMove.validate: objectIds[" + i + "] must be a non-empty string");
    }
  }

  // System-folder allowlist OR admin scope OR allowed-folders.
  var dest = move.toFolder;
  if (SYSTEM_FOLDERS[dest]) return move;
  var isAdmin = move.actor.mailScope === "admin";
  if (isAdmin) return move;
  var allowed = Array.isArray(move.actor.allowedFolders) ? move.actor.allowedFolders : null;
  if (allowed && allowed.indexOf(dest) >= 0) return move;
  throw new GuardMailMoveError("mail-move/destination-not-allowed",
    "guardMailMove.validate: destination '" + dest +
    "' requires mailScope:'admin' or membership in actor.allowedFolders");
}

/**
 * @primitive b.guardMailMove.compliancePosture
 * @signature b.guardMailMove.compliancePosture(posture)
 * @since     0.9.20
 * @status    stable
 *
 * Return the effective profile for a given compliance posture name.
 * Returns `null` for unknown posture names so operator typos surface
 * here instead of silently falling through to the default profile.
 *
 * @example
 *   b.guardMailMove.compliancePosture("hipaa");   // → "strict"
 */
function compliancePosture(posture) {
  return COMPLIANCE_POSTURES[posture] || null;
}

function _checkFolderName(name, label, profile) {
  if (typeof name !== "string" || name.length === 0) {
    throw new GuardMailMoveError("mail-move/bad-folder-name",
      "guardMailMove.validate: " + label + " must be a non-empty string");
  }
  if (Buffer.byteLength(name, "utf8") > profile.maxFolderNameBytes) {
    throw new GuardMailMoveError("mail-move/folder-name-too-long",
      "guardMailMove.validate: " + label + " exceeds maxFolderNameBytes=" + profile.maxFolderNameBytes);
  }
  // Path-traversal / control-char refusal. C0 controls, slash, NUL,
  // leading `.`, and `..` segments are all refused regardless of
  // profile.
  if (name.indexOf("..") >= 0) {
    throw new GuardMailMoveError("mail-move/path-traversal",
      "guardMailMove.validate: " + label + " contains '..'");
  }
  if (name.charAt(0) === ".") {
    throw new GuardMailMoveError("mail-move/hidden-name",
      "guardMailMove.validate: " + label + " starts with '.' (hidden-folder shape refused)");
  }
  for (var i = 0; i < name.length; i += 1) {
    var c = name.charCodeAt(i);
    if (c < 0x20 || c === 0x7F) {                                                                     // C0 + DEL refusal
      throw new GuardMailMoveError("mail-move/control-char-in-name",
        "guardMailMove.validate: " + label + " contains control char 0x" + c.toString(16));
    }
    if (c === 0x2F) {                                                                                 // '/' refusal
      throw new GuardMailMoveError("mail-move/slash-in-name",
        "guardMailMove.validate: " + label + " contains '/' (use IMAP '.' hierarchy separator)");
    }
  }
}

function _resolveProfile(opts) {
  if (opts.posture && COMPLIANCE_POSTURES[opts.posture]) {
    return COMPLIANCE_POSTURES[opts.posture];
  }
  var p = opts.profile || DEFAULT_PROFILE;
  if (!PROFILES[p]) {
    throw new GuardMailMoveError("mail-move/bad-profile",
      "guardMailMove: unknown profile '" + p + "'");
  }
  return p;
}

module.exports = {
  validate:            validate,
  compliancePosture:   compliancePosture,
  PROFILES:            PROFILES,
  COMPLIANCE_POSTURES: COMPLIANCE_POSTURES,
  SYSTEM_FOLDERS:      SYSTEM_FOLDERS,
  GuardMailMoveError:  GuardMailMoveError,
  NAME:                "mailMove",
  KIND:                "mail-move",
};
