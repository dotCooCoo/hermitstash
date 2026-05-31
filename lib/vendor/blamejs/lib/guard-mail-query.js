"use strict";
/**
 * @module     b.guardMailQuery
 * @nav        Guards
 * @title      Guard Mail Query
 * @order      430
 *
 * @intro
 *   Search / fetch / changes filter validator for `b.mail.agent`. Refuses
 *   filter shapes that can't safely cross the worker-thread or queue
 *   boundary (functions, regex objects with state, Date objects with
 *   non-finite values, cycles), enforces a projection-column allowlist
 *   against the mail-store schema, and pins the per-actor fields that
 *   the active compliance posture requires (HIPAA → `purposeOfUse`;
 *   PCI-DSS → `pciScope`; GDPR → `lawfulBasis`).
 *
 *   Composes `b.guardJson` (via `validate(JSON.stringify(filter))`-shape
 *   guard) at the structural level and adds mail-specific rules: the
 *   filter is recursively walked once with a depth cap, no operator
 *   key is allowed outside the documented set, and any field-name
 *   used as a comparator key must be in `FILTERABLE_COLUMNS`.
 *
 * @card
 *   Validates `b.mail.agent.search` / `Email/query` filter specs.
 *   Pure-data only (no functions / regex), bounded depth, projection
 *   allowlist, posture-required actor fields.
 */

var { defineClass } = require("./framework-error");

var GuardMailQueryError = defineClass("GuardMailQueryError", { alwaysPermanent: true });

var DEFAULT_PROFILE = "strict";

var PROFILES = Object.freeze({
  strict:     { maxDepth: 8,  maxKeys: 64,  maxStringBytes: 8192,  maxArrayLen: 256 },                // caps for filter spec
  balanced:   { maxDepth: 16, maxKeys: 128, maxStringBytes: 16384, maxArrayLen: 1024 },
  permissive: { maxDepth: 24, maxKeys: 512, maxStringBytes: 65536, maxArrayLen: 4096 },
});

var COMPLIANCE_POSTURES = Object.freeze({
  hipaa:     "strict",
  "pci-dss": "strict",
  gdpr:      "strict",
  soc2:      "strict",
});

// Columns the filter may reference and the projection may request.
// Sealed columns can be `=` / `IN` matched (the mail-store walks
// derivedHashes for the equality form); range / LIKE matches are only
// allowed against plaintext columns.
var FILTERABLE_COLUMNS = Object.freeze({
  objectid:       { kind: "plaintext", ops: ["eq", "in"] },
  modseq:         { kind: "plaintext", ops: ["eq", "gt", "lt", "ge", "le", "in"] },
  internal_date:  { kind: "plaintext", ops: ["eq", "gt", "lt", "ge", "le"] },
  received_at:    { kind: "plaintext", ops: ["eq", "gt", "lt", "ge", "le"] },
  size_bytes:     { kind: "plaintext", ops: ["eq", "gt", "lt", "ge", "le"] },
  thread_root_id: { kind: "plaintext", ops: ["eq", "in"] },
  legal_hold:     { kind: "plaintext", ops: ["eq"] },
  message_id:     { kind: "sealed",    ops: ["eq", "in"] },
  from_addr:      { kind: "sealed",    ops: ["eq", "in"] },
  subject:        { kind: "sealed",    ops: ["eq"] },
  flag:           { kind: "join",      ops: ["eq", "in"] },
  // v0.11.25 — sealed-token FTS filter keys. These accept a literal
  // string value; the agent layer hands them to `b.mailStore.search`
  // which tokenizes + vault-salt-hashes them before issuing the FTS5
  // MATCH. Bounded by `maxStringBytes` via `_checkScalar` so a single
  // term cannot carry a tokenizer-bomb shape.
  text:           { kind: "fts",       ops: ["eq"] },
  body:           { kind: "fts",       ops: ["eq"] },
  from:           { kind: "fts",       ops: ["eq"] },
  to:             { kind: "fts",       ops: ["eq"] },
  // Modseq + limit shortcuts so callers can pass `{ sinceModseq, limit,
  // text }` directly instead of the verbose `{ and:[{modseq:{gt}}, ...] }`
  // shape.
  sinceModseq:    { kind: "plaintext", ops: ["eq"] },
  limit:          { kind: "plaintext", ops: ["eq"] },
});

var ALLOWED_OPS = Object.freeze({
  eq: true, in: true, gt: true, lt: true, ge: true, le: true,
  and: true, or: true, not: true,
});

// Per-posture actor required fields. Operator must supply these on the
// agent actor object for any read/write op under the matching posture
// — refused otherwise.
var POSTURE_ACTOR_FIELDS = Object.freeze({
  hipaa:     ["purposeOfUse"],
  "pci-dss": ["pciScope"],
  gdpr:      ["lawfulBasis"],
  soc2:      [],
});

/**
 * @primitive b.guardMailQuery.validate
 * @signature b.guardMailQuery.validate(filter, opts?)
 * @since     0.9.20
 * @status    stable
 * @related   b.guardMailQuery.validateActor, b.mail.agent.create
 *
 * Validate a filter spec. Returns the input on success; throws
 * `GuardMailQueryError` on refusal.
 *
 * @opts
 *   profile:    "strict" | "balanced" | "permissive",   // default "strict"
 *   posture:    "hipaa" | "pci-dss" | "gdpr" | "soc2",  // pins strict
 *   project:    Array<string>,                           // projection columns
 *
 * @example
 *   b.guardMailQuery.validate({ and: [{ modseq: { gt: 0 } }, { flag: { eq: "\\Seen" } }] });
 */
function validate(filter, opts) {
  opts = opts || {};
  var profile = PROFILES[_resolveProfile(opts)];
  if (filter === undefined || filter === null) {
    throw new GuardMailQueryError("mail-query/empty",
      "guardMailQuery.validate: filter required");
  }
  if (typeof filter !== "object" || Array.isArray(filter)) {
    throw new GuardMailQueryError("mail-query/bad-input",
      "guardMailQuery.validate: filter must be a plain object");
  }
  _walk(filter, 0, profile, new Set());

  if (opts.project) {
    if (!Array.isArray(opts.project)) {
      throw new GuardMailQueryError("mail-query/bad-project",
        "guardMailQuery.validate: opts.project must be an array");
    }
    for (var i = 0; i < opts.project.length; i += 1) {
      var col = opts.project[i];
      if (typeof col !== "string" || !Object.prototype.hasOwnProperty.call(FILTERABLE_COLUMNS, col)) {
        throw new GuardMailQueryError("mail-query/bad-projection-column",
          "guardMailQuery.validate: column '" + col + "' not in projection allowlist");
      }
    }
  }
  return filter;
}

/**
 * @primitive b.guardMailQuery.validateActor
 * @signature b.guardMailQuery.validateActor(actor, posture?)
 * @since     0.9.20
 * @status    stable
 * @related   b.guardMailQuery.validate
 *
 * Validate that `actor` carries the per-posture required fields.
 * Returns `actor` on success; throws on missing field.
 *
 * @example
 *   b.guardMailQuery.validateActor({ id: "u1", roles: ["clinician"], purposeOfUse: "TREATMENT" }, "hipaa");
 */
function validateActor(actor, posture) {
  if (!actor || typeof actor !== "object") {
    throw new GuardMailQueryError("mail-query/no-actor",
      "guardMailQuery.validateActor: actor required");
  }
  if (typeof actor.id !== "string" || actor.id.length === 0) {
    throw new GuardMailQueryError("mail-query/bad-actor",
      "guardMailQuery.validateActor: actor.id must be a non-empty string");
  }
  if (posture && POSTURE_ACTOR_FIELDS[posture]) {
    var required = POSTURE_ACTOR_FIELDS[posture];
    for (var i = 0; i < required.length; i += 1) {
      var f = required[i];
      if (typeof actor[f] !== "string" || actor[f].length === 0) {
        throw new GuardMailQueryError("mail-query/missing-posture-field",
          "guardMailQuery.validateActor: posture '" + posture + "' requires actor." + f);
      }
    }
  }
  return actor;
}

/**
 * @primitive b.guardMailQuery.compliancePosture
 * @signature b.guardMailQuery.compliancePosture(posture)
 * @since     0.9.20
 * @status    stable
 *
 * Return the effective profile for a given compliance posture name.
 * Returns `null` when the posture is unknown (operator-supplied typos
 * surface here instead of silently falling back to the default).
 *
 * @example
 *   b.guardMailQuery.compliancePosture("hipaa");   // → "strict"
 */
function compliancePosture(posture) {
  return COMPLIANCE_POSTURES[posture] || null;
}

function _walk(node, depth, profile, visited) {
  if (depth > profile.maxDepth) {
    throw new GuardMailQueryError("mail-query/depth",
      "guardMailQuery.validate: filter depth exceeds maxDepth=" + profile.maxDepth);
  }
  if (node === null || typeof node !== "object") {
    _checkScalar(node, profile);
    return;
  }
  if (typeof node === "function") {
    throw new GuardMailQueryError("mail-query/function-not-allowed",
      "guardMailQuery.validate: functions refused (filter must be pure data)");
  }
  if (node instanceof RegExp) {
    throw new GuardMailQueryError("mail-query/regex-not-allowed",
      "guardMailQuery.validate: RegExp refused (use { like: ... } string predicate)");
  }
  if (node instanceof Date) {
    if (!isFinite(node.getTime())) {
      throw new GuardMailQueryError("mail-query/bad-date",
        "guardMailQuery.validate: invalid Date");
    }
    return;
  }
  if (Buffer.isBuffer(node)) {
    throw new GuardMailQueryError("mail-query/buffer-not-allowed",
      "guardMailQuery.validate: Buffer refused inside filter");
  }
  if (visited.has(node)) {
    throw new GuardMailQueryError("mail-query/cycle",
      "guardMailQuery.validate: cyclic filter refused");
  }
  visited.add(node);

  if (Array.isArray(node)) {
    if (node.length > profile.maxArrayLen) {
      throw new GuardMailQueryError("mail-query/array-too-long",
        "guardMailQuery.validate: array length " + node.length + " exceeds " + profile.maxArrayLen);
    }
    for (var i = 0; i < node.length; i += 1) {
      _walk(node[i], depth + 1, profile, visited);
    }
    return;
  }

  var keys = Object.keys(node);
  if (keys.length > profile.maxKeys) {
    throw new GuardMailQueryError("mail-query/too-many-keys",
      "guardMailQuery.validate: " + keys.length + " keys exceeds maxKeys=" + profile.maxKeys);
  }
  for (var ki = 0; ki < keys.length; ki += 1) {
    var k = keys[ki];
    if (k === "__proto__" || k === "constructor" || k === "prototype") {
      throw new GuardMailQueryError("mail-query/proto-key",
        "guardMailQuery.validate: forbidden key '" + k + "'");
    }
    var isOp = Object.prototype.hasOwnProperty.call(ALLOWED_OPS, k);
    var isCol = Object.prototype.hasOwnProperty.call(FILTERABLE_COLUMNS, k);
    if (!isOp && !isCol) {
      throw new GuardMailQueryError("mail-query/unknown-key",
        "guardMailQuery.validate: key '" + k + "' not an allowed operator or column");
    }
    _walk(node[k], depth + 1, profile, visited);
  }
}

function _checkScalar(v, profile) {
  if (typeof v === "string") {
    if (Buffer.byteLength(v, "utf8") > profile.maxStringBytes) {
      throw new GuardMailQueryError("mail-query/string-too-long",
        "guardMailQuery.validate: string exceeds maxStringBytes=" + profile.maxStringBytes);
    }
    return;
  }
  if (typeof v === "number") {
    if (!isFinite(v)) {
      throw new GuardMailQueryError("mail-query/bad-number",
        "guardMailQuery.validate: non-finite number refused");
    }
    return;
  }
  if (typeof v === "boolean") return;
  if (v === null) return;
  if (typeof v === "undefined") {
    throw new GuardMailQueryError("mail-query/undefined-not-allowed",
      "guardMailQuery.validate: undefined refused");
  }
  if (typeof v === "symbol" || typeof v === "bigint" || typeof v === "function") {
    throw new GuardMailQueryError("mail-query/bad-scalar",
      "guardMailQuery.validate: scalar type " + typeof v + " refused");
  }
}

function _resolveProfile(opts) {
  if (opts.posture && COMPLIANCE_POSTURES[opts.posture]) {
    return COMPLIANCE_POSTURES[opts.posture];
  }
  var p = opts.profile || DEFAULT_PROFILE;
  if (!PROFILES[p]) {
    throw new GuardMailQueryError("mail-query/bad-profile",
      "guardMailQuery: unknown profile '" + p + "'");
  }
  return p;
}

module.exports = {
  validate:            validate,
  validateActor:       validateActor,
  compliancePosture:   compliancePosture,
  PROFILES:            PROFILES,
  COMPLIANCE_POSTURES: COMPLIANCE_POSTURES,
  FILTERABLE_COLUMNS:  FILTERABLE_COLUMNS,
  POSTURE_ACTOR_FIELDS: POSTURE_ACTOR_FIELDS,
  GuardMailQueryError: GuardMailQueryError,
  NAME:                "mailQuery",
  KIND:                "mail-query",
};
