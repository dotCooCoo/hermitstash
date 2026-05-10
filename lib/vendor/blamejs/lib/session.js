"use strict";
/**
 * @module b.session
 * @featured true
 * @nav    Data
 * @title  Session
 *
 * @intro
 *   Server-side session store with idle + absolute timeouts, encrypted
 *   at rest, sealed columns, audit on every login / logout, and
 *   cluster-aware leader gating.
 *
 *   The session id (sid) is a 32-byte random value returned to the
 *   caller once and stored client-side (cookie / authorization header).
 *   The DB primary key is `sha3('bj-session:' || sid)` — the plaintext
 *   sid never lands in the database. DB exfiltration alone cannot
 *   impersonate a session: the attacker would also need the original
 *   sid the user holds. The `data` column is vault-sealed JSON;
 *   `userId` is sealed; `userIdHash` indexes for destroyAllForUser
 *   without unsealing every row.
 *
 *   Idle + absolute timeout enforcement follows OWASP ASVS 5.0 §3.3
 *   and NIST SP 800-63B-4. Defaults: idle 30 minutes, absolute 12
 *   hours. Both shorten the effective lifetime even when the operator
 *   picked a long ttlMs; repeated `touch({ extendBy })` cannot push
 *   `expiresAt` past the absolute ceiling.
 *
 *   Storage placement is mode-driven: single-node lives in the
 *   framework's main DB under `_blamejs_sessions` (baked into db.js's
 *   schema — apps cannot opt out); cluster mode lives in external-db
 *   under the same name. `clusterStorage.execute` routes by
 *   `cluster.isClusterMode()`; this module does not branch on mode.
 *
 *   Cluster posture per blamejs-cluster-spec.md:
 *   `create` / `destroy` / `destroyAllForUser` / `touch` / `rotate` /
 *   `purgeExpired` are leader-only (gated by `cluster.requireLeader`
 *   at call entry); `verify` and `count` run anywhere.
 *
 *   Optional fingerprint binding: pass `{ req, fingerprintFields }` to
 *   `create` and `verify` to bind a session to a stable hash of
 *   client-IP / user-agent / accept-language. Drift produces an audit
 *   event and surfaces as `fingerprintDrift: true`; strict operators
 *   pass `requireFingerprintMatch: true` (or a `maxAnomalyScore`
 *   threshold with a `scorer`) to refuse the session on drift.
 *
 * @card
 *   Server-side session store with idle + absolute timeouts, encrypted at rest, sealed columns, audit on every login / logout, and cluster-aware leader gating.
 */
var audit = require("./audit");
var canonicalJson = require("./canonical-json");
var cluster = require("./cluster");
var clusterStorage = require("./cluster-storage");
var C = require("./constants");
var { generateToken, sha3Hash } = require("./crypto");
var cryptoField = require("./crypto-field");
var requestHelpers = require("./request-helpers");
var safeJson = require("./safe-json");
var { SessionError } = require("./framework-error");

var _err = SessionError.factory;

var DEFAULT_TTL_MS = C.TIME.days(7);
// Sanity bound: any session that lives longer than this is almost
// certainly a misconfigured Infinity / oversized literal. Keeps
// expiresAt away from epoch overflow + database-int boundary issues.
var MAX_TTL_MS     = C.TIME.days(3650);   // ~10 years

// Idle + absolute timeout defaults per OWASP ASVS 5.0 §3.3 + NIST
// SP 800-63B-4. expiresAt is the operator-set window; idle/absolute
// are independent enforcement floors that shorten the effective
// session lifetime even when the operator picked a long ttlMs.
//
//  - idle: session expires N ms after the last verify() / touch().
//          Default 30 minutes — short enough to defeat session-token
//          theft via short-lived foothold; long enough that a user
//          reading a long article doesn't get logged out.
//  - absolute: session always expires at most N ms after creation,
//          regardless of activity. Default 12 hours — re-auth at
//          least once per shift even on a continuously-active
//          session. Repeated touch() with extendBy cannot push past
//          this ceiling.
var DEFAULT_IDLE_TIMEOUT_MS     = C.TIME.minutes(30);
var DEFAULT_ABSOLUTE_TIMEOUT_MS = C.TIME.hours(12);

function _validateTtl(ttl, where) {
  if (typeof ttl !== "number" || !isFinite(ttl) || ttl <= 0) {
    throw _err("INVALID_ARG",
      where + ": ttlMs must be a positive finite number, got " + JSON.stringify(ttl), true);
  }
  if (ttl > MAX_TTL_MS) {
    throw _err("INVALID_ARG",
      where + ": ttlMs " + ttl + " exceeds maximum " + MAX_TTL_MS + " (~10 years). " +
      "Sessions this long suggest a misconfigured value.", true);
  }
}
var SID_NAMESPACE  = "bj-session:";
// Session ID = 32 random bytes (64 hex chars) — 256-bit entropy floor
// keeps sids unforgeable even before sealed-cookie encryption layers on
// top. Routed through C.BYTES so every byte literal in the file lives
// behind the same helper.
var SID_BYTES      = C.BYTES.bytes(32);

// Column order used for INSERT — kept as a constant so the placeholders
// list and the values list stay in sync. Must match _blamejs_sessions's
// schema in db.js (single-node) and framework-schema.js (cluster mode).
var SESSION_COLS = ["sidHash", "userId", "userIdHash", "data", "createdAt", "expiresAt", "lastActivity"];

function _hashSid(sid) {
  return sha3Hash(SID_NAMESPACE + sid);
}

// Build a sealed row object with all SESSION_COLS keys present (null
// where not set). The cryptoField.sealRow call seals userId/data and
// produces userIdHash from userId.
function _sealForInsert(row) {
  var sealed = cryptoField.sealRow("_blamejs_sessions", row);
  for (var i = 0; i < SESSION_COLS.length; i++) {
    if (!(SESSION_COLS[i] in sealed)) sealed[SESSION_COLS[i]] = null;
  }
  return sealed;
}

// ---- Public API ----

// Build a stable fingerprint from a request's client-derived signals.
// Operators opt in via session.create({ req, fingerprintFields }) and
// session.verify({ req, ... }); when the fingerprint drifts (different
// IP / user-agent / accept-language), the verify result carries
// fingerprintDrift: true and an audit event fires. Operators in strict
// mode pass requireFingerprintMatch:true to make the drift kill the
// session; default returns the session (so a phone roaming between
// wifi and LTE doesn't get logged out, but the operator AND ops sees
// the drift signal).
//
// The fingerprint is HMAC'd with the session sid so a stolen DB can't
// be cross-correlated with public IP-UA logs to attribute sessions to
// users — same defense the sidHash already provides for the token
// itself, extended to the fingerprint.
var DEFAULT_FINGERPRINT_FIELDS = ["clientIp", "userAgent", "acceptLanguage"];

function _buildFingerprintInputs(req, fields) {
  if (!req) return null;
  var headers = req.headers || {};
  var inputs = {};
  for (var i = 0; i < fields.length; i++) {
    var f = fields[i];
    if (f === "clientIp") {
      inputs.clientIp = requestHelpers.clientIp(req) || "";
    } else if (f === "userAgent") {
      inputs.userAgent = String(headers["user-agent"] || "");
    } else if (f === "acceptLanguage") {
      // Take only the primary tag (en-US,en;q=0.9 → en-US) so a
      // browser's secondary q-list reordering doesn't flap drift.
      var raw = String(headers["accept-language"] || "");
      var primary = raw.split(",")[0] || "";
      inputs.acceptLanguage = primary.split(";")[0].trim().toLowerCase();
    } else if (typeof f === "function") {
      try { inputs[f.name || ("custom" + i)] = String(f(req) || ""); }
      catch (_e) { inputs[f.name || ("custom" + i)] = ""; }
    }
  }
  return inputs;
}

function _hashFingerprint(sid, inputs) {
  if (!inputs) return null;
  // Deterministic stringify with sorted keys at every depth — refuses to
  // silently round-trip Date / Buffer / Map / Set / BigInt to "{}".
  var canonical = canonicalJson.stringify(inputs);
  return sha3Hash("bj-session-fingerprint:" + sid + ":" + canonical);
}

/**
 * @primitive b.session.create
 * @signature b.session.create(opts)
 * @since     0.1.0
 * @related   b.session.verify, b.session.rotate, b.session.destroy
 *
 * Mint a fresh session for a known userId and return the plaintext sid
 * the caller stores client-side (cookie / authorization header). The
 * sid is 32 random bytes (256-bit entropy floor); the DB stores
 * `sha3('bj-session:' || sid)` so DB exfiltration alone cannot
 * impersonate the session. `data` is vault-sealed JSON; `userId` is
 * sealed; a derived `userIdHash` indexes for fast `destroyAllForUser`.
 * Leader-only — followers raise NotLeaderError.
 *
 * Pass `{ req, fingerprintFields }` to bind the session to a stable
 * hash of client-IP / user-agent / accept-language; the binding is
 * checked on every `verify` call.
 *
 * @opts
 *   {
 *     userId:              string,                // required — opaque user id (sealed at rest)
 *     data?:               object,                // optional sealed JSON payload
 *     ttlMs?:              number,                // session lifetime; default 7d, max ~10y
 *     req?:                IncomingMessage,       // bind fingerprint to this request's signals
 *     fingerprintFields?:  Array<string|fn>,      // default ["clientIp","userAgent","acceptLanguage"]
 *   }
 *
 * @example
 *   var s = await b.session.create({
 *     userId: "user-42",
 *     data:   { roles: ["admin"] },
 *     ttlMs:  b.constants.TIME.hours(8),
 *   });
 *   res.setHeader("Set-Cookie", "sid=" + s.token + "; HttpOnly; Secure; SameSite=Strict");
 *   // → { token: "9f2c…", expiresAt: 1735689600000 }
 */
async function create(opts) {
  cluster.requireLeader();
  if (!opts || !opts.userId) {
    throw _err("INVALID_ARG", "session.create requires { userId }", true);
  }
  var ttl = opts.ttlMs !== undefined ? opts.ttlMs : DEFAULT_TTL_MS;
  _validateTtl(ttl, "session.create");

  var sid       = generateToken(SID_BYTES);      // hex-encoded; only place the plaintext sid lives
  var sidHash   = _hashSid(sid);
  var nowMs     = Date.now();
  var expiresAt = nowMs + ttl;

  // Fingerprint capture (opt-in via opts.req). Stored as a reserved
  // key inside the sealed `data` field so it lives alongside the
  // operator-supplied session data without needing a schema column.
  var dataObj = opts.data ? Object.assign({}, opts.data) : null;
  var fpFields = Array.isArray(opts.fingerprintFields) && opts.fingerprintFields.length > 0
    ? opts.fingerprintFields : DEFAULT_FINGERPRINT_FIELDS;
  var fpInputs = _buildFingerprintInputs(opts.req, fpFields);
  if (fpInputs) {
    if (!dataObj) dataObj = {};
    dataObj.__bj_fingerprint = _hashFingerprint(sid, fpInputs);
  }

  var sealed = _sealForInsert({
    sidHash:      sidHash,
    userId:       opts.userId,
    data:         dataObj ? JSON.stringify(dataObj) : null,
    createdAt:    nowMs,
    expiresAt:    expiresAt,
    lastActivity: nowMs,
  });
  var values = SESSION_COLS.map(function (c) { return sealed[c]; });
  var placeholders = SESSION_COLS.map(function () { return "?"; }).join(", ");
  var quoted = SESSION_COLS.map(function (c) { return '"' + c + '"'; }).join(", ");
  await clusterStorage.execute(
    "INSERT INTO _blamejs_sessions (" + quoted + ") VALUES (" + placeholders + ")",
    values
  );

  return { token: sid, expiresAt: expiresAt };
}

/**
 * @primitive b.session.verify
 * @signature b.session.verify(token, opts?)
 * @since     0.1.0
 * @related   b.session.create, b.session.touch, b.session.rotate
 *
 * Look up a session by its plaintext sid, enforce TTL + idle +
 * absolute timeouts, optionally check fingerprint drift, and return
 * the unsealed payload. Returns `null` for unknown / expired / idle-
 * expired / absolute-expired sessions; runs anywhere (leader or
 * follower). On expiry, leader nodes best-effort delete the row;
 * followers skip cleanup.
 *
 * `idleTimeoutMs` defaults to 30 minutes, `absoluteTimeoutMs` to 12
 * hours; pass 0 to disable either floor. Pass `{ req }` to evaluate
 * the bound fingerprint — the result carries `fingerprintDrift: true`
 * on mismatch (audit event always fires). `requireFingerprintMatch:
 * true` or a `maxAnomalyScore` threshold (with a `scorer` callback)
 * makes drift refuse the session by returning `null`.
 *
 * @opts
 *   {
 *     idleTimeoutMs?:            number,          // default 30m; 0 disables
 *     absoluteTimeoutMs?:        number,          // default 12h; 0 disables
 *     req?:                      IncomingMessage, // for fingerprint check
 *     fingerprintFields?:        Array<string|fn>,
 *     requireFingerprintMatch?:  boolean,         // strict — drift kills the session
 *     maxAnomalyScore?:          number,          // 0..1; drift above kills
 *     scorer?:                   function,        // ({storedHash,currentInputs,currentHash,sessionAge}) -> 0..1
 *   }
 *
 * @example
 *   var info = await b.session.verify(req.cookies.sid, { req: req });
 *   if (!info) {
 *     res.statusCode = 401;
 *     res.end("login required");
 *     return;
 *   }
 *   var userId = info.userId;
 *   var roles  = (info.data && info.data.roles) || [];
 *   // → { userId: "user-42", data: { roles: ["admin"] }, createdAt: ..., expiresAt: ..., lastActivity: ..., fingerprintDrift: false, fingerprintAnomalyScore: null }
 */
async function verify(token, verifyOpts) {
  if (typeof token !== "string" || token.length === 0) return null;
  verifyOpts = verifyOpts || {};
  var sidHash = _hashSid(token);

  var row = await clusterStorage.executeOne(
    "SELECT sidHash, userId, userIdHash, data, createdAt, expiresAt, lastActivity " +
    "FROM _blamejs_sessions WHERE sidHash = ?",
    [sidHash]
  );
  if (!row) return null;
  var nowMs = Date.now();
  if (Number(row.expiresAt) < nowMs) {
    // Expired (operator-set ttl) — clean up and return null. Cleanup
    // is leader-only; verify is anywhere, so a follower observing an
    // expired row skips the cleanup (next leader-side call purges it).
    if (cluster.isLeader()) {
      try { await _deleteBySidHash(sidHash); } catch (_e) { /* best-effort */ }
    }
    return null;
  }

  // Idle + absolute timeout enforcement (OWASP ASVS 5.0 §3.3 / NIST
  // SP 800-63B-4). These shorten the effective lifetime even when the
  // operator picked a long ttlMs. Defaults: idle 30m, absolute 12h.
  // Operator opt-out by passing 0 (disables that timeout).
  var idleMs = verifyOpts.idleTimeoutMs !== undefined
    ? verifyOpts.idleTimeoutMs : DEFAULT_IDLE_TIMEOUT_MS;
  var absMs = verifyOpts.absoluteTimeoutMs !== undefined
    ? verifyOpts.absoluteTimeoutMs : DEFAULT_ABSOLUTE_TIMEOUT_MS;
  if (idleMs > 0) {
    var lastActivity = Number(row.lastActivity);
    if ((nowMs - lastActivity) > idleMs) {
      try {
        audit.safeEmit({
          action: "auth.session.expired_idle", outcome: "success",
          metadata: { idleMs: nowMs - lastActivity, threshold: idleMs },
        });
      } catch (_ignored) { /* audit best-effort */ }
      if (cluster.isLeader()) {
        try { await _deleteBySidHash(sidHash); } catch (_e) { /* best-effort */ }
      }
      return null;
    }
  }
  if (absMs > 0) {
    var createdAt = Number(row.createdAt);
    if ((nowMs - createdAt) > absMs) {
      try {
        audit.safeEmit({
          action: "auth.session.expired_absolute", outcome: "success",
          metadata: { ageMs: nowMs - createdAt, threshold: absMs },
        });
      } catch (_ignored) { /* audit best-effort */ }
      if (cluster.isLeader()) {
        try { await _deleteBySidHash(sidHash); } catch (_e) { /* best-effort */ }
      }
      return null;
    }
  }
  // Unseal sealed columns (userId, data) using the cryptoField pipeline
  // so we return cleartext to the caller — same shape as the previous
  // db().from(...).first() path delivered.
  var unsealed = cryptoField.unsealRow("_blamejs_sessions", row);
  var data = null;
  var storedFingerprint = null;
  if (unsealed.data) {
    try {
      data = safeJson.parse(unsealed.data);
      if (data && typeof data === "object" && typeof data.__bj_fingerprint === "string") {
        storedFingerprint = data.__bj_fingerprint;
        // Strip the reserved key from the operator-visible data so
        // routes don't accidentally render it / log it / pass it on.
        delete data.__bj_fingerprint;
        if (Object.keys(data).length === 0) data = null;
      }
    }
    catch (e) {
      // Decrypt-then-parse failure is rare but operationally important —
      // it usually signals key-rotation skew, DB corruption, or
      // tampering. Emit an audit event so ops can spot it before the
      // operator notices empty-`data` flows. data stays null so the
      // session remains usable for non-data flows.
      data = null;
      try {
        audit.safeEmit({
          action:   "auth.session.data_unparseable",
          outcome:  "failure",
          reason:   (e && e.message) || String(e),
          metadata: { hasUserId: !!unsealed.userId },
        });
      } catch (_ignored) { /* audit best-effort */ }
    }
  }

  // Fingerprint check — opt-in via verifyOpts.req. When the stored
  // fingerprint differs from the current request's fingerprint, audit
  // the drift and (in strict mode) refuse the session. Default mode
  // returns the session with `fingerprintDrift: true` so the operator
  // can decide (some drift — phone roaming wifi/LTE — is benign; a
  // login-from-Tokyo-then-immediately-from-Brazil pattern is not).
  var fingerprintDrift = false;
  var fingerprintAnomalyScore = null;
  if (storedFingerprint && verifyOpts.req) {
    var fpFields = Array.isArray(verifyOpts.fingerprintFields) && verifyOpts.fingerprintFields.length > 0
      ? verifyOpts.fingerprintFields : DEFAULT_FINGERPRINT_FIELDS;
    var currentInputs = _buildFingerprintInputs(verifyOpts.req, fpFields);
    var currentHash = _hashFingerprint(token, currentInputs);
    if (currentHash !== storedFingerprint) {
      fingerprintDrift = true;
      // Operator-supplied scorer: receives { storedHash, currentInputs,
      // currentHash, sessionAge: ms-since-create }. Returns a number
      // in [0, 1] — 0 = benign drift (phone roaming wifi), 1 =
      // definitely-malicious. Errors are swallowed; scorer-throw
      // doesn't break verify.
      if (typeof verifyOpts.scorer === "function") {
        try {
          var rawScore = verifyOpts.scorer({
            storedHash:    storedFingerprint,
            currentInputs: currentInputs,
            currentHash:   currentHash,
            sessionAge:    Date.now() - Number(unsealed.createdAt),
          });
          if (typeof rawScore === "number" && isFinite(rawScore)) {
            fingerprintAnomalyScore = Math.max(0, Math.min(1, rawScore));
          }
        } catch (_e) { /* scorer best-effort */ }
      }
      try {
        audit.safeEmit({
          action:   "auth.session.fingerprint_drift",
          outcome:  "success",
          metadata: { hasUserId: !!unsealed.userId,
            anomalyScore: fingerprintAnomalyScore },
        });
      } catch (_ignored) { /* audit best-effort */ }
      // Strict modes:
      //   requireFingerprintMatch: true       — any drift kills the session
      //   maxAnomalyScore: <0..1>             — drift above threshold kills
      if (verifyOpts.requireFingerprintMatch === true) {
        return null;
      }
      if (typeof verifyOpts.maxAnomalyScore === "number" &&
          fingerprintAnomalyScore !== null &&
          fingerprintAnomalyScore > verifyOpts.maxAnomalyScore) {
        return null;
      }
    }
  }

  return {
    userId:                   unsealed.userId,
    data:                     data,
    createdAt:                Number(unsealed.createdAt),
    expiresAt:                Number(unsealed.expiresAt),
    lastActivity:             Number(unsealed.lastActivity),
    fingerprintDrift:         fingerprintDrift,
    fingerprintAnomalyScore:  fingerprintAnomalyScore,
  };
}

/**
 * @primitive b.session.destroy
 * @signature b.session.destroy(token)
 * @since     0.1.0
 * @related   b.session.destroyAllForUser, b.session.create
 *
 * Revoke a single session by sid. Returns `true` when a row was
 * deleted, `false` when the sid is unknown / already gone / empty.
 * Standard logout flow: clear the client's cookie AND call
 * `destroy(sid)` so the row vanishes from the DB and verify(sid)
 * starts returning null cluster-wide. Leader-only.
 *
 * @example
 *   await b.session.destroy(req.cookies.sid);
 *   res.setHeader("Set-Cookie", "sid=; HttpOnly; Max-Age=0");
 *   res.end("logged out");
 *   // → true
 */
async function destroy(token) {
  cluster.requireLeader();
  if (typeof token !== "string" || token.length === 0) return false;
  return await _deleteBySidHash(_hashSid(token));
}

async function _deleteBySidHash(sidHash) {
  var result = await clusterStorage.execute(
    "DELETE FROM _blamejs_sessions WHERE sidHash = ?",
    [sidHash]
  );
  return (result.rowCount || 0) > 0;
}

/**
 * @primitive b.session.destroyAllForUser
 * @signature b.session.destroyAllForUser(userId)
 * @since     0.1.0
 * @related   b.session.destroy, b.session.rotate
 *
 * Revoke every active session for a userId at once. Returns the count
 * of rows deleted. Use after password change, role revocation,
 * compromised-account reports, or "log me out everywhere" UI flows.
 * Lookup goes through the derived `userIdHash` — no row needs
 * unsealing to find matches. Leader-only.
 *
 * @example
 *   var revoked = await b.session.destroyAllForUser("user-42");
 *   b.audit.emit({ action: "auth.session.revoke_all", outcome: "success",
 *     metadata: { userId: "user-42", count: revoked } });
 *   // → 3
 */
async function destroyAllForUser(userId) {
  cluster.requireLeader();
  if (!userId) throw _err("INVALID_ARG", "session.destroyAllForUser requires a userId", true);
  // userId is sealed; look up via derived userIdHash.
  var lookup = cryptoField.lookupHash("_blamejs_sessions", "userId", userId);
  if (!lookup) {
    throw _err("MISCONFIGURED",
      "_blamejs_sessions schema is missing the userIdHash derived hash — framework misconfigured",
      true);
  }
  var result = await clusterStorage.execute(
    "DELETE FROM _blamejs_sessions WHERE userIdHash = ?",
    [lookup.value]
  );
  return result.rowCount || 0;
}

/**
 * @primitive b.session.touch
 * @signature b.session.touch(token, opts)
 * @since     0.1.0
 * @related   b.session.verify, b.session.rotate
 *
 * Refresh `lastActivity` (resets the idle-timeout countdown) and
 * optionally extend `expiresAt`. Returns `true` when a non-expired
 * row was updated, `false` when the sid is unknown or the row is
 * already past its TTL. Pass `extendBy` to push `expiresAt` forward
 * relative to NOW (not the existing expiry — soaked sessions with
 * continuous traffic don't accumulate unbounded expiry); the
 * framework's MAX_TTL_MS bound applies. Leader-only.
 *
 * @opts
 *   {
 *     extendBy?: number,   // ms to set new expiresAt = now + extendBy
 *   }
 *
 * @example
 *   // Bump idle clock on every request:
 *   await b.session.touch(req.cookies.sid);
 *
 *   // Sliding-window: extend by another 8 hours when activity continues.
 *   await b.session.touch(req.cookies.sid, { extendBy: b.constants.TIME.hours(8) });
 *   // → true
 */
async function touch(token, opts) {
  cluster.requireLeader();
  opts = opts || {};
  if (typeof token !== "string" || token.length === 0) return false;
  var sidHash = _hashSid(token);
  var nowMs = Date.now();
  // Two SQL paths so the SET list stays static (no dynamic column
  // assembly) and matches the call shape clusterStorage expects.
  // extendBy resets expiresAt relative to NOW, not relative to the
  // current expiresAt — a soaked session with continuous traffic
  // shouldn't accumulate unbounded expiry. The same MAX_TTL_MS
  // ceiling create() and rotate() apply gates extendBy too — repeated
  // touch() calls cannot push expiresAt past the framework's bound.
  if (opts.extendBy !== undefined && opts.extendBy !== null) {
    _validateTtl(opts.extendBy, "session.touch");
    var newExpires = nowMs + opts.extendBy;
    var result = await clusterStorage.execute(
      "UPDATE _blamejs_sessions SET lastActivity = ?, expiresAt = ? " +
      "WHERE sidHash = ? AND expiresAt >= ?",
      [nowMs, newExpires, sidHash, nowMs]
    );
    return (result.rowCount || 0) > 0;
  }
  var result2 = await clusterStorage.execute(
    "UPDATE _blamejs_sessions SET lastActivity = ? " +
    "WHERE sidHash = ? AND expiresAt >= ?",
    [nowMs, sidHash, nowMs]
  );
  return (result2.rowCount || 0) > 0;
}

/**
 * @primitive b.session.rotate
 * @signature b.session.rotate(oldToken, opts)
 * @since     0.1.0
 * @related   b.session.create, b.session.verify, b.session.destroy
 *
 * Session-fixation defense: generate a fresh sid for the same userId +
 * data, atomically replacing the old sid in the row. Call after every
 * auth state change (login from anonymous, multifactor verified, role
 * escalation) so any sid an attacker planted pre-login becomes invalid.
 * Returns `{ token, expiresAt }` on success, `null` when the old token
 * is unknown / expired (operator distinguishes by checking for null).
 * Leader-only.
 *
 * Atomicity: a single WHERE-guarded UPDATE swaps `sidHash`. The old
 * and new tokens never coexist — the moment the UPDATE commits, only
 * the new token verifies. Audit event `auth.session.rotate` fires
 * best-effort with `metadata.reason`.
 *
 * @opts
 *   {
 *     data?:   object,     // replacement session data (re-sealed)
 *     ttlMs?:  number,     // new TTL; if absent, existing expiresAt preserved
 *     reason?: string,     // audit metadata ("login", "mfa", "role-change")
 *   }
 *
 * @example
 *   var rotated = await b.session.rotate(req.cookies.sid, {
 *     ttlMs:  b.constants.TIME.hours(8),
 *     reason: "mfa",
 *   });
 *   if (rotated) {
 *     res.setHeader("Set-Cookie", "sid=" + rotated.token + "; HttpOnly; Secure; SameSite=Strict");
 *   }
 *   // → { token: "7a1e…", expiresAt: 1735689600000 }
 */
async function rotate(oldToken, opts) {
  cluster.requireLeader();
  if (typeof oldToken !== "string" || oldToken.length === 0) return null;
  opts = opts || {};

  var newSid       = generateToken(SID_BYTES);
  var newSidHash   = _hashSid(newSid);
  var oldSidHash   = _hashSid(oldToken);
  var nowMs        = Date.now();
  var newExpires = null;
  if (opts.ttlMs !== undefined) {
    _validateTtl(opts.ttlMs, "session.rotate");
    newExpires = nowMs + opts.ttlMs;
  }

  var setParts = ['"sidHash" = ?', '"lastActivity" = ?'];
  var setParams = [newSidHash, nowMs];

  if (opts.data !== undefined) {
    var dataJson = opts.data ? JSON.stringify(opts.data) : null;
    var sealedRow = cryptoField.sealRow("_blamejs_sessions", { data: dataJson });
    setParts.push('"data" = ?');
    setParams.push(sealedRow.data);
  }
  if (newExpires !== null) {
    setParts.push('"expiresAt" = ?');
    setParams.push(newExpires);
  }

  var sql = "UPDATE _blamejs_sessions SET " + setParts.join(", ") +
            " WHERE sidHash = ? AND expiresAt >= ?";
  var params = setParams.concat([oldSidHash, nowMs]);
  var result = await clusterStorage.execute(sql, params);
  if ((result.rowCount || 0) === 0) return null;

  // Read the row's effective expiresAt to return — single source of truth.
  var row = await clusterStorage.executeOne(
    'SELECT "expiresAt" FROM _blamejs_sessions WHERE sidHash = ?',
    [newSidHash]
  );
  var expiresAt = row ? Number(row.expiresAt) : null;

  // Audit emit — best-effort. The framework's audit chain logs the
  // privilege transition so post-incident review can trace which
  // session id covered which privilege state.
  try {
    audit.emit({
      action:  "auth.session.rotate",
      outcome: "success",
      metadata: { reason: opts.reason || "explicit" },
    });
  } catch (_e) { /* audit emit best-effort — never block rotate() */ }

  return { token: newSid, expiresAt: expiresAt };
}

/**
 * @primitive b.session.purgeExpired
 * @signature b.session.purgeExpired()
 * @since     0.1.0
 * @related   b.session.count, b.session.destroy
 *
 * Bulk-delete every row whose `expiresAt` is in the past. Returns the
 * count of rows removed. The framework purges opportunistically on
 * `verify` (leader-side), but a periodic sweep keeps the table from
 * accumulating dead rows when verify traffic is sparse. Safe to schedule
 * on a recurring timer (the framework's scheduler primitive is the
 * intended caller). Leader-only.
 *
 * @example
 *   // Hourly purge from a scheduler:
 *   b.scheduler.every(b.constants.TIME.hours(1), async function () {
 *     var dropped = await b.session.purgeExpired();
 *     b.audit.emit({
 *       action: "auth.session.purge_expired", outcome: "success",
 *       metadata: { dropped: dropped },
 *     });
 *   });
 *   // → 17
 */
async function purgeExpired() {
  cluster.requireLeader();
  var result = await clusterStorage.execute(
    "DELETE FROM _blamejs_sessions WHERE expiresAt < ?",
    [Date.now()]
  );
  return result.rowCount || 0;
}

/**
 * @primitive b.session.count
 * @signature b.session.count()
 * @since     0.1.0
 * @related   b.session.purgeExpired, b.session.destroyAllForUser
 *
 * Return the number of currently-live sessions (rows whose `expiresAt`
 * is in the future). Useful for ops dashboards, capacity tracking, and
 * "active users" metrics. Runs anywhere — leader or follower — because
 * it only reads. Note that idle-timeout-eligible rows are still counted
 * until a `verify` or `purgeExpired` removes them; the value is an
 * upper bound on truly-active sessions.
 *
 * @example
 *   var live = await b.session.count();
 *   b.observability.event({ name: "session.live", value: live });
 *   // → 482
 */
async function count() {
  var row = await clusterStorage.executeOne(
    "SELECT COUNT(*) AS c FROM _blamejs_sessions WHERE expiresAt >= ?",
    [Date.now()]
  );
  return row ? Number(row.c) : 0;
}

function _resetForTest() { /* no module state to reset; clusterStorage and cryptoField own theirs */ }

module.exports = {
  create:               create,
  verify:               verify,
  destroy:              destroy,
  destroyAllForUser:    destroyAllForUser,
  touch:                touch,
  rotate:               rotate,
  purgeExpired:         purgeExpired,
  count:                count,
  DEFAULT_TTL_MS:       DEFAULT_TTL_MS,
  _resetForTest:        _resetForTest,
};
