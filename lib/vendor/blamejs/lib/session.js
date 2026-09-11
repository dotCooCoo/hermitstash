// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
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
var validateOpts = require("./validate-opts");
var cluster = require("./cluster");
var clusterStorage = require("./cluster-storage");
var C = require("./constants");
var cookies = require("./cookies");
var { generateToken, sha3Hash } = require("./crypto");
var cryptoField = require("./crypto-field");
var frameworkSchema = require("./framework-schema");
var lazyRequire = require("./lazy-require");
var requestHelpers = require("./request-helpers");
var safeAsync = require("./safe-async");
var safeJson = require("./safe-json");
var sql = require("./sql");
var { SessionError } = require("./framework-error");

function _isPlainObject(v) {
  if (v === null || typeof v !== "object" || Array.isArray(v)) return false;
  var proto = Object.getPrototypeOf(v);
  return proto === Object.prototype || proto === null;
}

// vault is initialized at boot before sessions; lazyRequire keeps the
// load order independent of module-import order. Used to seal/unseal
// the cookie-side sid so the wire token is ciphertext rather than
// plaintext (sealed-cookie default since v0.8.61).
var vault = lazyRequire(function () { return require("./vault"); });
// Lazy — b.session.logout composes the Clear-Site-Data header builder; keep it
// out of the boot require graph (no cycle, but session is a low-level primitive).
var clearSiteData = lazyRequire(function () { return require("./middleware/clear-site-data"); });

var _store = null;
function _currentStore() { return _store || clusterStorage; }

var _err = SessionError.factory;

var DEFAULT_TTL_MS = C.TIME.days(7);
var MAX_TTL_MS     = C.TIME.days(3650);

var DEFAULT_IDLE_TIMEOUT_MS     = C.TIME.minutes(30);
var DEFAULT_ABSOLUTE_TIMEOUT_MS = C.TIME.hours(12);

function _validateTtl(ttl, where) {
  if (typeof ttl !== "number" || !isFinite(ttl) || ttl <= 0) {
    throw _err("session/invalid-arg",
      where + ": ttlMs must be a positive finite number, got " + JSON.stringify(ttl), true);
  }
  if (ttl > MAX_TTL_MS) {
    throw _err("session/invalid-arg",
      where + ": ttlMs " + ttl + " exceeds maximum " + MAX_TTL_MS + " (~10 years). " +
      "Sessions this long suggest a misconfigured value.", true);
  }
}
var SID_NAMESPACE  = "bj-session:";
var SID_BYTES      = C.BYTES.bytes(32);

var SESSION_TABLE = "_blamejs_sessions";   // allow:hand-rolled-sql — canonical logical table-name + cryptoField registry key
function _sessionSqlTable() { return frameworkSchema.tableName(SESSION_TABLE); }

function _sessionSqlOpts() { return { dialect: clusterStorage.dialect() }; }

var VALID_FROM_TABLE = "_blamejs_session_valid_from";   // allow:hand-rolled-sql — canonical logical table-name + reserved schema name
var VALID_FROM_SUBJECT_NAMESPACE = "bj-session-valid-from-subject:";
function _validFromSqlTable() { return frameworkSchema.tableName(VALID_FROM_TABLE); }
function _hashSubjectId(subjectId) { return sha3Hash(VALID_FROM_SUBJECT_NAMESPACE + subjectId); }

function _validFromConflictRefs(dialect, table) {
  if (dialect === "mysql") {
    return {
      proposed: function (col) { return "VALUES(`" + col + "`)"; },
      existing: function (col) { return "`" + table + "`.`" + col + "`"; },
    };
  }
  return {
    proposed: function (col) { return "EXCLUDED.\"" + col + "\""; },
    existing: function (col) { return "\"" + table + "\".\"" + col + "\""; },
  };
}

function _validFromSchemaSql() {
  return sql.createTable(_validFromSqlTable(), [
    { name: "subjectHash",    type: "text", primaryKey: true },
    { name: "validFromEpoch", type: "int",  notNull: true },
    { name: "updatedAt",      type: "int",  notNull: true },
  ], { dialect: "sqlite" }).sql;
}

async function _runValidFrom(runner) {
  try {
    return await runner(clusterStorage);
  } catch (e) {
    if (e && e.code === "db/not-initialized" && _store) {
      await _store.execute(_validFromSchemaSql(), []);
      return await runner(_store);
    }
    throw e;
  }
}

var SESSION_COLS = ["sidHash", "userId", "userIdHash", "data", "createdAt", "expiresAt", "lastActivity"];

function _hashSid(sid) {
  return sha3Hash(SID_NAMESPACE + sid);
}

var SEALED_COOKIE_PREFIX = "vault:";

function _sealCookieToken(sid) {
  return vault().seal(sid);
}

function _unsealCookieToken(token) {
  if (typeof token !== "string" || token.length === 0) return null;
  if (token.indexOf(SEALED_COOKIE_PREFIX) !== 0) {
    return null;
  }
  try { return vault().unseal(token); }
  catch (_e) {
    return null;
  }
}

function _sealForInsert(row) {
  var sealed = cryptoField.sealRow(SESSION_TABLE, row);
  for (var i = 0; i < SESSION_COLS.length; i++) {
    if (!(SESSION_COLS[i] in sealed)) sealed[SESSION_COLS[i]] = null;
  }
  return sealed;
}

var DEFAULT_FINGERPRINT_FIELDS = ["clientIp", "userAgent", "acceptLanguage"];

function _clientIpResolver(opts) {
  if (opts && (opts.trustedProxies != null || typeof opts.clientIpResolver === "function")) {
    return requestHelpers.trustedClientIp({
      trustedProxies:   opts.trustedProxies,
      clientIpResolver: opts.clientIpResolver,
    }).resolve;
  }
  return requestHelpers.clientIp;
}

function _buildFingerprintInputs(req, fields, resolveIp) {
  if (!req) return null;
  resolveIp = resolveIp || requestHelpers.clientIp;
  var headers = req.headers || {};
  var inputs = {};
  for (var i = 0; i < fields.length; i++) {
    var f = fields[i];
    if (f === "clientIp") {
      inputs.clientIp = resolveIp(req) || "";
    } else if (f === "clientIpPrefix") {
      inputs.clientIpPrefix = requestHelpers.ipPrefix(resolveIp(req) || "");
    } else if (f === "userAgent") {
      inputs.userAgent = String(headers["user-agent"] || "");
    } else if (f === "acceptLanguage") {
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
 *   b.cookies.appendSetCookie(res, b.cookies.serialize("sid", s.token, {
 *     httpOnly: true, secure: true, sameSite: "Strict", path: "/",
 *   }));
 *   // → { token: "9f2c…", expiresAt: 1735689600000 }
 */
var ANON_PREFIX = "anon:";
function _isAnonymousUserId(id) {
  return typeof id === "string" && id.indexOf(ANON_PREFIX) === 0;
}

async function create(opts) {
  cluster.requireLeader();
  opts = opts || {};
  if (opts.anonymous === true) {
    if (opts.userId !== undefined && opts.userId !== null) {
      throw _err("session/invalid-arg",
        "session.create: pass either anonymous: true OR userId, not both", true);
    }
    var nodeCryptoForUuid = require("node:crypto");                                                // allow:inline-require — only the anon path needs randomUUID
    opts = Object.assign({}, opts, { userId: ANON_PREFIX + nodeCryptoForUuid.randomUUID() });
  }
  if (!opts.userId) {
    throw _err("session/invalid-arg", "session.create requires { userId } (or { anonymous: true })", true);
  }
  var ttl = opts.ttlMs !== undefined ? opts.ttlMs : DEFAULT_TTL_MS;
  _validateTtl(ttl, "session.create");

  var sid       = generateToken(SID_BYTES);
  var sidHash   = _hashSid(sid);
  var nowMs     = Date.now();
  var expiresAt = nowMs + ttl;

  var dataObj = opts.data ? Object.assign({}, opts.data) : null;
  if (dataObj) {
    delete dataObj.__bj_fingerprint;
    delete dataObj.__bj_deviceBinding;
  }
  var fpFields = Array.isArray(opts.fingerprintFields) && opts.fingerprintFields.length > 0
    ? opts.fingerprintFields : DEFAULT_FINGERPRINT_FIELDS;
  var fpInputs = _buildFingerprintInputs(opts.req, fpFields, _clientIpResolver(opts));
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
  var insertRow = {};
  for (var ci = 0; ci < SESSION_COLS.length; ci++) insertRow[SESSION_COLS[ci]] = sealed[SESSION_COLS[ci]];
  var built = sql.insert(_sessionSqlTable(), _sessionSqlOpts())
    .columns(SESSION_COLS)
    .values(insertRow)
    .toSql();
  await _currentStore().execute(built.sql, built.params);

  return { token: _sealCookieToken(sid), expiresAt: expiresAt };
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
 * makes drift refuse the session by returning `null`. A strict policy
 * also refuses (returns `null`) a session that carries no comparable
 * binding — one created without `{ req }`, or whose sealed binding
 * cannot be decrypted — since the device match cannot be proven; bind
 * every session you intend to verify strictly by passing `{ req }` to
 * `create`.
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
function _timeoutFloorBreach(row, nowMs, opts) {
  opts = opts || {};
  var idleMs = opts.idleTimeoutMs !== undefined ? opts.idleTimeoutMs : DEFAULT_IDLE_TIMEOUT_MS;
  var absMs = opts.absoluteTimeoutMs !== undefined ? opts.absoluteTimeoutMs : DEFAULT_ABSOLUTE_TIMEOUT_MS;
  if (idleMs > 0) {
    var lastActivity = Number(row.lastActivity);
    if ((nowMs - lastActivity) > idleMs) {
      return { action: "auth.session.expired_idle", metadata: { idleMs: nowMs - lastActivity, threshold: idleMs } };
    }
  }
  if (absMs > 0) {
    var createdAt = Number(row.createdAt);
    if ((nowMs - createdAt) > absMs) {
      return { action: "auth.session.expired_absolute", metadata: { ageMs: nowMs - createdAt, threshold: absMs } };
    }
  }
  return null;
}

async function _floorBreachAndCleanup(row, sidHash, nowMs, opts) {
  var breach = _timeoutFloorBreach(row, nowMs, opts);
  if (!breach) return null;
  try {
    audit.safeEmit({ action: breach.action, outcome: "success", metadata: breach.metadata });
  } catch (_ignored) { /* audit best-effort */ }
  if (cluster.isLeader()) {
    try { await _deleteBySidHash(sidHash); } catch (_e) { /* best-effort */ }
  }
  return breach;
}

async function verify(token, verifyOpts) {
  if (typeof token !== "string" || token.length === 0) return null;
  verifyOpts = verifyOpts || {};
  var sid = _unsealCookieToken(token);
  if (sid === null) return null;
  var sidHash = _hashSid(sid);

  var selBuilt = sql.select(_sessionSqlTable(), _sessionSqlOpts())
    .columns(["sidHash", "userId", "userIdHash", "data", "createdAt", "expiresAt", "lastActivity"])
    .where("sidHash", sidHash)
    .toSql();
  var row = await _currentStore().executeOne(selBuilt.sql, selBuilt.params);
  if (!row) return null;
  var nowMs = Date.now();
  if (Number(row.expiresAt) < nowMs) {
    if (cluster.isLeader()) {
      try { await _deleteBySidHash(sidHash); } catch (_e) { /* best-effort */ }
    }
    return null;
  }

  if (await _floorBreachAndCleanup(row, sidHash, nowMs, verifyOpts)) return null;
  var unsealed = cryptoField.unsealRow(SESSION_TABLE, row);
  var data = null;
  var storedFingerprint = null;
  var bindingUnreadable = (row.data != null && row.data !== "" && unsealed.data == null);
  if (unsealed.data) {
    try {
      data = safeJson.parse(unsealed.data);
      if (data && typeof data === "object" && typeof data.__bj_fingerprint === "string") {
        storedFingerprint = data.__bj_fingerprint;
        delete data.__bj_fingerprint;
        if (Object.keys(data).length === 0) data = null;
      }
    }
    catch (e) {
      data = null;
      bindingUnreadable = true;
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

  var fingerprintDrift = false;
  var fingerprintAnomalyScore = null;
  var strictFlagRequested =
    verifyOpts.requireFingerprintMatch === true ||
    typeof verifyOpts.maxAnomalyScore === "number";
  if (strictFlagRequested && !verifyOpts.req) {
    try {
      audit.safeEmit({
        action:   "auth.session.binding_no_request",
        outcome:  "failure",
        metadata: { hasUserId: !!unsealed.userId },
      });
    } catch (_ig) { /* audit best-effort */ }
    return null;
  }
  var strictBindingRequested = strictFlagRequested && !!verifyOpts.req;
  if (strictBindingRequested && !storedFingerprint) {
    try {
      audit.safeEmit({
        action:   bindingUnreadable ? "auth.session.binding_unreadable"
                                     : "auth.session.binding_missing",
        outcome:  "failure",
        metadata: { hasUserId: !!unsealed.userId },
      });
    } catch (_ig) { /* audit best-effort */ }
    return null;
  }
  if (storedFingerprint && verifyOpts.req) {
    var fpFields = Array.isArray(verifyOpts.fingerprintFields) && verifyOpts.fingerprintFields.length > 0
      ? verifyOpts.fingerprintFields : DEFAULT_FINGERPRINT_FIELDS;
    var currentInputs = _buildFingerprintInputs(verifyOpts.req, fpFields, _clientIpResolver(verifyOpts));
    var currentHash = _hashFingerprint(sid, currentInputs);
    if (currentHash !== storedFingerprint) {
      fingerprintDrift = true;
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
      if (verifyOpts.requireFingerprintMatch === true) {
        return null;
      }
      if (typeof verifyOpts.maxAnomalyScore === "number") {
        if (fingerprintAnomalyScore === null ||
            fingerprintAnomalyScore > verifyOpts.maxAnomalyScore) {
          return null;
        }
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
 *   b.cookies.appendSetCookie(res, b.cookies.serialize("sid", "", {
 *     httpOnly: true, sameSite: "Strict", path: "/", maxAge: 0,
 *   }));
 *   res.end("logged out");
 *   // → true
 */
async function destroy(token) {
  cluster.requireLeader();
  if (typeof token !== "string" || token.length === 0) return false;
  var sid = _unsealCookieToken(token);
  if (sid === null) return false;
  return await _deleteBySidHash(_hashSid(sid));
}

/**
 * @primitive b.session.logout
 * @signature b.session.logout(res, token, opts?)
 * @since     0.15.9
 * @status    stable
 * @related   b.session.destroy, b.middleware.clearSiteData
 *
 * Secure logout in one call: destroy the server-side session AND tell the
 * browser to wipe its client-side state. It emits a W3C Clear-Site-Data
 * response header (cookies + storage + cache + executionContexts by default)
 * and expires the session cookie, then destroys the session row. `destroy()`
 * alone is a store operation with no `res`, so it cannot wipe the browser's
 * cached pages / storage / any stale tab still holding the now-revoked cookie;
 * this composes the secure-default logout the middleware otherwise had to be
 * mounted by hand. Returns whether a session was destroyed. Leader-only.
 *
 * A browser deletes a cookie by MATCHING the expiry cookie's name, path and
 * domain against the one in its jar, and it refuses a `Secure` cookie
 * altogether when the response came over plain HTTP. So the expiry cookie has
 * to describe the same scope the session cookie was written with, or the
 * logout leaves it in place. Pass the `req` and the scheme is resolved through
 * `b.requestHelpers.trustedProtocol` (a forwarded scheme counts only from a
 * peer you declared trusted); pass `secure` to state it outright. With neither,
 * the cookie is `Secure` — the secure default, unchanged.
 *
 * @opts
 *   cookieName:       string,   // default: "sid" — the session cookie to expire
 *   types:            string[], // default: the W3C Clear-Site-Data directive set
 *   req:              object,   // resolve Secure from this request's scheme
 *   secure:           boolean,  // default: true — state the scheme outright
 *   sameSite:         string,   // default: "Strict" — Strict / Lax / None
 *   path:             string,   // default: "/" — must match the cookie's Path
 *   domain:           string,   // must match the cookie's Domain, if it had one
 *   trustedProxies:   string | string[],   // CIDRs, for the `req` scheme resolve
 *   protocolResolver: function(req),       // own the scheme decision instead
 *
 * @example
 *   app.post("/logout", async function (req, res) {
 *     await b.session.logout(res, req.cookies.sid, { req: req });
 *     res.end("logged out");
 *   });
 *   // → emits Clear-Site-Data + expires the sid cookie + destroys the session
 */
async function logout(res, token, opts) {
  if (!res || typeof res.setHeader !== "function") {
    throw new SessionError("session/bad-res",
      "b.session.logout: res must be an HTTP response with setHeader()");
  }
  cookies.assertAppendable(res);
  opts = opts || {};
  validateOpts(opts, [
    "cookieName", "types", "req", "secure", "sameSite", "path", "domain",
    "trustedProxies", "protocolResolver",
  ], "b.session.logout");
  var cookieName = opts.cookieName === undefined ? "sid" : opts.cookieName;
  if (typeof cookieName !== "string" || cookieName.length === 0) {
    throw new SessionError("session/bad-cookie-name",
      "b.session.logout: opts.cookieName must be a non-empty string");
  }
  var csd = clearSiteData();
  var types = opts.types === undefined ? csd.DEFAULT_TYPES : opts.types;
  var clearSiteDataValue = csd.headerValue(types, "b.session.logout");

  var expiryCookie = cookies.serialize(cookieName, "", {
    httpOnly: true,
    secure:   _logoutCookieSecure(opts, cookieName),
    sameSite: opts.sameSite === undefined ? "Strict" : opts.sameSite,
    path:     opts.path === undefined ? "/" : opts.path,
    domain:   opts.domain,
    maxAge:   0,
  });

  var destroyed = await destroy(token);

  res.setHeader("Clear-Site-Data", clearSiteDataValue);
  cookies.appendSetCookie(res, expiryCookie);
  return destroyed;
}

function _logoutCookieSecure(opts, cookieName) {
  if (opts.secure !== undefined) {
    if (typeof opts.secure !== "boolean") {
      throw new SessionError("session/bad-secure",
        "b.session.logout: opts.secure must be a boolean");
    }
    return opts.secure;
  }
  var lowerName = cookieName.toLowerCase();
  if (lowerName.indexOf("__host-") === 0 || lowerName.indexOf("__secure-") === 0) {
    return true;
  }
  if (opts.req === undefined) return true;
  if (opts.req === null || typeof opts.req !== "object") {
    throw new SessionError("session/bad-req",
      "b.session.logout: opts.req must be an HTTP request object");
  }
  var resolver = requestHelpers.trustedProtocol({
    trustedProxies:   opts.trustedProxies,
    protocolResolver: opts.protocolResolver,
  });
  return resolver.resolve(opts.req) === "https";
}

async function _deleteBySidHash(sidHash) {
  var built = sql.delete(_sessionSqlTable(), _sessionSqlOpts())
    .where("sidHash", sidHash)
    .toSql();
  var result = await _currentStore().execute(built.sql, built.params);
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
  if (!userId) throw _err("session/invalid-arg", "session.destroyAllForUser requires a userId", true);
  if (_isAnonymousUserId(userId)) {
    throw _err("session/invalid-arg",
      "session.destroyAllForUser: anonymous-prefix ids (\"anon:...\") are per-session — " +
      "use destroy(token) for that session, OR purgeExpired() for housekeeping",
      true);
  }
  var lookup = cryptoField.lookupHash(SESSION_TABLE, "userId", userId);
  if (!lookup) {
    throw _err("session/misconfigured",
      "session.destroyAllForUser: the session table's userIdHash derived-hash schema is " +
      "not registered. It is registered during b.db.init() — call b.db.init() at boot even " +
      "when session data lives in a pluggable store (b.session.useStore). If b.db is already " +
      "initialized, the session table schema is misconfigured.",
      true);
  }
  var userHashes = [lookup.value];
  if (lookup.legacyValue != null && lookup.legacyValue !== lookup.value) {
    userHashes.push(lookup.legacyValue);
  }
  var built = sql.delete(_sessionSqlTable(), _sessionSqlOpts())
    .whereIn("userIdHash", userHashes)
    .toSql();
  var result = await _currentStore().execute(built.sql, built.params);
  try {
    await bump(userId);
  } catch (e) {
    if (e && e.code === "db/not-initialized") {
      throw _err("session/misconfigured",
        "session.destroyAllForUser raises the stateless valid-from boundary (so a " +
        "logout-everywhere also revokes sealed-cookie / JWT sessions). No storage is " +
        "available: call b.db.init() at boot, OR configure a session store via " +
        "b.session.useStore. The store-backed rows were already deleted.", true);
    }
    throw e;
  }
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
  var sid = _unsealCookieToken(token);
  if (sid === null) return false;
  var sidHash = _hashSid(sid);
  var nowMs = Date.now();
  var floorSel = sql.select(_sessionSqlTable(), _sessionSqlOpts())
    .columns(["createdAt", "lastActivity"])
    .where("sidHash", sidHash)
    .where("expiresAt", ">=", nowMs)
    .toSql();
  var floorRow = await _currentStore().executeOne(floorSel.sql, floorSel.params);
  if (!floorRow) return false;
  if (await _floorBreachAndCleanup(floorRow, sidHash, nowMs, opts)) return false;
  if (opts.extendBy !== undefined && opts.extendBy !== null) {
    _validateTtl(opts.extendBy, "session.touch");
    var newExpires = nowMs + opts.extendBy;
    var built = sql.update(_sessionSqlTable(), _sessionSqlOpts())
      .set({ lastActivity: nowMs, expiresAt: newExpires })
      .where("sidHash", sidHash)
      .where("expiresAt", ">=", nowMs)
      .toSql();
    var result = await _currentStore().execute(built.sql, built.params);
    return (result.rowCount || 0) > 0;
  }
  var built2 = sql.update(_sessionSqlTable(), _sessionSqlOpts())
    .set({ lastActivity: nowMs })
    .where("sidHash", sidHash)
    .where("expiresAt", ">=", nowMs)
    .toSql();
  var result2 = await _currentStore().execute(built2.sql, built2.params);
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
 * Device binding: when the session was created with `{ req, fingerprintFields }`
 * the bound fingerprint is keyed to the sid, so rotation re-keys it to the new
 * sid from the live request. Pass the same `{ req, fingerprintFields }` to
 * `rotate` — a fingerprint-bound session rotated without `req` throws, because
 * the binding cannot follow the sid otherwise (it would silently break or make
 * the next `verify` falsely report drift).
 *
 * @opts
 *   {
 *     data?:              object,     // replacement session data (re-sealed)
 *     ttlMs?:             number,     // new TTL; if absent, existing expiresAt preserved
 *     reason?:            string,     // audit metadata ("login", "mfa", "role-change")
 *     req?:               IncomingMessage, // re-key the device fingerprint to the new sid
 *     fingerprintFields?: Array<string|fn>, // default ["clientIp","userAgent","acceptLanguage"]
 *     idleTimeoutMs?:     number,     // idle floor (default 30m; 0 disables)
 *     absoluteTimeoutMs?: number,     // absolute floor (default 12h; 0 disables)
 *   }
 *
 * rotate() enforces the SAME idle/absolute timeout floor verify() does and
 * fails closed (returns null + deletes) on a session past it — a rotate must
 * never resurrect a session verify() would expire. Pass idleTimeoutMs /
 * absoluteTimeoutMs consistently with the values used at verify() (the policy
 * is per-call): a deployment that disables the idle floor via
 * verify(token, { idleTimeoutMs: 0 }) must pass the same here, or a
 * long-idle-but-valid session is purged on rotation.
 *
 * @example
 *   var rotated = await b.session.rotate(req.cookies.sid, {
 *     ttlMs:  b.constants.TIME.hours(8),
 *     reason: "mfa",
 *   });
 *   if (rotated) {
 *     b.cookies.appendSetCookie(res, b.cookies.serialize("sid", rotated.token, {
 *       httpOnly: true, secure: true, sameSite: "Strict", path: "/",
 *     }));
 *   }
 *   // → { token: "7a1e…", expiresAt: 1735689600000 }
 */
async function rotate(oldToken, opts) {
  cluster.requireLeader();
  if (typeof oldToken !== "string" || oldToken.length === 0) return null;
  opts = opts || {};
  var oldSid = _unsealCookieToken(oldToken);
  if (oldSid === null) return null;

  var newSid       = generateToken(SID_BYTES);
  var newSidHash   = _hashSid(newSid);
  var oldSidHash   = _hashSid(oldSid);
  var nowMs        = Date.now();
  var newExpires = null;
  if (opts.ttlMs !== undefined) {
    _validateTtl(opts.ttlMs, "session.rotate");
    newExpires = nowMs + opts.ttlMs;
  }

  var setCols = { sidHash: newSidHash, lastActivity: nowMs };

  var fpFields = Array.isArray(opts.fingerprintFields) && opts.fingerprintFields.length > 0
    ? opts.fingerprintFields : DEFAULT_FINGERPRINT_FIELDS;
  var existingData = null;
  var rotSelBuilt = sql.select(_sessionSqlTable(), _sessionSqlOpts())
    .columns(["data", "createdAt", "lastActivity"])
    .where("sidHash", oldSidHash)
    .where("expiresAt", ">=", nowMs)
    .toSql();
  var existingRow = await _currentStore().executeOne(rotSelBuilt.sql, rotSelBuilt.params);
  if (!existingRow) return null;
  if (await _floorBreachAndCleanup(existingRow, oldSidHash, nowMs, opts)) return null;
  try {
    var unsealedExisting = cryptoField.unsealRow(SESSION_TABLE, existingRow);
    if (unsealedExisting.data) existingData = safeJson.parse(unsealedExisting.data);
  } catch (_e) { existingData = null; }
  var wasBound = existingData && typeof existingData === "object" &&
                 typeof existingData.__bj_fingerprint === "string";
  var carriedDeviceBinding = (existingData && typeof existingData === "object" &&
                              existingData.__bj_deviceBinding !== undefined)
    ? existingData.__bj_deviceBinding : null;

  if (opts.data !== undefined || wasBound || carriedDeviceBinding !== null) {
    var newDataObj;
    if (opts.data !== undefined) {
      newDataObj = (opts.data && typeof opts.data === "object") ? Object.assign({}, opts.data) : null;
    } else {
      newDataObj = (existingData && typeof existingData === "object") ? Object.assign({}, existingData) : null;
    }
    if (newDataObj) delete newDataObj.__bj_fingerprint;
    if (newDataObj) delete newDataObj.__bj_deviceBinding;
    if (carriedDeviceBinding !== null) {
      if (!newDataObj) newDataObj = {};
      newDataObj.__bj_deviceBinding = carriedDeviceBinding;
    }

    if (wasBound) {
      if (!opts.req) {
        throw _err("session/rotate-fingerprint-req-required",
          "session.rotate: this session is fingerprint-bound; pass { req, fingerprintFields } " +
          "so the device binding can be re-keyed to the new session id", true);
      }
      if (!newDataObj) newDataObj = {};
      newDataObj.__bj_fingerprint = _hashFingerprint(newSid, _buildFingerprintInputs(opts.req, fpFields, _clientIpResolver(opts)));
    }

    var dataJson = newDataObj ? JSON.stringify(newDataObj) : null;
    var sealedRow = cryptoField.sealRow(SESSION_TABLE, { data: dataJson });
    setCols.data = sealedRow.data;
  }
  if (newExpires !== null) {
    setCols.expiresAt = newExpires;
  }

  var updBuilt = sql.update(_sessionSqlTable(), _sessionSqlOpts())
    .set(setCols)
    .where("sidHash", oldSidHash)
    .where("expiresAt", ">=", nowMs)
    .toSql();
  var result = await _currentStore().execute(updBuilt.sql, updBuilt.params);
  if ((result.rowCount || 0) === 0) return null;

  var rowBuilt = sql.select(_sessionSqlTable(), _sessionSqlOpts())
    .columns(["expiresAt"])
    .where("sidHash", newSidHash)
    .toSql();
  var row = await _currentStore().executeOne(rowBuilt.sql, rowBuilt.params);
  var expiresAt = row ? Number(row.expiresAt) : null;

  try {
    audit.emit({
      action:  "auth.session.rotate",
      outcome: "success",
      metadata: { reason: opts.reason || "explicit" },
    });
  } catch (_e) { /* audit emit best-effort — never block rotate() */ }

  return { token: _sealCookieToken(newSid), expiresAt: expiresAt };
}

/**
 * @primitive b.session.updateData
 * @signature b.session.updateData(token, data, opts?)
 * @since     0.8.66
 * @related   b.session.verify, b.session.rotate
 *
 * Update the sealed `data` payload on a session WITHOUT rotating the
 * sid. Use cases: cart-state writes, user-preference flips, step-up-
 * auth completion flags, fingerprint-anomaly score updates. Anything
 * that doesn't change the security boundary (login transition, role
 * escalation, multifactor verified) — those still go through
 * `b.session.rotate({ data })` so the sid moves and any pre-login
 * tokens an attacker may have planted become invalid.
 *
 * Default semantics:
 *   - `data` REPLACES the existing payload (full overwrite). The
 *     reserved `__bj_fingerprint` and `__bj_deviceBinding` keys are
 *     preserved automatically so fingerprint- and device-binding
 *     survive the update. Both are also IGNORED when supplied in
 *     `data`: they decide whether a session is accepted, so the
 *     payload path cannot write them, on either the merge or the
 *     replace path. `b.sessionDeviceBinding` binds and unbinds
 *     through the framework's own writer.
 *   - `lastActivity` is bumped (idle-timeout reset) unless
 *     `opts.touchLastActivity: false`.
 *   - The session must be live (not expired) for the write to land;
 *     returns `false` for unknown / expired tokens.
 *
 * Pass `opts.merge: true` to deep-merge top-level keys into the
 * existing payload instead of replacing — useful for incremental
 * writes where the operator doesn't want to round-trip read+merge
 * themselves. Inner objects merge ONE LEVEL DEEP; arrays REPLACE.
 *
 * Leader-only.
 *
 * @opts
 *   {
 *     merge?:              boolean,   // default false (full replace)
 *     touchLastActivity?:  boolean,   // default true
 *     idleTimeoutMs?:      number,    // idle floor (default 30m; 0 disables)
 *     absoluteTimeoutMs?:  number,    // absolute floor (default 12h; 0 disables)
 *   }
 *
 * updateData() enforces the SAME idle/absolute timeout floor verify() does and
 * fails closed (returns false + deletes) on a session past it — a write must
 * not resurrect a session verify() would expire. The floor policy is per-call:
 * pass idleTimeoutMs / absoluteTimeoutMs consistently with the values used at
 * verify(), or a long-idle-but-valid session (e.g. one accepted under
 * verify(token, { idleTimeoutMs: 0 })) is purged on the next write.
 *
 * @example
 *   // Replace the data payload entirely.
 *   await b.session.updateData(req.cookies.sid, { roles: ["admin"], theme: "dark" });
 *
 *   // Merge a single field without disturbing the rest of the payload.
 *   await b.session.updateData(req.cookies.sid,
 *     { stepUpAt: Date.now() }, { merge: true });
 *   // → true
 */
async function updateData(token, data, opts) {
  return _updateData(token, data, opts, false);
}

async function _setDeviceBinding(token, binding) {
  return _updateData(token, { __bj_deviceBinding: binding }, { merge: true }, true);
}

async function _updateData(token, data, opts, allowReservedBinding) {
  cluster.requireLeader();
  opts = opts || {};
  if (typeof token !== "string" || token.length === 0) return false;
  if (data !== null && (typeof data !== "object" || Array.isArray(data))) {
    throw _err("session/invalid-arg",
      "session.updateData: data must be a plain object or null", true);
  }
  var sid = _unsealCookieToken(token);
  if (sid === null) return false;
  var sidHash = _hashSid(sid);
  var nowMs = Date.now();

  var selBuilt = sql.select(_sessionSqlTable(), _sessionSqlOpts())
    .columns(["userId", "userIdHash", "data", "createdAt", "expiresAt", "lastActivity"])
    .where("sidHash", sidHash)
    .where("expiresAt", ">=", nowMs)
    .toSql();
  var row = await _currentStore().executeOne(selBuilt.sql, selBuilt.params);
  if (!row) return false;
  if (await _floorBreachAndCleanup(row, sidHash, nowMs, opts)) return false;

  var unsealed = cryptoField.unsealRow(SESSION_TABLE, row);
  var existing = null;
  var storedFingerprint = null;
  var storedDeviceBinding = null;
  if (unsealed.data) {
    try {
      existing = safeJson.parse(unsealed.data);
      if (existing && typeof existing === "object" &&
          typeof existing.__bj_fingerprint === "string") {
        storedFingerprint = existing.__bj_fingerprint;
      }
      if (existing && typeof existing === "object" &&
          existing.__bj_deviceBinding !== undefined) {
        storedDeviceBinding = existing.__bj_deviceBinding;
      }
    } catch (_e) {
      existing = null;
      storedFingerprint = null;
      storedDeviceBinding = null;
    }
  }

  var next;
  if (opts.merge === true && existing && typeof existing === "object") {
    next = Object.assign({}, existing);
    if (data && typeof data === "object") {
      Object.keys(data).forEach(function (k) {
        if (k === "__bj_fingerprint") return;
        if (k === "__bj_deviceBinding" && !allowReservedBinding) return;
        var ev = existing[k], nv = data[k];
        if (_isPlainObject(ev) && _isPlainObject(nv)) {
          next[k] = Object.assign({}, ev, nv);
        } else {
          next[k] = nv;
        }
      });
    }
  } else {
    next = (data && typeof data === "object") ? Object.assign({}, data) : null;
    if (next) delete next.__bj_fingerprint;
    if (next && !allowReservedBinding) delete next.__bj_deviceBinding;
  }
  var keepsDeviceBinding = storedDeviceBinding !== null &&
    !(allowReservedBinding && data && typeof data === "object" &&
      Object.prototype.hasOwnProperty.call(data, "__bj_deviceBinding"));
  if ((storedFingerprint || keepsDeviceBinding) && !next) next = {};
  if (storedFingerprint && next) next.__bj_fingerprint = storedFingerprint;
  if (next && keepsDeviceBinding) next.__bj_deviceBinding = storedDeviceBinding;

  var sealedRow = cryptoField.sealRow(SESSION_TABLE, {
    data: next ? JSON.stringify(next) : null,
  });

  var setCols = { data: sealedRow.data };
  if (opts.touchLastActivity !== false) {
    setCols.lastActivity = nowMs;
  }
  var updBuilt = sql.update(_sessionSqlTable(), _sessionSqlOpts())
    .set(setCols)
    .where("sidHash", sidHash)
    .where("expiresAt", ">=", nowMs)
    .toSql();
  var result = await _currentStore().execute(updBuilt.sql, updBuilt.params);
  return (result.rowCount || 0) > 0;
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
 *   var sched = b.scheduler.create();
 *   sched.register("session-purge", b.constants.TIME.hours(1), async function () {
 *     var dropped = await b.session.purgeExpired();
 *     b.audit.emit({
 *       action: "auth.session.purge_expired", outcome: "success",
 *       metadata: { dropped: dropped },
 *     });
 *   });
 *   await sched.start();
 *   // → 17 sessions dropped on each run
 */
async function purgeExpired() {
  cluster.requireLeader();
  var built = sql.delete(_sessionSqlTable(), _sessionSqlOpts())
    .where("expiresAt", "<", Date.now())
    .toSql();
  var result = await _currentStore().execute(built.sql, built.params);
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
  var built = sql.select(_sessionSqlTable(), _sessionSqlOpts())
    .count("*", "c")
    .where("expiresAt", ">=", Date.now())
    .toSql();
  var row = await _currentStore().executeOne(built.sql, built.params);
  return row ? Number(row.c) : 0;
}

function _releaseStore(previous) {
  if (!previous || typeof previous.close !== "function") return null;
  try {
    var result = previous.close();
    safeAsync.containRejection(result);
    return null;
  } catch (e) {
    return e;
  }
}

function _resetForTest() {
  _releaseStore(_store);
  _store = null;
}

/**
 * @primitive b.session.useStore
 * @signature b.session.useStore(store)
 * @since     0.8.61
 * @status    stable
 * @related   b.session.stores.localDbThin
 *
 * Replace the default `_blamejs_sessions` storage backend (the
 * framework's main DB / external DB via cluster-storage) with an
 * operator-supplied store. The store must expose
 * `execute(sql, params)` and `executeOne(sql, params)` returning the
 * same `{ rows, rowCount }` / `row | null` shape `b.clusterStorage`
 * returns. Pass `null` to revert to the default.
 *
 * Typical use is to point session writes at an isolated SQLite file
 * (often tmpfs) so session churn doesn't fight the main DB's encrypted-
 * at-rest re-flush cycle. The first-party adapter is
 * `b.session.stores.localDbThin({ file })`.
 *
 * Call this once at boot, BEFORE the first `session.create` /
 * `session.verify`. Switching stores on a running app strands every
 * existing session in the old store.
 *
 * The store being replaced is CLOSED, when it exposes a `close()` —
 * `b.session.stores.localDbThin` does, because it holds an open SQLite
 * file. Dropping that reference without closing it leaves the handle
 * open for the life of the process, which on Windows blocks removal of
 * the file and of the directory holding it. Reverting with `null` and
 * `b.session._resetForTest()` release it the same way. A store you
 * supplied yourself is closed only if you gave it a `close()`; the
 * required surface is still just `execute` and `executeOne`.
 *
 * Throws `SessionError` (`session/store-close-failed`) when the
 * outgoing store's `close()` throws. The swap has already taken effect
 * by then — the new store is installed and serving — so this reports a
 * handle that may have leaked rather than a call to retry.
 *
 * A `close()` that returns a promise is STARTED, not awaited: this
 * function is synchronous. Its rejection is absorbed so it cannot
 * become an unhandled rejection, which means an asynchronous close
 * failure is not reported here. If your store closes asynchronously
 * and you need to know it finished, await its `close()` yourself
 * before handing the replacement to `useStore`.
 *
 * @example
 *   var b = require("@blamejs/core");
 *   await b.vault.init({ dataDir: "/var/lib/blamejs", mode: "plaintext" });
 *   await b.db.init({ dataDir: "/var/lib/blamejs" });
 *   var sessionStore = b.session.stores.localDbThin({ file: "/dev/shm/sessions.db" });
 *   b.session.useStore(sessionStore);
 *   // Every b.session.* call now routes through the tmpfs file.
 */
function useStore(store) {
  if (store === null || store === undefined) {
    var revertErr = _releaseStore(_store);
    _store = null;
    if (revertErr) {
      throw new SessionError("session/store-close-failed",
        "session.useStore: reverted to the default store, but closing the " +
        "previous one failed: " + revertErr.message);
    }
    return;
  }
  validateOpts.requireMethods(store, ["execute", "executeOne"],
    "session.useStore: store", SessionError, "session/invalid-arg", true);
  var previous = _store;
  _store = store;
  if (previous === store) return;
  var closeErr = _releaseStore(previous);
  if (closeErr) {
    throw new SessionError("session/store-close-failed",
      "session.useStore: installed the new store, but closing the previous " +
      "one failed and its handle may still be open: " + closeErr.message);
  }
}

/**
 * @primitive b.session.isAnonymous
 * @signature b.session.isAnonymous(userId)
 * @since     0.8.62
 * @status    stable
 * @related   b.session.create
 *
 * Returns `true` if the supplied userId was minted by
 * `b.session.create({ anonymous: true })` (i.e., starts with the
 * `anon:` prefix). Operators use this to gate post-auth behavior
 * (e.g., refuse a payment confirmation when the session is still
 * anonymous, or render the "log in to continue" banner).
 *
 * @example
 *   var info = await b.session.verify(req.cookies.sid);
 *   if (info && b.session.isAnonymous(info.userId)) {
 *     res.statusCode = 401; res.end("login required"); return;
 *   }
 */
function isAnonymous(userId) {
  return _isAnonymousUserId(userId);
}

/**
 * @primitive b.session.bump
 * @signature b.session.bump(subjectId, opts?)
 * @since     0.15.13
 * @status    stable
 * @related   b.session.check, b.session.validFrom, b.session.destroyAllForUser
 *
 * Revoke every STATELESS self-validating token (sealed cookie carrying no DB
 * row, JWT) for a subject by raising a durable per-subject valid-from boundary
 * to now. Any token whose issued-at (`iat`) predates the boundary fails
 * `b.session.check`. Unlike `destroyAllForUser` — which deletes server-side
 * session rows — this revokes tokens the framework never stored a row for:
 * log-out-everywhere, a right-to-erasure cutoff, a forced re-auth after a
 * password / key change. `destroyAllForUser` calls this for you, so a single
 * "logout everywhere" covers both store-backed and stateless tokens.
 *
 * The boundary is MONOTONIC: it only ever moves forward. A bump to an
 * `epochMs` at or below the stored value is a no-op — a replayed or
 * clock-skewed lower value can never widen a revoked window back open. Returns
 * the boundary in effect after the call. Leader-only. The subject id is stored
 * hashed; the plaintext id never lands in the table.
 *
 * @opts
 *   epochMs:  number,   // boundary to set; default Date.now(). Tokens with iat < this are revoked.
 *
 * @example
 *   // Force re-auth everywhere for a subject after a password change:
 *   var boundary = await b.session.bump("user-42");
 *   // Cut off at a specific instant (right-to-erasure effective time):
 *   await b.session.bump("user-42", { epochMs: erasureEffectiveMs });
 */
async function bump(subjectId, opts) {
  cluster.requireLeader();
  if (typeof subjectId !== "string" || subjectId.length === 0) {
    throw _err("session/invalid-arg", "session.bump requires a non-empty subjectId", true);
  }
  opts = opts || {};
  var epochMs = opts.epochMs === undefined ? Date.now() : opts.epochMs;
  if (typeof epochMs !== "number" || !isFinite(epochMs) || epochMs < 0) {
    throw _err("session/invalid-arg",
      "session.bump: epochMs must be a non-negative finite number, got " + JSON.stringify(epochMs), true);
  }
  var subjectHash = _hashSubjectId(subjectId);
  var t = _validFromSqlTable();
  var dialect = clusterStorage.dialect();
  var refs = _validFromConflictRefs(dialect, t);

  var validFromExpr = "CASE WHEN " + refs.proposed("validFromEpoch") + " > " +
    refs.existing("validFromEpoch") + " THEN " + refs.proposed("validFromEpoch") +
    " ELSE " + refs.existing("validFromEpoch") + " END";
  var built = sql.upsert(t, _sessionSqlOpts())
    .columns(["subjectHash", "validFromEpoch", "updatedAt"])
    .values({ subjectHash: subjectHash, validFromEpoch: epochMs, updatedAt: Date.now() })
    .onConflict(["subjectHash"])
    .doUpdate({ validFromEpoch: validFromExpr, updatedAt: "?" }, [Date.now()])
    .returning(["validFromEpoch"])
    .toSql();
  var row = await _runValidFrom(async function (target) {
    if (built.readbackSql) {
      await target.execute(built.sql, built.params);
      var readback = await target.execute(built.readbackSql.sql, built.readbackSql.params);
      return readback.rows && readback.rows[0];
    }
    var result = await target.execute(built.sql, built.params);
    return result.rows && result.rows[0];
  });
  var effective = row ? Number(row.validFromEpoch) : epochMs;

  // already drop-silent internally).
  try {
    audit.safeEmit({
      action:   "auth.session.valid_from_bump",
      outcome:  "success",
      metadata: { validFromEpoch: effective },
    });
  } catch (_ignored) { /* audit best-effort */ }

  return effective;
}

/**
 * @primitive b.session.validFrom
 * @signature b.session.validFrom(subjectId)
 * @since     0.15.13
 * @status    stable
 * @related   b.session.bump, b.session.check
 *
 * Read the current valid-from boundary (epoch ms) for a subject. Returns `0`
 * when the subject has never been bumped — no token is revoked by boundary, so
 * any non-negative token `iat` passes `b.session.check`. Runs anywhere (leader
 * or follower) — it only reads. The subject id is hashed before lookup; the
 * plaintext id never lands in the table.
 *
 * @example
 *   var boundary = await b.session.validFrom("user-42");
 *   // → 1735689600000  (last bump)   or   0  (never bumped)
 */
async function validFrom(subjectId) {
  if (typeof subjectId !== "string" || subjectId.length === 0) return 0;
  var built = sql.select(_validFromSqlTable(), _sessionSqlOpts())
    .columns(["validFromEpoch"])
    .where("subjectHash", _hashSubjectId(subjectId))
    .toSql();
  var row = await _runValidFrom(async function (target) {
    var result = await target.execute(built.sql, built.params);
    return result.rows && result.rows.length > 0 ? result.rows[0] : null;
  });
  return row ? Number(row.validFromEpoch) : 0;
}

/**
 * @primitive b.session.check
 * @signature b.session.check(subjectId, tokenIatMs)
 * @since     0.15.13
 * @status    stable
 * @related   b.session.bump, b.session.validFrom
 *
 * Decide whether a stateless self-validating token is still valid against the
 * subject's valid-from boundary. Returns `true` when the token's issued-at
 * (`tokenIatMs`, epoch ms) is at or after the boundary; `false` when the token
 * was issued before the last `bump` (revoked). A subject that was never bumped
 * has boundary `0`, so any non-negative `iat` is valid. Runs anywhere.
 *
 * Fails CLOSED: a non-finite / negative / non-number `tokenIatMs` returns
 * `false` (treat an unparseable token as revoked rather than admit it). Call
 * this AFTER the token's own signature + expiry checks pass — it is the
 * server-side revocation layer those stateless checks otherwise lack.
 *
 * @example
 *   // jwt already signature- and exp-verified; iat is in seconds → ms:
 *   var ok = await b.session.check(claims.sub, claims.iat * 1000);
 *   if (!ok) { res.statusCode = 401; res.end("session revoked"); return; }
 */
async function check(subjectId, tokenIatMs) {
  if (typeof tokenIatMs !== "number" || !isFinite(tokenIatMs) || tokenIatMs < 0) {
    return false;
  }
  var boundary = await validFrom(subjectId);
  return tokenIatMs >= boundary;
}

module.exports = {
  create:               create,
  verify:               verify,
  destroy:              destroy,
  logout:               logout,
  destroyAllForUser:    destroyAllForUser,
  touch:                touch,
  rotate:               rotate,
  updateData:           updateData,
  _setDeviceBinding:    _setDeviceBinding,
  purgeExpired:         purgeExpired,
  count:                count,
  bump:                 bump,
  validFrom:            validFrom,
  check:                check,
  useStore:             useStore,
  isAnonymous:          isAnonymous,
  stores:               require("./session-stores"),                                              // allow:inline-require — session-stores depends on local-db-thin which requires audit lazily; eager require is fine here
  DEFAULT_TTL_MS:       DEFAULT_TTL_MS,
  ANON_PREFIX:          ANON_PREFIX,
  _resetForTest:        _resetForTest,
};
