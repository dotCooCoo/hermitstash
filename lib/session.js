/**
 * A facade over the framework's session primitive, backed by its own SQLite
 * file on tmpfs rather than a table in the main database: a write on every
 * request would otherwise fight that database's WAL fsync and its periodic
 * encrypt-at-rest flush, and session state has no business in that snapshot.
 *
 * A request that presents no session cookie gets a new anonymous session to
 * hold CSRF tokens, OAuth state and passkey challenges before anyone signs in.
 * Anonymous sessions have a synthetic `anon:` user id. A request that
 * isSessionlessRequest matches gets an empty session instead, which is neither
 * stored nor sent as a cookie. Signing in destroys the anonymous session and
 * creates one under the real user id with the same data.
 */
"use strict";

var nodePath = require("node:path");
var nodeFs = require("node:fs");
var b = require("./vendor/blamejs");
var config = require("./config");
var clientIp = require("./client-ip");
var { TIME, DATA_DIR: _dataDir } = require("./constants");
var C = require("./constants");

var COOKIE_NAME      = "hs_sid";
var MAX_AGE          = TIME.days(7);
var DEFAULT_IDLE_MS  = TIME.minutes(30);
var DEFAULT_ABSOLUTE_MS = TIME.hours(12);
var PURGE_BATCH_LIMIT = 256;
var COMPACT_MIN_BYTES = C.BYTES.mib(16);
var SESSION_TABLE     = b.frameworkSchema.tableName("_blamejs_sessions");

// A GET for one of these paths that presents no session cookie stores no
// session. Health probes, crawlers, API clients and browsers fetching the web
// app manifest request these paths. Their handlers do not read the session.
var SESSIONLESS_PATHS = ["/health", "/sitemap.xml", "/manifest.json", "/.well-known/blamejs-pubkey"];

// A session is bound to the client's IP prefix and user agent by default. Its
// age is limited to SESSION_ABSOLUTE_TIMEOUT_MS when that is set and to
// DEFAULT_ABSOLUTE_MS otherwise. A value of 0 turns the limit off.
function _resolveFingerprintFields() {
  var raw = b.safeEnv.readVar("SESSION_FINGERPRINT_FIELDS");
  if (!raw) return ["clientIpPrefix", "userAgent"];
  return raw.split(",").map(function (f) { return f.trim(); }).filter(Boolean);
}
function _resolveAbsoluteTimeoutMs() {
  var raw = parseInt(b.safeEnv.readVar("SESSION_ABSOLUTE_TIMEOUT_MS") || "", 10);
  return Number.isFinite(raw) && raw >= 0 ? raw : DEFAULT_ABSOLUTE_MS;
}
var FINGERPRINT_FIELDS    = _resolveFingerprintFields();
var ABSOLUTE_TIMEOUT_MS   = _resolveAbsoluteTimeoutMs();

// Resolve tmpfs preference for the sessions DB.
var _tmpDir = b.safeEnv.readVar("HERMITSTASH_TMPDIR")
  || (nodeFs.existsSync("/dev/shm") ? "/dev/shm" : _dataDir);
var sessionDbPath = nodePath.join(_tmpDir, b.safeEnv.readVar("HERMITSTASH_SESSION_DB") || "hermitstash-sessions.db");

// The path is predictable and sits in a world-writable tmpfs directory, so the
// create has to refuse a symlink planted there — hence O_NOFOLLOW, which fails
// the open instead of redirecting the write.
try {
  if (process.platform !== "win32") {
    var _sessFd = b.atomicFile.openAppendNoFollowSync(sessionDbPath, 0o600);
    nodeFs.closeSync(_sessFd);
  }
} catch (_e) { /* file pre-existing, symlink refused, or fs error — non-fatal */ }

// Wire the framework session primitive at module-load time. Subsequent
// b.session.{create, verify, ...} calls go to this store. journal_size_limit
// truncates the write-ahead log to 4 MiB at each checkpoint, and temp_store
// keeps the copy that VACUUM builds in memory.
var _sessionStore = b.session.stores.localDbThin({
  file:    sessionDbPath,
  pragmas: { journal_size_limit: C.BYTES.mib(4), temp_store: "MEMORY" },
});
b.session.useStore(_sessionStore);

// b.db.init would register this, but HS owns its own database lifecycle and
// never calls it — without the entry, destroyAllForUser cannot compute the
// userIdHash and fails. Mirrors the framework's own definition; keep the two in
// step if it extends the schema.
b.cryptoField.registerTable("_blamejs_sessions", {
  sealedFields:  ["userId", "data"],
  derivedHashes: { userIdHash: { from: "userId" } },
});

// Bounded, and null-prototype, so an attacker-controlled Cookie header can
// neither pollute the prototype chain nor burn CPU on a pathological payload.
// Values arrive URL-decoded, so a caller must NOT decode them again.
function parseCookies(req) {
  return b.cookies.parseSafe(req.headers.cookie || "").jar;
}

function _anonUserId() {
  return "anon:" + b.crypto.generateToken(C.BYTES.bytes(16));
}

// `Secure` follows the scheme the request actually arrived on, peer-gated so a
// forwarded header counts only from a declared trusted proxy. Deriving it from
// config.rpOrigin would read the scheme the operator NAMED instead: with the
// https origin passkeys require, a plain-HTTP visitor is sent a Secure cookie,
// the browser discards it, and every later request arrives unauthenticated.
function _setSessionCookie(req, res, token) {
  var secure = clientIp.isSecureRequest(req) ? "; Secure" : "";
  var cookie = COOKIE_NAME + "=" + encodeURIComponent(token)
             + "; Path=/; HttpOnly; SameSite=Lax" + secure
             + "; Max-Age=" + (MAX_AGE / C.TIME.seconds(1));
  var existing = res.getHeader("Set-Cookie") || [];
  var arr = Array.isArray(existing) ? existing : (existing ? [existing] : []);
  // Drop any previous Set-Cookie for hs_sid we wrote (regenerate path)
  // so the response only carries the latest token.
  arr = arr.filter(function (c) { return !c.startsWith(COOKIE_NAME + "="); });
  arr.push(cookie);
  res.setHeader("Set-Cookie", arr);
}

// A request is sessionless when it presents no session cookie and it carries a
// bearer credential, is a HEAD or OPTIONS request, or is a GET for one of
// SESSIONLESS_PATHS. The router has no HEAD or OPTIONS routes.
function isSessionlessRequest(req, cookies) {
  if (cookies[COOKIE_NAME]) return false;
  if (b.requestHelpers.extractBearer(req)) return true;
  var method = String(req.method || "").toUpperCase();
  if (method === "HEAD" || method === "OPTIONS") return true;
  if (method !== "GET") return false;
  return SESSIONLESS_PATHS.indexOf(req.pathname || "") !== -1;
}

// ---- middleware ----

async function sessionMiddleware(req, res, next) {
  try {
    // verify, updateData and touch all receive these timeouts.
    var floors = {
      idleTimeoutMs:     config.sessionIdleTimeout || DEFAULT_IDLE_MS,
      absoluteTimeoutMs: ABSOLUTE_TIMEOUT_MS,
    };

    // Track the live token in closure scope so res.writeHead and
    // req.regenerateSession see the most recent value after a rotation. The
    // token stays null on a sessionless request until a handler calls
    // req.regenerateSession.
    var token = null;

    var cookies = parseCookies(req);
    var sessionless = isSessionlessRequest(req, cookies);
    if (cookies[COOKIE_NAME]) {
      // parseCookies (b.cookies.parseSafe) already URL-decodes — no
      // second decodeURIComponent here.
      var candidateToken = cookies[COOKIE_NAME];
      var verified = await b.session.verify(candidateToken, {
        req: req,
        idleTimeoutMs: floors.idleTimeoutMs,
        absoluteTimeoutMs: floors.absoluteTimeoutMs,
        fingerprintFields: FINGERPRINT_FIELDS,
        requireFingerprintMatch: true,         // hard-kill on UA / IP-prefix drift
        clientIpResolver: clientIp.getIp,      // proxy-aware IP so clientIpPrefix is stable behind nginx/Docker
      });
      if (verified) {
        token = candidateToken;
        req.session = verified.data || {};
      }
    }

    if (!token && !sessionless) {
      // No cookie / expired / drift / unknown → fresh anonymous session.
      var created = await b.session.create({
        userId: _anonUserId(),
        ttlMs: MAX_AGE,
        data: {},
        req: req,
        fingerprintFields: FINGERPRINT_FIELDS,
        clientIpResolver: clientIp.getIp,
      });
      token = created.token;
      req.session = {};
    }
    if (!token) req.session = {};

    req.sessionId = token;

    // Login + 2FA pending + 2FA complete all rotate the sid to defeat
    // session-fixation. Use destroy + create so the new userId is bound
    // at the storage layer (b.session.rotate keeps the existing userId,
    // which would leave the row glued to the anonymous identity).
    req.regenerateSession = async function (opts) {
      opts = opts || {};
      var carriedData = Object.assign({}, req.session);
      // Strip the framework's reserved fingerprint key so create() can
      // re-derive it from req.headers + the new sid (its own salt).
      delete carriedData.__bj_fingerprint;
      var newUserId = opts.userId || _anonUserId();
      if (token) {
        try { await b.session.destroy(token); } catch (_e) { /* the old token is already gone */ }
      }
      var created2 = await b.session.create({
        userId: newUserId,
        ttlMs: MAX_AGE,
        data: carriedData,
        req: req,
        fingerprintFields: FINGERPRINT_FIELDS,
        clientIpResolver: clientIp.getIp,
      });
      token = created2.token;
      req.session = carriedData;
      req.sessionId = token;
    };

    // Two hooks, because the cookie and the flush have different deadlines.
    // writeHead sets the cookie synchronously, since a route may write before
    // it ends and the headers must be committed by then. end awaits the flush
    // before handing off — without that wait, the next request can arrive
    // before the previous one's mutations are stored, so verify() reads stale
    // data and the middleware downstream re-creates fields that already exist.
    var origWriteHead = res.writeHead.bind(res);
    res.writeHead = function (statusCode, ...rest) {
      // secureLogout has already queued the expiry on this response, and
      // re-setting the live cookie here would clobber it, leaving the browser
      // holding a cookie for a session that no longer exists.
      if (token && !res._sessionLoggedOut) {
        _setSessionCookie(req, res, token);
      }
      return origWriteHead(statusCode, ...rest);
    };
    var origEnd = res.end.bind(res);
    res.end = function (chunk, encoding, callback) {
      // On a sessionless request that did not call req.regenerateSession, end
      // stores nothing.
      if (!token) return origEnd.apply(null, arguments);
      if (typeof chunk === "function") { callback = chunk; chunk = undefined; encoding = undefined; }
      else if (typeof encoding === "function") { callback = encoding; encoding = undefined; }
      // updateData stores the session data and leaves lastActivity alone. touch
      // sets lastActivity to the current time and expiresAt to MAX_AGE from
      // now. It is skipped when a route sets req._skipActivityUpdate, which the
      // liveness heartbeat does.
      var ops = [b.session.updateData(token, req.session, {
        touchLastActivity: false,
        idleTimeoutMs:     floors.idleTimeoutMs,
        absoluteTimeoutMs: floors.absoluteTimeoutMs,
      }).catch(function (_e) { /* persist best-effort */ })];
      if (!req._skipActivityUpdate) {
        ops.push(b.session.touch(token, {
          extendBy:          MAX_AGE,
          idleTimeoutMs:     floors.idleTimeoutMs,
          absoluteTimeoutMs: floors.absoluteTimeoutMs,
        }).catch(function (_e) { /* lastActivity best-effort */ }));
      }
      Promise.all(ops).then(function () {
        if (chunk !== undefined) origEnd(chunk, encoding, callback);
        else if (callback) origEnd(callback);
        else origEnd();
      });
      return res;
    };

    next();
  } catch (err) {
    next(err);
  }
}

// ---- HS API surface (unchanged shape; routes unchanged) ----

async function clearSessionsForUser(userId) {
  if (!userId) return 0;
  // Deletes the stored rows and raises the per-subject valid-from boundary. An
  // error here means the revocation itself failed and must propagate: reporting
  // a failed "sign out everywhere", suspension or deletion as zero sessions
  // closed is worse than the error.
  return await b.session.destroyAllForUser(userId);
}

async function clearSessionById(token) {
  if (!token) return false;
  try { return await b.session.destroy(token); }
  catch (_e) { return false; }
}

// Destroys the session row and tells the browser to drop its own state, via a
// Clear-Site-Data header and an expired cookie. Unlike clearSessionById this
// reaches the live response, so a stale tab cannot replay the revoked cookie.
//
// Three things it must get right:
//
// res._sessionLoggedOut, or the middleware re-emits a live cookie on this same
// response and clobbers the expiry written here.
//
// cookieName, because the framework defaults to a different name and would
// expire the wrong cookie while leaving this one live.
//
// secure, because a browser discards a Secure cookie arriving over plain HTTP —
// so on a cleartext deployment the expiry is dropped and the very cookie this
// call exists to clear stays in the jar. The session is destroyed either way,
// leaving a dead cookie rather than a live session, but it is still sent on
// every later request. The value comes from clientIp rather than from handing
// the framework the request, because the framework's own resolver does not have
// HS's trusted-proxy list and would answer false behind a TLS-terminating proxy
// where _setSessionCookie answers true.
async function secureLogout(res, token, req) {
  if (res) res._sessionLoggedOut = true;
  if (!token) return false;
  var opts = { cookieName: COOKIE_NAME };
  if (req) opts.secure = clientIp.isSecureRequest(req);
  try { return await b.session.logout(res, token, opts); }
  catch (_e) { return false; }
}

async function clearAllSessions() {
  // b.session has no purge-all primitive; the operator-shape "revoke
  // every session" requires a direct table delete. Hitting the
  // localDbThin store here is fine — it's the only consumer of this
  // file and the schema is owned by `b.session`.
  var all = b.sql.delete(SESSION_TABLE, { dialect: "sqlite" }).allowNoWhere().toSql();
  await _sessionStore.execute(all.sql, all.params);
  return true;
}

// purgeStaleSessions deletes every stored session that b.session.verify
// refuses: one past its expiresAt, one idle for longer than the configured idle
// timeout, and one older than ABSOLUTE_TIMEOUT_MS unless that is 0. It calls
// b.session.purgeStale, which deletes PURGE_BATCH_LIMIT rows at a time and
// returns the number of rows it deleted. Each delete repeats the stale
// condition. A session used between the select and the delete of its batch is
// kept.
async function purgeStaleSessions() {
  return b.session.purgeStale({
    idleTimeoutMs:     config.sessionIdleTimeout || DEFAULT_IDLE_MS,
    absoluteTimeoutMs: ABSOLUTE_TIMEOUT_MS,
    batchSize:         PURGE_BATCH_LIMIT,
  });
}

async function _pragmaNumber(sql, column) {
  var result = await _sessionStore.execute(sql, []);
  return Number(result.rows[0][column]);
}

// compactSessionStore rewrites the store file with VACUUM when the file is at
// least COMPACT_MIN_BYTES and free pages make up at least half of it, then
// truncates the write-ahead log. It returns true when it rewrote the file.
async function compactSessionStore() {
  var pages = await _pragmaNumber("SELECT * FROM pragma_page_count", "page_count");
  var free = await _pragmaNumber("SELECT * FROM pragma_freelist_count", "freelist_count");
  var pageSize = await _pragmaNumber("SELECT * FROM pragma_page_size", "page_size");
  if (pages * pageSize < COMPACT_MIN_BYTES || free * 2 < pages) return false;
  await _sessionStore.execute("VACUUM", []);
  await _sessionStore.execute("PRAGMA wal_checkpoint(TRUNCATE)", []);
  return true;
}

// The store is opened at module load, and on Windows an open handle blocks
// removal of the file and its directory — so a process that used sessions and
// never called this leaves its store directory behind. Idempotent, and safe on
// a store that was never opened.
function closeStore() {
  try {
    if (_sessionStore && typeof _sessionStore.close === "function") _sessionStore.close();
    return true;
  } catch (_e) {
    return false;
  }
}

async function getSessionData(token) {
  if (!token) return null;
  try {
    var verified = await b.session.verify(token, {});
    return verified ? (verified.data || null) : null;
  } catch (_e) {
    return null;
  }
}

module.exports = {
  sessionMiddleware:    sessionMiddleware,
  parseCookies:         parseCookies,
  clearSessionsForUser: clearSessionsForUser,
  clearSessionById:     clearSessionById,
  secureLogout:         secureLogout,
  clearAllSessions:     clearAllSessions,
  purgeStaleSessions:   purgeStaleSessions,
  compactSessionStore:  compactSessionStore,
  getSessionData:       getSessionData,
  closeStore:           closeStore,
};
