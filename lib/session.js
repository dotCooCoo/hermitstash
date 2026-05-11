/**
 * Session — thin facade over `b.session` backed by a tmpfs SQLite
 * store via `b.session.stores.localDbThin`.
 *
 * Why `b.session`: the framework's session primitive carries the same
 * vault-sealed-cookie envelope HermitStash had hand-rolled (ML-KEM-1024
 * + P-384 hybrid + XChaCha20-Poly1305 via `b.vault.seal`), the same
 * `/24` IPv4 + `/64` IPv6 fingerprint binding (via the
 * `clientIpPrefix` field), and the same idle-timeout semantics. v0.8.66
 * landed `b.session.updateData` — the missing primitive that makes the
 * full migration tractable. Earlier versions exposed only `touch` (no
 * data persist) and `rotate` (rotates the sid, breaking cookie
 * continuity), so HS had no way to flush per-request session.data
 * mutations back to storage between requests.
 *
 * Why a separate tmpfs SQLite file (instead of `_blamejs_sessions` in
 * the main DB): session writes on every request would fight the main
 * DB's WAL fsync + 5-minute encrypt-at-rest re-flush cycle. Routing
 * session writes to a dedicated tmpfs file (default `/dev/shm`) keeps
 * them RAM-fast and out of the encrypted-at-rest snapshot.
 *
 * On-the-wire cookie shape: HS strips the leading `vault:` envelope
 * prefix from the cookie value to save bytes (`b.session.create`
 * returns the prefixed token; we strip on Set-Cookie and re-add before
 * `b.session.verify`). The actual sealed payload is identical to what
 * `b.session` produces by default — same ciphertext, same envelope
 * version. The sid INSIDE the envelope is also the same shape (32-byte
 * hex token).
 *
 * Anonymous sessions: HS creates a session for every visitor on the
 * first request (so CSRF tokens, OAuth state, passkey challenges all
 * have a place to live before login). `b.session.create` requires a
 * `userId`, so anonymous visitors get `userId = "anon:<random>"`. On
 * login, `req.regenerateSession({ userId })` destroys the anonymous
 * session and creates a new one with the real user id, copying the
 * existing session.data forward — preventing session-fixation attacks
 * while keeping pre-login CSRF state continuous.
 *
 * Storage migration on upgrade: pre-v1.9.29 sessions lived in HS's
 * `sessions` table with raw-sid PK. v1.9.29+ uses
 * `b.session.stores.localDbThin`'s `_blamejs_sessions` table with
 * sha3-hashed sid PK. The two are incompatible, so existing sessions
 * are invalidated on the upgrade boot — every user re-authenticates
 * once. Pre-v1 framework, no compat shim ships.
 */
"use strict";

var path = require("path");
var fs = require("fs");
var b = require("./vendor/blamejs");
var config = require("./config");
var { TIME, DATA_DIR: _dataDir } = require("./constants");
var C = require("./constants");

var COOKIE_NAME      = "hs_sid";
var MAX_AGE          = TIME.days(7);
var DEFAULT_IDLE_MS  = TIME.minutes(30);

// Operator-tunable knobs surfaced as env vars (admin → Branding can
// expose later). Defaults match the framework's recommended posture
// for HS's threat model — strict /24+/64 subnet binding, no absolute
// timeout (TTL = MAX_AGE bounds lifetime).
function _resolveFingerprintFields() {
  var raw = b.safeEnv.readVar("SESSION_FINGERPRINT_FIELDS");
  if (!raw) return ["clientIpPrefix", "userAgent"];
  return raw.split(",").map(function (f) { return f.trim(); }).filter(Boolean);
}
function _resolveAbsoluteTimeoutMs() {
  var raw = parseInt(b.safeEnv.readVar("SESSION_ABSOLUTE_TIMEOUT_MS") || "", 10);
  return Number.isFinite(raw) && raw >= 0 ? raw : 0;
}
var FINGERPRINT_FIELDS    = _resolveFingerprintFields();
var ABSOLUTE_TIMEOUT_MS   = _resolveAbsoluteTimeoutMs();

// Resolve tmpfs preference for the sessions DB.
var _tmpDir = b.safeEnv.readVar("HERMITSTASH_TMPDIR")
  || (fs.existsSync("/dev/shm") ? "/dev/shm" : _dataDir);
var sessionDbPath = path.join(_tmpDir, b.safeEnv.readVar("HERMITSTASH_SESSION_DB") || "hermitstash-sessions.db");

// Harden the file mode on Unix (owner-only). Best-effort — Windows
// has no equivalent, file permissions are governed by ACLs.
try {
  if (process.platform !== "win32") {
    fs.writeFileSync(sessionDbPath, "", { flag: "a", mode: 0o600 });
  }
} catch (_e) { /* file pre-existing or fs error — non-fatal */ }

// Wire the framework session primitive at module-load time. Subsequent
// b.session.{create, verify, ...} calls go to this store.
var _sessionStore = b.session.stores.localDbThin({ file: sessionDbPath });
b.session.useStore(_sessionStore);

// Register the _blamejs_sessions schema with cryptoField. b.db.init
// would do this automatically as part of FRAMEWORK_SCHEMA, but we're
// not calling b.db.init for sessions (HS owns its main DB lifecycle).
// Without this, b.session.destroyAllForUser fails with "_blamejs_sessions
// schema is missing the userIdHash derived hash" because cryptoField
// can't compute the hash without the schema entry. Mirrors
// lib/vendor/blamejs/lib/db.js's FRAMEWORK_SCHEMA `_blamejs_sessions`
// table definition byte-for-byte — keep these in sync if blamejs
// extends the schema.
b.cryptoField.registerTable("_blamejs_sessions", {
  sealedFields:  ["userId", "data"],
  derivedHashes: { userIdHash: { from: "userId" } },
});

function parseCookies(req) {
  var cookies = {};
  var header = req.headers.cookie || "";
  header.split(";").forEach(function (c) {
    var idx = c.indexOf("=");
    if (idx === -1) return;
    var key = c.substring(0, idx).trim();
    var val = c.substring(idx + 1).trim();
    if (key) cookies[key] = val;
  });
  return cookies;
}

function _anonUserId() {
  return "anon:" + b.crypto.generateToken(C.BYTES.bytes(16));
}

// Cookie value is the framework-emitted token verbatim (vault:-
// prefixed envelope). Pre-v1.9.30 HS stripped the prefix to save 7
// wire bytes — that strip-and-restore dance is gone now; framework-
// shape parity wins over the byte savings. Existing pre-v1.9.30
// cookies don't have the prefix and naturally fail b.session.verify
// on first request after upgrade — affected users re-authenticate.
function _setSessionCookie(res, token) {
  var secure = config.rpOrigin && config.rpOrigin.startsWith("https") ? "; Secure" : "";
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

// ---- middleware ----

async function sessionMiddleware(req, res, next) {
  try {
    var idleTimeoutMs = config.sessionIdleTimeout || DEFAULT_IDLE_MS;

    // Track the live token in closure scope so res.writeHead and
    // req.regenerateSession see the most recent value after a rotation.
    var token = null;

    var cookies = parseCookies(req);
    if (cookies[COOKIE_NAME]) {
      var candidateToken = decodeURIComponent(cookies[COOKIE_NAME]);
      var verified = await b.session.verify(candidateToken, {
        req: req,
        idleTimeoutMs: idleTimeoutMs,
        absoluteTimeoutMs: ABSOLUTE_TIMEOUT_MS,
        fingerprintFields: FINGERPRINT_FIELDS,
        requireFingerprintMatch: true,         // hard-kill on UA / IP-prefix drift
      });
      if (verified) {
        token = candidateToken;
        req.session = verified.data || {};
      }
    }

    if (!token) {
      // No cookie / expired / drift / unknown → fresh anonymous session.
      var created = await b.session.create({
        userId: _anonUserId(),
        ttlMs: MAX_AGE,
        data: {},
        req: req,
        fingerprintFields: FINGERPRINT_FIELDS,
      });
      token = created.token;
      req.session = {};
    }

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
      try { await b.session.destroy(token); } catch (_e) { /* old token already gone — proceed */ }
      var created2 = await b.session.create({
        userId: newUserId,
        ttlMs: MAX_AGE,
        data: carriedData,
        req: req,
        fingerprintFields: FINGERPRINT_FIELDS,
      });
      token = created2.token;
      req.session = carriedData;
      req.sessionId = token;
    };

    // Persist any req.session mutations + bump lastActivity + (re)set
    // the cookie before the response goes out. Two hook points:
    //
    //   - writeHead wraps to set the cookie and capture status/headers
    //     synchronously (the route may call res.write before res.end,
    //     so headers must be committed early). The cookie write is
    //     synchronous; only the SQL flush is deferred.
    //
    //   - end wraps to await the b.session.updateData + .touch flush
    //     BEFORE calling origEnd. Without this delay, the next request
    //     can land on the server before the previous request's session
    //     mutations are persisted, so verify() reads stale data and
    //     downstream middleware (api-encrypt's apiKey handshake, csrf-
    //     policy's _csrf token) re-creates the field, breaking the
    //     same-session continuity the test client expects.
    var origWriteHead = res.writeHead.bind(res);
    res.writeHead = function (statusCode, ...rest) {
      _setSessionCookie(res, token);
      return origWriteHead(statusCode, ...rest);
    };
    var origEnd = res.end.bind(res);
    res.end = function (chunk, encoding, callback) {
      if (typeof chunk === "function") { callback = chunk; chunk = undefined; encoding = undefined; }
      else if (typeof encoding === "function") { callback = encoding; encoding = undefined; }
      Promise.all([
        b.session.updateData(token, req.session).catch(function (_e) { /* persist best-effort */ }),
        b.session.touch(token, { extendBy: MAX_AGE }).catch(function (_e) { /* lastActivity best-effort */ }),
      ]).then(function () {
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
  return b.session.destroyAllForUser(userId);
}

async function clearSessionById(token) {
  if (!token) return false;
  try { return await b.session.destroy(token); }
  catch (_e) { return false; }
}

async function clearAllSessions() {
  // b.session has no purge-all primitive; the operator-shape "revoke
  // every session" requires a direct table delete. Hitting the
  // localDbThin store here is fine — it's the only consumer of this
  // file and the schema is owned by `b.session`.
  await _sessionStore.execute("DELETE FROM _blamejs_sessions", []);
  return true;
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
  clearAllSessions:     clearAllSessions,
  getSessionData:       getSessionData,
};
