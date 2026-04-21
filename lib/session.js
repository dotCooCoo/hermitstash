/**
 * Session store — SQLite-on-tmpfs, vault-sealed session data.
 *
 * Why tmpfs (RAM): sessions are ephemeral by design. Losing them on
 * reboot just forces re-login, which is an acceptable UX cost in exchange
 * for never writing session state (which can include 2FA-verified flags,
 * cert fingerprints, and other sensitive markers) to physical disk.
 * Preference order: HERMITSTASH_TMPDIR env → /dev/shm → data dir fallback.
 * The fallback path lands on physical disk, but only when /dev/shm is
 * unavailable (e.g. macOS, some containers) — still sealed via vault, so
 * at-rest contents are XChaCha20-Poly1305 encrypted regardless.
 *
 * Every row's `data` column is vault.seal()'d before INSERT and
 * vault.unseal()'d after SELECT — the raw SQLite file is opaque if read
 * by anything other than this process with the vault key loaded.
 *
 * Uses Node's built-in node:sqlite (no npm dependency). WAL + synchronous=NORMAL
 * for throughput; per-session durability isn't needed because the whole store
 * is ephemeral.
 */
var path = require("path");
var { DatabaseSync } = require("node:sqlite");
var config = require("./config");
var vault = require("./vault");
var { generateToken } = require("./crypto");
var { VAULT_PREFIX, DATA_DIR: _dataDir, TIME } = require("./constants");

var COOKIE_NAME = "hs_sid";
var MAX_AGE = TIME.SEVEN_DAYS;

function generateId() {
  return generateToken(32);
}

function tryUnseal(sealed) { try { return vault.unseal(sealed); } catch (_e) { return null; } }

// SQLite-backed session store on tmpfs (RAM) — never touches physical disk
// Sessions are ephemeral; losing them on reboot just forces re-login
var _tmpDir = process.env.HERMITSTASH_TMPDIR || (require("fs").existsSync("/dev/shm") ? "/dev/shm" : _dataDir);
var sessionDbPath = path.join(_tmpDir, process.env.HERMITSTASH_SESSION_DB || "hermitstash-sessions.db");
// Harden file permissions (owner-only on Unix)
try { if (process.platform !== "win32") require("fs").writeFileSync(sessionDbPath, "", { flag: "a", mode: 0o600 }); } catch (_e) {}
var sdb = new DatabaseSync(sessionDbPath);
sdb.exec("PRAGMA journal_mode=WAL");  // SQLite exec, not child_process
sdb.exec("PRAGMA synchronous=NORMAL");
sdb.exec("CREATE TABLE IF NOT EXISTS sessions (sid TEXT PRIMARY KEY, data TEXT, expires INTEGER, lastActivity INTEGER)");
try { sdb.prepare("ALTER TABLE sessions ADD COLUMN lastActivity INTEGER").run(); } catch (_e) { /* already exists */ }

var stmtGet = sdb.prepare("SELECT data, expires, lastActivity FROM sessions WHERE sid = ?");
var stmtSet = sdb.prepare("INSERT OR REPLACE INTO sessions (sid, data, expires, lastActivity) VALUES (?, ?, ?, ?)");
var stmtDel = sdb.prepare("DELETE FROM sessions WHERE sid = ?");
var stmtClean = sdb.prepare("DELETE FROM sessions WHERE expires < ?");
var stmtAll = sdb.prepare("SELECT sid, data FROM sessions");

var sessions = {
  get: function (sid) {
    var row = stmtGet.get(sid);
    if (!row) return undefined;
    var json = tryUnseal(row.data);
    if (!json) return undefined;
    try { return { data: JSON.parse(json), expires: row.expires, lastActivity: row.lastActivity || Date.now() }; } catch (_e) { return undefined; }
  },
  set: function (sid, session) {
    var encrypted = vault.seal(JSON.stringify(session.data));
    stmtSet.run(sid, encrypted, session.expires, session.lastActivity || Date.now());
  },
  delete: function (sid) {
    stmtDel.run(sid);
  },
  has: function (sid) {
    return !!stmtGet.get(sid);
  },
  clearUser: function (userId) {
    // Decrypt each session to find matching userId (no LIKE on encrypted data)
    var rows = stmtAll.all();
    for (var i = 0; i < rows.length; i++) {
      var json = tryUnseal(rows[i].data);
      if (!json) continue;
      try {
        var parsed = JSON.parse(json);
        if (parsed && parsed.userId === userId) stmtDel.run(rows[i].sid);
      } catch (_e) { /* skip malformed sessions */ }
    }
  },
  cleanup: function () {
    stmtClean.run(Date.now());
  },
};

// Encrypt session ID via ML-KEM-1024 + P-384 + XChaCha20-Poly1305 hybrid vault
function sealCookie(sid) {
  return vault.seal(sid).substring(VAULT_PREFIX.length);
}

// Decrypt session ID via hybrid vault unseal
function unsealCookie(sealed) {
  try {
    return vault.unseal(VAULT_PREFIX + sealed);
  } catch (_e) {
    return null;
  }
}


function parseCookies(req) {
  var cookies = {};
  var header = req.headers.cookie || "";
  header.split(";").forEach((c) => {
    var [key, ...rest] = c.split("=");
    if (key) cookies[key.trim()] = rest.join("=").trim();
  });
  return cookies;
}

/**
 * Extract the subnet key from an IP address for loose session binding.
 *   IPv4 → /24    (e.g. 192.168.1.42      → "192.168.1")
 *   IPv6 → /64    (e.g. 2001:db8::abcd:1  → "2001:0db8:0000:0000")
 *
 * The IPv6 /64 covers the standard "single network" allocation. Privacy
 * addressing (RFC 4941) rotates the last 64 bits within a stable /64, so
 * without this a mobile/home IPv6 user saw spurious logouts every time the
 * OS generated a new privacy address.
 *
 * Risk is symmetric to IPv4 /24: two devices on the same subnet could in
 * theory share each other's sessions. We already accept this behind NAT.
 */
function ipSubnet(ip) {
  if (!ip) return "";
  var s = String(ip).toLowerCase();
  // IPv6-mapped IPv4 → treat as IPv4
  if (s.startsWith("::ffff:")) s = s.substring(7);
  if (s.indexOf(":") !== -1) {
    // IPv6: expand :: to zeros, keep first 4 groups (that's /64).
    var parts = s.split("::");
    var left = parts[0] ? parts[0].split(":") : [];
    var right = parts.length > 1 && parts[1] ? parts[1].split(":") : [];
    var missing = 8 - left.length - right.length;
    if (missing < 0) missing = 0;
    var groups = left.concat(new Array(missing).fill("0")).concat(right);
    return groups.slice(0, 4).map(function (g) { return (g || "0").padStart(4, "0"); }).join(":");
  }
  // IPv4: /24
  var v4 = s.split(".");
  if (v4.length === 4) return v4.slice(0, 3).join(".");
  return s;
}

/**
 * Session middleware — attaches req.session
 */
function sessionMiddleware(req, res, next) {
  var cookies = parseCookies(req);
  var sid = null;
  var session = null;

  var ua = req.headers["user-agent"] || "";
  var rateLimit = require("./rate-limit");
  var clientIp = rateLimit.getIp(req) || "";

  if (cookies[COOKIE_NAME]) {
    var raw = decodeURIComponent(cookies[COOKIE_NAME]);
    sid = unsealCookie(raw);
    if (sid) {
      var stored = sessions.get(sid);
      if (stored && Date.now() < stored.expires) {
        // Check idle timeout — only applies to authenticated sessions
        var idleTimeout = config.sessionIdleTimeout || TIME.THIRTY_MIN;
        if (stored.data.userId && stored.lastActivity && (Date.now() - stored.lastActivity) > idleTimeout) {
          sessions.delete(sid);
          stored = null;
        // Session binding: reject if UA changes or IP moves to a different /24 subnet
        // Using /24 instead of exact IP avoids false logouts on mobile/corporate NAT
        } else if (stored.data.userId && stored.data._ua && stored.data._ip &&
                   (stored.data._ua !== ua || ipSubnet(stored.data._ip) !== ipSubnet(clientIp))) {
          sessions.delete(sid);
          stored = null;
        } else {
          session = stored;
        }
      } else if (stored) {
        sessions.delete(sid);
      }
    }
  }

  var now = Date.now();
  if (!session) {
    sid = generateId();
    session = { data: { _ua: ua, _ip: clientIp }, expires: now + MAX_AGE, lastActivity: now };
    sessions.set(sid, session);
  }

  req.session = session.data;
  req.sessionId = sid;

  // Rotate session ID (call after login to prevent fixation)
  req.regenerateSession = function () {
    var oldSid = sid;
    var newSid = generateId();
    var newSession = { data: Object.assign({}, session.data), expires: Date.now() + MAX_AGE, lastActivity: Date.now() };
    sessions.delete(oldSid);
    sessions.set(newSid, newSession);
    sid = newSid;
    session = newSession;
    req.session = newSession.data;
    req.sessionId = newSid;
  };

  // Inject session cookie and persist to SQLite before headers are sent
  var origWriteHead = res.writeHead.bind(res);
  res.writeHead = function (statusCode, ...rest) {
    session.expires = Date.now() + MAX_AGE;
    if (!req._skipActivityUpdate) session.lastActivity = Date.now();
    sessions.set(sid, session);
    var sealed = sealCookie(sid);
    var secure = config.rpOrigin && config.rpOrigin.startsWith("https") ? "; Secure" : "";
    var cookie = `${COOKIE_NAME}=${encodeURIComponent(sealed)}; Path=/; HttpOnly; SameSite=Lax${secure}; Max-Age=${MAX_AGE / 1000}`;
    var existing = res.getHeader("Set-Cookie") || [];
    var arr = Array.isArray(existing) ? existing : existing ? [existing] : [];
    arr.push(cookie);
    res.setHeader("Set-Cookie", arr);
    return origWriteHead(statusCode, ...rest);
  };

  next();
}

// Cleanup expired sessions every 10 min
var cleanupTimer = setInterval(() => {
  sessions.cleanup();
}, TIME.TEN_MIN);
cleanupTimer.unref();

function clearSessionsForUser(userId) {
  sessions.clearUser(userId);
}

function clearSessionById(sid) {
  if (sid) sessions.delete(sid);
}

function clearAllSessions() {
  sdb.prepare("DELETE FROM sessions").run();
}

module.exports = { sessionMiddleware, parseCookies, clearSessionsForUser, clearSessionById, clearAllSessions };
