const fs = require("fs");
const path = require("path");
const { DatabaseSync } = require("node:sqlite");
const { generateToken, generateBytes, encryptPacked, decryptPacked } = require("./crypto");

const { DATA_DIR: dataDir, PATHS, TIME } = require("./constants");
if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir, { recursive: true });

// ---- Full database encryption at rest ----
// The encrypted file (.db.enc) on disk is the durable artifact.
// On startup we decrypt to a tmpfs-backed working file (RAM only, never touches
// physical disk). On shutdown we re-encrypt back to .db.enc.
// Set HERMITSTASH_TMPDIR to a tmpfs mount point (e.g. /dev/shm or a dedicated tmpfs).
// Falls back to the data directory if not set (plaintext on disk — less secure).
var tmpDir = process.env.HERMITSTASH_TMPDIR || (fs.existsSync("/dev/shm") ? "/dev/shm" : null);
if (tmpDir && !fs.existsSync(tmpDir)) { try { fs.mkdirSync(tmpDir, { recursive: true }); } catch (_e) { tmpDir = null; } }
if (!tmpDir) {
  if (process.env.HERMITSTASH_ALLOW_DISK_DB === "true") {
    tmpDir = dataDir;
    console.log("  ⚠ WARNING: No tmpfs available. Plaintext DB will be on disk (HERMITSTASH_ALLOW_DISK_DB=true).");
  } else {
    tmpDir = dataDir;
    if (process.env.NODE_ENV === "production") {
      console.error("  ✖ FATAL: No tmpfs available (/dev/shm missing, HERMITSTASH_TMPDIR not set).");
      console.error("  Set HERMITSTASH_TMPDIR=/tmp or HERMITSTASH_ALLOW_DISK_DB=true to proceed.");
      process.exit(1);
    }
    console.log("  ⚠ Dev mode: plaintext DB on disk (set HERMITSTASH_TMPDIR for production).");
  }
}
var dbBaseName = "hermitstash-" + generateToken(32) + ".db";
const dbPath = process.env.HERMITSTASH_DB_PATH || path.join(tmpDir, dbBaseName);
// Skip production DB decryption when a test DB path is explicitly set
const encPath = process.env.HERMITSTASH_DB_PATH ? null : PATHS.DB_ENC;

// Derive DB encryption key via ML-KEM-1024 + P-384 hybrid vault.
// Uses vault.seal on a fixed seed → the KEM ciphertext is deterministic
// per vault keypair, producing a stable key for DB file encryption.
var _dbKey = null;
var _dbKeyPath = PATHS.DB_KEY_ENC;

function getDbEncKey() {
  if (_dbKey) return _dbKey;

  // Store a vault-sealed AES key for DB file encryption
  if (fs.existsSync(_dbKeyPath)) {
    try {
      var vault = require("./vault");
      var sealed = fs.readFileSync(_dbKeyPath, "utf8").trim();
      _dbKey = Buffer.from(vault.unseal(sealed), "base64");
      return _dbKey;
    } catch (e) {
      // Key file corrupted, regenerate
      console.error("DB encryption key corrupted, regenerating:", e.message);
    }
  }

  // Generate new DB encryption key and seal with hybrid vault
  var vault = require("./vault");
  var rawKey = generateBytes(32);
  var sealed = vault.seal(rawKey.toString("base64"));
  fs.writeFileSync(_dbKeyPath, sealed, { mode: 0o600 });
  _dbKey = rawKey;
  return _dbKey;
}

function decryptDbFile() {
  if (!encPath || !fs.existsSync(encPath)) return;
  if (fs.existsSync(dbPath)) {
    var plainStat = fs.statSync(dbPath);
    var encStat = fs.statSync(encPath);
    if (plainStat.mtimeMs > encStat.mtimeMs && plainStat.size > 0) {
      console.log("  DB: plaintext is newer than encrypted — keeping plaintext (crash recovery)");
      return;
    }
  }
  var packed = fs.readFileSync(encPath);
  if (packed.length < 26) return;
  fs.writeFileSync(dbPath, decryptPacked(packed, getDbEncKey()));
}

// removePlaintext: true only on final shutdown, false for periodic snapshots
function encryptDbFile(removePlaintext) {
  if (!encPath) return; // test mode — no encrypted DB file
  try { db.exec("PRAGMA wal_checkpoint(TRUNCATE)"); } catch (_e) {} // eslint-disable-line
  if (!fs.existsSync(dbPath)) return;
  fs.writeFileSync(encPath, encryptPacked(fs.readFileSync(dbPath), getDbEncKey()));
  if (removePlaintext) {
    try { fs.unlinkSync(dbPath); } catch (_e) {}
    try { fs.unlinkSync(dbPath + "-wal"); } catch (_e) {}
    try { fs.unlinkSync(dbPath + "-shm"); } catch (_e) {}
  }
}

// Clean up stale plaintext DB files from previous crashed processes
try {
  var staleFiles = fs.readdirSync(tmpDir).filter(function (f) { return f.startsWith("hermitstash-") && f.endsWith(".db") && path.join(tmpDir, f) !== dbPath; });
  staleFiles.forEach(function (f) {
    try { fs.unlinkSync(path.join(tmpDir, f)); } catch (_e) {}
    try { fs.unlinkSync(path.join(tmpDir, f + "-wal")); } catch (_e) {}
    try { fs.unlinkSync(path.join(tmpDir, f + "-shm")); } catch (_e) {}
  });
} catch (_e) {}

// Decrypt .db.enc → plaintext in tmpfs
decryptDbFile();

const db = new DatabaseSync(dbPath);

// SQLite performance tuning
db.exec("PRAGMA journal_mode=WAL");
db.exec("PRAGMA synchronous=NORMAL");       // Safe with WAL, 2-3x faster writes
db.exec("PRAGMA cache_size=-8000");          // 8MB page cache (default ~2MB)
db.exec("PRAGMA temp_store=MEMORY");         // Temp tables in RAM
db.exec("PRAGMA busy_timeout=5000");         // Wait 5s instead of failing on lock
db.exec("PRAGMA mmap_size=268435456");       // 256MB memory-mapped I/O for reads
db.exec("PRAGMA auto_vacuum=INCREMENTAL");   // Reclaim space gradually

// Encrypt periodically (every 5 minutes) to keep .db.enc up to date
// No dirty tracking needed — always encrypt to prevent stale backups
var encTimer = setInterval(function () {
  try { encryptDbFile(); } catch (_e) {}
}, TIME.FIVE_MIN);
encTimer.unref();

// Encrypt DB on exit — server.js gracefulShutdown calls process.exit which triggers this
process.on("exit", function () { try { encryptDbFile(true); } catch (_e) {} });

// ---- Schema ----
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    _id TEXT PRIMARY KEY,
    googleId TEXT,
    email TEXT,
    displayName TEXT,
    avatar TEXT,
    passwordHash TEXT,
    authType TEXT,
    role TEXT DEFAULT 'user',
    status TEXT DEFAULT 'active',
    createdAt TEXT,
    lastLogin TEXT,
    data TEXT
  )
`);
// Drop stale indexes on sealed columns (no longer queried via SQL)
try { db.exec("DROP INDEX IF EXISTS idx_users_googleId"); } catch (_e) {}
try { db.exec("DROP INDEX IF EXISTS idx_users_email"); } catch (_e) {}
// Add status column to existing databases
try { db.exec("ALTER TABLE users ADD COLUMN status TEXT DEFAULT 'active'"); } catch (_e) { /* column already exists */ }
db.exec("CREATE INDEX IF NOT EXISTS idx_users_status ON users(status)");
db.exec("UPDATE users SET status = 'active' WHERE status IS NULL");
try { db.exec("ALTER TABLE users ADD COLUMN emailHash TEXT"); } catch (_e) { /* already exists */ }
db.exec("CREATE INDEX IF NOT EXISTS idx_users_emailHash ON users(emailHash)");
try { db.exec("ALTER TABLE users ADD COLUMN vaultEnabled TEXT"); } catch (_e) { /* already exists */ }
try { db.exec("ALTER TABLE users ADD COLUMN vaultPublicKey TEXT"); } catch (_e) { /* already exists */ }
try { db.exec("ALTER TABLE users ADD COLUMN vaultStealth TEXT"); } catch (_e) { /* already exists */ }
try { db.exec("ALTER TABLE users ADD COLUMN vaultMode TEXT"); } catch (_e) { /* already exists */ }
try { db.exec("ALTER TABLE users ADD COLUMN vaultSeed TEXT"); } catch (_e) { /* already exists */ }
try { db.exec("ALTER TABLE users ADD COLUMN totpLastStep TEXT"); } catch (_e) { /* already exists */ }
try { db.exec("ALTER TABLE users ADD COLUMN totpSecret TEXT"); } catch (_e) { /* already exists */ }
try { db.exec("ALTER TABLE users ADD COLUMN totpEnabled TEXT"); } catch (_e) { /* already exists */ }
try { db.exec("ALTER TABLE users ADD COLUMN totpBackupCodes TEXT"); } catch (_e) { /* already exists */ }
try { db.exec("ALTER TABLE users ADD COLUMN failedLoginAttempts INTEGER DEFAULT 0"); } catch (_e) { /* already exists */ }
try { db.exec("ALTER TABLE users ADD COLUMN lockedUntil TEXT"); } catch (_e) { /* already exists */ }
db.exec("CREATE INDEX IF NOT EXISTS idx_users_role ON users(role)");

// Audit log
db.exec(`
  CREATE TABLE IF NOT EXISTS audit_log (
    _id TEXT PRIMARY KEY,
    action TEXT,
    targetId TEXT,
    targetEmail TEXT,
    performedBy TEXT,
    performedByEmail TEXT,
    details TEXT,
    createdAt TEXT,
    data TEXT
  )
`);
db.exec("CREATE INDEX IF NOT EXISTS idx_audit_createdAt ON audit_log(createdAt)");
try { db.exec("ALTER TABLE audit_log ADD COLUMN ip TEXT"); } catch (_e) {}
// Drop stale indexes on sealed columns
try { db.exec("DROP INDEX IF EXISTS idx_audit_action"); } catch (_e) {}
try { db.exec("DROP INDEX IF EXISTS idx_audit_performedBy"); } catch (_e) {}

db.exec(`
  CREATE TABLE IF NOT EXISTS files (
    _id TEXT PRIMARY KEY,
    shareId TEXT,
    bundleId TEXT,
    bundleShareId TEXT,
    uploadedBy TEXT,
    uploaderEmail TEXT,
    originalName TEXT,
    relativePath TEXT,
    storagePath TEXT,
    mimeType TEXT,
    size INTEGER DEFAULT 0,
    downloads INTEGER DEFAULT 0,
    status TEXT,
    createdAt TEXT,
    data TEXT
  )
`);
db.exec("CREATE INDEX IF NOT EXISTS idx_files_uploadedBy ON files(uploadedBy)");
db.exec("CREATE INDEX IF NOT EXISTS idx_files_status ON files(status)");
// Drop stale indexes on sealed columns
try { db.exec("DROP INDEX IF EXISTS idx_files_shareId"); } catch (_e) {}
try { db.exec("DROP INDEX IF EXISTS idx_files_bundleShareId"); } catch (_e) {}
try { db.exec("DROP INDEX IF EXISTS idx_files_uploaderEmail"); } catch (_e) {}
try { db.exec("ALTER TABLE files ADD COLUMN encryptionKey TEXT"); } catch (_e) { /* already exists */ }
try { db.exec("ALTER TABLE files ADD COLUMN expiresAt TEXT"); } catch (_e) { /* already exists */ }
try { db.exec("ALTER TABLE files ADD COLUMN emailHash TEXT"); } catch (_e) { /* already exists */ }
try { db.exec("ALTER TABLE files ADD COLUMN shareIdHash TEXT"); } catch (_e) { /* already exists */ }
try { db.exec("ALTER TABLE files ADD COLUMN bundleShareIdHash TEXT"); } catch (_e) { /* already exists */ }
try { db.exec("ALTER TABLE files ADD COLUMN checksum TEXT"); } catch (_e) { /* already exists */ }
try { db.exec("ALTER TABLE files ADD COLUMN vaultBatchId TEXT"); } catch (_e) { /* already exists */ }
try { db.exec("ALTER TABLE files ADD COLUMN vaultBatchName TEXT"); } catch (_e) { /* already exists */ }
db.exec("CREATE INDEX IF NOT EXISTS idx_files_shareIdHash ON files(shareIdHash)");
db.exec("CREATE INDEX IF NOT EXISTS idx_files_bundleShareIdHash ON files(bundleShareIdHash)");
db.exec("CREATE INDEX IF NOT EXISTS idx_files_emailHash ON files(emailHash)");
// expiresAt is a sealed column — an index on ciphertext is useless. Cleanup runs via the ORM.
db.exec("DROP INDEX IF EXISTS idx_files_expiresAt");
db.exec("CREATE INDEX IF NOT EXISTS idx_files_createdAt ON files(createdAt)");

db.exec(`
  CREATE TABLE IF NOT EXISTS bundles (
    _id TEXT PRIMARY KEY,
    shareId TEXT,
    uploaderName TEXT,
    uploaderEmail TEXT,
    expectedFiles INTEGER DEFAULT 0,
    receivedFiles INTEGER DEFAULT 0,
    skippedCount INTEGER DEFAULT 0,
    totalSize INTEGER DEFAULT 0,
    downloads INTEGER DEFAULT 0,
    status TEXT,
    createdAt TEXT,
    data TEXT
  )
`);
db.exec("CREATE INDEX IF NOT EXISTS idx_bundles_status ON bundles(status)");
try { db.exec("DROP INDEX IF EXISTS idx_bundles_shareId"); } catch (_e) {}
try { db.exec("ALTER TABLE bundles ADD COLUMN emailHash TEXT"); } catch (_e) { /* already exists */ }
try { db.exec("ALTER TABLE bundles ADD COLUMN shareIdHash TEXT"); } catch (_e) { /* already exists */ }
db.exec("CREATE INDEX IF NOT EXISTS idx_bundles_shareIdHash ON bundles(shareIdHash)");
try { db.exec("ALTER TABLE bundles ADD COLUMN passwordHash TEXT"); } catch (_e) { /* already exists */ }
try { db.exec("ALTER TABLE bundles ADD COLUMN message TEXT"); } catch (_e) { /* already exists */ }
try { db.exec("ALTER TABLE bundles ADD COLUMN expiresAt TEXT"); } catch (_e) { /* already exists */ }
try { db.exec("ALTER TABLE bundles ADD COLUMN finalizeTokenHash TEXT"); } catch (_e) { /* already exists */ }
try { db.exec("ALTER TABLE bundles ADD COLUMN ownerId TEXT"); } catch (_e) { /* already exists */ }
try { db.exec("ALTER TABLE bundles ADD COLUMN skippedFiles TEXT"); } catch (_e) { /* already exists */ }
db.exec("CREATE INDEX IF NOT EXISTS idx_bundles_emailHash ON bundles(emailHash)");
db.exec("CREATE INDEX IF NOT EXISTS idx_bundles_expiresAt ON bundles(expiresAt)");
db.exec("CREATE INDEX IF NOT EXISTS idx_bundles_createdAt ON bundles(createdAt)");

db.exec(`
  CREATE TABLE IF NOT EXISTS blocked_ips (
    _id TEXT PRIMARY KEY,
    ip TEXT,
    reason TEXT,
    blockedBy TEXT,
    createdAt TEXT,
    data TEXT
  )
`);
db.exec("CREATE INDEX IF NOT EXISTS idx_blocked_ip ON blocked_ips(ip)");

db.exec(`
  CREATE TABLE IF NOT EXISTS api_keys (
    _id TEXT PRIMARY KEY,
    name TEXT,
    keyHash TEXT,
    prefix TEXT,
    permissions TEXT,
    userId TEXT,
    lastUsed TEXT,
    createdAt TEXT,
    data TEXT
  )
`);
// prefix is sealed, no SQL index needed
try { db.exec("DROP INDEX IF EXISTS idx_apikeys_prefix"); } catch (_e) {}
try { db.exec("ALTER TABLE api_keys ADD COLUMN boundStashId TEXT"); } catch (_e) {}
try { db.exec("ALTER TABLE api_keys ADD COLUMN boundBundleId TEXT"); } catch (_e) {}
try { db.exec("ALTER TABLE api_keys ADD COLUMN certIssuedAt TEXT"); } catch (_e) {}
try { db.exec("ALTER TABLE api_keys ADD COLUMN certExpiresAt TEXT"); } catch (_e) {}
try { db.exec("ALTER TABLE api_keys ADD COLUMN certFingerprint TEXT"); } catch (_e) {}

db.exec(`
  CREATE TABLE IF NOT EXISTS webhooks (
    _id TEXT PRIMARY KEY,
    url TEXT,
    events TEXT,
    secret TEXT,
    active TEXT DEFAULT 'true',
    createdBy TEXT,
    lastTriggered TEXT,
    createdAt TEXT,
    data TEXT
  )
`);

// Webhook delivery log
db.exec(`
  CREATE TABLE IF NOT EXISTS webhook_deliveries (
    _id TEXT PRIMARY KEY,
    webhookId TEXT,
    event TEXT,
    status TEXT,
    statusCode INTEGER,
    error TEXT,
    attempts INTEGER DEFAULT 0,
    createdAt TEXT,
    data TEXT
  )
`);
db.exec("CREATE INDEX IF NOT EXISTS idx_wd_webhookId ON webhook_deliveries(webhookId)");
db.exec("CREATE INDEX IF NOT EXISTS idx_wd_createdAt ON webhook_deliveries(createdAt)");

// Verification tokens
db.exec(`
  CREATE TABLE IF NOT EXISTS verification_tokens (
    _id TEXT PRIMARY KEY,
    userId TEXT,
    token TEXT,
    type TEXT DEFAULT 'email',
    expiresAt TEXT,
    createdAt TEXT,
    data TEXT
  )
`);
db.exec("CREATE INDEX IF NOT EXISTS idx_vtoken_token ON verification_tokens(token)");
db.exec("CREATE INDEX IF NOT EXISTS idx_vtoken_userId ON verification_tokens(userId)");

// WebAuthn credentials
db.exec(`
  CREATE TABLE IF NOT EXISTS credentials (
    _id TEXT PRIMARY KEY,
    userId TEXT,
    credentialId TEXT,
    publicKey TEXT,
    counter INTEGER DEFAULT 0,
    deviceType TEXT,
    backedUp INTEGER DEFAULT 0,
    transports TEXT,
    createdAt TEXT,
    data TEXT
  )
`);
db.exec("CREATE INDEX IF NOT EXISTS idx_cred_userId ON credentials(userId)");
// credentialId is sealed, no SQL index needed
try { db.exec("DROP INDEX IF EXISTS idx_cred_credentialId"); } catch (_e) {}

// Teams
db.exec(`
  CREATE TABLE IF NOT EXISTS teams (
    _id TEXT PRIMARY KEY,
    name TEXT,
    createdBy TEXT,
    createdAt TEXT,
    data TEXT
  )
`);

db.exec(`
  CREATE TABLE IF NOT EXISTS team_members (
    _id TEXT PRIMARY KEY,
    teamId TEXT,
    userId TEXT,
    role TEXT DEFAULT 'member',
    joinedAt TEXT,
    data TEXT
  )
`);
db.exec("CREATE INDEX IF NOT EXISTS idx_tm_teamId ON team_members(teamId)");
db.exec("CREATE INDEX IF NOT EXISTS idx_tm_userId ON team_members(userId)");

// Add teamId to files for team-scoped access
try { db.exec("ALTER TABLE files ADD COLUMN teamId TEXT"); } catch (_e) {}
try { db.exec("ALTER TABLE bundles ADD COLUMN teamId TEXT"); } catch (_e) {}

// Vault file columns (ML-KEM-1024 client-side encrypted uploads)
try { db.exec("ALTER TABLE files ADD COLUMN vaultEncrypted TEXT"); } catch (_e) {}
try { db.exec("ALTER TABLE files ADD COLUMN vaultEncapsulatedKey TEXT"); } catch (_e) {}
try { db.exec("ALTER TABLE files ADD COLUMN vaultIv TEXT"); } catch (_e) {}

// App settings (vault-sealed key-value pairs, replaces .env file)
db.exec(`
  CREATE TABLE IF NOT EXISTS settings (
    _id TEXT PRIMARY KEY,
    key TEXT,
    value TEXT,
    updatedAt TEXT,
    data TEXT
  )
`);

// Email send tracking for quota enforcement
db.exec(`
  CREATE TABLE IF NOT EXISTS email_sends (
    _id TEXT PRIMARY KEY,
    recipient TEXT,
    subject TEXT,
    backend TEXT,
    status TEXT,
    createdAt TEXT,
    data TEXT
  )
`);
db.exec("CREATE INDEX IF NOT EXISTS idx_email_sends_createdAt ON email_sends(createdAt)");
db.exec("CREATE INDEX IF NOT EXISTS idx_email_sends_status ON email_sends(status)");

// Invites table (SQLite exec, not child_process)
db.exec("CREATE TABLE IF NOT EXISTS invites (_id TEXT PRIMARY KEY, email TEXT, role TEXT, tokenHash TEXT, invitedBy TEXT, status TEXT, expiresAt TEXT, createdAt TEXT, data TEXT)");

// Customer Stash — branded upload portals
db.exec(`
  CREATE TABLE IF NOT EXISTS customer_stash (
    _id TEXT PRIMARY KEY,
    slug TEXT,
    name TEXT,
    title TEXT,
    subtitle TEXT,
    accentColor TEXT,
    logoUrl TEXT,
    passwordHash TEXT,
    maxFileSize INTEGER DEFAULT 0,
    maxFiles INTEGER DEFAULT 0,
    maxBundleSize INTEGER DEFAULT 0,
    defaultExpiry INTEGER DEFAULT 0,
    allowedExtensions TEXT,
    enabled TEXT DEFAULT 'true',
    createdBy TEXT,
    bundleCount INTEGER DEFAULT 0,
    totalBytes INTEGER DEFAULT 0,
    createdAt TEXT,
    data TEXT
  )
`);
try { db.exec("DROP INDEX IF EXISTS idx_stash_slug"); } catch (_e) {} // slug is now sealed
try { db.exec("ALTER TABLE customer_stash ADD COLUMN slugHash TEXT"); } catch (_e) { /* already exists */ }
try { db.exec("ALTER TABLE customer_stash ADD COLUMN allowedEmails TEXT"); } catch (_e) { /* already exists */ }
try { db.exec("ALTER TABLE customer_stash ADD COLUMN accessMode TEXT DEFAULT 'open'"); } catch (_e) { /* already exists */ }
try { db.exec("ALTER TABLE customer_stash ADD COLUMN syncEnabled TEXT DEFAULT 'false'"); } catch (_e) { /* already exists */ }
try { db.exec("ALTER TABLE customer_stash ADD COLUMN syncBundleId TEXT"); } catch (_e) { /* already exists */ }
db.exec("CREATE UNIQUE INDEX IF NOT EXISTS idx_stash_slugHash ON customer_stash(slugHash)");
try { db.exec("ALTER TABLE bundles ADD COLUMN stashId TEXT"); } catch (_e) { /* already exists */ }
try { db.exec("ALTER TABLE bundles ADD COLUMN bundleName TEXT"); } catch (_e) { /* already exists */ }
try { db.exec("ALTER TABLE bundles ADD COLUMN allowedEmails TEXT"); } catch (_e) { /* already exists */ }
try { db.exec("ALTER TABLE bundles ADD COLUMN accessMode TEXT DEFAULT 'open'"); } catch (_e) { /* already exists */ }
try { db.exec("ALTER TABLE bundles ADD COLUMN bundleType TEXT DEFAULT 'snapshot'"); } catch (_e) { /* already exists */ }
try { db.exec("ALTER TABLE bundles ADD COLUMN seq INTEGER DEFAULT 0"); } catch (_e) { /* already exists */ }
try { db.exec("ALTER TABLE files ADD COLUMN updatedAt TEXT"); } catch (_e) { /* already exists */ }
try { db.exec("ALTER TABLE files ADD COLUMN seq INTEGER DEFAULT 0"); } catch (_e) { /* already exists */ }
try { db.exec("ALTER TABLE files ADD COLUMN deletedAt TEXT"); } catch (_e) { /* already exists */ }
try { db.exec("ALTER TABLE files ADD COLUMN uploaderName TEXT"); } catch (_e) { /* already exists */ }

// Bundle access codes — one-time email verification codes for email-gated bundles
db.exec(`
  CREATE TABLE IF NOT EXISTS bundle_access_codes (
    _id TEXT PRIMARY KEY,
    bundleShareId TEXT,
    email TEXT,
    emailHash TEXT,
    code TEXT,
    codeHash TEXT,
    attempts INTEGER DEFAULT 0,
    status TEXT DEFAULT 'pending',
    expiresAt TEXT,
    createdAt TEXT,
    data TEXT
  )
`);
db.exec("CREATE INDEX IF NOT EXISTS idx_bac_bundleShareId ON bundle_access_codes(bundleShareId)");
db.exec("CREATE INDEX IF NOT EXISTS idx_bac_emailHash ON bundle_access_codes(emailHash)");
db.exec("CREATE INDEX IF NOT EXISTS idx_bac_status ON bundle_access_codes(status)");

// Bundle access log — verified email access audit trail
db.exec(`
  CREATE TABLE IF NOT EXISTS bundle_access_log (
    _id TEXT PRIMARY KEY,
    bundleShareId TEXT,
    email TEXT,
    emailHash TEXT,
    accessedAt TEXT,
    ip TEXT,
    data TEXT
  )
`);
db.exec("CREATE INDEX IF NOT EXISTS idx_bal_bundleShareId ON bundle_access_log(bundleShareId)");

// Certificate revocation list for mTLS sync client certs
db.exec(`
  CREATE TABLE IF NOT EXISTS cert_revocations (
    _id TEXT PRIMARY KEY,
    fingerprintHash TEXT,
    cn TEXT,
    revokedAt TEXT,
    reason TEXT,
    data TEXT
  )
`);
db.exec("CREATE INDEX IF NOT EXISTS idx_certrev_fp ON cert_revocations(fingerprintHash)");

// Sync enrollment codes — one-time codes for sync client provisioning
db.exec(`
  CREATE TABLE IF NOT EXISTS enrollment_codes (
    _id TEXT PRIMARY KEY,
    codeHash TEXT,
    apiKey TEXT,
    clientCert TEXT,
    clientKey TEXT,
    caCert TEXT,
    stashId TEXT,
    bundleId TEXT,
    createdBy TEXT,
    status TEXT DEFAULT 'pending',
    expiresAt TEXT,
    createdAt TEXT,
    data TEXT
  )
`);
db.exec("CREATE INDEX IF NOT EXISTS idx_enrollment_codeHash ON enrollment_codes(codeHash)");
db.exec("CREATE INDEX IF NOT EXISTS idx_enrollment_status ON enrollment_codes(status)");
try { db.exec("ALTER TABLE enrollment_codes ADD COLUMN reissue TEXT"); } catch (_e) {}
try { db.exec("ALTER TABLE enrollment_codes ADD COLUMN originalKeyId TEXT"); } catch (_e) {}

// Known columns per table
const COLUMNS = {
  users: ["_id", "googleId", "email", "displayName", "avatar", "passwordHash", "authType", "role", "status", "emailHash", "vaultEnabled", "vaultPublicKey", "vaultStealth", "vaultMode", "vaultSeed", "totpLastStep", "totpSecret", "totpEnabled", "totpBackupCodes", "failedLoginAttempts", "lockedUntil", "createdAt", "lastLogin"],
  audit_log: ["_id", "action", "targetId", "targetEmail", "performedBy", "performedByEmail", "details", "ip", "createdAt"],
  files: ["_id", "shareId", "shareIdHash", "bundleId", "bundleShareId", "bundleShareIdHash", "uploadedBy", "uploaderEmail", "uploaderName", "originalName", "relativePath", "storagePath", "mimeType", "size", "downloads", "status", "encryptionKey", "expiresAt", "emailHash", "teamId", "vaultEncrypted", "vaultEncapsulatedKey", "vaultIv", "vaultBatchId", "vaultBatchName", "checksum", "createdAt", "updatedAt", "seq", "deletedAt"],
  bundles: ["_id", "shareId", "shareIdHash", "uploaderName", "uploaderEmail", "expectedFiles", "receivedFiles", "skippedCount", "totalSize", "downloads", "status", "emailHash", "passwordHash", "message", "expiresAt", "finalizeTokenHash", "skippedFiles", "ownerId", "teamId", "stashId", "bundleName", "allowedEmails", "accessMode", "bundleType", "seq", "createdAt"],
  blocked_ips: ["_id", "ip", "reason", "blockedBy", "createdAt"],
  api_keys: ["_id", "name", "keyHash", "prefix", "permissions", "userId", "lastUsed", "createdAt", "boundStashId", "boundBundleId", "certIssuedAt", "certExpiresAt", "certFingerprint"],
  webhooks: ["_id", "url", "events", "secret", "active", "createdBy", "lastTriggered", "createdAt"],
  verification_tokens: ["_id", "userId", "token", "type", "expiresAt", "createdAt"],
  credentials: ["_id", "userId", "credentialId", "publicKey", "counter", "deviceType", "backedUp", "transports", "createdAt"],
  email_sends: ["_id", "recipient", "subject", "backend", "status", "createdAt"],
  teams: ["_id", "name", "createdBy", "createdAt"],
  team_members: ["_id", "teamId", "userId", "role", "joinedAt"],
  settings: ["_id", "key", "value", "updatedAt"],
  invites: ["_id", "email", "role", "tokenHash", "invitedBy", "status", "expiresAt", "createdAt"],
  webhook_deliveries: ["_id", "webhookId", "event", "status", "statusCode", "error", "attempts", "createdAt"],
  customer_stash: ["_id", "slug", "slugHash", "name", "title", "subtitle", "accentColor", "logoUrl", "passwordHash", "maxFileSize", "maxFiles", "maxBundleSize", "defaultExpiry", "allowedExtensions", "allowedEmails", "accessMode", "syncEnabled", "syncBundleId", "enabled", "createdBy", "bundleCount", "totalBytes", "createdAt"],
  bundle_access_codes: ["_id", "bundleShareId", "email", "emailHash", "code", "codeHash", "attempts", "status", "expiresAt", "createdAt"],
  bundle_access_log: ["_id", "bundleShareId", "email", "emailHash", "accessedAt", "ip"],
  cert_revocations: ["_id", "fingerprintHash", "cn", "revokedAt", "reason"],
  enrollment_codes: ["_id", "codeHash", "apiKey", "clientCert", "clientKey", "caCert", "stashId", "bundleId", "createdBy", "status", "expiresAt", "createdAt", "reissue", "originalKeyId"],
};

// ---- Data migration: promote overflow fields to real columns ----
// Moves values from the `data` JSON blob to their new dedicated columns.
// Safe to run multiple times (idempotent). Runs on every startup.
(function migrateOverflowFields() {
  var migrations = [
    { table: "users", fields: ["totpSecret", "totpEnabled", "totpBackupCodes", "totpLastStep", "vaultEnabled", "vaultPublicKey", "vaultStealth", "vaultMode", "vaultSeed", "failedLoginAttempts", "lockedUntil"] },
    { table: "files", fields: ["checksum", "uploaderName"] },
    { table: "bundles", fields: ["finalizeTokenHash", "skippedFiles", "ownerId", "stashId", "bundleName", "allowedEmails", "accessMode", "bundleType", "seq"] },
    { table: "api_keys", fields: ["certIssuedAt", "certExpiresAt", "certFingerprint"] },
    { table: "enrollment_codes", fields: ["reissue", "originalKeyId"] },
    { table: "audit_log", fields: ["ip"] },
  ];
  for (var m = 0; m < migrations.length; m++) {
    var table = migrations[m].table;
    var fields = migrations[m].fields;
    try {
      var rows = db.prepare("SELECT _id, data FROM " + table + " WHERE data IS NOT NULL AND data != 'null' AND data != '{}'").all();
      for (var r = 0; r < rows.length; r++) {
        var extra;
        try { extra = JSON.parse(rows[r].data); } catch (_e) { continue; }
        if (!extra || typeof extra !== "object") continue;
        var setClauses = [];
        var vals = [];
        var remaining = {};
        var migrated = false;
        for (var key in extra) {
          if (fields.indexOf(key) !== -1) {
            setClauses.push(key + " = ?");
            vals.push(typeof extra[key] === "object" ? JSON.stringify(extra[key]) : extra[key]);
            migrated = true;
          } else {
            remaining[key] = extra[key];
          }
        }
        if (migrated) {
          var newData = Object.keys(remaining).length > 0 ? JSON.stringify(remaining) : null;
          setClauses.push("data = ?");
          vals.push(newData);
          vals.push(rows[r]._id);
          db.prepare("UPDATE " + table + " SET " + setClauses.join(", ") + " WHERE _id = ?").run(...vals);
        }
      }
    } catch (_e) { /* table may not exist in test environments */ }
  }
})();

// ---- Raw SQL helpers for operations the ORM can't express ----
function rawExec(sql, ...params) { return db.prepare(sql).run(...params); }
function rawQuery(sql, ...params) { return db.prepare(sql).all(...params); }

// Prepared statement cache with LRU eviction (cap at 500)
var _stmtCache = {};
var _stmtOrder = [];
var STMT_CACHE_MAX = 500;
function stmt(sql) {
  if (_stmtCache[sql]) {
    // Move to end (most recently used)
    var idx = _stmtOrder.indexOf(sql);
    if (idx !== -1) { _stmtOrder.splice(idx, 1); _stmtOrder.push(sql); }
    return _stmtCache[sql];
  }
  // Evict oldest if at capacity
  if (_stmtOrder.length >= STMT_CACHE_MAX) {
    var oldest = _stmtOrder.shift();
    delete _stmtCache[oldest];
  }
  _stmtCache[sql] = db.prepare(sql);
  _stmtOrder.push(sql);
  return _stmtCache[sql];
}

// Columns that store JSON arrays/objects (need parse on read, stringify on write)
var JSON_COLUMNS = {
  bundles: ["skippedFiles"],
  users: ["totpBackupCodes"],
};

// Field-level crypto — auto seals on write, auto unseals on read
var fieldCrypto = require("./field-crypto");

class Collection {
  constructor(name) {
    this.name = name;
    this.columns = COLUMNS[name] || ["_id"];
    this.jsonColumns = JSON_COLUMNS[name] || [];
    this._autoSeal = true; // enabled by default
  }

  // Disable auto-seal for raw DB operations (used internally when data is already sealed)
  raw() {
    var clone = Object.create(this);
    clone._autoSeal = false;
    return clone;
  }

  _genId() {
    return generateToken(32);
  }

  // Split a doc into column values + overflow JSON for extra fields
  _split(doc) {
    const cols = {};
    const extra = {};
    for (const [k, v] of Object.entries(doc)) {
      if (this.columns.includes(k)) {
        cols[k] = v;
      } else {
        extra[k] = v;
      }
    }
    cols.data = Object.keys(extra).length > 0 ? JSON.stringify(extra) : null;
    return cols;
  }

  // Merge a row back into a plain object, auto-unseal if enabled
  _merge(row) {
    if (!row) return null;
    const doc = {};
    for (const [k, v] of Object.entries(row)) {
      if (k === "data") continue;
      if (v !== null) doc[k] = v;
    }
    if (row.data) {
      try { Object.assign(doc, JSON.parse(row.data)); } catch {}
    }
    // Parse JSON columns (arrays/objects stored as JSON strings in real columns)
    for (var j = 0; j < this.jsonColumns.length; j++) {
      var jc = this.jsonColumns[j];
      if (typeof doc[jc] === "string") {
        try { doc[jc] = JSON.parse(doc[jc]); } catch (_e) {}
      }
    }
    if (this._autoSeal) return fieldCrypto.unsealDoc(this.name, doc);
    return doc;
  }

  _toSqlVal(v) {
    if (v === undefined || v === null) return null;
    if (typeof v === "boolean") return v ? 1 : 0;
    if (typeof v === "object") return JSON.stringify(v);
    return v;
  }

  insert(doc) {
    var record = { _id: doc._id || this._genId(), ...doc };
    // Auto-seal: routes pass plaintext, crypto layer handles encryption
    if (this._autoSeal) record = fieldCrypto.sealDoc(this.name, record);
    const split = this._split(record);
    const keys = Object.keys(split);
    const placeholders = keys.map(() => "?").join(",");
    const sql = "INSERT INTO " + this.name + " (" + keys.join(",") + ") VALUES (" + placeholders + ")";
    try {
      stmt(sql).run(...keys.map(k => this._toSqlVal(split[k])));
    } catch (e) {
      if (e.message && e.message.includes("UNIQUE constraint")) {
        throw new Error("Duplicate record in " + this.name + " (id: " + record._id + ")");
      }
      throw e;
    }
    return { ...record };
  }

  // Auto-translate queries on sealed fields to their hash equivalents
  _translateQuery(query) {
    if (!this._autoSeal) return query;
    var translated = {};
    for (var key in query) {
      var val = query[key];
      // Check if this field is sealed and has a hash equivalent
      var lookup = fieldCrypto.lookupHash(this.name, key, val);
      if (lookup && typeof val === "string") {
        translated[lookup.key] = lookup.value;
      } else {
        translated[key] = val;
      }
    }
    return translated;
  }

  findOne(query) {
    const docs = this._query(this._translateQuery(query), 1);
    return docs.length > 0 ? docs[0] : null;
  }

  find(query) {
    return this._query(this._translateQuery(query || {}));
  }

  _query(query, limit) {
    const keys = Object.keys(query);

    // No filter — return all
    if (keys.length === 0) {
      var sql = "SELECT * FROM " + this.name + (limit ? " LIMIT " + limit : "");
      return stmt(sql).all().map(r => this._merge(r));
    }

    // Build WHERE clause for indexed columns, fall back to JS filter for extras
    var conditions = [];
    var values = [];
    var jsFilters = [];

    for (const [key, val] of Object.entries(query)) {
      if (val && typeof val === "object" && val.$ne !== undefined) {
        if (this.columns.includes(key)) {
          conditions.push(key + " IS NOT ?");
          values.push(val.$ne);
        } else {
          jsFilters.push({ key: key, op: "ne", val: val.$ne });
        }
      } else {
        if (this.columns.includes(key)) {
          conditions.push(key + " = ?");
          values.push(val);
        } else {
          jsFilters.push({ key: key, op: "eq", val: val });
        }
      }
    }

    var sql2 = "SELECT * FROM " + this.name;
    if (conditions.length > 0) sql2 += " WHERE " + conditions.join(" AND ");
    if (limit && jsFilters.length === 0) sql2 += " LIMIT " + limit;

    var rows = stmt(sql2).all(...values).map(r => this._merge(r));

    // Apply JS filters for non-column fields
    if (jsFilters.length > 0) {
      rows = rows.filter(function(doc) {
        for (var i = 0; i < jsFilters.length; i++) {
          var f = jsFilters[i];
          if (f.op === "eq" && doc[f.key] !== f.val) return false;
          if (f.op === "ne" && doc[f.key] === f.val) return false;
        }
        return true;
      });
      if (limit) rows = rows.slice(0, limit);
    }

    return rows;
  }

  // Paginated query with sorting
  findPaginated(query, opts) {
    opts = opts || {};
    var limit = opts.limit || 25;
    var offset = opts.offset || 0;
    var orderBy = opts.orderBy || "createdAt";
    var orderDir = (opts.orderDir || "DESC").toUpperCase() === "ASC" ? "ASC" : "DESC";

    // Only use SQL columns for ordering
    if (!this.columns.includes(orderBy)) orderBy = "createdAt";

    var conditions = [];
    var values = [];

    for (var key in query) {
      if (!query.hasOwnProperty(key)) continue;
      var val = query[key];
      if (val && typeof val === "object" && val.$ne !== undefined) {
        if (this.columns.includes(key)) { conditions.push(key + " IS NOT ?"); values.push(val.$ne); }
      } else {
        if (this.columns.includes(key)) { conditions.push(key + " = ?"); values.push(val); }
      }
    }

    var where = conditions.length > 0 ? " WHERE " + conditions.join(" AND ") : "";
    var total = stmt("SELECT COUNT(*) as c FROM " + this.name + where).get(...values).c;
    var rows = stmt("SELECT * FROM " + this.name + where + " ORDER BY " + orderBy + " " + orderDir + " LIMIT ? OFFSET ?").all(...values, limit, offset);

    return { data: rows.map(r => this._merge(r)), total: total, limit: limit, offset: offset };
  }

  // Search across multiple fields with LIKE + optional filters
  searchPaginated(searchFields, searchTerm, filterQuery, opts) {
    opts = opts || {};
    var limit = opts.limit || 25;
    var offset = opts.offset || 0;
    var orderBy = opts.orderBy || "createdAt";
    var orderDir = (opts.orderDir || "DESC").toUpperCase() === "ASC" ? "ASC" : "DESC";
    if (!this.columns.includes(orderBy)) orderBy = "createdAt";

    var conditions = [];
    var values = [];

    // Search term — OR across fields
    if (searchTerm && searchFields.length > 0) {
      var searchConds = [];
      for (var i = 0; i < searchFields.length; i++) {
        if (this.columns.includes(searchFields[i])) {
          searchConds.push(searchFields[i] + " LIKE ?");
          values.push("%" + searchTerm + "%");
        }
      }
      if (searchConds.length > 0) conditions.push("(" + searchConds.join(" OR ") + ")");
    }

    // Filter query — AND conditions
    for (var key in filterQuery) {
      if (!filterQuery.hasOwnProperty(key)) continue;
      var val = filterQuery[key];
      if (val !== undefined && val !== null && val !== "" && this.columns.includes(key)) {
        conditions.push(key + " = ?");
        values.push(val);
      }
    }

    var where = conditions.length > 0 ? " WHERE " + conditions.join(" AND ") : "";
    var total = stmt("SELECT COUNT(*) as c FROM " + this.name + where).get(...values).c;
    var rows = stmt("SELECT * FROM " + this.name + where + " ORDER BY " + orderBy + " " + orderDir + " LIMIT ? OFFSET ?").all(...values, limit, offset);

    return { data: rows.map(r => this._merge(r)), total: total, limit: limit, offset: offset };
  }

  update(query, ops) {
    // Auto-seal $set values before writing
    if (this._autoSeal && ops.$set) {
      ops = Object.assign({}, ops, { $set: fieldCrypto.sealDoc(this.name, ops.$set) });
    }
    // Auto-translate query
    var translatedQuery = this._translateQuery(query);

    // Fast path: $set only with SQL-queryable fields — single UPDATE statement
    if (ops.$set && !ops.$push) {
      var qKeys = Object.keys(translatedQuery);
      var allSqlQueryable = qKeys.every(k => this.columns.includes(k));
      var setKeys = Object.keys(ops.$set);
      var allSqlSettable = setKeys.every(k => this.columns.includes(k));

      if (allSqlQueryable && allSqlSettable && qKeys.length > 0) {
        var setClauses = setKeys.map(k => k + " = ?");
        var setVals = setKeys.map(k => this._toSqlVal(ops.$set[k]));
        var whereClauses = qKeys.map(k => {
          var v = translatedQuery[k];
          if (v && typeof v === "object" && v.$ne !== undefined) return k + " IS NOT ?";
          return k + " = ?";
        });
        var whereVals = qKeys.map(k => {
          var v = translatedQuery[k];
          return v && typeof v === "object" && v.$ne !== undefined ? v.$ne : v;
        });
        var sql = "UPDATE " + this.name + " SET " + setClauses.join(",") + " WHERE " + whereClauses.join(" AND ");
        var result = stmt(sql).run(...setVals, ...whereVals);
        return result.changes;
      }
    }

    // Slow path: load docs, modify in JS, write back (needed for $push or non-column fields)
    // Use raw() for read since we re-seal before write
    var docs = this.raw()._query(translatedQuery);
    var updated = 0;
    for (var i = 0; i < docs.length; i++) {
      var doc = docs[i];
      if (ops.$set) Object.assign(doc, ops.$set);
      if (ops.$push) {
        for (const [key, val] of Object.entries(ops.$push)) {
          if (!Array.isArray(doc[key])) doc[key] = [];
          doc[key].push(val);
        }
      }
      var split = this._split(doc);
      var setClauses = [];
      var vals = [];
      for (const [k, v] of Object.entries(split)) {
        if (k === "_id") continue;
        setClauses.push(k + " = ?");
        vals.push(this._toSqlVal(v));
      }
      vals.push(doc._id);
      stmt("UPDATE " + this.name + " SET " + setClauses.join(",") + " WHERE _id = ?").run(...vals);
      updated++;
    }
    return updated;
  }

  remove(query) {
    query = this._translateQuery(query);
    var qKeys = Object.keys(query);
    // Fast path: all query fields are SQL columns — single DELETE
    if (qKeys.length > 0 && qKeys.every(k => this.columns.includes(k))) {
      var conditions = qKeys.map(k => {
        var v = query[k];
        if (v && typeof v === "object" && v.$ne !== undefined) return k + " IS NOT ?";
        return k + " = ?";
      });
      var values = qKeys.map(k => {
        var v = query[k];
        return v && typeof v === "object" && v.$ne !== undefined ? v.$ne : v;
      });
      var sql = "DELETE FROM " + this.name + " WHERE " + conditions.join(" AND ");
      return stmt(sql).run(...values).changes;
    }
    // Slow path: find matching docs, delete by _id
    var docs = this.find(query);
    for (var i = 0; i < docs.length; i++) {
      stmt("DELETE FROM " + this.name + " WHERE _id = ?").run(docs[i]._id);
    }
    return docs.length;
  }

  count(query) {
    if (!query || Object.keys(query).length === 0) {
      return stmt("SELECT COUNT(*) as c FROM " + this.name).get().c;
    }
    // Fast path: all query fields are SQL columns
    var qKeys = Object.keys(query);
    if (qKeys.every(k => this.columns.includes(k))) {
      var conditions = qKeys.map(k => {
        var v = query[k];
        if (v && typeof v === "object" && v.$ne !== undefined) return k + " IS NOT ?";
        return k + " = ?";
      });
      var values = qKeys.map(k => {
        var v = query[k];
        return v && typeof v === "object" && v.$ne !== undefined ? v.$ne : v;
      });
      return stmt("SELECT COUNT(*) as c FROM " + this.name + " WHERE " + conditions.join(" AND ")).get(...values).c;
    }
    return this.find(query).length;
  }

}

// ---- Run migrations ----
var migrationRunner = require("../app/data/db/migration-runner");
migrationRunner.run(db);

// Atomic storage usage query (avoids TOCTOU in quota checks)
function getTotalStorageUsed() {
  var row = db.prepare("SELECT COALESCE(SUM(size), 0) as total FROM files").get();
  return row ? Number(row.total) : 0;
}

module.exports = {
  getDb: function () { return db; },
  getTotalStorageUsed: getTotalStorageUsed,
  rawExec: rawExec,
  rawQuery: rawQuery,
  users: new Collection("users"),
  files: new Collection("files"),
  bundles: new Collection("bundles"),
  auditLog: new Collection("audit_log"),
  blockedIps: new Collection("blocked_ips"),
  apiKeys: new Collection("api_keys"),
  webhooks: new Collection("webhooks"),
  verificationTokens: new Collection("verification_tokens"),
  credentials: new Collection("credentials"),
  emailSends: new Collection("email_sends"),
  teams: new Collection("teams"),
  teamMembers: new Collection("team_members"),
  settings: new Collection("settings"),
  invites: new Collection("invites"),
  webhookDeliveries: new Collection("webhook_deliveries"),
  customerStash: new Collection("customer_stash"),
  bundleAccessCodes: new Collection("bundle_access_codes"),
  bundleAccessLog: new Collection("bundle_access_log"),
  certRevocations: new Collection("cert_revocations"),
  enrollmentCodes: new Collection("enrollment_codes"),
};
