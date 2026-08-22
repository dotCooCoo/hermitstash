// codebase-patterns:allow-file raw-process-env — db.js is the boot-time reader of HERMITSTASH_TMPDIR / HERMITSTASH_DB_PATH / NODE_ENV; precedes safeEnv schema initialization
// codebase-patterns:allow-file console-direct — db.js runs at module-load before logger initialization (logger → env → vault → db chain); direct stdout/stderr is the only sink at this boot stage.
// codebase-patterns:allow-file process-exit — boot-fatal abort when production lacks tmpfs; refuse to serve traffic on disk-backed plaintext DB.
// codebase-patterns:allow-file inline-require — vault is a circular dep (vault unseals db.key.enc, db.js stores the sealed key); load lazily inside getDbEncKey() to break the cycle.
// codebase-patterns:allow-file silent-catch — every empty catch here is best-effort schema migration (CREATE/DROP/ALTER IF NOT EXISTS) or temp-file cleanup; failures are correct to swallow.
var b = require("./vendor/blamejs");
var nodeFs = require("node:fs");
var nodePath = require("node:path");
var { DatabaseSync } = require("node:sqlite");

var { DATA_DIR: dataDir, PATHS, TIME } = require("./constants");
var C = require("./constants");
var dbEncCodec = require("./db-enc-codec");
if (!nodeFs.existsSync(dataDir)) nodeFs.mkdirSync(dataDir, { recursive: true });

// .db.enc is the durable artifact. It is decrypted into a tmpfs-backed working
// file at startup and re-encrypted at shutdown, so the plaintext database never
// reaches physical disk. Without HERMITSTASH_TMPDIR pointing at a tmpfs mount
// the working file falls back to the data directory, in plaintext.
var tmpDir = process.env.HERMITSTASH_TMPDIR || (nodeFs.existsSync("/dev/shm") ? "/dev/shm" : null);
if (tmpDir && !nodeFs.existsSync(tmpDir)) { try { nodeFs.mkdirSync(tmpDir, { recursive: true }); } catch (_e) { tmpDir = null; } }
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
var dbBaseName = "hermitstash-" + b.crypto.generateToken(C.BYTES.bytes(32)) + ".db";
var dbPath = process.env.HERMITSTASH_DB_PATH || nodePath.join(tmpDir, dbBaseName);
// An explicit DB path means a test database, which must not decrypt production.
var encPath = process.env.HERMITSTASH_DB_PATH ? null : PATHS.DB_ENC;

var _dbKey = null;
var _dbKeyPath = PATHS.DB_KEY_ENC;

function getDbEncKey() {
  if (_dbKey) return _dbKey;

  if (nodeFs.existsSync(_dbKeyPath)) {
    try {
      var vault = require("./vault");
      var sealed = nodeFs.readFileSync(_dbKeyPath, "utf8").trim();
      _dbKey = Buffer.from(vault.unseal(sealed), "base64");
      return _dbKey;
    } catch (e) {
      // A corrupt key file and a mismatched vault keypair — a vault.key
      // restored from the wrong backup — are indistinguishable here: both
      // throw. So fail closed whenever db.enc exists. Minting a new key and
      // re-sealing would overwrite the only sealed copy of the real one, and
      // db.enc would stay unreadable even after the right vault.key came back.
      if (encPath && nodeFs.existsSync(encPath)) {
        console.error("FATAL: DB key could not be unsealed — restore the matching data/vault.key; refusing to start to avoid destroying db.enc.");
        console.error("  (db.enc exists; regenerating the DB key here would overwrite the only sealed copy of the real key and lose the database.)");
        console.error("  detail: " + e.message);
        process.exit(1);
      }
      // With no db.enc there is no database to strand, so regenerating is safe.
      console.error("DB encryption key unreadable and no db.enc present — regenerating:", e.message);
    }
  }

  var vault = require("./vault");
  var rawKey = b.crypto.generateBytes(C.BYTES.bytes(32));
  var sealed = vault.seal(rawKey.toString("base64"));

  // A first run reaches here with no db.enc, so the fresh key is correct by
  // construction. Reaching here WITH a db.enc the new key cannot read is a
  // contradiction — fail closed rather than clobber the only sealed copy.
  if (encPath && nodeFs.existsSync(encPath)) {
    var packed = nodeFs.readFileSync(encPath);
    if (packed.length < 26 || !dbEncCodec.canDecryptDbEnc(packed, rawKey, dataDir)) {
      console.error("FATAL: refusing to overwrite db.key.enc with a key that does not decrypt the existing db.enc.");
      console.error("  Restore the matching data/vault.key (and db.key.enc) from a consistent backup, then restart.");
      process.exit(1);
    }
  }

  // A torn write here would fail to unseal on the next boot, which is the way
  // into the data loss the guards above exist to prevent.
  b.atomicFile.writeSync(_dbKeyPath, sealed, { fileMode: 0o600 });
  _dbKey = rawKey;
  return _dbKey;
}

function decryptDbFile() {
  if (!encPath || !nodeFs.existsSync(encPath)) return;
  if (nodeFs.existsSync(dbPath)) {
    var plainStat = nodeFs.statSync(dbPath);
    var encStat = nodeFs.statSync(encPath);
    if (plainStat.mtimeMs > encStat.mtimeMs && plainStat.size > 0) {
      console.log("  DB: plaintext is newer than encrypted — keeping plaintext (crash recovery)");
      return;
    }
  }
  var packed = nodeFs.readFileSync(encPath);
  if (packed.length < 26) {
    // Fatal, not a silent return: the plaintext database lives on tmpfs, so
    // there is nothing else to load, and the server would come up empty and
    // then re-encrypt that emptiness over the only durable copy.
    console.error("FATAL: " + encPath + " is only " + packed.length + " bytes — too short to be an "
      + "encrypted database, so it is truncated or corrupt.");
    console.error("  Refusing to start: continuing would serve an empty database and then overwrite");
    console.error("  this file with it, losing whatever it still holds.");
    console.error("  Restore hermitstash.db.enc (with its matching data/vault.key and db.key.enc)");
    console.error("  from a backup, then restart. If this is a fresh install and the file is a stray");
    console.error("  empty one, delete it and restart to begin with a new database.");
    process.exit(1);
  }
  // The codec tries the dataDir-bound AAD, then falls back to an un-bound
  // decrypt: a rotated db.enc is bound, a pre-AAD file or a portable backup is
  // not. Without the fallback a vault-key rotation left the server unbootable.
  b.atomicFile.writeSync(dbPath, dbEncCodec.decryptDbEnc(packed, getDbEncKey(), dataDir));
}

var _suppressEncrypt = false;

function encryptDbFile(removePlaintext) {
  if (!encPath) return; // test mode — no encrypted DB file
  if (_suppressEncrypt) return; // a restore wrote the authoritative db.enc — never clobber it
  try { db.exec("PRAGMA wal_checkpoint(TRUNCATE)"); } catch (_e) { /* checkpoint is best-effort — WAL may already be clean */ }
  if (!nodeFs.existsSync(dbPath)) return;
  // The AAD binds the live db.enc to this data directory, so another install
  // sharing the operator passphrase cannot swap its own file in.
  b.atomicFile.writeSync(encPath, dbEncCodec.encryptDbEnc(nodeFs.readFileSync(dbPath), getDbEncKey(), dataDir), { fileMode: 0o600 });
  if (removePlaintext) {
    try { nodeFs.unlinkSync(dbPath); } catch (_e) { /* cleanup — file may already be gone */ }
    try { nodeFs.unlinkSync(dbPath + "-wal"); } catch (_e) { /* cleanup — WAL file may not exist */ }
    try { nodeFs.unlinkSync(dbPath + "-shm"); } catch (_e) { /* cleanup — SHM file may not exist */ }
  }
}

// Current DB state as a packed Buffer, independent of encPath — so a backup
// captures live bytes even in test mode, or between periodic re-encrypts.
function snapshotEncryptedDb() {
  try { db.exec("PRAGMA wal_checkpoint(TRUNCATE)"); } catch (_e) { /* best-effort */ }
  if (!nodeFs.existsSync(dbPath)) return null;
  var plain = nodeFs.readFileSync(dbPath);
  // Deliberately not AAD-bound, unlike the live db.enc: a backup has to restore
  // onto a machine whose data directory differs, which is the whole point of
  // having one. decryptDbFile's un-bound fallback is what opens it again.
  return b.crypto.encryptPacked(plain, getDbEncKey());
}

// Plaintext databases left behind by a crashed process.
try {
  var staleFiles = nodeFs.readdirSync(tmpDir).filter(function (f) { return f.startsWith("hermitstash-") && f.endsWith(".db") && nodePath.join(tmpDir, f) !== dbPath; });
  staleFiles.forEach(function (f) {
    try { nodeFs.unlinkSync(nodePath.join(tmpDir, f)); } catch (_e) { /* cleanup — stale DB file may have been removed concurrently */ }
    try { nodeFs.unlinkSync(nodePath.join(tmpDir, f + "-wal")); } catch (_e) { /* cleanup — stale WAL may not exist */ }
    try { nodeFs.unlinkSync(nodePath.join(tmpDir, f + "-shm")); } catch (_e) { /* cleanup — stale SHM may not exist */ }
  });
} catch (_e) { /* tmpDir may not exist yet on first run */ }

decryptDbFile();

// sqlLength caps a single statement at parse time, a DoS floor on the raw-SQL
// surface that complements the row-count gate.
var db = new DatabaseSync(dbPath, { limits: { sqlLength: C.BYTES.mib(1) } });

db.exec("PRAGMA journal_mode=WAL");
db.exec("PRAGMA synchronous=NORMAL");       // safe under WAL
db.exec("PRAGMA cache_size=-8000");         // 8MB page cache
db.exec("PRAGMA temp_store=MEMORY");
db.exec("PRAGMA busy_timeout=5000");
db.exec("PRAGMA mmap_size=268435456");      // 256MB
db.exec("PRAGMA auto_vacuum=INCREMENTAL");
// secure_delete zeroes freed pages, so a deleted sealed value cannot be carved
// back out of the file. trusted_schema refuses functions and virtual-table
// modules named by a planted shadow schema, which matters on restore.
// cell_size_check rejects a corrupt page at parse time instead of crashing.
db.exec("PRAGMA secure_delete=ON");
try { db.exec("PRAGMA trusted_schema=OFF"); } catch (_e) { /* sqlite < 3.31 */ }
try { db.exec("PRAGMA cell_size_check=ON"); } catch (_e) { /* sqlite < 3.26 */ }

// Unconditional rather than dirty-tracked, so a backup is never stale.
var encTimer = setInterval(function () {
  try { encryptDbFile(); } catch (e) { console.error("[db] periodic encrypt failed — .db.enc may be stale:", e.message); }
}, TIME.minutes(5));
encTimer.unref();

process.on("exit", function () { try { encryptDbFile(true); } catch (e) { console.error("[db] exit-time encrypt failed — .db.enc may be stale:", e.message); } });

// The restore endpoint calls this once the worker has written an authoritative
// db.enc, so the graceful shutdown that follows cannot re-encrypt the stale
// tmpfs database over it.
function suppressExitEncrypt() {
  _suppressEncrypt = true;
  try { clearInterval(encTimer); } catch (_e) { /* timer may already be cleared */ }
}

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
try { db.exec("ALTER TABLE users ADD COLUMN status TEXT DEFAULT 'active'"); } catch (_e) {}
db.exec("CREATE INDEX IF NOT EXISTS idx_users_status ON users(status)");
db.exec("UPDATE users SET status = 'active' WHERE status IS NULL");
try { db.exec("ALTER TABLE users ADD COLUMN emailHash TEXT"); } catch (_e) {}
// Staged email-change target. The account's live `email` stays authoritative
// (and the login identity) until the holder proves control of the new address
// via a verification round-trip; only then is pendingEmail committed to email.
try { db.exec("ALTER TABLE users ADD COLUMN pendingEmail TEXT"); } catch (_e) {}
// UNIQUE closes the registration TOCTOU — the window between findByEmail and
// insert that the argon2 hash awaits across. SQLite treats NULLs as distinct,
// so email-less OAuth accounts are unaffected. An upgrade already holding
// duplicates falls back to a plain index, leaving the app check as the guard.
try {
  db.exec("DROP INDEX IF EXISTS idx_users_emailHash");
  db.exec("CREATE UNIQUE INDEX idx_users_emailHash ON users(emailHash)");
} catch (_e) {
  try { db.exec("CREATE INDEX IF NOT EXISTS idx_users_emailHash ON users(emailHash)"); } catch (_e2) { /* index best-effort */ }
}
try { db.exec("ALTER TABLE users ADD COLUMN vaultEnabled TEXT"); } catch (_e) {}
try { db.exec("ALTER TABLE users ADD COLUMN vaultPublicKey TEXT"); } catch (_e) {}
try { db.exec("ALTER TABLE users ADD COLUMN vaultStealth TEXT"); } catch (_e) {}
try { db.exec("ALTER TABLE users ADD COLUMN vaultMode TEXT"); } catch (_e) {}
try { db.exec("ALTER TABLE users ADD COLUMN vaultSeed TEXT"); } catch (_e) {}
try { db.exec("ALTER TABLE users ADD COLUMN totpLastStep TEXT"); } catch (_e) {}
try { db.exec("ALTER TABLE users ADD COLUMN totpSecret TEXT"); } catch (_e) {}
try { db.exec("ALTER TABLE users ADD COLUMN totpEnabled TEXT"); } catch (_e) {}
try { db.exec("ALTER TABLE users ADD COLUMN totpBackupCodes TEXT"); } catch (_e) {}
try { db.exec("ALTER TABLE users ADD COLUMN totpAlgorithm TEXT"); } catch (_e) {}
try { db.exec("ALTER TABLE users ADD COLUMN failedLoginAttempts INTEGER DEFAULT 0"); } catch (_e) {}
try { db.exec("ALTER TABLE users ADD COLUMN lockedUntil TEXT"); } catch (_e) {}
// Per-user overrides, off by default: 0 or null means "not set" and falls back
// to the global config. The numeric limits stay raw because they are used in
// arithmetic; allowedExtensions is a string and is sealed.
try { db.exec("ALTER TABLE users ADD COLUMN quotaBytes INTEGER DEFAULT 0"); } catch (_e) {}
try { db.exec("ALTER TABLE users ADD COLUMN maxFileSize INTEGER DEFAULT 0"); } catch (_e) {}
try { db.exec("ALTER TABLE users ADD COLUMN maxFiles INTEGER DEFAULT 0"); } catch (_e) {}
try { db.exec("ALTER TABLE users ADD COLUMN maxBundleSize INTEGER DEFAULT 0"); } catch (_e) {}
try { db.exec("ALTER TABLE users ADD COLUMN allowedExtensions TEXT"); } catch (_e) {}
// tailscaleIdHash is a blind index in its own identity namespace, so a tailnet
// login coinciding with an existing email never cross-matches. Not UNIQUE: the
// column arrives empty for every row, and a duplicate must not brick the users
// table at boot.
try { db.exec("ALTER TABLE users ADD COLUMN tailscaleId TEXT"); } catch (_e) {}
try { db.exec("ALTER TABLE users ADD COLUMN tailscaleIdHash TEXT"); } catch (_e) {}
db.exec("CREATE INDEX IF NOT EXISTS idx_users_tailscaleIdHash ON users(tailscaleIdHash)");
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
try { db.exec("ALTER TABLE audit_log ADD COLUMN ip TEXT"); } catch (_e) { /* idempotent — column may already exist */ }
// method, authType and requestId stay raw — a verb, an auth class and a
// correlation id. path and userAgent are sealed, because they carry
// identifiers. A system event with no request leaves all of them null.
try { db.exec("ALTER TABLE audit_log ADD COLUMN method TEXT"); } catch (_e) { /* idempotent — column may already exist */ }
try { db.exec("ALTER TABLE audit_log ADD COLUMN path TEXT"); } catch (_e) { /* idempotent — column may already exist */ }
try { db.exec("ALTER TABLE audit_log ADD COLUMN authType TEXT"); } catch (_e) { /* idempotent — column may already exist */ }
try { db.exec("ALTER TABLE audit_log ADD COLUMN userAgent TEXT"); } catch (_e) { /* idempotent — column may already exist */ }
try { db.exec("ALTER TABLE audit_log ADD COLUMN requestId TEXT"); } catch (_e) { /* idempotent — column may already exist */ }
// Tamper-evidence chain columns (opt-in via AUDIT_CHAIN). Stay RAW — these are
// integrity hashes + a monotonic ordering counter; sealing them would break
// hash recomputation and integer ORDER BY. Populated only when the chain is
// enabled (lib/audit.js appendChained); on a chain-off deployment they stay NULL.
try { db.exec("ALTER TABLE audit_log ADD COLUMN monotonicCounter INTEGER"); } catch (_e) { /* idempotent — column may already exist */ }
try { db.exec("ALTER TABLE audit_log ADD COLUMN prevHash TEXT"); } catch (_e) { /* idempotent — column may already exist */ }
try { db.exec("ALTER TABLE audit_log ADD COLUMN rowHash TEXT"); } catch (_e) { /* idempotent — column may already exist */ }
try { db.exec("ALTER TABLE audit_log ADD COLUMN nonce BLOB"); } catch (_e) { /* idempotent — column may already exist */ }
db.exec("CREATE INDEX IF NOT EXISTS idx_audit_monotonicCounter ON audit_log(monotonicCounter)");
// Chain-origin anchor for the audit chain. When retention deletes the oldest
// (lowest-counter) rows, the chain would otherwise break at the new first row
// ("prevHash mismatch"). The anchor records the highest deleted
// (monotonicCounter, rowHash) so b.auditChain.verifyChain resumes the walk from
// the anchor instead of failing. Schema mirrors blamejs's _blamejs_audit_purge_anchor
// (single-row per scope) so the framework verifier reads it unchanged.
db.exec(`
  CREATE TABLE IF NOT EXISTS _blamejs_audit_purge_anchor (
    scope TEXT PRIMARY KEY CHECK (scope IN ('audit', 'consent')),
    lastPurgedCounter INTEGER NOT NULL,
    lastPurgedRowHash TEXT NOT NULL,
    archiveBundleId TEXT NOT NULL,
    purgedAt INTEGER NOT NULL
  )
`);
// Drop stale indexes on sealed columns
try { db.exec("DROP INDEX IF EXISTS idx_audit_action"); } catch (_e) { /* idempotent — index may not exist */ }
try { db.exec("DROP INDEX IF EXISTS idx_audit_performedBy"); } catch (_e) { /* idempotent — index may not exist */ }

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
try { db.exec("DROP INDEX IF EXISTS idx_files_shareId"); } catch (_e) { /* idempotent — index may not exist */ }
try { db.exec("DROP INDEX IF EXISTS idx_files_bundleShareId"); } catch (_e) { /* idempotent — index may not exist */ }
try { db.exec("DROP INDEX IF EXISTS idx_files_uploaderEmail"); } catch (_e) { /* idempotent — index may not exist */ }
try { db.exec("ALTER TABLE files ADD COLUMN encryptionKey TEXT"); } catch (_e) {}
try { db.exec("ALTER TABLE files ADD COLUMN expiresAt TEXT"); } catch (_e) {}
try { db.exec("ALTER TABLE files ADD COLUMN emailHash TEXT"); } catch (_e) {}
try { db.exec("ALTER TABLE files ADD COLUMN shareIdHash TEXT"); } catch (_e) {}
try { db.exec("ALTER TABLE files ADD COLUMN bundleShareIdHash TEXT"); } catch (_e) {}
try { db.exec("ALTER TABLE files ADD COLUMN checksum TEXT"); } catch (_e) {}
try { db.exec("ALTER TABLE files ADD COLUMN vaultBatchId TEXT"); } catch (_e) {}
try { db.exec("ALTER TABLE files ADD COLUMN vaultBatchName TEXT"); } catch (_e) {}
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
try { db.exec("DROP INDEX IF EXISTS idx_bundles_shareId"); } catch (_e) { /* idempotent — index may not exist */ }
try { db.exec("ALTER TABLE bundles ADD COLUMN emailHash TEXT"); } catch (_e) {}
try { db.exec("ALTER TABLE bundles ADD COLUMN shareIdHash TEXT"); } catch (_e) {}
db.exec("CREATE INDEX IF NOT EXISTS idx_bundles_shareIdHash ON bundles(shareIdHash)");
try { db.exec("ALTER TABLE bundles ADD COLUMN passwordHash TEXT"); } catch (_e) {}
try { db.exec("ALTER TABLE bundles ADD COLUMN message TEXT"); } catch (_e) {}
try { db.exec("ALTER TABLE bundles ADD COLUMN expiresAt TEXT"); } catch (_e) {}
try { db.exec("ALTER TABLE bundles ADD COLUMN finalizeTokenHash TEXT"); } catch (_e) {}
try { db.exec("ALTER TABLE bundles ADD COLUMN ownerId TEXT"); } catch (_e) {}
try { db.exec("ALTER TABLE bundles ADD COLUMN skippedFiles TEXT"); } catch (_e) {}
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
// keyHash is a raw SHA3-512 of the API token — hot path for api-auth middleware
// (findOne on every authenticated request). Without this index it's a full scan.
db.exec("CREATE INDEX IF NOT EXISTS idx_apikeys_keyHash ON api_keys(keyHash)");
try { db.exec("ALTER TABLE api_keys ADD COLUMN boundStashId TEXT"); } catch (_e) { /* idempotent — column may already exist */ }
try { db.exec("ALTER TABLE api_keys ADD COLUMN boundBundleId TEXT"); } catch (_e) { /* idempotent — column may already exist */ }
try { db.exec("ALTER TABLE api_keys ADD COLUMN certIssuedAt TEXT"); } catch (_e) { /* idempotent — column may already exist */ }
try { db.exec("ALTER TABLE api_keys ADD COLUMN certExpiresAt TEXT"); } catch (_e) { /* idempotent — column may already exist */ }
try { db.exec("ALTER TABLE api_keys ADD COLUMN certFingerprint TEXT"); } catch (_e) { /* idempotent — column may already exist */ }

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
try { db.exec("ALTER TABLE files ADD COLUMN vaultEncrypted TEXT"); } catch (_e) { /* idempotent — column may already exist */ }
try { db.exec("ALTER TABLE files ADD COLUMN vaultEncapsulatedKey TEXT"); } catch (_e) { /* idempotent — column may already exist */ }
try { db.exec("ALTER TABLE files ADD COLUMN vaultIv TEXT"); } catch (_e) { /* idempotent — column may already exist */ }

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
try { db.exec("ALTER TABLE customer_stash ADD COLUMN slugHash TEXT"); } catch (_e) {}
try { db.exec("ALTER TABLE customer_stash ADD COLUMN allowedEmails TEXT"); } catch (_e) {}
try { db.exec("ALTER TABLE customer_stash ADD COLUMN accessMode TEXT DEFAULT 'open'"); } catch (_e) {}
try { db.exec("ALTER TABLE customer_stash ADD COLUMN syncEnabled TEXT DEFAULT 'false'"); } catch (_e) {}
try { db.exec("ALTER TABLE customer_stash ADD COLUMN syncBundleId TEXT"); } catch (_e) {}
try { db.exec("ALTER TABLE customer_stash ADD COLUMN teamId TEXT"); } catch (_e) {}
db.exec("CREATE UNIQUE INDEX IF NOT EXISTS idx_stash_slugHash ON customer_stash(slugHash)");

// Individual user members of a customer stash — read access to the stash's
// uploads without requiring a team. stashId + userId are raw FK ids (membership
// lookups); addedAt is sealed, matching team_members.joinedAt.
db.exec(`
  CREATE TABLE IF NOT EXISTS stash_members (
    _id TEXT PRIMARY KEY,
    stashId TEXT,
    userId TEXT,
    addedAt TEXT,
    data TEXT
  )
`);
db.exec("CREATE INDEX IF NOT EXISTS idx_sm_stashId ON stash_members(stashId)");
db.exec("CREATE INDEX IF NOT EXISTS idx_sm_userId ON stash_members(userId)");

try { db.exec("ALTER TABLE bundles ADD COLUMN stashId TEXT"); } catch (_e) {}
try { db.exec("ALTER TABLE bundles ADD COLUMN bundleName TEXT"); } catch (_e) {}
try { db.exec("ALTER TABLE bundles ADD COLUMN allowedEmails TEXT"); } catch (_e) {}
try { db.exec("ALTER TABLE bundles ADD COLUMN accessMode TEXT DEFAULT 'open'"); } catch (_e) {}
try { db.exec("ALTER TABLE bundles ADD COLUMN bundleType TEXT DEFAULT 'snapshot'"); } catch (_e) {}
try { db.exec("ALTER TABLE bundles ADD COLUMN seq INTEGER DEFAULT 0"); } catch (_e) {}
try { db.exec("ALTER TABLE files ADD COLUMN updatedAt TEXT"); } catch (_e) {}
try { db.exec("ALTER TABLE files ADD COLUMN seq INTEGER DEFAULT 0"); } catch (_e) {}
try { db.exec("ALTER TABLE files ADD COLUMN deletedAt TEXT"); } catch (_e) {}
try { db.exec("ALTER TABLE files ADD COLUMN uploaderName TEXT"); } catch (_e) {}
// Composite index for the sync change-feed query (WHERE bundleId=? AND seq>?
// ORDER BY seq). Both columns are raw (bundleId is a FK id, seq a counter), so
// the index serves the paged catch_up directly instead of a full-bundle scan.
db.exec("CREATE INDEX IF NOT EXISTS idx_files_bundle_seq ON files(bundleId, seq)");

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

// Bundle access lockouts — persistent failed-attempt counters for bundle passwords.
// Replaces the old in-process Map which was lost on restart and not shared across
// workers. All columns are raw (no seal).
db.exec(`
  CREATE TABLE IF NOT EXISTS bundle_access_lockouts (
    _id TEXT PRIMARY KEY,
    shareIdHash TEXT,
    failures INTEGER DEFAULT 0,
    lastAttempt TEXT,
    data TEXT
  )
`);
db.exec("CREATE INDEX IF NOT EXISTS idx_balockout_shareIdHash ON bundle_access_lockouts(shareIdHash)");

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
try { db.exec("ALTER TABLE enrollment_codes ADD COLUMN reissue TEXT"); } catch (_e) { /* idempotent — column may already exist */ }
try { db.exec("ALTER TABLE enrollment_codes ADD COLUMN originalKeyId TEXT"); } catch (_e) { /* idempotent — column may already exist */ }

// The framework's idempotency store creates its own table at first use, so the
// HS-managed one is dropped on upgrade. The cache is transient, so nothing an
// operator would miss goes with it.
try { db.exec("DROP TABLE IF EXISTS idempotency_keys"); } catch (_e) { /* idempotent */ }

// Known columns per table
var COLUMNS = {
  users: ["_id", "googleId", "tailscaleId", "tailscaleIdHash", "email", "pendingEmail", "displayName", "avatar", "passwordHash", "authType", "role", "status", "emailHash", "vaultEnabled", "vaultPublicKey", "vaultStealth", "vaultMode", "vaultSeed", "totpLastStep", "totpSecret", "totpEnabled", "totpBackupCodes", "totpAlgorithm", "failedLoginAttempts", "lockedUntil", "quotaBytes", "maxFileSize", "maxFiles", "maxBundleSize", "allowedExtensions", "createdAt", "lastLogin"],
  audit_log: ["_id", "action", "targetId", "targetEmail", "performedBy", "performedByEmail", "details", "ip", "method", "path", "authType", "userAgent", "requestId", "createdAt", "monotonicCounter", "prevHash", "rowHash", "nonce"],
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
  customer_stash: ["_id", "slug", "slugHash", "name", "title", "subtitle", "accentColor", "logoUrl", "passwordHash", "maxFileSize", "maxFiles", "maxBundleSize", "defaultExpiry", "allowedExtensions", "allowedEmails", "accessMode", "syncEnabled", "syncBundleId", "teamId", "enabled", "createdBy", "bundleCount", "totalBytes", "createdAt"],
  stash_members: ["_id", "stashId", "userId", "addedAt"],
  bundle_access_codes: ["_id", "bundleShareId", "email", "emailHash", "code", "codeHash", "attempts", "status", "expiresAt", "createdAt"],
  bundle_access_log: ["_id", "bundleShareId", "email", "emailHash", "accessedAt", "ip"],
  bundle_access_lockouts: ["_id", "shareIdHash", "failures", "lastAttempt"],
  cert_revocations: ["_id", "fingerprintHash", "cn", "revokedAt", "reason"],
  enrollment_codes: ["_id", "codeHash", "apiKey", "clientCert", "clientKey", "caCert", "stashId", "bundleId", "createdBy", "status", "expiresAt", "createdAt", "reissue", "originalKeyId"],
};

// Moves values out of the `data` JSON blob into their dedicated columns.
// Idempotent, and runs on every startup.
(function migrateOverflowFields() {
  var migrations = [
    { table: "users", fields: ["totpSecret", "totpEnabled", "totpBackupCodes", "totpAlgorithm", "totpLastStep", "vaultEnabled", "vaultPublicKey", "vaultStealth", "vaultMode", "vaultSeed", "failedLoginAttempts", "lockedUntil"] },
    { table: "files", fields: ["checksum", "uploaderName"] },
    { table: "bundles", fields: ["finalizeTokenHash", "skippedFiles", "ownerId", "stashId", "bundleName", "allowedEmails", "accessMode", "bundleType", "seq"] },
    { table: "api_keys", fields: ["certIssuedAt", "certExpiresAt", "certFingerprint"] },
    { table: "enrollment_codes", fields: ["reissue", "originalKeyId"] },
    { table: "audit_log", fields: ["ip", "monotonicCounter", "prevHash", "rowHash", "nonce"] },
    { table: "customer_stash", fields: ["teamId"] },
  ];
  for (var m = 0; m < migrations.length; m++) {
    var table = migrations[m].table;
    var fields = migrations[m].fields;
    var qTable = b.safeSql.quoteIdentifier(table, "sqlite");
    try {
      var rows = db.prepare("SELECT _id, data FROM " + qTable + " WHERE data IS NOT NULL AND data != 'null' AND data != '{}'").all();
      for (var r = 0; r < rows.length; r++) {
        var extra;
        try { extra = b.safeJson.parse(rows[r].data); } catch (_e) { continue; } // b.safeJson strips __proto__/constructor from the overflow blob (matches the _merge read path)
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
          db.prepare("UPDATE " + qTable + " SET " + setClauses.join(", ") + " WHERE _id = ?").run(...vals);
        }
      }
    } catch (_e) { /* table may not exist in test environments */ }
  }
})();

// ---- Raw SQL helpers for operations the ORM can't express ----
function rawExec(sql, ...params) { return db.prepare(sql).run(...params); }
function rawQuery(sql, ...params) { return db.prepare(sql).all(...params); }
function rawGet(sql, ...params) { return db.prepare(sql).get(...params); }

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

// Registration has to happen up front: sealRow and unsealRow silently no-op —
// storing PLAINTEXT — for a table they do not know about. It is idempotent and
// key-independent, so module load is a safe place for it.
var fieldCrypto = require("./field-crypto");
fieldCrypto.registerWithBlamejs();

// Plain equality, { $ne } and { $in: [...] }. The $in form backs the
// blind-index dual-read, matching both the keyed MAC and the legacy unkeyed
// digest while the backfill in lib/derived-hash-backfill is still running.
function _sqlCond(col, v) {
  if (v && typeof v === "object" && v.$ne !== undefined) {
    return { clause: col + " IS NOT ?", values: [v.$ne] };
  }
  if (v && typeof v === "object" && Array.isArray(v.$in)) {
    if (v.$in.length === 0) return { clause: "0 = 1", values: [] }; // matches nothing
    return { clause: col + " IN (" + v.$in.map(function () { return "?"; }).join(",") + ")", values: v.$in.slice() };
  }
  return { clause: col + " = ?", values: [v] };
}

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
    return b.crypto.generateToken(C.BYTES.bytes(32));
  }

  // Split a doc into column values + overflow JSON for extra fields
  _split(doc) {
    var cols = {};
    var extra = {};
    for (var [k, v] of Object.entries(doc)) {
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
    var doc = {};
    for (var [k, v] of Object.entries(row)) {
      if (k === "data") continue;
      if (v !== null) doc[k] = v;
    }
    if (row.data) {
      try {
        // Parse via safeJson so a reserved key (__proto__ / constructor /
        // prototype) that reached the overflow blob — a field name can be
        // user-influenced (e.g. a settings/metadata key) — is stripped at parse
        // rather than re-parenting the doc via the computed-property write below.
        var blob = b.safeJson.parse(row.data);
        var realCols = this.columns;
        // A real column always wins. On an upgraded database the blob can still
        // carry a key since promoted to a column, and a blind Object.assign
        // would overwrite the live value with the stale one.
        Object.keys(blob).forEach(function (k) {
          if (k === "__proto__" || k === "constructor" || k === "prototype") return;
          if (realCols.indexOf(k) === -1) b.safeObject.ownSet(doc, k, blob[k]);
        });
      } catch { /* malformed overflow blob — real columns still apply */ }
    }
    // Unseal first. A column that is both sealed and JSON-typed — such as
    // users.totpBackupCodes — is still ciphertext here, so the JSON parse below
    // would throw and leave it a string.
    if (this._autoSeal) doc = fieldCrypto.unsealDoc(this.name, doc);
    // THEN parse JSON-typed columns (arrays/objects stored as JSON strings) on the
    // now-plaintext values so they round-trip as real arrays/objects.
    for (var j = 0; j < this.jsonColumns.length; j++) {
      var jc = this.jsonColumns[j];
      if (typeof doc[jc] === "string") {
        // b.safeJson.parseOrDefault: valid JSON → parsed (proto-pollution keys
        // stripped, matching the sibling b.safeJson.parse of the overflow blob
        // earlier in _merge); invalid → left as the original string.
        doc[jc] = b.safeJson.parseOrDefault(doc[jc], doc[jc]);
      }
    }
    return doc;
  }

  _toSqlVal(v) {
    if (v === undefined || v === null) return null;
    if (typeof v === "boolean") return v ? 1 : 0;
    // Buffers are binary column values (BLOB) — bind them through unchanged so
    // they round-trip as bytes (e.g. the audit-chain nonce). JSON-stringifying
    // a Buffer would corrupt it into a {"type":"Buffer",...} string.
    if (Buffer.isBuffer(v)) return v;
    if (typeof v === "object") return JSON.stringify(v);
    return v;
  }

  insert(doc) {
    var record = { _id: doc._id || this._genId(), ...doc };
    // Auto-seal: routes pass plaintext, crypto layer handles encryption.
    // _id is set above so AAD-bound sealing can bind to the row identity.
    if (this._autoSeal) record = fieldCrypto.sealDoc(this.name, record, record._id);
    var split = this._split(record);
    var keys = Object.keys(split);
    var placeholders = keys.map(() => "?").join(",");
    var sql = "INSERT INTO " + this.name + " (" + keys.join(",") + ") VALUES (" + placeholders + ")";
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

  // "Is this column ciphertext" — not "does it carry a derived index", which is
  // much narrower and left every other sealed column answering wrongly.
  // Cached per collection, because this runs for every key of every query.
  _isSealedColumn(key) {
    if (this._sealedNames === undefined) {
      try {
        var names = fieldCrypto.getSealedFields ? fieldCrypto.getSealedFields(this.name) : null;
        this._sealedNames = names && names.length ? new Set(names) : null;
      } catch (_e) {
        // Never let the guard's own failure block a query — a collection with no
        // sealed fields, or a field-crypto shape this does not understand, falls
        // back to the previous pass-through behaviour.
        this._sealedNames = null;
      }
    }
    return !!(this._sealedNames && this._sealedNames.has(key));
  }

  // Auto-translate queries on sealed fields to their hash equivalents
  _translateQuery(query) {
    if (!this._autoSeal) return query;
    var translated = {};
    for (var key in query) {
      var val = query[key];

      // IN-list over a sealed/derived field: hash EACH element with the
      // dual-read and union the candidate digests, so a blind-index IN lookup
      // matches the keyed MAC + legacy digest of every element. (Mirrors the
      // blamejs db-query sealed-block IN dual-read; HS owns its own query layer.)
      if (val && typeof val === "object" && Array.isArray(val.$in)) {
        var derivedKey = null;
        var union = [];
        for (var ei = 0; ei < val.$in.length; ei++) {
          var elem = val.$in[ei];
          if (typeof elem !== "string") { derivedKey = null; break; }
          var lk = fieldCrypto.lookupHash(this.name, key, elem);
          if (!lk) { derivedKey = null; break; }
          derivedKey = lk.key;
          var cands = lk.candidates || [lk.value];
          for (var ci = 0; ci < cands.length; ci++) {
            if (union.indexOf(cands[ci]) === -1) union.push(cands[ci]);
          }
        }
        if (derivedKey && val.$in.length > 0) {
          translated[derivedKey] = { $in: union };
        } else if (val.$in.length === 0) {
          // Answerable without touching the column: _sqlCond renders it `0 = 1`.
          // Callers build these lists dynamically, so "none of them" is an
          // ordinary query rather than one the storage cannot evaluate.
          translated[key] = val;
        } else if (this._isSealedColumn(key)) {
          // Sealed, but the blind index was unusable — a non-string element, or
          // a field with no derived index. Passing it through would compare
          // against ciphertext and quietly match nothing, so refuse: a caller
          // asking an unanswerable question should hear so, not get no rows.
          throw new Error("Cannot $in-query sealed field '" + key + "' in " + this.name
            + " — every element must be a string and the field must carry a derived index");
        } else {
          translated[key] = val; // raw column — pass through
        }
        continue;
      }

      // Equality over a sealed field → blind-index lookup with dual-read.
      var lookup = fieldCrypto.lookupHash(this.name, key, val);
      if (lookup && typeof val === "string") {
        // Dual-read: match every candidate digest (keyed MAC + legacy unkeyed)
        // during the blind-index migration. A single candidate collapses to
        // plain equality so the common (post-backfill) path stays a simple `=`.
        translated[lookup.key] = (lookup.candidates && lookup.candidates.length > 1)
          ? { $in: lookup.candidates }
          : lookup.value;
      } else if (this._isSealedColumn(key) && (val === null || val === undefined || val === "")) {
        // An absent or blank operand, `undefined` included. A write creates no
        // digest for an empty source, so nothing can match one — an empty $in
        // renders as `0 = 1` and gives that answer directly. Raising instead
        // would break live callers that reach here with no value and have
        // always been answered "no match"; the defect this guard exists for is
        // a query returning the WRONG rows, not one already returning none.
        translated[key] = { $in: [] };
      } else if (this._isSealedColumn(key)) {
        // Sealed and not blind-indexed, so it cannot be evaluated against the
        // ciphertext column. Passing it through compiles a silently wrong
        // predicate: `sealedCol IS NOT ?` matches every row and `sealedCol = ?`
        // matches none, so a query written to exclude something returns it.
        // Only equality and $in over a derived index are answerable.
        //
        // Booleans are refused too. The write path stores `false` raw as "0.0"
        // and `true` as ciphertext in one column, so `{vaultEnabled: false}`
        // would match by accident of the encoding while `{vaultEnabled: true}`
        // matched nothing. Store the flag raw if one ever needs querying.
        throw new Error("Unsupported query on sealed field '" + key + "' in " + this.name
          + " — only equality and $in over a derived index are blind-indexed; "
          + "unseal and filter in JS for anything else");
      } else {
        translated[key] = val;
      }
    }
    return translated;
  }

  findOne(query) {
    var docs = this._query(this._translateQuery(query), 1);
    return docs.length > 0 ? docs[0] : null;
  }

  find(query) {
    return this._query(this._translateQuery(query || {}));
  }

  _query(query, limit) {
    // Coerce limit to a non-negative integer before it reaches the LIMIT
    // clause (built by concatenation below) — defends against a non-numeric
    // limit from any future caller.
    if (limit != null) limit = Math.max(0, parseInt(limit, 10) || 0);
    var keys = Object.keys(query);

    // No filter — return all
    if (keys.length === 0) {
      var sql = "SELECT * FROM " + this.name + (limit ? " LIMIT " + limit : "");
      return stmt(sql).all().map(r => this._merge(r));
    }

    // Build WHERE clause for indexed columns, fall back to JS filter for extras
    var conditions = [];
    var values = [];
    var jsFilters = [];

    for (var [key, val] of Object.entries(query)) {
      var isObj = val && typeof val === "object";
      if (this.columns.includes(key)) {
        var c = _sqlCond(key, val);
        conditions.push(c.clause);
        for (var ci = 0; ci < c.values.length; ci++) values.push(c.values[ci]);
      } else if (isObj && val.$ne !== undefined) {
        jsFilters.push({ key: key, op: "ne", val: val.$ne });
      } else if (isObj && Array.isArray(val.$in)) {
        jsFilters.push({ key: key, op: "in", val: val.$in });
      } else {
        jsFilters.push({ key: key, op: "eq", val: val });
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
          if (f.op === "in" && f.val.indexOf(doc[f.key]) === -1) return false;
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

    // Translate sealed/derived-field predicates the same way find/findOne/count/
    // update/remove do: a bare `{ email: "x" }` filter would otherwise hit the
    // column check and compare plaintext against the SEALED `email` column (always
    // matching nothing). _translateQuery rewrites it to the keyed blind index and
    // throws loudly on an unsupported operator over a sealed field.
    query = this._translateQuery(query);
    for (var key in query) {
      if (!Object.prototype.hasOwnProperty.call(query, key)) continue;
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
      var _sealedSearch = this._autoSeal ? fieldCrypto.getSealedFields(this.name) : [];
      for (var i = 0; i < searchFields.length; i++) {
        // A sealed column holds AAD-bound ciphertext; `LIKE %term%` against it can
        // never match, so a sealed searchField would silently return nothing. Fail
        // loud — sealed-field search is done in JS after unseal, not in SQL.
        if (_sealedSearch.indexOf(searchFields[i]) !== -1) {
          throw new Error("Cannot LIKE-search sealed field '" + searchFields[i] + "' in " + this.name + " — search plaintext in JS after unseal.");
        }
        if (this.columns.includes(searchFields[i])) {
          searchConds.push(searchFields[i] + " LIKE ?");
          values.push("%" + searchTerm + "%");
        }
      }
      if (searchConds.length > 0) conditions.push("(" + searchConds.join(" OR ") + ")");
    }

    // Filter query — AND conditions. Translate sealed/derived predicates to their
    // blind index (as find/update/remove do) so a `{ email: x }` filter matches.
    filterQuery = this._translateQuery(filterQuery || {});
    for (var key in filterQuery) {
      if (!Object.prototype.hasOwnProperty.call(filterQuery, key)) continue;
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
    // Only $set and $push do anything below. An `ops` carrying neither writes
    // nothing and returns without complaint, so `repo.update(id, { field: v })`
    // — which is how the repositories' own (id, ops) signature reads — is a
    // silent no-op: no error, no write, and nothing for the caller to check.
    // Refuse it instead. Every call site in the tree passes an operator, so
    // this only ever fires on the mistake.
    if (!ops || typeof ops !== "object" || (!ops.$set && !ops.$push)) {
      throw new Error("db.update on " + this.name + " needs $set or $push — got "
        + (ops && typeof ops === "object" ? "keys [" + Object.keys(ops).join(", ") + "]" : typeof ops)
        + ". A bare object writes nothing; wrap the fields in { $set: { ... } }.");
    }
    // Sealed columns are AAD-bound to their row's _id, so each must be sealed
    // with its own — which the multi-row single UPDATE cannot do.
    var sealedFields = (this._autoSeal && ops.$set) ? fieldCrypto.getSealedFields(this.name) : [];
    var setTouchesSealed = false;
    if (ops.$set) {
      for (var sf in ops.$set) {
        if (Object.prototype.hasOwnProperty.call(ops.$set, sf) && sealedFields.indexOf(sf) !== -1) {
          setTouchesSealed = true; break;
        }
      }
    }

    // Auto-translate query
    var translatedQuery = this._translateQuery(query);

    // Raw columns — counters, status enums, FK ids, timestamps — need no
    // sealing, so a raw-only $set stays a single statement.
    if (ops.$set && !ops.$push && !setTouchesSealed) {
      var qKeys = Object.keys(translatedQuery);
      var allSqlQueryable = qKeys.every(k => this.columns.includes(k));
      var setKeys = Object.keys(ops.$set);
      var allSqlSettable = setKeys.every(k => this.columns.includes(k));

      if (allSqlQueryable && allSqlSettable && qKeys.length > 0) {
        var setClauses = setKeys.map(k => k + " = ?");
        var setVals = setKeys.map(k => this._toSqlVal(ops.$set[k]));
        var whereParts = qKeys.map(k => _sqlCond(k, translatedQuery[k]));
        var whereClauses = whereParts.map(p => p.clause);
        var whereVals = whereParts.reduce((acc, p) => acc.concat(p.values), []);
        var sql = "UPDATE " + this.name + " SET " + setClauses.join(",") + " WHERE " + whereClauses.join(" AND ");
        var result = stmt(sql).run(...setVals, ...whereVals);
        return result.changes;
      }
    }

    // Per row: load still-sealed, apply the plaintext $set, then seal each row
    // under its own _id. Untouched sealed columns pass through verbatim, so
    // only what changed is re-sealed.
    var docs = this.raw()._query(translatedQuery);
    var updated = 0;
    for (var i = 0; i < docs.length; i++) {
      var doc = docs[i];
      if (ops.$set) {
        var sealedSet = this._autoSeal
          ? fieldCrypto.sealDoc(this.name, Object.assign({ _id: doc._id }, ops.$set), doc._id)
          : ops.$set;
        Object.assign(doc, sealedSet);
      }
      if (ops.$push) {
        var _pushSealed = this._autoSeal ? fieldCrypto.getSealedFields(this.name) : [];
        // The rows above are raw so $set can pass untouched columns through, but
        // $push needs the decoded array — hence the re-read and the reseal.
        // Without it the push drops the existing entries and stores the array
        // as plaintext in a column that is supposed to be sealed.
        var _plain = this._query(this._translateQuery({ _id: doc._id }))[0] || {};
        var _pushedSealed = false;
        for (var [key, val] of Object.entries(ops.$push)) {
          var _cur = Array.isArray(_plain[key]) ? _plain[key].slice() : [];
          _cur.push(val);
          doc[key] = _cur;
          if (_pushSealed.indexOf(key) !== -1) _pushedSealed = true;
        }
        if (_pushedSealed) {
          var _reseal = { _id: doc._id };
          for (var _pk in ops.$push) {
            if (Object.prototype.hasOwnProperty.call(ops.$push, _pk) && _pushSealed.indexOf(_pk) !== -1) _reseal[_pk] = doc[_pk];
          }
          Object.assign(doc, fieldCrypto.sealDoc(this.name, _reseal, doc._id));
        }
      }
      var split = this._split(doc);
      var setClauses = [];
      var vals = [];
      for (var [k, v] of Object.entries(split)) {
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
      var parts = qKeys.map(k => _sqlCond(k, query[k]));
      var conditions = parts.map(p => p.clause);
      var values = parts.reduce((acc, p) => acc.concat(p.values), []);
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
    // Translate sealed/derived-field predicates the same way find/update/remove
    // do — a bare `{ email: "x" }` would otherwise hit the column fast-path and
    // compare the plaintext against the SEALED `email` column (always 0).
    // _translateQuery rewrites it to the keyed blind index (`{ emailHash: {$in} }`).
    var translated = this._translateQuery(query);
    var qKeys = Object.keys(translated);
    // Fast path: every translated field is a real SQL column — build the WHERE
    // through _sqlCond so eq / $ne / $in (the dual-read form) are all handled.
    if (qKeys.every(k => this.columns.includes(k))) {
      var values = [];
      var conditions = qKeys.map(k => {
        var c = _sqlCond(k, translated[k]);
        for (var ci = 0; ci < c.values.length; ci++) values.push(c.values[ci]);
        return c.clause;
      });
      return stmt("SELECT COUNT(*) as c FROM " + this.name + " WHERE " + conditions.join(" AND ")).get(...values).c;
    }
    return this.find(query).length;
  }

}

// ---- Run migrations ----
var migrationRunner = require("../app/data/db/migration-runner");
migrationRunner.run(db);

// Sum of committed file sizes. The SELECT is atomic, but that only makes the
// READ consistent — it does NOT close a check-then-act window: the SUM doesn't
// reflect an in-flight upload until that file's row commits. Callers must add a
// reservation or an authoritative post-write recheck (see upload.handler.js
// _postWriteQuotaReason and the vault upload) to actually bound a storage cap.
function getTotalStorageUsed() {
  var row = db.prepare("SELECT COALESCE(SUM(size), 0) as total FROM files").get();
  return row ? Number(row.total) : 0;
}

module.exports = {
  getDb: function () { return db; },
  snapshotEncryptedDb: snapshotEncryptedDb,
  suppressExitEncrypt: suppressExitEncrypt,
  decryptDbEnc: dbEncCodec.decryptDbEnc,
  getTotalStorageUsed: getTotalStorageUsed,
  rawExec: rawExec,
  rawQuery: rawQuery,
  rawGet: rawGet,
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
  stashMembers: new Collection("stash_members"),
  bundleAccessCodes: new Collection("bundle_access_codes"),
  bundleAccessLog: new Collection("bundle_access_log"),
  bundleAccessLockouts: new Collection("bundle_access_lockouts"),
  certRevocations: new Collection("cert_revocations"),
  enrollmentCodes: new Collection("enrollment_codes"),
};
