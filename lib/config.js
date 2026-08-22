// codebase-patterns:allow-file raw-byte-literal — config layer holds operator default byte-shaped values (file size, port, quota)
// codebase-patterns:allow-file raw-time-literal — config layer holds operator default timeout/port values; ports collide with multiples-of-60
// codebase-patterns:allow-file raw-process-env — config layer IS the canonical env reader (DB > env > default merge)
/**
 * Configuration module.
 *
 * Priority: the sealed settings table, then process.env, then the defaults.
 * There is no .env file; the admin UI writes to the database, and an
 * environment variable overrides what it saved.
 *
 * The framework owns the backing store — the subscriber, the row-to-overlay
 * merge, and the validated snapshot in cfg.value. This module owns the shape
 * operators see, the per-setting coercion, and the save path. A save reaches
 * the exported object through cfg.reload, then cfg.subscribe, then _build.
 */
var b = require("./vendor/blamejs");
var settingsSchema = require("./settings-schema");

// Lazy-load DB to avoid circular dep (config -> db).
var db = b.lazyRequire(function () { return require("./db"); });

var parseList = (str) =>
  str ? str.split(",").map((s) => s.trim().toLowerCase()).filter(Boolean) : [];

// Deliberately permissive: coercion happens in the s/n/bool/bFalse helpers
// below, so this only has to expose the raw strings from env and the DB
// overlay. The schema exists because b.config.create requires one.
var cfg = b.config.create({
  schema: b.safeSchema.record(b.safeSchema.string()),
  env:    process.env,
});

// Tolerates the database not being ready at module load: cfg.value stays at
// the env baseline until a later call populates it.
function _syncHydrateFromDb() {
  var _strip = settingsSchema.stripControls;
  try {
    var rows = db().settings.find({});
    var overlay = {};
    for (var i = 0; i < rows.length; i++) {
      var row = rows[i];
      if (!row || !row.key) continue;
      // An explicitly empty row is the operator clearing a list setting, so it
      // is preserved rather than falling back to env.
      //
      // Already plaintext — the settings repo unseals on read. Unsealing again
      // is a no-op until an operator value happens to start with the "vault:"
      // sentinel, at which point it throws, the catch below discards the whole
      // overlay, and every stored setting silently reverts to its env baseline.
      var plain = row.value || "";
      // row.key is operator-influenced, so a "__proto__"-named row must not be
      // able to re-parent the overlay.
      if (typeof plain === "string") b.safeObject.ownSet(overlay, row.key, _strip(plain).trim());
      else b.safeObject.ownSet(overlay, row.key, plain);
    }
    cfg.reload(overlay);
  } catch (_e) { /* DB not ready yet during initial load — env baseline applies */ }
}

// Derived from settingsMap, which is defined below _build() — hence lazily.
var _envToSchemaKey = null;
function envToSchemaKey(envKey) {
  if (_envToSchemaKey === null) {
    _envToSchemaKey = {};
    if (typeof settingsMap !== "undefined" && settingsMap) {
      for (var k in settingsMap) {
        if (settingsMap[k] && settingsMap[k].env) _envToSchemaKey[settingsMap[k].env] = k;
      }
    }
  }
  return _envToSchemaKey[envKey];
}

// Database overlay, then env, then the default. Strings are trimmed and
// stripped of control characters. A value failing its schema bound — PORT
// above 65535, an unknown timezone — falls back to the default here rather
// than surfacing at listen() time.
function loadSetting(envKey, defaultVal) {
  var _strip = settingsSchema.stripControls;
  // cfg.value already has DB > env precedence baked in via reload().
  var val = cfg.value[envKey];
  if (val === undefined || val === "") return defaultVal;
  var clean = typeof val === "string" ? _strip(val).trim() : val;
  var schemaKey = envToSchemaKey(envKey);
  if (schemaKey && !settingsSchema.validate(schemaKey, String(clean)).valid) return defaultVal;
  return clean;
}

/**
 * Like loadSetting but treats an explicitly-saved empty value as the operator's
 * choice rather than "no setting, use default." Use for list-type settings
 * where empty = "no restrictions" is a valid configured state — clearing the
 * Allowed Extensions list (Allow All) or any list-type setting via the admin
 * UI must persist as empty across restarts.
 *
 * The default vs. empty distinction matters because the operator may want
 * "no value here" as a meaningful state. Check for KEY PRESENCE in cfg.value
 * rather than truthiness of the value.
 */
function loadListSetting(envKey, defaultVal) {
  var _strip = settingsSchema.stripControls;
  if (envKey in cfg.value) {
    var val = cfg.value[envKey];
    return typeof val === "string" ? _strip(val).trim() : val;
  }
  return defaultVal;
}

function s(envKey, def) { return String(loadSetting(envKey, def || "")); }

// Where a module caching a config-dependent resource registers to be told.
var _resetCallbacks = [];
var _lastChangedKeys = [];
function onReset(fn) { _resetCallbacks.push(fn); }
// Strictly positive, because a negative is truthy: `parseInt(...) || def` let a
// stray MAX_FILE_SIZE=-1 through, and the parser downstream then throws on a
// non-positive maxBytes and takes the whole upload surface down with it.
function pnum(raw, def) { var v = parseInt(raw, 10); return v > 0 ? v : def; }
function n(envKey, def) { return pnum(loadSetting(envKey, String(def)), def); }
function bool(envKey, def) { var v = loadSetting(envKey, def ? "true" : "false"); return v !== "false"; }
function bFalse(envKey) { var v = loadSetting(envKey, "false"); return v === "true"; }

_syncHydrateFromDb();

// Re-runs on every cfg.subscribe firing, so the exported object stays current
// after an admin saves.
function _build() {
  // Forwarding forces both audit-capture toggles on: a SIEM receiving a hashed
  // source IP is no use to an investigator, and one switch keeps the stored log
  // and the forwarded stream consistent.
  var siemOn = bool("SIEM_ENABLED", false);
  return {
  port: n("PORT", 3000),
  sessionSecret: s("SESSION_SECRET", "change-me-please"),
  sessionIdleTimeout: n("SESSION_IDLE_TIMEOUT", 1800000), // 30 minutes in ms

  siteName: s("SITE_NAME", "HermitStash"),
  customLogo: s("CUSTOM_LOGO"),
  dropTitle: s("DROP_TITLE", "Drop your files."),
  dropSubtitle: s("DROP_SUBTITLE", "Drag entire folders \u2014 we grab what we can, skip the rest. No login required."),
  landingEnabled: bool("LANDING_ENABLED", true),
  heroTitle: s("HERO_TITLE"),
  heroSubtitle: s("HERO_SUBTITLE"),

  google: {
    clientID: s("GOOGLE_CLIENT_ID"),
    clientSecret: s("GOOGLE_CLIENT_SECRET"),
    callbackURL: s("GOOGLE_CALLBACK_URL"),
  },

  tailscale: {
    // Master opt-in. Nothing about Tailscale activates unless this is true — no
    // LocalAPI probing, no trusted-header parsing, no boot-time sidecar install.
    enabled: bFalse("TAILSCALE_ENABLED"),
    // WhoIs over this socket is the spoof-proof identity source; the
    // Tailscale-User-* headers are a convenience confirmed against it.
    socketPath: s("TAILSCALE_SOCKET", "/run/tailscale/tailscaled.sock"),
    // Signs in an existing account. Creating one is governed below.
    ssoEnabled: bFalse("TAILSCALE_SSO"),
    // An account is created only for a tailnet user carrying the required
    // capability grant, or one on the allowlist. Leaving both empty means SSO
    // signs in existing accounts and provisions nothing.
    ssoRequiredGrant: s("TAILSCALE_SSO_GRANT"),
    ssoAllowlist: parseList(loadListSetting("TAILSCALE_SSO_ALLOWLIST", "")),
    // Derive the WebAuthn RP origin + share-URL base from the node's MagicDNS
    // name when Tailscale is enabled and no explicit RP_ORIGIN is set. Never
    // overrides an operator-set origin.
    hostnameAutoConfig: bool("TAILSCALE_HOSTNAME_AUTOCONFIG", true),
    // "serve" is tailnet-only and injects identity headers; "funnel" is the
    // public internet and injects none; "off" leaves tailscaled to the
    // operator. The container entrypoint acts on it — the app only reports it.
    serveMode: s("TAILSCALE_SERVE_MODE", "off"),
  },

  allowedDomains: parseList(loadListSetting("ALLOWED_DOMAINS", "")),
  adminEmails: parseList(loadListSetting("ADMIN_EMAILS", "")),

  // List-type setting: empty = "allow all" (operator's explicit choice). Must
  // use loadListSetting so a saved empty value isn't replaced by the default.
  allowedExtensions: parseList(
    loadListSetting("ALLOWED_EXTENSIONS",
      ".pdf,.doc,.docx,.xls,.xlsx,.ppt,.pptx,.txt,.csv,.rtf,.png,.jpg,.jpeg,.gif,.svg,.webp,.bmp,.ico,.tiff,.zip,.tar.gz,.7z,.rar,.gz,.bz2")
  ),
  maxFileSize: n("MAX_FILE_SIZE", 104857600),

  localAuth: bool("LOCAL_AUTH", true),
  registrationOpen: bool("REGISTRATION_OPEN", true),

  uploadTimeout: n("UPLOAD_TIMEOUT", 300000),
  uploadConcurrency: n("UPLOAD_CONCURRENCY", 3),
  uploadRetries: n("UPLOAD_RETRIES", 2),
  // 0 = keep audit entries indefinitely (no time-based deletion). A positive
  // value deletes entries older than that many days (chain-safe — see retention).
  auditRetentionDays: n("AUDIT_RETENTION_DAYS", 0),
  // Off stores the source IP as a hash the operator cannot reverse. On stores
  // it sealed and readable — a deliberate privacy reduction, and only for rows
  // written from then on.
  auditIpFull: siemOn || bool("AUDIT_IP_FULL", false),
  // Default OFF: client user-agent (a device/browser fingerprint, PII) is not
  // recorded. ON captures it vault-sealed for investigations. Forced ON while
  // SIEM forwarding is enabled (the SIEM needs the user-agent).
  auditCaptureUserAgent: siemOn || bool("AUDIT_CAPTURE_USER_AGENT", false),
  // Off by default because it turns the audit write from fire-and-forget into
  // a serialized append with a per-row SHA3-512 — a cost to opt into rather
  // than impose. Archival bundles carry chain proof, so enabling archival
  // enables the chain here, where env and the API reach it as well as the UI.
  auditChainEnabled: bool("AUDIT_CHAIN", false) || bool("AUDIT_ARCHIVE", false),
  auditChainStrict: bool("AUDIT_CHAIN_STRICT", false),
  // Past the row threshold, the oldest entries move to an encrypted, signed
  // bundle on disk and the chain is re-anchored. See lib/audit-archive.js.
  auditArchiveEnabled: bool("AUDIT_ARCHIVE", false),
  auditArchiveThresholdRows: n("AUDIT_ARCHIVE_THRESHOLD_ROWS", 50000),
  // Bundle-encryption passphrase (Argon2id → XChaCha20-Poly1305). Sealed in the
  // settings table. Required to archive, verify, or export an archive.
  auditArchivePassphrase: process.env.AUDIT_ARCHIVE_PASSPHRASE || "",
  // Audit-signing key storage. "plaintext" (default, non-interactive — matches the
  // default plaintext vault) writes data/audit-sign.key 0600; "wrapped" seals it
  // under BLAMEJS_AUDIT_SIGNING_PASSPHRASE.
  auditSigningMode: process.env.AUDIT_SIGNING_MODE || "plaintext",
  // Streams every audit event over RFC 5424 syslog or an HTTP webhook. Secret
  // and PII value shapes are redacted before anything leaves the host.
  siemEnabled: siemOn,
  siemProtocol: process.env.SIEM_PROTOCOL || "syslog", // "syslog" | "webhook"
  siemUrl: process.env.SIEM_URL || "",                  // udp|tcp|tls://host:port, or https://...
  siemWebhookAuth: process.env.SIEM_WEBHOOK_AUTH || "none", // none|bearer|basic|header
  siemWebhookToken: process.env.SIEM_WEBHOOK_TOKEN || "",   // bearer token / user:pass / header value
  siemMinLevel: process.env.SIEM_MIN_LEVEL || "info",   // info|warn|error

  emailVerification: bool("EMAIL_VERIFICATION", true),
  passkeyEnabled: bool("PASSKEY_ENABLED", true),
  // Soft enforcement: web-guard destroys a non-mTLS socket at the app layer,
  // with no HTTP response, after the handshake has already completed.
  // ENFORCE_MTLS_STRICT drives the hard, TLS-layer form instead.
  //
  // ENFORCE_MTLS_STRICT=false is the lockout escape hatch, and it is honoured
  // on every rebuild rather than only at boot — otherwise a settings
  // hot-reload re-reads the stored ENFORCE_MTLS=true and re-locks the operator
  // mid-session.
  enforceMtls: process.env.ENFORCE_MTLS_STRICT === "false" ? false : bool("ENFORCE_MTLS", false),
  // Moves an existing ECDSA-P384 sync CA to ML-DSA-87 at boot, where the
  // runtime can verify it. Turn off to keep a classical CA for peers that
  // cannot. See lib/mtls-migrate.js.
  mtlsAutoMigrate: bool("MTLS_AUTO_MIGRATE", true),
  rpName: s("RP_NAME", "HermitStash"),
  rpId: s("RP_ID", "localhost"),
  rpOrigin: s("RP_ORIGIN", "http://localhost:3000"),

  showMaintainerSupport: bFalse("SHOW_MAINTAINER_SUPPORT"),
  maintenanceMode: bFalse("MAINTENANCE_MODE"),
  announcementBanner: s("ANNOUNCEMENT_BANNER"),
  privacyPolicy: s("PRIVACY_POLICY"),
  termsOfService: s("TERMS_OF_SERVICE"),
  cookiePolicy: s("COOKIE_POLICY"),
  analyticsScript: s("ANALYTICS_SCRIPT"),
  analyticsCspDomains: s("ANALYTICS_CSP_DOMAINS"),
  fileExpiryDays: n("FILE_EXPIRY_DAYS", 0),
  storageQuotaBytes: n("STORAGE_QUOTA_BYTES", 0),
  perUserQuotaBytes: n("PER_USER_QUOTA", 0),
  corsOrigins: parseList(loadListSetting("CORS_ORIGINS", "")),
  // Other names the app answers on — a LAN hostname, a tailnet MagicDNS name.
  // Accepted for state-changing requests; rpOrigin alone still generates every
  // share link, email URL and sitemap entry.
  //
  // Deliberately separate from corsOrigins: CORS governs which origins may READ
  // a response, this governs which may CAUSE a state change. Folding them
  // together would widen CSRF acceptance for anyone who set CORS_ORIGINS for
  // an unrelated reason.
  additionalOrigins: parseList(loadListSetting("ADDITIONAL_ORIGINS", "")),

  publicUpload: bool("PUBLIC_UPLOAD", true),
  publicMaxFiles: n("PUBLIC_MAX_FILES", 200),
  publicMaxBundleSize: n("PUBLIC_MAX_BUNDLE_SIZE", 524288000),
  publicIpQuotaBytes: n("PUBLIC_IP_QUOTA_BYTES", 0),

  storage: {
    backend: s("STORAGE_BACKEND", "local"),
    uploadDir: s("UPLOAD_DIR", "./uploads"),
    // Always local disk, whatever the backend: thousands of tiny transient
    // objects suit S3 badly on cost, latency and rate limits. Point it at a
    // tmpfs mount to stage in RAM.
    chunkScratchDir: s("CHUNK_SCRATCH_DIR", null),
    s3: {
      bucket: s("S3_BUCKET"),
      region: s("S3_REGION", "us-east-1"),
      accessKey: s("S3_ACCESS_KEY"),
      secretKey: s("S3_SECRET_KEY"),
      endpoint: s("S3_ENDPOINT"),
    },
  },

  backup: {
    enabled: bFalse("BACKUP_ENABLED"),
    scope: s("BACKUP_SCOPE", "db"),
    schedule: n("BACKUP_SCHEDULE", b.constants.TIME.days(1)),
    // HH:MM (24-hour). When set, daily/weekly schedules anchor to this
    // wall-clock time in `timezone` (below) instead of "now + interval" —
    // survives restarts so backups don't drift across the day.
    timeOfDay: s("BACKUP_TIME_OF_DAY", "03:00"),
    // An IANA name. Defaults to the server timezone, which follows the
    // container's TZ, so setting TZ alone anchors backups correctly. Set this
    // to decouple the two. Falls back to UTC if the server's cannot be read.
    timezone: s("BACKUP_TIMEZONE", (function () {
      try { return Intl.DateTimeFormat().resolvedOptions().timeZone || "UTC"; }
      catch (_e) { return "UTC"; }
    })()),
    retention: n("BACKUP_RETENTION", 7),
    passphrase: s("BACKUP_PASSPHRASE"),
    passphraseHash: s("BACKUP_PASSPHRASE_HASH"),
    s3: {
      bucket: s("BACKUP_S3_BUCKET"),
      region: s("BACKUP_S3_REGION", "us-east-1"),
      accessKey: s("BACKUP_S3_ACCESS_KEY"),
      secretKey: s("BACKUP_S3_SECRET_KEY"),
      endpoint: s("BACKUP_S3_ENDPOINT"),
    },
  },

  email: {
    // Off makes every send a no-op while preserving the credentials, so email
    // can be silenced during an outage and the out-of-band delivery paths —
    // invite, reset and verification URLs shown in the admin UI — exercised.
    enabled: bool("EMAIL_ENABLED", true),
    backend: s("EMAIL_BACKEND", "smtp"),
    host: s("SMTP_HOST"),
    port: n("SMTP_PORT", 587),
    user: s("SMTP_USER"),
    pass: s("SMTP_PASS"),
    from: s("SMTP_FROM", "HermitStash <noreply@hermitstash.com>"),
    resendApiKey: s("RESEND_API_KEY"),
    resendQuotaDaily: n("RESEND_QUOTA_DAILY", 100),
    resendQuotaMonthly: n("RESEND_QUOTA_MONTHLY", 3000),
  },

  emailTemplateMode: s("EMAIL_TEMPLATE_MODE", "text"),
  emailTemplateSubject: s("EMAIL_TEMPLATE_SUBJECT", "Your files have been uploaded to {siteName}"),
  emailTemplateHeader: s("EMAIL_TEMPLATE_HEADER", "Your upload is ready!"),
  emailTemplateFooter: s("EMAIL_TEMPLATE_FOOTER", "Powered by {siteName}"),

  themeAccentColor: s("THEME_ACCENT_COLOR"),
  themeBgColor: s("THEME_BG_COLOR"),
  themeFont: s("THEME_FONT"),

  smtpRejectUnauthorized: bool("SMTP_REJECT_UNAUTHORIZED", true),
  trustProxy: s("TRUST_PROXY"),
  // Empty means no fence, and requireAdmin is the only gate. A non-empty list
  // adds a network-layer fence on top of it.
  adminAllowedCidrs: parseList(loadListSetting("ADMIN_ALLOWED_CIDRS", "")),
  setupComplete: bFalse("SETUP_COMPLETE"),
};}

// Assigned below settingsMap, so the reverse env-to-key map is populated before
// the first build and loadSetting's schema fallback covers boot-time env values
// as well as hot-reloads.
var config;

// On every cfg.reload (admin save), rebuild the operator-facing object in
// place (preserve the module.exports reference) and fan out to the
// HermitStash-side reset callbacks.
cfg.subscribe(function () {
  var fresh = _build();
  // Top-level keys
  for (var k in fresh) config[k] = fresh[k];
  // Nested objects need full replacement so dropped keys don't leak
  config.google  = fresh.google;
  config.tailscale = fresh.tailscale;
  config.storage = fresh.storage;
  config.backup  = fresh.backup;
  config.email   = fresh.email;
  for (var ri = 0; ri < _resetCallbacks.length; ri++) {
    try { _resetCallbacks[ri](_lastChangedKeys); } catch (_e) { /* reset callback failure must not block settings save */ }
  }
});

// Which env var each setting reads, and whether changing it needs a restart.
// That is the whole contract: this map does not decide where a value lands on
// the config object — _build() does, reading it back out of cfg.value.
//
// A new setting needs an entry here, a settings-schema type, a line in
// _build() and a line in getSettings().
var settingsMap = {
  siteName:          { env: "SITE_NAME" },
  customLogo:        { env: "CUSTOM_LOGO" },
  dropTitle:         { env: "DROP_TITLE" },
  dropSubtitle:      { env: "DROP_SUBTITLE" },
  landingEnabled:    { env: "LANDING_ENABLED" },
  heroTitle:         { env: "HERO_TITLE" },
  heroSubtitle:      { env: "HERO_SUBTITLE" },
  showMaintainerSupport: { env: "SHOW_MAINTAINER_SUPPORT" },
  maintenanceMode:   { env: "MAINTENANCE_MODE" },
  announcementBanner:{ env: "ANNOUNCEMENT_BANNER" },
  privacyPolicy:     { env: "PRIVACY_POLICY" },
  termsOfService:    { env: "TERMS_OF_SERVICE" },
  cookiePolicy:      { env: "COOKIE_POLICY" },
  analyticsScript:   { env: "ANALYTICS_SCRIPT" },
  analyticsCspDomains:{ env: "ANALYTICS_CSP_DOMAINS" },
  port:              { env: "PORT", restart: true },
  sessionSecret:     { env: "SESSION_SECRET", restart: true },
  sessionIdleTimeout:{ env: "SESSION_IDLE_TIMEOUT" },
  googleClientID:    { env: "GOOGLE_CLIENT_ID" },
  googleClientSecret:{ env: "GOOGLE_CLIENT_SECRET" },
  googleCallbackURL: { env: "GOOGLE_CALLBACK_URL" },
  // Tailscale. enabled/socket/serveMode/hostnameAutoConfig wire boot-time
  // surfaces (trusted-header middleware, LocalAPI target, RP-origin derivation)
  // → restart. The SSO gate fields are read live per sign-in attempt.
  tailscaleEnabled:  { env: "TAILSCALE_ENABLED", restart: true },
  tailscaleSocket:   { env: "TAILSCALE_SOCKET", restart: true },
  tailscaleSso:      { env: "TAILSCALE_SSO" },
  tailscaleSsoGrant: { env: "TAILSCALE_SSO_GRANT" },
  tailscaleSsoAllowlist: { env: "TAILSCALE_SSO_ALLOWLIST" },
  tailscaleHostnameAutoConfig: { env: "TAILSCALE_HOSTNAME_AUTOCONFIG", restart: true },
  tailscaleServeMode: { env: "TAILSCALE_SERVE_MODE", restart: true },
  allowedDomains:    { env: "ALLOWED_DOMAINS" },
  adminEmails:       { env: "ADMIN_EMAILS" },
  allowedExtensions: { env: "ALLOWED_EXTENSIONS" },
  maxFileSize:       { env: "MAX_FILE_SIZE" },
  uploadTimeout:     { env: "UPLOAD_TIMEOUT" },
  uploadConcurrency: { env: "UPLOAD_CONCURRENCY" },
  uploadRetries:     { env: "UPLOAD_RETRIES" },
  localAuth:         { env: "LOCAL_AUTH" },
  registrationOpen:  { env: "REGISTRATION_OPEN" },
  fileExpiryDays:    { env: "FILE_EXPIRY_DAYS" },
  storageQuotaBytes: { env: "STORAGE_QUOTA_BYTES" },
  perUserQuotaBytes: { env: "PER_USER_QUOTA" },
  corsOrigins:       { env: "CORS_ORIGINS" },
  additionalOrigins: { env: "ADDITIONAL_ORIGINS" },
  publicUpload:      { env: "PUBLIC_UPLOAD" },
  publicMaxFiles:    { env: "PUBLIC_MAX_FILES" },
  publicMaxBundleSize:{ env: "PUBLIC_MAX_BUNDLE_SIZE" },
  publicIpQuotaBytes: { env: "PUBLIC_IP_QUOTA_BYTES" },
  // Audit log. retention takes effect on the next boot (the cleanup interval
  // captures the value at start); the IP / user-agent flags are read live per
  // audit write, so they apply immediately on save.
  auditRetentionDays:    { env: "AUDIT_RETENTION_DAYS", restart: true },
  auditIpFull:           { env: "AUDIT_IP_FULL" },
  auditCaptureUserAgent: { env: "AUDIT_CAPTURE_USER_AGENT" },
  // Enabling archival also turns the tamper chain on so archived bundles carry
  // chain proof; takes effect on the next boot (the chain write-path + scheduler
  // are wired at start).
  auditChainEnabled:          { env: "AUDIT_CHAIN", restart: true },
  auditArchiveEnabled:        { env: "AUDIT_ARCHIVE", restart: true },
  auditArchiveThresholdRows:  { env: "AUDIT_ARCHIVE_THRESHOLD_ROWS" },
  auditArchivePassphrase:     { env: "AUDIT_ARCHIVE_PASSPHRASE" },
  // SIEM forwarding — re-init the log-stream dispatcher on the next boot.
  siemEnabled:      { env: "SIEM_ENABLED", restart: true },
  siemProtocol:     { env: "SIEM_PROTOCOL", restart: true },
  siemUrl:          { env: "SIEM_URL", restart: true },
  siemWebhookAuth:  { env: "SIEM_WEBHOOK_AUTH", restart: true },
  siemWebhookToken: { env: "SIEM_WEBHOOK_TOKEN", restart: true },
  siemMinLevel:     { env: "SIEM_MIN_LEVEL", restart: true },
  storageBackend:    { env: "STORAGE_BACKEND", restart: true },
  uploadDir:         { env: "UPLOAD_DIR", restart: true },
  chunkScratchDir:   { env: "CHUNK_SCRATCH_DIR", restart: true },
  s3Bucket:          { env: "S3_BUCKET" },
  s3Region:          { env: "S3_REGION" },
  s3AccessKey:       { env: "S3_ACCESS_KEY" },
  s3SecretKey:       { env: "S3_SECRET_KEY" },
  s3Endpoint:        { env: "S3_ENDPOINT" },
  backupEnabled:     { env: "BACKUP_ENABLED" },
  backupScope:       { env: "BACKUP_SCOPE" },
  backupSchedule:    { env: "BACKUP_SCHEDULE", restart: true },
  backupTimeOfDay:   { env: "BACKUP_TIME_OF_DAY", restart: true },
  backupTimezone:    { env: "BACKUP_TIMEZONE", restart: true },
  backupRetention:   { env: "BACKUP_RETENTION" },
  backupPassphrase:  { env: "BACKUP_PASSPHRASE" },
  backupPassphraseHash: { env: "BACKUP_PASSPHRASE_HASH" },
  backupS3Bucket:    { env: "BACKUP_S3_BUCKET" },
  backupS3Region:    { env: "BACKUP_S3_REGION" },
  backupS3AccessKey: { env: "BACKUP_S3_ACCESS_KEY" },
  backupS3SecretKey: { env: "BACKUP_S3_SECRET_KEY" },
  backupS3Endpoint:  { env: "BACKUP_S3_ENDPOINT" },
  emailEnabled:      { env: "EMAIL_ENABLED" },
  enforceMtls:       { env: "ENFORCE_MTLS" },
  mtlsAutoMigrate:   { env: "MTLS_AUTO_MIGRATE" },
  emailBackend:      { env: "EMAIL_BACKEND" },
  resendApiKey:      { env: "RESEND_API_KEY" },
  resendQuotaDaily:  { env: "RESEND_QUOTA_DAILY" },
  resendQuotaMonthly:{ env: "RESEND_QUOTA_MONTHLY" },
  smtpHost:          { env: "SMTP_HOST" },
  smtpPort:          { env: "SMTP_PORT" },
  smtpUser:          { env: "SMTP_USER" },
  smtpPass:          { env: "SMTP_PASS" },
  smtpFrom:          { env: "SMTP_FROM" },
  emailTemplateMode: { env: "EMAIL_TEMPLATE_MODE" },
  emailTemplateSubject: { env: "EMAIL_TEMPLATE_SUBJECT" },
  emailTemplateHeader: { env: "EMAIL_TEMPLATE_HEADER" },
  emailTemplateFooter: { env: "EMAIL_TEMPLATE_FOOTER" },
  emailVerification: { env: "EMAIL_VERIFICATION" },
  passkeyEnabled:    { env: "PASSKEY_ENABLED" },
  rpName:            { env: "RP_NAME" },
  rpId:              { env: "RP_ID" },
  rpOrigin:          { env: "RP_ORIGIN" },
  themeAccentColor:  { env: "THEME_ACCENT_COLOR" },
  themeBgColor:      { env: "THEME_BG_COLOR" },
  themeFont:         { env: "THEME_FONT" },
  trustProxy:        { env: "TRUST_PROXY" },
  adminAllowedCidrs: { env: "ADMIN_ALLOWED_CIDRS", restart: true },
  setupComplete:     { env: "SETUP_COMPLETE" },
};

// First build runs here (after settingsMap) so envToSchemaKey is populated and
// loadSetting's schema-bound fallback applies to boot-time env values too.
config = _build();

/**
 * Get current settings as a plain object (masks sensitive values).
 */
function mask(v) { return v ? "\u2022".repeat(Math.min(String(v).length, 20)) : ""; }

function getSettings() {
  return {
    siteName: config.siteName,
    customLogo: config.customLogo,
    dropTitle: config.dropTitle,
    dropSubtitle: config.dropSubtitle,
    landingEnabled: config.landingEnabled,
    heroTitle: config.heroTitle,
    heroSubtitle: config.heroSubtitle,
    showMaintainerSupport: config.showMaintainerSupport,
    maintenanceMode: config.maintenanceMode,
    announcementBanner: config.announcementBanner,
    privacyPolicy: config.privacyPolicy,
    termsOfService: config.termsOfService,
    cookiePolicy: config.cookiePolicy,
    analyticsScript: config.analyticsScript,
    analyticsCspDomains: config.analyticsCspDomains,
    port: config.port,
    sessionSecret: mask(config.sessionSecret),
    sessionIdleTimeout: config.sessionIdleTimeout,
    googleClientID: config.google.clientID,
    googleClientSecret: mask(config.google.clientSecret),
    googleCallbackURL: config.google.callbackURL,
    tailscaleEnabled: config.tailscale.enabled,
    tailscaleSocket: config.tailscale.socketPath,
    tailscaleSso: config.tailscale.ssoEnabled,
    tailscaleSsoGrant: config.tailscale.ssoRequiredGrant,
    tailscaleSsoAllowlist: config.tailscale.ssoAllowlist.join(", "),
    tailscaleHostnameAutoConfig: config.tailscale.hostnameAutoConfig,
    tailscaleServeMode: config.tailscale.serveMode,
    allowedDomains: config.allowedDomains.join(", "),
    adminEmails: config.adminEmails.join(", "),
    allowedExtensions: config.allowedExtensions.join(", "),
    maxFileSize: config.maxFileSize,
    uploadTimeout: config.uploadTimeout,
    uploadConcurrency: config.uploadConcurrency,
    uploadRetries: config.uploadRetries,
    localAuth: config.localAuth,
    registrationOpen: config.registrationOpen,
    fileExpiryDays: config.fileExpiryDays,
    storageQuotaBytes: config.storageQuotaBytes,
    perUserQuotaBytes: config.perUserQuotaBytes,
    corsOrigins: config.corsOrigins.join(", "),
    additionalOrigins: config.additionalOrigins.join(", "),
    publicUpload: config.publicUpload,
    publicMaxFiles: config.publicMaxFiles,
    publicMaxBundleSize: config.publicMaxBundleSize,
    publicIpQuotaBytes: config.publicIpQuotaBytes,
    auditRetentionDays: config.auditRetentionDays,
    auditIpFull: config.auditIpFull,
    auditCaptureUserAgent: config.auditCaptureUserAgent,
    auditChainEnabled: config.auditChainEnabled,
    auditArchiveEnabled: config.auditArchiveEnabled,
    auditArchiveThresholdRows: config.auditArchiveThresholdRows,
    auditArchivePassphrase: mask(config.auditArchivePassphrase),
    siemEnabled: config.siemEnabled,
    siemProtocol: config.siemProtocol,
    siemUrl: config.siemUrl,
    siemWebhookAuth: config.siemWebhookAuth,
    siemWebhookToken: mask(config.siemWebhookToken),
    siemMinLevel: config.siemMinLevel,
    storageBackend: config.storage.backend,
    uploadDir: config.storage.uploadDir,
    chunkScratchDir: config.storage.chunkScratchDir,
    s3Bucket: config.storage.s3.bucket,
    s3Region: config.storage.s3.region,
    s3AccessKey: mask(config.storage.s3.accessKey),
    s3SecretKey: mask(config.storage.s3.secretKey),
    s3Endpoint: config.storage.s3.endpoint,
    backupEnabled: config.backup.enabled,
    backupScope: config.backup.scope,
    backupSchedule: config.backup.schedule,
    backupTimeOfDay: config.backup.timeOfDay,
    backupTimezone: config.backup.timezone,
    serverTimezone: (function () { try { return Intl.DateTimeFormat().resolvedOptions().timeZone || "UTC"; } catch (_e) { return "UTC"; } })(),
    // Full IANA timezone list for the admin UI's searchable dropdown.
    // Intl.supportedValuesOf was added in Node 18 and ships with ~400 zones.
    availableTimezones: (function () { try { return Intl.supportedValuesOf("timeZone"); } catch (_e) { return ["UTC"]; } })(),
    backupRetention: config.backup.retention,
    // Masked like every other sensitive field, so saving an unrelated backup
    // setting does not clobber the stored passphrase with an empty input and
    // silently break scheduled backups.
    backupPassphrase: mask(config.backup.passphrase),
    backupPassphraseHash: config.backup.passphraseHash ? "set" : "",
    backupS3Bucket: config.backup.s3.bucket,
    backupS3Region: config.backup.s3.region,
    backupS3AccessKey: mask(config.backup.s3.accessKey),
    backupS3SecretKey: mask(config.backup.s3.secretKey),
    backupS3Endpoint: config.backup.s3.endpoint,
    enforceMtls: config.enforceMtls,
    emailEnabled: config.email.enabled,
    emailBackend: config.email.backend,
    resendApiKey: mask(config.email.resendApiKey),
    resendQuotaDaily: config.email.resendQuotaDaily,
    resendQuotaMonthly: config.email.resendQuotaMonthly,
    smtpHost: config.email.host,
    smtpPort: config.email.port,
    smtpUser: config.email.user,
    smtpPass: mask(config.email.pass),
    smtpFrom: config.email.from,
    emailTemplateMode: config.emailTemplateMode,
    emailTemplateSubject: config.emailTemplateSubject,
    emailTemplateHeader: config.emailTemplateHeader,
    emailTemplateFooter: config.emailTemplateFooter,
    emailVerification: config.emailVerification,
    passkeyEnabled: config.passkeyEnabled,
    rpName: config.rpName,
    rpId: config.rpId,
    rpOrigin: config.rpOrigin,
    themeAccentColor: config.themeAccentColor,
    themeBgColor: config.themeBgColor,
    themeFont: config.themeFont,
    trustProxy: config.trustProxy,
    adminAllowedCidrs: config.adminAllowedCidrs.join(", "),
  };
}

// Updated only when the submitted value is not itself a mask, and always shown
// as bullets. backupPassphraseHash belongs here despite being an Argon2 PHC
// string rather than the passphrase: exposing it enables an offline attack.
var sensitiveKeys = new Set([
  "sessionSecret", "googleClientSecret", "s3AccessKey", "s3SecretKey", "smtpPass", "resendApiKey",
  "backupS3AccessKey", "backupS3SecretKey", "backupPassphrase", "backupPassphraseHash",
  "auditArchivePassphrase", "siemWebhookToken",
]);

/**
 * Update settings: applies to memory + saves to DB (vault-sealed).
 * Returns { updated: [...keys], restart: boolean }
 */
function updateSettings(changes) {
  var updated = [];
  var needsRestart = false;

  // Safety check: prevent disabling all auth methods
  // Simulate the state after applying changes to check for lockout
  var willLocalAuth = changes.localAuth !== undefined ? String(changes.localAuth) !== "false" : config.localAuth;
  var willPasskey = changes.passkeyEnabled !== undefined ? String(changes.passkeyEnabled) !== "false" : config.passkeyEnabled;
  var willGoogle = changes.googleClientID !== undefined ? !!changes.googleClientID : !!config.google.clientID;
  // Skip masked values — admin didn't change them
  if (changes.googleClientID && /^\u2022+$/.test(changes.googleClientID)) willGoogle = !!config.google.clientID;
  if (!willLocalAuth && !willPasskey && !willGoogle) {
    throw new Error("Cannot disable password authentication — enable passkeys or Google OAuth first so users can still sign in.");
  }

  // Prevent saving S3 storage without credentials
  if (changes.storageBackend === "s3") {
    var hasBucket = changes.s3Bucket || config.storage.s3.bucket;
    var hasAccess = (changes.s3AccessKey && !/^\u2022+$/.test(changes.s3AccessKey)) || config.storage.s3.accessKey;
    var hasSecret = (changes.s3SecretKey && !/^\u2022+$/.test(changes.s3SecretKey)) || config.storage.s3.secretKey;
    if (!hasBucket || !hasAccess || !hasSecret) {
      throw new Error("S3 storage requires bucket, access key, and secret key.");
    }
  }

  // Prevent enabling backups without credentials
  if (String(changes.backupEnabled) === "true") {
    var hasBucket = changes.backupS3Bucket || config.backup.s3.bucket;
    var hasAccess = (changes.backupS3AccessKey && !/^\u2022+$/.test(changes.backupS3AccessKey)) || config.backup.s3.accessKey;
    var hasSecret = (changes.backupS3SecretKey && !/^\u2022+$/.test(changes.backupS3SecretKey)) || config.backup.s3.secretKey;
    if (!hasBucket || !hasAccess || !hasSecret) {
      throw new Error("Backup requires S3 bucket, access key, and secret key.");
    }
  }

  // Prevent storage and backup using the same S3 bucket
  var effectiveStorageBucket = (changes.s3Bucket && !/^\u2022+$/.test(changes.s3Bucket)) ? changes.s3Bucket : config.storage.s3.bucket;
  var effectiveBackupBucket = (changes.backupS3Bucket && !/^\u2022+$/.test(changes.backupS3Bucket)) ? changes.backupS3Bucket : config.backup.s3.bucket;
  if (effectiveStorageBucket && effectiveBackupBucket && effectiveStorageBucket.trim() === effectiveBackupBucket.trim()) {
    var effectiveStorageEndpoint = (changes.s3Endpoint || config.storage.s3.endpoint || "").trim();
    var effectiveBackupEndpoint = (changes.backupS3Endpoint || config.backup.s3.endpoint || "").trim();
    if (effectiveStorageEndpoint === effectiveBackupEndpoint) {
      throw new Error("Storage and backup cannot use the same S3 bucket. Backups overwriting upload data would cause data loss.");
    }
  }

  for (var [key, value] of Object.entries(changes)) {
    // Own-property lookup: a key naming an inherited Object.prototype member
    // ("toString", "hasOwnProperty", "valueOf", ...) would resolve settingsMap[key]
    // to a truthy inherited function and slip past the unknown-key gate.
    var mapping = b.safeObject.ownProp(settingsMap, key) || null;
    if (!mapping) continue;

    // Skip masked values for sensitive fields
    if (sensitiveKeys.has(key) && /^\u2022+$/.test(value)) continue;

    // Sanitize via settings-schema (trim, strip controls, type-specific normalization)
    var cleaned = settingsSchema.sanitize(key, value);

    // Save to DB (vault-sealed). The in-memory config object refreshes
    // via cfg.subscribe → _build() after _syncHydrateFromDb() below.
    var envKey = mapping.env;
    var existing = db().settings.findOne({ key: envKey });
    if (existing) {
      db().settings.update({ key: envKey }, { $set: { value: cleaned, updatedAt: new Date().toISOString() } });
    } else {
      db().settings.insert({ _id: envKey, key: envKey, value: cleaned, updatedAt: new Date().toISOString() });
    }

    updated.push(key);
    if (mapping.restart) needsRestart = true;
  }

  // Refresh cfg.value from DB → fires cfg.subscribe → _build() rebuilds
  // config in place → _resetCallbacks fire with the updated key list.
  if (updated.length > 0) {
    _lastChangedKeys = updated;
    _syncHydrateFromDb();
  }

  // Warn about users who will be locked out when disabling localAuth
  var warnings = [];
  if (updated.includes("localAuth") && !config.localAuth) {
    try {
      var allUsers = db().users.find({}).filter(function (u) { return u.authType === "local"; });
      var creds = db().credentials;
      var lockedOut = allUsers.filter(function (u) {
        var hasPasskey = creds.count({ userId: u._id }) > 0;
        var hasGoogle = !!u.googleId;
        return !hasPasskey && !hasGoogle;
      });
      if (lockedOut.length > 0) {
        warnings.push(lockedOut.length + " user(s) with password-only accounts will be locked out until they add a passkey or Google account: " + lockedOut.map(function (u) { return u.email; }).join(", "));
      }
    } catch (_e) { /* ignore during startup */ }
  }

  return { updated, restart: needsRestart, warnings: warnings };
}

/**
 * Get environment/runtime info for admin panel.
 * Shows which settings come from env vars vs DB vs defaults,
 * plus Docker and Node.js runtime details.
 */
function getEnvironment() {
  var isDocker = require("node:fs").existsSync("/.dockerenv");
  var envOverrides = [];
  for (var key in settingsMap) {
    var envKey = settingsMap[key].env;
    if (process.env[envKey] !== undefined && process.env[envKey] !== "") {
      var isSensitive = sensitiveKeys.has(key);
      envOverrides.push({
        setting: key,
        env: envKey,
        value: isSensitive ? mask(process.env[envKey]) : process.env[envKey],
        restart: !!settingsMap[key].restart,
      });
    }
  }
  // Vault passphrase protection status — show the MODE (operator needs to
  // know if it's active), but NEVER show the passphrase itself. VAULT_PASSPHRASE
  // and VAULT_PASSPHRASE_FILE are boot-time secrets not surfaced here.
  var vaultPassphraseMode = (process.env.VAULT_PASSPHRASE_MODE || "disabled").toLowerCase();
  return {
    docker: isDocker,
    node: process.version,
    openssl: process.versions.openssl,
    platform: process.platform,
    arch: process.arch,
    pid: process.pid,
    uptime: Math.floor(process.uptime()),
    tmpdir: process.env.HERMITSTASH_TMPDIR || "(not set — using data/)",
    nodeEnv: process.env.NODE_ENV || "development",
    vaultPassphraseMode: vaultPassphraseMode,
    envOverrides: envOverrides,
  };
}

/**
 * Validate every env var that's set in process.env against its settings-schema
 * type. Returns an array of warning strings for invalid values. Used by
 * startup-checks to surface bad input loudly at boot — previously these
 * silently fell back to defaults via parseInt-or-default patterns.
 */
function validateEnvVars() {
  var warnings = [];
  for (var key in settingsMap) {
    var envKey = settingsMap[key].env;
    if (!envKey) continue;
    var raw = process.env[envKey];
    if (raw === undefined || raw === "") continue;
    var result = settingsSchema.validate(key, String(raw).trim());
    if (!result.valid) {
      warnings.push(envKey + "='" + raw + "' is invalid: " + result.error + ". Using default.");
    }
  }
  return warnings;
}

module.exports = config;
module.exports.getSettings = getSettings;
module.exports.updateSettings = updateSettings;
module.exports.getEnvironment = getEnvironment;
module.exports.onReset = onReset;
module.exports.validateEnvVars = validateEnvVars;
