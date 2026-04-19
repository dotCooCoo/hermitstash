/**
 * Configuration module.
 *
 * Priority: DB settings table (vault-sealed) > process.env > defaults.
 * No .env file needed — just `npm install && node server.js`.
 * Admin UI saves to DB; process.env overrides for Docker/containers.
 */
var vault = require("./vault");

// Lazy-load DB to avoid circular dep (vault -> config -> db)
var _db = null;
function db() {
  if (!_db) _db = require("./db");
  return _db;
}

var parseList = (str) =>
  str ? str.split(",").map((s) => s.trim().toLowerCase()).filter(Boolean) : [];

// Load a setting: DB first, then process.env, then default.
// All string values are sanitized (trim + strip control chars) to prevent whitespace/injection bugs.
function loadSetting(envKey, defaultVal) {
  var _strip = require("./settings-schema").stripControls;
  // Check DB
  try {
    var row = db().settings.findOne({ key: envKey });
    if (row && row.value) {
      var val = vault.unseal(row.value);
      return typeof val === "string" ? _strip(val).trim() : val;
    }
  } catch (_e) { /* DB not ready yet during initial load */ }
  // Check process.env
  if (process.env[envKey] !== undefined && process.env[envKey] !== "") {
    return _strip(process.env[envKey]).trim();
  }
  return defaultVal;
}

/**
 * Like loadSetting but treats an explicitly-saved empty value as the operator's
 * choice rather than "no setting, use default." Use for list-type settings
 * where empty = "no restrictions" is a valid configured state — clearing the
 * Allowed Extensions list (Allow All) or any list-type setting via the admin
 * UI must persist as empty across restarts.
 *
 * The default vs. empty distinction matters because vault.seal("") returns ""
 * unchanged (line 57: `if (!plaintext) return plaintext`), so the DB row has
 * value="" — falsy by the standard truthiness check, indistinguishable from
 * "row not yet saved." This helper instead checks for row existence directly.
 */
function loadListSetting(envKey, defaultVal) {
  var _strip = require("./settings-schema").stripControls;
  try {
    var row = db().settings.findOne({ key: envKey });
    if (row) {
      // Row exists — operator has saved this setting (possibly to ""). Respect it.
      var val = row.value ? vault.unseal(row.value) : "";
      return typeof val === "string" ? _strip(val).trim() : val;
    }
  } catch (_e) { /* DB not ready yet during initial load */ }
  if (process.env[envKey] !== undefined) {
    return _strip(process.env[envKey] || "").trim();
  }
  return defaultVal;
}

function s(envKey, def) { return String(loadSetting(envKey, def || "")); }

// ---- Config reset registry ----
// Modules that cache config-dependent resources register here.
// Called after updateSettings applies changes, with the list of changed setting keys.
var _resetCallbacks = [];
function onReset(fn) { _resetCallbacks.push(fn); }
function n(envKey, def) { return parseInt(loadSetting(envKey, String(def)), 10) || def; }
function b(envKey, def) { var v = loadSetting(envKey, def ? "true" : "false"); return v !== "false"; }
function bFalse(envKey) { var v = loadSetting(envKey, "false"); return v === "true"; }

var config = {
  port: n("PORT", 3000),
  sessionSecret: s("SESSION_SECRET", "change-me-please"),
  sessionIdleTimeout: n("SESSION_IDLE_TIMEOUT", 1800000), // 30 minutes in ms

  // Branding
  siteName: s("SITE_NAME", "HermitStash"),
  customLogo: s("CUSTOM_LOGO"),
  dropTitle: s("DROP_TITLE", "Drop your files."),
  dropSubtitle: s("DROP_SUBTITLE", "Drag entire folders \u2014 we grab what we can, skip the rest. No login required."),
  landingEnabled: b("LANDING_ENABLED", true),
  heroTitle: s("HERO_TITLE"),
  heroSubtitle: s("HERO_SUBTITLE"),

  google: {
    clientID: s("GOOGLE_CLIENT_ID"),
    clientSecret: s("GOOGLE_CLIENT_SECRET"),
    callbackURL: s("GOOGLE_CALLBACK_URL"),
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

  localAuth: b("LOCAL_AUTH", true),
  registrationOpen: b("REGISTRATION_OPEN", true),

  uploadTimeout: n("UPLOAD_TIMEOUT", 300000),
  uploadConcurrency: n("UPLOAD_CONCURRENCY", 3),
  uploadRetries: n("UPLOAD_RETRIES", 2),
  auditRetentionDays: n("AUDIT_RETENTION_DAYS", 0),

  emailVerification: b("EMAIL_VERIFICATION", true),
  passkeyEnabled: b("PASSKEY_ENABLED", true),
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
  healthCorsOrigins: parseList(loadListSetting("HEALTH_CORS_ORIGINS", "")),

  fileExpiryDays: n("FILE_EXPIRY_DAYS", 0),
  storageQuotaBytes: n("STORAGE_QUOTA_BYTES", 0),
  perUserQuotaBytes: n("PER_USER_QUOTA", 0),
  corsOrigins: parseList(loadListSetting("CORS_ORIGINS", "")),

  publicUpload: b("PUBLIC_UPLOAD", true),
  publicMaxFiles: n("PUBLIC_MAX_FILES", 200),
  publicMaxBundleSize: n("PUBLIC_MAX_BUNDLE_SIZE", 524288000),
  publicIpQuotaBytes: n("PUBLIC_IP_QUOTA_BYTES", 0),

  storage: {
    backend: s("STORAGE_BACKEND", "local"),
    uploadDir: s("UPLOAD_DIR", "./uploads"),
    // Scratch space for chunked-upload staging. Always local-disk regardless of
    // backend (S3 is unsuitable for thousands of tiny transient objects — cost,
    // latency, rate limits). Defaults to <uploadDir>/chunks. Point at a tmpfs
    // mount (e.g. /dev/shm/hermitstash-chunks) for RAM-backed staging.
    chunkScratchDir: s("CHUNK_SCRATCH_DIR", null),
    s3DirectDownloads: bFalse("S3_DIRECT_DOWNLOADS"),
    s3PresignExpiry: n("S3_PRESIGN_EXPIRY", 604800),
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
    schedule: n("BACKUP_SCHEDULE", 86400000),
    // HH:MM (24-hour). When set, daily/weekly schedules anchor to this
    // wall-clock time in `timezone` (below) instead of "now + interval" —
    // survives restarts so backups don't drift across the day.
    timeOfDay: s("BACKUP_TIME_OF_DAY", "03:00"),
    // IANA timezone name (e.g. "America/New_York", "Europe/London"). Defaults
    // to the resolved server timezone (which itself follows the Docker TZ env
    // var via /etc/localtime) so a deployment with TZ=America/New_York gets
    // backups anchored to Eastern time without extra config. Operator can
    // override explicitly to decouple from the server TZ. Falls back to UTC
    // if the resolved server TZ can't be determined.
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

  smtpRejectUnauthorized: b("SMTP_REJECT_UNAUTHORIZED", true),
  trustProxy: s("TRUST_PROXY"),
  setupComplete: bFalse("SETUP_COMPLETE"),
};

// Map of setting keys to env var names and how to apply them
var settingsMap = {
  siteName:          { env: "SITE_NAME",             apply: (v) => { config.siteName = v; } },
  customLogo:        { env: "CUSTOM_LOGO",           apply: (v) => { config.customLogo = v; } },
  dropTitle:         { env: "DROP_TITLE",            apply: (v) => { config.dropTitle = v; } },
  dropSubtitle:      { env: "DROP_SUBTITLE",         apply: (v) => { config.dropSubtitle = v; } },
  landingEnabled:    { env: "LANDING_ENABLED",       apply: (v) => { config.landingEnabled = v !== "false"; } },
  heroTitle:         { env: "HERO_TITLE",            apply: (v) => { config.heroTitle = v; } },
  heroSubtitle:      { env: "HERO_SUBTITLE",         apply: (v) => { config.heroSubtitle = v; } },
  showMaintainerSupport: { env: "SHOW_MAINTAINER_SUPPORT", apply: (v) => { config.showMaintainerSupport = v === "true"; } },
  maintenanceMode:   { env: "MAINTENANCE_MODE",      apply: (v) => { config.maintenanceMode = v === "true"; } },
  announcementBanner:{ env: "ANNOUNCEMENT_BANNER",   apply: (v) => { config.announcementBanner = v; } },
  privacyPolicy:     { env: "PRIVACY_POLICY",        apply: (v) => { config.privacyPolicy = v; } },
  termsOfService:    { env: "TERMS_OF_SERVICE",       apply: (v) => { config.termsOfService = v; } },
  cookiePolicy:      { env: "COOKIE_POLICY",          apply: (v) => { config.cookiePolicy = v; } },
  analyticsScript:   { env: "ANALYTICS_SCRIPT",       apply: (v) => { config.analyticsScript = v; } },
  analyticsCspDomains:{ env: "ANALYTICS_CSP_DOMAINS", apply: (v) => { config.analyticsCspDomains = v; } },
  healthCorsOrigins:  { env: "HEALTH_CORS_ORIGINS",   apply: (v) => { config.healthCorsOrigins = parseList(v); } },
  port:              { env: "PORT",                  apply: (v) => { config.port = parseInt(v, 10) || 3000; }, restart: true },
  sessionSecret:     { env: "SESSION_SECRET",        apply: (v) => { config.sessionSecret = v; }, restart: true },
  sessionIdleTimeout:{ env: "SESSION_IDLE_TIMEOUT",  apply: (v) => { config.sessionIdleTimeout = Math.max(parseInt(v, 10) || 1800000, 60000); } },
  googleClientID:    { env: "GOOGLE_CLIENT_ID",      apply: (v) => { config.google.clientID = v; } },
  googleClientSecret:{ env: "GOOGLE_CLIENT_SECRET",  apply: (v) => { config.google.clientSecret = v; } },
  googleCallbackURL: { env: "GOOGLE_CALLBACK_URL",   apply: (v) => { config.google.callbackURL = v; } },
  allowedDomains:    { env: "ALLOWED_DOMAINS",       apply: (v) => { config.allowedDomains = parseList(v); } },
  adminEmails:       { env: "ADMIN_EMAILS",          apply: (v) => { config.adminEmails = parseList(v); } },
  allowedExtensions: { env: "ALLOWED_EXTENSIONS",    apply: (v) => { config.allowedExtensions = parseList(v); } },
  maxFileSize:       { env: "MAX_FILE_SIZE",         apply: (v) => { config.maxFileSize = parseInt(v, 10) || 104857600; } },
  uploadTimeout:     { env: "UPLOAD_TIMEOUT",        apply: (v) => { config.uploadTimeout = parseInt(v, 10) || 300000; } },
  uploadConcurrency: { env: "UPLOAD_CONCURRENCY",    apply: (v) => { config.uploadConcurrency = parseInt(v, 10) || 3; } },
  uploadRetries:     { env: "UPLOAD_RETRIES",         apply: (v) => { config.uploadRetries = parseInt(v, 10) || 2; } },
  localAuth:         { env: "LOCAL_AUTH",             apply: (v) => { config.localAuth = v !== "false"; } },
  registrationOpen:  { env: "REGISTRATION_OPEN",     apply: (v) => { config.registrationOpen = v !== "false"; } },
  fileExpiryDays:    { env: "FILE_EXPIRY_DAYS",       apply: (v) => { config.fileExpiryDays = parseInt(v, 10) || 0; } },
  storageQuotaBytes: { env: "STORAGE_QUOTA_BYTES",    apply: (v) => { config.storageQuotaBytes = parseInt(v, 10) || 0; } },
  perUserQuotaBytes: { env: "PER_USER_QUOTA",         apply: (v) => { config.perUserQuotaBytes = parseInt(v, 10) || 0; } },
  corsOrigins:       { env: "CORS_ORIGINS",           apply: (v) => { config.corsOrigins = parseList(v); } },
  publicUpload:      { env: "PUBLIC_UPLOAD",          apply: (v) => { config.publicUpload = v !== "false"; } },
  publicMaxFiles:    { env: "PUBLIC_MAX_FILES",       apply: (v) => { config.publicMaxFiles = parseInt(v, 10) || 200; } },
  publicMaxBundleSize:{ env: "PUBLIC_MAX_BUNDLE_SIZE",apply: (v) => { config.publicMaxBundleSize = parseInt(v, 10) || 524288000; } },
  publicIpQuotaBytes: { env: "PUBLIC_IP_QUOTA_BYTES",  apply: (v) => { config.publicIpQuotaBytes = parseInt(v, 10) || 0; } },
  storageBackend:    { env: "STORAGE_BACKEND",        apply: (v) => { config.storage.backend = v; }, restart: true },
  uploadDir:         { env: "UPLOAD_DIR",             apply: (v) => { config.storage.uploadDir = v; }, restart: true },
  chunkScratchDir:   { env: "CHUNK_SCRATCH_DIR",       apply: (v) => { config.storage.chunkScratchDir = v || null; }, restart: true },
  s3Bucket:          { env: "S3_BUCKET",              apply: (v) => { config.storage.s3.bucket = v; } },
  s3Region:          { env: "S3_REGION",              apply: (v) => { config.storage.s3.region = v; } },
  s3AccessKey:       { env: "S3_ACCESS_KEY",          apply: (v) => { config.storage.s3.accessKey = v; } },
  s3SecretKey:       { env: "S3_SECRET_KEY",          apply: (v) => { config.storage.s3.secretKey = v; } },
  s3Endpoint:        { env: "S3_ENDPOINT",            apply: (v) => { config.storage.s3.endpoint = v; } },
  s3DirectDownloads: { env: "S3_DIRECT_DOWNLOADS",   apply: (v) => { config.storage.s3DirectDownloads = v === "true"; } },
  s3PresignExpiry:   { env: "S3_PRESIGN_EXPIRY",     apply: (v) => { config.storage.s3PresignExpiry = parseInt(v, 10) || 3600; } },
  backupEnabled:     { env: "BACKUP_ENABLED",          apply: (v) => { config.backup.enabled = v === "true"; } },
  backupScope:       { env: "BACKUP_SCOPE",            apply: (v) => { config.backup.scope = v; } },
  backupSchedule:    { env: "BACKUP_SCHEDULE",          apply: (v) => { config.backup.schedule = parseInt(v, 10) || 86400000; }, restart: true },
  backupTimeOfDay:   { env: "BACKUP_TIME_OF_DAY",       apply: (v) => { config.backup.timeOfDay = v || "03:00"; }, restart: true },
  backupTimezone:    { env: "BACKUP_TIMEZONE",          apply: (v) => { config.backup.timezone = v || "UTC"; }, restart: true },
  backupRetention:   { env: "BACKUP_RETENTION",         apply: (v) => { config.backup.retention = parseInt(v, 10) || 7; } },
  backupPassphrase:  { env: "BACKUP_PASSPHRASE",        apply: (v) => { config.backup.passphrase = v; } },
  backupPassphraseHash: { env: "BACKUP_PASSPHRASE_HASH", apply: (v) => { config.backup.passphraseHash = v; } },
  backupS3Bucket:    { env: "BACKUP_S3_BUCKET",         apply: (v) => { config.backup.s3.bucket = v; } },
  backupS3Region:    { env: "BACKUP_S3_REGION",         apply: (v) => { config.backup.s3.region = v; } },
  backupS3AccessKey: { env: "BACKUP_S3_ACCESS_KEY",     apply: (v) => { config.backup.s3.accessKey = v; } },
  backupS3SecretKey: { env: "BACKUP_S3_SECRET_KEY",     apply: (v) => { config.backup.s3.secretKey = v; } },
  backupS3Endpoint:  { env: "BACKUP_S3_ENDPOINT",       apply: (v) => { config.backup.s3.endpoint = v; } },
  emailBackend:      { env: "EMAIL_BACKEND",          apply: (v) => { config.email.backend = v; } },
  resendApiKey:      { env: "RESEND_API_KEY",         apply: (v) => { config.email.resendApiKey = v; } },
  resendQuotaDaily:  { env: "RESEND_QUOTA_DAILY",     apply: (v) => { config.email.resendQuotaDaily = parseInt(v, 10) || 100; } },
  resendQuotaMonthly:{ env: "RESEND_QUOTA_MONTHLY",   apply: (v) => { config.email.resendQuotaMonthly = parseInt(v, 10) || 3000; } },
  smtpHost:          { env: "SMTP_HOST",              apply: (v) => { config.email.host = v; } },
  smtpPort:          { env: "SMTP_PORT",              apply: (v) => { config.email.port = parseInt(v, 10) || 587; } },
  smtpUser:          { env: "SMTP_USER",              apply: (v) => { config.email.user = v; } },
  smtpPass:          { env: "SMTP_PASS",              apply: (v) => { config.email.pass = v; } },
  smtpFrom:          { env: "SMTP_FROM",              apply: (v) => { config.email.from = v; } },
  emailTemplateMode: { env: "EMAIL_TEMPLATE_MODE", apply: (v) => { config.emailTemplateMode = v; } },
  emailTemplateSubject: { env: "EMAIL_TEMPLATE_SUBJECT", apply: (v) => { config.emailTemplateSubject = v; } },
  emailTemplateHeader: { env: "EMAIL_TEMPLATE_HEADER", apply: (v) => { config.emailTemplateHeader = v; } },
  emailTemplateFooter: { env: "EMAIL_TEMPLATE_FOOTER", apply: (v) => { config.emailTemplateFooter = v; } },
  emailVerification: { env: "EMAIL_VERIFICATION",    apply: (v) => { config.emailVerification = v !== "false"; } },
  passkeyEnabled:    { env: "PASSKEY_ENABLED",       apply: (v) => { config.passkeyEnabled = v !== "false"; } },
  rpName:            { env: "RP_NAME",               apply: (v) => { config.rpName = v; } },
  rpId:              { env: "RP_ID",                 apply: (v) => { config.rpId = v; } },
  rpOrigin:          { env: "RP_ORIGIN",             apply: (v) => { config.rpOrigin = v; } },
  themeAccentColor:  { env: "THEME_ACCENT_COLOR",    apply: (v) => { config.themeAccentColor = v; } },
  themeBgColor:      { env: "THEME_BG_COLOR",        apply: (v) => { config.themeBgColor = v; } },
  themeFont:         { env: "THEME_FONT",            apply: (v) => { config.themeFont = v; } },
  trustProxy:        { env: "TRUST_PROXY",           apply: (v) => { config.trustProxy = v; } },
  setupComplete:     { env: "SETUP_COMPLETE",        apply: (v) => { config.setupComplete = v === "true"; } },
};

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
    healthCorsOrigins: config.healthCorsOrigins.join(", "),
    port: config.port,
    sessionSecret: mask(config.sessionSecret),
    sessionIdleTimeout: config.sessionIdleTimeout,
    googleClientID: config.google.clientID,
    googleClientSecret: mask(config.google.clientSecret),
    googleCallbackURL: config.google.callbackURL,
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
    publicUpload: config.publicUpload,
    publicMaxFiles: config.publicMaxFiles,
    publicMaxBundleSize: config.publicMaxBundleSize,
    publicIpQuotaBytes: config.publicIpQuotaBytes,
    storageBackend: config.storage.backend,
    uploadDir: config.storage.uploadDir,
    chunkScratchDir: config.storage.chunkScratchDir,
    s3Bucket: config.storage.s3.bucket,
    s3Region: config.storage.s3.region,
    s3AccessKey: mask(config.storage.s3.accessKey),
    s3SecretKey: mask(config.storage.s3.secretKey),
    s3Endpoint: config.storage.s3.endpoint,
    s3DirectDownloads: config.storage.s3DirectDownloads,
    s3PresignExpiry: config.storage.s3PresignExpiry,
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
    backupPassphraseHash: config.backup.passphraseHash ? "set" : "",
    backupS3Bucket: config.backup.s3.bucket,
    backupS3Region: config.backup.s3.region,
    backupS3AccessKey: mask(config.backup.s3.accessKey),
    backupS3SecretKey: mask(config.backup.s3.secretKey),
    backupS3Endpoint: config.backup.s3.endpoint,
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
  };
}

// Sensitive keys — only update if value doesn't look like a mask
var sensitiveKeys = new Set([
  "sessionSecret", "googleClientSecret", "s3AccessKey", "s3SecretKey", "smtpPass", "resendApiKey",
  "backupS3AccessKey", "backupS3SecretKey", "backupPassphrase",
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

  var settingsSchema = require("./settings-schema");

  for (var [key, value] of Object.entries(changes)) {
    var mapping = settingsMap[key];
    if (!mapping) continue;

    // Skip masked values for sensitive fields
    if (sensitiveKeys.has(key) && /^\u2022+$/.test(value)) continue;

    // Sanitize via settings-schema (trim, strip controls, type-specific normalization)
    var cleaned = settingsSchema.sanitize(key, value);

    // Apply to memory (plaintext)
    mapping.apply(cleaned);

    // Save to DB (vault-sealed)
    var envKey = mapping.env;
    var sealed = vault.seal(cleaned);
    var existing = db().settings.findOne({ key: envKey });
    if (existing) {
      db().settings.update({ key: envKey }, { $set: { value: sealed, updatedAt: new Date().toISOString() } });
    } else {
      db().settings.insert({ _id: envKey, key: envKey, value: sealed, updatedAt: new Date().toISOString() });
    }

    updated.push(key);
    if (mapping.restart) needsRestart = true;
  }

  // Notify cached-client modules so they can invalidate stale instances
  if (updated.length > 0) {
    for (var ri = 0; ri < _resetCallbacks.length; ri++) {
      try { _resetCallbacks[ri](updated); } catch (_e) {}
    }
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
  var isDocker = require("fs").existsSync("/.dockerenv");
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
  var settingsSchema = require("./settings-schema");
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
