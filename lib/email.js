// codebase-patterns:allow-file raw-byte-literal — HTML template literal byte sizes (font-size, padding), inline HTML pixel values
/**
 * Email sending module — supports SMTP and Resend API.
 * Backend selected via config.email.backend ("smtp" or "resend").
 * Resend API has configurable daily/monthly quota enforcement.
 * All sends are tracked in email_sends table and audit-logged.
 *
 * SMTP + Resend transports delegate to b.mail.transports.smtp /
 * b.mail.transports.resend (v0.9.20+). Pre-this-swap HS hand-rolled
 * a 75-line SMTP state machine (EHLO / STARTTLS / AUTH LOGIN / MAIL
 * FROM / RCPT TO / DATA / QUIT) and a manual httpClient POST for
 * Resend. The framework primitives carry RFC 5321 §4.5.3.1 line
 * caps, RFC 3030 BDAT chunking with peer-advertised size honoring,
 * RFC 1870 SIZE precheck, EAI / SMTPUTF8 (RFC 6531) + IDN Punycode
 * (RFC 3492), TLS 1.3-minimum + ecdhCurve composition (HS still
 * pins TLS_GROUP_CURVE_STR via the opt) — all worth more than the
 * mostly-duplicated bytes the hand-rolled state machine produced.
 */
var b = require("./vendor/blamejs");
var C = require("./constants");
var config = require("./config");
var logger = require("../app/shared/logger");
var { formatSize } = require("./template");

// ---- Pre-built mailers per configured backend ----
//
// Rebuilt on config.onReset (admin UI edits to SMTP host / port / creds
// or to RESEND_API_KEY trigger the rebuild without a restart). Either
// mailer is null when its backend is unconfigured; trySend()'s
// short-circuit returns { success: false, reason: "not configured" }.
var smtpMailer = null;
var resendMailer = null;

function buildMailers() {
  smtpMailer = config.email.host ? b.mail.create({
    transport: b.mail.transports.smtp({
      host:               config.email.host,
      port:               config.email.port,
      user:               config.email.user || undefined,
      pass:               config.email.pass || undefined,
      rejectUnauthorized: config.smtpRejectUnauthorized !== false,
      ehloName:           "hermitstash",
      ecdhCurve:          b.constants.TLS_GROUP_CURVE_STR,
      timeoutMs:          C.TIME.seconds(15),
    }),
    defaults: { from: config.email.from },
  }) : null;

  resendMailer = config.email.resendApiKey ? b.mail.create({
    transport: b.mail.transports.resend({ apiKey: config.email.resendApiKey }),
    defaults: { from: config.email.from },
  }) : null;
}

buildMailers();
config.onReset(function () { buildMailers(); });

// Lazy-load to avoid circular deps during startup
// (email → config → db → audit → email on send-failure paths).
var db = b.lazyRequire(function () { return require("./db"); });
var audit = b.lazyRequire(function () { return require("./audit"); });

// ---- Quota enforcement ----

// A reservation ("pending") row counts toward the quota the instant it is
// written, BEFORE the network send resolves, so concurrent in-flight sends see
// each other and the cap holds (see trySend/finalizeReservation). A row left
// "pending" longer than this (process crash between reserve and confirm) is
// reclaimed so it can't permanently consume quota.
var PENDING_RESERVATION_TTL = C.TIME.minutes(10);

// Drop stale "pending" reservations whose send neither confirmed nor failed —
// only a crash between reserve and finalize leaves these. Runs lazily on every
// quota read so an abandoned reservation is reclaimed within one TTL window.
function reclaimStalePending() {
  var sends = db().emailSends;
  var cutoff = new Date(Date.now() - PENDING_RESERVATION_TTL).toISOString();
  sends.find({ status: "pending" }).forEach(function (s) {
    if (s.createdAt < cutoff) { try { sends.remove({ _id: s._id }); } catch (_e) { /* best-effort reclaim */ } }
  });
}

function getQuotaCounts() {
  reclaimStalePending();
  var sends = db().emailSends;
  var now = new Date();
  // Compute the day/month boundaries in UTC to match the UTC ISO createdAt
  // timestamps. Using the local-timezone constructor shifted the window by the
  // host's UTC offset, so the daily/monthly quota counted the wrong set of sends
  // (and reset at local — not UTC — midnight).
  var todayStart = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate())).toISOString();
  var monthStart = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), 1)).toISOString();

  // Count "sent" AND "pending" rows toward the cap. A read-check-then-send with
  // no reservation let K concurrent sends each read the same pre-send count and
  // all proceed, overrunning the cap by K-1. The pending reservation is written
  // synchronously before the await, so a concurrent send observes it here.
  function counted(s) { return s.status === "sent" || s.status === "pending"; }
  var dailySends = sends.find({}).filter(function (s) { return counted(s) && s.createdAt >= todayStart; }).length;
  var monthlySends = sends.find({}).filter(function (s) { return counted(s) && s.createdAt >= monthStart; }).length;

  return { daily: dailySends, monthly: monthlySends };
}

// Does the configured backend mode route any mail through Resend? Covers the
// single "resend" mode and both combo modes ("smtp+resend", "resend+smtp") so
// the daily/monthly cap is enforced whenever Resend is actually attempted — the
// strict `=== "resend"` test silently bypassed the quota in combo modes.
function resendInChain() {
  var mode = (config.email && config.email.backend) || "";
  return mode.split("+").indexOf("resend") !== -1;
}

// opts.backend, when given, is the CONCRETE backend trySend is about to attempt
// ("resend"/"smtp"). The quota only applies to a Resend attempt. When called
// with no backend (the exported admin-widget path), apply it whenever the mode
// chain includes resend, so the widget reports real numbers in combo modes.
function checkQuota(opts) {
  var applies = opts && opts.backend ? opts.backend === "resend" : resendInChain();
  if (!applies) return { allowed: true };
  var counts = getQuotaCounts();
  if (counts.daily >= config.email.resendQuotaDaily) {
    return { allowed: false, reason: "Daily quota exceeded (" + counts.daily + "/" + config.email.resendQuotaDaily + ")" };
  }
  if (counts.monthly >= config.email.resendQuotaMonthly) {
    return { allowed: false, reason: "Monthly quota exceeded (" + counts.monthly + "/" + config.email.resendQuotaMonthly + ")" };
  }
  return { allowed: true, daily: counts.daily, monthly: counts.monthly };
}

function trackSend(to, subject, backend, status) {
  try {
    var row = db().emailSends.insert({
      // recipient is a sealed STRING column. Admin-notification sends pass an array
      // of recipients; an array here would be coerced/mangled into the sealed cell,
      // so normalize to a comma-joined string.
      recipient: Array.isArray(to) ? to.join(", ") : String(to == null ? "" : to),
      subject: subject,
      backend: backend,
      status: status,
      createdAt: new Date().toISOString(),
    });
    return row ? row._id : null;
  } catch (_e) { /* ignore tracking errors */ return null; }
}

// Reserve a quota slot BEFORE the resend network round-trip by inserting a
// "pending" row. getQuotaCounts counts pending rows, so the reservation is
// visible to every concurrently-checking send the instant it lands — closing
// the read-check-then-send window. Returns the reservation _id, or null if the
// insert failed (in which case trySend falls back to tracking on resolution).
function reserveQuota(to, subject) {
  return trackSend(to, subject, "resend", "pending");
}

// Promote a reservation to "sent" (delivered) or remove it (failed/threw), so a
// failed send doesn't permanently hold a quota slot. Idempotent and best-effort.
function finalizeReservation(reservationId, delivered) {
  if (!reservationId) return;
  try {
    if (delivered) {
      db().emailSends.update({ _id: reservationId }, { $set: { status: "sent", createdAt: new Date().toISOString() } });
    } else {
      db().emailSends.remove({ _id: reservationId });
    }
  } catch (_e) { /* best-effort finalize */ }
}

// ---- Unified send function ----

async function trySend(backend, to, subject, html) {
  if (backend === "resend") {
    if (!config.email.resendApiKey) return { success: false, reason: "not configured" };
    var quota = checkQuota({ backend: "resend" });
    if (!quota.allowed) {
      trackSend(to, subject, "resend", "quota_exceeded");
      try { audit().log(audit().ACTIONS.EMAIL_QUOTA_EXCEEDED, { details: quota.reason + ", to: " + to }); } catch (_e) { /* audit log is best-effort — quota rejection proceeds */ }
      return { success: false, reason: "quota exceeded" };
    }
    // Reserve the slot synchronously — between this insert and resendSend's
    // await, a concurrent send's checkQuota already counts this pending row, so
    // the cap holds under burst. sendEmail finalizes the reservation by _id.
    var reservationId = reserveQuota(to, subject);
    var ok = await resendSend({ to, subject, html });
    return { success: ok, backend: "resend", reservationId: reservationId };
  } else {
    if (!config.email.host) return { success: false, reason: "not configured" };
    var ok = await smtpSend({ to, subject, html });
    return { success: ok, backend: "smtp" };
  }
}

// Validate email addresses to prevent SMTP header injection. Route the CR/LF/NUL
// reject through the shared primitive (b.safeBuffer.assertHeaderSafe) rather than a
// hand-rolled regex; it throws, so keep the boolean contract with a local catch.
function validateEmailAddr(addr) {
  if (!addr || typeof addr !== "string") return false;
  try {
    b.safeBuffer.assertHeaderSafe(addr, "email recipient", Error, "EMAIL_HEADER_UNSAFE");
  } catch (_e) {
    return false;
  }
  return true;
}

// HTML-escape user-provided values for email templates
var { escapeHtml: escHtml } = require("./vendor/blamejs").template;

async function sendEmail({ to, subject, html }) {
  if (!to) return false;
  // Accept a single address OR an array. sendAdminNotification passes an array of
  // admin recipients; the old single-string-only guard rejected it and SILENTLY
  // dropped every admin upload notification. b.mail.send normalizes + validates an
  // array natively (per-recipient CRLF/NUL header-injection reject); we keep a cheap
  // explicit per-element guard here and, critically, allow the array form.
  var addrs = Array.isArray(to) ? to : [to];
  if (addrs.length === 0) return false;
  for (var ai = 0; ai < addrs.length; ai++) {
    if (!validateEmailAddr(addrs[ai])) return false;
  }
  // Fold the user-influenced subject onto a single header line. A bare CR/LF strip
  // left a NUL byte — which SMTP/RFC 5322 parsers treat specially — on the Subject
  // line; foldHeaderText removes CR/LF (→ space) AND NUL.
  if (subject) subject = b.safeBuffer.foldHeaderText(subject);

  // Master kill switch — short-circuit without touching any backend. Callers
  // get `false` which they treat as "email failed, surface the link instead".
  if (config.email && config.email.enabled === false) {
    trackSend(to, subject, "disabled", "skipped");
    try { audit().log(audit().ACTIONS.EMAIL_SEND_FAILED, { details: "backend: disabled, reason: EMAIL_ENABLED=false, to: " + to }); } catch (_e) { /* audit log is best-effort — disabled backend short-circuit proceeds */ }
    return false;
  }

  var mode = config.email.backend || "smtp";

  // Build send order: primary, then optional fallback.
  // TODO(email-backends): before adding a 3rd backend, refactor this block
  // together with the emailBackend enum in lib/settings-schema.js and the
  // dropdown in views/admin.html (#pane-email) to use a single
  // SUPPORTED_BACKENDS list + parseBackendChain helper. Hardcoding explicit
  // combinations doesn't scale past 2–3 backends (N singles + N*(N-1) pairs).
  var order = [];
  if (mode === "resend+smtp") { order = ["resend", "smtp"]; }
  else if (mode === "smtp+resend") { order = ["smtp", "resend"]; }
  else if (mode === "resend") { order = ["resend"]; }
  else { order = ["smtp"]; }

  for (var i = 0; i < order.length; i++) {
    var backend = order[i];
    var isFallback = i > 0;
    try {
      var result = await trySend(backend, to, subject, html);
      if (result.success) {
        // For resend, trySend already reserved a "pending" row — promote it to
        // "sent" rather than inserting a duplicate (which would double-count the
        // quota). Other backends carry no reservation, so track fresh.
        if (result.reservationId) { finalizeReservation(result.reservationId, true); }
        else { trackSend(to, subject, backend, "sent"); }
        try { audit().log(audit().ACTIONS.EMAIL_SENT, { details: "backend: " + backend + (isFallback ? " (fallback)" : "") + ", to: " + to }); } catch (_e) { /* audit log is best-effort — email was sent */ }
        return true;
      }
      // Release the reservation on a clean failure so a failed resend doesn't
      // hold a quota slot; then record the failure for the audit/admin view.
      if (result.reservationId) { finalizeReservation(result.reservationId, false); }
      trackSend(to, subject, backend, "failed");
      try { audit().log(audit().ACTIONS.EMAIL_SEND_FAILED, { details: "backend: " + backend + ", reason: " + (result.reason || "send failed") + ", to: " + to }); } catch (_e) { /* audit log is best-effort — send already failed */ }
    } catch (e) {
      // trySend threw after reserving — its reservationId is unavailable here,
      // but reclaimStalePending() reclaims any orphaned pending row within the
      // TTL, so a thrown send never permanently consumes a quota slot.
      trackSend(to, subject, backend, "failed");
      try { audit().log(audit().ACTIONS.EMAIL_SEND_FAILED, { details: "backend: " + backend + ", error: " + e.message + ", to: " + to }); } catch (_e2) { /* audit log is best-effort — send already threw */ }
    }
  }

  return false;
}

// ---- Resend API ----

async function resendSend({ to, subject, html }) {
  if (!resendMailer) return false;
  try {
    await resendMailer.send({ to: to, subject: subject, html: html });
    return true;
  } catch (e) {
    logger.error("Resend error", { error: e.message || String(e) });
    return false;
  }
}

// ---- SMTP ----

async function smtpSend({ to, subject, html }) {
  if (!smtpMailer) return false;
  try {
    await smtpMailer.send({ to: to, subject: subject, html: html });
    return true;
  } catch (e) {
    logger.error("SMTP error", { error: e.message || String(e) });
    return false;
  }
}

// ---- Email template system (Matrix-inspired modern design) ----

function tpl(str, vars) {
  return str.replace(/\{(\w+)\}/g, function (_, key) { return vars[key] !== undefined ? vars[key] : "{" + key + "}"; });
}

function renderTpl(str, vars) {
  if (config.emailTemplateMode === "html") {
    // The admin-authored template `str` is trusted HTML, but the substituted
    // VALUES are not — uploaderName originates from the unauthenticated
    // public-upload form. Escape each string value before substitution so a
    // template that interpolates {uploaderName} (or any var) into the email HTML
    // can't carry injected markup, while the admin's literal HTML still renders.
    // This mirrors the explicit escHtml(uploaderName) at the sibling sinks below.
    // (Text mode escapes the whole rendered result instead — see below.)
    var safeVars = {};
    Object.keys(vars).forEach(function (k) {
      safeVars[k] = typeof vars[k] === "string" ? escHtml(vars[k]) : vars[k];
    });
    return tpl(str, safeVars);
  }
  var result = tpl(str, vars);
  // Escape via the framework escaper (covers & < > " ' — the hand-rolled
  // version missed the two quote characters) before turning newlines into <br>.
  result = escHtml(result);
  result = result.replace(/\n/g, "<br>");
  return result;
}

// Shared base layout — table-based for email client compatibility
function emailLayout(title, body, footer) {
  return `<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1.0"><title>${title}</title></head>
<body style="margin:0;padding:0;background:#f4f4f7;font-family:'Helvetica Neue',Helvetica,Arial,sans-serif;-webkit-text-size-adjust:100%">
<table width="100%" cellpadding="0" cellspacing="0" style="background:#f4f4f7;padding:40px 0">
<tr><td align="center">
<table width="600" cellpadding="0" cellspacing="0" style="max-width:600px;width:100%;background:#ffffff;border-radius:12px;overflow:hidden;box-shadow:0 4px 24px rgba(0,0,0,0.08)">
<!-- Header bar -->
<tr><td style="background:#1a1a2e;padding:32px 40px;text-align:center">
<h1 style="margin:0;color:#ffffff;font-size:24px;font-weight:700;letter-spacing:-0.5px">${title}</h1>
</td></tr>
<!-- Body -->
<tr><td style="padding:40px">${body}</td></tr>
<!-- Footer -->
<tr><td style="background:#f8f8fa;padding:24px 40px;border-top:1px solid #eeeef0">
<table width="100%" cellpadding="0" cellspacing="0">
<tr><td style="font-size:12px;color:#92929d;line-height:1.6;text-align:center">${footer}</td></tr>
</table>
</td></tr>
</table>
</td></tr></table></body></html>`;
}

function emailButton(text, href) {
  return `<table cellpadding="0" cellspacing="0" style="margin:28px auto"><tr>
<td style="background:#8B5CF6;border-radius:8px;padding:14px 36px;text-align:center">
<a href="${href}" style="color:#ffffff;font-size:15px;font-weight:600;text-decoration:none;display:inline-block">${text}</a>
</td></tr></table>`;
}

function emailInfoRow(label, value, color) {
  return `<tr><td style="padding:10px 0;border-bottom:1px solid #f0f0f3;color:#92929d;font-size:13px;width:140px">${label}</td><td style="padding:10px 0;border-bottom:1px solid #f0f0f3;font-size:14px;font-weight:600;color:${color || '#2d2d3a'}">${value}</td></tr>`;
}

// ---- Public email functions ----

async function sendUploaderConfirmation({ to, uploaderName, bundleUrl, uploadedCount, uploadedFiles, skippedCount, skippedFiles, totalSize }) {
  if (!to || uploadedCount === 0) return false;

  var siteName = config.siteName || "HermitStash";
  var vars = { siteName: siteName, uploaderName: uploaderName, fileCount: uploadedCount, totalSize: formatSize(totalSize) };
  var subject = tpl(config.emailTemplateSubject || "Your files have been uploaded to {siteName}", vars);
  var header = renderTpl(config.emailTemplateHeader || "Your upload is ready!", vars);
  var footer = renderTpl(config.emailTemplateFooter || "Sent by " + siteName + " &mdash; Post-quantum encrypted file sharing", vars);

  var uploadedRows = (uploadedFiles || []).slice(0, 100)
    .map(f => `<tr><td style="padding:8px 12px;border-bottom:1px solid #f0f0f3;font-size:13px;color:#2d2d3a;word-break:break-all">${escHtml(f.path)}</td><td style="padding:8px 12px;border-bottom:1px solid #f0f0f3;font-size:13px;color:#92929d;text-align:right;white-space:nowrap">${formatSize(f.size)}</td></tr>`).join("");

  var skippedRows = (skippedFiles || []).slice(0, 50)
    .map(f => `<tr><td style="padding:8px 12px;border-bottom:1px solid #f0f0f3;font-size:13px;color:#2d2d3a;word-break:break-all">${escHtml(f.path)}</td><td style="padding:8px 12px;border-bottom:1px solid #f0f0f3;font-size:13px;color:#92929d">${escHtml(f.reason)}</td></tr>`).join("");

  var body = `<p style="font-size:16px;color:#2d2d3a;margin:0 0 24px;line-height:1.6">${header}</p>
<table width="100%" cellpadding="0" cellspacing="0" style="margin-bottom:8px">
${emailInfoRow("From", escHtml(uploaderName))}
${emailInfoRow("Files", uploadedCount + " uploaded" + (skippedCount > 0 ? ", " + skippedCount + " skipped" : ""))}
${emailInfoRow("Size", formatSize(totalSize))}
</table>
${emailButton("View Your Upload", bundleUrl)}
${uploadedRows ? `<p style="font-size:12px;font-weight:700;color:#92929d;text-transform:uppercase;letter-spacing:1px;margin:28px 0 8px">Uploaded Files (${uploadedCount})</p>
<table width="100%" cellpadding="0" cellspacing="0" style="background:#fafafa;border-radius:8px;overflow:hidden">${uploadedRows}</table>` : ""}
${skippedRows ? `<p style="font-size:12px;font-weight:700;color:#8B5CF6;text-transform:uppercase;letter-spacing:1px;margin:20px 0 8px">Skipped (${skippedCount})</p>
<table width="100%" cellpadding="0" cellspacing="0" style="background:#fff8f6;border-radius:8px;overflow:hidden">${skippedRows}</table>` : ""}`;

  return sendEmail({ to, subject: subject, html: emailLayout(siteName, body, footer) });
}

async function sendAdminNotification({ adminEmails, uploaderName, uploaderEmail, bundleUrl, uploadedCount, skippedCount, totalSize }) {
  if (uploadedCount === 0) return false;
  var siteName = config.siteName || "HermitStash";
  var footer = renderTpl(config.emailTemplateFooter || "Sent by " + siteName + " &mdash; Post-quantum encrypted file sharing", { siteName: siteName, uploaderName: uploaderName, fileCount: uploadedCount, totalSize: formatSize(totalSize) });
  // Pass the recipient ARRAY (b.mail normalizes arrays natively). A comma-joined
  // string is treated as one malformed address, so 2+ admins silently get nothing.
  var to = Array.isArray(adminEmails) ? adminEmails : [adminEmails];

  var body = `<p style="font-size:16px;color:#2d2d3a;margin:0 0 4px;line-height:1.6">A new public upload has been received.</p>
<p style="font-size:13px;color:#92929d;margin:0 0 24px">Review the details below and take action if needed.</p>
<table width="100%" cellpadding="0" cellspacing="0" style="margin-bottom:8px">
${emailInfoRow("From", escHtml(uploaderName) + (uploaderEmail ? " (" + escHtml(uploaderEmail) + ")" : ""))}
${emailInfoRow("Files", uploadedCount + " uploaded, " + skippedCount + " skipped")}
${emailInfoRow("Size", formatSize(totalSize))}
</table>
${emailButton("View Upload", bundleUrl)}`;

  return sendEmail({ to, subject: "New upload from " + uploaderName + " (" + uploadedCount + " files)", html: emailLayout("New Upload Received", body, footer) });
}

async function sendVerificationEmail({ to, displayName, verifyUrl }) {
  if (!to) return false;
  var siteName = config.siteName || "HermitStash";

  var body = `<p style="font-size:16px;color:#2d2d3a;margin:0 0 8px;line-height:1.6">Hi ${escHtml(displayName || "there")},</p>
<p style="font-size:15px;color:#55556d;margin:0 0 8px;line-height:1.7">Thanks for creating an account on <strong>${escHtml(siteName)}</strong>. Please verify your email address to activate your account.</p>
${emailButton("Verify Email Address", verifyUrl)}
<p style="font-size:12px;color:#92929d;margin:0 0 6px;text-align:center">Or copy this link:</p>
<p style="font-size:11px;color:#b0b0be;word-break:break-all;text-align:center;margin:0 0 20px;padding:12px;background:#f8f8fa;border-radius:6px">${escHtml(verifyUrl)}</p>
<p style="font-size:12px;color:#92929d;text-align:center;margin:0">This link expires in 24 hours.</p>`;

  return sendEmail({ to, subject: "Verify your email \u2014 " + siteName, html: emailLayout("Verify Your Email", body, "Sent by " + siteName) });
}

async function sendInviteEmail({ to, inviteUrl, inviterName, role }) {
  if (!to) return false;
  var siteName = config.siteName || "HermitStash";

  var body = `<p style="font-size:16px;color:#2d2d3a;margin:0 0 8px;line-height:1.6">You've been invited!</p>
<p style="font-size:15px;color:#55556d;margin:0 0 8px;line-height:1.7"><strong>${escHtml(inviterName)}</strong> has invited you to join <strong>${escHtml(siteName)}</strong> as ${role === "admin" ? "an administrator" : "a member"}.</p>
<p style="font-size:15px;color:#55556d;margin:0 0 4px;line-height:1.7">Click below to set up your account.</p>
${emailButton("Accept Invite", inviteUrl)}
<p style="font-size:12px;color:#92929d;text-align:center;margin:0">This invite expires in 48 hours.</p>`;

  return sendEmail({ to, subject: "You're invited to " + siteName, html: emailLayout("You're Invited", body, "Sent by " + siteName) });
}

async function sendPasswordResetEmail({ to, resetUrl }) {
  if (!to) return false;
  var siteName = config.siteName || "HermitStash";

  var body = `<p style="font-size:16px;color:#2d2d3a;margin:0 0 8px;line-height:1.6">Hi there,</p>
<p style="font-size:15px;color:#55556d;margin:0 0 8px;line-height:1.7">We received a request to reset your password on <strong>${escHtml(siteName)}</strong>. Click the button below to choose a new password.</p>
${emailButton("Reset Password", resetUrl)}
<p style="font-size:12px;color:#92929d;margin:0 0 6px;text-align:center">Or copy this link:</p>
<p style="font-size:11px;color:#b0b0be;word-break:break-all;text-align:center;margin:0 0 20px;padding:12px;background:#f8f8fa;border-radius:6px">${escHtml(resetUrl)}</p>
<p style="font-size:12px;color:#92929d;text-align:center;margin:0">This link expires in 1 hour. If you did not request a password reset, you can safely ignore this email.</p>`;

  return sendEmail({ to, subject: "Reset your password \u2014 " + siteName, html: emailLayout("Reset Your Password", body, "Sent by " + siteName) });
}

async function sendBundleAccessCode({ to, code, bundleName, senderName, expiresMinutes }) {
  if (!to) return false;
  var siteName = config.siteName || "HermitStash";

  var body = `<p style="font-size:16px;color:#2d2d3a;margin:0 0 8px;line-height:1.6">Hi there,</p>
<p style="font-size:15px;color:#55556d;margin:0 0 24px;line-height:1.7">You've been sent files via <strong>${escHtml(siteName)}</strong>${senderName ? " from <strong>" + escHtml(senderName) + "</strong>" : ""}${bundleName ? ' ("<em>' + escHtml(bundleName) + '</em>")' : ""}. Enter this code to access them:</p>
<table cellpadding="0" cellspacing="0" style="margin:0 auto 24px">
<tr><td style="background:#f8f8fa;border:2px solid #e0e0e5;border-radius:12px;padding:20px 40px;text-align:center">
<span style="font-size:36px;letter-spacing:8px;font-weight:700;font-family:monospace;color:#2d2d3a">${escHtml(code)}</span>
</td></tr></table>
<p style="font-size:13px;color:#92929d;text-align:center;margin:0 0 8px">This code expires in ${expiresMinutes || 10} minutes.</p>
<p style="font-size:12px;color:#b0b0be;text-align:center;margin:0">If you didn't request this, you can safely ignore this email.</p>`;

  return sendEmail({ to, subject: "Your access code \u2014 " + siteName, html: emailLayout("Access Code", body, "Sent by " + siteName) });
}

module.exports = { sendEmail, sendUploaderConfirmation, sendAdminNotification, sendVerificationEmail, sendInviteEmail, sendPasswordResetEmail, sendBundleAccessCode, checkQuota, getQuotaCounts, _renderTpl: renderTpl };
