/**
 * Email sending module — supports SMTP and Resend API.
 * Backend selected via config.email.backend ("smtp" or "resend").
 * Resend API has configurable daily/monthly quota enforcement.
 * All sends are tracked in email_sends table and audit-logged.
 */
var net = require("net");
var tls = require("tls");
var https = require("https");
var { agent: pqcAgent } = require("./pqc-agent");
var { TLS_GROUP_CURVE_STR } = require("./constants");
var config = require("./config");
var logger = require("../app/shared/logger");
var { formatSize } = require("./template");

// Lazy-load to avoid circular deps during startup
var _db = null;
function db() { if (!_db) _db = require("./db"); return _db; }
var _audit = null;
function audit() { if (!_audit) _audit = require("./audit"); return _audit; }

// ---- Quota enforcement ----

function getQuotaCounts() {
  var sends = db().emailSends;
  var now = new Date();
  var todayStart = new Date(now.getFullYear(), now.getMonth(), now.getDate()).toISOString();
  var monthStart = new Date(now.getFullYear(), now.getMonth(), 1).toISOString();

  var dailySends = sends.find({ status: "sent" }).filter(function (s) { return s.createdAt >= todayStart; }).length;
  var monthlySends = sends.find({ status: "sent" }).filter(function (s) { return s.createdAt >= monthStart; }).length;

  return { daily: dailySends, monthly: monthlySends };
}

function checkQuota() {
  if (config.email.backend !== "resend") return { allowed: true };
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
    db().emailSends.insert({
      recipient: to,
      subject: subject,
      backend: backend,
      status: status,
      createdAt: new Date().toISOString(),
    });
  } catch (_e) { /* ignore tracking errors */ }
}

// ---- Unified send function ----

async function trySend(backend, to, subject, html) {
  if (backend === "resend") {
    if (!config.email.resendApiKey) return { success: false, reason: "not configured" };
    var quota = checkQuota();
    if (!quota.allowed) {
      trackSend(to, subject, "resend", "quota_exceeded");
      try { audit().log(audit().ACTIONS.EMAIL_QUOTA_EXCEEDED, { details: quota.reason + ", to: " + to }); } catch (_e) { /* audit log is best-effort — quota rejection proceeds */ }
      return { success: false, reason: "quota exceeded" };
    }
    var ok = await resendSend({ to, subject, html });
    return { success: ok, backend: "resend" };
  } else {
    if (!config.email.host) return { success: false, reason: "not configured" };
    var ok = await smtpSend({ to, subject, html });
    return { success: ok, backend: "smtp" };
  }
}

// Validate email addresses to prevent SMTP header injection
function validateEmailAddr(addr) {
  if (!addr || typeof addr !== "string") return false;
  if (/[\r\n\0]/.test(addr)) return false;
  return true;
}

// HTML-escape user-provided values for email templates
var { escHtml } = require("./sanitize");

async function sendEmail({ to, subject, html }) {
  if (!to) return false;
  if (!validateEmailAddr(to)) return false;
  // Sanitize subject to prevent SMTP header injection via CRLF
  if (subject) subject = subject.replace(/[\r\n]/g, "");

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
        trackSend(to, subject, backend, "sent");
        try { audit().log(audit().ACTIONS.EMAIL_SENT, { details: "backend: " + backend + (isFallback ? " (fallback)" : "") + ", to: " + to }); } catch (_e) { /* audit log is best-effort — email was sent */ }
        return true;
      }
      trackSend(to, subject, backend, "failed");
      try { audit().log(audit().ACTIONS.EMAIL_SEND_FAILED, { details: "backend: " + backend + ", reason: " + (result.reason || "send failed") + ", to: " + to }); } catch (_e) { /* audit log is best-effort — send already failed */ }
    } catch (e) {
      trackSend(to, subject, backend, "failed");
      try { audit().log(audit().ACTIONS.EMAIL_SEND_FAILED, { details: "backend: " + backend + ", error: " + e.message + ", to: " + to }); } catch (_e2) { /* audit log is best-effort — send already threw */ }
    }
  }

  return false;
}

// ---- Resend API ----

function resendSend({ to, subject, html }) {
  return new Promise(function (resolve) {
    var apiKey = config.email.resendApiKey;
    var body = JSON.stringify({
      from: config.email.from,
      to: Array.isArray(to) ? to : [to],
      subject: subject,
      html: html,
    });

    var req = https.request("https://api.resend.com/emails", {
      method: "POST",
      agent: pqcAgent,
      headers: {
        "Authorization": "Bearer " + apiKey,
        "Content-Type": "application/json",
        "Content-Length": Buffer.byteLength(body),
      },
      timeout: 15000,
    }, function (res) {
      var chunks = [];
      res.on("data", function (c) { chunks.push(c); });
      res.on("end", function () {
        var text = Buffer.concat(chunks).toString();
        try {
          var data = JSON.parse(text);
          if (data.id) {
            resolve(true);
          } else {
            logger.error("Resend error", { error: data.message || text });
            resolve(false);
          }
        } catch (_e) {
          logger.error("Resend parse error", { error: text });
          resolve(false);
        }
      });
    });
    req.on("error", function (err) { logger.error("Resend error", { error: err.message || String(err) }); resolve(false); });
    req.on("timeout", function () { req.destroy(); resolve(false); });
    req.write(body);
    req.end();
  });
}

// ---- SMTP ----

function smtpSend({ to, subject, html }) {
  if (!config.email.host) return Promise.resolve(false);

  return new Promise((resolve) => {
    var port = config.email.port;
    var useImplicitTLS = port === 465;
    var socket;
    var step = 0;
    var buffer = "";
    var upgradedToTLS = false;

    function connect() {
      if (useImplicitTLS) {
        socket = tls.connect(port, config.email.host, { rejectUnauthorized: config.smtpRejectUnauthorized !== false, ecdhCurve: TLS_GROUP_CURVE_STR, minVersion: "TLSv1.3" }, () => {});
      } else {
        socket = net.createConnection(port, config.email.host, () => {});
      }
      socket.setEncoding("utf8");
      socket.setTimeout(15000);
      socket.on("data", onData);
      socket.on("error", (err) => { logger.error("SMTP error", { error: err.message || String(err) }); resolve(false); });
      socket.on("timeout", () => { socket.destroy(); resolve(false); });
    }

    function send(cmd) { socket.write(cmd + "\r\n"); }

    function onData(data) {
      buffer += data;
      var lines = buffer.split("\r\n");
      buffer = lines.pop();
      for (var line of lines) {
        if (!line) continue;
        var code = parseInt(line.slice(0, 3), 10);
        if (line[3] === "-") continue;
        handleResponse(code, line);
      }
    }

    var fromAddr = extractEmail(config.email.from);
    var message = [
      `From: ${config.email.from}`,
      `To: ${to}`,
      `Subject: ${subject}`,
      `MIME-Version: 1.0`,
      `Content-Type: text/html; charset=utf-8`,
      ``,
      html,
    ].join("\r\n");

    function handleResponse(code) {
      if (step === 0) { send("EHLO hermitstash"); step = 1; }
      else if (step === 1) {
        if (!useImplicitTLS && !upgradedToTLS) { send("STARTTLS"); step = 10; }
        else if (config.email.user) { send("AUTH LOGIN"); step = 2; }
        else { send(`MAIL FROM:<${fromAddr}>`); step = 5; }
      } else if (step === 10) {
        var tlsSocket = tls.connect({ socket, rejectUnauthorized: config.smtpRejectUnauthorized !== false, servername: config.email.host, ecdhCurve: TLS_GROUP_CURVE_STR, minVersion: "TLSv1.3" }, () => {
          upgradedToTLS = true; socket = tlsSocket;
          socket.setEncoding("utf8"); socket.on("data", onData);
          send("EHLO hermitstash"); step = 1;
        });
        tlsSocket.on("error", (err) => { logger.error("TLS error", { error: err.message || String(err) }); resolve(false); });
      } else if (step === 2) { send(Buffer.from(config.email.user).toString("base64")); step = 3; }
      else if (step === 3) { send(Buffer.from(config.email.pass).toString("base64")); step = 4; }
      else if (step === 4) {
        if (code !== 235) { logger.error("SMTP auth failed", { error: "Authentication rejected" }); socket.end(); resolve(false); return; }
        send(`MAIL FROM:<${fromAddr}>`); step = 5;
      } else if (step === 5) { send(`RCPT TO:<${to}>`); step = 6; }
      else if (step === 6) { send("DATA"); step = 7; }
      else if (step === 7) { send(message + "\r\n."); step = 8; }
      else if (step === 8) { send("QUIT"); socket.end(); resolve(code === 250); }
    }

    connect();
  });
}

function extractEmail(from) {
  var match = from.match(/<(.+)>/);
  return match ? match[1] : from;
}

// ---- Email template system (Matrix-inspired modern design) ----

function tpl(str, vars) {
  return str.replace(/\{(\w+)\}/g, function (_, key) { return vars[key] !== undefined ? vars[key] : "{" + key + "}"; });
}

function renderTpl(str, vars) {
  var result = tpl(str, vars);
  if (config.emailTemplateMode === "html") return result;
  result = result.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
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
  var to = adminEmails.join(",");

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

  var body = `<p style="font-size:16px;color:#2d2d3a;margin:0 0 8px;line-height:1.6">Hi ${displayName || "there"},</p>
<p style="font-size:15px;color:#55556d;margin:0 0 8px;line-height:1.7">Thanks for creating an account on <strong>${siteName}</strong>. Please verify your email address to activate your account.</p>
${emailButton("Verify Email Address", verifyUrl)}
<p style="font-size:12px;color:#92929d;margin:0 0 6px;text-align:center">Or copy this link:</p>
<p style="font-size:11px;color:#b0b0be;word-break:break-all;text-align:center;margin:0 0 20px;padding:12px;background:#f8f8fa;border-radius:6px">${verifyUrl}</p>
<p style="font-size:12px;color:#92929d;text-align:center;margin:0">This link expires in 24 hours.</p>`;

  return sendEmail({ to, subject: "Verify your email \u2014 " + siteName, html: emailLayout("Verify Your Email", body, "Sent by " + siteName) });
}

async function sendInviteEmail({ to, inviteUrl, inviterName, role }) {
  if (!to) return false;
  var siteName = config.siteName || "HermitStash";

  var body = `<p style="font-size:16px;color:#2d2d3a;margin:0 0 8px;line-height:1.6">You've been invited!</p>
<p style="font-size:15px;color:#55556d;margin:0 0 8px;line-height:1.7"><strong>${inviterName}</strong> has invited you to join <strong>${siteName}</strong> as ${role === "admin" ? "an administrator" : "a member"}.</p>
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

module.exports = { sendEmail, sendUploaderConfirmation, sendAdminNotification, sendVerificationEmail, sendInviteEmail, sendPasswordResetEmail, sendBundleAccessCode, checkQuota, getQuotaCounts };
