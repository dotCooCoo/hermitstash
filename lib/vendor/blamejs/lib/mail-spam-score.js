"use strict";
/**
 * @module     b.mail.spamScore
 * @nav        Mail
 * @title      Mail Spam Score
 * @order      557
 *
 * @intro
 *   Operator-supplied spam scorer facade. The framework deliberately
 *   does NOT vendor a spam-classifier engine — the bayes corpora,
 *   URIBL caches, neural models, and per-recipient training are all
 *   operator state. Instead, `b.mail.spamScore.create` wraps the
 *   operator's chosen scorer (SpamAssassin via spamc, Rspamd HTTP
 *   API, Cloudmark, Vade, in-house) in a uniform threshold-driven
 *   verdict pipeline that the MX listener (v0.9.45) and submission
 *   listener (v0.9.47) consume.
 *
 *   ## Operator-supplied scorer contract
 *
 *   ```
 *   async function scorer({ rawBytes, headers, envelope }) {
 *     // call out to SpamAssassin / Rspamd / commercial scorer
 *     return { score: 7.3, reasons: ["BAYES_99", "URIBL_RED"] };
 *   }
 *   ```
 *
 *   - `score` MUST be a finite number (any range; the threshold is
 *     operator-tuned). Negative scores mean "ham-shaped"; positive
 *     scores mean "spam-shaped". Convention matches SpamAssassin.
 *   - `reasons` MUST be an Array of short ASCII tags. The facade caps
 *     each tag at 256 bytes and refuses control bytes; the cap protects
 *     audit storage + outbound headers (`X-Spam-Status: ...`) from
 *     hostile expansion via a compromised scorer.
 *
 *   ## Thresholds
 *
 *   - **strict** — 5.0 (matches SpamAssassin's default `required_score`).
 *   - **balanced** — 7.5.
 *   - **permissive** — 10.0.
 *
 *   Operators tune via `opts.threshold` per-instance. The verdict is
 *   `"accept"` (score < threshold), `"score-tag"` (score === threshold —
 *   add `X-Spam-Status` header but deliver), or `"refuse"`
 *   (score > threshold — return SMTP 550).
 *
 *   ## Composition
 *
 *   - **`b.audit`** receives every `score` / `accept` / `score_tag` /
 *     `refuse` decision. Audit failure is drop-silent (hot path).
 *
 *   ## Threat model
 *
 *   - **Hostile reason-tag** (compromised scorer injects CRLF into a
 *     tag, smuggling extra `X-Spam-*` headers into the outbound
 *     wrapper): defended by per-tag length cap + control-byte refusal.
 *   - **NaN / Infinity score** (scorer bug): refused as
 *     `mail-spam-score/bad-score`; the listener treats the message as
 *     unscanned (operator's tempfail policy applies).
 *   - **Slow scorer DoS**: the scorer function is operator code, so
 *     timing belongs to the operator. The listener wraps the
 *     `.score()` promise in its own per-connection deadline.
 *
 * @card
 *   Threshold-driven spam-scorer facade. Operator wires SpamAssassin /
 *   Rspamd / commercial scorer; the framework owns the verdict
 *   pipeline + reason-tag hardening + audit emission. Three default
 *   thresholds (strict 5.0 / balanced 7.5 / permissive 10.0).
 */

var { defineClass }   = require("./framework-error");
var lazyRequire       = require("./lazy-require");
var validateOpts      = require("./validate-opts");

var audit = lazyRequire(function () { return require("./audit"); });

var MailSpamScoreError = defineClass("MailSpamScoreError", { alwaysPermanent: true });

var DEFAULT_PROFILE = "strict";

// reason-tag length cap defends outbound
// header / audit-store from hostile expansion via compromised scorer.
var MAX_REASON_BYTES = 256;

// reason-list count cap, defends audit volume.
var MAX_REASONS = 32;

var PROFILES = Object.freeze({
  strict:     { threshold: 5.0,  maxReasons: MAX_REASONS, maxReasonBytes: MAX_REASON_BYTES },      // matches SpamAssassin default required_score
  balanced:   { threshold: 7.5,  maxReasons: MAX_REASONS, maxReasonBytes: MAX_REASON_BYTES },
  permissive: { threshold: 10.0, maxReasons: MAX_REASONS, maxReasonBytes: MAX_REASON_BYTES },
});

var COMPLIANCE_POSTURES = Object.freeze({
  hipaa:     "strict",
  "pci-dss": "strict",
  gdpr:      "strict",
  soc2:      "strict",
});

/**
 * @primitive b.mail.spamScore.create
 * @signature b.mail.spamScore.create(opts)
 * @since     0.9.81
 * @status    stable
 * @related   b.mail.scan.create
 *
 * Build a spam-score handle. Returns `{ score(message, opts),
 * threshold, profile, MailSpamScoreError }` where `.score` resolves to
 * `{ score, reasons, verdict }`. `verdict` is `"accept"` /
 * `"score-tag"` / `"refuse"` based on threshold comparison.
 *
 * @opts
 *   scorer:    async fn({ rawBytes, headers, envelope }) → { score, reasons } — required
 *   threshold: number — overrides profile default
 *   profile:   "strict" | "balanced" | "permissive"
 *   posture:   "hipaa" | "pci-dss" | "gdpr" | "soc2"
 *   audit:     b.audit instance
 *
 * @example
 *   var spam = b.mail.spamScore.create({
 *     scorer: async function (ctx) {
 *       return await callSpamAssassin(ctx.rawBytes);
 *     },
 *   });
 *   var v = await spam.score({ rawBytes: msg });
 *   if (v.verdict === "refuse") refuseConnection(v.reasons.join(","));
 */
function create(opts) {
  opts = validateOpts.requireObject(opts || {}, "mail.spamScore.create",
    MailSpamScoreError, "mail-spam-score/bad-opts");
  validateOpts(opts, [
    "scorer", "threshold", "profile", "posture", "audit",
  ], "mail.spamScore.create");
  if (typeof opts.scorer !== "function") {
    throw new MailSpamScoreError("mail-spam-score/bad-scorer",
      "mail.spamScore.create.scorer must be a function; got " + (typeof opts.scorer));
  }
  var profile = opts.profile || (opts.posture && COMPLIANCE_POSTURES[opts.posture]) || DEFAULT_PROFILE;
  if (!PROFILES[profile]) {
    throw new MailSpamScoreError("mail-spam-score/bad-profile",
      "mail.spamScore.create.profile: unknown '" + profile +
      "' (valid: strict / balanced / permissive)");
  }
  var caps = PROFILES[profile];
  var threshold;
  if (opts.threshold !== undefined) {
    if (typeof opts.threshold !== "number" || !isFinite(opts.threshold)) {
      throw new MailSpamScoreError("mail-spam-score/bad-threshold",
        "mail.spamScore.create.threshold must be a finite number; got " +
        (typeof opts.threshold) + " " + String(opts.threshold));
    }
    threshold = opts.threshold;
  } else {
    threshold = caps.threshold;
  }
  var auditImpl = opts.audit || audit();

  async function score(message) {
    if (!message || typeof message !== "object") {
      throw new MailSpamScoreError("mail-spam-score/bad-input",
        "mail.spamScore.score: message must be an object with rawBytes/headers/envelope");
    }
    var rv;
    try {
      rv = await opts.scorer({
        rawBytes: message.rawBytes,
        headers:  message.headers || {},
        envelope: message.envelope || {},
      });
    } catch (e) {
      _emitAudit(auditImpl, "mail.spam_score.error", "failure", {
        message: (e && e.message) || String(e),
      });
      throw new MailSpamScoreError("mail-spam-score/scorer-threw",
        "mail.spamScore.score: scorer threw: " + ((e && e.message) || e));
    }
    if (!rv || typeof rv !== "object") {
      throw new MailSpamScoreError("mail-spam-score/bad-result",
        "mail.spamScore.score: scorer must return { score, reasons }; got " +
        (typeof rv));
    }
    if (typeof rv.score !== "number" || !isFinite(rv.score)) {
      throw new MailSpamScoreError("mail-spam-score/bad-score",
        "mail.spamScore.score: scorer returned non-finite score=" + String(rv.score));
    }
    var reasons = _sanitizeReasons(rv.reasons, caps);

    var verdict;
    if (rv.score < threshold)       verdict = "accept";
    else if (rv.score === threshold) verdict = "score-tag";
    else                              verdict = "refuse";

    _emitAudit(auditImpl, "mail.spam_score.score", "success", {
      score: rv.score, threshold: threshold, verdict: verdict, reasons: reasons,
    });
    if (verdict === "accept") {
      _emitAudit(auditImpl, "mail.spam_score.accept", "success", { score: rv.score });
    } else if (verdict === "score-tag") {
      _emitAudit(auditImpl, "mail.spam_score.score_tag", "success",
        { score: rv.score, reasons: reasons });
    } else {
      _emitAudit(auditImpl, "mail.spam_score.refuse", "success",
        { score: rv.score, reasons: reasons });
    }
    return { score: rv.score, reasons: reasons, verdict: verdict };
  }

  return {
    score:                score,
    threshold:            threshold,
    profile:              profile,
    MailSpamScoreError:   MailSpamScoreError,
  };
}

/**
 * @primitive b.mail.spamScore.compliancePosture
 * @signature b.mail.spamScore.compliancePosture(posture)
 * @since     0.9.81
 * @status    stable
 *
 * Return the effective profile name for a compliance posture, or
 * `null` for unknown posture names.
 *
 * @example
 *   b.mail.spamScore.compliancePosture("hipaa");   // → "strict"
 */
function compliancePosture(posture) {
  return COMPLIANCE_POSTURES[posture] || null;
}

function _sanitizeReasons(reasons, caps) {
  if (reasons === undefined || reasons === null) return [];
  if (!Array.isArray(reasons)) {
    throw new MailSpamScoreError("mail-spam-score/bad-reasons",
      "mail.spamScore.score: scorer returned non-array reasons (" + (typeof reasons) + ")");
  }
  if (reasons.length > caps.maxReasons) {
    throw new MailSpamScoreError("mail-spam-score/too-many-reasons",
      "mail.spamScore.score: scorer returned " + reasons.length +
      " reasons; cap is " + caps.maxReasons);
  }
  var out = [];
  for (var i = 0; i < reasons.length; i += 1) {
    var r = reasons[i];
    if (typeof r !== "string" || r.length === 0) {
      throw new MailSpamScoreError("mail-spam-score/bad-reason",
        "mail.spamScore.score: reasons[" + i + "] must be a non-empty string");
    }
    if (Buffer.byteLength(r, "utf8") > caps.maxReasonBytes) {
      throw new MailSpamScoreError("mail-spam-score/oversize-reason",
        "mail.spamScore.score: reasons[" + i + "] exceeds " + caps.maxReasonBytes + " bytes");
    }
    // Refuse control bytes (CR / LF / NUL / etc.) — a compromised
    // scorer could try to smuggle CRLF into an outbound X-Spam-Status
    // header.
    for (var c = 0; c < r.length; c += 1) {
      var cc = r.charCodeAt(c);
      if (cc < 0x20 || cc === 0x7f) {                                                              // RFC 5234 CTL refusal range
        throw new MailSpamScoreError("mail-spam-score/control-byte",
          "mail.spamScore.score: reasons[" + i + "] contains control byte 0x" +
          cc.toString(16));                                                                        // hex radix
      }
    }
    out.push(r);
  }
  return out;
}

function _emitAudit(auditImpl, action, outcome, metadata) {
  try {
    if (auditImpl && typeof auditImpl.safeEmit === "function") {
      auditImpl.safeEmit({ action: action, outcome: outcome, metadata: metadata });
    }
  } catch (_e) { /* drop-silent — audit failures don't break score path */ }
}

module.exports = {
  create:                create,
  compliancePosture:     compliancePosture,
  PROFILES:              PROFILES,
  COMPLIANCE_POSTURES:   COMPLIANCE_POSTURES,
  MailSpamScoreError:    MailSpamScoreError,
};
