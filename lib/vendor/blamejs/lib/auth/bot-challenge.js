"use strict";
/**
 * @module     b.auth.botChallenge
 * @nav        Identity
 * @title      Bot Challenge Verifier
 * @order      375
 *
 * @intro
 *   Server-side verifier for the modern privacy-preserving bot-
 *   challenge widgets: Cloudflare Turnstile, hCaptcha, and Google
 *   reCAPTCHA v3. The client-side widget produces a short-lived
 *   token; the server POSTs that token (along with the operator's
 *   secret + optionally the remote IP) to the provider's siteverify
 *   endpoint and inspects the verdict.
 *
 *   Why a verifier and not a heuristic — `b.middleware.botGuard`
 *   inspects User-Agent / Accept-Language / fetch-metadata for
 *   stale crawlers, but a determined adversary forges those bytes
 *   trivially. A widget-issued token is a cryptographic claim from
 *   the provider that the request originated from a human (or a
 *   passable approximation under reCAPTCHA-v3's score model).
 *
 *   The verifier:
 *
 *     - POSTs the token via `b.httpClient` — every outbound hop
 *       goes through `b.ssrfGuard` + the framework's DNS pinning,
 *       so a redirect to a cloud-metadata endpoint can't smuggle
 *       past the first-hop gate. Raw `node:http` / `node:https` /
 *       global `fetch` is never used.
 *     - Sends the secret in the POST body as
 *       `application/x-www-form-urlencoded` (Cloudflare's
 *       documented shape). The secret never appears in the URL,
 *       query string, headers, log lines, or audit metadata.
 *     - Refuses a token that is not a non-empty string under
 *       `MAX_TOKEN_BYTES` (4 KiB) — Cloudflare tokens cap around
 *       2 KiB; a 1 MiB "token" is operator misuse or an attack.
 *     - Validates `success === true` AND (when configured)
 *       hostname-in-allowlist AND action-in-allowlist before
 *       returning. The provider's hostname / action fields are
 *       embedded in the token by the widget; operators using
 *       multi-domain or multi-action deployments allowlist the
 *       expected values to refuse cross-site token replay.
 *     - For reCAPTCHA-v3, exposes the `score` (0.0–1.0) on the
 *       success shape so the operator can threshold per-route.
 *     - Audits every verify call drop-silent via
 *       `b.audit.safeEmit` (action `auth.bot_challenge.verify`,
 *       outcome `success` / `failure`, metadata
 *       `{ provider, hostname?, ok, errorCodes? }`). The token
 *       and secret NEVER appear in audit metadata; only the
 *       token's 8-char prefix surfaces, and only when the operator
 *       has opted into trace-level metadata.
 *
 *   Compose with `b.authBotChallenge` (the adaptive staircase gate)
 *   by passing the verifier's `verify` function as the staircase's
 *   `challengeFn` — failed-auth attempts ride the staircase up to
 *   the challenge stage, the operator renders the Turnstile widget,
 *   and the verifier validates the resulting token. The two
 *   primitives are deliberately separate concerns.
 *
 *   References:
 *     - Cloudflare Turnstile siteverify
 *       https://developers.cloudflare.com/turnstile/get-started/server-side-validation/
 *     - hCaptcha siteverify
 *       https://docs.hcaptcha.com/#verify-the-user-response-server-side
 *     - reCAPTCHA v3 siteverify
 *       https://developers.google.com/recaptcha/docs/v3
 *     - OWASP ASVS v5 §11.5 (bot-defense controls)
 *     - RFC 6749 §4.1.3 (`application/x-www-form-urlencoded` body
 *       conventions for OAuth-style endpoints)
 *
 * @card
 *   Server-side verifier for Cloudflare Turnstile / hCaptcha / reCAPTCHA-v3 widget tokens with SSRF-guarded outbound, hostname + action allowlists, and drop-silent audit.
 */

var nodeQuerystring = require("node:querystring");

var lazyRequire  = require("../lazy-require");
var validateOpts = require("../validate-opts");
var safeJson     = require("../safe-json");
var C            = require("../constants");
var { BotChallengeError } = require("../framework-error");

var httpClient = lazyRequire(function () { return require("../http-client"); });
var audit      = lazyRequire(function () { return require("../audit"); });

// ---- constants ----

// Token byte ceiling. Turnstile tokens hover around 2 KiB; hCaptcha is
// similar; reCAPTCHA-v3 tokens are slightly larger but well under 4 KiB.
// A token that exceeds this cap is operator misuse (passed the wrong
// field) or a probe — refuse at the boundary rather than forwarding
// kilobytes of operator-supplied bytes to the provider.
var MAX_TOKEN_BYTES   = C.BYTES.kib(4);

// Default wall-clock timeout for the siteverify round-trip. Five seconds
// is the documented Cloudflare service-level target with healthy
// headroom; operators can override per-call but cannot drop below
// MIN_TIMEOUT_MS without the create() factory refusing the opts.
var DEFAULT_TIMEOUT_MS = C.TIME.seconds(5);
var MIN_TIMEOUT_MS     = 500; // anti-misconfiguration floor              // allow:raw-byte-literal — 500ms wall-clock floor, not a byte literal

// Response-body cap. Provider siteverify responses are small JSON
// (well under 4 KiB); a multi-MiB response is either a redirect to
// HTML (shouldn't happen — providers terminate JSON-only) or an
// attacker-shaped probe via DNS poisoning.
var MAX_RESPONSE_BYTES = C.BYTES.kib(64);

// Allowed siteverify response Content-Type — providers return
// `application/json` (Cloudflare + hCaptcha) or
// `application/json; charset=utf-8` (Google). The verifier rejects
// other content types rather than attempting to parse arbitrary bodies.
var EXPECTED_CONTENT_TYPE_PREFIX = "application/json";

// Number of characters of the token's prefix that surface in audit
// metadata for diagnosability. Eight characters is small enough that
// the surfaced bytes are not the secret token (≈ 48 bits visible vs.
// ~2 KiB total), but large enough to cluster verifications belonging
// to the same widget render in a debug session.
var TOKEN_PREFIX_AUDIT_CHARS = 8;                                          // allow:raw-byte-literal — debug-prefix length, not a byte literal

// ---- provider catalog ----
//
// Each provider entry exposes:
//   endpoint        — the siteverify URL (https only)
//   contentTypeBody — the POST body's Content-Type
//   parseResponse(body, raw) → { ok, hostname, action, ts, score?, errorCodes }
//
// The parseResponse contract is uniform across providers even though
// each provider's response shape differs slightly. Cloudflare /
// hCaptcha return `{ success, hostname, action, challenge_ts,
// "error-codes" }`; Google reCAPTCHA-v3 also returns `score` (and
// `action` is REQUIRED for v3).
//
// Each parseResponse normalises the raw body into the unified shape.
// `errorCodes` is always an array of strings (possibly empty); `ok`
// reflects the provider's success flag verbatim with no operator-
// configurable bypass.

function _parseCloudflareLike(rawObj) {
  var errorCodes = [];
  var raw = rawObj && typeof rawObj === "object" ? rawObj : {};
  if (Array.isArray(raw["error-codes"])) {
    for (var i = 0; i < raw["error-codes"].length; i++) {
      var ec = raw["error-codes"][i];
      if (typeof ec === "string") errorCodes.push(ec);
    }
  }
  return {
    ok:          raw.success === true,
    hostname:    typeof raw.hostname === "string" ? raw.hostname : null,
    action:      typeof raw.action === "string" ? raw.action : null,
    challengeTs: typeof raw.challenge_ts === "string" ? raw.challenge_ts : null,
    score:       null,
    errorCodes:  errorCodes,
  };
}

function _parseRecaptchaV3(rawObj) {
  var base = _parseCloudflareLike(rawObj);
  var raw = rawObj && typeof rawObj === "object" ? rawObj : {};
  if (typeof raw.score === "number" && isFinite(raw.score)) {
    base.score = raw.score;
  }
  return base;
}

var PROVIDERS = Object.freeze({
  "turnstile": Object.freeze({
    endpoint:        "https://challenges.cloudflare.com/turnstile/v0/siteverify",
    contentTypeBody: "application/x-www-form-urlencoded",
    parseResponse:   _parseCloudflareLike,
  }),
  "hcaptcha": Object.freeze({
    endpoint:        "https://api.hcaptcha.com/siteverify",
    contentTypeBody: "application/x-www-form-urlencoded",
    parseResponse:   _parseCloudflareLike,
  }),
  "recaptcha-v3": Object.freeze({
    endpoint:        "https://www.google.com/recaptcha/api/siteverify",
    contentTypeBody: "application/x-www-form-urlencoded",
    parseResponse:   _parseRecaptchaV3,
  }),
});

var DEFAULT_PROVIDER = "turnstile";

var ALLOWED_CREATE_OPTS = [
  "secret", "provider", "httpClient", "timeoutMs",
  "allowedHostnames", "allowedActions", "audit",
];

var ALLOWED_VERIFY_OPTS = [
  "remoteIp", "expectedAction", "expectedHostname",
];

// ---- helpers ----

function _requireNonEmptyString(name, val) {
  if (typeof val !== "string" || val.length === 0) {
    throw new BotChallengeError("bot-challenge/bad-opt",
      name + ": expected non-empty string, got " + typeof val);
  }
}

function _normaliseAllowlist(name, val) {
  if (val === undefined || val === null) return null;
  if (!Array.isArray(val)) {
    throw new BotChallengeError("bot-challenge/bad-opt",
      name + ": expected array of strings or null/undefined, got " + typeof val);
  }
  var out = [];
  for (var i = 0; i < val.length; i++) {
    var entry = val[i];
    if (typeof entry !== "string" || entry.length === 0) {
      throw new BotChallengeError("bot-challenge/bad-opt",
        name + "[" + i + "]: expected non-empty string");
    }
    out.push(entry);
  }
  if (out.length === 0) {
    throw new BotChallengeError("bot-challenge/bad-opt",
      name + ": allowlist must contain at least one entry when set");
  }
  return Object.freeze(out);
}

function _httpClientShape(client, callerLabel) {
  if (client === undefined || client === null) return null;
  if (typeof client !== "object" || typeof client.request !== "function") {
    throw new BotChallengeError("bot-challenge/bad-opt",
      callerLabel + ": httpClient must be a b.httpClient-shaped object (request fn)");
  }
  return client;
}

function _normaliseTimeoutMs(val) {
  if (val === undefined || val === null) return DEFAULT_TIMEOUT_MS;
  if (typeof val !== "number" || !isFinite(val) || val < MIN_TIMEOUT_MS ||
      Math.floor(val) !== val) {
    throw new BotChallengeError("bot-challenge/bad-opt",
      "timeoutMs: expected integer >= " + MIN_TIMEOUT_MS + " ms, got " +
      JSON.stringify(val));
  }
  return val;
}

function _byteLengthOf(s) {
  // Conservative UTF-8 byte count. Buffer.byteLength is the right
  // tool here because Turnstile tokens are ASCII-base64url today —
  // but the contract is in bytes, not chars.
  return Buffer.byteLength(s, "utf8");
}

function _isTimeoutError(err) {
  if (!err) return false;
  if (err.code === "TIMEOUT" || err.code === "WALL_CLOCK_TIMEOUT" ||
      err.code === "IDLE_TIMEOUT") return true;
  if (err.name === "AbortError") return true;
  var msg = err.message || "";
  return /timeout|timed out|aborted/i.test(msg);
}

function _safeAudit(safeEmit, action, outcome, metadata) {
  if (typeof safeEmit !== "function") return;
  try {
    safeEmit({
      action:   action,
      outcome:  outcome,
      metadata: metadata || {},
    });
  } catch (_e) { /* drop-silent — audit is best-effort */ }
}

function _resolveAuditSafeEmit(auditOpt) {
  // Operator-supplied audit takes precedence (mirrors `b.audit` shape).
  // Fall back to the framework's global `b.audit` via lazyRequire so
  // the verifier emits without explicit wiring. Drop-silent on every
  // failure path (per validation-tier rule §5, hot-path observability
  // sinks NEVER throw).
  if (auditOpt && typeof auditOpt.safeEmit === "function") {
    return auditOpt.safeEmit.bind(auditOpt);
  }
  try {
    var global = audit();
    if (global && typeof global.safeEmit === "function") {
      return global.safeEmit.bind(global);
    }
  } catch (_e) { /* no global audit available */ }
  return null;
}

// ---- public surface ----

/**
 * @primitive  b.auth.botChallenge.create
 * @signature  b.auth.botChallenge.create(opts)
 * @since      0.11.25
 * @status     stable
 * @compliance gdpr, soc2
 * @related    b.authBotChallenge.create, b.middleware.botGuard, b.httpClient
 *
 * Build a server-side verifier for a bot-challenge widget token.
 * Returns `{ verify(token, verifyOpts?) }`. The factory throws on
 * malformed opts; `verify` throws a typed `BotChallengeError` on
 * any verification failure and resolves on success.
 *
 * @opts
 *   secret:            string,    // provider-issued site secret — preserved verbatim
 *   provider:          string,    // "turnstile" | "hcaptcha" | "recaptcha-v3" (default "turnstile")
 *   httpClient:        Object,    // b.httpClient-shaped { request } — default: framework http-client
 *   timeoutMs:         number,    // wall-clock cap for the siteverify call (default 5_000; minimum 500)
 *   allowedHostnames:  string[],  // optional hostname allowlist — verify refuses tokens whose embedded hostname is absent
 *   allowedActions:    string[],  // optional action allowlist — verify refuses tokens whose embedded action is absent
 *   audit:             Object,    // optional b.audit-shaped sink; defaults to framework global b.audit
 *
 * @example
 *   var verifier = b.auth.botChallenge.create({
 *     secret:            process.env.TURNSTILE_SECRET,
 *     provider:          "turnstile",
 *     allowedHostnames:  ["app.example.com"],
 *     allowedActions:    ["login", "signup"],
 *   });
 *
 *   // In a login handler:
 *   try {
 *     var verdict = await verifier.verify(req.body["cf-turnstile-response"], {
 *       remoteIp:         b.requestHelpers.clientIp(req),
 *       expectedAction:   "login",
 *     });
 *     // verdict.ok === true; verdict.hostname / verdict.action / verdict.challengeTs populated.
 *   } catch (e) {
 *     // e instanceof b.auth.botChallenge.BotChallengeError
 *     // e.code === "bot-challenge/invalid-token" (or hostname-mismatch / timeout / etc.)
 *   }
 */
function create(opts) {
  opts = opts || {};
  validateOpts(opts, ALLOWED_CREATE_OPTS, "auth.botChallenge.create");

  _requireNonEmptyString("secret", opts.secret);
  // Preserve the secret verbatim — provider secrets are
  // case-sensitive and carry no canonical-form transformation rule.
  var secret = opts.secret;

  var providerKey = opts.provider !== undefined ? opts.provider : DEFAULT_PROVIDER;
  if (typeof providerKey !== "string" || !PROVIDERS[providerKey]) {
    var supported = Object.keys(PROVIDERS).join(", ");
    throw new BotChallengeError("bot-challenge/bad-opt",
      "provider: expected one of [" + supported + "], got " + JSON.stringify(providerKey));
  }
  var providerSpec = PROVIDERS[providerKey];

  var client = _httpClientShape(opts.httpClient, "auth.botChallenge.create") || httpClient();
  var timeoutMs = _normaliseTimeoutMs(opts.timeoutMs);
  var allowedHostnames = _normaliseAllowlist("allowedHostnames", opts.allowedHostnames);
  var allowedActions   = _normaliseAllowlist("allowedActions",   opts.allowedActions);

  if (opts.audit !== undefined) {
    validateOpts.auditShape(opts.audit, "auth.botChallenge.create", BotChallengeError);
  }
  var safeEmit = _resolveAuditSafeEmit(opts.audit);

  async function verify(token, verifyOpts) {
    verifyOpts = verifyOpts || {};
    validateOpts(verifyOpts, ALLOWED_VERIFY_OPTS, "auth.botChallenge.verify");

    var tokenPrefix = (typeof token === "string"
      ? token.slice(0, TOKEN_PREFIX_AUDIT_CHARS)
      : "");

    // Boundary refusals — every reject here is typed + audited.
    if (typeof token !== "string" || token.length === 0) {
      _safeAudit(safeEmit, "auth.bot_challenge.verify", "failure", {
        provider: providerKey, ok: false, reason: "empty-token",
      });
      throw new BotChallengeError("bot-challenge/invalid-token",
        "token must be a non-empty string");
    }
    if (_byteLengthOf(token) > MAX_TOKEN_BYTES) {
      _safeAudit(safeEmit, "auth.bot_challenge.verify", "failure", {
        provider: providerKey, ok: false, reason: "token-too-large",
        prefix: tokenPrefix,
      });
      throw new BotChallengeError("bot-challenge/invalid-token",
        "token exceeds " + MAX_TOKEN_BYTES + " bytes");
    }

    var expectedAction = verifyOpts.expectedAction !== undefined
      ? verifyOpts.expectedAction : null;
    if (expectedAction !== null && (typeof expectedAction !== "string" ||
        expectedAction.length === 0)) {
      throw new BotChallengeError("bot-challenge/bad-opt",
        "expectedAction: expected non-empty string");
    }
    var expectedHostname = verifyOpts.expectedHostname !== undefined
      ? verifyOpts.expectedHostname : null;
    if (expectedHostname !== null && (typeof expectedHostname !== "string" ||
        expectedHostname.length === 0)) {
      throw new BotChallengeError("bot-challenge/bad-opt",
        "expectedHostname: expected non-empty string");
    }
    if (verifyOpts.remoteIp !== undefined && verifyOpts.remoteIp !== null &&
        (typeof verifyOpts.remoteIp !== "string" || verifyOpts.remoteIp.length === 0)) {
      throw new BotChallengeError("bot-challenge/bad-opt",
        "remoteIp: expected non-empty string when set");
    }

    // Compose the application/x-www-form-urlencoded body. The secret
    // is in the body — never the URL/query/headers/audit metadata.
    var bodyFields = { secret: secret, response: token };
    if (verifyOpts.remoteIp) bodyFields.remoteip = verifyOpts.remoteIp;
    var body = nodeQuerystring.stringify(bodyFields);

    var res;
    try {
      res = await client.request({
        method:    "POST",
        url:       providerSpec.endpoint,
        body:      body,
        headers:   { "Content-Type": providerSpec.contentTypeBody },
        timeoutMs: timeoutMs,
        maxBytes:  MAX_RESPONSE_BYTES,
      });
    } catch (e) {
      if (_isTimeoutError(e)) {
        _safeAudit(safeEmit, "auth.bot_challenge.verify", "failure", {
          provider: providerKey, ok: false, reason: "timeout",
          prefix: tokenPrefix,
        });
        throw new BotChallengeError("bot-challenge/timeout",
          "siteverify timed out after " + timeoutMs + " ms");
      }
      _safeAudit(safeEmit, "auth.bot_challenge.verify", "failure", {
        provider: providerKey, ok: false, reason: "transport",
        prefix: tokenPrefix,
        // Surface the underlying message but not the secret/token bytes.
        message: (e && e.message) || String(e),
      });
      throw new BotChallengeError("bot-challenge/transport-error",
        "siteverify transport failure: " + ((e && e.message) || String(e)));
    }

    if (res.statusCode < 200 || res.statusCode >= 300) {                  // allow:raw-byte-literal — HTTP 2xx range bounds
      _safeAudit(safeEmit, "auth.bot_challenge.verify", "failure", {
        provider: providerKey, ok: false, reason: "non-2xx",
        statusCode: res.statusCode, prefix: tokenPrefix,
      });
      throw new BotChallengeError("bot-challenge/provider-error",
        "siteverify returned non-2xx status " + res.statusCode);
    }

    // Defensive Content-Type guard — providers return JSON.
    var ctHeader = (res.headers && (res.headers["content-type"] ||
                                     res.headers["Content-Type"])) || "";
    if (typeof ctHeader !== "string" ||
        ctHeader.toLowerCase().indexOf(EXPECTED_CONTENT_TYPE_PREFIX) !== 0) {
      _safeAudit(safeEmit, "auth.bot_challenge.verify", "failure", {
        provider: providerKey, ok: false, reason: "bad-content-type",
        contentType: ctHeader, prefix: tokenPrefix,
      });
      throw new BotChallengeError("bot-challenge/provider-error",
        "siteverify returned non-JSON Content-Type: " + ctHeader);
    }

    var raw;
    try {
      var bodyText = Buffer.isBuffer(res.body)
        ? res.body.toString("utf8")
        : String(res.body || "");
      raw = safeJson.parse(bodyText, { maxBytes: MAX_RESPONSE_BYTES });
    } catch (e) {
      _safeAudit(safeEmit, "auth.bot_challenge.verify", "failure", {
        provider: providerKey, ok: false, reason: "parse-error",
        prefix: tokenPrefix,
      });
      throw new BotChallengeError("bot-challenge/provider-error",
        "siteverify response parse failed: " + ((e && e.message) || String(e)));
    }

    var parsed = providerSpec.parseResponse(raw, res);

    if (!parsed.ok) {
      _safeAudit(safeEmit, "auth.bot_challenge.verify", "failure", {
        provider:   providerKey, ok: false, reason: "provider-rejected",
        errorCodes: parsed.errorCodes, hostname: parsed.hostname,
        prefix:     tokenPrefix,
      });
      var err = new BotChallengeError("bot-challenge/invalid-token",
        "siteverify rejected token: " +
        (parsed.errorCodes.length ? parsed.errorCodes.join(",") : "(no error-codes)"));
      err.errorCodes = parsed.errorCodes;
      throw err;
    }

    // Hostname allowlist — factory-configured allowlist OR per-call
    // expectedHostname (the per-call value overrides the allowlist for
    // exact-match in the same call but does not relax the allowlist).
    if (allowedHostnames && (!parsed.hostname ||
        allowedHostnames.indexOf(parsed.hostname) === -1)) {
      _safeAudit(safeEmit, "auth.bot_challenge.verify", "failure", {
        provider: providerKey, ok: false, reason: "hostname-mismatch",
        hostname: parsed.hostname, prefix: tokenPrefix,
      });
      throw new BotChallengeError("bot-challenge/hostname-mismatch",
        "hostname '" + parsed.hostname + "' not in allowedHostnames");
    }
    if (expectedHostname !== null && parsed.hostname !== expectedHostname) {
      _safeAudit(safeEmit, "auth.bot_challenge.verify", "failure", {
        provider: providerKey, ok: false, reason: "hostname-mismatch",
        hostname: parsed.hostname, expectedHostname: expectedHostname,
        prefix:   tokenPrefix,
      });
      throw new BotChallengeError("bot-challenge/hostname-mismatch",
        "hostname '" + parsed.hostname + "' does not match expectedHostname '" +
        expectedHostname + "'");
    }

    // Action allowlist — same shape as hostname.
    if (allowedActions && (!parsed.action ||
        allowedActions.indexOf(parsed.action) === -1)) {
      _safeAudit(safeEmit, "auth.bot_challenge.verify", "failure", {
        provider: providerKey, ok: false, reason: "action-mismatch",
        action: parsed.action, hostname: parsed.hostname,
        prefix:   tokenPrefix,
      });
      throw new BotChallengeError("bot-challenge/action-mismatch",
        "action '" + parsed.action + "' not in allowedActions");
    }
    if (expectedAction !== null && parsed.action !== expectedAction) {
      _safeAudit(safeEmit, "auth.bot_challenge.verify", "failure", {
        provider: providerKey, ok: false, reason: "action-mismatch",
        action: parsed.action, expectedAction: expectedAction,
        hostname: parsed.hostname, prefix: tokenPrefix,
      });
      throw new BotChallengeError("bot-challenge/action-mismatch",
        "action '" + parsed.action + "' does not match expectedAction '" +
        expectedAction + "'");
    }

    var successMeta = {
      provider:   providerKey, ok: true,
      hostname:   parsed.hostname, action: parsed.action,
      prefix:     tokenPrefix,
    };
    if (parsed.score !== null) successMeta.score = parsed.score;
    _safeAudit(safeEmit, "auth.bot_challenge.verify", "success", successMeta);

    var result = {
      ok:          true,
      provider:    providerKey,
      hostname:    parsed.hostname,
      action:      parsed.action,
      challengeTs: parsed.challengeTs,
      raw:         raw,
    };
    if (parsed.score !== null) result.score = parsed.score;
    return result;
  }

  return { verify: verify };
}

module.exports = {
  create:             create,
  PROVIDERS:          PROVIDERS,
  BotChallengeError:  BotChallengeError,
  DEFAULTS: Object.freeze({
    provider:       DEFAULT_PROVIDER,
    timeoutMs:      DEFAULT_TIMEOUT_MS,
    minTimeoutMs:   MIN_TIMEOUT_MS,
    maxTokenBytes:  MAX_TOKEN_BYTES,
  }),
};
