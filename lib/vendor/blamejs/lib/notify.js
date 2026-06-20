"use strict";
/**
 * @module b.notify
 * @nav    Communication
 * @title  Notify
 *
 * @intro
 *   Pluggable notification dispatcher. One contract — `{ name, send }`
 *   — adapts any transport (Slack incoming-webhook, Discord, Microsoft
 *   Teams, PagerDuty, Twilio, FCM / APNs operator shim, plain
 *   developer log) and the dispatcher coordinates retry / timeout /
 *   circuit-breaker / observability / audit / PII redaction around it.
 *
 *   Composition over reinvention: every cross-cutting concern routes
 *   through an existing primitive — `b.retry.withRetry` for backoff +
 *   classification, `b.safeAsync.withTimeout` for per-call timeouts,
 *   `b.retry.CircuitBreaker` for per-channel breakers, `b.observability.
 *   tap` for span+counter wrapping, `b.audit.safeEmit` for audit rows
 *   (drop-silent on transport failure — observability sinks must not
 *   crash send), `b.requestHelpers.extractActorContext` for the 5 W's,
 *   `b.safeUrl.parse` + `b.httpClient.request` for HTTP I/O,
 *   `b.redact.redact` for default PII scrubbing of message contents
 *   before they hit the audit chain.
 *
 *   Built-in transports: `httpJson` (POST JSON / form to a URL — the
 *   workhorse for Slack / Discord / generic incoming-webhook
 *   integrations, with optional `b.webhook.signer` injection),
 *   `log` (fire-and-forget developer logger via `b.log`),
 *   `test` (captures sends to `.sent[]` for fixture inspection).
 *   Operators bring their own SDK shims for Twilio / FCM / APNs /
 *   Slack-API (the framework intentionally ships no vendor SDKs).
 *
 *   Out of scope by design: template rendering (use `b.template`),
 *   recipient preferences (operator concern), replacing `b.mail`
 *   (SMTP / MIME stays its own primitive), replacing
 *   `b.websocketChannels` (transient pub/sub vs retry-on-fail
 *   delivery).
 *
 * @card
 *   Pluggable notification dispatcher.
 */

var lazyRequire = require("./lazy-require");
var logModule = require("./log");
var numericChecks = require("./numeric-checks");
var requestHelpers = require("./request-helpers");
var safeAsync = require("./safe-async");
var safeUrl = require("./safe-url");
var validateOpts = require("./validate-opts");
var C = require("./constants");
var { NotifyError } = require("./framework-error");

// Lazy-required modules to avoid load-order cycles. retry / observability /
// redact / httpClient don't currently import notify, but treating them
// the same way every primitive does keeps the load-order story uniform.
var retryHelper = lazyRequire(function () { return require("./retry"); });
var observability = lazyRequire(function () { return require("./observability"); });
var redact = lazyRequire(function () { return require("./redact"); });
var httpClient = lazyRequire(function () { return require("./http-client"); });

var _err = NotifyError.factory;

var DEFAULTS = Object.freeze({
  auditSuccess:     true,
  auditFailures:    true,
  defaultTimeoutMs: C.TIME.seconds(30),
  // defaultRetry inherits from b.retry.DEFAULT_RETRY at create time so
  // we get the framework's policy without forking the constants.
});

// ---- Call-site validation (throw on bad input) ----

var _isFiniteNonNegative = numericChecks.isFiniteNonNegative;

function _validateTransport(name, t) {
  if (!t || typeof t !== "object") {
    throw _err("BAD_OPT", "notify: transport for channel '" + name +
      "' must be an object with a send() function");
  }
  if (typeof t.send !== "function") {
    throw _err("BAD_OPT", "notify: transport for channel '" + name +
      "' is missing required send() function");
  }
}

function _validateChannelEntry(name, entry) {
  if (typeof entry !== "object" || entry === null) {
    throw _err("BAD_OPT", "notify: channel '" + name + "' must map to a transport or { transport, ... } object");
  }
  // Two accepted shapes:
  //   - Transport object directly: { name, send }
  //   - Channel-config object:     { transport, retry?, breaker?, timeoutMs?, serialize? }
  if (typeof entry.send === "function") {
    return { transport: entry, retry: null, breaker: null, timeoutMs: null, serialize: false };
  }
  if (entry.transport === undefined) {
    throw _err("BAD_OPT", "notify: channel '" + name +
      "': must be a transport (with send fn) OR an object with .transport");
  }
  _validateTransport(name, entry.transport);
  if (entry.retry !== undefined && (typeof entry.retry !== "object" || entry.retry === null)) {
    throw _err("BAD_OPT", "notify: channel '" + name + "' retry must be a b.retry.withRetry opts object");
  }
  if (entry.breaker !== undefined && entry.breaker !== null && typeof entry.breaker !== "object") {
    throw _err("BAD_OPT", "notify: channel '" + name + "' breaker must be a b.retry.CircuitBreaker opts object or null");
  }
  if (entry.timeoutMs !== undefined && entry.timeoutMs !== 0 && !_isFiniteNonNegative(entry.timeoutMs)) {
    throw _err("BAD_OPT", "notify: channel '" + name + "' timeoutMs must be a non-negative finite number (0 disables)");
  }
  if (entry.serialize !== undefined && typeof entry.serialize !== "boolean") {
    throw _err("BAD_OPT", "notify: channel '" + name + "' serialize must be a boolean");
  }
  return {
    transport: entry.transport,
    retry:     entry.retry || null,
    breaker:   entry.breaker || null,
    timeoutMs: (entry.timeoutMs !== undefined) ? entry.timeoutMs : null,
    serialize: entry.serialize === true,
  };
}

function _validateCreateOpts(opts) {
  validateOpts.requireObject(opts, "notify.create", NotifyError);
  if (!opts.channels || typeof opts.channels !== "object") {
    throw _err("BAD_OPT", "notify.create: channels must be an object mapping channel names to transports");
  }
  var keys = Object.keys(opts.channels);
  if (keys.length === 0) {
    throw _err("BAD_OPT", "notify.create: channels object must have at least one channel");
  }
  validateOpts.auditShape(opts.audit, "notify.create", NotifyError);
  validateOpts.optionalBoolean(opts.auditSuccess, "notify.create: auditSuccess", NotifyError);
  validateOpts.optionalBoolean(opts.auditFailures, "notify.create: auditFailures", NotifyError);
  if (opts.redact !== undefined && opts.redact !== null && typeof opts.redact !== "function") {
    throw _err("BAD_OPT", "notify.create: redact must be a function returning a redacted message");
  }
  if (opts.defaultTimeoutMs !== undefined &&
      opts.defaultTimeoutMs !== 0 &&
      !_isFiniteNonNegative(opts.defaultTimeoutMs)) {
    throw _err("BAD_OPT", "notify.create: defaultTimeoutMs must be a non-negative finite number (0 disables)");
  }
  if (opts.defaultRetry !== undefined && opts.defaultRetry !== null &&
      (typeof opts.defaultRetry !== "object")) {
    throw _err("BAD_OPT", "notify.create: defaultRetry must be a b.retry.withRetry opts object");
  }
  if (opts.defaultBreaker !== undefined && opts.defaultBreaker !== null &&
      typeof opts.defaultBreaker !== "object") {
    throw _err("BAD_OPT", "notify.create: defaultBreaker must be a b.retry.CircuitBreaker opts object");
  }
  validateOpts.optionalObjectWithMethod(opts.queue, "enqueue",
    "notify.create: queue", NotifyError, "BAD_OPT",
    "must be a b.queue-shaped handle (enqueue fn)");
  validateOpts.optionalFunction(opts.clock, "notify.create: clock", NotifyError);
}

// ---- Built-in transports ----

/**
 * @primitive b.notify.transports.httpJson
 * @signature b.notify.transports.httpJson(opts)
 * @since     0.6.0
 * @status    stable
 * @related   b.notify.create, b.webhook.signer
 *
 * Built-in transport that POSTs the message as JSON (or
 * `application/x-www-form-urlencoded`) to a URL via `b.httpClient.
 * request`. Validates the URL at create time so bad URLs surface at
 * boot, not at first send. Optional `signing` slot accepts any object
 * with a `sign(body) → headers | { headers }` function — drop a
 * `b.webhook.signer` straight in for HMAC / PQC signed deliveries.
 * The default success classifier accepts HTTP 2xx; non-success
 * statuses throw a plain `Error` with `statusCode` set so
 * `b.retry.isRetryable` classifies the response (429 / 503 / network
 * errors retry; permanent rejections don't).
 *
 * @opts
 *   url:           string,                              // required
 *   method:        "POST" | "PUT" | "PATCH",            // default "POST"
 *   bodyFormat:    "json" | "form",                     // default "json"
 *   headers:       { [k]: string },
 *   signing:       { sign(body) => headers | { headers } },
 *   successStatus: function (status) => boolean,
 *   allowHttp:     boolean,                             // default false (HTTPS-only)
 *   allowInternal: boolean,
 *   httpClient:    object,                              // override b.httpClient
 *   name:          string,                              // for audit + logs
 *
 * @example
 *   var b = require("@blamejs/core");
 *   var slack = b.notify.transports.httpJson({
 *     url:  "https://hooks.slack.com/services/T0/B0/X",
 *     name: "slack",
 *   });
 *   // → { name: "slack", send: async function (message, sendOpts) { ... } }
 */
function httpJson(opts) {
  if (!opts || typeof opts !== "object") {
    throw _err("BAD_OPT", "notify.transports.httpJson: opts must be { url, ... }");
  }
  validateOpts.requireNonEmptyString(opts.url, "notify.transports.httpJson: url", NotifyError, "BAD_OPT");
  var allowedProtocols = opts.allowHttp ? safeUrl.ALLOW_HTTP_ALL : safeUrl.ALLOW_HTTP_TLS;
  var allowInternal = opts.allowInternal != null ? opts.allowInternal : null;
  // Validate URL at create time so bad URLs surface at boot, not at first send.
  safeUrl.parse(opts.url, { allowedProtocols: allowedProtocols, errorClass: NotifyError });

  var method = opts.method || "POST";
  var bodyFormat = opts.bodyFormat || "json";
  if (bodyFormat !== "json" && bodyFormat !== "form") {
    throw _err("BAD_OPT", "notify.transports.httpJson: bodyFormat must be 'json' or 'form'");
  }
  var staticHeaders = opts.headers || {};
  var signing = opts.signing || null;
  if (signing && typeof signing.sign !== "function") {
    throw _err("BAD_OPT", "notify.transports.httpJson: signing must have a sign(body) function");
  }
  var successStatus = (typeof opts.successStatus === "function")
    ? opts.successStatus
    : function (s) { return typeof s === "number" && s >= 200 && s < 300; };
  var customClient = opts.httpClient || null;
  var name = opts.name || "httpJson";

  return {
    name: name,
    send: async function (message, sendOpts) {
      var client = customClient || httpClient();
      var body;
      var contentType;
      if (bodyFormat === "form") {
        body = new URLSearchParams(message || {}).toString();
        contentType = "application/x-www-form-urlencoded";
      } else {
        body = JSON.stringify(message || {});
        contentType = "application/json";
      }
      var headers = Object.assign({ "Content-Type": contentType }, staticHeaders);
      if (sendOpts && sendOpts.headers) Object.assign(headers, sendOpts.headers);
      if (signing) {
        // signing.sign(body) returns either a headers object or a string.
        // The shape mirrors b.webhook.signer outputs so operators can plug
        // a webhook signer in directly.
        var signed = signing.sign(body);
        if (signed && typeof signed === "object" && !Array.isArray(signed)) {
          if (signed.headers) Object.assign(headers, signed.headers);
          else Object.assign(headers, signed);
        }
      }
      var startedAt = Date.now();
      var res = await client.request({
        method:           method,
        url:              opts.url,
        headers:          headers,
        body:             body,
        allowedProtocols: allowedProtocols,
        allowInternal:    allowInternal,
        errorClass:       NotifyError,
      });
      var status = (res && (res.statusCode || res.status)) || 0;
      if (!successStatus(status)) {
        // Throw a plain Error (not NotifyError) so b.retry.isRetryable
        // can classify on err.statusCode. NotifyError is alwaysPermanent
        // by design — wrapping a 429 in it would tell retry "don't try
        // again" before retry's HTTP-status classifier ever runs.
        // We only convert to NotifyError after retry exhaustion (in the
        // caller), which is when the error truly IS permanent.
        var httpErr = new Error(
          "notify.httpJson: " + opts.url + " responded " + status);
        httpErr.code = "HTTP_FAILURE";
        httpErr.statusCode = status;
        throw httpErr;
      }
      return {
        id:         null,
        status:     "delivered",
        attempts:   1,
        durationMs: Date.now() - startedAt,
        response:   res,
      };
    },
  };
}

// log — fire-and-forget developer logger. Never throws; audit + obs still emit.
function logTransport(opts) {
  opts = opts || {};
  // logModule.boot() returns a callable with .info / .warn / .error
  // attached; that shape satisfies the operator-supplied opts.logger
  // contract directly. No fallback wrapper needed.
  var logger;
  if (opts.logger && typeof opts.logger.info === "function") {
    logger = opts.logger;
  } else {
    logger = logModule.boot("notify.log");
  }
  return {
    name: opts.name || "log",
    send: async function (message, _sendOpts) {
      try { logger.info(JSON.stringify(message)); }
      catch (_e) { /* logger best-effort */ }
      return { id: null, status: "delivered", attempts: 1, durationMs: 0 };
    },
  };
}

// test — captures sends to .sent for fixture inspection. Never throws.
function testTransport() {
  var sent = [];
  return {
    name: "test",
    sent: sent,
    send: async function (message, sendOpts) {
      sent.push({
        message: message,
        sendOpts: sendOpts || null,
        sentAt:   Date.now(),
      });
      return { id: null, status: "delivered", attempts: 1, durationMs: 0 };
    },
    clear: function () { sent.length = 0; },
  };
}

// ---- Public create ----

/**
 * @primitive b.notify.create
 * @signature b.notify.create(opts)
 * @since     0.6.0
 * @status    stable
 * @compliance soc2, gdpr
 * @related   b.notify.transports.httpJson
 *
 * Build a dispatcher bound to a set of named channels. Returns
 * `{ send, sendBatch, queue, addChannel, channels, transport }`:
 * `send` delivers one message through one channel with the full retry /
 * timeout / breaker / span+counter / audit stack; `sendBatch` settles
 * each input independently so one channel down doesn't fail the rest;
 * `queue` enqueues onto a `b.queue` handle for out-of-band delivery;
 * `addChannel` registers a new channel post-construction;
 * `channels()` lists registered names; `transport(name)` exposes the
 * raw transport handle for diagnostics. Each channel entry is either
 * a transport object directly (`{ send, name? }`) or a config wrapper
 * (`{ transport, retry?, breaker?, timeoutMs?, serialize? }`) so
 * operators tune retry / breaker / timeout / serialize per channel.
 *
 * @opts
 *   channels:         { [name]: transport | { transport, retry?, breaker?, timeoutMs?, serialize? } },
 *   audit:            object,                          // b.audit handle
 *   auditSuccess:     boolean,                         // default true
 *   auditFailures:    boolean,                         // default true
 *   redact:           function (message) => any,       // default b.redact.redact
 *   defaultTimeoutMs: number,                          // default 30s, 0 disables
 *   defaultRetry:     object,                          // b.retry.withRetry opts
 *   defaultBreaker:   object,                          // b.retry.CircuitBreaker opts
 *   queue:            { enqueue(name, payload), registerHandler? },
 *   clock:            function () => number,           // ms
 *
 * @example
 *   var b = require("@blamejs/core");
 *   var notify = b.notify.create({
 *     channels: {
 *       slack: b.notify.transports.httpJson({ url: "https://hooks.slack.com/services/T0/B0/X" }),
 *       log:   b.notify.transports.log(),
 *     },
 *   });
 *   // → { send, sendBatch, queue, addChannel, channels, transport }
 */
function create(opts) {
  opts = opts || {};
  validateOpts(opts, [
    "channels", "audit", "auditSuccess", "auditFailures",
    "redact", "defaultTimeoutMs", "defaultRetry", "defaultBreaker",
    "queue", "clock",
  ], "notify");
  _validateCreateOpts(opts);
  var cfg = validateOpts.applyDefaults(opts, DEFAULTS);

  var auditSuccess  = cfg.auditSuccess;
  var auditFailures = cfg.auditFailures;
  var audit = opts.audit || null;
  var redactFn = (typeof opts.redact === "function")
    ? opts.redact
    // Default: b.redact.redact — the framework's PII detector chain.
    : function (m) { return redact().redact(m); };
  var defaultTimeoutMs = cfg.defaultTimeoutMs;
  var defaultRetry = opts.defaultRetry || null;
  var defaultBreaker = opts.defaultBreaker || null;
  var operatorQueue = opts.queue || null;
  var clock = opts.clock || function () { return Date.now(); };

  // Build channel registry: name → { transport, retry, breaker, timeoutMs, serialize, mutex? }
  var channels = {};
  var channelNames = Object.keys(opts.channels);
  for (var i = 0; i < channelNames.length; i++) {
    var n = channelNames[i];
    var entry = _validateChannelEntry(n, opts.channels[n]);
    var registry = {
      transport: entry.transport,
      retry:     entry.retry || defaultRetry,
      timeoutMs: (entry.timeoutMs === null) ? defaultTimeoutMs : entry.timeoutMs,
      breaker:   null,
      mutex:     null,
    };
    var breakerOpts = entry.breaker || defaultBreaker;
    if (breakerOpts) {
      registry.breaker = new (retryHelper().CircuitBreaker)(n, breakerOpts);
    }
    if (entry.serialize) registry.mutex = new safeAsync.Mutex();
    channels[n] = registry;
  }

  var _emitAudit = validateOpts.makeAuditEmitter(audit);

  function _actor(callerOpts) {
    return requestHelpers.resolveActorWithOverride(callerOpts);
  }

  function _redactedMetadata(channel, message, extra) {
    var redactedMessage;
    try { redactedMessage = redactFn(message); }
    catch (_e) { redactedMessage = "[redact-failed]"; }
    return Object.assign({
      channel:  channel,
      message:  redactedMessage,
    }, extra || {});
  }

  // Send a single message to one channel. The whole call is wrapped in
  // observability.tap (span+counter), inside which we layer:
  //
  //   withRetry( withTimeout( breaker.wrap( transport.send ) ) )
  //
  // Each layer comes from an existing primitive — notify never
  // re-implements retry / timeout / breaker / span+counter logic.
  async function send(input) {
    if (!input || typeof input !== "object") {
      throw _err("BAD_OPT", "notify.send: input must be { channel, message, ... }");
    }
    if (typeof input.channel !== "string" || input.channel.length === 0) {
      throw _err("BAD_OPT", "notify.send: channel must be a non-empty string");
    }
    if (input.message === undefined || input.message === null) {
      throw _err("MISSING_MESSAGE", "notify.send: message is required");
    }
    var channel = input.channel;
    var entry = channels[channel];
    if (!entry) {
      throw _err("NO_CHANNEL", "notify.send: unknown channel '" + channel + "'");
    }
    var perCallTimeoutMs = (input.timeoutMs !== undefined) ? input.timeoutMs : entry.timeoutMs;
    var perCallRetry = input.retry || entry.retry;
    var message = input.message;

    var attemptCount = 0;
    var startedAt = clock();
    var transport = entry.transport;
    var transportName = transport.name || channel;

    // The retryable single attempt. Each call to this function is one
    // transport.send invocation (so withRetry's loop is the only retry
    // mechanism — no double-retry inside the breaker or transport).
    async function _oneAttempt(attemptIdx) {
      attemptCount = attemptIdx;
      observability().safeEvent("notify.send.attempt", 1, { channel: channel, attempt: attemptIdx });
      var sendPromise = entry.transport.send(message, input.sendOpts || null);
      // withTimeout from b.safeAsync — never re-implement timer races.
      var timed = (perCallTimeoutMs > 0)
        ? safeAsync.withTimeout(sendPromise, perCallTimeoutMs, { name: "notify." + channel })
        : sendPromise;
      try {
        return await timed;
      } catch (e) {
        // Map withTimeout's async/timeout into a transient error so retry
        // classifies it correctly (operators can still opt OUT by setting
        // err.permanent in their transport).
        if (e && e.code === "async/timeout") {
          observability().safeEvent("notify.send.timeout", 1, { channel: channel });
          var te = _err("TIMEOUT",
            "notify.send: '" + channel + "' transport timed out after " + perCallTimeoutMs + "ms");
          // Mark transient via a NETWORK-style code so b.retry.isRetryable
          // routes it through the retry path.
          te.code = "ETIMEDOUT";
          throw te;
        }
        throw e;
      }
    }

    // Wrap each attempt with the breaker, if configured.
    async function _attemptWithBreaker(attemptIdx) {
      if (entry.breaker) {
        try {
          return await entry.breaker.wrap(function () { return _oneAttempt(attemptIdx); });
        } catch (e) {
          if (e && e.code === "CIRCUIT_OPEN") {
            observability().safeEvent("notify.send.breaker.open", 1, { channel: channel });
          }
          throw e;
        }
      }
      return _oneAttempt(attemptIdx);
    }

    // Optional serialize: only one in-flight send per channel at a time.
    async function _attemptSerialized(attemptIdx) {
      if (!entry.mutex) return _attemptWithBreaker(attemptIdx);
      await entry.mutex.acquire();
      try { return await _attemptWithBreaker(attemptIdx); }
      finally { entry.mutex.release(); }
    }

    // Outer span+counter wrapping via b.observability.tap so a single call
    // produces both a span (under the operator's tracer) AND a counter.
    return observability().tap("notify.send", { channel: channel }, async function () {
      try {
        // b.retry.withRetry IS the retry loop. Notify never hand-rolls
        // backoff/jitter/classification — the framework owns it.
        var result = await retryHelper().withRetry(function (attempt) {
          return _attemptSerialized(attempt);
        }, perCallRetry);

        var durationMs = clock() - startedAt;
        observability().safeEvent("notify.send.success", 1, { channel: channel, durationMs: durationMs });
        if (auditSuccess) {
          _emitAudit("notify.send.success", {
            actor:    _actor(input),
            resource: { kind: "notify.channel", id: channel },
            outcome:  "success",
            metadata: _redactedMetadata(channel, message, {
              transport:  transportName,
              attempts:   attemptCount,
              durationMs: durationMs,
            }),
          });
        }
        return Object.assign({}, result, {
          channel:    channel,
          attempts:   attemptCount,
          durationMs: durationMs,
        });
      } catch (e) {
        observability().safeEvent("notify.send.failure", 1, {
          channel: channel,
          reason:  (e && e.code) || "unknown",
        });
        if (auditFailures) {
          _emitAudit("notify.send.failure", {
            actor:    _actor(input),
            resource: { kind: "notify.channel", id: channel },
            outcome:  "failure",
            reason:   (e && e.code) || "send-failed",
            metadata: _redactedMetadata(channel, message, {
              transport: transportName,
              attempts:  attemptCount,
              message_:  (e && e.message) || String(e),
            }),
          });
        }
        // If the error is already a NotifyError, propagate verbatim.
        // Otherwise wrap so callers always catch a single class while
        // keeping the cause chain.
        if (e && e.isNotifyError) throw e;
        var wrapped = _err("SEND_FAILED",
          "notify.send: '" + channel + "' failed after " + attemptCount + " attempt(s): " +
          ((e && e.message) || String(e)));
        wrapped.cause = e;
        if (e && typeof e.statusCode === "number") wrapped.statusCode = e.statusCode;
        throw wrapped;
      }
    });
  }

  // sendBatch: settle each input independently. One channel down doesn't
  // fail the whole batch; the result array carries either the success
  // shape OR a NotifyError for each input position.
  async function sendBatch(inputs) {
    if (!Array.isArray(inputs)) {
      throw _err("BAD_OPT", "notify.sendBatch: inputs must be an array");
    }
    var promises = inputs.map(function (input) {
      return send(input).then(
        function (result) { return result; },
        function (err)    { return err; }
      );
    });
    var results = await Promise.all(promises);
    var ok = 0;
    var failed = 0;
    for (var i = 0; i < results.length; i++) {
      if (results[i] && results[i].isNotifyError) failed++;
      else ok++;
    }
    observability().safeEvent("notify.batch", 1, { size: inputs.length, ok: ok, failed: failed });
    return results;
  }

  // queue: enqueue an async send onto the operator's b.queue. Requires a
  // queue handle wired at create() OR per-call. Notify registers a
  // default handler for `notifyQueueName` on first use.
  var _queueHandlerRegistered = {};
  async function queue(input, queueOpts) {
    queueOpts = queueOpts || {};
    var q = queueOpts.queue || operatorQueue;
    if (!q || typeof q.enqueue !== "function") {
      throw _err("NO_QUEUE", "notify.queue: requires a b.queue handle (pass at create or per-call)");
    }
    if (!input || typeof input !== "object" || typeof input.channel !== "string") {
      throw _err("BAD_OPT", "notify.queue: input must be { channel, message, ... }");
    }
    var queueName = queueOpts.queueName || "notify";
    // Handler registration is operator-driven for the b.queue primitive
    // — operators have their own worker boot. We don't try to start
    // workers here. The handler signature follows b.jobs / b.queue
    // conventions: receives { input } and re-invokes notify.send.
    if (!_queueHandlerRegistered[queueName] && typeof q.registerHandler === "function") {
      try {
        q.registerHandler(queueName, async function (job) {
          var payload = (job && job.payload) || job;
          return send(payload);
        });
        _queueHandlerRegistered[queueName] = true;
      } catch (_e) { /* operator may register their own handler */ }
    }
    var jobId = await q.enqueue(queueName, input);
    observability().safeEvent("notify.queue.enqueued", 1, { channel: input.channel, queueName: queueName });
    return { jobId: jobId };
  }

  function addChannel(name, transport, channelOpts) {
    if (channels[name]) {
      throw _err("CHANNEL_EXISTS", "notify.addChannel: channel '" + name + "' already exists");
    }
    channelOpts = channelOpts || {};
    var entry = _validateChannelEntry(name,
      channelOpts.transport || channelOpts.send || transport
        ? Object.assign({ transport: transport }, channelOpts)
        : transport);
    var registry = {
      transport: entry.transport,
      retry:     entry.retry || defaultRetry,
      timeoutMs: (entry.timeoutMs === null) ? defaultTimeoutMs : entry.timeoutMs,
      breaker:   null,
      mutex:     null,
    };
    var breakerOpts = entry.breaker || defaultBreaker;
    if (breakerOpts) registry.breaker = new (retryHelper().CircuitBreaker)(name, breakerOpts);
    if (entry.serialize) registry.mutex = new safeAsync.Mutex();
    channels[name] = registry;
  }

  function listChannels() {
    return Object.keys(channels);
  }

  function transportFor(name) {
    var entry = channels[name];
    return entry ? entry.transport : null;
  }

  return {
    send:         send,
    sendBatch:    sendBatch,
    queue:        queue,
    addChannel:   addChannel,
    channels:     listChannels,
    transport:    transportFor,
  };
}

module.exports = {
  create:      create,
  NotifyError: NotifyError,
  DEFAULTS:    DEFAULTS,
  transports: {
    httpJson: httpJson,
    log:      logTransport,
    test:     testTransport,
  },
};
