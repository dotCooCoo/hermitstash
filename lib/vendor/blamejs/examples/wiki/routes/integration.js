"use strict";
/**
 * Integration-test routes — mounted ONLY when WIKI_INTEGRATION_TEST=1.
 * Exposes a thin HTTP surface over a curated set of framework primitives
 * so the wiki integration suite can drive each backend through a real
 * app context rather than a unit-test harness.
 *
 * Every route uses the SAME framework module instance the rest of the
 * wiki uses, so a configuration change (e.g. queue.bootFromEnv pointing
 * at Redis) is reflected here automatically — the integration test
 * therefore validates the wiki's actual operational wiring, not a
 * parallel test-only setup.
 *
 * Routes are namespaced under /test/ to keep them well-separated from
 * production paths. The mount-gate (WIKI_INTEGRATION_TEST=1) is the
 * sole defense — production deploys must NEVER set this env var. The
 * wiki app refuses to mount these routes otherwise, even if reached
 * through a misrouted request.
 */
var b = require("@blamejs/core");

// Per-request body cap for the integration test routes — large enough
// to carry test payloads (cache values, mail bodies, base64-encoded
// object-store blobs) but bounded so a malformed body never grows
// unbounded in memory.
var INTEGRATION_BODY_LIMIT = b.constants.BYTES.mib(1);

function _readJsonBody(req) {
  return new Promise(function (resolve, reject) {
    if (req.body && typeof req.body === "object") { resolve(req.body); return; }
    var chunks = [];
    req.on("data", function (c) { chunks.push(c); });
    req.on("end", function () {
      var raw = Buffer.concat(chunks).toString("utf8");
      if (!raw) return resolve({});
      try { resolve(b.safeJson.parse(raw, { maxBytes: INTEGRATION_BODY_LIMIT })); }
      catch (e) { reject(e); }
    });
    req.on("error", reject);
  });
}

function _send(res, status, body) {
  res.statusCode = status;
  res.setHeader("content-type", "application/json");
  res.end(JSON.stringify(body));
}

function register(router, ctx) {
  // ---- Diagnostic — surfaces the active backend posture ----
  router.get("/test/diagnostic", function (req, res) {
    var snap = {};
    try { snap.network = b.network.snapshot(); } catch (_e) { snap.network = null; }
    try { snap.queue = b.queue.listBackends ? b.queue.listBackends() : null; } catch (_e) { snap.queue = null; }
    try { snap.logSinks = b.logStream.listSinks ? b.logStream.listSinks() : null; } catch (_e) { snap.logSinks = null; }
    try { snap.mtlsCa = ctx.mtlsCa && ctx.mtlsCa.status ? ctx.mtlsCa.status() : null; } catch (_e) { snap.mtlsCa = null; }
    snap.frameworkVersion = b.version;
    snap.integrationTestMode = b.safeEnv.readVar("WIKI_INTEGRATION_TEST", { type: "boolean", default: false });
    _send(res, 200, snap);
  });

  // ---- Cache: set / get / delete ----
  router.post("/test/cache/set", async function (req, res) {
    try {
      var body = await _readJsonBody(req);
      if (!body.key || typeof body.key !== "string") {
        return _send(res, 400, { error: "key required" });
      }
      await ctx.testCache.set(body.key, body.value, { ttlMs: body.ttlMs || b.constants.TIME.minutes(1) });
      _send(res, 200, { ok: true });
    } catch (e) { _send(res, 500, { error: e.message, code: e.code }); }
  });
  router.get("/test/cache/get", async function (req, res) {
    try {
      var key = (req.query && req.query.key) || "";
      var v = await ctx.testCache.get(key);
      _send(res, 200, { value: v === undefined ? null : v });
    } catch (e) { _send(res, 500, { error: e.message, code: e.code }); }
  });
  router.post("/test/cache/del", async function (req, res) {
    try {
      var body = await _readJsonBody(req);
      await ctx.testCache.del(body.key);
      _send(res, 200, { ok: true });
    } catch (e) { _send(res, 500, { error: e.message, code: e.code }); }
  });

  // ---- Queue: enqueue / size ----
  router.post("/test/queue/enqueue", async function (req, res) {
    try {
      var body = await _readJsonBody(req);
      var rv = await b.queue.enqueue(body.queueName || "test-q", body.payload || {}, {
        availableAt:  body.availableAt,
        delaySeconds: body.delaySeconds,
        maxAttempts:  body.maxAttempts,
      });
      _send(res, 200, { jobId: rv.jobId, queueName: rv.queueName });
    } catch (e) { _send(res, 500, { error: e.message, code: e.code }); }
  });
  router.get("/test/queue/size", async function (req, res) {
    try {
      var queueName = (req.query && req.query.queueName) || "test-q";
      var size = await b.queue.size(queueName);
      _send(res, 200, { size: size });
    } catch (e) { _send(res, 500, { error: e.message, code: e.code }); }
  });

  // ---- Mail: send via the configured transport ----
  router.post("/test/mail/send", async function (req, res) {
    try {
      var body = await _readJsonBody(req);
      if (!ctx.testMail) return _send(res, 503, { error: "mail transport not wired" });
      var rv = await ctx.testMail.send({
        from:    body.from    || "test@blamejs.local",
        to:      body.to      || ["recipient@example.com"],
        subject: body.subject || "wiki-integration",
        text:    body.text    || "wiki integration test message",
      });
      _send(res, 200, { transport: rv.transport, deliveredAt: rv.deliveredAt });
    } catch (e) { _send(res, 500, { error: e.message, code: e.code }); }
  });

  // ---- Object-store: put / get ----
  router.post("/test/objectstore/put", async function (req, res) {
    try {
      if (!ctx.testObjectStore) return _send(res, 503, { error: "object-store not wired" });
      var body = await _readJsonBody(req);
      if (!body.key) return _send(res, 400, { error: "key required" });
      var bytes = Buffer.from(body.bodyBase64 || "", "base64");
      var rv = await ctx.testObjectStore.put(body.key, bytes, { contentType: body.contentType || "application/octet-stream" });
      _send(res, 200, { key: body.key, size: bytes.length, etag: rv && rv.etag });
    } catch (e) { _send(res, 500, { error: e.message, code: e.code }); }
  });
  router.get("/test/objectstore/get", async function (req, res) {
    try {
      if (!ctx.testObjectStore) return _send(res, 503, { error: "object-store not wired" });
      var key = (req.query && req.query.key) || "";
      var got = await ctx.testObjectStore.get(key);
      var buf = Buffer.isBuffer(got) ? got : (got && got.body);
      _send(res, 200, { bodyBase64: Buffer.isBuffer(buf) ? buf.toString("base64") : null, size: buf && buf.length });
    } catch (e) { _send(res, 500, { error: e.message, code: e.code }); }
  });

  // ---- HTTP client (exercises ssrfGuard + httpClient pipeline) ----
  router.post("/test/http/fetch", async function (req, res) {
    try {
      var body = await _readJsonBody(req);
      var resp = await b.httpClient.request({
        method:           body.method || "GET",
        url:              body.url,
        headers:          body.headers || {},
        body:             body.body ? Buffer.from(body.body, "utf8") : undefined,
        idleTimeoutMs:    body.timeoutMs || b.constants.TIME.seconds(5),
        allowedProtocols: body.allowHttp ? b.safeUrl.ALLOW_HTTP_ALL : b.safeUrl.ALLOW_HTTP_TLS,
        allowInternal:    body.allowInternal === true,
      });
      _send(res, 200, {
        statusCode: resp.statusCode,
        headers:    resp.headers,
        body:       Buffer.isBuffer(resp.body) ? resp.body.toString("utf8") : resp.body,
      });
    } catch (e) { _send(res, 200, { error: e.message, code: e.code, statusCode: e.statusCode || null }); }
  });

  // ---- Log-stream: emit a record + drain via shutdown of a scoped sink ----
  router.post("/test/logstream/emit", async function (req, res) {
    try {
      var body = await _readJsonBody(req);
      var level = body.level || "info";
      b.logStream[level](body.message || "wiki-integration", body.meta || {});
      _send(res, 200, { ok: true });
    } catch (e) { _send(res, 500, { error: e.message, code: e.code }); }
  });

  // ---- mTLS-CA: issue a leaf cert + return its EKU ----
  router.post("/test/mtls/issue", async function (req, res) {
    try {
      var body = await _readJsonBody(req);
      if (!ctx.mtlsCa) return _send(res, 503, { error: "mtls-ca not wired" });
      var leaf = await ctx.mtlsCa.generateClientCert({
        cn:           body.cn || "wiki-integration",
        usage:        body.usage || "client",
        sans:         body.sans,
        validityDays: body.validityDays || 7,
      });
      _send(res, 200, {
        cert:      leaf.cert,
        usage:     leaf.usage,
        issuedAt:  leaf.issuedAt,
        expiresAt: leaf.expiresAt,
      });
    } catch (e) { _send(res, 500, { error: e.message, code: e.code }); }
  });

  // ---- NTP: report current drift ----
  router.get("/test/ntp/check", async function (req, res) {
    try {
      var server = (req.query && req.query.server) || "127.0.0.1";
      var port = parseInt((req.query && req.query.port) || "12300", 10);
      var rv = await b.ntpCheck.querySingle(server, { port: port, timeoutMs: b.constants.TIME.seconds(4) });
      _send(res, 200, rv);
    } catch (e) { _send(res, 500, { error: e.message, code: e.code }); }
  });

  // ---- DNS: lookup via current resolver ----
  router.get("/test/dns/lookup", async function (req, res) {
    try {
      var host = (req.query && req.query.host) || "example.com";
      var rv = await b.network.dns.lookup(host);
      _send(res, 200, rv);
    } catch (e) { _send(res, 500, { error: e.message, code: e.code }); }
  });

  // ---- SSRF guard: classify an IP / check a URL ----
  router.get("/test/ssrf/classify", function (req, res) {
    var ip = (req.query && req.query.ip) || "";
    _send(res, 200, { classification: b.ssrfGuard.classify(ip) });
  });
  router.post("/test/ssrf/check", async function (req, res) {
    try {
      var body = await _readJsonBody(req);
      var rv = await b.ssrfGuard.checkUrl(body.url, {
        allowInternal: body.allowInternal === true,
      });
      _send(res, 200, { ok: true, ips: rv.ips });
    } catch (e) { _send(res, 200, { ok: false, error: e.message, code: e.code }); }
  });
}

module.exports = { register: register };
