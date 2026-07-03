// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * createApp — factory that wires the framework's primitives into a
 * runnable application.
 *
 * Without this factory an operator boots the framework manually:
 *
 *   await b.vault.init({...});
 *   if (cluster mode)  b.externalDb.init({...});
 *   if (cluster mode)  await b.cluster.init({...});
 *   if (cluster mode)  await b.frameworkSchema.ensureSchema({...});
 *   await b.db.init({...});
 *   var r = new b.router.Router();
 *   r.use(b.middleware.requestId());
 *   r.use(b.middleware.securityHeaders());
 *   r.use(b.middleware.botGuard());
 *   yourRoutes(r);
 *   r.onError(b.middleware.errorHandler());
 *   var server = r.listen(port, ...);
 *
 * createApp collapses that into:
 *
 *   var app = await createApp({
 *     dataDir:   "./data",
 *     schema:    [...],
 *     routes:    function (r) { r.get("/", ...); },
 *   });
 *   await app.listen({ port: 3000 });
 *
 * Each underlying module remains accessible (b.vault, b.db, b.cluster,
 * etc.) — createApp doesn't hide them, it just orchestrates the
 * dependency-ordered boot.
 *
 * Boot order is fixed because the dependency graph is fixed:
 *
 *   vault.init        — derives encryption keys
 *      ↓
 *   externalDb.init   — connection pool (cluster mode only)
 *      ↓
 *   cluster.init      — leader election, fencing token (opt-in)
 *      ↓
 *   frameworkSchema   — audit/consent/sessions/queue tables
 *     .ensureSchema     in external-db when cluster mode (opt-in;
 *                       skip when operator wants gates-only)
 *      ↓
 *   db.init           — local SQLite + audit chain verify + audit
 *                       checkpoint verify + audit-tip rollback check
 *                       (single-node) or cluster boot checks (cluster)
 *      ↓
 *   router.Router()
 *   middleware stack mounted in canonical order
 *   operator routes registered
 *   error handler attached via router.onError()
 *
 * Default middleware: requestId + securityHeaders + botGuard +
 * errorHandler (mounted as the route-error catcher). cors and
 * rateLimit are opt-in only — both require explicit configuration
 * (origins, thresholds) that the framework can't sensibly default.
 *
 * Operators disable any default middleware by passing
 * `middleware: { requestId: false, securityHeaders: false, ... }`.
 *
 * Public API:
 *
 *   await createApp(opts)  →  app
 *
 *   app.router             — the b.router.Router instance (operator
 *                            adds late routes / inspects state)
 *   app.db, app.vault      — re-exports for convenience; nothing app-
 *                            specific lives on these
 *
 *   await app.listen(opts2?)
 *     opts2.port  (default opts.port, then 0 = ephemeral)
 *     opts2.host  (default opts.host, then unspecified)
 *     opts2.tls   (TLS options forwarded to router.listen — h2 + h1)
 *     → { port, host, server }   the bound port + the underlying
 *                                 http(s).Server instance for ops use
 *
 *   app.address()
 *     → { port, host } | null    bound socket info post-listen
 *
 *   await app.shutdown()
 *     Closes WebSockets gracefully (timeoutMs default 5s), closes
 *     the http server, then unwinds cluster / db / externalDb.
 *     Idempotent — safe to call repeatedly.
 *
 * Validation: opts.dataDir is required. Other config is optional with
 * documented defaults. Schema is optional too — apps with no app-
 * level tables still get the framework tables (sessions, queue jobs,
 * audit_log, consent_log).
 */
var nodeFs = require("node:fs");
var nodePath = require("node:path");
var appShutdown = require("./app-shutdown");
var audit = require("./audit");
var validateOpts = require("./validate-opts");
var C = require("./constants");
var cluster = require("./cluster");
var db = require("./db");
var externalDb = require("./external-db");
var frameworkSchema = require("./framework-schema");
var jobsMod = require("./jobs");
var middleware = require("./middleware");
var queue = require("./queue");
var routerMod = require("./router");
var vault = require("./vault");

function _resolveMiddlewareOpt(value, allowDefault, name) {
  // value can be:
  //   false          — operator opted out
  //   undefined      — fall back to allowDefault (mount with empty opts)
  //   true           — explicit opt-in with default opts
  //   object         — explicit opts
  if (value === false) {
    // Operator explicitly disabled this middleware. When it's one of the
    // security-on-by-default layers (allowDefault), leave an audit trace
    // so the weakened posture is visible — security defaults
    // shouldn't be silently opt-out-able. Drop-silent observability sink.
    if (allowDefault && name) {
      try {
        audit.safeEmit({
          action:   "app.middleware.disabled",
          outcome:  "success",
          metadata: { middleware: name },
        });
      } catch (_e) { /* drop-silent — by design */ }
    }
    return null;
  }
  if (value === undefined) return allowDefault ? {} : null;
  if (value === true) return {};
  if (value && typeof value === "object") return value;
  return null;
}

async function createApp(opts) {
  if (!opts || typeof opts !== "object") {
    throw new Error("createApp: opts object is required");
  }
  if (!opts.dataDir || typeof opts.dataDir !== "string") {
    throw new Error("createApp: opts.dataDir is required");
  }
  // Constructor-time default port (used by listen() when listenOpts.port is
  // omitted); allowZero for the ephemeral-bind sentinel.
  validateOpts.optionalPort(opts.port, "createApp: opts.port", undefined, undefined, { allowZero: true });
  var dataDir = nodePath.resolve(opts.dataDir);
  if (!nodeFs.existsSync(dataDir)) {
    nodeFs.mkdirSync(dataDir, { recursive: true });
  }

  // ---- 1. Vault ----
  var vaultOpts = Object.assign({ dataDir: dataDir }, opts.vault || {});
  if (!vaultOpts.mode) vaultOpts.mode = "wrapped";
  await vault.init(vaultOpts);

  // ---- 2. External DB (cluster mode) ----
  if (opts.externalDb) {
    externalDb.init(opts.externalDb);
  }

  // ---- 3. Cluster (opt-in) ----
  if (opts.cluster) {
    // Schema needs to exist before cluster.init's boot-time rollback
    // check tries to read _blamejs_audit_tip — if cluster has an
    // externalDbBackend AND the operator hasn't disabled the schema
    // step, ensure schemas first.
    if (opts.cluster.externalDbBackend && opts.frameworkSchema !== false) {
      await frameworkSchema.ensureSchema({
        externalDbBackend: opts.cluster.externalDbBackend,
        dialect:           opts.cluster.dialect || "postgres",
      });
    }
    await cluster.init(opts.cluster);
  }

  // ---- 4. Local DB ----
  var dbOpts = Object.assign({
    dataDir: dataDir,
    schema:  opts.schema || [],
  }, opts.db || {});
  await db.init(dbOpts);

  // ---- 5. Jobs (opt-in) ----
  // Operator-supplied callback that defines named handlers. We boot
  // queue with a default 'local' backend (the framework's built-in
  // SQLite-backed protocol) before invoking the callback. Operators
  // who want a different backend pass opts.queue: { backends: { … } }
  // and skip opts.jobs, then wire jobs themselves.
  var jobsInstance = null;
  if (typeof opts.jobs === "function") {
    var queueConfig = opts.queue || { backends: { primary: { protocol: "local" } } };
    queue.init(queueConfig);
    jobsInstance = jobsMod.create(opts.jobsOptions || {});
    opts.jobs(jobsInstance);
    await jobsInstance.start();
  } else if (opts.queue) {
    // Operator wants queue without the jobs sugar (rare, but legitimate
    // — they'll call queue.consume themselves).
    queue.init(opts.queue);
  }

  // ---- 6. Router + middleware ----
  var router = new routerMod.Router();
  var mwConfig = opts.middleware || {};

  // Shutdown orchestrator. Created early so its drain-guard middleware
  // mounts as the first middleware in the chain — once shutdown begins,
  // every new request gets 503 immediately. Standard phases are wired
  // below once we know which components exist; the operator's
  // beforeStop / afterDrain hooks slot in around drain-in-flight.
  var shutdownOpts = opts.shutdown || {};
  var orchestrator = appShutdown.create({
    graceMs:               shutdownOpts.graceMs,
    installSignalHandlers: !!shutdownOpts.installSignalHandlers,
    phases:                [],
  });
  router.use(orchestrator.middleware());

  var requestIdOpts = _resolveMiddlewareOpt(mwConfig.requestId, true, "requestId");
  if (requestIdOpts) router.use(middleware.requestId(requestIdOpts));

  var securityHeadersOpts = _resolveMiddlewareOpt(mwConfig.securityHeaders, true, "securityHeaders");
  if (securityHeadersOpts) router.use(middleware.securityHeaders(securityHeadersOpts));

  var corsOpts = _resolveMiddlewareOpt(mwConfig.cors, false, "cors");
  if (corsOpts) router.use(middleware.cors(corsOpts));

  var botGuardOpts = _resolveMiddlewareOpt(mwConfig.botGuard, true, "botGuard");
  if (botGuardOpts) router.use(middleware.botGuard(botGuardOpts));

  var rateLimitOpts = _resolveMiddlewareOpt(mwConfig.rateLimit, false, "rateLimit");
  if (rateLimitOpts) router.use(middleware.rateLimit(rateLimitOpts));

  // Security middleware wired ON by default. Each reads its
  // config from opts.middleware.<name>: pass `false` to opt out (audited
  // via _resolveMiddlewareOpt), or an object to customize — operator cookie
  // / field names flow straight through, nothing static is baked in.
  // Ordered so each layer has what it needs: cookies + cspNonce +
  // fetchMetadata first, then bodyParser (so csrf can read a body-field
  // token), then csrfProtect last. Every layer is idempotent — if an
  // operator also mounts one of these inside opts.routes, the second mount
  // is a no-op rather than a double-apply.
  var cookiesOpts = _resolveMiddlewareOpt(mwConfig.cookies, true, "cookies");
  if (cookiesOpts) router.use(middleware.cookies(cookiesOpts));

  var cspNonceOpts = _resolveMiddlewareOpt(mwConfig.cspNonce, true, "cspNonce");
  if (cspNonceOpts) router.use(middleware.cspNonce(cspNonceOpts));

  var fetchMetadataOpts = _resolveMiddlewareOpt(mwConfig.fetchMetadata, true, "fetchMetadata");
  if (fetchMetadataOpts) router.use(middleware.fetchMetadata(fetchMetadataOpts));

  var bodyParserOpts = _resolveMiddlewareOpt(mwConfig.bodyParser, true, "bodyParser");
  if (bodyParserOpts) router.use(middleware.bodyParser(bodyParserOpts));

  var csrfOpts = _resolveMiddlewareOpt(mwConfig.csrf, true, "csrf");
  if (csrfOpts) {
    // Defaults: double-submit cookie (unless the operator chose a token
    // lookup or their own cookie config) + skip validation for stateless
    // token-API / cookieless requests. Operator config overrides both.
    var csrfDefaults = { skipStateless: true };
    if (csrfOpts.tokenLookup === undefined && csrfOpts.cookie === undefined) {
      csrfDefaults.cookie = true;
    }
    csrfOpts = Object.assign(csrfDefaults, csrfOpts);
    router.use(middleware.csrfProtect(csrfOpts));
  }

  // ---- 6. Operator routes ----
  if (typeof opts.routes === "function") {
    opts.routes(router);
  }

  // ---- 7. Error handler — last so it catches everything ----
  var errorHandlerOpts = _resolveMiddlewareOpt(mwConfig.errorHandler, true);
  if (errorHandlerOpts) {
    router.onError(middleware.errorHandler(errorHandlerOpts));
  }

  // ---- App handle ----
  var server = null;
  var listenPort = null;
  var listenHost = null;

  function listen(listenOpts) {
    listenOpts = listenOpts || {};
    // Port 0 is the legitimate ephemeral-bind sentinel for a listen socket
    // (RFC 6335 §6 / POSIX bind), so allowZero — but a non-integer / NaN /
    // out-of-range port is an operator typo that must fail at boot.
    validateOpts.optionalPort(listenOpts.port, "createApp.listen: listenOpts.port", undefined, undefined, { allowZero: true });
    var port = (listenOpts.port !== undefined) ? listenOpts.port
             : (opts.port !== undefined) ? opts.port
             : 0;
    var host = listenOpts.host || opts.host;
    var tls  = listenOpts.tls  || opts.tls;
    return new Promise(function (resolve, reject) {
      try {
        server = router.listen(port, function () {
          var addr = server.address();
          if (addr && typeof addr === "object") {
            listenPort = addr.port;
            listenHost = addr.address;
          }
          // Now that we know the server, finalize shutdown phases.
          _wireShutdownPhases();
          resolve({ port: listenPort, host: listenHost, server: server });
        }, tls, host);
      } catch (e) { reject(e); }
    });
  }

  function address() {
    if (!server) return null;
    return { port: listenPort, host: listenHost };
  }

  // Wire the standard shutdown phases. Called from listen() so the
  // server reference is live; idempotent so listen() can be called
  // multiple times without duplicating phases.
  var phasesWired = false;
  function _wireShutdownPhases() {
    if (phasesWired) return;
    phasesWired = true;

    // Operator beforeStop hook (runs before anything else, including
    // mark-draining — useful for snapshotting state, posting a
    // "going down" event to a metrics pipeline, etc.)
    if (typeof shutdownOpts.beforeStop === "function") {
      orchestrator.addPhase({
        name: "beforeStop",
        run:  shutdownOpts.beforeStop,
        timeoutMs: shutdownOpts.beforeStopTimeoutMs || C.TIME.seconds(5),
      });
    }

    // Drain in-flight requests phase. Mount FIRST among framework
    // phases so we drain before stopping subsystems jobs depend on.
    orchestrator.addPhase({
      name: "drain-in-flight",
      run:  orchestrator.waitInFlight,
      timeoutMs: shutdownOpts.drainTimeoutMs || C.TIME.seconds(10),
    });

    if (typeof shutdownOpts.afterDrain === "function") {
      orchestrator.addPhase({
        name: "afterDrain",
        run:  shutdownOpts.afterDrain,
        timeoutMs: shutdownOpts.afterDrainTimeoutMs || C.TIME.seconds(5),
      });
    }

    // Standard component phases (scheduler, jobs, websocket, server,
    // cluster, db, external-db) in canonical order. The http-server
    // phase is built manually below so we can null the local `server`
    // ref after close — operators expect address() to return null
    // after shutdown.
    var standard = appShutdown.standardPhases({
      health:     shutdownOpts.health || null,
      scheduler:  shutdownOpts.scheduler || null,
      jobs:       jobsInstance,
      queue:      jobsInstance ? null : (opts.queue ? queue : null),
      router:     router,
      // Omit server here; we add a custom phase below that also
      // clears the local server reference.
      server:     null,
      cluster:    opts.cluster ? cluster : null,
      db:         db,
      externalDb: opts.externalDb ? externalDb : null,
    });
    // Insert the http-server phase right after websockets (mirrors
    // standardPhases ordering: websockets → http-server → cluster → db).
    if (server) {
      var httpServerPhase = {
        name: "http-server",
        run:  function () {
          return new Promise(function (resolve) {
            if (!server) { resolve(); return; }
            server.close(function () {
              server = null;     // address() now returns null
              listenPort = null;
              listenHost = null;
              resolve();
            });
          });
        },
        timeoutMs: C.TIME.seconds(10),
      };
      // Find the index right after the "websockets" phase if present;
      // otherwise prepend before "cluster" (or just push to end if
      // those phases aren't there either).
      var insertAt = standard.findIndex(function (p) { return p.name === "websockets"; });
      if (insertAt === -1) insertAt = standard.findIndex(function (p) { return p.name === "cluster"; });
      if (insertAt === -1) insertAt = standard.length;
      else insertAt += (standard[insertAt].name === "websockets") ? 1 : 0;
      standard.splice(insertAt, 0, httpServerPhase);
    }
    for (var i = 0; i < standard.length; i++) {
      orchestrator.addPhase(standard[i]);
    }
  }

  async function shutdown() {
    // If listen() was never called, wire phases now so a server-less
    // app (e.g. a worker process that uses the framework's primitives
    // without HTTP) still gets cluster/db/jobs cleanup.
    _wireShutdownPhases();
    return await orchestrator.shutdown();
  }

  return {
    router:    router,
    db:        db,
    vault:     vault,
    jobs:      jobsInstance,
    listen:    listen,
    address:   address,
    shutdown:  shutdown,
    // Expose the orchestrator for power users / observability — they
    // can read draining(), inFlight(), or addPhase before listen().
    shutdownOrchestrator: orchestrator,
  };
}

module.exports = { createApp: createApp };
