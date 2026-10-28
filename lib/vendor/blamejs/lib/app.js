// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module   b.createApp
 * @nav      Production
 * @title    Create App
 * @featured true
 * @slug     create-app
 *
 * @intro
 *   The framework's entry point. One call opens the vault, opens the
 *   database, builds a router carrying the security middleware, wires the
 *   jobs runner and the queue when they are configured, and resolves with
 *   the pieces an application serves from.
 *
 *   The middleware is on the router before any route is registered, so a
 *   route cannot be added outside the request lifecycle's protections.
 *   Nine of the eleven middlewares are installed without being asked for;
 *   `cors` and `rateLimit` wait for an origin list or a bound, because
 *   neither has a safe default. Turning one of the nine off records an
 *   <code>app.middleware.disabled</code> event in the audit chain, so the
 *   deployment's own posture is auditable rather than implicit.
 *
 *   Shutdown is phase-ordered through <code>b.appShutdown</code>: in-flight
 *   requests drain, then jobs, the queue, the router, the cluster and the
 *   databases. An application that calls <code>shutdown()</code> on SIGTERM
 *   survives a rolling restart without dropping a request.
 *
 * @card
 *   One call opens the vault and the database, builds a router with the
 *   security middleware already installed, and hands back `listen`,
 *   `address` and a phase-ordered `shutdown`.
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
var numericBounds = require("./numeric-bounds");
var queue = require("./queue");
var routerMod = require("./router");
var vault = require("./vault");

var SHUTDOWN_MS_KEYS = Object.freeze([
  "graceMs", "beforeStopTimeoutMs", "drainTimeoutMs", "afterDrainTimeoutMs",
]);

var MIDDLEWARE_KEYS = Object.freeze([
  "requestId", "securityHeaders", "cors", "botGuard", "rateLimit", "cookies",
  "cspNonce", "fetchMetadata", "bodyParser", "csrf", "errorHandler",
]);
var ROUTER_KEYS = Object.freeze(["tls0Rtt", "allowedRedirectOrigins", "logErrors"]);

function _assertMiddlewareShape(value, name) {
  if (value === undefined || value === true || value === false) return;
  if (value && typeof value === "object" && !Array.isArray(value)) return;
  throw new Error("createApp: opts.middleware." + name +
    " must be false, true, or an options object; got " +
    (value === null ? "null" : typeof value) +
    ". A string \"false\" is not false, and reading it as one would take the " +
    "middleware off without recording that it went.");
}

function _resolveMiddlewareOpt(value, allowDefault, name) {
  if (value === false) {
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
  _assertMiddlewareShape(value, name || "<key>");
  return value;
}

/**
 * @primitive b.createApp
 * @signature b.createApp(opts)
 * @since     0.1.65
 * @status    stable
 * @related   b.router, b.db.init, b.vault.init, b.jobs.create
 *
 * Open the vault, open the database, build a router with the security
 * middleware already on it, and resolve with the pieces an application needs
 * to serve: `{ router, db, vault, jobs, listen, address, shutdown,
 * shutdownOrchestrator }`.
 *
 * `dataDir` is the only required option. The directory is created when it does
 * not exist, and the vault opens in `wrapped` mode unless `vault.mode` says
 * otherwise.
 *
 * Nine middlewares are installed unless the matching `middleware` key is
 * `false`: `requestId`, `securityHeaders`, `botGuard`, `cookies`, `cspNonce`,
 * `fetchMetadata`, `csrf`, `bodyParser` and `errorHandler`. `cors` and
 * `rateLimit` are installed only when their key is present, since both need an
 * origin list or a bound to mean anything. Passing `false` for one of the nine
 * records an `app.middleware.disabled` audit event, so an operator can see from
 * the chain which defaults a deployment turned off.
 *
 * Each of those eleven keys is `false`, `true`, or that middleware's options
 * object, and anything else raises before the vault, the database or the job
 * consumers are started, so a refused configuration leaves nothing running. A
 * configuration file deserialized into the string `"false"`, or a `0`, or a
 * `null`, would otherwise read as "not `false`, not an object" and take the
 * middleware off without recording it, which is the one way to lose CSRF or
 * the bot guard silently.
 *
 * `router` is passed to `b.router.create` and takes `tls0Rtt`,
 * `allowedRedirectOrigins` and `logErrors`. Another key, or a `router` that is
 * not a plain object, raises before the vault opens, and so does a value that
 * `b.router.create` refuses, such as a non-boolean `logErrors`
 * (`router/bad-log-errors`) or an origin that is not HTTPS
 * (`router/allowed-redirect-origin-not-https-origin`).
 *
 * `routes` receives the router after the middleware is on it and before the
 * error handler, which is why a route registered there is covered by both.
 *
 * `listen(listenOpts?)` starts the server, taking `port`, `host` and `tls`
 * from its own argument first and from `createApp`'s options otherwise.
 * `address()` answers the bound address once it is listening. `shutdown()`
 * drains through the orchestrator: in-flight requests, then jobs, then the
 * queue, the router, the cluster and the databases.
 *
 * @opts
 *   dataDir:          string,   // required; created when absent
 *   port:             number,   // 0 binds an arbitrary free port
 *   host:             string,
 *   tls:              object,   // passed to the TLS server
 *   vault:            object,   // b.vault.init opts; mode defaults to "wrapped"
 *   db:               object,   // b.db.init opts
 *   schema:           array,    // table definitions for b.db.init
 *   frameworkSchema:  boolean,  // false skips the cluster schema check
 *   externalDb:       object,   // b.externalDb.init config
 *   cluster:          object,   // b.cluster.init config
 *   queue:            object,   // b.queue.init config
 *   jobs:             object,   // function (jobs) registering handlers
 *   jobsOptions:      object,   // b.jobs.create opts
 *   middleware:       object,   // per-middleware opts, or false to omit one
 *   router:           object,   // b.router.create opts: tls0Rtt, allowedRedirectOrigins, logErrors
 *   routes:           object,   // function (router) registering routes
 *   shutdown:         object,   // graceMs, installSignalHandlers, afterDrain
 *
 * @example
 *   var b = require("@blamejs/core");
 *   var app = await b.createApp({
 *     dataDir: "./data",
 *     port:    0,
 *     routes:  function (router) {
 *       router.get("/health", function (req, res) { res.json({ ok: true }); });
 *     },
 *   });
 *   await app.listen();
 *   app.address().port;          // → the port it bound
 *   await app.shutdown();
 */
async function createApp(opts) {
  if (!opts || typeof opts !== "object") {
    throw new Error("createApp: opts object is required");
  }
  if (!opts.dataDir || typeof opts.dataDir !== "string") {
    throw new Error("createApp: opts.dataDir is required");
  }
  validateOpts.optionalPort(opts.port, "createApp: opts.port", undefined, undefined, { allowZero: true });
  validateOpts.optionalBoolean(opts.frameworkSchema, "createApp: opts.frameworkSchema");
  validateOpts.optionalPlainObject(opts.middleware, "createApp: opts.middleware",
    undefined, undefined,
    "must be an object keyed by " + MIDDLEWARE_KEYS.join(" / ") +
    ", or null. Indexing a string or an array for those keys reads every one " +
    "as absent, which turns the configuration into the defaults it was " +
    "written to change.");
  validateOpts.optionalPlainObject(opts.shutdown, "createApp: opts.shutdown",
    undefined, undefined,
    "must be an object of graceMs / installSignalHandlers / drain settings, " +
    "or null. The same indexing reads every setting as absent, so a shutdown " +
    "configured not to install signal handlers would install them.");
  if (opts.shutdown) {
    validateOpts.optionalBoolean(opts.shutdown.installSignalHandlers,
      "createApp: opts.shutdown.installSignalHandlers");
    SHUTDOWN_MS_KEYS.forEach(function (k) {
      if (opts.shutdown[k] === undefined) return;
      if (!numericBounds.isPositiveFiniteInt(opts.shutdown[k])) {
        throw new Error("createApp: opts.shutdown." + k +
          " must be a positive whole number of milliseconds, and a zero is " +
          "refused rather than read as a budget; got " +
          numericBounds.shape(opts.shutdown[k]));
      }
    });
  }
  var mwShapes = opts.middleware || {};
  for (var mk = 0; mk < MIDDLEWARE_KEYS.length; mk += 1) {
    _assertMiddlewareShape(mwShapes[MIDDLEWARE_KEYS[mk]], MIDDLEWARE_KEYS[mk]);
  }
  validateOpts.optionalPlainObject(opts.router, "createApp: opts.router",
    undefined, undefined,
    "must be an object of " + ROUTER_KEYS.join(" / ") + ", or null");
  var routerOpts = opts.router || {};
  Object.keys(routerOpts).forEach(function (rk) {
    if (ROUTER_KEYS.indexOf(rk) === -1) {
      throw new Error("createApp: opts.router." + rk + " is not a router option; " +
        "expected one of " + ROUTER_KEYS.join(", "));
    }
  });
  var router = routerMod.create(routerOpts);
  var dataDir = nodePath.resolve(opts.dataDir);
  if (!nodeFs.existsSync(dataDir)) {
    nodeFs.mkdirSync(dataDir, { recursive: true });
  }

  var vaultOpts = Object.assign({ dataDir: dataDir }, opts.vault || {});
  if (!vaultOpts.mode) vaultOpts.mode = "wrapped";
  await vault.init(vaultOpts);

  if (opts.externalDb) {
    externalDb.init(opts.externalDb);
  }

  if (opts.cluster) {
    if (opts.cluster.externalDbBackend && opts.frameworkSchema !== false) {
      await frameworkSchema.ensureSchema({
        externalDbBackend: opts.cluster.externalDbBackend,
        dialect:           opts.cluster.dialect || "postgres",
      });
    }
    await cluster.init(opts.cluster);
  }

  var dbOpts = Object.assign({
    dataDir: dataDir,
    schema:  opts.schema || [],
  }, opts.db || {});
  await db.init(dbOpts);

  var jobsInstance = null;
  if (typeof opts.jobs === "function") {
    var queueConfig = opts.queue || { backends: { primary: { protocol: "local" } } };
    queue.init(queueConfig);
    jobsInstance = jobsMod.create(opts.jobsOptions || {});
    opts.jobs(jobsInstance);
    await jobsInstance.start();
  } else if (opts.queue) {
    queue.init(opts.queue);
  }

  var mwConfig = opts.middleware || {};

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
    var csrfDefaults = { skipStateless: true };
    if (csrfOpts.tokenLookup === undefined && csrfOpts.cookie === undefined) {
      csrfDefaults.cookie = true;
    }
    csrfOpts = Object.assign(csrfDefaults, csrfOpts);
    router.use(middleware.csrfProtect(csrfOpts));
  }

  if (typeof opts.routes === "function") {
    opts.routes(router);
  }

  var errorHandlerOpts = _resolveMiddlewareOpt(mwConfig.errorHandler, true, "errorHandler");
  if (errorHandlerOpts) {
    router.onError(middleware.errorHandler(errorHandlerOpts));
  }

  var server = null;
  var listenPort = null;
  var listenHost = null;

  function listen(listenOpts) {
    listenOpts = listenOpts || {};
    validateOpts.optionalPort(listenOpts.port, "createApp.listen: listenOpts.port", undefined, undefined, { allowZero: true });
    var port = (listenOpts.port !== undefined) ? listenOpts.port
             : (opts.port !== undefined) ? opts.port
             : 0;
    var host = listenOpts.host || opts.host;
    var tls  = listenOpts.tls  || opts.tls;
    return new Promise(function (resolve, reject) {
      function onBindError(err) { reject(err); }
      try {
        server = router.listen(port, function () {
          server.removeListener("error", onBindError);
          var addr = server.address();
          if (addr && typeof addr === "object") {
            listenPort = addr.port;
            listenHost = addr.address;
          }
          _wireShutdownPhases();
          resolve({ port: listenPort, host: listenHost, server: server });
        }, tls, host);
      } catch (e) { reject(e); return; }
      server.once("error", onBindError);
    });
  }

  function address() {
    if (!server) return null;
    return { port: listenPort, host: listenHost };
  }

  var phasesWired = false;
  function _wireShutdownPhases() {
    if (phasesWired) return;
    phasesWired = true;

    if (typeof shutdownOpts.beforeStop === "function") {
      orchestrator.addPhase({
        name: "beforeStop",
        run:  shutdownOpts.beforeStop,
        timeoutMs: shutdownOpts.beforeStopTimeoutMs || C.TIME.seconds(5),
      });
    }

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

    var standard = appShutdown.standardPhases({
      health:     shutdownOpts.health || null,
      scheduler:  shutdownOpts.scheduler || null,
      jobs:       jobsInstance,
      queue:      jobsInstance ? null : (opts.queue ? queue : null),
      router:     router,
      server:     null,
      cluster:    opts.cluster ? cluster : null,
      db:         db,
      externalDb: opts.externalDb ? externalDb : null,
    });
    if (server) {
      var httpServerPhase = {
        name: "http-server",
        run:  function () {
          return new Promise(function (resolve) {
            if (!server) { resolve(); return; }
            server.close(function () {
              server = null;
              listenPort = null;
              listenHost = null;
              resolve();
            });
          });
        },
        timeoutMs: C.TIME.seconds(10),
      };
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
    shutdownOrchestrator: orchestrator,
  };
}

module.exports = { createApp: createApp };
