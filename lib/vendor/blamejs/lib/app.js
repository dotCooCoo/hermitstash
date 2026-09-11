// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
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
  validateOpts.optionalPort(opts.port, "createApp: opts.port", undefined, undefined, { allowZero: true });
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

  var router = new routerMod.Router();
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
