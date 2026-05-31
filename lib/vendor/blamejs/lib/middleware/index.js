"use strict";
/**
 * HTTP middleware — request-lifecycle hardening primitives.
 *
 * Exposed as b.middleware.{requestId, securityHeaders, errorHandler,
 * botGuard, cors, rateLimit}. Each export is a `create(opts)` factory
 * that returns a 3-arg `(req, res, next)` middleware function compatible
 * with the framework's Router.
 *
 * Recommended mount order:
 *   1. requestId        — every later middleware should be able to log requestId
 *   2. securityHeaders  — set headers before any response could be partially sent
 *   3. cors             — handle preflights before deeper logic
 *   4. botGuard         — cheap rejection of obviously-bot traffic
 *   5. rateLimit        — slow down anything still here
 *   6. (your auth + business middleware + routes)
 *   7. errorHandler     — must be LAST so it catches everything that throws
 */
var aiActDisclosure = require("./ai-act-disclosure");
var apiEncrypt = require("./api-encrypt");
var openapiServe = require("./openapi-serve");
var asyncapiServe = require("./asyncapi-serve");
var flagContext = require("./flag-context");
var assetlinks = require("./assetlinks");
var attachUser = require("./attach-user");
var bearerAuth = require("./bearer-auth");
var bodyParser = require("./body-parser");
var clearSiteData = require("./clear-site-data");
var botDisclose = require("./bot-disclose");
var botGuard = require("./bot-guard");
var compression = require("./compression");
var cookies = require("./cookies");
var cors = require("./cors");
var dailyByteQuota = require("./daily-byte-quota");
var cspNonce = require("./csp-nonce");
var cspReport = require("./csp-report");
var csrfProtect = require("./csrf-protect");
var dbRoleFor = require("./db-role-for");
var dpop = require("./dpop");
var errorHandler = require("./error-handler");
var fetchMetadata = require("./fetch-metadata");
var gpc = require("./gpc");
var headers = require("./headers");
var health = require("./health");
var hostAllowlist = require("./host-allowlist");
var nel = require("./nel");
var networkAllowlist = require("./network-allowlist");
var rateLimit = require("./rate-limit");
var speculationRules = require("./speculation-rules");
var requestId = require("./request-id");
var requestLog = require("./request-log");
var requireAal = require("./require-aal");
var requireAuth = require("./require-auth");
var requireContentType = require("./require-content-type");
var ageGate = require("./age-gate");
var requireBoundKey = require("./require-bound-key");
var requireMethods = require("./require-methods");
var requireMtls = require("./require-mtls");
var requireStepUp = require("./require-step-up");
var securityHeaders = require("./security-headers");
var securityTxt = require("./security-txt");
var spanHttpServer = require("./span-http-server");
var sse = require("./sse");
var traceLogCorrelation = require("./trace-log-correlation");
var tracePropagate = require("./trace-propagate");
var tusUpload = require("./tus-upload");
var webAppManifest = require("./web-app-manifest");
var protectedResourceMetadata = require("./protected-resource-metadata");
var scimServer = require("./scim-server");
var idempotencyKey = require("./idempotency-key");
var noCache = require("./no-cache");
var composePipeline = require("./compose-pipeline");

module.exports = {
  requestId:        requestId.create,
  securityHeaders:  securityHeaders.create,
  errorHandler:     errorHandler.create,
  botDisclose:      botDisclose.create,
  botGuard:         botGuard.create,
  cors:             cors.create,
  dailyByteQuota:   dailyByteQuota.create,
  rateLimit:        rateLimit.create,
  attachUser:       attachUser.create,
  bearerAuth:       bearerAuth.create,
  requireAal:       requireAal.create,
  requireAuth:      requireAuth.create,
  requireContentType: requireContentType.create,
  ageGate:          ageGate.create,
  requireBoundKey:  requireBoundKey.create,
  requireMethods:   requireMethods.create,
  requireMtls:      requireMtls.create,
  requireStepUp:    requireStepUp.create,
  csrfProtect:      csrfProtect.create,
  fetchMetadata:    fetchMetadata.create,
  gpc:              gpc.create,
  headers:          headers.create,
  bodyParser:       bodyParser.create,
  health:           health.create,
  compression:      compression.create,
  cookies:          cookies.create,
  cspNonce:         cspNonce.create,
  cspReport:        cspReport.create,
  securityTxt:      securityTxt.create,
  sse:              sse.create,
  requestLog:       requestLog.create,
  apiEncrypt:       apiEncrypt,
  aiActDisclosure:  aiActDisclosure.create,
  openapiServe:     openapiServe.create,
  asyncapiServe:    asyncapiServe.create,
  flagContext:      flagContext.create,
  assetlinks:       assetlinks.create,
  dbRoleFor:        dbRoleFor.create,
  dpop:             dpop.create,
  hostAllowlist:    hostAllowlist.create,
  networkAllowlist: networkAllowlist.create,
  spanHttpServer:        spanHttpServer.create,
  traceLogCorrelation:   traceLogCorrelation.create,
  tracePropagate:        tracePropagate.create,
  tusUpload:        tusUpload.create,
  webAppManifest:   webAppManifest.create,
  clearSiteData:    clearSiteData.create,
  nel:              nel.create,
  speculationRules: speculationRules.create,
  protectedResourceMetadata: protectedResourceMetadata.create,
  scimServer:       scimServer.create,
  idempotencyKey:   Object.assign(idempotencyKey.create, {
    memoryStore: idempotencyKey.memoryStore,
    DEFAULT_METHODS: idempotencyKey.DEFAULT_METHODS,
    IdempotencyError: idempotencyKey.IdempotencyError,
  }),
  noCache:          noCache.create,
  composePipeline:  composePipeline,

  // Module exports for advanced use (constants, raw factory access)
  _modules: {
    requestId:        requestId,
    securityHeaders:  securityHeaders,
    errorHandler:     errorHandler,
    botDisclose:      botDisclose,
    botGuard:         botGuard,
    cors:             cors,
    dailyByteQuota:   dailyByteQuota,
    rateLimit:        rateLimit,
    attachUser:       attachUser,
    bearerAuth:       bearerAuth,
    requireAal:       requireAal,
    requireAuth:      requireAuth,
    requireContentType: requireContentType,
    ageGate:          ageGate,
    requireBoundKey:  requireBoundKey,
    requireMethods:   requireMethods,
    requireMtls:      requireMtls,
    requireStepUp:    requireStepUp,
    csrfProtect:      csrfProtect,
    fetchMetadata:    fetchMetadata,
    bodyParser:       bodyParser,
    health:           health,
    compression:      compression,
    cspNonce:         cspNonce,
    securityTxt:      securityTxt,
    sse:              sse,
    requestLog:       requestLog,
    apiEncrypt:       apiEncrypt,
    aiActDisclosure:  aiActDisclosure,
    openapiServe:     openapiServe,
    asyncapiServe:    asyncapiServe,
    flagContext:      flagContext,
    assetlinks:       assetlinks,
    dbRoleFor:        dbRoleFor,
    dpop:             dpop,
    hostAllowlist:    hostAllowlist,
    networkAllowlist: networkAllowlist,
    spanHttpServer:        spanHttpServer,
    traceLogCorrelation:   traceLogCorrelation,
    tracePropagate:        tracePropagate,
    tusUpload:        tusUpload,
    webAppManifest:   webAppManifest,
    clearSiteData:    clearSiteData,
    nel:              nel,
    speculationRules: speculationRules,
    idempotencyKey:   idempotencyKey,
    noCache:          noCache,
  },
};

module.exports.tusUpload.memoryStore = tusUpload.memoryStore;
