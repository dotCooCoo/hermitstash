"use strict";

// TLS 1.3 minimum, framework-wide. Sets the default for every TLS
// socket the process opens — outbound (https.request, mail SMTP+
// STARTTLS, redis/postgres/mongo with TLS, http-client) AND inbound
// (https.createServer when blamejs is the listener). Per-call override
// still works when an operator with a legacy peer needs TLSv1.2.
// node:tls reads `DEFAULT_MIN_VERSION` once at first TLS use; setting
// it here, before any framework module loads node:tls, makes the
// default sticky for the entire process.
var _tls = require("node:tls");
_tls.DEFAULT_MIN_VERSION = "TLSv1.3";

/**
 * blamejs — public API entry point.
 *
 * The Node framework that owns its stack.
 *
 * Public surface lives on the exported object below — see
 * `module.exports` for the authoritative list. Notable groupings:
 *
 *   Crypto:       crypto, vault, vaultWrap, vaultPassphraseSource,
 *                 vaultPassphraseOps, vaultRotate, cryptoField, mtlsCa,
 *                 pqcGate, pqcAgent
 *   Storage:      db, storage, objectStore, queue, externalDb,
 *                 frameworkSchema, clusterStorage, session, atomicFile,
 *                 cookies
 *   Audit:        audit, auditChain, auditSign, auditTools, consent,
 *                 subject, events, redact
 *   HTTP:         router, middleware (csrf, cors, rate-limit, request-id,
 *                 security-headers, bot-guard, attach-user, require-auth,
 *                 error-handler, body-parser, csp-nonce, compression,
 *                 health, api-encrypt), httpClient, websocket,
 *                 websocketChannels, nonceStore
 *   Auth:         auth.{password,totp,passkey,jwt,oauth,lockout}, authHeader
 *   Render:       template, render, staticServe, forms, errorPage
 *   App:          createApp, jobs, mail, mailBounce, scheduler,
 *                 appShutdown
 *   Backup:       backup, backupCrypto, backupManifest, backupBundle,
 *                 restore, restoreBundle, restoreRollback
 *   DX:           log, dev, bundler, cli, migrations, deprecate,
 *                 apiSnapshot
 *   Validation:   safeSchema, safeJson, safeSql, safeBuffer, safeUrl,
 *                 safeAsync, parsers, pagination
 *   Observability: metrics, tracing, ntpCheck, logStream
 *   Cluster:      cluster (leader election + write-side gates), handlers,
 *                 chainWriter, lazyRequire, frameworkError
 *   Constants:    constants (version-stable namespace), version
 *
 * See LICENSE (Apache-2.0) and NOTICE for vendored attribution.
 */

var crypto = require("./lib/crypto");
// Attach RFC 9180 HPKE (lib/crypto-hpke.js) and RFC 9421 HTTP Message
// Signatures (lib/http-message-signature.js) onto b.crypto so operators
// reach b.crypto.hpke.seal({...}) / b.crypto.httpSig.sign({...}) without
// remembering separate top-level namespaces. Implementations live in
// the dedicated lib files; these are thin aliases.
crypto.hpke = require("./lib/crypto-hpke");
crypto.httpSig = require("./lib/http-message-signature");
var tlsExporter = require("./lib/tls-exporter");
var router = require("./lib/router");
var constants = require("./lib/constants");
var vault = require("./lib/vault");
var vaultWrap = require("./lib/vault/wrap");
var vaultPassphraseSource = require("./lib/vault/passphrase-source");
var db = require("./lib/db");
// Standalone encrypted-DB-file lifecycle for consumers that own
// their own SQLite handle. Attached as b.db.fileLifecycle so it
// rides alongside the framework's full b.db API.
db.fileLifecycle = require("./lib/db-file-lifecycle").fileLifecycle;
var xmlC14n = require("./lib/xml-c14n");
var cryptoField = require("./lib/crypto-field");
var audit = require("./lib/audit");
// Attach the audit-tools dispatcher onto b.audit so operators can
// reach `b.audit.export({ format: "cadf" })` without remembering the
// audit-tools namespace. The implementation lives in audit-tools; this
// is a thin alias.
audit.export = function (opts) {
  return require("./lib/audit-tools").exportAudit(opts);
};
var auditChain = require("./lib/audit-chain");
var consent = require("./lib/consent");
var subject = require("./lib/subject");
var session = require("./lib/session");
var storage = require("./lib/storage");
var safeJson = require("./lib/safe-json");
var safeJsonPath = require("./lib/safe-jsonpath");
var safeMime = require("./lib/safe-mime");
var safeDns = require("./lib/safe-dns");
var safeSmtp = require("./lib/safe-smtp");
var mailStore = require("./lib/mail-store");
var ntpCheck = require("./lib/ntp-check");
var auditSign = require("./lib/audit-sign");
var objectStore = require("./lib/object-store");
var retry = require("./lib/retry");
var queue = require("./lib/queue");
var logStream = require("./lib/log-stream");
var redact = require("./lib/redact");
var externalDb = require("./lib/external-db");
var middleware = require("./lib/middleware");
var atomicFile = require("./lib/atomic-file");
var parsers = require("./lib/parsers");
var cluster = require("./lib/cluster");
var frameworkSchema = require("./lib/framework-schema");
var clusterStorage = require("./lib/cluster-storage");
var safeAsync = require("./lib/safe-async");
var handlers = require("./lib/handlers");
var safeSql = require("./lib/safe-sql");
var chainWriter = require("./lib/chain-writer");
var safeBuffer = require("./lib/safe-buffer");
var lazyRequire = require("./lib/lazy-require");
var frameworkError = require("./lib/framework-error");
var nistCrosswalk = require("./lib/nist-crosswalk");
var httpClient = require("./lib/http-client");
// Attach the encrypted-payload helper from the api-encrypt middleware so
// `b.httpClient.encrypted({ pubkey, baseUrl })` is available alongside
// the bare `b.httpClient.request(...)`. The api-encrypt module owns the
// implementation; httpClient stays free of an api-encrypt dependency.
httpClient.encrypted = require("./lib/middleware/api-encrypt").httpClient;
httpClient.cookieJar = require("./lib/http-client-cookie-jar");
httpClient.cache     = require("./lib/http-client-cache");
var websocket = require("./lib/websocket");
var sse = require("./lib/sse");
var mcp = require("./lib/mcp");
var graphqlFederation = require("./lib/graphql-federation");
var aiInput = require("./lib/ai-input");
var a2a = require("./lib/a2a");
var darkPatterns = require("./lib/dark-patterns");
var budr = require("./lib/budr");
var secCyber = require("./lib/sec-cyber");
var iabTcf = require("./lib/iab-tcf");
var fapi2 = require("./lib/fapi2");
var contentCredentials = require("./lib/content-credentials");
var aiPref = require("./lib/ai-pref");
var fdx = require("./lib/fdx");
var tcpa10dlc = require("./lib/tcpa-10dlc");
var iabMspa = require("./lib/iab-mspa");
var safeUrl = require("./lib/safe-url");
var safeRedirect = require("./lib/safe-redirect");
var pick = require("./lib/pick");
var dora = require("./lib/dora");
var fda21cfr11 = require("./lib/fda-21cfr11");
var auditDailyReview = require("./lib/audit-daily-review");
var ddlChangeControl = require("./lib/ddl-change-control");
var compliance = Object.assign({}, require("./lib/compliance"), {
  eaa: require("./lib/compliance-eaa"),
});
var dataAct = require("./lib/data-act");
var problemDetails = require("./lib/problem-details");
var testHarness = require("./lib/test-harness");
var cacheStatus = require("./lib/cache-status");
var cdnCacheControl = require("./lib/cdn-cache-control");
var clientHints = require("./lib/client-hints");
var structuredFields = require("./lib/structured-fields");
var vex = require("./lib/vex");
var vendorData = require("./lib/vendor-data");
var serverTiming = require("./lib/server-timing");
var earlyHints = require("./lib/early-hints");
var gateContract = require("./lib/gate-contract");
var guardCsv = require("./lib/guard-csv");
var guardHtml = require("./lib/guard-html");
var guardSvg = require("./lib/guard-svg");
var guardFilename = require("./lib/guard-filename");
var guardMessageId = require("./lib/guard-message-id");
var guardSmtpCommand = require("./lib/guard-smtp-command");
var guardEnvelope = require("./lib/guard-envelope");
var guardDsn = require("./lib/guard-dsn");
var guardListUnsubscribe = require("./lib/guard-list-unsubscribe");
var guardListId = require("./lib/guard-list-id");
var guardMailQuery = require("./lib/guard-mail-query");
var guardMailCompose = require("./lib/guard-mail-compose");
var guardMailReply = require("./lib/guard-mail-reply");
var guardMailMove = require("./lib/guard-mail-move");
var guardMailSieve = require("./lib/guard-mail-sieve");
var guardAgentRegistry = require("./lib/guard-agent-registry");
var guardIdempotencyKey = require("./lib/guard-idempotency-key");
var guardStreamArgs = require("./lib/guard-stream-args");
var guardEventBusTopic = require("./lib/guard-event-bus-topic");
var guardEventBusPayload = require("./lib/guard-event-bus-payload");
var guardTenantId = require("./lib/guard-tenant-id");
var guardSagaConfig = require("./lib/guard-saga-config");
var guardPostureChain = require("./lib/guard-posture-chain");
var guardTraceContext = require("./lib/guard-trace-context");
var guardSnapshotEnvelope = require("./lib/guard-snapshot-envelope");
var agentOrchestrator = require("./lib/agent-orchestrator");
var agentIdempotency = require("./lib/agent-idempotency");
var agentStream = require("./lib/agent-stream");
var agentEventBus = require("./lib/agent-event-bus");
var agentTenant = require("./lib/agent-tenant");
var agentSaga = require("./lib/agent-saga");
var agentPostureChain = require("./lib/agent-posture-chain");
var agentTrace = require("./lib/agent-trace");
var agentSnapshot = require("./lib/agent-snapshot");
var guardArchive = require("./lib/guard-archive");
var guardJson = require("./lib/guard-json");
var guardYaml = require("./lib/guard-yaml");
var guardXml = require("./lib/guard-xml");
var guardMarkdown = require("./lib/guard-markdown");
var guardEmail = require("./lib/guard-email");
var guardDomain = require("./lib/guard-domain");
var guardUuid = require("./lib/guard-uuid");
var guardCidr = require("./lib/guard-cidr");
var guardTime = require("./lib/guard-time");
var guardMime = require("./lib/guard-mime");
var guardJwt = require("./lib/guard-jwt");
var guardOauth = require("./lib/guard-oauth");
var guardGraphql = require("./lib/guard-graphql");
var guardShell = require("./lib/guard-shell");
var guardRegex = require("./lib/guard-regex");
var guardJsonpath = require("./lib/guard-jsonpath");
var guardTemplate = require("./lib/guard-template");
var guardImage = require("./lib/guard-image");
var guardPdf = require("./lib/guard-pdf");
var guardAuth = require("./lib/guard-auth");
var guardAll = require("./lib/guard-all");
var ssrfGuard = require("./lib/ssrf-guard");
var authHeader = require("./lib/auth-header");
var auth = {
  password: require("./lib/auth/password"),
  totp:     require("./lib/totp"),
  passkey:  require("./lib/auth/passkey"),
  fidoMds3: require("./lib/auth/fido-mds3"),
  jwt:      Object.assign({},
              require("./lib/auth/jwt"),
              { verifyExternal: require("./lib/auth/jwt-external").verifyExternal }),
  oauth:    require("./lib/auth/oauth"),
  lockout:  require("./lib/auth/lockout"),
  dpop:     require("./lib/auth/dpop"),
  aal:      require("./lib/auth/aal"),
  fal:      require("./lib/auth/fal"),
  statusList: require("./lib/auth/status-list"),
  sdJwtVc:    require("./lib/auth/sd-jwt-vc"),
  stepUp:     require("./lib/auth/step-up"),
  acr:        require("./lib/auth/acr-vocabulary"),
  authTime:   require("./lib/auth/auth-time-tracker"),
  accessLock: require("./lib/auth/access-lock"),
  atoKillSwitch: require("./lib/auth/ato-kill-switch"),
  ciba:             require("./lib/auth/ciba"),
  oid4vci:          require("./lib/auth/oid4vci"),
  oid4vp:           require("./lib/auth/oid4vp"),
  saml:             require("./lib/auth/saml"),
  openidFederation: require("./lib/auth/openid-federation"),
};
var template = require("./lib/template");
var render = require("./lib/render");
var htmlBalance = require("./lib/html-balance");
var validateOpts = require("./lib/validate-opts");
var cliHelpers = require("./lib/cli-helpers");
var staticServe = require("./lib/static");
var forms = require("./lib/forms");
var app = require("./lib/app");
var jobs = require("./lib/jobs");
var archive = require("./lib/archive");
var breakGlass = require("./lib/break-glass");
var config = require("./lib/config");
var csv = require("./lib/csv");
var time = require("./lib/time");
var uuid = require("./lib/uuid");
var mail = require("./lib/mail");
mail.rbl = require("./lib/mail-rbl");
mail.greylist = require("./lib/mail-greylist");
mail.helo = require("./lib/mail-helo");
mail.server = mail.server || {};
mail.server.mx = require("./lib/mail-server-mx");
var mailArf = require("./lib/mail-arf");
var mailBounce = require("./lib/mail-bounce");
var mailMdn = require("./lib/mail-mdn");
var publicSuffix = require("./lib/public-suffix");
var pubsub = require("./lib/pubsub");
var websocketChannels = require("./lib/websocket-channels");
var nonceStore = require("./lib/nonce-store");
var scheduler = require("./lib/scheduler");
var log = require("./lib/log");
var errorPage = require("./lib/error-page");
var cookies = require("./lib/cookies");
var migrations = require("./lib/migrations");
var cli = require("./lib/cli");
var argParser = require("./lib/arg-parser");
var dev = require("./lib/dev");
var bundler = require("./lib/bundler");
var pqcGate = require("./lib/pqc-gate");
var pqcAgent = require("./lib/pqc-agent");
var pqcSoftware = require("./lib/pqc-software");
var vaultRotate = require("./lib/vault/rotate");
var vaultPassphraseOps = require("./lib/vault/passphrase-ops");
var mtlsCa = require("./lib/mtls-ca");
var mtlsEngine = require("./lib/mtls-engine-default");
var backupCrypto = require("./lib/backup/crypto");
var backupManifest = require("./lib/backup/manifest");
var backupBundle = require("./lib/backup/bundle");
var restoreBundle = require("./lib/restore-bundle");
var backup = require("./lib/backup");
var restoreRollback = require("./lib/restore-rollback");
var restore = require("./lib/restore");
var deprecate = require("./lib/deprecate");
var apiSnapshot = require("./lib/api-snapshot");
var openapi = require("./lib/openapi");
var asyncapi = require("./lib/asyncapi");
var wsClient = require("./lib/ws-client");
var flag = require("./lib/flag");
var auditTools = require("./lib/audit-tools");
var events = require("./lib/events");
var safeSchema = require("./lib/safe-schema");
var pagination = require("./lib/pagination");
var metrics = require("./lib/metrics");
var tracing = require("./lib/tracing");
var observability = require("./lib/observability");
var otelExport = require("./lib/otel-export");
var protocolDispatcher = require("./lib/protocol-dispatcher");
var requestHelpers = require("./lib/request-helpers");
var appShutdown = require("./lib/app-shutdown");
var slug = require("./lib/slug");
var webhook = require("./lib/webhook");
var apiKey = require("./lib/api-key");
var honeytoken = require("./lib/honeytoken");
var resourceAccessLock = require("./lib/resource-access-lock");
var processSpawn = require("./lib/process-spawn");
var keychain = require("./lib/keychain");
var credentialHash = require("./lib/credential-hash");
var permissions = require("./lib/permissions");
var cache = require("./lib/cache");
var seeders = require("./lib/seeders");
var i18n = require("./lib/i18n");
var notify = require("./lib/notify");
var testing = require("./lib/testing");
var configDrift = require("./lib/config-drift");
var security = require("./lib/security-assert");
var fileType = require("./lib/file-type");
var fileUpload = require("./lib/file-upload");
var dualControl = require("./lib/dual-control");
var retention = require("./lib/retention");
var legalHold = require("./lib/legal-hold");
var network = require("./lib/network");
var cloudEvents = require("./lib/cloud-events");
var dsr = require("./lib/dsr");
var outbox = require("./lib/outbox");
var inbox = require("./lib/inbox");
var tenantQuota = require("./lib/tenant-quota");
var drRunbook = require("./lib/dr-runbook");
var sandbox = require("./lib/sandbox");
var workerPool = require("./lib/worker-pool");
var authBotChallenge = require("./lib/auth-bot-challenge");
var sessionDeviceBinding = require("./lib/session-device-binding");
var acme = require("./lib/acme");
var watcher = require("./lib/watcher");
var localDbThin = require("./lib/local-db-thin");
var daemon = require("./lib/daemon");
var selfUpdate = require("./lib/self-update");

module.exports = {
  crypto:           crypto,
  router:           router,
  constants:        constants,
  vault:            vault,
  vaultWrap:        vaultWrap,
  vaultPassphraseSource: vaultPassphraseSource,
  db:               db,
  xmlC14n:          xmlC14n,
  cryptoField:      cryptoField,
  audit:            audit,
  auditChain:       auditChain,
  auditSign:        auditSign,
  auditTools:       auditTools,
  events:           events,
  consent:          consent,
  subject:          subject,
  session:          session,
  storage:          storage,
  objectStore:      objectStore,
  retry:            retry,
  circuitBreaker:   require("./lib/circuit-breaker"),
  incident:         { report: require("./lib/incident-report") },
  cra:              { report: require("./lib/cra-report") },
  nis2:             { report: require("./lib/nis2-report") },
  gdpr:             { ropa: require("./lib/gdpr-ropa") },
  breach:           require("./lib/breach-deadline"),
  ai:               { adverseDecision: require("./lib/ai-adverse-decision"), input: aiInput },
  queue:            queue,
  logStream:        logStream,
  redact:           redact,
  externalDb:       externalDb,
  middleware:       middleware,
  atomicFile:       atomicFile,
  parsers:          parsers,
  safeEnv:          parsers.env,
  cluster:          cluster,
  frameworkSchema:  frameworkSchema,
  clusterStorage:   clusterStorage,
  safeAsync:        safeAsync,
  handlers:         handlers,
  safeSql:          safeSql,
  chainWriter:      chainWriter,
  safeBuffer:       safeBuffer,
  lazyRequire:      lazyRequire,
  frameworkError:   frameworkError,
  httpClient:       httpClient,
  websocket:        websocket,
  sse:              sse,
  mcp:              mcp,
  graphqlFederation: graphqlFederation,
  a2a:              a2a,
  darkPatterns:     darkPatterns,
  budr:             budr,
  secCyber:         secCyber,
  iabTcf:           iabTcf,
  fapi2:            fapi2,
  contentCredentials: contentCredentials,
  aiPref:           aiPref,
  fdx:              fdx,
  tcpa10dlc:        tcpa10dlc,
  iabMspa:          iabMspa,
  safeUrl:          safeUrl,
  safeRedirect:     safeRedirect,
  pick:             pick,
  dora:             dora,
  fda21cfr11:       fda21cfr11,
  auditDailyReview: auditDailyReview,
  ddlChangeControl: ddlChangeControl,
  compliance:       compliance,
  nistCrosswalk:    nistCrosswalk,
  dataAct:          dataAct,
  problemDetails:   problemDetails,
  testHarness:      testHarness,
  cacheStatus:      cacheStatus,
  cdnCacheControl:  cdnCacheControl,
  clientHints:      clientHints,
  structuredFields: structuredFields,
  vex:              vex,
  vendorData:       vendorData,
  serverTiming:     serverTiming,
  earlyHints:       earlyHints,
  gateContract:     gateContract,
  guardCsv:         guardCsv,
  guardHtml:        guardHtml,
  guardSvg:         guardSvg,
  guardFilename:    guardFilename,
  guardMessageId:   guardMessageId,
  guardSmtpCommand: guardSmtpCommand,
  guardEnvelope:    guardEnvelope,
  guardDsn:         guardDsn,
  guardListUnsubscribe: guardListUnsubscribe,
  guardListId:      guardListId,
  guardMailQuery:   guardMailQuery,
  guardMailCompose: guardMailCompose,
  guardMailReply:   guardMailReply,
  guardMailMove:    guardMailMove,
  guardMailSieve:   guardMailSieve,
  guardAgentRegistry: guardAgentRegistry,
  guardIdempotencyKey: guardIdempotencyKey,
  guardStreamArgs:  guardStreamArgs,
  guardEventBusTopic: guardEventBusTopic,
  guardEventBusPayload: guardEventBusPayload,
  guardTenantId:    guardTenantId,
  guardSagaConfig:  guardSagaConfig,
  guardPostureChain: guardPostureChain,
  guardTraceContext: guardTraceContext,
  guardSnapshotEnvelope: guardSnapshotEnvelope,
  agent:            { orchestrator: agentOrchestrator, idempotency: agentIdempotency, stream: agentStream, eventBus: agentEventBus, tenant: agentTenant, saga: agentSaga, postureChain: agentPostureChain, trace: agentTrace, snapshot: agentSnapshot },
  guardArchive:     guardArchive,
  guardJson:        guardJson,
  guardYaml:        guardYaml,
  guardXml:         guardXml,
  guardMarkdown:    guardMarkdown,
  guardEmail:       guardEmail,
  guardDomain:      guardDomain,
  guardUuid:        guardUuid,
  guardCidr:        guardCidr,
  guardTime:        guardTime,
  guardMime:        guardMime,
  guardJwt:         guardJwt,
  guardOauth:       guardOauth,
  guardGraphql:     guardGraphql,
  guardShell:       guardShell,
  guardRegex:       guardRegex,
  guardJsonpath:    guardJsonpath,
  guardTemplate:    guardTemplate,
  guardImage:       guardImage,
  guardPdf:         guardPdf,
  guardAuth:        guardAuth,
  guardAll:         guardAll,
  ssrfGuard:        ssrfGuard,
  authHeader:       authHeader,
  auth:             auth,
  template:         template,
  render:           render,
  htmlBalance:      htmlBalance,
  validateOpts:     validateOpts,
  cliHelpers:       cliHelpers,
  staticServe:      staticServe,
  forms:            forms,
  createApp:        app.createApp,
  jobs:             jobs,
  archive:          archive,
  breakGlass:       breakGlass,
  config:           config,
  csv:              csv,
  time:             time,
  uuid:             uuid,
  mail:             mail,
  mailArf:          mailArf,
  mailBounce:       mailBounce,
  mailMdn:          mailMdn,
  publicSuffix:      publicSuffix,
  pubsub:            pubsub,
  websocketChannels: websocketChannels,
  nonceStore:        nonceStore,
  scheduler:        scheduler,
  log:              log,
  errorPage:       errorPage,
  cookies:          cookies,
  migrations:       migrations,
  cli:              cli,
  argParser:        argParser,
  dev:              dev,
  bundler:          bundler,
  pqcGate:          pqcGate,
  pqcAgent:         pqcAgent,
  pqcSoftware:      pqcSoftware,
  vaultRotate:      vaultRotate,
  vaultPassphraseOps: vaultPassphraseOps,
  mtlsCa:           mtlsCa,
  mtlsEngine:       mtlsEngine,
  backupCrypto:     backupCrypto,
  backupManifest:   backupManifest,
  backupBundle:     backupBundle,
  restoreBundle:    restoreBundle,
  backup:           backup,
  restoreRollback:  restoreRollback,
  restore:          restore,
  deprecate:        deprecate,
  apiSnapshot:      apiSnapshot,
  openapi:          openapi,
  asyncapi:         asyncapi,
  wsClient:         wsClient,
  flag:             flag,
  safeJson:         safeJson,
  safeJsonPath:     safeJsonPath,
  safeMime:         safeMime,
  safeDns:          safeDns,
  safeSmtp:         safeSmtp,
  mailStore:        mailStore,
  safeSchema:       safeSchema,
  pagination:       pagination,
  metrics:          metrics,
  tracing:          tracing,
  observability:    observability,
  otelExport:       otelExport,
  protocolDispatcher: protocolDispatcher,
  requestHelpers:   requestHelpers,
  appShutdown:      appShutdown,
  slug:             slug,
  webhook:          webhook,
  apiKey:           apiKey,
  honeytoken:       honeytoken,
  resourceAccessLock: resourceAccessLock,
  processSpawn:       processSpawn,
  keychain:         keychain,
  credentialHash:   credentialHash,
  permissions:      permissions,
  cache:            cache,
  seeders:          seeders,
  i18n:             i18n,
  notify:           notify,
  testing:          testing,
  configDrift:      configDrift,
  security:         security,
  fileType:         fileType,
  fileUpload:       fileUpload,
  dualControl:      dualControl,
  retention:        retention,
  legalHold:        legalHold,
  network:          network,
  cloudEvents:      cloudEvents,
  dsr:              dsr,
  outbox:           outbox,
  inbox:            inbox,
  tenantQuota:      tenantQuota,
  drRunbook:        drRunbook,
  sandbox:          sandbox,
  workerPool:       workerPool,
  authBotChallenge: authBotChallenge,
  sessionDeviceBinding: sessionDeviceBinding,
  acme:             acme,
  ntpCheck:         ntpCheck,
  tlsExporter:      tlsExporter,
  watcher:          watcher,
  localDb:          { thin: localDbThin.thin, LocalDbThinError: localDbThin.LocalDbThinError },
  daemon:           daemon,
  selfUpdate:       selfUpdate,
  version:          constants.version,
};
