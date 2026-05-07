"use strict";
/**
 * run-example — child-process entry point for wiki example execution.
 *
 * Invoked by validate-primitive-sections.js. The parent passes the
 * example specification on stdin as JSON:
 *
 *   { code: "<javascript source>", slug: "<page>", heading: "<...>" }
 *
 * The child:
 *   1. Boots a fresh framework instance via the canonical test fixture
 *      (test/helpers/db.js → setupTestDb) — same encrypted-at-rest +
 *      wrapped-vault + audit-chain shape the framework's own smoke
 *      suite uses. The schema is rich enough to cover every table the
 *      wiki examples reference (`users`, `orders`, `products`,
 *      `inventory`, etc.).
 *   2. Inits queue (local protocol) and externalDb (single fake
 *      Postgres-dialect backend) so examples that touch those reach a
 *      callable surface.
 *   3. Wraps the example code in an async closure under
 *      vm.compileFunction with `b` plus a stub harness in scope (req,
 *      res, env, pg, connectPrimary, etc.). Operator-supplied symbols
 *      get realistic stubs so the example reaches the framework
 *      boundary it cares about.
 *   4. Awaits the example.
 *   5. Reports the outcome to stdout as JSON.
 *
 * One child per example gives each run isolated framework state — no
 * module-singleton bleed-through, no fragile reset sequencing. Process
 * exit cleans up the tmpdir + handles.
 */
var fs = require("node:fs");
var os = require("node:os");
var path = require("node:path");
var vm = require("node:vm");
var nodeCrypto = require("node:crypto");

// Generate a real RSA keypair once per child process so dkim/jwt
// examples that reach the framework's PEM parser succeed instead of
// throwing on the placeholder fake.
var TEST_RSA = nodeCrypto.generateKeyPairSync("rsa", {
  modulusLength: 2048,
  publicKeyEncoding:  { type: "spki",  format: "pem" },
  privateKeyEncoding: { type: "pkcs8", format: "pem" },
});

// `b` is the installed copy at examples/wiki/node_modules/@blamejs/core.
// Cross-realm imports (the workspace-root test/helpers/db.js) are NOT
// safe here: when CI runs `npm install --install-links`, the wiki gets
// a real copy of @blamejs/core, distinct from any workspace `require`.
// Two copies → two module-cache entries → two singletons; the helper
// would init the workspace db while examples run against the installed
// db (uninited → "db.init() must be awaited before using db API").
// Locally on a `file:` symlink dev install both resolve to the same
// module and the bug is invisible. Boot the fixture inline against
// THIS file's `b` so init + use share one singleton in both setups.
var b = require("@blamejs/core");

var TEST_PASSPHRASE = "blamejs-wiki-validator-passphrase-not-secret";

// Reference schema covering every table wiki examples reference. The
// validator scans `b.db.from("...")` and SQL strings; this list grows
// as new tables enter the wiki.
var WIKI_SCHEMA = [
  {
    name: "users",
    columns: {
      _id:          "TEXT PRIMARY KEY",
      email:        "TEXT",
      emailHash:    "TEXT",
      name:         "TEXT",
      tenantId:     "TEXT",
      passwordHash: "TEXT",
      secretHash:   "TEXT",
      ssn:          "TEXT",
      diagnosis:    "TEXT",
      notes:        "TEXT",
      status:       "TEXT DEFAULT 'active'",
      createdAt:    "INTEGER NOT NULL DEFAULT 0",
    },
    indexes: ["emailHash", "status"],
    sealedFields:  ["email", "name", "ssn", "diagnosis", "notes"],
    derivedHashes: {
      emailHash: { from: "email", normalize: function (v) { return String(v).toLowerCase(); } },
    },
  },
  { name: "orders",     columns: { _id: "TEXT PRIMARY KEY", userId: "TEXT", total: "INTEGER", createdAt: "INTEGER" } },
  { name: "products",   columns: { _id: "TEXT PRIMARY KEY", name: "TEXT NOT NULL", price: "INTEGER" } },
  { name: "inventory",  columns: { _id: "TEXT PRIMARY KEY", productId: "TEXT NOT NULL", stock: "INTEGER" } },
  { name: "rows",       columns: { _id: "TEXT PRIMARY KEY", payload: "TEXT" } },
  { name: "sessions",   columns: { _id: "TEXT PRIMARY KEY", userId: "TEXT NOT NULL", startedAt: "INTEGER", endedAt: "INTEGER", tenantId: "TEXT" }, sealedFields: [] },
];

function _fakePgClient() {
  return {
    connect: async function () { return { id: "fake-pg" }; },
    query:   async function (_c, _sql, _p) { return { rows: [], rowCount: 0 }; },
    close:   async function () {},
  };
}

// req/res stubs compose from b.testing.mockReq/mockRes (the framework's
// canonical test mocks) plus wiki-example-specific extras: an actor on
// req.user/.apiKey, request body shape, cookie jar, .json/.status/
// .redirect/.cookie helpers most operators expect on res.
function _stubReq() {
  var req = b.testing.mockReq({
    method: "GET",
    url:    "/",
    headers: {
      host: "wiki.example.com", "user-agent": "wiki-validator",
      authorization: "Bearer wiki_pk_x", cookie: "blamejs_sid=sess-1",
      "x-blamejs-signature": "t=1,id=u,k1=sig",
    },
    ip: "127.0.0.1",
  });
  req.cookies = { blamejs_sid: "sess-1" };
  req.user    = {
    _id: "u-1", roles: ["admin"], scopes: ["users:read"],
    tenantId: "t-1", totpSecret: "JBSWY3DPEHPK3PXP",
  };
  req.apiKey  = { id: "ak-1", scopes: ["users:read"] };
  req.session = { passkeyChallenge: null, sid: "sess-1" };
  req.body    = {
    reason: "investigation request — ticket #1",
    totpCode: "123456",
    email: "alice@example.test",
    password: "hunter2-pass-32-chars-min-pad-padding",
    code: "123456",
  };
  req.params  = { id: "id-1" };
  req.query   = {};
  return req;
}

function _stubRes() {
  var res = b.testing.mockRes();
  // Helpers wiki examples reach for that aren't on the bare mockRes:
  // .json (Express-shape), .status (chainable), .cookie / .redirect /
  // .send. Wrapped over the underlying writeHead/end so the captured
  // state is consistent.
  var statusCode = 200;
  res.status = function (s) { statusCode = s; this.writeHead(s); return this; };
  res.json   = function (o) {
    this.writeHead(statusCode, { "content-type": "application/json" });
    this.end(JSON.stringify(o));
    return this;
  };
  res.cookie   = function () { return this; };
  res.redirect = function () { return this; };
  res.send     = function (chunk) { this.end(chunk); return this; };
  return res;
}

function _envFn(name, fallback) {
  var fakes = {
    DKIM_PRIVATE_KEY:    TEST_RSA.privateKey,
    JWT_PRIVATE_KEY:     TEST_RSA.privateKey,
    JWT_PUBLIC_KEY:      TEST_RSA.publicKey,
    SMTP_HOST:           "smtp.example.test",
    SMTP_USER:           "test",
    SMTP_PASS:           "test",
    JWT_AUDIENCE:        "wiki",
    JWT_ISSUER:          "wiki",
    JWT_SECRET:          "wiki-validator-jwt-secret-32-chars-min-pad",
    OAUTH_CLIENT_ID:     "wiki",
    OAUTH_CLIENT_SECRET: "wiki",
    GOOGLE_CLIENT_ID:    "wiki-google.apps.googleusercontent.com",
    GOOGLE_CLIENT_SECRET: "wiki-google-secret",
    GITHUB_CLIENT_ID:    "wiki-github",
    GITHUB_CLIENT_SECRET: "wiki-github-secret",
    OTLP_ENDPOINT:       "http://127.0.0.1:65535/v1/metrics",
    HONEYCOMB_API_KEY:   "test",
    HMAC_KEY:            "wiki-validator-hmac",
    PG_HOST:             "127.0.0.1",
    BUCKET:              "test-bucket",
    AWS_REGION:          "us-east-1",
    SLACK_WEBHOOK_URL:   "http://127.0.0.1:65535/slack",
    DISCORD_WEBHOOK_URL: "http://127.0.0.1:65535/discord",
    PAGERDUTY_URL:       "http://127.0.0.1:65535/pd",
    OTEL_TOKEN:          "test-otel-token",
    APP_VERSION:         "1.0.0-test",
    SIEM_HMAC_SECRET:    "wiki-validator-hmac",
    AWS_ACCESS_KEY_ID:   "AKIATEST",
    AWS_SECRET_ACCESS_KEY: "test-secret-access-key",
    AWS_SESSION_TOKEN:   "",
  };
  return Object.prototype.hasOwnProperty.call(fakes, name) ? fakes[name] : (fallback || "");
}

async function _bootFixture() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "wiki-validator-"));
  // Inline the same wrapped-vault + encrypted-at-rest setup the
  // framework's smoke suite uses (test/helpers/db.js shape), against
  // THIS file's `b` so init touches the same singleton the examples do.
  process.env.BLAMEJS_SKIP_NTP_CHECK           = "1";
  process.env.BLAMEJS_VAULT_PASSPHRASE         = TEST_PASSPHRASE;
  process.env.BLAMEJS_AUDIT_SIGNING_PASSPHRASE = TEST_PASSPHRASE;
  delete process.env.BLAMEJS_AUDIT_SIGNING_MODE;
  b.cluster._resetForTest();
  b.audit._resetForTest();
  b.vault._resetForTest();
  b.db._resetForTest();
  await b.vault.init({ dataDir: tmpDir });
  await b.db.init({
    dataDir: tmpDir,
    tmpDir:  path.join(tmpDir, "tmpfs"),
    schema:  WIKI_SCHEMA,
  });
  // Queue init — local protocol, in-process backend.
  b.queue.init({ backends: { primary: { protocol: "local" } } });
  // ExternalDb init — fake Postgres-dialect backend so examples that
  // call b.externalDb.read.query / write.query / transaction reach a
  // callable pool. Returns empty rows for any SQL.
  var fake = _fakePgClient();
  b.externalDb.init({
    backends: {
      main: {
        connect: fake.connect, query: fake.query, close: fake.close,
        dialect: "postgres",
      },
    },
    defaultBackend: "main",
  });
  // breakGlass init — wiki examples call b.breakGlass.policy.set /
  // .grant directly, which require the namespace to be initialized.
  if (b.breakGlass && typeof b.breakGlass.init === "function") {
    try { b.breakGlass.init({}); } catch (_e) {}
  }
  // Storage init — wiki object-store examples call b.storage.put/get
  // directly without showing init; the validator inits a local-filesystem
  // backend so they reach the framework boundary.
  if (b.storage && typeof b.storage.init === "function") {
    try {
      b.storage.init({
        backends: {
          primary: { protocol: "local", root: path.join(tmpDir, "object-store") },
        },
      });
    } catch (_e) {}
  }
  // Cluster init is intentionally NOT done here — it requires a real
  // externalDb provider for leader election and the validator harness's
  // fake-backend doesn't satisfy that. Scheduler/cluster examples that
  // need cluster.init are exempted for the same reason.
  return { tmpDir: tmpDir };
}

// Strip illustrative scaffolding that's not part of the example's
// actual call shape. Common patterns:
//
//   var b = require("@blamejs/core");
//   module.exports = b.db.declareView({...});
//
// → run the call directly without dragging require/module-exports
// through vm.compileFunction (which doesn't expose `require`).
function _preprocessExample(code) {
  return code
    // Drop a leading `var b = require("@blamejs/core");` line.
    .replace(/^\s*var\s+b\s*=\s*require\(['"]@blamejs\/core['"]\);?\s*$/gm, "")
    // Drop other top-level `var X = require(...);` lines — examples
    // sometimes import operator-side libs (the `pg` driver, etc.) we
    // already provide as stubs in the harness.
    .replace(/^\s*var\s+[A-Za-z_$][\w$]*\s*=\s*require\(['"][^'"]+['"]\);?\s*$/gm, "")
    // `module.exports = expr;` → just `expr;` — preserves the
    // expression so the example still calls the framework.
    .replace(/\bmodule\.exports\s*=\s*/g, "");
}

async function _teardownFixture(handle) {
  try { if (b.queue && typeof b.queue.shutdown === "function") await b.queue.shutdown(); } catch (_e) {}
  try { await b.externalDb.shutdown(); } catch (_e) {}
  // Drain audit handler buffered emissions BEFORE close so pending
  // rows land in audit_log rather than leaking into the next child.
  try { await b.audit.flush(); } catch (_e) {}
  try { b.db.close(); } catch (_e) {}
  b.audit._resetForTest();
  b.db._resetForTest();
  b.vault._resetForTest();
  b.cluster._resetForTest();
  if (handle && handle.tmpDir) {
    try { fs.rmSync(handle.tmpDir, { recursive: true, force: true }); } catch (_e) {}
  }
}

// Use the real b.router.Router instance — wiki examples that call
// router.use(...) / router.post(...) reach the actual framework
// surface, so any drift in the routing API surfaces here too.
function _realRouter() {
  return new b.router.Router();
}

function _stubUser() {
  return {
    _id:        "u-1",
    id:         "u-1",
    email:      "alice@example.test",
    name:       "Alice",
    tenantId:   "t-1",
    roles:      ["admin"],
    scopes:     ["*:*"],
    passwordHash: "argon2-fake",
  };
}

function _runCode(code) {
  var preprocessed = _preprocessExample(code);
  var asyncBody = "return (async () => {\n" + preprocessed + "\n})();";
  var harness = vm.compileFunction(asyncBody, [
    "b", "req", "res", "env", "C", "router", "user", "userId", "sid", "since", "id",
    "secret", "presented", "stored", "verified", "issued", "record",
    "keys", "perms", "signer", "breaker", "store",
    "rawSsn", "patientId", "orderId", "pgBackend", "rollupFn",
    "welcomeTemplate", "buf", "groupName", "tenantId", "expectedBasic",
    "policyId", "session", "claim", "stream", "fetchUrl",
    "reason", "batchId", "sku", "slug", "payload", "jobId",
    "actorId", "channel", "topic", "key", "value", "rid",
    "factor", "title", "saveHandler",
    "pg", "connectPrimary", "connectReplica", "connectReplica1", "connectReplica2",
    "rawConnect", "rawQuery", "operatorPgClient", "log", "db",
    // Additional operator-side stubs added to support compound
    // primitive examples (handler / middleware / helper references
    // that the original prose-shaped sections embedded in multi-line
    // call patterns).
    "app", "authMiddleware", "loginHandler", "users", "template",
    "metrics", "currentToken", "largeBuffer", "body", "loginUrl", "meUrl",
    // Node built-ins commonly needed by examples that mkdir / join paths.
    // The preprocessor strips `var path = require("path")` lines, so we
    // pass the real modules in directly; examples reference them as if
    // already required.
    "path", "os", "fs",
  ]);
  var fakeConnect = function () { return _fakePgClient().connect(); };
  var noopThen = function () { return Promise.resolve({ rows: [], rowCount: 0 }); };
  return harness(
    b,
    _stubReq(), _stubRes(), _envFn,
    b.constants,
    _realRouter(),
    _stubUser(),
    "u-1",                // userId
    "sess-1",             // sid
    Date.now() - 60000,   // since
    "id-1",               // id
    "test-secret-32-chars-min-pad-padding",     // secret
    "test-secret-32-chars-min-pad-padding",     // presented
    "argon2-fake-stored-hash",                  // stored
    null,                 // verified
    null,                 // issued
    null,                 // record
    null,                 // keys
    null,                 // perms
    null,                 // signer
    null,                 // breaker
    {},                   // store
    "123-45-6789",        // rawSsn
    "p-1",                // patientId
    "o-1",                // orderId
    "main",               // pgBackend (string backend name)
    function () { return Promise.resolve(); },  // rollupFn
    function () { return { subject: "Welcome", text: "Welcome aboard!" }; }, // welcomeTemplate
    Buffer.from("test-buf"),  // buf
    "ops-team",           // groupName
    "t-1",                // tenantId
    "Basic dGVzdDp0ZXN0",  // expectedBasic
    "policy-1",           // policyId
    {},                   // session (some examples shadow req.session as `session` local)
    {},                   // claim
    null,                 // stream
    "https://example.test/api",  // fetchUrl
    "investigation",      // reason
    "batch-1",            // batchId
    "SKU-001",            // sku
    "test-slug",          // slug
    { foo: "bar" },       // payload
    "job-1",              // jobId
    "u-1",                // actorId
    "channel-1",          // channel
    "topic-1",            // topic
    "key-1",              // key
    "value-1",            // value
    "row-1",              // rid
    { type: "totp", code: "123456", secret: "JBSWY3DPEHPK3PXP" }, // factor
    "title-1",            // title
    function (_req, _res, next) { next && next(); },  // saveHandler
    _fakePgClient(),
    fakeConnect, fakeConnect, fakeConnect, fakeConnect, fakeConnect,
    noopThen, _fakePgClient(),
    { warn: function () {}, info: function () {}, error: function () {}, debug: function () {} },
    b.db,                 // db
    // Operator-side stubs:
    {                     // app — Express-/router-shape stub. Examples that
                          // call app.use(mw) record the registration without
                          // actually mounting a server.
      use:    function () { return this; },
      get:    function () { return this; },
      post:   function () { return this; },
      put:    function () { return this; },
      patch:  function () { return this; },
      delete: function () { return this; },
      head:   function () { return this; },
      listen: function () { return { close: function () {} }; },
      close:  function () {},
    },
    function (_req, _res, next) { next && next(); },  // authMiddleware
    function (_req, _res, next) { next && next(); },  // loginHandler
    {                     // users — db-model stub (.create, .findOne, .updateOne, etc.)
      create:     async function (row) { return Object.assign({ _id: "u-stub" }, row); },
      findOne:    async function () { return null; },
      findMany:   async function () { return []; },
      updateOne:  async function () { return true; },
      deleteOne:  async function () { return true; },
      count:      async function () { return 0; },
    },
    {                     // template — template engine stub (.create / .precompileAll / .render)
      create:        function () { return this; },
      precompileAll: function () { return this; },
      render:        function () { return ""; },
    },
    {                     // metrics — observability counter stub
      counter:   function () { return { inc: function () {}, observe: function () {} }; },
      histogram: function () { return { observe: function () {} }; },
      gauge:     function () { return { set: function () {}, inc: function () {}, dec: function () {} }; },
    },
    function () { return "wiki-validator-token-stub"; },  // currentToken
    Buffer.alloc(64),     // largeBuffer
    { foo: "bar" },       // body — generic request body
    "https://example.test/login",   // loginUrl
    "https://example.test/me",      // meUrl
    path,                  // node:path
    os,                    // node:os
    fs                     // node:fs
  );
}

async function main() {
  var stdin = "";
  for await (var chunk of process.stdin) stdin += chunk;
  var spec = JSON.parse(stdin);

  var handle;
  try {
    handle = await _bootFixture();
  } catch (e) {
    process.stdout.write(JSON.stringify({
      status: "fixture-error",
      error:  (e && e.message) || String(e),
    }));
    process.exit(0);
  }

  var outcome;
  try {
    await _runCode(spec.code);
    outcome = { status: "ran" };
  } catch (e) {
    var msg = (e && e.message) || String(e);
    var stack = (e && e.stack) || "";
    if (e instanceof ReferenceError) {
      var match = msg.match(/^([A-Za-z_$][\w$]*) is not defined/);
      outcome = {
        status:  "reference-error",
        error:   msg,
        missing: match ? match[1] : null,
      };
    } else if (e instanceof SyntaxError) {
      outcome = { status: "syntax-error", error: msg };
    } else {
      outcome = {
        status: "runtime-error",
        error:  msg,
        stack:  stack.split("\n").slice(0, 5).join("\n"),
      };
    }
  } finally {
    await _teardownFixture(handle);
  }

  // Framework boot writes JSON-shaped log lines to stdout; the outcome
  // is preceded by a sentinel so the parent can locate it in the
  // mixed stream.
  process.stdout.write("\n<<<WIKI-VALIDATOR-OUTCOME>>>\n" + JSON.stringify(outcome) + "\n");
  process.exit(0);
}

main().catch(function (e) {
  process.stdout.write("\n<<<WIKI-VALIDATOR-OUTCOME>>>\n" + JSON.stringify({
    status: "harness-error",
    error:  (e && e.stack) || String(e),
  }) + "\n");
  process.exit(1);
});
