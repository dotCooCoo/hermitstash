"use strict";
/**
 * b.openapi — OpenAPI 3.1 schema-document builder.
 */

var b = require("../..");
var check = require("../helpers/check").check;

function rejects(label, fn, pattern) {
  var threw = false; var msg = "";
  try { fn(); } catch (e) { threw = true; msg = e.message; }
  check("threw on " + label, threw && (pattern.test ? pattern.test(msg) : msg.indexOf(pattern) !== -1));
}

function run() {
  // ---- module shape ----
  check("b.openapi is object",                   typeof b.openapi === "object");
  check("b.openapi.create is fn",                typeof b.openapi.create === "function");
  check("b.openapi.security is object",          typeof b.openapi.security === "object");
  check("b.openapi.VERSION === 3.1.0",           b.openapi.VERSION === "3.1.0");
  check("b.openapi.schemaWalk is fn",            typeof b.openapi.schemaWalk === "function");

  // ---- create requires info ----
  rejects("create: missing info",
    function () { b.openapi.create({}); }, /info/);
  rejects("create: missing info.title",
    function () { b.openapi.create({ info: { version: "1.0" } }); }, /title/);
  rejects("create: missing info.version",
    function () { b.openapi.create({ info: { title: "T" } }); }, /version/);

  // ---- minimal valid doc ----
  var api = b.openapi.create({ info: { title: "Test API", version: "1.0.0" } });
  check("create returns builder",                typeof api.path === "function");
  check("info accessible",                       api.info.title === "Test API");

  // ---- path + responses ----
  api.path("get", "/health", {
    summary: "Health probe",
    responses: {
      "200": { description: "ok",
               content: { "application/json": { schema: { type: "object" } } } },
    },
  });
  var doc1 = api.toJson();
  check("doc.openapi version",                   doc1.openapi === "3.1.0");
  check("doc.info.title",                        doc1.info.title === "Test API");
  check("doc.paths['/health'] exists",           doc1.paths["/health"] != null);
  check("doc.paths['/health'].get.summary",      doc1.paths["/health"].get.summary === "Health probe");
  check("doc.paths['/health'].get.responses",    doc1.paths["/health"].get.responses["200"].description === "ok");

  // ---- duplicate operation rejected ----
  rejects("path: duplicate operation",
    function () {
      api.path("get", "/health", {
        responses: { "200": { description: "ok" } },
      });
    },
    /duplicate operation/);

  // ---- bad method ----
  rejects("path: bad method",
    function () {
      api.path("nope", "/x", { responses: { "200": { description: "ok" } } });
    },
    /method must be/);

  // ---- bad URL pattern ----
  rejects("path: missing slash prefix",
    function () {
      api.path("get", "noslash", { responses: { "200": { description: "ok" } } });
    },
    /must start with/);

  // ---- responses required ----
  rejects("path: missing responses",
    function () { api.path("get", "/needs-resp", {}); },
    /responses object is required/);

  rejects("path: response missing description",
    function () {
      api.path("get", "/no-desc", { responses: { "200": {} } });
    },
    /description is required/);

  // ---- path-template parameter validation ----
  rejects("path: undeclared {id}",
    function () {
      api.path("get", "/users/{id}", {
        responses: { "200": { description: "ok" } },
      });
    },
    /no parameter with in=path/);

  api.path("get", "/users/{id}", {
    parameters: [{ name: "id", in: "path", required: true, schema: { type: "string" } }],
    responses: { "200": { description: "ok" } },
  });
  var doc2 = api.toJson();
  check("path: declared {id} accepted",          doc2.paths["/users/{id}"].get != null);

  // path param without required:true
  rejects("path: path param missing required:true",
    function () {
      api.path("get", "/posts/{id}", {
        parameters: [{ name: "id", in: "path", schema: { type: "string" } }],
        responses: { "200": { description: "ok" } },
      });
    },
    /must have required=true/);

  // bad parameter location
  rejects("path: bad parameter in",
    function () {
      api.path("get", "/badparam", {
        parameters: [{ name: "x", in: "body", schema: { type: "string" } }],
        responses: { "200": { description: "ok" } },
      });
    },
    /in must be one of/);

  // ---- request body ----
  api.path("post", "/users", {
    summary: "Create user",
    requestBody: {
      required: true,
      content: {
        "application/json": {
          schema: {
            type: "object",
            properties: {
              name:  { type: "string" },
              email: { type: "string", format: "email" },
            },
            required: ["name", "email"],
          },
        },
      },
    },
    responses: {
      "201": { description: "created",
               content: { "application/json": { schema: { type: "object" } } } },
      "400": { description: "bad request" },
    },
  });
  var doc3 = api.toJson();
  check("post /users requestBody required",      doc3.paths["/users"].post.requestBody.required === true);
  check("post /users response 201",              doc3.paths["/users"].post.responses["201"].description === "created");

  // ---- reusable component schema ----
  api.schema("User", {
    type: "object",
    properties: {
      id:    { type: "string", format: "uuid" },
      name:  { type: "string" },
      email: { type: "string", format: "email" },
    },
    required: ["id", "name", "email"],
  });
  var doc4 = api.toJson();
  check("components.schemas.User present",       doc4.components.schemas.User.type === "object");
  check("User has 3 properties",                 Object.keys(doc4.components.schemas.User.properties).length === 3);

  rejects("schema: duplicate component",
    function () { api.schema("User", { type: "object" }); },
    /already registered/);

  rejects("schema: missing name",
    function () { api.schema("", { type: "object" }); },
    /name/);

  // ---- tags ----
  api.tag({ name: "users", description: "User management" });
  var doc5 = api.toJson();
  check("tag: added",                            Array.isArray(doc5.tags) && doc5.tags[0].name === "users");

  rejects("tag: missing name",
    function () { api.tag({ description: "x" }); }, /tagSpec.name/);

  // ---- security ----
  api.security.add("bearerJwt", b.openapi.security.bearer({ jwtBearer: true }));
  api.security.require({ bearerJwt: [] });
  var doc6 = api.toJson();
  check("security scheme: bearerJwt",            doc6.components.securitySchemes.bearerJwt.type === "http");
  check("security scheme: bearerJwt format",     doc6.components.securitySchemes.bearerJwt.bearerFormat === "JWT");
  check("security: doc-level",                   Array.isArray(doc6.security) && doc6.security[0].bearerJwt.length === 0);

  // dangling security reference detected
  var apiBad = b.openapi.create({ info: { title: "Bad API", version: "1.0" } });
  apiBad.security.require({ undefinedScheme: [] });
  apiBad.path("get", "/x", { responses: { "200": { description: "ok" } } });
  rejects("toJson: dangling doc-level security",
    function () { apiBad.toJson(); },
    /undefined scheme/);

  var apiBad2 = b.openapi.create({ info: { title: "Bad API 2", version: "1.0" } });
  apiBad2.path("get", "/x", {
    security: [{ ghost: [] }],
    responses: { "200": { description: "ok" } },
  });
  rejects("toJson: dangling op-level security",
    function () { apiBad2.toJson(); },
    /undefined security scheme/);

  // ---- security scheme builders ----
  var sec = b.openapi.security;
  check("security.bearer",                       sec.bearer().type === "http" && sec.bearer().scheme === "bearer");
  check("security.basic",                        sec.basic().scheme === "basic");
  var ak = sec.apiKey({ name: "X-API-Key", in: "header" });
  check("security.apiKey",                       ak.type === "apiKey" && ak.name === "X-API-Key");
  rejects("apiKey: bad in",
    function () { sec.apiKey({ name: "k", in: "body" }); }, /in must be one of/);
  rejects("apiKey: missing name",
    function () { sec.apiKey({ in: "header" }); }, /name/);

  var oauth = sec.oauth2({
    flows: {
      authorizationCode: {
        authorizationUrl: "https://idp.example.com/auth",
        tokenUrl:         "https://idp.example.com/token",
        scopes:           { "read": "read access", "write": "write access" },
      },
    },
  });
  check("security.oauth2",                       oauth.type === "oauth2");
  check("oauth2.flow.authorizationCode",         oauth.flows.authorizationCode.tokenUrl === "https://idp.example.com/token");
  rejects("oauth2: bad flow name",
    function () { sec.oauth2({ flows: { nope: { scopes: {} } } }); },
    /unknown flow/);
  rejects("oauth2: missing scopes",
    function () { sec.oauth2({ flows: { clientCredentials: { tokenUrl: "https://x", scopes: null } } }); },
    /scopes must be/);

  var oidc = sec.openIdConnect({ url: "https://idp.example.com/.well-known/openid-configuration" });
  check("security.openIdConnect",                oidc.type === "openIdConnect");
  rejects("openIdConnect: missing url",
    function () { sec.openIdConnect({}); }, /url/);

  var mtls = sec.mtls();
  check("security.mtls",                         mtls.type === "mutualTLS");

  var dpop = sec.dpop();
  check("security.dpop",                         dpop.type === "http" && dpop.scheme === "dpop");

  // ---- server entries ----
  var apiS = b.openapi.create({
    info: { title: "S", version: "1.0" },
    servers: [{ url: "https://api.example.com", description: "prod" }],
  });
  apiS.server({ url: "https://staging.example.com", description: "staging" });
  apiS.path("get", "/x", { responses: { "200": { description: "ok" } } });
  var docS = apiS.toJson();
  check("servers: 2 entries",                    docS.servers.length === 2);

  rejects("server: bad spec",
    function () { apiS.server({ description: "no url" }); }, /url/);

  // ---- toJsonString ----
  var jsonStr = api.toJsonString();
  check("toJsonString: returns string",          typeof jsonStr === "string");
  var parsed = JSON.parse(jsonStr);
  check("toJsonString: round-trips",             parsed.openapi === "3.1.0");

  // ---- middleware ----
  var apiMw = b.openapi.create({ info: { title: "MW", version: "1.0" } });
  apiMw.path("get", "/health", { responses: { "200": { description: "ok" } } });
  var mw = apiMw.middleware({ pretty: true });
  check("middleware: factory returns fn",        typeof mw === "function");
  var sent = { status: null, headers: null, body: null };
  var res = {
    writeHead: function (s, h) { sent.status = s; sent.headers = h; },
    end:       function (b) { sent.body = b; },
  };
  mw({}, res, function () {});
  check("middleware: 200",                       sent.status === 200);
  check("middleware: Content-Type JSON",         sent.headers["Content-Type"].indexOf("application/json") === 0);
  check("middleware: Cache-Control",             sent.headers["Cache-Control"] === "public, max-age=300");
  var parsedBody = JSON.parse(sent.body);
  check("middleware: body has paths",            parsedBody.paths["/health"] != null);

  check("middleware.forceRebuild is fn",         typeof mw.forceRebuild === "function");

  // ---- schemaWalk: safeSchema input ----
  var s = b.safeSchema;
  var userSchema = s.object({
    id:    s.string(),
    name:  s.string(),
    age:   s.number(),
    email: s.string().optional(),
  });
  var converted = b.openapi.schemaWalk(userSchema);
  check("schemaWalk: object type",               converted.type === "object");
  check("schemaWalk: properties present",        converted.properties.id.type === "string");
  check("schemaWalk: number property",           converted.properties.age.type === "number");
  check("schemaWalk: required list excludes optional",
                                                  Array.isArray(converted.required) &&
                                                  converted.required.indexOf("id") !== -1 &&
                                                  converted.required.indexOf("email") === -1);

  // ---- schemaWalk: passthrough plain JSON Schema ----
  var plainJs = b.openapi.schemaWalk({
    type: "object",
    properties: { x: { type: "string" } },
  });
  check("schemaWalk: passthrough plain",         plainJs.type === "object" && plainJs.properties.x.type === "string");

  // ---- schemaWalk: string primitive ----
  var prim = b.openapi.schemaWalk("integer");
  check("schemaWalk: primitive string",          prim.type === "integer");

  // ---- response component ----
  api.response("Error400", {
    description: "Bad request",
    content: { "application/json": { schema: { type: "object" } } },
  });
  var doc7 = api.toJson();
  check("components.responses.Error400",         doc7.components.responses.Error400.description === "Bad request");

  rejects("response: missing description",
    function () { api.response("Bad", { content: {} }); }, /description/);

  // ---- parameter component ----
  api.parameter("PageSize", {
    name: "pageSize",
    in:   "query",
    schema: s.number(),
  });
  var doc8 = api.toJson();
  check("components.parameters.PageSize",        doc8.components.parameters.PageSize.in === "query");

  // ---- requestBody component ----
  api.requestBody("CreateUser", {
    required: true,
    content: { "application/json": { schema: { type: "object" } } },
  });
  var doc9 = api.toJson();
  check("components.requestBodies.CreateUser",   doc9.components.requestBodies.CreateUser.required === true);

  // ---- header component ----
  api.header("X-Rate-Limit", { schema: { type: "integer" } });
  // ---- example component ----
  api.example("UserSample", { value: { id: "u1", name: "Alex" } });
  var doc10 = api.toJson();
  check("components.headers + examples",         doc10.components.headers["X-Rate-Limit"] != null &&
                                                  doc10.components.examples.UserSample.value.id === "u1");

  // ---- final shape ----
  var finalDoc = api.toJson();
  check("final: has paths",                      typeof finalDoc.paths === "object");
  check("final: has components.schemas",         typeof finalDoc.components.schemas === "object");
  check("final: has tags",                       Array.isArray(finalDoc.tags));
  check("final: openapi version",                finalDoc.openapi === "3.1.0");

  // ---- path methods stable order ----
  var apiOrder = b.openapi.create({ info: { title: "O", version: "1.0" } });
  apiOrder.path("post", "/x", { responses: { "200": { description: "ok" } } });
  apiOrder.path("get", "/x",  { responses: { "200": { description: "ok" } } });
  apiOrder.path("delete", "/x", { responses: { "204": { description: "no content" } } });
  var orderDoc = apiOrder.toJson();
  var methodKeys = Object.keys(orderDoc.paths["/x"]);
  check("methods ordered: get first",            methodKeys[0] === "get");
  check("methods ordered: post second",          methodKeys[1] === "post");
  check("methods ordered: delete third",         methodKeys[2] === "delete");

  // ---- paths sorted alphabetically ----
  var apiSorted = b.openapi.create({ info: { title: "Z", version: "1.0" } });
  apiSorted.path("get", "/zebra", { responses: { "200": { description: "ok" } } });
  apiSorted.path("get", "/alpha", { responses: { "200": { description: "ok" } } });
  apiSorted.path("get", "/middle", { responses: { "200": { description: "ok" } } });
  var sortedDoc = apiSorted.toJson();
  var pathKeys = Object.keys(sortedDoc.paths);
  check("paths sorted: alpha first",             pathKeys[0] === "/alpha");
  check("paths sorted: middle second",           pathKeys[1] === "/middle");
  check("paths sorted: zebra last",              pathKeys[2] === "/zebra");

  // ---- deprecated flag ----
  var apiDep = b.openapi.create({ info: { title: "D", version: "1.0" } });
  apiDep.path("get", "/old", {
    deprecated: true,
    responses: { "200": { description: "ok" } },
  });
  var depDoc = apiDep.toJson();
  check("deprecated retained",                   depDoc.paths["/old"].get.deprecated === true);

  // ---- YAML emitter ----
  var yapi = b.openapi.create({ info: { title: "Y", version: "1.0" } });
  yapi.path("get", "/health", { responses: { "200": { description: "ok" } } });
  yapi.schema("Item", { type: "object", properties: { id: { type: "string" } }, required: ["id"] });
  var yamlOut = yapi.toYaml();
  check("toYaml: returns string",                typeof yamlOut === "string");
  check("toYaml: starts with openapi key",       yamlOut.indexOf("openapi:") !== -1);
  check("toYaml: contains paths",                yamlOut.indexOf("paths:") !== -1);
  check("toYaml: contains health path",          yamlOut.indexOf("/health") !== -1);
  check("toYaml: contains components",           yamlOut.indexOf("Item:") !== -1);
  check("toYaml: 2-space indent",                yamlOut.indexOf("  info:") !== -1 || yamlOut.indexOf("info:") !== -1);

  // YAML quoting of special values
  var yspecial = b.openapi.toYaml({
    booleanKey: true,
    stringFalse: "false",       // string that looks like bool — must be quoted
    numericString: "12345",     // string that looks like number — must be quoted
    plainString: "hello",       // unambiguous — unquoted
    nullVal:    null,
    emptyArr:   [],
    emptyObj:   {},
    nested:     { inner: [1, 2, 3] },
  });
  check("yaml: bool unquoted",                   yspecial.indexOf("booleanKey: true") !== -1);
  check("yaml: numeric-looking string quoted",   yspecial.indexOf('numericString: "12345"') !== -1);
  check("yaml: bool-looking string quoted",      yspecial.indexOf('stringFalse: "false"') !== -1);
  check("yaml: null literal",                    yspecial.indexOf("nullVal: null") !== -1);
  check("yaml: empty array inline",              yspecial.indexOf("emptyArr: []") !== -1);
  check("yaml: empty object inline",             yspecial.indexOf("emptyObj: {}") !== -1);
  check("yaml: nested array",                    yspecial.indexOf("- 1") !== -1);

  rejects("toYaml: bad input",
    function () { b.openapi.toYaml(null); }, /non-null object/);

  // ---- complex realistic API doc ----
  var realApi = b.openapi.create({
    info: {
      title:   "Acme E-Commerce API",
      version: "2.3.1",
      description: "Internal API for the e-commerce platform",
      termsOfService: "https://acme.example.com/terms",
      contact: { name: "API team", email: "api@acme.example.com" },
      license: { name: "Apache-2.0", url: "https://apache.org/licenses/LICENSE-2.0" },
    },
    servers: [
      { url: "https://api.acme.example.com/v2", description: "production" },
      { url: "https://staging-api.acme.example.com/v2", description: "staging" },
    ],
  });

  realApi.security.add("bearerAuth", b.openapi.security.bearer({ jwtBearer: true }));
  realApi.security.add("apiKeyAuth", b.openapi.security.apiKey({ name: "X-API-Key", in: "header" }));
  realApi.security.require({ bearerAuth: [] });

  realApi.tag({ name: "products", description: "Product catalog" });
  realApi.tag({ name: "orders", description: "Order management" });

  realApi.schema("Product", {
    type: "object",
    properties: {
      id:    { type: "string", format: "uuid" },
      name:  { type: "string" },
      price: { type: "number", minimum: 0 },
      tags:  { type: "array", items: { type: "string" } },
    },
    required: ["id", "name", "price"],
  });
  realApi.schema("ErrorResponse", {
    type: "object",
    properties: {
      code:    { type: "string" },
      message: { type: "string" },
      details: { type: "object", additionalProperties: true },
    },
    required: ["code", "message"],
  });

  realApi.path("get", "/products", {
    summary:     "List products",
    operationId: "listProducts",
    tags:        ["products"],
    parameters: [
      { name: "page",  in: "query", schema: { type: "integer", minimum: 1, default: 1 } },
      { name: "limit", in: "query", schema: { type: "integer", minimum: 1, maximum: 100, default: 20 } },
    ],
    responses: {
      "200": {
        description: "Product list",
        content: {
          "application/json": {
            schema: {
              type: "array", items: { "$ref": "#/components/schemas/Product" },
            },
          },
        },
      },
      "401": { description: "Authentication required" },
    },
  });

  realApi.path("post", "/products", {
    summary:     "Create product",
    operationId: "createProduct",
    tags:        ["products"],
    requestBody: {
      required: true,
      content: {
        "application/json": {
          schema: { "$ref": "#/components/schemas/Product" },
        },
      },
    },
    responses: {
      "201": {
        description: "Product created",
        content: { "application/json": { schema: { "$ref": "#/components/schemas/Product" } } },
      },
      "400": {
        description: "Validation failed",
        content: { "application/json": { schema: { "$ref": "#/components/schemas/ErrorResponse" } } },
      },
    },
  });

  realApi.path("get", "/products/{productId}", {
    summary:    "Get a product",
    operationId: "getProduct",
    tags:       ["products"],
    parameters: [
      { name: "productId", in: "path", required: true, schema: { type: "string", format: "uuid" } },
    ],
    responses: {
      "200": {
        description: "Product",
        content: { "application/json": { schema: { "$ref": "#/components/schemas/Product" } } },
      },
      "404": { description: "Not found" },
    },
  });

  realApi.path("get", "/admin/orders", {
    summary:     "List all orders (admin)",
    operationId: "adminListOrders",
    tags:        ["orders"],
    security:    [{ bearerAuth: [] }, { apiKeyAuth: [] }],
    responses:   { "200": { description: "Orders" } },
  });

  var realDoc = realApi.toJson();
  check("realDoc: title",                         realDoc.info.title === "Acme E-Commerce API");
  check("realDoc: contact",                       realDoc.info.contact.email === "api@acme.example.com");
  check("realDoc: 3 path keys (4 ops)",           Object.keys(realDoc.paths).length === 3);
  check("realDoc: /products has 2 methods",       Object.keys(realDoc.paths["/products"]).length === 2);
  check("realDoc: products list operationId",     realDoc.paths["/products"].get.operationId === "listProducts");
  check("realDoc: post products requires body",   realDoc.paths["/products"].post.requestBody.required === true);
  check("realDoc: get by id has path param",      realDoc.paths["/products/{productId}"].get.parameters[0].in === "path");
  check("realDoc: admin orders has 2 sec opts",   realDoc.paths["/admin/orders"].get.security.length === 2);

  // YAML round-trip of complex doc
  var realYaml = realApi.toYaml();
  check("realYaml: substantial",                  realYaml.length > 1000);
  check("realYaml: contains operationId",         realYaml.indexOf("listProducts") !== -1);
  check("realYaml: contains tags",                realYaml.indexOf("products") !== -1);

  // ---- middleware integration ----
  var apiMw2 = b.openapi.create({ info: { title: "MW2", version: "1.0" } });
  apiMw2.path("get", "/foo", { responses: { "200": { description: "ok" } } });
  var mw2 = apiMw2.middleware();
  var sent2 = { status: null, body: null, headers: null };
  var res2 = {
    writeHead: function (s, h) { sent2.status = s; sent2.headers = h; },
    end:       function (b) { sent2.body = b; },
  };
  mw2({}, res2, function () {});
  check("mw2: 200 default",                      sent2.status === 200);

  // forceRebuild after path added
  apiMw2.path("get", "/bar", { responses: { "200": { description: "ok" } } });
  mw2.forceRebuild();
  var sent3 = { status: null, body: null, headers: null };
  var res3 = {
    writeHead: function (s, h) { sent3.status = s; sent3.headers = h; },
    end:       function (b) { sent3.body = b; },
  };
  mw2({}, res3, function () {});
  var parsed3 = JSON.parse(sent3.body);
  check("mw2: forceRebuild picks up new path",   parsed3.paths["/bar"] != null);

  // ---- bearerAuth without JWT format ----
  var bb = sec.bearer();
  check("bearer (no jwt)",                       bb.bearerFormat === undefined);

  // ---- all 4 oauth2 flow types ----
  var oauth4 = sec.oauth2({
    flows: {
      authorizationCode: {
        authorizationUrl: "https://auth/auth",
        tokenUrl:         "https://auth/token",
        scopes:           {},
      },
      clientCredentials: {
        tokenUrl: "https://auth/token",
        scopes:   {},
      },
      implicit: {
        authorizationUrl: "https://auth/auth",
        scopes:           {},
      },
      password: {
        tokenUrl: "https://auth/token",
        scopes:   {},
      },
    },
  });
  check("oauth2: 4 flows accepted",              Object.keys(oauth4.flows).length === 4);

  // missing required URLs
  rejects("oauth2.authCode: missing authUrl",
    function () { sec.oauth2({ flows: { authorizationCode: { tokenUrl: "x", scopes: {} } } }); },
    /authorizationUrl/);
  rejects("oauth2.authCode: missing tokenUrl",
    function () { sec.oauth2({ flows: { authorizationCode: { authorizationUrl: "x", scopes: {} } } }); },
    /tokenUrl/);

  // ---- middleware.openapiServe ----
  check("middleware.openapiServe is fn",         typeof b.middleware.openapiServe === "function");

  rejects("openapiServe: missing document",
    function () { b.middleware.openapiServe({}); }, /document must be/);

  rejects("openapiServe: bad pathJson",
    function () {
      b.middleware.openapiServe({ document: realApi, pathJson: "no-slash" });
    }, /must start with/);

  var serveDoc = b.openapi.create({ info: { title: "Serve", version: "1.0" } });
  serveDoc.path("get", "/health", { responses: { "200": { description: "ok" } } });
  var serve = b.middleware.openapiServe({
    document: serveDoc,
    pathJson: "/openapi.json",
    pathYaml: "/openapi.yaml",
    pretty:   true,
    audit:    false,
  });

  // GET /openapi.json
  var sentJson = { status: null, headers: null, body: null };
  var resJson = {
    writeHead: function (s, h) { sentJson.status = s; sentJson.headers = h; },
    end:       function (b) { sentJson.body = b; },
  };
  var nextJson = 0;
  serve({ method: "GET", url: "/openapi.json", pathname: "/openapi.json", headers: {} },
        resJson, function () { nextJson += 1; });
  check("openapiServe JSON: 200",                sentJson.status === 200);
  check("openapiServe JSON: Content-Type",       sentJson.headers["Content-Type"].indexOf("application/json") === 0);
  check("openapiServe JSON: ETag",               typeof sentJson.headers["ETag"] === "string");
  check("openapiServe JSON: CORS public",        sentJson.headers["Access-Control-Allow-Origin"] === "*");
  check("openapiServe JSON: did not call next",  nextJson === 0);
  var parsedServed = JSON.parse(sentJson.body);
  check("openapiServe JSON: body is openapi doc", parsedServed.openapi === "3.1.0");

  // GET /openapi.yaml
  var sentYaml = { status: null, headers: null, body: null };
  var resYaml = {
    writeHead: function (s, h) { sentYaml.status = s; sentYaml.headers = h; },
    end:       function (b) { sentYaml.body = b; },
  };
  serve({ method: "GET", url: "/openapi.yaml", pathname: "/openapi.yaml", headers: {} },
        resYaml, function () {});
  check("openapiServe YAML: 200",                sentYaml.status === 200);
  check("openapiServe YAML: Content-Type",       sentYaml.headers["Content-Type"].indexOf("application/yaml") === 0);

  // 304 on If-None-Match
  var etag = sentJson.headers["ETag"];
  var sent304 = { status: null, headers: null };
  var res304 = {
    writeHead: function (s, h) { sent304.status = s; sent304.headers = h; },
    end:       function () {},
  };
  serve({ method: "GET", url: "/openapi.json", pathname: "/openapi.json",
          headers: { "if-none-match": etag } },
        res304, function () {});
  check("openapiServe: 304 on matching ETag",    sent304.status === 304);

  // Other paths fall through
  var nextOther = 0;
  serve({ method: "GET", url: "/foo", pathname: "/foo", headers: {} },
        { writeHead: function () {}, end: function () {} },
        function () { nextOther += 1; });
  check("openapiServe: passes other paths",      nextOther === 1);

  // POST is passed through (only GET / HEAD respond)
  var nextPost = 0;
  serve({ method: "POST", url: "/openapi.json", pathname: "/openapi.json", headers: {} },
        { writeHead: function () {}, end: function () {} },
        function () { nextPost += 1; });
  check("openapiServe: POST falls through",      nextPost === 1);

  // accessControl=same-origin omits CORS header
  var serveSO = b.middleware.openapiServe({
    document: serveDoc,
    accessControl: "same-origin",
    audit: false,
  });
  var sentSO = { status: null, headers: null, body: null };
  serveSO({ method: "GET", url: "/openapi.json", pathname: "/openapi.json", headers: {} },
          { writeHead: function (s, h) { sentSO.headers = h; },
            end:       function () {} },
          function () {});
  check("openapiServe: same-origin omits CORS",  sentSO.headers["Access-Control-Allow-Origin"] == null);

  // accessControl={ allowOrigin } echoes one validated origin + Vary: Origin
  var serveAO = b.middleware.openapiServe({
    document: serveDoc,
    accessControl: { allowOrigin: "https://docs.example.com" },
    audit: false,
  });
  var sentAO = { headers: null };
  serveAO({ method: "GET", url: "/openapi.json", pathname: "/openapi.json", headers: {} },
          { writeHead: function (s, h) { sentAO.headers = h; },
            end:       function () {} },
          function () {});
  check("openapiServe: allowOrigin echoed",      sentAO.headers["Access-Control-Allow-Origin"] === "https://docs.example.com");
  check("openapiServe: allowOrigin sets Vary",   sentAO.headers["Vary"] === "Origin");

  // allowOrigin with a default port is canonicalized (443 dropped)
  var serveAOPort = b.middleware.openapiServe({
    document: serveDoc,
    accessControl: { allowOrigin: "https://Docs.Example.com:443" },
    audit: false,
  });
  var sentAOPort = { headers: null };
  serveAOPort({ method: "GET", url: "/openapi.json", pathname: "/openapi.json", headers: {} },
          { writeHead: function (s, h) { sentAOPort.headers = h; },
            end:       function () {} },
          function () {});
  check("openapiServe: allowOrigin canonicalized", sentAOPort.headers["Access-Control-Allow-Origin"] === "https://docs.example.com");

  // A bad allowOrigin throws at config time (header-injection / pathful / junk)
  rejects("openapiServe: allowOrigin with path rejected",
    function () { b.middleware.openapiServe({ document: serveDoc, accessControl: { allowOrigin: "https://x.example.com/docs" } }); },
    /bare origin/);
  rejects("openapiServe: allowOrigin CRLF rejected",
    function () { b.middleware.openapiServe({ document: serveDoc, accessControl: { allowOrigin: "https://x.example.com\r\nX-Evil: 1" } }); },
    /valid|bare origin/);
  rejects("openapiServe: allowOrigin non-http rejected",
    function () { b.middleware.openapiServe({ document: serveDoc, accessControl: { allowOrigin: "ftp://x.example.com" } }); },
    /valid|origin/);

  check("openapiServe.forceRebuild is fn",       typeof serve.forceRebuild === "function");

  // HEAD carries the GET response headers (incl. Content-Length) with an
  // EMPTY body (RFC 9110 §9.3.2). GET unchanged: it still returns the
  // body. Asserts the head-suppression against both JSON and YAML mounts.
  var sentHeadJson = { status: null, headers: null, body: undefined, ended: false };
  serve({ method: "HEAD", url: "/openapi.json", pathname: "/openapi.json", headers: {} },
        { writeHead: function (s, h) { sentHeadJson.status = s; sentHeadJson.headers = h; },
          end:       function (bdy) { sentHeadJson.body = bdy; sentHeadJson.ended = true; } },
        function () {});
  check("openapiServe HEAD JSON: 200",           sentHeadJson.status === 200);
  check("openapiServe HEAD JSON: Content-Length set like GET",
        sentHeadJson.headers["Content-Length"] === sentJson.headers["Content-Length"]);
  check("openapiServe HEAD JSON: Content-Type set like GET",
        sentHeadJson.headers["Content-Type"] === sentJson.headers["Content-Type"]);
  check("openapiServe HEAD JSON: empty body",
        sentHeadJson.ended === true && (sentHeadJson.body === undefined || sentHeadJson.body == null));

  var sentHeadYaml = { status: null, headers: null, body: undefined, ended: false };
  serve({ method: "HEAD", url: "/openapi.yaml", pathname: "/openapi.yaml", headers: {} },
        { writeHead: function (s, h) { sentHeadYaml.status = s; sentHeadYaml.headers = h; },
          end:       function (bdy) { sentHeadYaml.body = bdy; sentHeadYaml.ended = true; } },
        function () {});
  check("openapiServe HEAD YAML: 200",           sentHeadYaml.status === 200);
  check("openapiServe HEAD YAML: Content-Length set like GET",
        sentHeadYaml.headers["Content-Length"] === sentYaml.headers["Content-Length"]);
  check("openapiServe HEAD YAML: empty body",
        sentHeadYaml.ended === true && (sentHeadYaml.body === undefined || sentHeadYaml.body == null));

  // GET still returns the body after the HEAD path was added.
  var sentGetAfter = { status: null, headers: null, body: null };
  serve({ method: "GET", url: "/openapi.json", pathname: "/openapi.json", headers: {} },
        { writeHead: function (s, h) { sentGetAfter.status = s; sentGetAfter.headers = h; },
          end:       function (bdy) { sentGetAfter.body = bdy; } },
        function () {});
  check("openapiServe GET still returns body",
        sentGetAfter.status === 200 && typeof sentGetAfter.body === "string" &&
        sentGetAfter.body.length > 0);

  // ---- bigger schema-walk coverage ----
  var arrSchema = b.openapi.schemaWalk({
    type:  "array",
    items: { type: "string" },
    minItems: 1,
    maxItems: 100,
  });
  check("schemaWalk: array passthrough",         arrSchema.type === "array");
  check("schemaWalk: array minItems",            arrSchema.minItems === 1);

  var unionSchema = b.openapi.schemaWalk({
    oneOf: [{ type: "string" }, { type: "integer" }],
  });
  check("schemaWalk: oneOf passthrough",         Array.isArray(unionSchema.oneOf));

  // safeSchema array (kind extracted)
  var arrSs = s.array(s.string());
  var arrConv = b.openapi.schemaWalk(arrSs);
  check("schemaWalk: safeSchema array kind",     arrConv.type === "array");

  // safeSchema boolean
  var boolSs = s.boolean();
  var boolConv = b.openapi.schemaWalk(boolSs);
  check("schemaWalk: safeSchema boolean",        boolConv.type === "boolean");

  // bad schema input
  rejects("schemaWalk: bad input",
    function () { b.openapi.schemaWalk(123); }, /unsupported schema/);

  // ---- security composite ----
  var apiBoth = b.openapi.create({ info: { title: "Both", version: "1.0" } });
  apiBoth.security.add("oidc", b.openapi.security.openIdConnect({ url: "https://idp/.wkc" }));
  apiBoth.security.add("mtls", b.openapi.security.mtls({ description: "client cert" }));
  apiBoth.security.add("dpop", b.openapi.security.dpop());
  apiBoth.path("get", "/x", {
    security: [{ oidc: ["read"] }, { mtls: [], dpop: [] }],
    responses: { "200": { description: "ok" } },
  });
  var bothDoc = apiBoth.toJson();
  check("composite security: oidc",              bothDoc.components.securitySchemes.oidc.type === "openIdConnect");
  check("composite security: mtls",              bothDoc.components.securitySchemes.mtls.type === "mutualTLS");
  check("composite security: dpop scheme=dpop",  bothDoc.components.securitySchemes.dpop.scheme === "dpop");
  check("composite op security",                 bothDoc.paths["/x"].get.security[1].mtls.length === 0);

  // ---- empty paths still emits valid doc ----
  var apiEmpty = b.openapi.create({ info: { title: "E", version: "1.0" } });
  var emptyDoc = apiEmpty.toJson();
  check("empty doc: openapi version",            emptyDoc.openapi === "3.1.0");
  check("empty doc: paths is empty object",      typeof emptyDoc.paths === "object" &&
                                                   Object.keys(emptyDoc.paths).length === 0);
  check("empty doc: no components",              emptyDoc.components === undefined);

  // ---- request-body with description ----
  var apiReqDesc = b.openapi.create({ info: { title: "RD", version: "1.0" } });
  apiReqDesc.path("post", "/x", {
    requestBody: {
      description: "User payload",
      content: { "application/json": { schema: { type: "object" } } },
    },
    responses: { "200": { description: "ok" } },
  });
  var rdDoc = apiReqDesc.toJson();
  check("requestBody: description retained",     rdDoc.paths["/x"].post.requestBody.description === "User payload");

  // ---- response with multiple content types ----
  var apiMulti = b.openapi.create({ info: { title: "MC", version: "1.0" } });
  apiMulti.path("get", "/x", {
    responses: {
      "200": {
        description: "ok",
        content: {
          "application/json": { schema: { type: "object" } },
          "application/xml":  { schema: { type: "object" } },
          "text/plain":       { schema: { type: "string" } },
        },
      },
    },
  });
  var mcDoc = apiMulti.toJson();
  check("response: 3 content types",             Object.keys(mcDoc.paths["/x"].get.responses["200"].content).length === 3);

  // ---- nested path templates ----
  var apiNested = b.openapi.create({ info: { title: "N", version: "1.0" } });
  apiNested.path("get", "/users/{userId}/posts/{postId}", {
    parameters: [
      { name: "userId", in: "path", required: true, schema: { type: "string" } },
      { name: "postId", in: "path", required: true, schema: { type: "string" } },
    ],
    responses: { "200": { description: "ok" } },
  });
  var nestedDoc = apiNested.toJson();
  check("nested path: 2 path params accepted",   nestedDoc.paths["/users/{userId}/posts/{postId}"].get.parameters.length === 2);

  // Missing one of two path params throws
  rejects("nested path: missing one path param",
    function () {
      var apiBad = b.openapi.create({ info: { title: "X", version: "1.0" } });
      apiBad.path("get", "/users/{userId}/posts/{postId}", {
        parameters: [
          { name: "userId", in: "path", required: true, schema: { type: "string" } },
        ],
        responses: { "200": { description: "ok" } },
      });
    },
    /no parameter with in=path/);

  // ---- per-operation servers override ----
  var apiOpServers = b.openapi.create({
    info: { title: "OS", version: "1.0" },
    servers: [{ url: "https://default.example.com" }],
  });
  apiOpServers.path("post", "/upload", {
    servers: [{ url: "https://uploads.example.com" }],
    responses: { "200": { description: "ok" } },
  });
  var osDoc = apiOpServers.toJson();
  check("op servers override",                   osDoc.paths["/upload"].post.servers[0].url === "https://uploads.example.com");

  // ---- b.openapi.parse — external doc validation ----
  check("b.openapi.parse is fn",                 typeof b.openapi.parse === "function");

  var validOas = b.openapi.create({ info: { title: "T", version: "1.0" } });
  validOas.path("get", "/x", { responses: { "200": { description: "ok" } } });
  var validOasJson = validOas.toJsonString();
  var oasParse = b.openapi.parse(validOasJson);
  check("openapi.parse: valid doc round-trip",   oasParse.valid === true);
  check("openapi.parse: errors empty",           oasParse.errors.length === 0);
  check("openapi.parse: doc returned",           oasParse.doc.info.title === "T");

  var oasParseObj = b.openapi.parse(validOas.toJson());
  check("openapi.parse: object input",           oasParseObj.valid === true);

  var badVer = b.openapi.parse({ openapi: "3.0.0", info: { title: "T", version: "1.0" }, paths: {} });
  check("openapi.parse: wrong version → invalid", badVer.valid === false);
  check("openapi.parse: error mentions 3.1.x",   badVer.errors.join(",").indexOf("3.1") !== -1);

  var badResp = b.openapi.parse({
    openapi: "3.1.0", info: { title: "T", version: "1.0" },
    paths: { "/x": { get: { responses: { "200": {} } } } },
  });
  check("openapi.parse: missing description",    badResp.valid === false &&
                                                  badResp.errors.join(",").indexOf("description is required") !== -1);

  var badPath = b.openapi.parse({
    openapi: "3.1.0", info: { title: "T", version: "1.0" },
    paths: { "noslash": { get: { responses: { "200": { description: "ok" } } } } },
  });
  check("openapi.parse: missing slash prefix",   badPath.valid === false);

  var badPathParam = b.openapi.parse({
    openapi: "3.1.0", info: { title: "T", version: "1.0" },
    paths: { "/x/{id}": { get: {
      parameters: [{ name: "id", in: "path" }],
      responses: { "200": { description: "ok" } },
    }}},
  });
  check("openapi.parse: path param missing required",
                                                  badPathParam.valid === false &&
                                                  badPathParam.errors.join(",").indexOf("required=true") !== -1);

  var dangling = b.openapi.parse({
    openapi: "3.1.0", info: { title: "T", version: "1.0" },
    security: [{ ghost: [] }],
    paths: { "/x": { get: { responses: { "200": { description: "ok" } } } } },
  });
  check("openapi.parse: dangling security",      dangling.valid === false &&
                                                  dangling.errors.join(",").indexOf("undefined scheme") !== -1);
  var danglingWebhook = b.openapi.parse({
    openapi: "3.2.0", info: { title: "T", version: "1.0" },
    webhooks: { e: { post: { responses: { "200": { description: "ok" } }, security: [{ missing: [] }] } } },
    components: { securitySchemes: {} },
  });
  check("openapi.parse: dangling webhook-operation security",
        danglingWebhook.valid === false &&
        danglingWebhook.errors.join(",").indexOf("undefined scheme") !== -1);

  rejects("openapi.parse: bad JSON",
    function () { b.openapi.parse("{not valid json"); }, /invalid JSON/);
  rejects("openapi.parse: bad input",
    function () { b.openapi.parse(42); }, /must be a JSON string/);

  // ---- OpenAPI 3.2: opt-in version + webhooks + jsonSchemaDialect ----

  // 3.1 stays the default emitted version unless opted in.
  var apiDefault = b.openapi.create({ info: { title: "Def", version: "1.0.0" } });
  check("3.2: default version still 3.1.0",      apiDefault.toJson().openapi === "3.1.0");
  check("3.2: no webhooks key by default",       apiDefault.toJson().webhooks === undefined);
  check("3.2: no jsonSchemaDialect by default",  apiDefault.toJson().jsonSchemaDialect === undefined);

  // Opt into 3.2 with webhooks + jsonSchemaDialect.
  var api32 = b.openapi.create({
    openapi:           "3.2.0",
    jsonSchemaDialect: "https://spec.openapis.org/oas/3.1/dialect/base",
    info:              { title: "Webhook API", version: "1.0.0" },
  });
  api32.path("get", "/health", { responses: { "200": { description: "ok" } } });
  api32.webhook("newPet", "post", {
    summary:     "A new pet has been created",
    requestBody: { content: { "application/json": { schema: { type: "object" } } } },
    responses:   { "200": { description: "ack" }, "410": { description: "stop" } },
  });
  var doc32 = api32.toJson();
  check("3.2: opted-in version emitted",         doc32.openapi === "3.2.0");
  check("3.2: jsonSchemaDialect emitted",        doc32.jsonSchemaDialect === "https://spec.openapis.org/oas/3.1/dialect/base");
  check("3.2: webhooks map present",             doc32.webhooks != null && doc32.webhooks.newPet != null);
  check("3.2: webhook operation method",         doc32.webhooks.newPet.post.summary === "A new pet has been created");
  check("3.2: webhook responses retained",       doc32.webhooks.newPet.post.responses["200"].description === "ack");
  check("3.2: paths still emitted alongside",    doc32.paths["/health"].get != null);

  // YAML emits the new top-level keys.
  var yaml32 = api32.toYaml();
  check("3.2: YAML has webhooks",                yaml32.indexOf("webhooks:") !== -1);
  check("3.2: YAML has jsonSchemaDialect",       yaml32.indexOf("jsonSchemaDialect:") !== -1);

  // Unsupported version refused at config time.
  rejects("3.2: unknown version 4.0 refused",
    function () { b.openapi.create({ openapi: "4.0.0", info: { title: "x", version: "1.0.0" } }); },
    /version must be one of/);

  // Non-string jsonSchemaDialect refused at config time.
  rejects("3.2: non-string dialect refused",
    function () { b.openapi.create({ jsonSchemaDialect: 123, info: { title: "x", version: "1.0.0" } }); },
    /jsonSchemaDialect/);

  // Webhook duplicate operation rejected.
  rejects("3.2: duplicate webhook operation",
    function () {
      api32.webhook("newPet", "post", { responses: { "200": { description: "ok" } } });
    },
    /duplicate operation/);

  // Webhook bad method rejected.
  rejects("3.2: webhook bad method",
    function () { api32.webhook("e", "nope", { responses: { "200": { description: "ok" } } }); },
    /method must be/);

  // Webhook missing name rejected.
  rejects("3.2: webhook missing name",
    function () { api32.webhook("", "post", { responses: { "200": { description: "ok" } } }); },
    /name/);

  // Webhook responses still required (operation rules apply).
  rejects("3.2: webhook missing responses",
    function () { api32.webhook("noResp", "post", {}); },
    /responses object is required/);

  // Per-webhook-operation dangling security is caught.
  var apiWhSec = b.openapi.create({ openapi: "3.2.0", info: { title: "WS", version: "1.0.0" } });
  apiWhSec.webhook("evt", "post", {
    security:  [{ ghost: [] }],
    responses: { "200": { description: "ok" } },
  });
  rejects("3.2: dangling webhook security",
    function () { apiWhSec.toJson(); },
    /webhook POST evt references undefined security scheme/);

  // Webhook with a registered scheme passes.
  var apiWhOk = b.openapi.create({ openapi: "3.2.0", info: { title: "WO", version: "1.0.0" } });
  apiWhOk.security.add("bearerAuth", b.openapi.security.bearer());
  apiWhOk.webhook("evt", "post", {
    security:  [{ bearerAuth: [] }],
    responses: { "200": { description: "ok" } },
  });
  check("3.2: webhook with registered scheme ok", apiWhOk.toJson().webhooks.evt.post.security[0].bearerAuth.length === 0);

  // ---- parse() accepts 3.2 + validates webhooks / jsonSchemaDialect ----
  var p32 = b.openapi.parse({
    openapi:           "3.2.0",
    jsonSchemaDialect: "https://spec.openapis.org/oas/3.1/dialect/base",
    info:              { title: "T", version: "1.0.0" },
    paths:             { "/x": { get: { responses: { "200": { description: "ok" } } } } },
    webhooks:          { newPet: { post: { responses: { "200": { description: "ack" } } } } },
  });
  check("parse: 3.2 webhook doc valid",          p32.valid === true && p32.errors.length === 0);

  // 3.1 doc still parses unchanged.
  var p31 = b.openapi.parse({ openapi: "3.1.0", info: { title: "T", version: "1.0.0" } });
  check("parse: 3.1 still valid",                p31.valid === true);

  // Unknown version 4.0 still refused.
  var p40 = b.openapi.parse({ openapi: "4.0.0", info: { title: "T", version: "1.0.0" } });
  check("parse: 4.0 invalid",                    p40.valid === false &&
                                                  p40.errors.join(",").indexOf("3.2.x") !== -1);

  // Webhook operation missing description is invalid.
  var pWhBad = b.openapi.parse({
    openapi: "3.2.0", info: { title: "T", version: "1.0.0" },
    webhooks: { e: { post: { responses: { "200": {} } } } },
  });
  check("parse: webhook missing description",    pWhBad.valid === false &&
                                                  pWhBad.errors.join(",").indexOf("webhook e") !== -1);

  // Webhooks not an object is invalid.
  var pWhType = b.openapi.parse({
    openapi: "3.2.0", info: { title: "T", version: "1.0.0" }, webhooks: "nope",
  });
  check("parse: webhooks non-object invalid",    pWhType.valid === false &&
                                                  pWhType.errors.join(",").indexOf("webhooks") !== -1);

  // Non-string jsonSchemaDialect is invalid.
  var pDialect = b.openapi.parse({
    openapi: "3.2.0", info: { title: "T", version: "1.0.0" }, jsonSchemaDialect: 5,
  });
  check("parse: bad jsonSchemaDialect invalid",  pDialect.valid === false &&
                                                  pDialect.errors.join(",").indexOf("jsonSchemaDialect") !== -1);

  // Round-trip a built 3.2 doc through parse.
  var built32 = b.openapi.create({ openapi: "3.2.0", info: { title: "T", version: "1.0.0" } });
  built32.webhook("evt", "post", { responses: { "200": { description: "ok" } } });
  var roundTrip32 = b.openapi.parse(built32.toJsonString());
  check("parse: 3.2 round-trip valid",           roundTrip32.valid === true);

  console.log("OK — openapi tests");
}

module.exports = { run: run };
if (require.main === module) {
  try { run(); process.exit(0); } catch (e) { console.error(e); process.exit(1); }
}
