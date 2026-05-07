"use strict";
/**
 * b.asyncapi — AsyncAPI 3.0 schema-document builder.
 */

var b = require("../..");
var check = require("../helpers/check").check;

function rejects(label, fn, pattern) {
  var threw = false; var msg = "";
  try { fn(); } catch (e) { threw = true; msg = e.message; }
  check("threw on " + label, threw && (pattern.test ? pattern.test(msg) : msg.indexOf(pattern) !== -1));
}

function run() {
  // ---- shape ----
  check("b.asyncapi is object",                  typeof b.asyncapi === "object");
  check("b.asyncapi.create is fn",               typeof b.asyncapi.create === "function");
  check("b.asyncapi.bindings is object",         typeof b.asyncapi.bindings === "object");
  check("b.asyncapi.VERSION === 3.0.0",          b.asyncapi.VERSION === "3.0.0");
  check("b.asyncapi.security",                   typeof b.asyncapi.security === "object");
  check("b.asyncapi.toYaml is fn",               typeof b.asyncapi.toYaml === "function");

  // ---- create requires info ----
  rejects("create: missing info",
    function () { b.asyncapi.create({}); }, /info/);
  rejects("create: missing info.title",
    function () { b.asyncapi.create({ info: { version: "1.0" } }); }, /title/);
  rejects("create: missing info.version",
    function () { b.asyncapi.create({ info: { title: "T" } }); }, /version/);

  // ---- minimal valid doc ----
  var aapi = b.asyncapi.create({ info: { title: "Events", version: "1.0.0" } });
  check("create returns builder",                typeof aapi.channel === "function");
  check("info accessible",                       aapi.info.title === "Events");
  check("asyncapi version",                      aapi.asyncapi === "3.0.0");

  var doc1 = aapi.toJson();
  check("doc.asyncapi version",                  doc1.asyncapi === "3.0.0");
  check("doc.info.title",                        doc1.info.title === "Events");
  check("doc.defaultContentType",                doc1.defaultContentType === "application/json");
  check("doc.channels empty obj",                typeof doc1.channels === "object" && Object.keys(doc1.channels).length === 0);
  check("doc.operations empty obj",              typeof doc1.operations === "object" && Object.keys(doc1.operations).length === 0);

  // ---- channel + operation ----
  aapi.channel("orders.created", {
    address: "orders.created",
    summary: "Order created",
    messages: {
      OrderCreated: {
        contentType: "application/json",
        payload: { type: "object", properties: { id: { type: "string" } }, required: ["id"] },
      },
    },
  });
  aapi.operation("publishOrderCreated", {
    action: "send",
    channel: "orders.created",
    summary: "Publish an order-created event",
  });

  var doc2 = aapi.toJson();
  check("channel registered",                    doc2.channels["orders.created"] != null);
  check("channel address",                       doc2.channels["orders.created"].address === "orders.created");
  check("channel message present",               doc2.channels["orders.created"].messages.OrderCreated.contentType === "application/json");
  check("operation registered",                  doc2.operations.publishOrderCreated.action === "send");
  check("operation channel ref",                 doc2.operations.publishOrderCreated.channel["$ref"] === "#/channels/orders.created");

  // ---- duplicate guards ----
  rejects("channel: duplicate id",
    function () { aapi.channel("orders.created", { address: "x" }); }, /already registered/);
  rejects("operation: duplicate id",
    function () { aapi.operation("publishOrderCreated", { action: "send", channel: "orders.created" }); }, /already registered/);

  // ---- bad action ----
  rejects("operation: bad action",
    function () { aapi.operation("badop", { action: "publish", channel: "orders.created" }); }, /must be 'send' or 'receive'/);

  // ---- dangling channel reference ----
  rejects("operation: dangling channel",
    function () { aapi.operation("ghostop", { action: "send", channel: "no-such-channel" }); }, /not registered/);

  // ---- receive operation ----
  aapi.channel("orders.cancelled", {
    address: "orders.cancelled",
    messages: {
      OrderCancelled: {
        contentType: "application/json",
        payload: { type: "object", properties: { id: { type: "string" } } },
      },
    },
  });
  aapi.operation("onOrderCancelled", {
    action: "receive",
    channel: "orders.cancelled",
    summary: "React to order cancellations",
  });
  var doc3 = aapi.toJson();
  check("receive operation",                     doc3.operations.onOrderCancelled.action === "receive");

  // ---- reusable schema component ----
  aapi.schema("Order", {
    type: "object",
    properties: {
      id:    { type: "string", format: "uuid" },
      total: { type: "number", minimum: 0 },
    },
    required: ["id", "total"],
  });
  var doc4 = aapi.toJson();
  check("components.schemas.Order",              doc4.components.schemas.Order.type === "object");

  rejects("schema: duplicate",
    function () { aapi.schema("Order", { type: "object" }); }, /already registered/);
  rejects("schema: missing name",
    function () { aapi.schema("", { type: "object" }); }, /name/);

  // ---- reusable message component ----
  aapi.message("OrderEnvelope", {
    contentType: "application/json",
    payload: { type: "object", properties: { kind: { type: "string" } } },
  });
  var doc5 = aapi.toJson();
  check("components.messages.OrderEnvelope",     doc5.components.messages.OrderEnvelope.contentType === "application/json");

  // ---- correlationId component ----
  aapi.correlationId("OrderId", { location: "$message.payload#/id", description: "order id" });
  var doc6 = aapi.toJson();
  check("components.correlationIds",             doc6.components.correlationIds.OrderId.location === "$message.payload#/id");

  rejects("correlationId: bad spec",
    function () { aapi.correlationId("X", {}); }, /location/);

  // ---- security ----
  aapi.security.add("bearerJwt", b.asyncapi.security.bearer({ jwtBearer: true }));
  aapi.security.require({ bearerJwt: [] });
  var doc7 = aapi.toJson();
  check("security scheme",                       doc7.components.securitySchemes.bearerJwt.type === "http");
  check("doc-level security",                    Array.isArray(doc7.security) && doc7.security[0].bearerJwt.length === 0);

  // ---- dangling security caught ----
  var aapiBad = b.asyncapi.create({ info: { title: "Bad", version: "1.0" } });
  aapiBad.security.require({ undefinedScheme: [] });
  rejects("toJson: dangling doc-level security",
    function () { aapiBad.toJson(); }, /undefined scheme/);

  var aapiBad2 = b.asyncapi.create({ info: { title: "Bad2", version: "1.0" } });
  aapiBad2.channel("c", { address: "c" });
  aapiBad2.operation("op", { action: "send", channel: "c", security: [{ ghost: [] }] });
  rejects("toJson: dangling op-level security",
    function () { aapiBad2.toJson(); }, /undefined security/);

  // ---- tags ----
  aapi.tag({ name: "orders", description: "Order lifecycle" });
  var doc8 = aapi.toJson();
  check("tags registered",                       Array.isArray(doc8.tags) && doc8.tags[0].name === "orders");

  rejects("tag: missing name",
    function () { aapi.tag({}); }, /name is required/);

  // ---- servers ----
  var aapiS = b.asyncapi.create({
    info: { title: "S", version: "1.0" },
    servers: {
      production: { host: "broker.acme.example.com:9092", protocol: "kafka", description: "prod" },
    },
  });
  aapiS.channel("c", { address: "c" });
  aapiS.server("staging", { host: "staging-broker.acme.example.com:9092", protocol: "kafka" });
  var docS = aapiS.toJson();
  check("servers: 2 entries",                    Object.keys(docS.servers).length === 2);
  check("server protocol",                        docS.servers.production.protocol === "kafka");

  rejects("server: bad spec (missing host)",
    function () { aapiS.server("bad", { protocol: "kafka" }); }, /host/);
  rejects("server: bad spec (missing protocol)",
    function () { aapiS.server("bad2", { host: "x" }); }, /protocol/);
  rejects("create: servers must be map",
    function () { b.asyncapi.create({ info: { title: "x", version: "1" }, servers: [] }); }, /must be a map/);

  // ---- bindings: websockets ----
  var ws = b.asyncapi.bindings.websockets({ method: "GET" });
  check("bindings.websockets",                   ws.method === "GET" && typeof ws.bindingVersion === "string");
  rejects("bindings.websockets: bad method",
    function () { b.asyncapi.bindings.websockets({ method: "DELETE" }); }, /must be GET or POST/);

  // ---- bindings: kafka ----
  var kf = b.asyncapi.bindings.kafka({
    topic: "events.foo", partitions: 12, replicas: 3,
    schemaRegistryUrl: "http://reg:8081",
  });
  check("bindings.kafka topic",                  kf.topic === "events.foo");
  check("bindings.kafka partitions",             kf.partitions === 12);
  check("bindings.kafka schemaRegistry",         kf.schemaRegistryUrl === "http://reg:8081");
  rejects("bindings.kafka: bad partitions",
    function () { b.asyncapi.bindings.kafka({ partitions: -1 }); }, /positive number/);
  rejects("bindings.kafka: bad replicas",
    function () { b.asyncapi.bindings.kafka({ replicas: 0 }); }, /positive number/);

  // ---- bindings: amqp ----
  var aq = b.asyncapi.bindings.amqp({
    is: "queue", queue: { name: "orders" }, deliveryMode: 2, ack: true,
    bcc: ["audit"],
  });
  check("bindings.amqp is",                      aq.is === "queue");
  check("bindings.amqp ack",                     aq.ack === true);
  check("bindings.amqp bcc",                     Array.isArray(aq.bcc) && aq.bcc[0] === "audit");
  rejects("bindings.amqp: bad is",
    function () { b.asyncapi.bindings.amqp({ is: "topic" }); }, /must be/);

  // ---- bindings: mqtt ----
  var mq = b.asyncapi.bindings.mqtt({ qos: 1, retain: true, topic: "sensors/temp" });
  check("bindings.mqtt qos",                     mq.qos === 1);
  check("bindings.mqtt retain",                  mq.retain === true);
  rejects("bindings.mqtt: bad qos",
    function () { b.asyncapi.bindings.mqtt({ qos: 5 }); }, /must be 0, 1, or 2/);
  rejects("bindings.mqtt: float qos",
    function () { b.asyncapi.bindings.mqtt({ qos: 1.5 }); }, /must be 0, 1, or 2/);

  // ---- bindings: http ----
  var ht = b.asyncapi.bindings.http({ type: "request", method: "POST" });
  check("bindings.http",                         ht.type === "request" && ht.method === "POST");
  rejects("bindings.http: bad type",
    function () { b.asyncapi.bindings.http({ type: "ping" }); }, /must be 'request' or 'response'/);

  // ---- channel + operation with bindings ----
  aapi.channel("kafka.events", {
    address: "events",
    bindings: { kafka: b.asyncapi.bindings.kafka({ topic: "events", partitions: 4 }) },
  });
  aapi.operation("publishKafka", {
    action: "send",
    channel: "kafka.events",
    bindings: { kafka: { groupId: "blamejs-app" } },
  });
  var docK = aapi.toJson();
  check("channel bindings",                      docK.channels["kafka.events"].bindings.kafka.topic === "events");
  check("operation bindings",                    docK.operations.publishKafka.bindings.kafka.groupId === "blamejs-app");

  // ---- channel parameters ----
  aapi.channel("user.events", {
    address: "user/{userId}/events",
    parameters: { userId: { description: "User ID" } },
  });
  var docCp = aapi.toJson();
  check("channel parameters",                    docCp.channels["user.events"].parameters.userId.description === "User ID");

  // ---- operation references inline messages ----
  aapi.operation("publishOrderEnv", {
    action: "send",
    channel: "orders.created",
    messages: ["OrderCreated"],
  });
  var docM = aapi.toJson();
  check("operation messages [name]",             docM.operations.publishOrderEnv.messages[0]["$ref"] ===
                                                  "#/channels/orders.created/messages/OrderCreated");

  rejects("operation: bad message entry",
    function () {
      aapi.operation("badmsg", {
        action: "send",
        channel: "orders.created",
        messages: [42],
      });
    },
    /must be a message name string or an object with \$ref/);

  // ---- toJsonString round-trip ----
  var jsonStr = aapi.toJsonString();
  check("toJsonString returns string",           typeof jsonStr === "string");
  var parsed = JSON.parse(jsonStr);
  check("toJsonString round-trips",              parsed.asyncapi === "3.0.0");

  // ---- toYaml ----
  var yamlOut = aapi.toYaml();
  check("toYaml returns string",                 typeof yamlOut === "string");
  check("toYaml: contains asyncapi key",         yamlOut.indexOf("asyncapi:") !== -1);
  check("toYaml: contains channels",             yamlOut.indexOf("channels:") !== -1);

  // ---- comprehensive realistic doc ----
  var realApi = b.asyncapi.create({
    info: {
      title:   "Acme E-Commerce Events",
      version: "2.1.0",
      description: "Internal kafka topology",
      contact: { name: "Events team", email: "events@acme.example.com" },
      license: { name: "Apache-2.0" },
    },
    servers: {
      production: { host: "kafka.acme.example.com:9092", protocol: "kafka",
                    description: "Production Kafka cluster" },
      staging:    { host: "staging-kafka.acme.example.com:9092", protocol: "kafka" },
    },
    defaultContentType: "application/json",
  });

  realApi.security.add("saslPlain", { type: "scramSha256" });
  realApi.security.require({ saslPlain: [] });

  realApi.tag({ name: "orders" });
  realApi.tag({ name: "inventory" });

  realApi.schema("Order", {
    type: "object",
    properties: {
      id:    { type: "string", format: "uuid" },
      total: { type: "number" },
      lineItems: { type: "array", items: { type: "object" } },
    },
    required: ["id", "total"],
  });

  realApi.message("OrderCreatedV1", {
    title: "OrderCreatedV1",
    contentType: "application/json",
    payload: { type: "object", properties: { id: { type: "string" } } },
  });

  realApi.channel("orders.created.v1", {
    address: "orders.created.v1",
    bindings: { kafka: b.asyncapi.bindings.kafka({ topic: "orders.created.v1", partitions: 8, replicas: 3 }) },
    messages: {
      OrderCreatedV1: {
        contentType: "application/json",
        payload: { "$ref": "#/components/schemas/Order" },
      },
    },
  });

  realApi.channel("inventory.depleted.v1", {
    address: "inventory.depleted.v1",
    bindings: { kafka: b.asyncapi.bindings.kafka({ topic: "inventory.depleted.v1", partitions: 4 }) },
    messages: {
      InventoryDepleted: {
        contentType: "application/json",
        payload: { type: "object", properties: { sku: { type: "string" } } },
      },
    },
  });

  realApi.operation("publishOrderCreated", {
    action: "send",
    channel: "orders.created.v1",
    tags: ["orders"],
    summary: "Emit order-created event after persistence commit",
  });

  realApi.operation("onInventoryDepleted", {
    action: "receive",
    channel: "inventory.depleted.v1",
    tags: ["inventory"],
    summary: "Trigger restock workflow when inventory is depleted",
  });

  var realDoc = realApi.toJson();
  check("realDoc.info.title",                    realDoc.info.title === "Acme E-Commerce Events");
  check("realDoc: 2 servers",                    Object.keys(realDoc.servers).length === 2);
  check("realDoc: 2 channels",                   Object.keys(realDoc.channels).length === 2);
  check("realDoc: 2 operations",                 Object.keys(realDoc.operations).length === 2);
  check("realDoc: kafka binding partitions",     realDoc.channels["orders.created.v1"].bindings.kafka.partitions === 8);
  check("realDoc: tag count",                    realDoc.tags.length === 2);

  var realYaml = realApi.toYaml();
  check("realYaml: substantial",                 realYaml.length > 500);
  check("realYaml: contains kafka",              realYaml.indexOf("kafka") !== -1);

  // ---- parameter component ----
  aapi.parameter("UserIdParam", { description: "User ID", schema: { type: "string" } });
  var docPa = aapi.toJson();
  check("components.parameters.UserIdParam",     docPa.components.parameters.UserIdParam.description === "User ID");

  // ---- empty doc shape ----
  var aapiEmpty = b.asyncapi.create({ info: { title: "E", version: "1.0" } });
  var emptyDoc = aapiEmpty.toJson();
  check("empty doc: no components",              emptyDoc.components === undefined);
  check("empty doc: no servers",                 emptyDoc.servers === undefined);
  check("empty doc: empty channels obj",         Object.keys(emptyDoc.channels).length === 0);

  // ---- bad message body ----
  rejects("channel: bad message body",
    function () {
      aapi.channel("badmsg-channel", {
        address: "x",
        messages: { Bad: 42 },
      });
    },
    /message must be an object/);

  // ---- security scheme catalog reuse from openapi ----
  check("security.bearer",                       b.asyncapi.security.bearer().type === "http");
  check("security.apiKey",                       b.asyncapi.security.apiKey({ name: "X-API-Key", in: "header" }).type === "apiKey");

  // ---- doc id ----
  var aapiId = b.asyncapi.create({
    info: { title: "I", version: "1.0" },
    id:   "urn:com:acme:events",
  });
  aapiId.channel("c", { address: "c" });
  var docId = aapiId.toJson();
  check("doc.id",                                docId.id === "urn:com:acme:events");

  // ---- channel-level servers list ----
  aapi.channel("scoped.channel", {
    address: "scoped",
    servers: ["#/servers/production"],
  });
  var docSc = aapi.toJson();
  check("channel servers[]",                     docSc.channels["scoped.channel"].servers[0] === "#/servers/production");

  // ---- operation reply ----
  aapi.channel("rpc.responses", { address: "rpc.responses" });
  aapi.operation("rpcCall", {
    action: "send",
    channel: "orders.created",
    reply: { channel: { "$ref": "#/channels/rpc.responses" } },
  });
  var docR = aapi.toJson();
  check("operation reply",                       docR.operations.rpcCall.reply.channel["$ref"] === "#/channels/rpc.responses");

  // ---- middleware.asyncapiServe ----
  check("middleware.asyncapiServe is fn",        typeof b.middleware.asyncapiServe === "function");

  rejects("asyncapiServe: missing document",
    function () { b.middleware.asyncapiServe({}); }, /document must be/);
  rejects("asyncapiServe: bad pathJson",
    function () { b.middleware.asyncapiServe({ document: realApi, pathJson: "no-slash" }); },
    /must start with/);

  var serve = b.middleware.asyncapiServe({
    document: realApi,
    pathJson: "/asyncapi.json",
    pathYaml: "/asyncapi.yaml",
    pretty:   true,
    audit:    false,
  });
  check("asyncapiServe: factory returns fn",     typeof serve === "function");

  // GET JSON
  var sentJson = { status: null, headers: null, body: null };
  var resJson = {
    writeHead: function (s, h) { sentJson.status = s; sentJson.headers = h; },
    end:       function (b) { sentJson.body = b; },
  };
  serve({ method: "GET", url: "/asyncapi.json", pathname: "/asyncapi.json", headers: {} },
        resJson, function () {});
  check("asyncapiServe JSON: 200",               sentJson.status === 200);
  check("asyncapiServe JSON: ETag",              typeof sentJson.headers["ETag"] === "string");
  check("asyncapiServe JSON: CORS",              sentJson.headers["Access-Control-Allow-Origin"] === "*");
  var parsedServed = JSON.parse(sentJson.body);
  check("asyncapiServe JSON: body is asyncapi",  parsedServed.asyncapi === "3.0.0");

  // GET YAML
  var sentYaml = { status: null, headers: null, body: null };
  var resYaml = {
    writeHead: function (s, h) { sentYaml.status = s; sentYaml.headers = h; },
    end:       function (b) { sentYaml.body = b; },
  };
  serve({ method: "GET", url: "/asyncapi.yaml", pathname: "/asyncapi.yaml", headers: {} },
        resYaml, function () {});
  check("asyncapiServe YAML: 200",               sentYaml.status === 200);
  check("asyncapiServe YAML: Content-Type",      sentYaml.headers["Content-Type"].indexOf("application/yaml") === 0);

  // 304 on If-None-Match
  var etag = sentJson.headers["ETag"];
  var sent304 = { status: null, headers: null };
  var res304 = {
    writeHead: function (s, h) { sent304.status = s; sent304.headers = h; },
    end:       function () {},
  };
  serve({ method: "GET", url: "/asyncapi.json", pathname: "/asyncapi.json",
          headers: { "if-none-match": etag } }, res304, function () {});
  check("asyncapiServe: 304 on matching ETag",   sent304.status === 304);

  // POST falls through
  var nextPost = 0;
  serve({ method: "POST", url: "/asyncapi.json", pathname: "/asyncapi.json", headers: {} },
        { writeHead: function () {}, end: function () {} },
        function () { nextPost += 1; });
  check("asyncapiServe: POST falls through",     nextPost === 1);

  // Unknown path falls through
  var nextOther = 0;
  serve({ method: "GET", url: "/foo", pathname: "/foo", headers: {} },
        { writeHead: function () {}, end: function () {} },
        function () { nextOther += 1; });
  check("asyncapiServe: unknown path falls through", nextOther === 1);

  // accessControl=same-origin omits CORS
  var serveSO = b.middleware.asyncapiServe({
    document: realApi, accessControl: "same-origin", audit: false,
  });
  var sentSO = { status: null, headers: null, body: null };
  serveSO({ method: "GET", url: "/asyncapi.json", pathname: "/asyncapi.json", headers: {} },
          { writeHead: function (s, h) { sentSO.headers = h; }, end: function () {} },
          function () {});
  check("asyncapiServe: same-origin omits CORS", sentSO.headers["Access-Control-Allow-Origin"] == null);

  check("asyncapiServe.forceRebuild is fn",      typeof serve.forceRebuild === "function");

  // ---- operation messages with $ref form ----
  aapi.operation("publishWithRef", {
    action: "send",
    channel: "orders.created",
    messages: [
      { "$ref": "#/components/messages/OrderEnvelope" },
    ],
  });
  var docMR = aapi.toJson();
  check("operation messages [$ref]",             docMR.operations.publishWithRef.messages[0]["$ref"] ===
                                                  "#/components/messages/OrderEnvelope");

  // ---- amqp deliveryMode + replyTo ----
  var aq2 = b.asyncapi.bindings.amqp({
    is: "routingKey", exchange: { name: "events", type: "topic" },
    deliveryMode: 2, replyTo: "responses", timestamp: true,
  });
  check("amqp: deliveryMode",                    aq2.deliveryMode === 2);
  check("amqp: replyTo",                         aq2.replyTo === "responses");
  check("amqp: timestamp",                       aq2.timestamp === true);

  // ---- mqtt messageExpiryInterval ----
  var mq2 = b.asyncapi.bindings.mqtt({ qos: 0, messageExpiryInterval: 600 });
  check("mqtt: messageExpiryInterval",           mq2.messageExpiryInterval === 600);

  // ---- kafka full surface ----
  var kf2 = b.asyncapi.bindings.kafka({
    topic: "events", partitions: 16, replicas: 3,
    topicConfiguration: { "cleanup.policy": ["compact"] },
    groupId: { type: "string", enum: ["group-A", "group-B"] },
    clientId: "blamejs-app",
    schemaRegistryUrl: "http://reg:8081",
    schemaRegistryVendor: "confluent",
    schemaIdLocation: "header",
    schemaIdPayloadEncoding: "confluent",
    schemaLookupStrategy: "TopicNameStrategy",
    key: { type: "string" },
  });
  check("kafka: topicConfiguration",             Array.isArray(kf2.topicConfiguration["cleanup.policy"]));
  check("kafka: groupId",                        kf2.groupId.type === "string");
  check("kafka: schemaRegistryVendor",           kf2.schemaRegistryVendor === "confluent");

  // ---- websockets full surface ----
  var ws2 = b.asyncapi.bindings.websockets({
    method: "POST",
    query: { type: "object", properties: { token: { type: "string" } } },
    headers: { type: "object", properties: { "x-trace-id": { type: "string" } } },
    bindingVersion: "0.1.0",
  });
  check("ws: query",                             ws2.query.type === "object");
  check("ws: headers",                           ws2.headers.type === "object");

  // ---- http binding full surface ----
  var ht2 = b.asyncapi.bindings.http({
    type: "request", method: "GET", statusCode: 200,
    query:   { type: "object", properties: { q: { type: "string" } } },
    headers: { type: "object", properties: { authorization: { type: "string" } } },
  });
  check("http: statusCode",                      ht2.statusCode === 200);

  // ---- traits ----
  check("b.asyncapi.traits is object",           typeof b.asyncapi.traits === "object");
  check("b.asyncapi.traits.operation is fn",     typeof b.asyncapi.traits.operation === "function");
  check("b.asyncapi.traits.message is fn",       typeof b.asyncapi.traits.message === "function");
  check("b.asyncapi.traits.applyOperation",      typeof b.asyncapi.traits.applyOperation === "function");
  check("b.asyncapi.traits.applyMessage",        typeof b.asyncapi.traits.applyMessage === "function");

  var opTrait = b.asyncapi.traits.operation({
    bindings: { kafka: { groupId: "consumers-prod" } },
    tags: [{ name: "kafka" }],
  });
  check("traits.operation: bindings kept",       opTrait.bindings.kafka.groupId === "consumers-prod");
  check("traits.operation: frozen",              Object.isFrozen(opTrait));

  rejects("traits.operation: bad shape",
    function () { b.asyncapi.traits.operation(null); }, /must be an object/);

  // applyOperation merges
  var merged = b.asyncapi.traits.applyOperation(
    { action: "send", channel: "events", summary: "child" },
    [opTrait, { tags: [{ name: "events" }] }],
  );
  check("applyOperation: action retained",       merged.action === "send");
  check("applyOperation: tags concatenated",     Array.isArray(merged.tags) && merged.tags.length === 2);
  check("applyOperation: bindings inherited",    merged.bindings.kafka.groupId === "consumers-prod");
  check("applyOperation: parent summary wins",   merged.summary === "child");

  // applyMessage shallow merge
  var msgTrait = b.asyncapi.traits.message({
    contentType: "application/json",
    headers: { type: "object", properties: { traceparent: { type: "string" } } },
  });
  var mmerged = b.asyncapi.traits.applyMessage(
    { name: "OrderEvent", payload: { type: "object" } },
    [msgTrait],
  );
  check("applyMessage: name retained",           mmerged.name === "OrderEvent");
  check("applyMessage: contentType from trait",  mmerged.contentType === "application/json");
  check("applyMessage: payload retained",        mmerged.payload.type === "object");

  // applyOperation with no traits
  var noTrait = b.asyncapi.traits.applyOperation({ action: "send", channel: "x" }, null);
  check("applyOperation: no traits is ident",    noTrait.action === "send");

  rejects("applyOperation: bad parent",
    function () { b.asyncapi.traits.applyOperation(null, [opTrait]); }, /parent must be an object/);
  rejects("applyOperation: traits not array",
    function () { b.asyncapi.traits.applyOperation({ action: "send", channel: "x" }, "trait"); },
    /must be an array/);

  // overlapping bindings: shallow merge (top-level keys merge; inner objects replace)
  var t1 = b.asyncapi.traits.operation({ bindings: { kafka: { a: 1 }, mqtt: { x: 1 } } });
  var t2 = b.asyncapi.traits.operation({ bindings: { kafka: { b: 99 } } });
  var mtt = b.asyncapi.traits.applyOperation(
    { action: "send", channel: "x" },
    [t1, t2],
  );
  check("traits: bindings.mqtt retained from t1", mtt.bindings.mqtt.x === 1);
  check("traits: bindings.kafka replaced by t2",  mtt.bindings.kafka.b === 99);
  check("traits: bindings.kafka.a not retained",  mtt.bindings.kafka.a === undefined);

  // Empty traits in array (skipped)
  var withEmpty = b.asyncapi.traits.applyOperation(
    { action: "send", channel: "x" },
    [null, undefined, opTrait, "string"],
  );
  check("traits: skip null/undefined/non-obj",   withEmpty.action === "send" &&
                                                  withEmpty.bindings.kafka.groupId === "consumers-prod");

  // ---- doc with externalDocs ----
  var aapiED = b.asyncapi.create({
    info: { title: "ED", version: "1.0" },
    externalDocs: { url: "https://docs.example.com", description: "External docs" },
  });
  aapiED.channel("c", { address: "c" });
  var docED = aapiED.toJson();
  check("doc.externalDocs",                      docED.externalDocs.url === "https://docs.example.com");

  // ---- forceRebuild same content same etag ----
  var realServeMw = b.middleware.asyncapiServe({
    document: realApi, audit: false,
  });
  var sentR1 = { headers: null, body: null };
  realServeMw({ method: "GET", url: "/asyncapi.json", pathname: "/asyncapi.json", headers: {} },
              { writeHead: function (s, h) { sentR1.headers = h; }, end: function (bd) { sentR1.body = bd; } },
              function () {});
  realServeMw.forceRebuild();
  var sentR2 = { headers: null, body: null };
  realServeMw({ method: "GET", url: "/asyncapi.json", pathname: "/asyncapi.json", headers: {} },
              { writeHead: function (s, h) { sentR2.headers = h; }, end: function (bd) { sentR2.body = bd; } },
              function () {});
  check("asyncapiServe: same content same etag", sentR1.headers["ETag"] === sentR2.headers["ETag"]);

  // ---- channel-only doc valid ----
  var aapiNoOp = b.asyncapi.create({ info: { title: "NoOp", version: "1.0" } });
  aapiNoOp.channel("orphan", { address: "orphan" });
  var docNoOp = aapiNoOp.toJson();
  check("doc: channel-only valid",               Object.keys(docNoOp.channels).length === 1 &&
                                                  Object.keys(docNoOp.operations).length === 0);

  // ---- multiple operations on same channel ----
  var aapiMulti = b.asyncapi.create({ info: { title: "MO", version: "1.0" } });
  aapiMulti.channel("shared", { address: "shared",
    messages: { Msg: { contentType: "application/json", payload: { type: "object" } } } });
  aapiMulti.operation("publish", { action: "send", channel: "shared" });
  aapiMulti.operation("subscribe", { action: "receive", channel: "shared" });
  var docMO = aapiMulti.toJson();
  check("multi-ops same channel: send",          docMO.operations.publish.action === "send");
  check("multi-ops same channel: receive",       docMO.operations.subscribe.action === "receive");

  // ---- info contact / license retention ----
  var aapiInfo = b.asyncapi.create({
    info: {
      title: "I", version: "1.0",
      description: "Internal API",
      termsOfService: "https://acme.example.com/terms",
      contact: { name: "Team", email: "team@acme.example.com", url: "https://acme.example.com" },
      license: { name: "MIT", url: "https://opensource.org/licenses/MIT" },
    },
  });
  aapiInfo.channel("c", { address: "c" });
  var docInfo = aapiInfo.toJson();
  check("info.description",                      docInfo.info.description === "Internal API");
  check("info.contact.email",                    docInfo.info.contact.email === "team@acme.example.com");
  check("info.license.name",                     docInfo.info.license.name === "MIT");
  check("info.termsOfService",                   docInfo.info.termsOfService === "https://acme.example.com/terms");

  // ---- trait keys catalog ----
  check("OPERATION_TRAIT_KEYS catalog",          b.asyncapi.traits.OPERATION_TRAIT_KEYS.indexOf("bindings") !== -1);
  check("MESSAGE_TRAIT_KEYS catalog",            b.asyncapi.traits.MESSAGE_TRAIT_KEYS.indexOf("payload") === -1);     // payload not in trait keys
  check("MESSAGE_TRAIT_KEYS catalog has headers", b.asyncapi.traits.MESSAGE_TRAIT_KEYS.indexOf("headers") !== -1);

  // ---- bindings: kafka with topic but no partitions defaults ----
  var kfMin = b.asyncapi.bindings.kafka({});
  check("kafka: no opts ok",                     typeof kfMin.bindingVersion === "string");
  check("kafka: no topic when omitted",          kfMin.topic === undefined);

  // ---- bindings versioning override ----
  var wsVer = b.asyncapi.bindings.websockets({ method: "GET", bindingVersion: "0.2.0" });
  check("ws: bindingVersion override",           wsVer.bindingVersion === "0.2.0");

  // ---- doc ID retained ----
  var aapiId2 = b.asyncapi.create({
    info: { title: "X", version: "1.0" },
    id:   "urn:com:acme:async:v1",
  });
  aapiId2.channel("c", { address: "c" });
  var docId2 = aapiId2.toJson();
  check("doc.id present",                        docId2.id === "urn:com:acme:async:v1");

  // ---- operation tags ----
  aapi.operation("taggedOp", {
    action: "send", channel: "orders.created",
    tags: ["events", "publishing"],
  });
  var docTo = aapi.toJson();
  check("operation tags",                        docTo.operations.taggedOp.tags.length === 2);

  // ---- operation summary + description ----
  aapi.operation("descOp", {
    action: "send", channel: "orders.created",
    summary: "Short", description: "Long form",
  });
  var docDe = aapi.toJson();
  check("operation summary",                     docDe.operations.descOp.summary === "Short");
  check("operation description",                 docDe.operations.descOp.description === "Long form");

  // ---- channel external docs ----
  aapi.channel("ext.doc.channel", {
    address: "ext.doc.channel",
    externalDocs: { url: "https://example.com/event-spec" },
  });
  var docX = aapi.toJson();
  check("channel externalDocs",                  docX.channels["ext.doc.channel"].externalDocs.url === "https://example.com/event-spec");

  // ---- security via openIdConnect ----
  aapi.security.add("oidcMQ", b.asyncapi.security.openIdConnect({ url: "https://idp/.wkc" }));
  var docOIDC = aapi.toJson();
  check("security: oidc",                        docOIDC.components.securitySchemes.oidcMQ.type === "openIdConnect");

  // ---- channel summary, title, description ----
  aapi.channel("ttsd", {
    address: "ttsd",
    title: "T", summary: "S", description: "D",
  });
  var docTTSD = aapi.toJson();
  check("channel title",                         docTTSD.channels.ttsd.title === "T");
  check("channel summary",                       docTTSD.channels.ttsd.summary === "S");
  check("channel description",                   docTTSD.channels.ttsd.description === "D");

  // ---- operation externalDocs ----
  aapi.operation("opExt", {
    action: "send", channel: "orders.created",
    externalDocs: { url: "https://example.com/op-spec", description: "Op spec" },
  });
  var docOX = aapi.toJson();
  check("operation externalDocs",                docOX.operations.opExt.externalDocs.url === "https://example.com/op-spec");

  // ---- bindings versioning override on kafka ----
  var kfVer = b.asyncapi.bindings.kafka({ topic: "x", bindingVersion: "0.4.0" });
  check("kafka: bindingVersion override",        kfVer.bindingVersion === "0.4.0");

  // ---- amqp omitting all opts is valid ----
  var amqpMin = b.asyncapi.bindings.amqp({});
  check("amqp: no opts ok",                      typeof amqpMin.bindingVersion === "string");

  // ---- mqtt omitting all opts is valid ----
  var mqttMin = b.asyncapi.bindings.mqtt({});
  check("mqtt: no opts ok",                      typeof mqttMin.bindingVersion === "string");

  // ---- http omitting type is valid ----
  var httpMin = b.asyncapi.bindings.http({});
  check("http: no opts ok",                      typeof httpMin.bindingVersion === "string");

  // ---- channel servers as references ----
  aapi.channel("with.servers", {
    address: "with.servers",
    servers: ["#/servers/production", "#/servers/staging"],
  });
  var docWs = aapi.toJson();
  check("channel servers list len",              docWs.channels["with.servers"].servers.length === 2);

  // ---- toYaml of complex doc with all surfaces ----
  var allYaml = realApi.toYaml();
  check("realYaml: contains servers",            allYaml.indexOf("servers:") !== -1);
  check("realYaml: contains channels",           allYaml.indexOf("channels:") !== -1);
  check("realYaml: contains operations",         allYaml.indexOf("operations:") !== -1);
  check("realYaml: contains components",         allYaml.indexOf("components:") !== -1);

  // ---- duplicate channel address allowed (different keys) ----
  var aapiDupAddr = b.asyncapi.create({ info: { title: "D", version: "1.0" } });
  aapiDupAddr.channel("aliasA", { address: "shared.address" });
  aapiDupAddr.channel("aliasB", { address: "shared.address" });
  var docDA = aapiDupAddr.toJson();
  check("duplicate address allowed",             Object.keys(docDA.channels).length === 2);

  // ---- channel with bindings only (no messages) ----
  aapi.channel("bind.only", {
    address: "bind.only",
    bindings: { kafka: b.asyncapi.bindings.kafka({ topic: "bind.only" }) },
  });
  var docBO = aapi.toJson();
  check("channel: bindings only",                docBO.channels["bind.only"].bindings.kafka.topic === "bind.only");
  check("channel: no messages",                  docBO.channels["bind.only"].messages === undefined);

  // ---- message with all fields ----
  aapi.channel("rich.msg", {
    address: "rich.msg",
    messages: {
      Rich: {
        name: "Rich",
        title: "Rich Message",
        summary: "Rich summary",
        description: "Long description",
        contentType: "application/cloudevents+json",
        headers: { type: "object", properties: { traceparent: { type: "string" } } },
        payload: { type: "object", properties: { id: { type: "string" } } },
        correlationId: { location: "$message.payload#/id" },
        bindings: { kafka: { key: { type: "string" } } },
        examples: [{ name: "ex1", payload: { id: "abc" } }],
      },
    },
  });
  var docRich = aapi.toJson();
  var rm = docRich.channels["rich.msg"].messages.Rich;
  check("rich msg: name",                        rm.name === "Rich");
  check("rich msg: title",                       rm.title === "Rich Message");
  check("rich msg: contentType",                 rm.contentType === "application/cloudevents+json");
  check("rich msg: headers walked",              rm.headers.type === "object");
  check("rich msg: payload walked",              rm.payload.type === "object");
  check("rich msg: correlationId",               rm.correlationId.location === "$message.payload#/id");
  check("rich msg: bindings",                    rm.bindings.kafka.key.type === "string");
  check("rich msg: examples",                    Array.isArray(rm.examples) && rm.examples[0].name === "ex1");

  // ---- VALID_OPERATION_ACTIONS — receive only ----
  var aapiR = b.asyncapi.create({ info: { title: "R", version: "1.0" } });
  aapiR.channel("inbox", { address: "inbox" });
  aapiR.operation("listen", { action: "receive", channel: "inbox" });
  var docR2 = aapiR.toJson();
  check("op receive only",                       docR2.operations.listen.action === "receive");

  // ---- security require validates schemes pre-toJson ----
  rejects("security.require: bad shape",
    function () { aapi.security.require("string"); }, /must be an object/);
  rejects("security.add: missing type",
    function () { aapi.security.add("noType", { other: 1 }); }, /must be a securityScheme/);
  rejects("security.add: missing name",
    function () { aapi.security.add("", b.asyncapi.security.bearer()); }, /name/);

  // ---- toJson is idempotent ----
  var aapiIdem = b.asyncapi.create({ info: { title: "Idem", version: "1.0" } });
  aapiIdem.channel("c", { address: "c" });
  var d1 = aapiIdem.toJson();
  var d2 = aapiIdem.toJson();
  check("toJson: idempotent",                    JSON.stringify(d1) === JSON.stringify(d2));

  // ---- middleware fall-through for non-text response (no writeHead) ----
  var serveNonHttp = b.middleware.asyncapiServe({ document: realApi, audit: false });
  var nextNonHttp = 0;
  serveNonHttp({ method: "GET", url: "/asyncapi.json" }, {}, function () { nextNonHttp += 1; });
  check("asyncapiServe: no writeHead → next",    nextNonHttp === 1);

  // ---- HEAD method also responds ----
  var sentHead = { status: null, headers: null, body: null };
  serve({ method: "HEAD", url: "/asyncapi.json", pathname: "/asyncapi.json", headers: {} },
        { writeHead: function (s, h) { sentHead.status = s; sentHead.headers = h; },
          end:       function (b) { sentHead.body = b; } },
        function () {});
  check("asyncapiServe: HEAD responds 200",      sentHead.status === 200);

  // ---- info with default-content-type override ----
  var aapiCt = b.asyncapi.create({
    info: { title: "Ct", version: "1.0" },
    defaultContentType: "application/cloudevents+json",
  });
  aapiCt.channel("c", { address: "c" });
  var docCt = aapiCt.toJson();
  check("doc.defaultContentType overridden",     docCt.defaultContentType === "application/cloudevents+json");

  // ---- doc-level externalDocs ----
  var aapiED2 = b.asyncapi.create({
    info: { title: "X", version: "1.0" },
    externalDocs: { url: "https://docs/asyncapi", description: "Detailed external docs" },
  });
  aapiED2.channel("c", { address: "c" });
  var docED2 = aapiED2.toJson();
  check("doc.externalDocs description",          docED2.externalDocs.description === "Detailed external docs");

  // ---- b.asyncapi.parse — external doc validation ----
  check("b.asyncapi.parse is fn",                typeof b.asyncapi.parse === "function");

  var validAapi = b.asyncapi.create({ info: { title: "T", version: "1.0" } });
  validAapi.channel("c", { address: "c" });
  validAapi.operation("op", { action: "send", channel: "c" });
  var aapiJson = validAapi.toJsonString();
  var aapiParse = b.asyncapi.parse(aapiJson);
  check("asyncapi.parse: valid round-trip",      aapiParse.valid === true);

  var dangChannel = b.asyncapi.parse({
    asyncapi: "3.0.0", info: { title: "T", version: "1.0" },
    channels: {},
    operations: { op: { action: "send", channel: { "$ref": "#/channels/ghost" } } },
  });
  check("asyncapi.parse: dangling channel",      dangChannel.valid === false);

  var badAction = b.asyncapi.parse({
    asyncapi: "3.0.0", info: { title: "T", version: "1.0" },
    channels: { c: { address: "c" } },
    operations: { op: { action: "publish", channel: { "$ref": "#/channels/c" } } },
  });
  check("asyncapi.parse: bad action",            badAction.valid === false);

  var badServer = b.asyncapi.parse({
    asyncapi: "3.0.0", info: { title: "T", version: "1.0" },
    servers: { prod: { host: "kafka:9092" } },
    channels: {}, operations: {},
  });
  check("asyncapi.parse: server missing protocol", badServer.valid === false);

  var threwAapi = false; var msgAapi = "";
  try { b.asyncapi.parse("{not valid"); } catch (e) { threwAapi = true; msgAapi = e.message; }
  check("asyncapi.parse: bad JSON throws",       threwAapi && /invalid JSON/.test(msgAapi));

  console.log("OK — asyncapi tests");
}

module.exports = { run: run };
if (require.main === module) {
  try { run(); process.exit(0); } catch (e) { console.error(e); process.exit(1); }
}
