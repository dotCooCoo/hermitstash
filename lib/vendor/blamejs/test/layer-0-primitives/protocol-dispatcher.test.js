"use strict";
/**
 * protocol-dispatcher — pluggable protocol resolver.
 *
 * Run standalone: `node test/layer-0-primitives/protocol-dispatcher.test.js`
 * Or via smoke:   `node test/smoke.js`
 */

var helpers = require("../helpers");
var b     = helpers.b;
var check = helpers.check;

function _fakeProto(name) {
  return { name: name, create: function (cfg) { return { proto: name, cfg: cfg }; } };
}

function testSurface() {
  check("b.protocolDispatcher exposed",       typeof b.protocolDispatcher === "object");
  check("create is a function",               typeof b.protocolDispatcher.create === "function");
  check("default ProtocolDispatcherError",    typeof b.protocolDispatcher.ProtocolDispatcherError === "function");
}

function testCreateValidatesOpts() {
  var threwName = null;
  try { b.protocolDispatcher.create({ protocols: { a: _fakeProto("a") } }); }
  catch (e) { threwName = e; }
  check("create: missing name rejected",        threwName && /opts.name/.test(threwName.message));

  var threwProtos = null;
  try { b.protocolDispatcher.create({ name: "x" }); }
  catch (e) { threwProtos = e; }
  check("create: missing protocols rejected",  threwProtos && /opts.protocols/.test(threwProtos.message));

  var threwProtosArray = null;
  try { b.protocolDispatcher.create({ name: "x", protocols: [] }); }
  catch (e) { threwProtosArray = e; }
  check("create: array protocols rejected",     threwProtosArray && /opts.protocols/.test(threwProtosArray.message));

  var threwBadProto = null;
  try { b.protocolDispatcher.create({ name: "x", protocols: { foo: { /* missing .create */ } } }); }
  catch (e) { threwBadProto = e; }
  check("create: protocol without .create rejected",
        threwBadProto && /\.create function/.test(threwBadProto.message));

  var threwBadDeferred = null;
  try { b.protocolDispatcher.create({ name: "x", protocols: { a: _fakeProto("a") }, deferred: "no" }); }
  catch (e) { threwBadDeferred = e; }
  check("create: non-object deferred rejected", threwBadDeferred && /opts.deferred/.test(threwBadDeferred.message));

  var threwBadFallback = null;
  try { b.protocolDispatcher.create({ name: "x", protocols: { a: _fakeProto("a") }, fallbackProtocol: 42 }); }
  catch (e) { threwBadFallback = e; }
  check("create: non-string fallbackProtocol rejected",
        threwBadFallback && /fallbackProtocol/.test(threwBadFallback.message));

  var threwBadErrCls = null;
  try { b.protocolDispatcher.create({ name: "x", protocols: { a: _fakeProto("a") }, errorClass: "not-a-class" }); }
  catch (e) { threwBadErrCls = e; }
  check("create: non-function errorClass rejected",
        threwBadErrCls && /errorClass/.test(threwBadErrCls.message));
}

function testResolveKnownProtocol() {
  var d = b.protocolDispatcher.create({
    name: "test",
    protocols: { foo: _fakeProto("foo"), bar: _fakeProto("bar") },
  });
  check("resolve: returns the matching proto",  d.resolve("foo").name === "foo");
  check("resolve: alternate proto",              d.resolve("bar").name === "bar");
}

function testResolveMissingProtocol() {
  var d = b.protocolDispatcher.create({
    name: "test",
    protocols: { foo: _fakeProto("foo") },
  });
  var threw = null;
  try { d.resolve(); } catch (e) { threw = e; }
  check("resolve: missing protocol → MISSING_PROTOCOL",
        threw && threw.code === "MISSING_PROTOCOL");
  check("resolve: missing protocol — error names dispatcher",
        threw && /test backend/.test(threw.message));
}

function testResolveUnknownProtocol() {
  var d = b.protocolDispatcher.create({
    name: "test",
    protocols: { foo: _fakeProto("foo"), bar: _fakeProto("bar") },
  });
  var threw = null;
  try { d.resolve("baz"); } catch (e) { threw = e; }
  check("resolve: unknown → UNKNOWN_PROTOCOL",
        threw && threw.code === "UNKNOWN_PROTOCOL");
  check("resolve: unknown — error lists known protocols",
        threw && /known: bar, foo/.test(threw.message));
}

function testResolveDeferredProtocol() {
  var d = b.protocolDispatcher.create({
    name: "test",
    protocols: { foo: _fakeProto("foo") },
    deferred: { redis: { description: "Redis Streams", since: "future" } },
    fallbackProtocol: "foo",
  });
  var threw = null;
  try { d.resolve("redis"); } catch (e) { threw = e; }
  check("resolve: deferred → PROTOCOL_NOT_IMPLEMENTED",
        threw && threw.code === "PROTOCOL_NOT_IMPLEMENTED");
  check("resolve: deferred error includes description",
        threw && /Redis Streams/.test(threw.message));
  check("resolve: deferred error includes since",
        threw && /future/.test(threw.message));
  check("resolve: deferred error suggests fallback",
        threw && /Use protocol: 'foo'/.test(threw.message));
}

function testProtocolsAndDeferredArrays() {
  var d = b.protocolDispatcher.create({
    name: "test",
    protocols: { local: _fakeProto("local"), webhook: _fakeProto("webhook") },
    deferred:  { syslog: { description: "x" }, otlp: { description: "y" } },
  });
  check("protocols: sorted array",
        Array.isArray(d.protocols) && d.protocols.length === 2 &&
        d.protocols[0] === "local" && d.protocols[1] === "webhook");
  check("deferred: sorted array",
        Array.isArray(d.deferred) && d.deferred.length === 2 &&
        d.deferred[0] === "otlp" && d.deferred[1] === "syslog");
}

function testThreeFrameworkUsages() {
  // Verify the three migrated callers (queue / log-stream / object-store)
  // expose dispatcher-driven PROTOCOLS / DEFERRED_PROTOCOLS arrays.
  check("queue.PROTOCOLS includes local",
        b.queue.PROTOCOLS.indexOf("local") !== -1);
  check("queue.PROTOCOLS includes redis (shipped in v0.6.27)",
        b.queue.PROTOCOLS.indexOf("redis") !== -1);
  check("queue.PROTOCOLS includes sqs (shipped in v0.6.43)",
        b.queue.PROTOCOLS.indexOf("sqs") !== -1);
  check("queue.DEFERRED_PROTOCOLS still includes amqp",
        b.queue.DEFERRED_PROTOCOLS.indexOf("amqp") !== -1);
  check("logStream.PROTOCOLS includes webhook",
        b.logStream.PROTOCOLS.indexOf("webhook") !== -1);
  check("logStream.PROTOCOLS includes otlp (shipped in v0.6.24)",
        b.logStream.PROTOCOLS.indexOf("otlp") !== -1);
  check("logStream.PROTOCOLS includes cloudwatch (shipped in v0.6.25)",
        b.logStream.PROTOCOLS.indexOf("cloudwatch") !== -1);
  check("logStream.PROTOCOLS includes syslog",
        b.logStream.PROTOCOLS.indexOf("syslog") !== -1);
  check("logStream.DEFERRED_PROTOCOLS is empty",
        b.logStream.DEFERRED_PROTOCOLS.length === 0);
  check("objectStore.PROTOCOLS includes sigv4",
        b.objectStore.PROTOCOLS.indexOf("sigv4") !== -1);
}

async function run() {
  testSurface();
  testCreateValidatesOpts();
  testResolveKnownProtocol();
  testResolveMissingProtocol();
  testResolveUnknownProtocol();
  testResolveDeferredProtocol();
  testProtocolsAndDeferredArrays();
  testThreeFrameworkUsages();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("protocol-dispatcher tests passed"); process.exit(0); },
    function (e) { console.error(e); process.exit(1); }
  );
}
