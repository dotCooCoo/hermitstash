"use strict";

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

function _fakeAgent(name) {
  return {
    name: name,
    folders: function (args) { return Promise.resolve({ folders: [{ name: "INBOX" }] }); },
    fetch:   function (args) { return Promise.resolve({ subject: name + ":" + args.objectId }); },
  };
}

function expectRejection(label, p, codeMatch) {
  return p.then(
    function () { check(label + " (did not reject)", false); },
    function (e) { check(label, (e && e.code || "").indexOf(codeMatch) !== -1); }
  );
}

function testSurface() {
  check("create is fn",          typeof b.agent.orchestrator.create === "function");
  check("shardFor is fn",         typeof b.agent.orchestrator.shardFor === "function");
  check("AgentOrchestratorError", typeof b.agent.orchestrator.AgentOrchestratorError === "function");
  check("guards.registry",        b.agent.orchestrator.guards.registry === b.guardAgentRegistry);
  var e = new b.agent.orchestrator.AgentOrchestratorError("agent-orchestrator/test", "t");
  check("error carries code",     e.code === "agent-orchestrator/test");
}

async function testRegisterLookupUnregister() {
  var orch = b.agent.orchestrator.create({});
  var agent = _fakeAgent("acme");
  var r = await orch.register("tenant-acme.mail", agent, { agentKind: "mail", tenantId: "acme" });
  check("register: returns name",       r.name === "tenant-acme.mail");
  check("register: registeredAt is num", typeof r.registeredAt === "number");

  var looked = await orch.lookup("tenant-acme.mail");
  check("lookup: returns agent",         looked === agent);

  var miss = await orch.lookup("nope");
  check("lookup: miss returns null",     miss === null);

  await expectRejection("register: duplicate refused",
    orch.register("tenant-acme.mail", agent, { agentKind: "mail" }),
    "agent-orchestrator/duplicate");

  var u = await orch.unregister("tenant-acme.mail");
  check("unregister: returns name",     u.name === "tenant-acme.mail");

  await expectRejection("unregister: not-found refused",
    orch.unregister("tenant-acme.mail"),
    "agent-orchestrator/not-found");
}

async function testList() {
  var orch = b.agent.orchestrator.create({});
  await orch.register("tenant-a.mail",  _fakeAgent("a"), { agentKind: "mail", tenantId: "a" });
  await orch.register("tenant-b.mail",  _fakeAgent("b"), { agentKind: "mail", tenantId: "b" });
  await orch.register("tenant-a.dsr",   _fakeAgent("ad"), { agentKind: "dsr",  tenantId: "a" });
  var all = await orch.list({});
  check("list: 3 entries",              all.length === 3);
  var mail = await orch.list({ kind: "mail" });
  check("list filter kind",             mail.length === 2);
  var aOnly = await orch.list({ tenantId: "a" });
  check("list filter tenant",           aOnly.length === 2);
}

async function testGuardRefusals() {
  var orch = b.agent.orchestrator.create({});
  await expectRejection("register refuses bad name",
    orch.register("a/b", _fakeAgent("x"), { agentKind: "mail" }),
    "agent-registry/bad-name-char");
  await expectRejection("register refuses bad kind",
    orch.register("x", _fakeAgent("x"), { agentKind: "BAD-SHAPE!" }),
    "agent-registry/bad-kind-shape");
  await expectRejection("register refuses reserved",
    orch.register("ROOT", _fakeAgent("x"), { agentKind: "mail" }),
    "agent-registry/reserved-name");
}

async function testElect() {
  var orch = b.agent.orchestrator.create({
    cluster: { isClusterMode: function () { return false; } },
  });
  var elec = await orch.elect({ resource: "mail.mdn.dispatcher" });
  check("elect single-process: leader",  elec.isLeader === true);
  check("elect single-process: fencing", elec.fencingToken === 1);
}

async function testElectCluster() {
  var fakeCluster = {
    isClusterMode: function () { return true; },
    isLeader:      function () { return true; },
    fencingToken:  function () { return 42; },
    currentLeader: function () { return Promise.resolve({ nodeId: "node-1" }); },
  };
  var orch = b.agent.orchestrator.create({ cluster: fakeCluster });
  var elec = await orch.elect({ resource: "test-resource" });
  check("elect cluster: leader",         elec.isLeader === true);
  check("elect cluster: fencing token",  elec.fencingToken === 42);
  check("elect cluster: leaderId",       elec.leaderId === "node-1");
}

async function testNonIntegerShardsRefused() {
  var fakeQueue = {
    enqueue: async function () { return { jobId: "j" }; },
    consume: async function () { return { unsubscribe: async function () {} }; },
  };
  var orch = b.agent.orchestrator.create({});
  var threw = null;
  try {
    orch.spawnConsumers({ agent: _fakeAgent("x"), queue: fakeQueue, shards: 1.5 });
  } catch (e) { threw = e; }
  check("spawnConsumers refuses fractional shards",
        threw && (threw.code || "").indexOf("agent-orchestrator/bad-shard-count") !== -1);
}

async function testBackendRowJsonRoundTrip() {
  // v0.9.22 meta-detector applied retroactively: every backend row
  // must round-trip cleanly through JSON. Codex flagged the original
  // shape (agentRef function in row) on PR #51; this regression test
  // pins the post-fix shape so future drift surfaces locally.
  var { assertJsonRoundTrip } = require("../helpers/json-round-trip");
  var captured = null;
  var fakeBackend = {
    get:    function (k) { return Promise.resolve(captured && captured.name === k ? captured : null); },
    set:    function (k, v) { captured = v; return Promise.resolve(); },
    delete: function () { captured = null; return Promise.resolve(); },
    list:   function () { return Promise.resolve(captured ? [captured] : []); },
  };
  var orch = b.agent.orchestrator.create({ backend: fakeBackend });
  await orch.register("tenant-acme.mail", _fakeAgent("acme"), {
    agentKind: "mail", tenantId: "acme",
    metadata: { endpoint: "https://acme.example/jmap" },
  });
  assertJsonRoundTrip(captured, "agent-orchestrator backend row");
}

async function testLiveAgentSeparateFromBackend() {
  // The backend row should not carry the agent function ref — a
  // JSON/DB-backed implementation has to be able to round-trip the row.
  var captured = null;
  var fakeBackend = {
    get:    function (k)    { return Promise.resolve(captured && captured.name === k ? captured : null); },
    set:    function (k, v) { captured = v; return Promise.resolve(); },
    delete: function (k)    { captured = null; return Promise.resolve(); },
    list:   function ()     { return Promise.resolve(captured ? [captured] : []); },
  };
  var orch = b.agent.orchestrator.create({ backend: fakeBackend });
  var agent = _fakeAgent("acme");
  await orch.register("tenant-acme.mail", agent, { agentKind: "mail" });
  check("backend row has no live ref",     captured && captured.agentRef === undefined);
  check("backend row has metadata",        captured && captured.kind === "mail");

  // Round-trip the backend row through JSON — must not throw.
  var json = JSON.stringify(captured);
  check("backend row JSON-serializable",   typeof json === "string" && json.indexOf("\"kind\"") !== -1);

  // Live lookup returns the agent ref from in-process map.
  var looked = await orch.lookup("tenant-acme.mail");
  check("lookup returns live ref",         looked === agent);
}

async function testNotHydrated() {
  // Simulate: backend row exists from another process, but THIS process
  // never called register(name, agent). lookup() must surface explicitly.
  var orch = b.agent.orchestrator.create({
    backend: {
      get:    function (k) {
        return Promise.resolve(k === "remote.mail" ? { name: "remote.mail", kind: "mail" } : null);
      },
      set:    function () { return Promise.resolve(); },
      delete: function () { return Promise.resolve(); },
      list:   function () { return Promise.resolve([]); },
    },
  });
  await expectRejection("lookup refuses not-hydrated",
    orch.lookup("remote.mail"),
    "agent-orchestrator/not-hydrated");
}

async function testSpawnConsumers() {
  var enqueued = [];
  var fakeQueue = {
    enqueue: async function (topic, payload) { enqueued.push({ topic: topic, payload: payload }); return { jobId: "j1" }; },
    consume: async function (topic, handler, opts) {
      // record subscription; no actual delivery in test.
      return { unsubscribe: async function () { /* noop */ } };
    },
  };
  var orch = b.agent.orchestrator.create({});
  var agent = _fakeAgent("test");
  var consumers = orch.spawnConsumers({
    agent: agent, queue: fakeQueue,
    shards: 3, taskTopic: "mail.agent.tasks",
  });
  check("spawn: 3 consumers",            consumers.length === 3);
  check("spawn: topic suffix",           consumers[0].topic === "mail.agent.tasks.0");
  check("spawn: topic suffix end",       consumers[2].topic === "mail.agent.tasks.2");
  for (var i = 0; i < consumers.length; i += 1) await consumers[i].start();
}

function testShardFor() {
  // FNV-1a determinism — same input maps to same shard.
  var s1 = b.agent.orchestrator.shardFor("tenant-acme", 8);
  var s2 = b.agent.orchestrator.shardFor("tenant-acme", 8);
  check("shardFor: deterministic",       s1 === s2);
  check("shardFor: in range",             s1 >= 0 && s1 < 8);
  check("shardFor: shards=1 always 0",   b.agent.orchestrator.shardFor("anything", 1) === 0);
  check("shardFor: empty key → 0",       b.agent.orchestrator.shardFor("", 8) === 0);
}

async function testDrain() {
  var stopCount = 0;
  var fakeQueue = {
    enqueue: async function () { return { jobId: "j" }; },
    consume: async function () { return { unsubscribe: async function () { stopCount += 1; } }; },
  };
  var orch = b.agent.orchestrator.create({});
  var consumers = orch.spawnConsumers({
    agent: _fakeAgent("x"), queue: fakeQueue, shards: 2,
  });
  for (var i = 0; i < consumers.length; i += 1) await consumers[i].start();
  var r = await orch.drain({});
  check("drain: drained count",          r.drained === 2);
  check("drain: stops subs",             stopCount === 2);
  check("drain: elapsedMs set",          typeof r.elapsedMs === "number");
  check("drain: isDraining true after",  orch.isDraining() === true);
}

async function testHealth() {
  var orch = b.agent.orchestrator.create({});
  await orch.register("a.mail", _fakeAgent("a"), { agentKind: "mail", tenantId: "a" });
  var h = await orch.health();
  check("health: agents listed",         h.agents.length === 1);
  check("health: overall ok",            h.overall === "ok");
  check("health: not draining",          h.draining === false);
  check("health: consumers list",        Array.isArray(h.consumers));
}

async function testStreamRegistry() {
  var orch = b.agent.orchestrator.create({});
  var id = orch.registerStream({ kind: "search", actor: { id: "u1" } });
  check("registerStream returns id",     typeof id === "string" && id.indexOf("stream-") === 0);
  var h = await orch.health();
  check("health: stream count = 1",      h.streams === 1);
  orch.unregisterStream(id);
  var h2 = await orch.health();
  check("health: stream count = 0",      h2.streams === 0);
}

async function testPermissions() {
  var perms = b.permissions.create({
    roles: { reader: { permissions: ["agent-registry:read"] }, writer: { permissions: ["agent-registry:read", "agent-registry:write"] } },
    auditFailures: false, auditSuccess: false,
  });
  var orch = b.agent.orchestrator.create({ permissions: perms });
  var reader = { id: "r1", roles: ["reader"] };
  var writer = { id: "w1", roles: ["writer"] };

  // writer can register
  await orch.register("tenant-x.mail", _fakeAgent("x"), { agentKind: "mail", actor: writer });
  // reader can lookup
  var hit = await orch.lookup("tenant-x.mail", { actor: reader });
  check("perms: reader can lookup",      hit !== null);
  // reader cannot register
  await expectRejection("perms: reader cannot register",
    orch.register("tenant-y.mail", _fakeAgent("y"), { agentKind: "mail", actor: reader }),
    "agent-orchestrator/permission-denied");
}

async function testHydrate() {
  // SUBSTRATE-3 — cross-orchestrator-restart replay. Operator
  // re-attaches a live agent ref to a row that's already in the
  // persistent backend.
  var captured = null;
  var fakeBackend = {
    get:    function (k)    { return Promise.resolve(captured && captured.name === k ? captured : null); },
    set:    function (k, v) { captured = v; return Promise.resolve(); },
    delete: function ()     { captured = null; return Promise.resolve(); },
    list:   function ()     { return Promise.resolve(captured ? [captured] : []); },
  };
  // Process A registers.
  var orchA = b.agent.orchestrator.create({ backend: fakeBackend });
  await orchA.register("remote.mail", _fakeAgent("remote"), { agentKind: "mail" });
  check("Process A: lookup works after register", typeof (await orchA.lookup("remote.mail")) === "object");

  // Process B starts: backend row visible; no live ref locally.
  var orchB = b.agent.orchestrator.create({ backend: fakeBackend });
  await expectRejection("Process B: lookup throws not-hydrated before hydrate",
    orchB.lookup("remote.mail"), "agent-orchestrator/not-hydrated");

  // SUBSTRATE-3: hydrate installs the live ref locally.
  var newAgent = _fakeAgent("new-process");
  var hyd = await orchB.hydrate("remote.mail", newAgent);
  check("SUBSTRATE-3: hydrate echoes name", hyd.name === "remote.mail");

  var afterHydrate = await orchB.lookup("remote.mail");
  check("SUBSTRATE-3: lookup post-hydrate returns ref",
    afterHydrate === newAgent);

  // Double-hydrate refused.
  await expectRejection("SUBSTRATE-3: double-hydrate refused",
    orchB.hydrate("remote.mail", _fakeAgent("other")),
    "agent-orchestrator/already-hydrated");
  // Hydrate missing-row refused.
  await expectRejection("SUBSTRATE-3: hydrate refuses missing-row",
    orchB.hydrate("never-registered", _fakeAgent("z")),
    "agent-orchestrator/not-in-registry");
}

async function testDrainQuiesce() {
  // SUBSTRATE-8 — drain quiesces outbox + saga before returning.
  // BUG-6 — per-consumer timeout: a hung consumer doesn't block other
  // consumers' stop() within the budget.
  var pendingNow = 3;
  var fakeOutbox = {
    pendingCount: function () { return Promise.resolve(pendingNow); },
  };
  var _stopped = [];
  var fakeQueue = {
    consume: async function () {
      return { unsubscribe: async function () { /* fast */ } };
    },
  };
  var orch = b.agent.orchestrator.create({
    outbox:            fakeOutbox,
    perConsumerStopMs: 100,                                                                             // small budget for the test
  });
  var consumers = orch.spawnConsumers({ agent: _fakeAgent("x"), queue: fakeQueue, shards: 2 });
  // Wrap one consumer's stop to be slow (simulates a hung consumer).
  var orig = consumers[0].stop;
  consumers[0].stop = function () {
    return new Promise(function () { /* never resolves */ });
  };
  // After consumers are "stopped", simulate the publisher draining its queue.
  helpers.passiveObserve(50, "agent-orchestrator: simulate publisher drain after consumer stop").then(function () {
    pendingNow = 0;
  });
  var r = await orch.drain({ timeoutMs: 500 });
  check("BUG-6: drain didn't hang past timeout", r.elapsedMs < 1500);
  check("SUBSTRATE-8: quiesce reflected", r.inFlightQuiescent === true);
  // Restore so subsequent tests don't leak.
  consumers[0].stop = orig;
}

async function testShardForSaltedFnv() {
  // SUBSTRATE-20 — salted FNV: vault-less fallback still distributes
  // reasonably. Doesn't assert randomness — just that the same inputs
  // produce the same output and varied inputs produce varied output.
  var s1 = b.agent.orchestrator.shardFor("tenant-acme", 8);
  var s2 = b.agent.orchestrator.shardFor("tenant-acme", 8);
  check("SUBSTRATE-20: shardFor deterministic", s1 === s2);
  var spread = {};
  for (var i = 0; i < 50; i += 1) {
    var s = b.agent.orchestrator.shardFor("tenant-" + i, 8);
    spread[s] = (spread[s] || 0) + 1;
  }
  check("SUBSTRATE-20: shardFor distributes over 8 shards (>=4 occupied)",
    Object.keys(spread).length >= 4);
}

async function run() {
  testSurface();
  await testRegisterLookupUnregister();
  await testList();
  await testGuardRefusals();
  await testElect();
  await testElectCluster();
  await testNonIntegerShardsRefused();
  await testBackendRowJsonRoundTrip();
  await testLiveAgentSeparateFromBackend();
  await testNotHydrated();
  await testHydrate();
  await testSpawnConsumers();
  testShardFor();
  await testShardForSaltedFnv();
  await testDrain();
  await testDrainQuiesce();
  await testHealth();
  await testStreamRegistry();
  await testPermissions();
}

module.exports = { run: run };
if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e); process.exit(1); });
}
