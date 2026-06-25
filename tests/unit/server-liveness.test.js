/**
 * server-liveness unit tests.
 *
 * Covers scripts/lib/server-liveness.js — the protocol-agnostic TCP-connect
 * probe shared by the offline vault tools (vault-key-rotate,
 * vault-passphrase-{setup,rotate,remove}).
 *
 * The probe MUST detect a server that speaks ANY protocol on either the public
 * gate port (PORT) or the internal TLS port (INTERNAL_TLS_PORT) — the old
 * plain-HTTP /health probe was inert on every TLS/PQC deployment because the
 * raw bytes never produced an HTTP response. A bare TCP listener that NEVER
 * sends an HTTP response (the worst case for the old probe) is the key
 * regression case here.
 */
var { describe, it, before, after, afterEach } = require("node:test");
var assert = require("node:assert");
var net = require("net");

var liveness = require("../../scripts/lib/server-liveness");

// A raw TCP listener that accepts connections but speaks no protocol — the
// shape a probe over plain HTTP could never observe via an HTTP response.
function listenSilent() {
  return new Promise(function (resolve) {
    var srv = net.createServer(function (sock) {
      // Accept and hold the socket open; send nothing. Mimics a TLS/PQC gate
      // that resets a non-handshake byte but still ACKed the TCP connect.
      sock.resume();
    });
    srv.listen(0, "127.0.0.1", function () { resolve(srv); });
  });
}

function closeServer(srv) {
  return new Promise(function (resolve) {
    if (!srv) return resolve();
    srv.close(function () { resolve(); });
  });
}

// A port that is (almost certainly) refused: bind, capture the port, close.
function refusedPort() {
  return new Promise(function (resolve) {
    var srv = net.createServer();
    srv.listen(0, "127.0.0.1", function () {
      var p = srv.address().port;
      srv.close(function () { resolve(p); });
    });
  });
}

var savedPort, savedTls;

before(function () {
  savedPort = process.env.PORT;
  savedTls = process.env.INTERNAL_TLS_PORT;
});

afterEach(function () {
  if (savedPort === undefined) delete process.env.PORT; else process.env.PORT = savedPort;
  if (savedTls === undefined) delete process.env.INTERNAL_TLS_PORT; else process.env.INTERNAL_TLS_PORT = savedTls;
});

describe("server-liveness.probePort", function () {
  it("returns 'listening' for a bare TCP listener that sends no bytes", async function () {
    var srv = await listenSilent();
    try {
      var result = await liveness.probePort(srv.address().port);
      assert.strictEqual(result, "listening");
    } finally {
      await closeServer(srv);
    }
  });

  it("returns 'refused' when nothing is listening", async function () {
    var port = await refusedPort();
    var result = await liveness.probePort(port);
    assert.strictEqual(result, "refused");
  });
});

describe("server-liveness.isServerRunning", function () {
  it("detects a silent listener on the GATE port (PORT)", async function () {
    var gate = await listenSilent();
    var idleTls = await refusedPort();
    try {
      process.env.PORT = String(gate.address().port);
      process.env.INTERNAL_TLS_PORT = String(idleTls);
      assert.strictEqual(await liveness.isServerRunning(), true);
    } finally {
      await closeServer(gate);
    }
  });

  it("detects a silent listener on the INTERNAL_TLS_PORT only (gate refused)", async function () {
    var tls = await listenSilent();
    var idleGate = await refusedPort();
    try {
      process.env.PORT = String(idleGate);
      process.env.INTERNAL_TLS_PORT = String(tls.address().port);
      assert.strictEqual(await liveness.isServerRunning(), true);
    } finally {
      await closeServer(tls);
    }
  });

  it("reports not-running only when BOTH ports cleanly refuse", async function () {
    var gate = await refusedPort();
    var tls = await refusedPort();
    process.env.PORT = String(gate);
    process.env.INTERNAL_TLS_PORT = String(tls);
    assert.strictEqual(await liveness.isServerRunning(), false);
  });
});

describe("server-liveness.assertServerNotRunning", function () {
  it("resolves immediately when --force-with-server-running is set, without probing", async function () {
    // Point at a live listener; force flag must short-circuit before any probe.
    var gate = await listenSilent();
    try {
      process.env.PORT = String(gate.address().port);
      await liveness.assertServerNotRunning({ forceWithServerRunning: true });
      assert.ok(true, "did not exit despite a live server");
    } finally {
      await closeServer(gate);
    }
  });

  it("resolves (no exit) when both ports refuse", async function () {
    var gate = await refusedPort();
    var tls = await refusedPort();
    process.env.PORT = String(gate);
    process.env.INTERNAL_TLS_PORT = String(tls);
    await liveness.assertServerNotRunning({ forceWithServerRunning: false });
    assert.ok(true, "resolved when no server present");
  });
});

describe("server-liveness port resolution", function () {
  it("defaults gate to 3000 and internal TLS to 3001", function () {
    delete process.env.PORT;
    delete process.env.INTERNAL_TLS_PORT;
    assert.strictEqual(liveness.gatePort(), 3000);
    assert.strictEqual(liveness.internalTlsPort(), 3001);
  });

  it("honors PORT / INTERNAL_TLS_PORT env overrides", function () {
    process.env.PORT = "8080";
    process.env.INTERNAL_TLS_PORT = "8443";
    assert.strictEqual(liveness.gatePort(), 8080);
    assert.strictEqual(liveness.internalTlsPort(), 8443);
  });
});

after(function () {
  if (savedPort === undefined) delete process.env.PORT; else process.env.PORT = savedPort;
  if (savedTls === undefined) delete process.env.INTERNAL_TLS_PORT; else process.env.INTERNAL_TLS_PORT = savedTls;
});
