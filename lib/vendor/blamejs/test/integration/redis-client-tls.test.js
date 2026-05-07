"use strict";
/**
 * Live RESP2 round-trip against the docker-compose Redis fixture's TLS
 * port (6380). Exercises lib/redis-client.js end-to-end on rediss://
 * with strict CA verification — no rejectUnauthorized=false bypass.
 */
var helpers = require("../helpers");
var check = helpers.check;
var services = require("../helpers/services");
var redisClient = require("../../lib/redis-client");

async function run() {
  var svc = await services.requireService("redisTls");
  if (!svc.ok) throw new Error("redis-tls unreachable: " + svc.reason);

  // Cert covers DNS:redis, DNS:blamejs-test-redis, DNS:localhost.
  // Use localhost for SNI compatibility.
  var c = redisClient.create({
    url:                "rediss://localhost:6380/0",
    connectTimeoutMs:   3000,
    commandTimeoutMs:   5000,
    maxReconnectAttempts: 2,
  });
  await c.connect();
  check("connect: TLS handshake succeeded with private CA",   c.isOpen());
  check("_state: tls flag set",                                 c._state().tls === true);
  check("_state: port matches",                                 c._state().port === 6380);

  // ---- PING ----
  var pong = await c.command("PING");
  check("PING: PONG",
        pong === "PONG" || (Buffer.isBuffer(pong) && pong.toString() === "PONG"));

  // ---- SET / GET round-trip ----
  var k = "blamejs:test:tls:" + Date.now();
  var setRv = await c.command("SET", k, "hello-tls");
  check("SET: returns OK",
        setRv === "OK" || (Buffer.isBuffer(setRv) && setRv.toString() === "OK"));
  var getRv = await c.command("GET", k);
  check("GET: bytes round-trip",
        Buffer.isBuffer(getRv) && getRv.toString() === "hello-tls");

  // ---- binary payload through TLS ----
  var binaryKey = "blamejs:test:tls:bin:" + Date.now();
  var binaryVal = Buffer.from([0x00, 0xff, 0x42, 0x01, 0xfe]);
  await c.command("SET", binaryKey, binaryVal);
  var binaryGet = await c.command("GET", binaryKey);
  check("binary value round-trips through TLS exactly",
        Buffer.isBuffer(binaryGet) && Buffer.compare(binaryGet, binaryVal) === 0);

  // ---- pipelining: 50 SETs in flight ----
  var pipelinePromises = [];
  for (var i = 0; i < 50; i++) {
    pipelinePromises.push(c.command("SET", "blamejs:test:tls:pipe:" + i, "v-" + i));
  }
  var pipelineResults = await Promise.all(pipelinePromises);
  check("pipelining: all 50 SETs returned OK",
        pipelineResults.every(function (r) {
          return r === "OK" || (Buffer.isBuffer(r) && r.toString() === "OK");
        }));

  // ---- runScript: simple Lua via EVAL ----
  var luaRv = await c.runScript("return ARGV[1]", 0, "lua-via-tls");
  check("runScript: EVAL returns ARGV[1]",
        Buffer.isBuffer(luaRv) ? luaRv.toString() === "lua-via-tls" : luaRv === "lua-via-tls");

  // ---- cleanup ----
  for (var j = 0; j < 50; j++) {
    await c.command("DEL", "blamejs:test:tls:pipe:" + j);
  }
  await c.command("DEL", k, binaryKey);
  await c.close();
  check("close: client reports closed",  !c.isOpen());

  // ---- bad URL: rediss:// to wrong port should fail cleanly ----
  var badC = redisClient.create({
    url:                  "rediss://localhost:6379/0",  // 6379 is plain, not TLS
    connectTimeoutMs:     1500,
    maxReconnectAttempts: 0,
  });
  var threwBad = null;
  try { await badC.connect(); }
  catch (e) { threwBad = e; }
  try { await badC.close(); } catch (_e) {}
  check("rediss to plain port: clean error (not a hang)",
        threwBad !== null && typeof threwBad.code === "string");
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); process.exit(0); },
    function (e) { console.error("FAIL:", e.stack || e); process.exit(1); }
  );
}
