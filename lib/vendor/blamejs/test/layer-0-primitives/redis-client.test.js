"use strict";
/**
 * RESP protocol parser + URL parsing tests. These cover the bespoke
 * client's pure functions (no socket needed). Live Redis round-trip
 * coverage lives in queue-redis.test.js (which skips cleanly when
 * BLAMEJS_TEST_REDIS_URL is not set).
 */
var helpers = require("../helpers");
var check = helpers.check;
var redis = require("../../lib/redis-client");

function _bytes(s) { return Buffer.from(s, "utf8"); }

async function run() {
  // ---- _parseRedisUrl ----
  var u1 = redis._parseRedisUrl("redis://localhost:6379/0");
  check("url: defaults", u1.host === "localhost" && u1.port === 6379 && u1.tls === false && u1.db === 0);

  var u2 = redis._parseRedisUrl("rediss://user:pw@cache.example.com:6380/3");
  check("url: rediss + auth + db", u2.host === "cache.example.com" && u2.port === 6380 &&
                                    u2.tls === true && u2.username === "user" &&
                                    u2.password === "pw" && u2.db === 3);

  var u3 = redis._parseRedisUrl("redis://:secretonly@h:6379");
  check("url: legacy single-arg AUTH (empty user, password)",
        u3.username === null && u3.password === "secretonly");

  var u4 = redis._parseRedisUrl("redis://h:6379/15");
  check("url: max db 15 OK", u4.db === 15);

  var threwBadDb = false;
  try { redis._parseRedisUrl("redis://h:6379/16"); } catch (_e) { threwBadDb = true; }
  check("url: db > 15 throws", threwBadDb);

  var threwBadProto = false;
  try { redis._parseRedisUrl("http://h:6379/0"); } catch (_e) { threwBadProto = true; }
  check("url: non-redis protocol throws", threwBadProto);

  // ---- _encodeCommand ----
  var enc1 = redis._encodeCommand(["SET", "key", "value"]);
  check("encode: SET key value", enc1.toString("utf8") === "*3\r\n$3\r\nSET\r\n$3\r\nkey\r\n$5\r\nvalue\r\n");

  var enc2 = redis._encodeCommand(["GET", "x"]);
  check("encode: short cmd", enc2.toString("utf8") === "*2\r\n$3\r\nGET\r\n$1\r\nx\r\n");

  // Binary-safe: a Buffer arg with embedded NULs survives
  var binArg = Buffer.from([0x00, 0xff, 0x10, 0x42]);
  var enc3 = redis._encodeCommand(["HSET", "k", "field", binArg]);
  // *4\r\n            (4)
  // $4\r\nHSET\r\n    (10)
  // $1\r\nk\r\n       (7)
  // $5\r\nfield\r\n   (11)
  // $4\r\n<bin>\r\n   (4 + 4 + 2 = 10)
  check("encode: binary arg length", enc3.length === 4 + 10 + 7 + 11 + 10);
  // Find the binary blob — last 6 bytes should be "<bin>\r\n"
  check("encode: binary arg bytes preserved",
        enc3.slice(enc3.length - 6, enc3.length - 2).equals(binArg));

  var threwNull = false;
  try { redis._encodeCommand(["SET", "k", null]); } catch (_e) { threwNull = true; }
  check("encode: null arg throws", threwNull);

  // ---- _parseFrame ----
  // Simple string
  var f1 = redis._parseFrame(_bytes("+OK\r\n"), 0);
  check("parse: +OK", f1.type === "string" && f1.value === "OK" && f1.consumed === 5);

  // Error
  var f2 = redis._parseFrame(_bytes("-ERR wrong type\r\n"), 0);
  check("parse: error", f2.type === "error" && f2.value === "ERR wrong type");

  // Integer
  var f3 = redis._parseFrame(_bytes(":12345\r\n"), 0);
  check("parse: integer", f3.type === "int" && f3.value === 12345);

  // Bulk
  var f4 = redis._parseFrame(_bytes("$5\r\nhello\r\n"), 0);
  check("parse: bulk", f4.type === "bulk" && f4.value.toString("utf8") === "hello");

  // Nil bulk
  var f5 = redis._parseFrame(_bytes("$-1\r\n"), 0);
  check("parse: nil bulk", f5.type === "bulk" && f5.value === null);

  // Array
  var f6 = redis._parseFrame(_bytes("*3\r\n$3\r\nfoo\r\n$3\r\nbar\r\n:42\r\n"), 0);
  var v6 = redis._frameToValue(f6);
  check("parse: array of 3", Array.isArray(v6) && v6.length === 3 &&
                              v6[0].toString("utf8") === "foo" &&
                              v6[1].toString("utf8") === "bar" &&
                              v6[2] === 42);

  // Nested array
  var f7 = redis._parseFrame(_bytes("*2\r\n*2\r\n$1\r\na\r\n$1\r\nb\r\n:7\r\n"), 0);
  var v7 = redis._frameToValue(f7);
  check("parse: nested array", Array.isArray(v7) && Array.isArray(v7[0]) &&
                                 v7[0][0].toString() === "a" && v7[1] === 7);

  // Incomplete frame (mid-bulk)
  var f8 = redis._parseFrame(_bytes("$10\r\nabc"), 0);
  check("parse: incomplete bulk", f8.type === "incomplete");

  // Incomplete frame (no CRLF after marker)
  var f9 = redis._parseFrame(_bytes("+OK"), 0);
  check("parse: incomplete simple string", f9.type === "incomplete");

  // Empty bulk ($0)
  var f10 = redis._parseFrame(_bytes("$0\r\n\r\n"), 0);
  check("parse: empty bulk", f10.type === "bulk" && f10.value.length === 0);

  // Pipelined frames — parse two from one buffer
  var pipelined = _bytes("+OK\r\n:5\r\n");
  var pf1 = redis._parseFrame(pipelined, 0);
  var pf2 = redis._parseFrame(pipelined, pf1.consumed);
  check("parse: pipelined frame 1", pf1.value === "OK");
  check("parse: pipelined frame 2", pf2.value === 5);

  // ---- error frame surfaced via _frameToValue ----
  var efv = redis._frameToValue(redis._parseFrame(_bytes("-ERR boom\r\n"), 0));
  check("frameToValue: error becomes _redisError marker",
        efv && efv._redisError === true && efv.message === "ERR boom");
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e.stack || e); process.exit(1); }
  );
}
