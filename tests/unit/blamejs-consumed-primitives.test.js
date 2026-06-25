// Direct behavioral coverage for blamejs primitives HermitStash consumes but
// had no test reference for. tests/lint/test-coverage.test.js enumerates the
// vendored framework surface and flags any HS-consumed b.* primitive without a
// test that names it; the 0.15.19 surface added several. Each test here exercises
// the real primitive (not a name-drop) at the same call shape HS uses it.

var { describe, it, before, after } = require("node:test");
var assert = require("node:assert");
var path = require("path");
var fs = require("fs");
var os = require("os");
var http = require("http");
var nodeCrypto = require("crypto");

// Isolated test DB so vault loads cleanly (mirrors field-crypto.test.js).
var testId = nodeCrypto.randomBytes(4).toString("hex");
var testDbPath = path.join(__dirname, "..", "..", "data", "test-prim-cov-" + testId + ".db");
process.env.HERMITSTASH_DB_PATH = testDbPath;

// Clear the cache FIRST, then require the framework + vault, so the `b` we assert
// against is the SAME framework instance lib/vault initializes. The vendored
// blamejs path contains "hermitstash", so it is cleared here too — requiring `b`
// before the clear would leave us holding a stale, never-initialized instance.
Object.keys(require.cache).forEach(function (k) {
  if (k.includes("hermitstash") && !k.includes("node_modules") && !k.includes("test")) delete require.cache[k];
});

var b = require("../../lib/vendor/blamejs");
var vault = require("../../lib/vault");

var TMP;
before(async function () {
  // getDerivedHashMacKey / computeNamespacedHash both pull the keyed-hash material
  // from the vault, so it must be initialized first.
  await vault.init();
  TMP = fs.mkdtempSync(path.join(os.tmpdir(), "hs-prim-cov-"));
});

after(function () {
  try { fs.rmSync(TMP, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 }); } catch (_e) { /* best effort */ }
  ["", "-shm", "-wal", ".enc"].forEach(function (suffix) {
    try { fs.unlinkSync(testDbPath + suffix); } catch (_e) { /* best effort */ }
  });
});

describe("blamejs consumed-primitive coverage", function () {
  it("b.ssrfGuard.cidrContains matches in-range and rejects out-of-range (v4 + v6)", function () {
    assert.strictEqual(b.ssrfGuard.cidrContains("10.0.0.0/8", "10.1.2.3"), true);
    assert.strictEqual(b.ssrfGuard.cidrContains("10.0.0.0/8", "11.0.0.1"), false);
    assert.strictEqual(b.ssrfGuard.cidrContains("2001:db8::/32", "2001:db8::1"), true);
    assert.strictEqual(b.ssrfGuard.cidrContains("2001:db8::/32", "2001:dba::1"), false);
  });

  it("b.nonceStore.checkAndInsert accepts a nonce once and rejects the replay", async function () {
    var store = b.nonceStore.create({ backend: "memory" });
    var first = await store.checkAndInsert("nonce-A", Date.now() + 60000);
    var replay = await store.checkAndInsert("nonce-A", Date.now() + 60000);
    assert.strictEqual(first, true, "first insert is accepted");
    assert.strictEqual(replay, false, "replay of the same nonce is refused");
  });

  it("b.middleware.requestId attaches a request id and calls next", function () {
    var mw = b.middleware.requestId();
    assert.strictEqual(typeof mw, "function");
    var req = { headers: {}, method: "GET", url: "/" };
    var res = { setHeader: function () {}, getHeader: function () {}, on: function () {} };
    var nexted = false;
    mw(req, res, function () { nexted = true; });
    assert.strictEqual(nexted, true, "next() is called");
    assert.strictEqual(typeof req.requestId, "string");
    assert.ok(req.requestId.length > 0, "a non-empty request id is attached");
  });

  it("b.auditChain.computeRowHash is deterministic and input-sensitive", function () {
    var prev = "a".repeat(128); // 128-hex SHA3-512 chain tip
    var nonce = Buffer.from("11".repeat(16), "hex"); // per-row nonce (non-empty Buffer)
    var h1 = b.auditChain.computeRowHash(prev, JSON.stringify({ a: 1 }), nonce);
    var h2 = b.auditChain.computeRowHash(prev, JSON.stringify({ a: 1 }), nonce);
    var h3 = b.auditChain.computeRowHash(prev, JSON.stringify({ a: 2 }), nonce);
    assert.strictEqual(h1, h2, "same inputs hash identically");
    assert.notStrictEqual(h1, h3, "a changed payload changes the row hash");
    assert.match(h1, /^[0-9a-f]{128}$/, "row hash is a 128-hex SHA3-512 digest");
  });

  it("b.atomicFile.writeSync/readSync round-trips a buffer", function () {
    var f = path.join(TMP, "af.dat");
    var data = Buffer.from("atomic-file-content");
    b.atomicFile.writeSync(f, data);
    assert.ok(b.atomicFile.readSync(f).equals(data));
  });

  it("b.atomicFile.openAppendNoFollowSync appends to a real path and refuses a symlink", function () {
    var real = path.join(TMP, "real.log");
    fs.writeFileSync(real, "start\n");
    var fd = b.atomicFile.openAppendNoFollowSync(real);
    fs.writeSync(fd, "more\n");
    fs.closeSync(fd);
    assert.ok(fs.readFileSync(real, "utf8").indexOf("more") !== -1, "append reaches the real file");

    var link = path.join(TMP, "link.log");
    var symlinkable = true;
    try { fs.symlinkSync(real, link); } catch (_e) { symlinkable = false; } // Windows often needs privilege
    if (symlinkable) {
      assert.throws(function () {
        var lfd = b.atomicFile.openAppendNoFollowSync(link);
        fs.closeSync(lfd);
      }, /ELOOP|symlink|not permitted|EMLINK/i, "a symlinked final component is refused (O_NOFOLLOW)");
    }
  });

  it("b.atomicFile core file ops round-trip (write/writeExclSync/fdSafeReadSync/openNoFollowSync/fsyncDir/renameWithRetry)", async function () {
    var data = Buffer.from("atomic-ops");

    // write (async, atomic temp+rename)
    var wp = path.join(TMP, "w.dat");
    await b.atomicFile.write(wp, data);
    assert.ok(b.atomicFile.fdSafeReadSync(wp).equals(data), "write + fdSafeReadSync round-trip");

    // writeExclSync (atomic write via an exclusive temp)
    var xp = path.join(TMP, "x.dat");
    b.atomicFile.writeExclSync(xp, data);
    assert.ok(fs.readFileSync(xp).equals(data), "writeExclSync writes the bytes");

    // openNoFollowSync (read fd; refuses a symlinked final component)
    var op = path.join(TMP, "o.dat");
    fs.writeFileSync(op, data);
    var fd = b.atomicFile.openNoFollowSync(op);
    assert.strictEqual(typeof fd, "number");
    fs.closeSync(fd);
    var olink = path.join(TMP, "o-link.dat");
    var symlinkable = true;
    try { fs.symlinkSync(op, olink); } catch (_e) { symlinkable = false; }
    if (symlinkable) {
      assert.throws(function () { fs.closeSync(b.atomicFile.openNoFollowSync(olink)); },
        /ELOOP|symlink|not permitted/i, "openNoFollowSync refuses a symlink");
    }

    // fsyncDir (durability barrier — must not throw on a real dir)
    assert.doesNotThrow(function () { b.atomicFile.fsyncDir(TMP); });

    // renameWithRetry (atomic move)
    var src = path.join(TMP, "src.dat");
    var dst = path.join(TMP, "dst.dat");
    fs.writeFileSync(src, data);
    b.atomicFile.renameWithRetry(src, dst);
    assert.ok(!fs.existsSync(src), "source is gone after rename");
    assert.ok(fs.readFileSync(dst).equals(data), "destination has the bytes");
  });

  it("b.staticServe.create returns a 3-arg middleware", function () {
    var mw = b.staticServe.create({ root: TMP });
    assert.strictEqual(typeof mw, "function");
    assert.strictEqual(mw.length, 3, "static-serve middleware is (req,res,next)");
  });

  it("b.session.logout clears the session cookie", async function () {
    var headers = {};
    var res = {
      setHeader: function (k, v) { headers[k.toLowerCase()] = v; },
      getHeader: function (k) { return headers[k.toLowerCase()]; },
      headersSent: false,
    };
    await b.session.logout(res, "some-token", { cookieName: "hs_sid" });
    var sc = headers["set-cookie"];
    var joined = Array.isArray(sc) ? sc.join("\n") : String(sc || "");
    assert.match(joined, /hs_sid=/, "the session cookie is named in the clear");
    assert.match(joined, /Max-Age=0|Expires=/i, "the cookie is expired immediately");
  });

  it("b.httpClient.request performs a GET and resolves the response", async function () {
    var server = http.createServer(function (req, res) {
      res.writeHead(200, { "Content-Type": "text/plain" });
      res.end("primitive-ok");
    });
    await new Promise(function (resolve) { server.listen(0, "127.0.0.1", resolve); });
    var port = server.address().port;
    try {
      // httpClient is HTTPS-only and SSRF-guarded by default; opt into cleartext
      // and loopback for the in-process test server.
      var resp = await b.httpClient.request({
        method: "GET",
        url: "http://127.0.0.1:" + port + "/",
        timeoutMs: 5000,
        allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL,
        allowInternal: true,
      });
      var status = resp.status != null ? resp.status : resp.statusCode;
      assert.strictEqual(status, 200);
      assert.ok(String(resp.body != null ? resp.body : resp.text).indexOf("primitive-ok") !== -1);
    } finally {
      server.close();
    }
  });

  it("b.vault.getDerivedHashMacKey returns a stable 32-byte derived key", function () {
    var k1 = b.vault.getDerivedHashMacKey();
    var k2 = b.vault.getDerivedHashMacKey();
    assert.ok(Buffer.isBuffer(k1));
    assert.ok(k1.length >= 32, "MAC key is at least 256-bit");
    assert.ok(k1.equals(k2), "derivation is stable across calls");
  });

  it("b.cryptoField.computeNamespacedHash is deterministic and namespace-separated", function () {
    var a = b.cryptoField.computeNamespacedHash("email", "a@b.com", { mode: "hmac-shake256" });
    var aAgain = b.cryptoField.computeNamespacedHash("email", "a@b.com", { mode: "hmac-shake256" });
    var diffNs = b.cryptoField.computeNamespacedHash("slug", "a@b.com", { mode: "hmac-shake256" });
    var diffVal = b.cryptoField.computeNamespacedHash("email", "c@d.com", { mode: "hmac-shake256" });
    assert.strictEqual(a, aAgain, "same namespace + value → same blind index");
    assert.notStrictEqual(a, diffNs, "different namespace → different blind index");
    assert.notStrictEqual(a, diffVal, "different value → different blind index");
  });
});
