var scratch = require("../helpers/isolate-db"); // must precede every HermitStash require
/**
 * The burn-after-read store in lib/storage.js.
 *
 * A burn file is pushed to the vendored @blamejs/stash store with a read budget.
 * One credit is spent per completed download, after the last byte has been
 * written to the response. A download the client abandons part-way, and one
 * whose ciphertext fails authentication, leave the credit in place. A second
 * reader during a download is refused with ECLAIMED. A claim left by a crashed
 * process is restored once the claim timeout has passed.
 */
var fs = require("node:fs");
var path = require("node:path");
var cp = require("node:child_process");
var { PassThrough, Writable } = require("node:stream");
process.env.HERMITSTASH_DATA_DIR = scratch.dir;
process.env.UPLOAD_DIR = path.join(scratch.dir, "uploads");
fs.mkdirSync(process.env.UPLOAD_DIR, { recursive: true });

var { describe, it, after } = require("node:test");
var assert = require("node:assert");
var b = require("../../lib/vendor/blamejs");
var C = require("../../lib/constants");
var storage = require("../../lib/storage");
var stashShim = require("../../lib/stash-shim");

var FUTURE = function () { return new Date(Date.now() + C.TIME.days(1)).toISOString(); };

after(function () { return storage.closeEphemeral(); });

// A Writable standing in for the HTTP response. It records what it received,
// and `stallAfter` makes it stop acknowledging writes after that many bytes,
// as a slow client does.
function sinkOf(opts) {
  opts = opts || {};
  var parts = [];
  var total = 0;
  var stalled = [];
  var w = new Writable({
    highWaterMark: opts.highWaterMark || C.BYTES.kib(16),
    write: function (chunk, _enc, cb) {
      parts.push(chunk);
      total += chunk.length;
      if (opts.stallAfter !== undefined && total >= opts.stallAfter) { stalled.push(cb); return; }
      cb();
    },
  });
  w.body = function () { return Buffer.concat(parts); };
  w.received = function () { return total; };
  w.stalled = function () { return stalled.length; };
  w.release = function () { var s = stalled.splice(0); s.forEach(function (cb) { cb(); }); };
  return w;
}

function consume(storagePath, key, sink) {
  return storage.consumeEphemeral(storagePath, key, { sink: sink, onStart: function () {} });
}

var tick = require("node:timers/promises").setTimeout;

// Poll a condition (sync or async) until it holds, failing after a deadline.
async function waitFor(cond, label) {
  var deadline = Date.now() + C.TIME.seconds(10);
  for (;;) {
    var ok = false;
    try { ok = await cond(); } catch (_e) { ok = false; }
    if (ok) return;
    if (Date.now() > deadline) throw new Error("timed out waiting for: " + label);
    await tick(5);
  }
}

function creditsAre(storagePath, n) {
  return async function () { return (await storage.peekEphemeral(storagePath)) === n; };
}

describe("burn store round trip and budget", function () {
  it("streams the plaintext back and spends one credit per completed read (N=3)", async function () {
    var data = b.crypto.generateBytes(C.BYTES.kib(200) + 17);
    var saved = await storage.saveEphemeral(data, { reads: 3, expiresAt: FUTURE() });
    assert.ok(storage.isStashPath(saved.path), "the storage path is a stash: path");
    assert.strictEqual(await storage.peekEphemeral(saved.path), 3);

    var s1 = sinkOf();
    var r1 = await consume(saved.path, saved.encryptionKey, s1);
    assert.ok(s1.body().equals(data), "the first read returns the exact plaintext");
    assert.strictEqual(r1.readsLeft, 2);

    var r2 = await consume(saved.path, saved.encryptionKey, sinkOf());
    assert.strictEqual(r2.readsLeft, 1);
    var r3 = await consume(saved.path, saved.encryptionKey, sinkOf());
    assert.strictEqual(r3.readsLeft, 0);
    assert.strictEqual(await storage.peekEphemeral(saved.path), null, "the last credit destroys the entry");

    await assert.rejects(consume(saved.path, saved.encryptionKey, sinkOf()), function (e) { return e.code === "ENOREF"; });
  });

  it("burns after a single read (N=1), including an empty file", async function () {
    var saved = await storage.saveEphemeral(Buffer.alloc(0), { reads: 1, expiresAt: FUTURE() });
    var s = sinkOf();
    var r = await consume(saved.path, saved.encryptionKey, s);
    assert.strictEqual(s.body().length, 0);
    assert.strictEqual(r.readsLeft, 0);
    assert.strictEqual(await storage.peekEphemeral(saved.path), null);
  });

  it("refuses a budget outside 1..ceiling and a missing or past expiry", async function () {
    await assert.rejects(storage.saveEphemeral(Buffer.from("x"), { reads: 0, expiresAt: FUTURE() }));
    await assert.rejects(storage.saveEphemeral(Buffer.from("x"), { reads: C.UPLOAD.MAX_BURN_READS_CEILING + 1, expiresAt: FUTURE() }));
    await assert.rejects(storage.saveEphemeral(Buffer.from("x"), { reads: 1.5, expiresAt: FUTURE() }));
    await assert.rejects(storage.saveEphemeral(Buffer.from("x"), { reads: 1, expiresAt: null }));
    await assert.rejects(storage.saveEphemeral(Buffer.from("x"), { reads: 1, expiresAt: "2020-01-01T00:00:00.000Z" }));
  });

  it("sets the stash TTL to the expiry", async function () {
    var expiresAt = new Date(Date.now() + C.TIME.hours(3)).toISOString();
    var saved = await storage.saveEphemeral(Buffer.from("ttl"), { reads: 1, expiresAt: expiresAt });
    var st = new stashShim.Stash({ backend: new stashShim.DiskBackend({ root: C.PATHS.STASH_DIR }), digest: "sha3-512" });
    var entry = await st.show(saved.path.slice("stash:".length));
    await st.close();
    assert.ok(Math.abs(entry.expiresAt - Date.parse(expiresAt)) < C.TIME.seconds(5), "expiresAt matches within clock skew");
  });

  it("drop destroys the entry before its credits run out", async function () {
    var saved = await storage.saveEphemeral(Buffer.from("drop"), { reads: 5, expiresAt: FUTURE() });
    await storage.deleteFile(saved.path);
    assert.strictEqual(await storage.peekEphemeral(saved.path), null);
  });

  it("keeps stash files at owner-only modes", function () {
    if (process.platform === "win32") return; // POSIX modes only
    var mode = fs.statSync(C.PATHS.STASH_DIR).mode & 0o777;
    assert.strictEqual(mode & 0o077, 0, "the stash root is not group/world accessible");
  });
});

describe("the credit is spent only after the response finishes", function () {
  it("does not spend while the last bytes wait in a stalled response", async function () {
    var data = b.crypto.generateBytes(C.BYTES.kib(300));
    var saved = await storage.saveEphemeral(data, { reads: 2, expiresAt: FUTURE() });
    // The sink accepts everything but never acknowledges its final writes, so
    // the response never finishes, like a client that stopped reading.
    var sink = sinkOf({ stallAfter: data.length - C.BYTES.kib(1) });
    var p = consume(saved.path, saved.encryptionKey, sink);
    p.catch(function () {});
    await waitFor(function () { return sink.stalled() > 0; }, "the sink to stall");
    assert.strictEqual(await storage.peekEphemeral(saved.path), 2, "no credit spent while the response is unfinished");
    sink.release();
    var r = await p;
    assert.strictEqual(r.readsLeft, 1, "the credit is spent once the response finished");
  });

  it("an aborted download leaves the credit intact and the file readable", async function () {
    var data = b.crypto.generateBytes(C.BYTES.kib(400));
    var saved = await storage.saveEphemeral(data, { reads: 1, expiresAt: FUTURE() });
    var sink = sinkOf({ stallAfter: C.BYTES.kib(100) });
    var p = consume(saved.path, saved.encryptionKey, sink);
    await waitFor(function () { return sink.stalled() > 0; }, "the sink to stall");
    sink.destroy(); // the client disconnects mid-stream
    await assert.rejects(p, function (e) { return e.code === "EBURNABORT"; });
    await waitFor(creditsAre(saved.path, 1), "the claim to be restored");
    assert.strictEqual(await storage.peekEphemeral(saved.path), 1, "the credit was restored");
    var s2 = sinkOf();
    var r = await consume(saved.path, saved.encryptionKey, s2);
    assert.ok(s2.body().equals(data), "a retry downloads the whole file");
    assert.strictEqual(r.readsLeft, 0);
  });

  it("a client that disconnects after the last chunk but before finish keeps the credit", async function () {
    var data = b.crypto.generateBytes(C.BYTES.kib(70));
    var saved = await storage.saveEphemeral(data, { reads: 1, expiresAt: FUTURE() });
    var sink = sinkOf({ stallAfter: data.length });
    var p = consume(saved.path, saved.encryptionKey, sink);
    await waitFor(function () { return sink.received() === data.length && sink.stalled() > 0; }, "every byte to be written");
    sink.destroy();
    await assert.rejects(p, function (e) { return e.code === "EBURNABORT"; });
    await waitFor(creditsAre(saved.path, 1), "the claim to be restored");
    assert.strictEqual(await storage.peekEphemeral(saved.path), 1);
  });
});

describe("concurrency", function () {
  it("serializes concurrent readers: one streams, the other gets ECLAIMED", async function () {
    var data = b.crypto.generateBytes(C.BYTES.kib(200));
    var saved = await storage.saveEphemeral(data, { reads: 1, expiresAt: FUTURE() });
    var slow = sinkOf({ stallAfter: C.BYTES.kib(64) });
    var first = consume(saved.path, saved.encryptionKey, slow);
    await waitFor(function () { return slow.stalled() > 0; }, "the first reader to stall");
    await assert.rejects(consume(saved.path, saved.encryptionKey, sinkOf()), function (e) { return e.code === "ECLAIMED"; });
    slow.release();
    // Release every later stalled write as it arrives.
    var timer = setInterval(function () { slow.release(); }, 5);
    var r = await first;
    clearInterval(timer);
    assert.strictEqual(r.readsLeft, 0);
  });

  it("many simultaneous readers on the last credit: exactly one succeeds", async function () {
    var saved = await storage.saveEphemeral(b.crypto.generateBytes(C.BYTES.kib(150)), { reads: 1, expiresAt: FUTURE() });
    var results = await Promise.allSettled([0, 1, 2, 3, 4].map(function () { return consume(saved.path, saved.encryptionKey, sinkOf()); }));
    var ok = results.filter(function (r) { return r.status === "fulfilled"; });
    var refused = results.filter(function (r) { return r.status === "rejected"; });
    assert.strictEqual(ok.length, 1, "exactly one reader gets the file");
    refused.forEach(function (r) { assert.ok(r.reason.code === "ECLAIMED" || r.reason.code === "ENOREF", "losers are refused, not served: " + r.reason.code); });
  });
});

describe("tampering", function () {
  function blobPath(storagePath) {
    var id = storagePath.slice("stash:".length);
    var found = null;
    (function walk(dir) {
      fs.readdirSync(dir, { withFileTypes: true }).forEach(function (d) {
        var full = path.join(dir, d.name);
        if (d.isDirectory()) walk(full);
        else if (d.name.indexOf(id) !== -1 && full.indexOf(path.sep + "blobs" + path.sep) !== -1) found = full;
      });
    })(C.PATHS.STASH_DIR);
    return found;
  }

  it("a flipped ciphertext byte fails authentication and spends no credit", async function () {
    var data = b.crypto.generateBytes(C.BYTES.kib(130));
    var saved = await storage.saveEphemeral(data, { reads: 1, expiresAt: FUTURE() });
    var file = blobPath(saved.path);
    assert.ok(file, "the blob is on disk under the stash root");
    var bytes = fs.readFileSync(file);
    bytes[C.BYTES.kib(70)] ^= 0xff; // inside the second frame
    fs.writeFileSync(file, bytes);
    var sink = sinkOf();
    await assert.rejects(consume(saved.path, saved.encryptionKey, sink), function (e) { return e.code === "EBURNINTEGRITY"; });
    await waitFor(creditsAre(saved.path, 1), "the claim to be restored");
    assert.strictEqual(await storage.peekEphemeral(saved.path), 1, "no credit spent on a failed read");
  });

  it("a damaged hold region after a complete delivery destroys the entry instead of restoring the credit", async function () {
    var data = b.crypto.generateBytes(C.BYTES.kib(90));
    var saved = await storage.saveEphemeral(data, { reads: 3, expiresAt: FUTURE() });
    var file = blobPath(saved.path);
    var bytes = fs.readFileSync(file);
    bytes[bytes.length - 1] ^= 0xff; // the last byte of the hold region
    fs.writeFileSync(file, bytes);
    var sink = sinkOf();
    var r = await consume(saved.path, saved.encryptionKey, sink);
    assert.ok(sink.body().equals(data), "the recipient received the whole, authenticated file");
    assert.deepStrictEqual(r, { readsLeft: 0, damaged: true });
    await waitFor(creditsAre(saved.path, null), "the entry to be destroyed");
    await assert.rejects(consume(saved.path, saved.encryptionKey, sinkOf()), function (e) { return e.code === "ENOREF"; });
  });

  it("the wrong key fails on the first chunk and spends no credit", async function () {
    var saved = await storage.saveEphemeral(Buffer.from("secret"), { reads: 1, expiresAt: FUTURE() });
    var wrong = b.crypto.generateBytes(32).toString("base64");
    await assert.rejects(consume(saved.path, wrong, sinkOf()), function (e) { return e.code === "EBURNINTEGRITY"; });
    await waitFor(creditsAre(saved.path, 1), "the claim to be restored");
    assert.strictEqual(await storage.peekEphemeral(saved.path), 1);
  });
});

describe("storedSizeOf", function () {
  function blobSize(storagePath) {
    var id = storagePath.slice("stash:".length);
    var size = null;
    (function walk(dir) {
      fs.readdirSync(dir, { withFileTypes: true }).forEach(function (d) {
        var full = path.join(dir, d.name);
        if (d.isDirectory()) walk(full);
        else if (d.name === id && full.indexOf(path.sep + "blobs" + path.sep) !== -1) size = fs.statSync(full).size;
      });
    })(C.PATHS.STASH_DIR);
    return size;
  }

  var chunk = C.BYTES.kib(64);
  [
    ["0 bytes", 0],
    ["1 byte", 1],
    ["exactly one chunk", chunk],
    ["one chunk plus 1", chunk + 1],
    ["several chunks", 5 * chunk + 123],
  ].forEach(function (c) {
    it("matches the stored stash entry for " + c[0], async function () {
      // generateBytes(0) does not return an empty buffer, so 0 uses Buffer.alloc.
      var data = c[1] === 0 ? Buffer.alloc(0) : b.crypto.generateBytes(c[1]);
      assert.strictEqual(data.length, c[1]);
      var saved = await storage.saveEphemeral(data, { reads: 1, expiresAt: FUTURE() });
      var expected = storage.storedSizeOf(c[1], true);
      assert.strictEqual(saved.storedSize, expected, "saveEphemeral reports the predicted size");
      assert.strictEqual(blobSize(saved.path), expected, "the blob on disk has the predicted size");
      var st = new stashShim.Stash({ backend: new stashShim.DiskBackend({ root: C.PATHS.STASH_DIR }), digest: "sha3-512" });
      var entry = await st.show(saved.path.slice("stash:".length));
      await st.close();
      assert.strictEqual(entry.size, expected, "the stash entry records the predicted size");
    });
  });

  it("counts plaintext for a file outside the burn store", function () {
    assert.strictEqual(storage.storedSizeOf(12345, false), 12345);
    assert.strictEqual(storage.storedSizeOf(0, false), 0);
  });

  it("charges a file row its storedSize when set, else its size", function () {
    assert.strictEqual(storage.storedSizeOfRecord({ size: 10, storedSize: 1048700 }), 1048700);
    assert.strictEqual(storage.storedSizeOfRecord({ size: 10, storedSize: null }), 10);
    assert.strictEqual(storage.storedSizeOfRecord({ size: 10 }), 10);
  });
});

describe("other storage entry points refuse stash paths", function () {
  it("getFileStream throws instead of spending a credit", async function () {
    var saved = await storage.saveEphemeral(Buffer.from("guard"), { reads: 1, expiresAt: FUTURE() });
    await assert.rejects(storage.getFileStream(saved.path, saved.encryptionKey), /consumeEphemeral/);
    assert.strictEqual(await storage.peekEphemeral(saved.path), 1);
  });

  it("resolveLocalPath does not map a stash path into the upload directory", function () {
    var r = storage.resolveLocalPath("stash:v1_" + "A".repeat(43));
    assert.strictEqual(r.ok, false);
  });

  it("the stash root is independent of the upload directory", function () {
    assert.strictEqual(C.PATHS.STASH_DIR, path.join(scratch.dir, "burn-stash"));
    assert.ok(!C.PATHS.STASH_DIR.startsWith(storage.uploadDir + path.sep));
  });
});

describe("crash recovery", function () {
  it("a process killed mid-download leaves a claim that recovery restores with the credit intact", async function () {
    var data = b.crypto.generateBytes(C.BYTES.kib(300));
    var saved = await storage.saveEphemeral(data, { reads: 1, expiresAt: FUTURE() });
    await storage.closeEphemeral();
    // The child takes the claim, reads part of the file, and exits without
    // resolving the claim, as a crash or kill does.
    var child = cp.spawnSync(process.execPath, ["-e", [
      "var s=require(process.argv[1]);",
      "var st=new s.Stash({backend:new s.DiskBackend({root:process.argv[2]}),digest:'sha3-512'});",
      "st.apply(process.argv[3]).then(function(r){r.once('data',function(){process.exit(0)});});",
    ].join(""), path.join(__dirname, "..", "..", "lib", "stash-shim.js"), C.PATHS.STASH_DIR, saved.path.slice("stash:".length)], { encoding: "utf8", timeout: 30000 });
    assert.strictEqual(child.status, 0, child.stderr);

    // A reader in a new process with a short claim timeout runs recovery.
    var st = new stashShim.Stash({ backend: new stashShim.DiskBackend({ root: C.PATHS.STASH_DIR }), digest: "sha3-512", claimTimeout: 1 });
    var entry = null;
    await waitFor(async function () {
      entry = await st.show(saved.path.slice("stash:".length));
      return entry && entry.readsLeft === 1;
    }, "recovery to restore the orphan claim");
    await st.close();
    assert.strictEqual(entry.readsLeft, 1, "the interrupted read did not spend the credit");

    var s = sinkOf();
    var r = await consume(saved.path, saved.encryptionKey, s);
    assert.ok(s.body().equals(data));
    assert.strictEqual(r.readsLeft, 0);
  });
});

describe("PassThrough sink sanity", function () {
  it("works with a plain PassThrough", async function () {
    var saved = await storage.saveEphemeral(Buffer.from("hello"), { reads: 1, expiresAt: FUTURE() });
    var pt = new PassThrough();
    var chunks = [];
    pt.on("data", function (c) { chunks.push(c); });
    await consume(saved.path, saved.encryptionKey, pt);
    assert.strictEqual(Buffer.concat(chunks).toString(), "hello");
  });
});
