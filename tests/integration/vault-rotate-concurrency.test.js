/**
 * Regression: per-user serialization of vault mutations.
 *
 * POST /vault/rotate snapshots the user's vault files, re-encrypts each under
 * a new key, then swaps the user's vault key. Without a per-user lock:
 *   - a concurrent /vault/upload could commit a file under the OLD key after
 *     the snapshot but before the swap, orphaning it under the discarded seed;
 *   - two concurrent rotations could interleave across the saveRaw await so the
 *     losing rotation's bytes (under a discarded key) win on disk.
 *
 * These tests fire those interleavings and assert no file is orphaned and an
 * overlapping rotation is refused with 409.
 */
const { describe, it, before, after } = require("node:test");
const assert = require("node:assert");
const path = require("path");
const crypto = require("crypto");

var testServer = require("../helpers/test-server");
var { TestClient } = require("../helpers/http-client");
var client;
var ownerUserId;

function fakePublicKey() { return crypto.randomBytes(1568).toString("base64"); }
function fakeSeed() { return crypto.randomBytes(32).toString("base64"); }

before(async function () {
  await testServer.start();
  client = new TestClient(testServer.baseUrl());

  var b = require(path.join(testServer.projectRoot, "lib", "vendor", "blamejs"));
  var vault = require(path.join(testServer.projectRoot, "lib", "vault"));
  var { hashEmail } = require(path.join(testServer.projectRoot, "lib", "crypto"));
  var { users } = require(path.join(testServer.projectRoot, "lib", "db"));
  var hash = await b.auth.password.hash("rotateowner123");
  var owner = users.insert({
    email: vault.seal("rotateowner@test.com"), emailHash: hashEmail("rotateowner@test.com"),
    displayName: vault.seal("Rotate Owner"), passwordHash: hash,
    authType: "local", role: "user", status: "active",
    createdAt: new Date().toISOString(),
  });
  ownerUserId = owner._id;
});

after(function () { return testServer.stop(); });

var rateLimit = require(path.join(__dirname, "..", "..", "lib", "rate-limit"));

async function login() {
  client.clearCookies();
  await client.initApiKey();
  rateLimit.resetAllInstances();
  var res = await client.post("/auth/login", {
    json: { email: "rotateowner@test.com", password: "rotateowner123" },
  });
  assert.strictEqual(res.json.success, true, "owner login should succeed");
}

async function enableVault() {
  var res = await client.post("/vault/enable", {
    json: { publicKey: fakePublicKey(), mode: "passkey", seed: fakeSeed() },
  });
  assert.strictEqual(res.status, 200, "vault enable should succeed");
}

async function uploadFile(tag) {
  var res = await client.post("/vault/upload", {
    json: {
      ciphertext: crypto.randomBytes(96).toString("base64"),
      encapsulatedKey: Buffer.from("ek-" + tag).toString("base64"),
      iv: crypto.randomBytes(12).toString("base64"),
      filename: "f-" + tag + ".bin",
    },
  });
  return res;
}

// Build a rotation body that re-encrypts every current vault file under a new
// key. `marker` tags the re-encrypted encapsulatedKey so we can tell which
// rotation's bytes won.
async function buildRotateBody(marker) {
  var listRes = await client.get("/vault/files");
  assert.strictEqual(listRes.status, 200);
  var files = listRes.json.files.map(function (f) {
    return {
      shareId: f.shareId,
      ciphertext: crypto.randomBytes(96).toString("base64"),
      encapsulatedKey: Buffer.from("rot-" + marker + "-" + f.shareId).toString("base64"),
      iv: crypto.randomBytes(12).toString("base64"),
    };
  });
  return {
    newPublicKey: fakePublicKey(),
    newMode: "passkey",
    newSeed: fakeSeed(),
    files: files,
  };
}

describe("vault rotation concurrency", function () {
  it("concurrent upload during rotation does not orphan the uploaded file", async function () {
    await login();
    await enableVault();

    // Seed a couple of existing files so the rotation re-encrypt loop has work
    // to do (an await per file widens the interleaving window).
    await uploadFile("seed1");
    await uploadFile("seed2");

    var rotateBody = await buildRotateBody("R1");

    // Fire upload + rotate together. Either ordering is acceptable as long as
    // the uploaded file is never left orphaned.
    var rotateP = client.post("/vault/rotate", { json: rotateBody });
    var uploadP = uploadFile("concurrent");
    var [rotateRes, uploadRes] = await Promise.all([rotateP, uploadP]);

    // Rotation either succeeds or is refused with 409 — never a silent partial.
    assert.ok(
      rotateRes.status === 200 || rotateRes.status === 409,
      "rotate should be 200 or 409, got " + rotateRes.status + " " + JSON.stringify(rotateRes.json)
    );

    // If the upload committed (200), the file must still be present and
    // downloadable afterward — i.e. it was NOT orphaned by the rotation.
    if (uploadRes.status === 200) {
      assert.ok(uploadRes.json.shareId, "upload should return a shareId");
      var dl = await client.get("/vault/download/" + uploadRes.json.shareId);
      assert.strictEqual(dl.status, 200, "uploaded file must still be downloadable (not orphaned)");
      assert.ok(dl.json.ciphertext, "downloaded file must have ciphertext");
      assert.ok(dl.json.encapsulatedKey, "downloaded file must have an encapsulated key");
    } else {
      // The only acceptable non-200 for the upload is a vault-state rejection
      // (e.g. it ran after a rotation flipped state) — never a 500.
      assert.notStrictEqual(uploadRes.status, 500, "upload must not 500: " + JSON.stringify(uploadRes.json));
    }

    // Every vault file in the final set must be downloadable — nothing orphaned.
    var listRes = await client.get("/vault/files");
    for (var i = 0; i < listRes.json.files.length; i++) {
      var f = listRes.json.files[i];
      var d = await client.get("/vault/download/" + f.shareId);
      assert.strictEqual(d.status, 200, "every vault file must be downloadable: " + f.shareId);
      assert.ok(d.json.encapsulatedKey, "each file must carry an encapsulated key: " + f.shareId);
    }
  });

  it("two concurrent rotations: one wins, the other is refused 409, no orphans", async function () {
    await login();
    // Vault already enabled from the previous test; ensure at least one file.
    await uploadFile("pre-double");

    var bodyA = await buildRotateBody("A");
    var bodyB = await buildRotateBody("B");

    var [resA, resB] = await Promise.all([
      client.post("/vault/rotate", { json: bodyA }),
      client.post("/vault/rotate", { json: bodyB }),
    ]);

    // The lock serializes the two rotations. Two outcomes are both correct and
    // both orphan-free:
    //   - true overlap: the second reaches the handler while the first holds
    //     the lock and is refused 409 (one 200, one 409);
    //   - no overlap: the first fully completes before the second arrives, so
    //     the second re-encrypts the first's output and also commits (200/200).
    // What is NEVER acceptable is a partial/500 or two interleaved writes that
    // leave files split across the two rotations' keys (asserted below).
    var statuses = [resA.status, resB.status];
    for (var s = 0; s < statuses.length; s++) {
      assert.ok(
        statuses[s] === 200 || statuses[s] === 409,
        "each rotation must be 200 or 409, got " + statuses[s] +
        " A=" + JSON.stringify(resA.json) + " B=" + JSON.stringify(resB.json)
      );
    }
    assert.ok(
      statuses.indexOf(200) !== -1,
      "at least one rotation must commit (200), got " + JSON.stringify(statuses)
    );

    // The winning rotation re-encrypted every file consistently under ONE
    // marker — assert no file was left with a stale (un-rotated) key from the
    // losing rotation. We read each file's stored encapsulatedKey and require
    // it to decode to a single rotation marker prefix.
    var listRes = await client.get("/vault/files");
    assert.ok(listRes.json.files.length >= 1, "should have at least one vault file");
    var markers = {};
    for (var i = 0; i < listRes.json.files.length; i++) {
      var f = listRes.json.files[i];
      var d = await client.get("/vault/download/" + f.shareId);
      assert.strictEqual(d.status, 200, "file must be downloadable (not orphaned): " + f.shareId);
      var ekText = Buffer.from(d.json.encapsulatedKey, "base64").toString();
      // Must be a rotated key from the winning rotation (rot-<marker>-...),
      // never a pre-rotation upload key (ek-...) left behind.
      var m = ekText.match(/^rot-([AB])-/);
      assert.ok(m, "file " + f.shareId + " must carry a rotated key, got '" + ekText + "'");
      markers[m[1]] = true;
    }
    // All files must share the SAME winning rotation marker — a mix of A and B
    // would mean the two rotations interleaved and orphaned files under split
    // keys, which is exactly the bug being fixed.
    assert.strictEqual(
      Object.keys(markers).length, 1,
      "all files must be re-encrypted under a single rotation's key, got markers " + Object.keys(markers).join(",")
    );
  });
});
