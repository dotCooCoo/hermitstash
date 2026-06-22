var { describe, it, after } = require("node:test");
var assert = require("node:assert");
var path = require("path");
var fs = require("fs");
var crypto = require("crypto");
var b = require("../../lib/vendor/blamejs");

// Use an isolated test database
var testId = b.crypto.generateToken(4);
var testDbPath = path.join(__dirname, "..", "..", "data", "test-storage-" + testId + ".db");
process.env.HERMITSTASH_DB_PATH = testDbPath;

// Clear require cache so all lib modules load fresh against the test DB
Object.keys(require.cache).forEach(function (k) {
  if (k.includes("hermitstash") && !k.includes("node_modules") && !k.includes("test")) delete require.cache[k];
});

var storage = require("../../lib/storage");

// Track created test directories for cleanup
var testSubDir = "test-storage-" + testId;

after(function () {
  // Remove test upload subdirectory
  var testDir = path.join(storage.uploadDir, testSubDir);
  try { fs.rmSync(testDir, { recursive: true, force: true }); } catch {}
  // Clean up DB files
  try { fs.unlinkSync(testDbPath); } catch {}
  try { fs.unlinkSync(testDbPath + "-shm"); } catch {}
  try { fs.unlinkSync(testDbPath + "-wal"); } catch {}
  try { fs.unlinkSync(testDbPath + ".enc"); } catch {}
});

describe("storage", function () {

  // ---- Module exports ----

  describe("module exports", function () {
    it("exports saveFile function", function () {
      assert.strictEqual(typeof storage.saveFile, "function");
    });

    it("exports getFileStream function", function () {
      assert.strictEqual(typeof storage.getFileStream, "function");
    });

    it("exports deleteFile function", function () {
      assert.strictEqual(typeof storage.deleteFile, "function");
    });

    it("exports getPresignedUrl function", function () {
      assert.strictEqual(typeof storage.getPresignedUrl, "function");
    });

    it("exports uploadDir string", function () {
      assert.strictEqual(typeof storage.uploadDir, "string");
      assert.ok(storage.uploadDir.length > 0, "uploadDir should not be empty");
    });
  });

  // ---- encryptBuffer / decryptBuffer via saveFile+getFileStream roundtrip ----

  describe("file encryption roundtrip", function () {
    it("saveFile encrypts and returns path + encryptionKey", async function () {
      var buffer = Buffer.from("Hello, encrypted world!");
      var storagePath = testSubDir + "/encrypt-test-1.bin";

      var result = await storage.saveFile(buffer, storagePath);
      assert.ok(result.path, "should return file path");
      assert.ok(result.encryptionKey, "should return encryptionKey");
      // saveFile returns the plaintext base64 key; the DB layer (field-crypto)
      // AAD-seals it at rest when the file row is written.
      assert.ok(!String(result.encryptionKey).startsWith("vault:"),
        "encryptionKey should be plaintext (not vault-sealed) — sealing is the DB layer's job");
      assert.strictEqual(Buffer.from(result.encryptionKey, "base64").length, 32,
        "encryptionKey should decode to a 32-byte key");

      // The file on disk should be encrypted (not plaintext)
      var onDisk = fs.readFileSync(path.join(storage.uploadDir, result.path));
      assert.notStrictEqual(onDisk.toString(), "Hello, encrypted world!", "on-disk data should be encrypted");
      assert.ok(onDisk.length > buffer.length, "encrypted data should be larger (has IV + tag)");
    });

    it("getFileStream decrypts file back to original content", async function () {
      var original = "Decryption roundtrip test data: " + b.crypto.generateToken(32);
      var buffer = Buffer.from(original);
      var storagePath = testSubDir + "/decrypt-test-1.bin";

      var result = await storage.saveFile(buffer, storagePath);
      var stream = await storage.getFileStream(storagePath, result.encryptionKey);

      // Read the stream
      var chunks = [];
      for await (var chunk of stream) {
        chunks.push(chunk);
      }
      var decrypted = Buffer.concat(chunks).toString();
      assert.strictEqual(decrypted, original, "decrypted content should match original");
    });

    it("roundtrips binary data correctly", async function () {
      var binaryData = crypto.randomBytes(1024);
      var storagePath = testSubDir + "/binary-test.bin";

      var result = await storage.saveFile(binaryData, storagePath);
      var stream = await storage.getFileStream(storagePath, result.encryptionKey);

      var chunks = [];
      for await (var chunk of stream) {
        chunks.push(chunk);
      }
      var decrypted = Buffer.concat(chunks);
      assert.ok(binaryData.equals(decrypted), "binary roundtrip should preserve exact bytes");
    });

    it("roundtrips empty buffer", async function () {
      var emptyBuffer = Buffer.alloc(0);
      var storagePath = testSubDir + "/empty-test.bin";

      var result = await storage.saveFile(emptyBuffer, storagePath);
      var stream = await storage.getFileStream(storagePath, result.encryptionKey);

      var chunks = [];
      for await (var chunk of stream) {
        chunks.push(chunk);
      }
      var decrypted = Buffer.concat(chunks);
      assert.strictEqual(decrypted.length, 0, "empty buffer roundtrip should return empty");
    });

    it("roundtrips large buffer (100KB)", async function () {
      var largeBuffer = crypto.randomBytes(102400);
      var storagePath = testSubDir + "/large-test.bin";

      var result = await storage.saveFile(largeBuffer, storagePath);
      var stream = await storage.getFileStream(storagePath, result.encryptionKey);

      var chunks = [];
      for await (var chunk of stream) {
        chunks.push(chunk);
      }
      var decrypted = Buffer.concat(chunks);
      assert.ok(largeBuffer.equals(decrypted), "large buffer roundtrip should match");
    });

    it("each saveFile produces unique encryptionKey", async function () {
      var buffer = Buffer.from("same content");
      var path1 = testSubDir + "/unique-key-1.bin";
      var path2 = testSubDir + "/unique-key-2.bin";

      var result1 = await storage.saveFile(buffer, path1);
      var result2 = await storage.saveFile(buffer, path2);

      assert.notStrictEqual(result1.encryptionKey, result2.encryptionKey,
        "each file should have a unique encryption key");
    });

    it("encrypted file has IV prefix (12 bytes) + tag (16 bytes) + ciphertext", async function () {
      var buffer = Buffer.from("prefix test");
      var storagePath = testSubDir + "/prefix-test.bin";

      var result = await storage.saveFile(buffer, storagePath);
      var onDisk = fs.readFileSync(path.join(storage.uploadDir, result.path));

      // Minimum size: 12 (IV) + 16 (tag) + encrypted data length
      assert.ok(onDisk.length >= 28, "encrypted file should be at least 28 bytes (IV + tag)");
    });

    it("tampered encrypted data fails decryption", async function () {
      var buffer = Buffer.from("tamper test data");
      var storagePath = testSubDir + "/tamper-test.bin";

      var result = await storage.saveFile(buffer, storagePath);

      // Read and tamper with the file
      var onDisk = fs.readFileSync(path.join(storage.uploadDir, result.path));
      // Flip some bytes in the ciphertext area (after IV and tag)
      if (onDisk.length > 30) {
        onDisk[29] = onDisk[29] ^ 0xFF;
        onDisk[30] = onDisk[30] ^ 0xFF;
      }
      fs.writeFileSync(path.join(storage.uploadDir, result.path), onDisk);

      // Decryption should fail due to GCM authentication
      try {
        var stream = await storage.getFileStream(storagePath, result.encryptionKey);
        var chunks = [];
        for await (var chunk of stream) {
          chunks.push(chunk);
        }
        assert.fail("should have thrown on tampered data");
      } catch (e) {
        assert.ok(e.message !== "should have thrown on tampered data",
          "tampered data should cause decryption error");
      }
    });

    it("wrong encryptionKey fails decryption", async function () {
      var buffer = Buffer.from("wrong key test");
      var storagePath = testSubDir + "/wrongkey-test.bin";

      var result = await storage.saveFile(buffer, storagePath);

      // A different plaintext base64 key (saveFile now returns plaintext keys)
      var wrongKey = crypto.randomBytes(32).toString("base64");

      try {
        var stream = await storage.getFileStream(storagePath, wrongKey);
        var chunks = [];
        for await (var chunk of stream) {
          chunks.push(chunk);
        }
        assert.fail("should have thrown with wrong key");
      } catch (e) {
        assert.ok(e.message !== "should have thrown with wrong key",
          "wrong key should cause decryption error");
      }
    });
  });

  describe("symlink-refusing reads + path-escape (A3-3 / A3-6 / C2-02)", function () {
    function trySymlink(target, linkPath) {
      try { fs.symlinkSync(target, linkPath); return true; } catch (_e) { return false; }
    }

    it("getRawBuffer rejects a path that escapes the upload dir", async function () {
      await assert.rejects(function () { return storage.getRawBuffer("../../etc/passwd"); });
    });

    it("getRawBuffer / getFileStream refuse a symlinked blob (no symlink-follow on the download path)", async function () {
      var victim = path.join(storage.uploadDir, testSubDir, "victim-secret.txt");
      fs.mkdirSync(path.dirname(victim), { recursive: true });
      fs.writeFileSync(victim, "TOP-SECRET-VICTIM");
      var storagePath = testSubDir + "/symlink-blob.bin";
      var result = await storage.saveFile(Buffer.from("real blob"), storagePath);
      var onDisk = path.join(storage.uploadDir, result.path);
      fs.unlinkSync(onDisk);
      if (!trySymlink(victim, onDisk)) return; // no symlink privilege — skip
      await assert.rejects(function () { return storage.getRawBuffer(storagePath); },
        "getRawBuffer must refuse to read through a symlinked blob");
      await assert.rejects(async function () {
        var s = await storage.getFileStream(storagePath, null);
        for await (var _chunk of s) { /* drain */ }
      }, "getFileStream must refuse a symlinked blob");
    });
  });

  // ---- saveFile disk operations ----

  describe("saveFile", function () {
    it("creates the file on disk", async function () {
      var buffer = Buffer.from("disk creation test");
      var storagePath = testSubDir + "/disk-create.bin";

      var result = await storage.saveFile(buffer, storagePath);
      assert.ok(fs.existsSync(path.join(storage.uploadDir, result.path)), "file should exist on disk");
    });

    it("creates nested directories if needed", async function () {
      var buffer = Buffer.from("nested dir test");
      var storagePath = testSubDir + "/nested/deep/path/file.bin";

      var result = await storage.saveFile(buffer, storagePath);
      assert.ok(fs.existsSync(path.join(storage.uploadDir, result.path)), "file in nested dir should exist");
    });

    it("overwrites existing file at same path", async function () {
      var storagePath = testSubDir + "/overwrite.bin";

      await storage.saveFile(Buffer.from("first"), storagePath);
      var result = await storage.saveFile(Buffer.from("second"), storagePath);

      // The file should exist (overwritten)
      assert.ok(fs.existsSync(path.join(storage.uploadDir, result.path)));
      // Content should be the second version (encrypted)
      var stream = await storage.getFileStream(storagePath, result.encryptionKey);
      var chunks = [];
      for await (var chunk of stream) {
        chunks.push(chunk);
      }
      assert.strictEqual(Buffer.concat(chunks).toString(), "second");
    });
  });

  // ---- deleteFile ----

  describe("deleteFile", function () {
    it("removes file from disk", async function () {
      var buffer = Buffer.from("delete me");
      var storagePath = testSubDir + "/to-delete.bin";

      var result = await storage.saveFile(buffer, storagePath);
      assert.ok(fs.existsSync(path.join(storage.uploadDir, result.path)), "file should exist before delete");

      await storage.deleteFile(storagePath);
      assert.ok(!fs.existsSync(path.join(storage.uploadDir, result.path)), "file should not exist after delete");
    });

    it("does not throw when file does not exist", async function () {
      await assert.doesNotReject(async function () {
        await storage.deleteFile(testSubDir + "/nonexistent-file.bin");
      }, "deleteFile should not throw for missing file");
    });

    it("only removes the specified file", async function () {
      var buffer = Buffer.from("data");
      var path1 = testSubDir + "/keep.bin";
      var path2 = testSubDir + "/remove.bin";

      var result1 = await storage.saveFile(buffer, path1);
      var result2 = await storage.saveFile(buffer, path2);

      await storage.deleteFile(path2);

      assert.ok(fs.existsSync(path.join(storage.uploadDir, result1.path)), "other file should still exist");
      assert.ok(!fs.existsSync(path.join(storage.uploadDir, result2.path)), "target file should be removed");
    });
  });

  // ---- getFileStream without encryptionKey (legacy) ----

  describe("getFileStream legacy mode", function () {
    it("returns raw stream when encryptionKey is null", async function () {
      // Write a raw (unencrypted) file directly to disk
      var storagePath = testSubDir + "/legacy-raw.txt";
      var fullPath = path.join(storage.uploadDir, storagePath);
      var dir = path.dirname(fullPath);
      if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
      fs.writeFileSync(fullPath, "legacy raw content");

      var stream = await storage.getFileStream(storagePath, null);
      var chunks = [];
      for await (var chunk of stream) {
        chunks.push(chunk);
      }
      assert.strictEqual(Buffer.concat(chunks).toString(), "legacy raw content",
        "null encryptionKey should return raw content");
    });
  });

  // ---- getPresignedUrl (local backend) ----

  describe("getPresignedUrl", function () {
    it("returns null for local storage backend", function () {
      // Default config is local backend, so presigned URLs should return null
      var url = storage.getPresignedUrl("some/path.pdf", "test.pdf", "application/pdf");
      assert.strictEqual(url, null, "local backend should not generate presigned URLs");
    });
  });

  // ---- uploadDir ----

  describe("uploadDir", function () {
    it("is an absolute path", function () {
      assert.ok(path.isAbsolute(storage.uploadDir), "uploadDir should be absolute");
    });

    it("directory exists on disk", function () {
      assert.ok(fs.existsSync(storage.uploadDir), "uploadDir should exist");
    });
  });
});
