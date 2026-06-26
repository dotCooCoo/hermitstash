/**
 * Zero-Knowledge Personal Vault routes.
 *
 * Files in the vault are encrypted client-side with ML-KEM-1024 + XChaCha20-Poly1305.
 * The server stores only ciphertext — it cannot decrypt vault files.
 *
 * Two vault modes:
 *   "prf"     — keypair derived from passkey PRF seed (true zero-knowledge)
 *   "passkey" — keypair from random seed stored server-side (vault-sealed),
 *               released after passkey re-auth (works with all passkey providers)
 */
var b = require("../lib/vendor/blamejs");
var nodePath = require("node:path");
var C = require("../lib/constants");
var logger = require("../app/shared/logger");
var usersRepo = require("../app/data/repositories/users.repo");
var { canEditOwned } = require("../app/shared/authz");
var filesRepo = require("../app/data/repositories/files.repo");
var credentialsRepo = require("../app/data/repositories/credentials.repo");
var { sanitizeFilename, sanitizeRename } = require("../app/shared/sanitize-filename");
var config = require("../lib/config");
var storage = require("../lib/storage");
var audit = require("../lib/audit");
var requireAuth = require("../middleware/require-auth");
var { send, host } = require("../middleware/send");
var rateLimit = require("../lib/rate-limit");
var vaultLock = require("../lib/vault-mutation-lock");
var { AppError, ValidationError, AuthenticationError, NotFoundError, ConflictError } = require("../app/shared/errors");

module.exports = function (app) {

  // Enable vault — stores the user's ML-KEM-1024 public key
  // Supports two modes:
  //   "prf"     — keypair derived from passkey PRF (zero-knowledge, server never sees seed)
  //   "passkey" — keypair from random seed, seed stored server-side vault-sealed,
  //               released after passkey re-authentication (works with all passkey providers)
  app.post("/vault/enable", async (req, res) => {
    if (!requireAuth(req, res)) return;
    try {
      var body = (await b.parsers.json(req)) || {};
      var publicKey = body.publicKey; // base64-encoded ML-KEM public key
      var mode = body.mode === "prf" ? "prf" : "passkey";
      if (!publicKey || publicKey.length < 100) {
        throw new ValidationError("Invalid public key.");
      }
      // Validate key size: ML-KEM-1024 = 1568 bytes only
      var decoded = Buffer.from(publicKey, "base64");
      if (decoded.length !== 1568) {
        throw new ValidationError("Invalid ML-KEM public key size. Only ML-KEM-1024 (1568 bytes) accepted.");
      }

      var update = { vaultEnabled: "true", vaultPublicKey: publicKey, vaultMode: mode };

      if (mode === "passkey") {
        // Passkey-gated mode: client sends the seed for server-side storage
        var seed = body.seed;
        if (!seed || seed.length < 20) {
          throw new ValidationError("Vault seed required for passkey mode.");
        }
        // Validate seed size (32 bytes → 44 base64 chars)
        var seedBytes = Buffer.from(seed, "base64");
        if (seedBytes.length !== 32 && seedBytes.length !== 64) {
          throw new ValidationError("Invalid seed size.");
        }
        update.vaultSeed = seed; // auto-sealed by field-crypto on write
      } else {
        update.vaultSeed = null; // PRF mode: no server-stored seed
      }

      usersRepo.update(req.user._id, { $set: update });
      audit.log(audit.ACTIONS.ADMIN_SETTINGS_CHANGED, { targetId: req.user._id, details: "Vault enabled, mode: " + mode, req: req });
      res.json({ success: true, mode: mode });
    } catch (e) {
      if (e.isAppError) throw e;
      logger.error("Vault enable error", { error: e.message || String(e) });
      throw new AppError("Failed to enable vault.", 500);
    }
  });

  // Disable vault (doesn't delete vault files, just disables new vault uploads)
  app.post("/vault/disable", async (req, res) => {
    if (!requireAuth(req, res)) return;
    var vaultFileCount = filesRepo.count({ uploadedBy: req.user._id, vaultEncrypted: "true", status: "complete" });
    usersRepo.update(req.user._id, { $set: { vaultEnabled: "false", vaultPublicKey: null, vaultMode: null, vaultSeed: null, vaultStealth: null } });
    audit.log(audit.ACTIONS.ADMIN_SETTINGS_CHANGED, { targetId: req.user._id, details: "Vault disabled, encrypted files remaining: " + vaultFileCount, req: req });
    res.json({ success: true, vaultFileCount: vaultFileCount });
  });

  // Force-reset vault — wipes vault state AND deletes all vault files
  // Use when vault is in a broken state (failed rotation, lost passkey, etc.)
  app.post("/vault/force-reset", async (req, res) => {
    if (!requireAuth(req, res)) return;
    try {
      var body = (await b.parsers.json(req)) || {};
      if (body.confirm !== "RESET") throw new ValidationError("Type RESET to confirm.");

      // Delete all vault files from storage and DB
      var vaultFiles = filesRepo.findAll({ uploadedBy: req.user._id, vaultEncrypted: "true" });
      var deleted = 0;
      for (var i = 0; i < vaultFiles.length; i++) {
        try {
          await storage.deleteFile(vaultFiles[i].storagePath);
        } catch (_e) { /* cleanup — storage file may already be gone */ }
        filesRepo.remove(vaultFiles[i]._id);
        deleted++;
      }

      // Clear all vault state on user
      usersRepo.update(req.user._id, { $set: { vaultEnabled: "false", vaultPublicKey: null, vaultMode: null, vaultSeed: null, vaultStealth: null } });
      audit.log(audit.ACTIONS.ADMIN_SETTINGS_CHANGED, { targetId: req.user._id, details: "Vault force-reset, " + deleted + " encrypted files deleted", req: req });
      res.json({ success: true, filesDeleted: deleted });
    } catch (e) {
      if (e.isAppError) throw e;
      logger.error("Vault force-reset error", { error: e.message });
      throw new AppError("Force reset failed.", 500);
    }
  });

  // Toggle stealth mode — requires passkey re-authentication
  // Stealth mode suppresses audit log entries for vault operations
  app.post("/vault/stealth", async (req, res) => {
    if (!requireAuth(req, res)) return;
    try {
      var body = (await b.parsers.json(req)) || {};
      var enable = body.enable === true;
      var user = usersRepo.findById(req.user._id);
      if (user.vaultEnabled !== "true") throw new ValidationError("Vault must be enabled first.");

      usersRepo.update(req.user._id, { $set: { vaultStealth: enable ? "true" : "false" } });
      // This toggle itself is always logged (so admin knows stealth was activated)
      audit.log(audit.ACTIONS.ADMIN_SETTINGS_CHANGED, { targetId: req.user._id, details: "Vault stealth " + (enable ? "enabled" : "disabled"), req: req });
      res.json({ success: true, stealth: enable });
    } catch (err) {
      if (err.isAppError) throw err;
      logger.error("[vault/stealth] Error", { userId: req.user && req.user._id, error: err.message });
      throw new AppError("Failed to toggle stealth.", 500);
    }
  });

  // Unlock vault — passkey-gated mode only
  // Verifies passkey authentication, then releases the vault seed for client-side decryption
  app.post("/vault/unlock", rateLimit.guard({ max: 5, windowMs: C.TIME.minutes(5), algorithm: "fixed-window" }), async (req, res) => {
    if (!requireAuth(req, res)) return;
    try {
      var user = usersRepo.findById(req.user._id);
      if (user.vaultEnabled !== "true") throw new ValidationError("Vault not enabled.");
      if ((user.vaultMode || "prf") !== "passkey") throw new ValidationError("Vault uses PRF mode — unlock client-side.");
      if (!user.vaultSeed) throw new ValidationError("No vault seed stored.");

      var body = (await b.parsers.json(req)) || {};
      if (!body.assertion) throw new ValidationError("Passkey assertion required.");

      // Verify the passkey assertion
      var expectedChallenge = req.session.vaultUnlockChallenge;
      delete req.session.vaultUnlockChallenge;
      if (!expectedChallenge) throw new ValidationError("No pending vault unlock challenge.");

      var incomingCredId = body.assertion.id;
      var allCreds = credentialsRepo.findByUser(req.user._id);
      var matchedCred = null;
      for (var i = 0; i < allCreds.length; i++) {
        var storedB64url = Buffer.from(allCreds[i].credentialId, "base64").toString("base64url");
        if (storedB64url === incomingCredId) { matchedCred = allCreds[i]; break; }
      }
      if (!matchedCred) throw new AuthenticationError("Unknown passkey.");

      var verification = await b.auth.passkey.verifyAuthentication({
        response: body.assertion,
        expectedChallenge: expectedChallenge,
        expectedOrigin: config.rpOrigin,
        expectedRPID: config.rpId,
        credential: {
          id: incomingCredId,
          publicKey: Buffer.from(matchedCred.publicKey, "base64"),
          // Pass the stored counter verbatim (no `|| 0`): the wrapper refuses
          // undefined / null explicitly, so a credential with a dropped counter
          // fails closed (vault stays locked) rather than silently coercing to 0
          // and defeating clone detection on the most sensitive unlock path.
          counter: matchedCred.counter,
          transports: typeof matchedCred.transports === "string"
            ? b.safeJson.parseOrDefault(matchedCred.transports, [])
            : (matchedCred.transports || []),
        },
        // Vault unlock is the most sensitive operation — require user
        // verification explicitly (matches simplewebauthn's prior default).
        requireUserVerification: true,
      });

      if (!verification.verified) {
        audit.log(audit.ACTIONS.PASSKEY_LOGIN_FAILED, { targetId: req.user._id, details: "Vault unlock failed", req: req });
        throw new AuthenticationError("Passkey verification failed.");
      }

      // Update credential counter
      credentialsRepo.update(matchedCred._id, { $set: { counter: verification.authenticationInfo.newCounter } });

      // Release the vault seed (already unsealed by field-crypto on read)
      audit.log(audit.ACTIONS.ADMIN_SETTINGS_CHANGED, { targetId: req.user._id, details: "Vault unlocked via passkey", req: req, vaultOp: true });
      res.json({ success: true, seed: user.vaultSeed });
    } catch (e) {
      if (e.isAppError) throw e;
      logger.error("Vault unlock error", { error: e.message || String(e), stack: e.stack ? e.stack.split("\n").slice(0, 3).join(" | ") : "" });
      throw new AppError("Vault unlock failed: " + (e.message || "unknown error"), 500);
    }
  });

  // Generate a challenge for vault unlock (passkey-gated mode)
  app.post("/vault/unlock/challenge", (req, res) => {
    if (!requireAuth(req, res)) return;
    var challenge = b.crypto.generateBytes(32).toString("base64url");
    req.session.vaultUnlockChallenge = challenge;
    res.json({ challenge: challenge });
  });

  // Get vault status and public key
  app.get("/vault/status", (req, res) => {
    if (!requireAuth(req, res)) return;
    var user = usersRepo.findById(req.user._id);
    res.json({
      enabled: user.vaultEnabled === "true",
      mode: user.vaultMode || "prf",
      stealth: user.vaultStealth === "true",
      hasPublicKey: !!user.vaultPublicKey,
      publicKey: user.vaultPublicKey || null,
    });
  });

  // Upload a vault-encrypted file
  // The file data is already encrypted client-side — server just stores the blob
  app.post("/vault/upload", async (req, res) => {
    if (!requireAuth(req, res)) return;
    try {
      var body = (await b.parsers.json(req, { maxBytes: config.maxFileSize * 2 })) || {}; // base64 overhead
      if (!body.ciphertext || !body.encapsulatedKey || !body.iv || !body.filename) {
        throw new ValidationError("Missing encrypted file data.");
      }
      // Sanitize filename — strip path components, limit length
      body.filename = nodePath.basename(String(body.filename)).slice(0, 255);
      // Strip null bytes and control characters
      body.filename = body.filename.replace(/[\x00-\x1f\x7f]/g, "");
      if (!body.filename) body.filename = "unnamed";

      // Serialize against vault rotation for this user. An upload that
      // committed a row under the OLD key after rotation snapshotted the file
      // set but before it swapped the user key would be left encrypted under
      // the discarded seed — undecryptable. Holding the per-user lock across
      // the enabled check + write + create keeps the upload outside any
      // in-flight rotation window. The enabled check runs UNDER the lock so it
      // also reflects a rotation that just disabled the prior mode.
      var fileShareId = await vaultLock.withUserLock(req.user._id, async function () {
        var user = usersRepo.findById(req.user._id);
        if (user.vaultEnabled !== "true") {
          throw new ValidationError("Vault not enabled.");
        }

        // Enforce storage quota (atomic SQL query to avoid TOCTOU race)
        if (config.storageQuotaBytes > 0) {
          var totalUsed = require("../lib/db").getTotalStorageUsed();
          var newSize = Buffer.from(body.ciphertext, "base64").length;
          if (totalUsed + newSize > config.storageQuotaBytes) {
            throw new ValidationError("Storage quota exceeded.");
          }
        }

        // Decode from base64
        var ciphertext = Buffer.from(body.ciphertext, "base64");
        var encapsulatedKey = body.encapsulatedKey; // keep as base64 string for DB
        var iv = body.iv; // keep as base64 string for DB

        // Store the encrypted blob using regular storage (no additional server encryption)
        var shareId = b.crypto.generateToken(32);
        // Extension is incorporated into the storage path; restrict to a safe
        // charset (alnum, 1–10 chars) so a filename like "a.<odd>" can't create
        // surprising on-disk names for operators browsing the upload dir.
        var ext = nodePath.extname(body.filename).toLowerCase() || "";
        if (!/^\.[a-z0-9]{1,10}$/.test(ext)) ext = "";
        var storagePath = "vault/" + req.user._id + "/" + Date.now() + "-" + shareId + ext;

        // Write raw ciphertext to storage — no server-side encryption layer
        var savedPath = await storage.saveRaw(ciphertext, storagePath);
        storagePath = savedPath;

        filesRepo.create({
          shareId: shareId,
          originalName: sanitizeFilename(body.filename),
          relativePath: sanitizeFilename(body.relativePath || body.filename, 500),
          storagePath: storagePath,
          mimeType: body.mimeType || "application/octet-stream",
          size: ciphertext.length,
          uploadedBy: req.user._id,
          uploaderEmail: req.user.email,
          downloads: 0,
          status: "complete",
          vaultEncrypted: "true",
          vaultEncapsulatedKey: encapsulatedKey,
          vaultIv: iv,
          vaultBatchId: body.batchId || null,
          createdAt: new Date().toISOString(),
        });

        audit.log(audit.ACTIONS.BUNDLE_FILE_UPLOADED, { targetId: req.user._id, details: "vault file: " + body.filename + ", size: " + ciphertext.length, req: req, vaultOp: true });
        return shareId;
      });

      res.json({ success: true, shareId: fileShareId });
    } catch (e) {
      if (e.isAppError) throw e;
      logger.error("Vault upload error", { error: e.message || String(e) });
      throw new AppError("Vault upload failed.", 500);
    }
  });

  // Standalone vault file page — self-access link for decrypt & download
  app.get("/vault/s/:shareId", (req, res) => {
    if (!requireAuth(req, res)) return;
    var doc = filesRepo.findByShareId(req.params.shareId);
    if (!doc || doc.vaultEncrypted !== "true" || !canEditOwned(doc, req.user, "uploadedBy")) {
      res.writeHead(404); return res.end("Not found");
    }
    send(res, "vault-share", {
      user: req.user,
      file: { shareId: doc.shareId, originalName: doc.originalName, size: doc.size, mimeType: doc.mimeType },
      host: host(req),
    });
  });

  // Download vault-encrypted file (returns ciphertext + encapsulated key + IV)
  app.get("/vault/download/:shareId", async (req, res) => {
    if (!requireAuth(req, res)) return;
    var doc = filesRepo.findByShareId(req.params.shareId);
    if (!doc || doc.vaultEncrypted !== "true" || !canEditOwned(doc, req.user, "uploadedBy")) {
      res.writeHead(404); return res.end("Not found");
    }

    // Admin can see metadata but NOT decrypt (no secret key)
    // Return the encrypted blob + encapsulated key for client-side decryption
    try {
      var ciphertext = await storage.getRawBuffer(doc.storagePath);

      filesRepo.update(doc._id, { $set: { downloads: (doc.downloads || 0) + 1 } });
      audit.log(audit.ACTIONS.FILE_DOWNLOADED, { targetId: doc._id, details: "vault file: " + doc.originalName, req: req, vaultOp: true });

      res.json({
        filename: doc.originalName,
        relativePath: doc.relativePath || doc.originalName,
        mimeType: doc.mimeType,
        size: doc.size,
        ciphertext: ciphertext.toString("base64"),
        encapsulatedKey: doc.vaultEncapsulatedKey,
        iv: doc.vaultIv,
      });
    } catch (e) {
      if (e.isAppError) throw e;
      logger.error("Vault download error", { error: e.message || String(e) });
      throw new AppError("Vault download failed.", 500);
    }
  });

  // List vault files for the current user
  app.get("/vault/files", (req, res) => {
    if (!requireAuth(req, res)) return;
    var vaultFiles = filesRepo.findAll({ uploadedBy: req.user._id, vaultEncrypted: "true", status: "complete" })
      .sort((a, b) => (b.createdAt || "").localeCompare(a.createdAt || ""));
    var safe = vaultFiles.map(function (f) {
      return {
        shareId: f.shareId,
        originalName: f.originalName,
        mimeType: f.mimeType,
        size: f.size,
        downloads: f.downloads,
        createdAt: f.createdAt,
        vaultBatchId: f.vaultBatchId || null,
        vaultBatchName: f.vaultBatchName || null,
      };
    });
    res.json({ files: safe });
  });

  // Rotate vault passkey — accepts re-encrypted files with new key
  // The client decrypts all files with the old key and re-encrypts with the new key,
  // then sends the re-encrypted data + new public key in one batch.
  app.post("/vault/rotate", async (req, res) => {
    if (!requireAuth(req, res)) return;
    try {
      var body = (await b.parsers.json(req, { maxBytes: config.maxFileSize * 2 })) || {}; // base64 overhead
      var user = usersRepo.findById(req.user._id);
      if (user.vaultEnabled !== "true") throw new ValidationError("Vault not enabled.");

      // Validate new public key
      var newPublicKey = body.newPublicKey;
      var newMode = body.newMode === "prf" ? "prf" : "passkey";
      if (!newPublicKey || newPublicKey.length < 100) throw new ValidationError("Invalid new public key.");
      var decoded = Buffer.from(newPublicKey, "base64");
      if (decoded.length !== 1568) throw new ValidationError("Invalid ML-KEM public key size. Only ML-KEM-1024 (1568 bytes) accepted.");

      // Validate new seed for passkey mode
      var newSeed = null;
      if (newMode === "passkey") {
        if (!body.newSeed || body.newSeed.length < 20) throw new ValidationError("New vault seed required.");
        var seedBytes = Buffer.from(body.newSeed, "base64");
        if (seedBytes.length !== 32 && seedBytes.length !== 64) throw new ValidationError("Invalid seed size.");
        newSeed = body.newSeed;
      }

      // Validate re-encrypted files
      var reencryptedFiles = body.files;
      if (!Array.isArray(reencryptedFiles)) throw new ValidationError("Re-encrypted files array required.");

      // Acquire-or-reject the per-user vault lock, held across the snapshot ->
      // re-encrypt loop -> key swap. A double-clicked rotation queued behind
      // the first would re-encrypt under a key the first already discarded and
      // its on-disk bytes would win the saveRaw race — orphaning files. The
      // acquire-or-reject is atomic (no await between the held-check and the
      // acquire), so the second rotation is refused with 409 rather than
      // running after the first, instead of silently corrupting files.
      var outcome = await vaultLock.tryWithUserLock(req.user._id, async function () {
        // Snapshot UNDER the lock — a concurrent upload cannot commit after
        // this read because it contends for the same lock.
        var vaultFiles = filesRepo.findAll({ uploadedBy: req.user._id, vaultEncrypted: "true", status: "complete" });

        // Verify we have re-encrypted data for every vault file (fail closed:
        // a single missing file aborts the rotation before the key swap, so we
        // never discard the old seed while a file is still encrypted under it).
        var reencMap = {};
        for (var i = 0; i < reencryptedFiles.length; i++) {
          reencMap[reencryptedFiles[i].shareId] = reencryptedFiles[i];
        }
        for (var j = 0; j < vaultFiles.length; j++) {
          var rec = reencMap[vaultFiles[j].shareId];
          if (!rec || !rec.ciphertext || !rec.encapsulatedKey || !rec.iv) {
            throw new ValidationError("Missing re-encrypted data for file: " + vaultFiles[j].originalName);
          }
        }

        // Update each file with re-encrypted data
        var count = 0;
        for (var k = 0; k < vaultFiles.length; k++) {
          var doc = vaultFiles[k];
          var reenc = reencMap[doc.shareId];

          // Write new ciphertext to storage
          var ciphertext = Buffer.from(reenc.ciphertext, "base64");
          await storage.saveRaw(ciphertext, doc.storagePath);

          // Update DB with new encapsulated key and IV. Do NOT take size from
          // the client — rotation re-encrypts the same plaintext, so the
          // original size is unchanged and preserving doc.size avoids a quota
          // bypass where an attacker rotates their own file with originalSize=0.
          filesRepo.update(doc._id, { $set: {
            vaultEncapsulatedKey: reenc.encapsulatedKey,
            vaultIv: reenc.iv,
          }});
          count++;
        }

        // Update user's vault public key and seed only after every file has
        // been re-encrypted under the new key.
        var vaultUpdate = { vaultPublicKey: newPublicKey, vaultMode: newMode };
        if (newSeed) vaultUpdate.vaultSeed = newSeed;
        else vaultUpdate.vaultSeed = null;
        usersRepo.update(req.user._id, { $set: vaultUpdate });

        return count;
      });

      if (!outcome.acquired) {
        throw new ConflictError("A vault mutation is already in progress. Retry shortly.");
      }
      var updated = outcome.value;

      audit.log(audit.ACTIONS.ADMIN_SETTINGS_CHANGED, { targetId: req.user._id, details: "Vault passkey rotated, mode: " + newMode + ", files re-encrypted: " + updated, req: req });
      res.json({ success: true, filesUpdated: updated });
    } catch (e) {
      if (e.isAppError) throw e;
      logger.error("Vault rotate error", { error: e.message || String(e) });
      throw new AppError("Vault rotation failed.", 500);
    }
  });

  // Delete vault file
  app.post("/vault/delete/:shareId", async (req, res) => {
    if (!requireAuth(req, res)) return;
    var doc = filesRepo.findByShareId(req.params.shareId);
    if (!doc || doc.vaultEncrypted !== "true" || !canEditOwned(doc, req.user, "uploadedBy")) {
      throw new NotFoundError("Not found.");
    }
    // Serialize against rotation — a delete that removed a file from the set
    // mid-rotation would race the re-encrypt loop's saveRaw on the same path.
    await vaultLock.withUserLock(req.user._id, async function () {
      // Delete the encrypted blob
      try {
        await storage.deleteFile(doc.storagePath);
      } catch (_e) { /* cleanup — storage file may already be gone */ }
      filesRepo.remove(doc._id);
    });
    audit.log(audit.ACTIONS.FILE_DELETED, { targetId: doc._id, details: "vault file: " + doc.originalName, req: req, vaultOp: true });
    res.json({ success: true });
  });

  // Rename vault batch
  app.post("/vault/batch/:batchId/rename", async (req, res) => {
    if (!requireAuth(req, res)) return;
    var body = (await b.parsers.json(req)) || {};
    var result = sanitizeRename(body.name, { maxLength: 200 });
    if (!result.valid) throw new ValidationError(result.error || "Invalid name.");
    var batchFiles = filesRepo.findAll({ uploadedBy: req.user._id, vaultEncrypted: "true" })
      .filter(function (f) { return f.vaultBatchId === req.params.batchId; });
    if (batchFiles.length === 0) throw new NotFoundError("Batch not found.");
    for (var i = 0; i < batchFiles.length; i++) {
      filesRepo.update(batchFiles[i]._id, { $set: { vaultBatchName: result.name } });
    }
    res.json({ success: true, name: result.name });
  });

  // Rename vault file
  app.post("/vault/file/:shareId/rename", async (req, res) => {
    if (!requireAuth(req, res)) return;
    var doc = filesRepo.findAll({ shareId: req.params.shareId, uploadedBy: req.user._id, vaultEncrypted: "true", status: "complete" })[0];
    if (!doc) throw new NotFoundError("Not found.");
    var body = (await b.parsers.json(req)) || {};
    var result = sanitizeRename(body.name, { originalName: doc.originalName });
    if (!result.valid) throw new ValidationError(result.error);
    filesRepo.update(doc._id, { $set: { originalName: result.name } });
    res.json({ success: true, name: result.name });
  });

  // Delete all vault files in a batch
  app.post("/vault/batch/delete", async (req, res) => {
    if (!requireAuth(req, res)) return;
    try {
      var body = (await b.parsers.json(req)) || {};
      if (!body.batchId) throw new ValidationError("Batch ID required.");
      // Serialize against rotation — see /vault/delete/:shareId.
      var filesDeleted = await vaultLock.withUserLock(req.user._id, async function () {
        var vaultFiles = filesRepo.findAll({ uploadedBy: req.user._id, vaultEncrypted: "true" }).filter(function (f) { return f.vaultBatchId === body.batchId; });
        if (vaultFiles.length === 0) throw new NotFoundError("No files in batch.");
        for (var i = 0; i < vaultFiles.length; i++) {
          try {
            await storage.deleteFile(vaultFiles[i].storagePath);
          } catch (_e) { /* cleanup — storage file may already be gone */ }
          filesRepo.remove(vaultFiles[i]._id);
        }
        return vaultFiles.length;
      });
      audit.log(audit.ACTIONS.FILE_DELETED, { targetId: req.user._id, details: "vault batch delete: " + body.batchId + ", files: " + filesDeleted, req: req, vaultOp: true });
      res.json({ success: true, filesDeleted: filesDeleted });
    } catch (e) {
      if (e.isAppError) throw e;
      logger.error("Vault batch delete error", { error: e.message || String(e) });
      throw new AppError("Batch delete failed.", 500);
    }
  });
};
