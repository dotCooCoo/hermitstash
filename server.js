/**
 * HermitStash — bootstrap wrapper.
 *
 * This tiny entry point exists so the vault can be initialized asynchronously
 * BEFORE any module that transitively calls vault.seal/unseal at require-time
 * (notably lib/db.js, which reads db.key.enc via vault.unseal when its module
 * initializer runs).
 *
 * In plaintext mode (VAULT_PASSPHRASE_MODE unset or =disabled), vault.init()
 * resolves via a synchronous file read — the await is essentially free.
 * In wrapped mode (VAULT_PASSPHRASE_MODE=required), vault.init() awaits the
 * passphrase unwrap (Argon2id is async) before allowing server-main to load.
 *
 * All real server logic lives in server-main.js. Any command-line tooling
 * that needs the server's modules should follow the same pattern: await
 * vault.init() first, then require the code that depends on it.
 */
"use strict";

// Node version guard — fail fast with a clear message on <24.19.0.
// HermitStash needs Node 24.19.0+ for OpenSSL 3.5 post-quantum bindings
// (ML-KEM-1024, SLH-DSA-SHAKE-256f, ML-DSA-87) plus the cumulative
// security patches that have shipped on the 24.x line since 24.8
// (24.17.0 was a security release; 24.19.0 bundles SQLite 3.53.3).
// Operators bypassing deploy/install.sh + Dockerfile (e.g. running
// directly under a system Node) get this error instead of cryptic
// blamejs / OpenSSL failures deep in the require chain.
(function checkNodeVersion() {
  var parts = process.versions.node.split(".").map(Number);
  var major = parts[0], minor = parts[1];
  var tooOld = major < 24 || (major === 24 && minor < 19);
  if (tooOld) {
    console.error(
      "FATAL: HermitStash requires Node.js 24.19.0 or newer (found v" + process.versions.node + ").\n" +
      "  HermitStash uses OpenSSL 3.5 post-quantum bindings (ML-KEM-1024, SLH-DSA-SHAKE-256f, ML-DSA-87)\n" +
      "  plus crypto.argon2; the 24.19.0 floor pins the latest active 24.x patches. Upgrade Node and re-run.\n" +
      "  Install: https://nodejs.org/  |  Linux/systemd: deploy/install.sh"
    );
    process.exit(1);
  }
})();

(async function boot() {
  var safeLog = require("./lib/safe-log");
  var vault;
  try {
    vault = require("./lib/vault");
  } catch (e) {
    console.error("FATAL: cannot load lib/vault: " + (e && e.message));
    if (e && e.stack) console.error(e.stack);
    process.exit(1);
  }
  try {
    await vault.init();
  } catch (e) {
    // vault.init() itself calls process.exit(1) on fatal errors and prints a
    // detailed message. A throw reaching here is an unexpected exception — and
    // because vault.init() parses and unwraps secret key material, its error
    // text or stack can embed raw key bytes (CWE-532). Log only the non-secret
    // error code and suppress the message/stack.
    console.error("FATAL: unexpected error during vault init (code: " + safeLog.code(e) + "). Error text suppressed to avoid logging key material; see the vault.init diagnostics above.");
    process.exit(1);
  }
  // Vault is now either loaded (plaintext) or unsealed (wrapped). The module
  // cache for lib/vault holds the plaintext keys, so every downstream
  // vault.seal/unseal from here on is synchronous and safe.

  // Framework-internal audit emits — silence before any framework code loads.
  //
  // blamejs's internal modules (mtls-engine-default at boot, others later)
  // emit best-effort audit events via b.audit.safeEmit. b.audit's async
  // handler tries to record these through b.db, which HermitStash does NOT
  // initialize — HS owns its own DB lifecycle (lib/db.js) with separate
  // vault sealing (lib/vault.js). The handler's flush throws db/not-
  // initialized; the handler catches + log.errors "flush dropped event: ..."
  // every boot. That's a false alert to any operator monitoring on log
  // severity.
  //
  // The events themselves are framework-internal observability (e.g. mtls
  // algorithm selection — also visible via lib/mtls-ca.js's own info log),
  // not data HS cares to chain. Routing them into HS's audit_log would need
  // a shape adapter; b.audit doesn't currently expose a custom-handler
  // primitive to do that cleanly. Patching emit/safeEmit to no-op here is
  // a transparent silencer — same end state the catch-and-drop path would
  // produce, minus the false error log. Framework code is unaffected (try-
  // wrapped at every call site).
  //
  // Fundamental fix belongs upstream: b.audit needs `useStore({ record })`
  // so operators with their own audit infrastructure can register a sink.
  // Tracked locally; file upstream PR when bandwidth allows.
  var b = require("./lib/vendor/blamejs");
  b.audit.emit = function () {};
  b.audit.safeEmit = function () {};

  // Boot-time NTP clock-drift check. Audit log entries, token expirations,
  // backup naming, and cert validity windows all depend on a sane wall clock.
  // BLAMEJS_NTP_STRICT=1 → refuse to boot on fatal drift; otherwise warn + continue.
  // NTP unreachable (container with UDP/123 egress blocked) is a soft warning.
  try {
    var ntpResult = await b.ntpCheck.bootCheck();
    if (ntpResult.severity === "fatal") {
      if (process.env.BLAMEJS_NTP_STRICT === "1") {
        console.error("FATAL: " + ntpResult.message);
        process.exit(1);
      }
      console.warn("[ntp] " + ntpResult.message + " (set BLAMEJS_NTP_STRICT=1 to fail closed)");
    } else if (ntpResult.severity === "warning") {
      console.warn("[ntp] " + ntpResult.message);
    } else {
      console.log("[ntp] " + ntpResult.message);
    }
  } catch (e) {
    // NTP module failure must not block boot — log and continue.
    console.warn("[ntp] boot check failed to run: " + (e && e.message));
  }

  // Boot-time auto-migrate (Phase 2): if the on-disk envelope is still
  // 0xE1, convert it to 0xE2 before any subsequent module calls
  // vault.unseal (which post-Phase-2 refuses 0xE1). Idempotent — the
  // module's isAlreadyMigrated() probe short-circuits when data is
  // already 0xE2. Logs progress with [envelope-migrate] lines so an
  // operator watching `docker logs` sees the conversion happen on
  // first boot after the v1.9.17 → v1.9.18 upgrade. Subsequent boots
  // are a no-op.
  try {
    var migrate = require("./lib/legacy-envelope-migrate");
    if (!migrate.isAlreadyMigrated()) {
      console.log("[envelope-migrate] detected 0xE1 sealed data — converting to 0xE2 before server start...");
      var keys;
      try {
        keys = b.safeJson.parse(vault.getKeysJson(), { maxBytes: b.constants.BYTES.mib(1) });
      } catch (_e) {
        // getKeysJson() returns JSON.stringify(keys) so this normally cannot
        // throw; guard anyway so a future change or in-memory corruption can't
        // dump raw key bytes through the catch below (CWE-532). Mirrors the
        // operator CLI twin scripts/envelope-migrate-0xE1-to-0xE2.js.
        console.error("FATAL: in-memory vault keypair did not serialize to valid JSON (parser detail suppressed to avoid logging key material).");
        process.exit(1);
      }
      var result = migrate.run({
        keys: keys,
        log:  { info: function (m) { console.log("[envelope-migrate] " + m); }, warn: console.warn, error: console.error },
      });
      console.log("[envelope-migrate] complete — " + result.filesMigrated + " sealed files + " + result.rowsMigrated + " DB rows migrated to 0xE2");
    }
  } catch (e) {
    // migrate.run() re-encrypts sealed data with the vault keys; an error can
    // carry a window of those bytes in its message/stack (CWE-532). Scrub
    // credential-shaped substrings, log only the non-secret code, and never
    // dump the raw stack.
    console.error("FATAL: envelope migration failed (code: " + safeLog.code(e) + "): " + safeLog.scrub(e && e.message || String(e)));
    console.error("Restore data/ from a pre-upgrade backup, then either re-run the upgrade or run scripts/envelope-migrate-0xE1-to-0xE2.js manually.");
    process.exit(1);
  }

  // Boot-time keyed-MAC blind-index backfill. Rewrites legacy unkeyed derived
  // indexes (emailHash, slugHash, ...) to the keyed MAC under the vault MAC key.
  // Non-fatal by design: lookups dual-read both digests, so a failure here only
  // defers the cleanup to the next boot — it never blocks startup. A completion
  // marker short-circuits subsequent boots.
  try {
    var derivedBackfill = require("./lib/derived-hash-backfill");
    if (!derivedBackfill.isComplete()) {
      var dh = derivedBackfill.run({
        log: { info: function (m) { console.log(m); }, warn: console.warn, error: console.error },
      });
      if (dh && !dh.skipped) {
        console.log("[derived-hash] blind-index backfill complete — " + dh.rewritten + " of " + dh.checked +
          " rows re-keyed" + (dh.sourceUnreadable ? " (" + dh.sourceUnreadable + " sources unreadable, indexes preserved)" : ""));
      }
    }
  } catch (e) {
    console.warn("[derived-hash] backfill deferred (non-fatal): " + (e && e.message) +
      " — dual-read keeps lookups working; will retry next boot.");
  }

  // mTLS sync-CA PQC auto-migration + grace close-out. Runs HERE in the async
  // boot — BEFORE server-main builds its TLS trust bundle — so a migrated
  // ML-DSA-87 CA (and the retained previous CA) are committed to disk before the
  // live `ca` bundle is read: new PQC client certs verify in the SAME process,
  // and existing sync certs keep working via ca.prev.crt during the grace window.
  // Non-fatal — a capability-probe / commit failure degrades to a logged warning.
  try {
    await require("./lib/mtls-migrate").runBootMigration({
      log: function (m) { console.log("  " + m); },
    });
  } catch (e) {
    console.warn("[mtls-migrate] boot migration deferred (non-fatal): " + (e && e.message));
  }

  require("./server-main");
})();
