#!/usr/bin/env node
/**
 * vault-passphrase-rotate.js — rotate the passphrase that wraps
 * data/vault.key.sealed.
 *
 * Run offline (stop the server first).
 *
 * Usage (interactive, recommended for local dev):
 *   docker exec -it hermitstash node scripts/vault-passphrase-rotate.js
 *
 * Usage (scripted, secrets-manager friendly):
 *   VAULT_PASSPHRASE_OLD='<current>' \
 *   VAULT_PASSPHRASE_NEW='<new>' \
 *     node scripts/vault-passphrase-rotate.js
 *
 * After success, update the server's permanent VAULT_PASSPHRASE /
 * VAULT_PASSPHRASE_FILE source to the new value, then restart.
 *
 * Why rotation matters:
 *  - Annual hygiene, compliance requirements
 *  - Partial exposure (someone briefly saw the passphrase, OR an old
 *    .env file leaked but no sealed-blob copy was taken)
 *
 * IMPORTANT LIMITATION:
 *  Passphrase rotation protects the FUTURE, not the past. If an
 *  attacker already captured the sealed file AND the old passphrase,
 *  they already have the vault key. Rotating the passphrase then
 *  doesn't help — the vault key itself is unchanged. For that
 *  scenario you need FULL vault key rotation (re-encrypt every DB
 *  field, every file key), which is a separate feature tracked for
 *  v1.9.3.
 *
 * Crash safety:
 *  Rotation only touches ONE file (vault.key.sealed). Atomic rename
 *  of .tmp → .sealed handles every crash point: crash before rename
 *  leaves an orphan .tmp (cleaned on next boot), crash after rename
 *  leaves the successfully-rotated file in place. No migration
 *  marker needed because there's no two-file coordination.
 */
"use strict";

var fs = require("fs");
var http = require("http");

var C = require("../lib/constants");
var vaultWrap = require("../lib/vault-wrap");
var passphraseSource = require("../lib/passphrase-source");

var SEALED_PATH = C.PATHS.VAULT_KEY_SEALED;
var SEALED_TMP_PATH = C.PATHS.VAULT_KEY_SEALED_TMP;
var MIGRATION_PENDING = C.PATHS.VAULT_KEY_MIGRATION_PENDING;
var UNSEAL_PENDING = C.PATHS.VAULT_KEY_UNSEAL_PENDING;

function parseArgs(argv) {
  var opts = {
    forceWithServerRunning: false,
    allowRoot: false,
    help: false,
  };
  for (var i = 2; i < argv.length; i++) {
    var a = argv[i];
    if (a === "--force-with-server-running") opts.forceWithServerRunning = true;
    else if (a === "--allow-root") opts.allowRoot = true;
    else if (a === "--help" || a === "-h") opts.help = true;
    else {
      console.error("Unknown argument: " + a);
      process.exit(2);
    }
  }
  return opts;
}

function printHelp() {
  process.stdout.write([
    "vault-passphrase-rotate.js — change the passphrase wrapping vault.key.sealed",
    "",
    "Options:",
    "  --force-with-server-running   Skip running-server check",
    "  --allow-root                  Run as UID 0",
    "  -h, --help                    This help",
    "",
    "Passphrase sources (both must be available via same mechanism):",
    "  Interactive:   no env vars set → two stdin prompts (old, then new+confirm)",
    "  Env (scripted): VAULT_PASSPHRASE_OLD + VAULT_PASSPHRASE_NEW",
    "  Files:         VAULT_PASSPHRASE_OLD_FILE + VAULT_PASSPHRASE_NEW_FILE",
    "",
    "After success:",
    "  Update the server's VAULT_PASSPHRASE / VAULT_PASSPHRASE_FILE to match",
    "  the new passphrase, then restart.",
    "",
    "⚠  This protects the FUTURE. If an attacker already has your sealed file",
    "   AND your old passphrase, they already have the vault key; rotating the",
    "   passphrase doesn't undo that. For suspected vault-key compromise, use",
    "   full vault key rotation (v1.9.3 feature, not yet shipped).",
    "",
  ].join("\n"));
}

function preflight(opts) {
  if (process.getuid && process.getuid() === 0 && !opts.allowRoot) {
    console.error("ERROR: running as root. Pass --allow-root to proceed.");
    process.exit(1);
  }
  if (!fs.existsSync(SEALED_PATH)) {
    console.error("ERROR: " + SEALED_PATH + " does not exist — nothing to rotate.");
    console.error("  Run scripts/vault-passphrase-setup.js first to enable passphrase protection.");
    process.exit(1);
  }
  if (fs.existsSync(SEALED_TMP_PATH)) {
    console.error("ERROR: stale " + SEALED_TMP_PATH + " exists.");
    console.error("  A previous operation crashed. Start the server briefly so its boot");
    console.error("  cleanup removes the orphan, then re-run this rotation.");
    process.exit(1);
  }
  if (fs.existsSync(MIGRATION_PENDING) || fs.existsSync(UNSEAL_PENDING)) {
    console.error("ERROR: an unresolved migration/unseal marker exists.");
    console.error("  Start the server briefly to run boot recovery, then re-run rotation.");
    process.exit(1);
  }

  if (!opts.forceWithServerRunning) {
    return new Promise(function (resolve) {
      var port = Number(process.env.PORT || 3000);
      var req = http.get({ host: "127.0.0.1", port: port, path: "/health", timeout: 1500 }, function (res) {
        res.resume();
        console.error("ERROR: a HermitStash server appears to be running on port " + port + ".");
        console.error("  Stop it first, or pass --force-with-server-running.");
        process.exit(1);
      });
      req.on("error", function () { resolve(); });
      req.on("timeout", function () { req.destroy(); resolve(); });
    });
  }
  return Promise.resolve();
}

// Pick up two passphrases: OLD and NEW. Support both env-pair and interactive flows.
async function acquirePassphrases() {
  var oldFromEnv = process.env.VAULT_PASSPHRASE_OLD;
  var newFromEnv = process.env.VAULT_PASSPHRASE_NEW;
  var oldFileEnv = process.env.VAULT_PASSPHRASE_OLD_FILE;
  var newFileEnv = process.env.VAULT_PASSPHRASE_NEW_FILE;

  // Env/file path: either both present or both absent. Mixed is an operator error.
  var anyEnv = !!(oldFromEnv || newFromEnv || oldFileEnv || newFileEnv);
  if (anyEnv) {
    if ((oldFromEnv || oldFileEnv) && (newFromEnv || newFileEnv)) {
      var oldPw, newPw;
      if (oldFileEnv) {
        oldPw = await passphraseSource.fromFile(oldFileEnv);
      } else {
        oldPw = Buffer.from(oldFromEnv, "utf8");
        delete process.env.VAULT_PASSPHRASE_OLD;
      }
      if (newFileEnv) {
        newPw = await passphraseSource.fromFile(newFileEnv);
      } else {
        newPw = Buffer.from(newFromEnv, "utf8");
        delete process.env.VAULT_PASSPHRASE_NEW;
      }
      if (Buffer.compare(oldPw, newPw) === 0) {
        console.error("ERROR: new passphrase is identical to old passphrase. No rotation performed.");
        process.exit(1);
      }
      return { oldPw: oldPw, newPw: newPw };
    }
    console.error("ERROR: partial env passphrase config. Need BOTH:");
    console.error("  VAULT_PASSPHRASE_OLD[_FILE] and VAULT_PASSPHRASE_NEW[_FILE]");
    process.exit(1);
  }

  // Interactive path
  if (!process.stdin.isTTY) {
    console.error("ERROR: no passphrase env vars set, and stdin is not a TTY.");
    console.error("  Either run with -it for interactive prompts, or set");
    console.error("  VAULT_PASSPHRASE_OLD and VAULT_PASSPHRASE_NEW in the environment.");
    process.exit(1);
  }

  console.log("");
  console.log("======================================================================");
  console.log("  Vault passphrase rotation");
  console.log("");
  console.log("  Store the NEW passphrase in a password manager BEFORE proceeding.");
  console.log("  If you lose it after rotation, all encrypted data is unrecoverable.");
  console.log("======================================================================");
  console.log("");

  var oldPw = await passphraseSource.fromStdin("Current vault passphrase: ");
  var newPw1 = await passphraseSource.fromStdin("New vault passphrase:     ");
  var newPw2 = await passphraseSource.fromStdin("Confirm new passphrase:   ");
  if (Buffer.compare(newPw1, newPw2) !== 0) {
    console.error("ERROR: new passphrase confirmation does not match. Aborting.");
    process.exit(1);
  }
  if (Buffer.compare(oldPw, newPw1) === 0) {
    console.error("ERROR: new passphrase is identical to old passphrase. No rotation performed.");
    process.exit(1);
  }
  if (newPw1.length < 12) {
    console.warn("[rotate] NOTE: new passphrase is shorter than 12 bytes. Continuing anyway.");
  }

  var yes = await readLine("Type YES (all caps) to confirm you've stored the new passphrase safely: ");
  if (yes !== "YES") {
    console.error("ERROR: confirmation declined. No changes made.");
    process.exit(1);
  }
  return { oldPw: oldPw, newPw: newPw1 };
}

function readLine(prompt) {
  return new Promise(function (resolve) {
    var readline = require("readline");
    var rl = readline.createInterface({ input: process.stdin, output: process.stdout });
    rl.question(prompt, function (answer) { rl.close(); resolve(answer); });
  });
}

async function execute(oldPw, newPw) {
  console.log("[rotate] Reading " + SEALED_PATH + "...");
  var sealedBytes = fs.readFileSync(SEALED_PATH);

  console.log("[rotate] Unwrapping with OLD passphrase...");
  var plaintextBytes;
  try {
    plaintextBytes = await vaultWrap.unwrap(sealedBytes, oldPw);
  } catch (e) {
    console.error("ERROR: " + e.message);
    console.error("  OLD passphrase rejected. The sealed file is unchanged.");
    process.exit(1);
  }

  console.log("[rotate] Re-wrapping with NEW passphrase (fresh salt + nonce, Argon2id defaults)...");
  var newSealed;
  try {
    newSealed = await vaultWrap.wrap(plaintextBytes, newPw);
  } catch (e) {
    console.error("ERROR: failed to wrap with new passphrase: " + e.message);
    console.error("  The sealed file is unchanged.");
    process.exit(1);
  }

  // In-process round-trip verify with the NEW passphrase
  console.log("[rotate] Verifying round-trip with new passphrase...");
  var verifyBytes;
  try {
    verifyBytes = await vaultWrap.unwrap(newSealed, newPw);
  } catch (e) {
    console.error("ERROR: round-trip verification failed — " + e.message);
    console.error("  The sealed file is unchanged.");
    process.exit(1);
  }
  if (Buffer.compare(verifyBytes, plaintextBytes) !== 0) {
    console.error("ERROR: round-trip produced different bytes than the original.");
    console.error("  This should be impossible — please report this as a bug.");
    console.error("  The sealed file is unchanged.");
    process.exit(1);
  }

  // Atomic replace: write .tmp, fsync, rename, fsync directory
  fs.writeFileSync(SEALED_TMP_PATH, newSealed, { mode: 0o600 });
  fsyncPath(SEALED_TMP_PATH);
  fs.renameSync(SEALED_TMP_PATH, SEALED_PATH);
  fsyncDataDir();
  console.log("[rotate] New sealed file written.");
}

function fsyncPath(p) {
  try {
    var fd = fs.openSync(p, "r+");
    try { fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
  } catch (_e) { /* best-effort */ }
}
function fsyncDataDir() {
  try {
    var fd = fs.openSync(C.DATA_DIR, "r");
    try { fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
  } catch (_e) { /* best-effort */ }
}

function printSuccess() {
  console.log("");
  console.log("======================================================================");
  console.log("  ✓ Rotation complete.");
  console.log("");
  console.log("    " + SEALED_PATH + " — re-wrapped with new passphrase");
  console.log("");
  console.log("  To activate the new passphrase:");
  console.log("    1. Update VAULT_PASSPHRASE (env) or VAULT_PASSPHRASE_FILE (secret)");
  console.log("       in the server's environment to the NEW value.");
  console.log("    2. Restart the server.");
  console.log("    3. Expected startup line:");
  console.log("         [vault] Unsealed successfully.");
  console.log("");
  console.log("  The OLD passphrase will no longer work against this sealed file.");
  console.log("  If you were using secrets rotation, the OLD passphrase is now safe");
  console.log("  to remove from the secrets manager.");
  console.log("======================================================================");
}

(async function main() {
  var opts = parseArgs(process.argv);
  if (opts.help) { printHelp(); return; }

  try {
    await preflight(opts);
    var pws = await acquirePassphrases();
    await execute(pws.oldPw, pws.newPw);
    printSuccess();
  } catch (e) {
    console.error("FATAL: " + (e && e.message || String(e)));
    if (e && e.stack) console.error(e.stack);
    process.exit(1);
  }
})();
