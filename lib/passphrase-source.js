/**
 * Passphrase source drivers — env / file / stdin.
 *
 * Single interface: `getPassphrase(opts)` returns a Promise<Buffer>. Buffers
 * (not strings) because we want to preserve byte-exactness for binary
 * passphrases and avoid accidental intermediate string allocations that
 * linger in the heap.
 *
 * Selected via `VAULT_PASSPHRASE_SOURCE` env var:
 *   (unset|auto)  — priority order: VAULT_PASSPHRASE_FILE, VAULT_PASSPHRASE, stdin
 *   env           — require VAULT_PASSPHRASE
 *   file          — require VAULT_PASSPHRASE_FILE
 *   stdin         — require a TTY on stdin
 *
 * After reading the env source, `delete process.env.VAULT_PASSPHRASE` limits
 * exposure to later env-dump surfaces (admin /environment, crash dumps, etc.).
 * This doesn't zero the memory — JavaScript can't — but does remove the
 * reference the env object holds.
 */
var fs = require("fs");

var MAX_PASSPHRASE_BYTES = 4096; // sanity limit; Argon2 doesn't care

function stripEnvVar() {
  // Best-effort removal of the passphrase from process.env after we've read it.
  // This doesn't scrub memory but does hide the value from later callers.
  if ("VAULT_PASSPHRASE" in process.env) {
    delete process.env.VAULT_PASSPHRASE;
  }
}

function trimTrailingNewlines(buf) {
  // Trim \r\n, \n, \r from the end. Preserves internal whitespace (which is
  // a valid part of a passphrase) and leading whitespace (operator intent).
  var end = buf.length;
  while (end > 0) {
    var b = buf[end - 1];
    if (b === 0x0A || b === 0x0D) end--;
    else break;
  }
  return end === buf.length ? buf : buf.subarray(0, end);
}

function validatePassphraseBuffer(buf, contextLabel) {
  if (!buf || buf.length === 0) {
    throw new Error(contextLabel + ": passphrase is empty");
  }
  if (buf.length > MAX_PASSPHRASE_BYTES) {
    throw new Error(contextLabel + ": passphrase exceeds " + MAX_PASSPHRASE_BYTES + " byte sanity limit");
  }
}

// ---- Source: env ----
async function fromEnv() {
  var val = process.env.VAULT_PASSPHRASE;
  if (val === undefined || val === null || val === "") {
    throw new Error("VAULT_PASSPHRASE env var is not set or is empty");
  }
  var buf = Buffer.from(val, "utf8");
  validatePassphraseBuffer(buf, "env source");
  stripEnvVar();
  return buf;
}

// ---- Source: file ----
async function fromFile(filePath) {
  if (!filePath) {
    throw new Error("VAULT_PASSPHRASE_FILE is not set");
  }
  var raw;
  try {
    raw = fs.readFileSync(filePath);
  } catch (e) {
    // Don't include the file's contents in the error, but the path is fine
    // (operator already knows it; it's in their env).
    throw new Error("failed to read VAULT_PASSPHRASE_FILE (" + filePath + "): " + e.code);
  }
  var buf = trimTrailingNewlines(raw);
  validatePassphraseBuffer(buf, "file source (" + filePath + ")");
  return buf;
}

// ---- Source: stdin ----
// readline-based prompt with echo suppression. Node's readline doesn't have a
// built-in "hidden input" mode, so we manually suppress echo via setRawMode.
async function fromStdin(promptText) {
  if (!process.stdin.isTTY) {
    throw new Error("stdin passphrase source requires a TTY (use `docker run -it` or similar)");
  }
  var readline = require("readline");
  promptText = promptText || "Vault passphrase: ";

  return new Promise(function (resolve, reject) {
    var rl = readline.createInterface({
      input: process.stdin,
      output: process.stdout,
      terminal: true,
    });
    // Suppress echo: write the prompt, then intercept keystrokes manually
    process.stdout.write(promptText);

    var chunks = [];

    var onData = function (chunk) {
      // chunk is a Buffer from raw-mode stdin
      for (var i = 0; i < chunk.length; i++) {
        var b = chunk[i];
        if (b === 0x03) { // ctrl-C
          cleanup();
          process.stdout.write("\n");
          reject(new Error("passphrase input cancelled"));
          return;
        }
        if (b === 0x0A || b === 0x0D) { // enter
          cleanup();
          process.stdout.write("\n");
          var buf = Buffer.concat(chunks);
          try {
            validatePassphraseBuffer(buf, "stdin source");
            resolve(buf);
          } catch (e) {
            reject(e);
          }
          return;
        }
        if (b === 0x7F || b === 0x08) { // backspace / DEL
          if (chunks.length > 0) chunks.pop();
          continue;
        }
        chunks.push(Buffer.from([b]));
      }
    };

    var cleanup = function () {
      try { process.stdin.setRawMode(false); } catch (_e) { /* best effort */ }
      process.stdin.removeListener("data", onData);
      rl.close();
    };

    process.stdin.setRawMode(true);
    process.stdin.resume();
    process.stdin.on("data", onData);
  });
}

// ---- Source selection ----
function sourceKind() {
  var mode = (process.env.VAULT_PASSPHRASE_SOURCE || "auto").toLowerCase();
  if (mode === "auto") {
    if (process.env.VAULT_PASSPHRASE_FILE) return "file";
    if (process.env.VAULT_PASSPHRASE) return "env";
    if (process.stdin.isTTY) return "stdin";
    return null; // no source available
  }
  if (mode === "env" || mode === "file" || mode === "stdin") return mode;
  throw new Error("Unknown VAULT_PASSPHRASE_SOURCE: " + mode + " (expected auto, env, file, or stdin)");
}

async function getPassphrase(opts) {
  opts = opts || {};
  var kind = sourceKind();
  if (!kind) {
    throw new Error(
      "No passphrase source available. Set one of: " +
      "VAULT_PASSPHRASE, VAULT_PASSPHRASE_FILE, " +
      "or run with a TTY on stdin."
    );
  }
  if (kind === "env") return fromEnv();
  if (kind === "file") return fromFile(process.env.VAULT_PASSPHRASE_FILE);
  if (kind === "stdin") return fromStdin(opts.prompt);
  throw new Error("Unreachable: unknown passphrase source kind " + kind);
}

module.exports = {
  getPassphrase: getPassphrase,
  sourceKind: sourceKind,
  // Exported for direct use by CLI tools that want to bypass selection:
  fromEnv: fromEnv,
  fromFile: fromFile,
  fromStdin: fromStdin,
  MAX_PASSPHRASE_BYTES: MAX_PASSPHRASE_BYTES,
};
