"use strict";
/**
 * Passphrase source drivers — env / file / stdin.
 *
 * Single interface: `getPassphrase(opts)` returns a Promise<Buffer>. Buffers
 * (not strings) preserve byte-exactness for binary passphrases and avoid
 * accidental intermediate string allocations that linger in the heap.
 *
 * Defaults select the *vault* passphrase env vars
 * (BLAMEJS_VAULT_PASSPHRASE / _FILE / _SOURCE). Callers needing a different
 * env namespace (e.g. audit-signing) pass overrides via opts.envVars:
 *
 *   vaultPassphraseSource.getPassphrase({
 *     envVars: {
 *       value:  "BLAMEJS_AUDIT_SIGNING_PASSPHRASE",
 *       file:   "BLAMEJS_AUDIT_SIGNING_PASSPHRASE_FILE",
 *       source: "BLAMEJS_AUDIT_SIGNING_PASSPHRASE_SOURCE",
 *     },
 *     prompt: "Audit-signing passphrase: ",
 *   });
 *
 * After reading the env source, the matching env var is deleted to limit
 * exposure to later env-dump surfaces. This doesn't zero the memory
 * (JavaScript can't) but does remove the env-object reference.
 */
var nodeFs = require("fs");
var readline = require("readline");
var safeEnv = require("../parsers/safe-env");
var safeBuffer = require("../safe-buffer");

var MAX_PASSPHRASE_BYTES = 4096;

var DEFAULT_ENV_VARS = {
  value:  "BLAMEJS_VAULT_PASSPHRASE",
  file:   "BLAMEJS_VAULT_PASSPHRASE_FILE",
  source: "BLAMEJS_VAULT_PASSPHRASE_SOURCE",
};

function resolveEnvVars(opts) {
  var override = (opts && opts.envVars) || {};
  return {
    value:  override.value  || DEFAULT_ENV_VARS.value,
    file:   override.file   || DEFAULT_ENV_VARS.file,
    source: override.source || DEFAULT_ENV_VARS.source,
  };
}

function trimTrailingNewlines(buf) {
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

async function fromEnv(opts) {
  var envVars = resolveEnvVars(opts);
  // safeEnv.readVar handles: missing/empty (required), size cap, utf8→Buffer
  // coercion, and process.env strip-after-read in one call.
  return safeEnv.readVar(envVars.value, {
    type:     "buffer",
    required: true,
    maxBytes: MAX_PASSPHRASE_BYTES,
    strip:    true,
  });
}

async function fromFile(filePath, opts) {
  var envVars = resolveEnvVars(opts);
  if (!filePath) {
    throw new Error(envVars.file + " is not set");
  }
  var raw;
  try {
    raw = nodeFs.readFileSync(filePath);
  } catch (e) {
    throw new Error("failed to read " + envVars.file + " (" + filePath + "): " + e.code);
  }
  var buf = trimTrailingNewlines(raw);
  validatePassphraseBuffer(buf, "file source (" + filePath + ")");
  return buf;
}

async function fromStdin(promptText) {
  if (!process.stdin.isTTY) {
    throw new Error("stdin passphrase source requires a TTY (use `docker run -it` or similar)");
  }
  promptText = promptText || "Vault passphrase: ";

  return new Promise(function (resolve, reject) {
    var rl = readline.createInterface({
      input:    process.stdin,
      output:   process.stdout,
      terminal: true,
    });
    process.stdout.write(promptText);

    var chunks = [];

    var onData = function (chunk) {
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
          // Zero each per-byte chunk now that the bytes are copied into
          // `buf`. Each chunk held a single passphrase character; keeping
          // them around extends the secret's heap footprint.
          for (var ci = 0; ci < chunks.length; ci++) safeBuffer.secureZero(chunks[ci]);
          try {
            validatePassphraseBuffer(buf, "stdin source");
            resolve(buf);
          } catch (e) {
            safeBuffer.secureZero(buf);
            reject(e);
          }
          return;
        }
        if (b === 0x7F || b === 0x08) { // backspace / DEL
          if (chunks.length > 0) safeBuffer.secureZero(chunks.pop());
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

function sourceKind(opts) {
  var envVars = resolveEnvVars(opts);
  var mode = (process.env[envVars.source] || "auto").toLowerCase();
  if (mode === "auto") {
    if (process.env[envVars.file]) return "file";
    if (process.env[envVars.value]) return "env";
    if (process.stdin.isTTY) return "stdin";
    return null;
  }
  if (mode === "env" || mode === "file" || mode === "stdin") return mode;
  throw new Error("Unknown " + envVars.source + ": " + mode + " (expected auto, env, file, or stdin)");
}

async function getPassphrase(opts) {
  opts = opts || {};
  var envVars = resolveEnvVars(opts);
  var kind = sourceKind(opts);
  if (!kind) {
    throw new Error(
      "No passphrase source available. Set one of: " +
      envVars.value + ", " + envVars.file + ", " +
      "or run with a TTY on stdin."
    );
  }
  if (kind === "env")   return fromEnv(opts);
  if (kind === "file")  return fromFile(process.env[envVars.file], opts);
  if (kind === "stdin") return fromStdin(opts.prompt);
  throw new Error("Unreachable: unknown passphrase source kind " + kind);
}

module.exports = {
  getPassphrase:        getPassphrase,
  sourceKind:           sourceKind,
  fromEnv:              fromEnv,
  fromFile:             fromFile,
  fromStdin:            fromStdin,
  MAX_PASSPHRASE_BYTES: MAX_PASSPHRASE_BYTES,
  // Default vault env var names exposed for documentation/testing
  ENV_PASSPHRASE:       DEFAULT_ENV_VARS.value,
  ENV_PASSPHRASE_FILE:  DEFAULT_ENV_VARS.file,
  ENV_PASSPHRASE_SRC:   DEFAULT_ENV_VARS.source,
};
