// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
var readline = require("node:readline");
var safeEnv = require("../parsers/safe-env");
var safeBuffer = require("../safe-buffer");
var atomicFile = require("../atomic-file");

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
    raw = atomicFile.fdSafeReadSync(filePath, { maxBytes: MAX_PASSPHRASE_BYTES });
  } catch (e) {
    throw new Error("failed to read " + envVars.file + " (" + filePath + "): " + (e.code || e.message));
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
        if (b === 0x03) {
          cleanup();
          process.stdout.write("\n");
          reject(new Error("passphrase input cancelled"));
          return;
        }
        if (b === 0x0A || b === 0x0D) {
          cleanup();
          process.stdout.write("\n");
          var buf = Buffer.concat(chunks);
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
        if (b === 0x7F || b === 0x08) {
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
  ENV_PASSPHRASE:       DEFAULT_ENV_VARS.value,
  ENV_PASSPHRASE_FILE:  DEFAULT_ENV_VARS.file,
  ENV_PASSPHRASE_SRC:   DEFAULT_ENV_VARS.source,
};
