// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module b.vaultPassphraseSource
 * @nav    Crypto
 * @title  Vault Passphrase Source
 * @slug   vault-passphrase-source
 *
 * @intro
 *   Where the vault's passphrase comes from, and how it stops being in
 *   memory. Three sources: an environment variable, a file the variable points
 *   at, or a TTY prompt. Which one is used is a deployment decision, so it is
 *   read from the environment rather than written into the application.
 *
 *   A passphrase arrives as a Buffer rather than a string, because a string
 *   cannot be zeroed: the bytes stay reachable until the collector decides
 *   otherwise, and a heap dump finds them. The caller is handed a Buffer and
 *   is expected to zero it once the derivation is done.
 *

 *   Reading from the environment strips the variable, so a child process
 *   started afterwards does not inherit the passphrase and nothing reading
 *   <code>process.env</code> later finds it. It does <strong>not</strong>
 *   erase the environment block the process was started with: on Linux a
 *   variable set at exec time stays readable through
 *   <code>/proc/&lt;pid&gt;/environ</code> for as long as the process lives,
 *   whatever this module does afterwards. A deployment that needs the
 *   passphrase kept away from a local reader passes it as a file or over a
 *   TTY rather than in the environment.
 *
 *   Stripping would then leave a retry with nothing to read, so the
 *   retry-aware callers hold the resolved copy for exactly as long as the
 *   operation that read it.
 *
 * @card
 *   Resolve the vault passphrase from an environment variable, a file or a TTY
 *   as a zeroable Buffer, stripping the variable so no child process inherits
 *   it.
 */

var readline = require("node:readline");
var safeEnv = require("../parsers/safe-env");
var safeBuffer = require("../safe-buffer");
var atomicFile = require("../atomic-file");
var validateOpts = require("../validate-opts");

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

var _heldEnvPassphrase = Object.create(null);
var _envReadCount = Object.create(null);

function _readCountFor(varName) {
  return _envReadCount[varName] || 0;
}

function _entryFor(varName) {
  return Object.prototype.hasOwnProperty.call(_heldEnvPassphrase, varName)
    ? _heldEnvPassphrase[varName]
    : null;
}

function _heldFor(varName) {
  var entry = _entryFor(varName);
  return entry === null ? null : entry.buf;
}

function _heldOwnerFor(varName) {
  var entry = _entryFor(varName);
  return entry === null ? null : entry.owner;
}

function _releaseHeld(varName, err, owner, readsBefore) {
  var entry = _entryFor(varName);
  if (entry !== null && owner !== undefined && entry.owner !== owner) return;
  if (entry !== null && readsBefore !== undefined && readsBefore !== null &&
      _readCountFor(varName) <= readsBefore) {
    return;
  }
  if (err && err.isArgon2Error === true && err.permanent === false) return;
  _clearHeld(varName);
}

function _clearHeld(varName) {
  if (varName === undefined) {
    Object.keys(_heldEnvPassphrase).forEach(function (k) { _clearHeld(k); });
    return;
  }
  var held = _heldFor(varName);
  if (held) safeBuffer.secureZero(held);
  delete _heldEnvPassphrase[varName];
}

/**
 * @primitive b.vaultPassphraseSource.fromEnv
 * @signature b.vaultPassphraseSource.fromEnv(opts?)
 * @since     0.1.96
 * @status    stable
 * @related   b.vaultPassphraseSource.getPassphrase, b.vaultPassphraseSource.fromFile
 *
 * Read the passphrase from `BLAMEJS_VAULT_PASSPHRASE` and answer a Buffer.
 *
 * The variable is stripped as it is read, so nothing the process starts later
 * inherits it. That also means the read happens once: a second call finds
 * nothing.
 *
 * Stripping does not reach the environment block the process started with. A
 * passphrase that was in the environment at exec time stays readable through
 * `/proc/<pid>/environ` on Linux for the life of the process, so treat the
 * strip as protection against inheritance, not against a local reader.
 *
 * The value is used as the variable holds it. A secret delivered through a
 * shell heredoc or a `$(cat file)` often carries a final newline, and that
 * byte is part of the passphrase here: a vault sealed through this source
 * with the newline needs the newline to open. `fromFile` is the other way
 * round and always strips trailing CR and LF, so the same secret reaches the
 * two sources differently.
 *
 * `trimTrailingNewlines` makes this source strip them as well. It is off by
 * default because turning it on changes the derived key: a vault sealed
 * through this source from a value ending in a newline stops opening once it
 * is set. Set it on a new vault, or re-seal an existing one first with
 * `b.vaultPassphraseOps.rotate`.
 *
 * An empty or oversized value is refused, and so is one that is nothing but
 * newlines once trimmed.
 *
 * @opts
 *   envVars:              object,   // override the variable names
 *   trimTrailingNewlines: boolean,  // default false; strip trailing CR and LF
 *
 * @example
 *   var b = require("@blamejs/core");
 *   process.env.BLAMEJS_VAULT_PASSPHRASE = "correct horse battery";
 *   var pass = await b.vaultPassphraseSource.fromEnv();
 *   process.env.BLAMEJS_VAULT_PASSPHRASE;   // → undefined, it was stripped
 *   pass.fill(0);
 */
async function fromEnv(opts) {
  validateOpts.optionalBoolean(opts && opts.trimTrailingNewlines,
    "fromEnv: opts.trimTrailingNewlines (anything else was read as false, so " +
    "the trailing newline stayed in the passphrase)");
  var envVars = resolveEnvVars(opts);
  var holdForRetry = !!(opts && opts._holdForRetry === true);
  if (holdForRetry && process.env[envVars.value] === undefined) {
    var held = _heldFor(envVars.value);
    if (held) {
      _envReadCount[envVars.value] = _readCountFor(envVars.value) + 1;
      return Buffer.from(held);
    }
  }
  var raw = safeEnv.readVar(envVars.value, {
    type:     "buffer",
    required: true,
    maxBytes: MAX_PASSPHRASE_BYTES,
    strip:    true,
  });
  var buf = opts && opts.trimTrailingNewlines === true
    ? trimTrailingNewlines(raw) : raw;
  validatePassphraseBuffer(buf, "env source (" + envVars.value + ")");
  _clearHeld(envVars.value);
  if (holdForRetry) {
    _heldEnvPassphrase[envVars.value] = {
      buf:   Buffer.from(buf),
      owner: opts && opts._holdOwner !== undefined ? opts._holdOwner : null,
    };
  }
  _envReadCount[envVars.value] = _readCountFor(envVars.value) + 1;
  return buf;
}

/**
 * @primitive b.vaultPassphraseSource.fromFile
 * @signature b.vaultPassphraseSource.fromFile(filePath, opts?)
 * @since     0.1.96
 * @status    stable
 * @related   b.vaultPassphraseSource.fromEnv, b.vaultPassphraseSource.getPassphrase
 *
 * Read the passphrase from a file and answer a Buffer. This is the source for
 * a secret delivered as a mounted file, which is how most orchestrators hand
 * one over.
 *
 * The read is bounded at the passphrase limit and goes through a descriptor
 * that cannot be swapped between the check and the read, so a path pointing at
 * something enormous is refused rather than loaded.
 *
 * Trailing newlines are removed, since an editor or a secret store usually
 * adds one. A missing path raises naming the variable that should have held
 * it, and a read failure reports the file and the system error.
 *
 * @opts
 *   envVars: object,   // override the variable names used in the messages
 *
 * @example
 *   // requires: a readable passphrase file at the path below
 *   var b = require("@blamejs/core");
 *   var pass = await b.vaultPassphraseSource.fromFile("/run/secrets/vault-passphrase");
 *   pass.fill(0);
 */
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

/**
 * @primitive b.vaultPassphraseSource.fromStdin
 * @signature b.vaultPassphraseSource.fromStdin(promptText?)
 * @since     0.1.96
 * @status    stable
 * @related   b.vaultPassphraseSource.getPassphrase
 *
 * Prompt for the passphrase on the terminal and answer a Buffer. The prompt
 * defaults to `Vault passphrase: `.
 *
 * It requires a TTY and raises otherwise, naming the interactive flag, because
 * reading a passphrase from a non-TTY stdin would take whatever happened to be
 * piped in. The typed characters are not echoed.
 *
 * This is the source for an operator unsealing a vault by hand. A service
 * starting unattended reads a variable or a file instead.
 *
 * @example
 *   // requires: a TTY on stdin
 *   var b = require("@blamejs/core");
 *   var pass = await b.vaultPassphraseSource.fromStdin("Unseal passphrase: ");
 *   pass.fill(0);
 */
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

/**
 * @primitive b.vaultPassphraseSource.sourceKind
 * @signature b.vaultPassphraseSource.sourceKind(opts?)
 * @since     0.1.96
 * @status    stable
 * @related   b.vaultPassphraseSource.getPassphrase
 *
 * Answer which source would be used: `"env"`, `"file"`, `"stdin"`, or `null`
 * when none is available. It reads the environment and does not consume the
 * passphrase, so a boot check can report what will happen before trying it.
 *
 * `BLAMEJS_VAULT_PASSPHRASE_SOURCE` forces a source. Left at `auto`, a
 * passphrase file wins over an inline variable, and a TTY is the last resort.
 * A value other than `auto`, `env`, `file` or `stdin` raises rather than
 * falling back, since a typo there would otherwise pick a source the operator
 * did not choose.
 *
 * @opts
 *   envVars: object,   // override the variable names
 *
 * @example
 *   var b = require("@blamejs/core");
 *   b.vaultPassphraseSource.sourceKind();   // → "env", "file", "stdin" or null
 */
function sourceKind(opts) {
  var envVars = resolveEnvVars(opts);
  var mode = (process.env[envVars.source] || "auto").toLowerCase();
  if (mode === "auto") {
    if (process.env[envVars.file]) return "file";
    if (process.env[envVars.value]) return "env";
    if (opts && opts._holdForRetry === true && _heldFor(envVars.value)) return "env";
    if (process.stdin.isTTY) return "stdin";
    return null;
  }
  if (mode === "env" || mode === "file" || mode === "stdin") return mode;
  throw new Error("Unknown " + envVars.source + ": " + mode + " (expected auto, env, file, or stdin)");
}

/**
 * @primitive b.vaultPassphraseSource.getPassphrase
 * @signature b.vaultPassphraseSource.getPassphrase(opts?)
 * @since     0.1.96
 * @status    stable
 * @related   b.vaultPassphraseSource.sourceKind, b.vault.init
 *
 * Resolve the passphrase from whichever source the environment selects, and
 * answer a Buffer the caller zeroes when it is done.
 *
 * With no source available it raises, naming the variables to set and the TTY
 * option, because a vault that silently falls back to no passphrase is worse
 * than one that will not open.
 *
 * `prompt` is the text shown when the source is a TTY. The environment
 * variable names are overridable, which is how the audit-signing key uses the
 * same resolution with its own variables.
 *
 * @opts
 *   prompt:  string,   // text shown when reading from a TTY
 *   envVars: object,   // override the variable names
 *
 * Reading here consumes the source, so a caller that resolves the passphrase
 * itself has to use the Buffer it was handed. `b.vault.init` resolves its own,
 * which is why a deployment booting the vault does not call this first: doing
 * so strips the variable and leaves `init` with no source.
 *
 * @example
 *   // requires: one of the passphrase env vars set, or a TTY on stdin
 *   var b = require("@blamejs/core");
 *   var pass = await b.vaultPassphraseSource.getPassphrase({ prompt: "Vault passphrase: " });
 *   try {
 *     await b.vaultPassphraseOps.seal({ dataDir: "./data", passphrase: pass });
 *   } finally {
 *     pass.fill(0);
 *   }
 */
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
  _clearHeldEnvPassphrase:   _clearHeld,
  _releaseHeldEnvPassphrase: _releaseHeld,
  _heldEnvPassphraseOwner:   _heldOwnerFor,
  _envPassphraseReadCount:   _readCountFor,
  MAX_PASSPHRASE_BYTES: MAX_PASSPHRASE_BYTES,
  ENV_PASSPHRASE:       DEFAULT_ENV_VARS.value,
  ENV_PASSPHRASE_FILE:  DEFAULT_ENV_VARS.file,
  ENV_PASSPHRASE_SRC:   DEFAULT_ENV_VARS.source,
};
