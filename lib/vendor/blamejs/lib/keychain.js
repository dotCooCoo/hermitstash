// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module b.keychain
 * @nav    Crypto
 * @title  Keychain
 *
 * @intro
 *   OS keychain abstraction with encrypted-file fallback — stores /
 *   retrieves / removes a `(service, account) -> password` binding via
 *   the host operating system's native credential store. Operators
 *   reach for this from CLI bootstraps that need to materialize a
 *   database password, outbound webhook secret, SMTP relay credential,
 *   etc., without baking the value into a config file or env var.
 *
 *   Backend dispatch:
 *     - macOS    -> `/usr/bin/security` (add-/find-/delete-generic-password)
 *     - Linux    -> `secret-tool` from libsecret; password on stdin so
 *                   it never reaches /proc/<pid>/cmdline
 *     - Windows  -> PowerShell + the CredentialManager module; password
 *                   on stdin via [Console]::In.ReadToEnd(). Falls through
 *                   to the file backend when CredentialManager is absent
 *     - File     -> XChaCha20-Poly1305-sealed JSON whose KEK is derived
 *                   via Argon2id from `opts.passphrase`. Wrap format is
 *                   shared with `b.vault.wrap` (magic 0xE2). File mode
 *                   0o600, atomic via `b.atomicFile.write`.
 *
 *   Process-list-safety: every native-tool invocation passes the
 *   password on stdin. macOS `security` is invoked with `-w -` (the
 *   documented stdin sentinel); secret-tool always reads from stdin;
 *   PowerShell scripts use `[Console]::In.ReadToEnd()`. The plaintext
 *   never crosses argv on any backend.
 *
 *   Validation tier: config-time / entry-point. Bad opts throw
 *   `KeychainError` synchronously; native-tool failures surface as
 *   `KeychainError` with the tool's stderr included.
 *
 *   Audit: every call emits one of `keychain.stored` / `keychain.retrieved`
 *   / `keychain.removed` (or the `.failed` sibling). Audit metadata
 *   records service / account / backend / outcome. The password value
 *   is never audited.
 *
 * @card
 *   OS keychain abstraction with encrypted-file fallback — stores / retrieves / removes a `(service, account) -> password` binding via the host operating system's native credential store.
 */

var nodeFs = require("node:fs");
var nodePath = require("node:path");

var atomicFile = require("./atomic-file");
var C = require("./constants");
var lazyRequire = require("./lazy-require");
var processSpawn = require("./process-spawn");
var safeBuffer = require("./safe-buffer");
var safeEnv = require("./parsers/safe-env");
var safeJson = require("./safe-json");
var validateOpts = require("./validate-opts");
var vaultWrap = require("./vault/wrap");
var { FrameworkError, KeychainError } = require("./framework-error");

var audit = lazyRequire(function () { return require("./audit"); });

// ---- Backend detection -----------------------------------------------------

// Cached per-process so multiple calls don't re-stat /usr/bin/security
// on every invocation. Detection is best-effort — `null` means "fall
// through to the next backend / file fallback".
var _cachedBackend = null;

function _detectBackend() {
  if (_cachedBackend !== null) return _cachedBackend;
  var p = process.platform;
  if (p === "darwin") {
    if (_existsExecutable("/usr/bin/security")) {
      _cachedBackend = "macos-security";
      return _cachedBackend;
    }
  } else if (p === "linux") {
    if (_resolveOnPath("secret-tool")) {
      _cachedBackend = "linux-secret-tool";
      return _cachedBackend;
    }
  } else if (p === "win32") {
    if (_resolveOnPath("powershell.exe") || _resolveOnPath("pwsh.exe")) {
      _cachedBackend = "windows-credential";
      return _cachedBackend;
    }
  }
  _cachedBackend = null;
  return null;
}

function _existsExecutable(filepath) {
  try {
    var st = nodeFs.statSync(filepath);
    return st.isFile();
  } catch (_e) { return false; }
}

// Allowlist of bin names this module is permitted to resolve on PATH.
// Frozen so a future caller can't smuggle an attacker-controlled name
// through _resolveOnPath — the lookup is gated by hardcoded membership
// in this set, not by any operator-supplied opts.
var _PATH_RESOLVE_ALLOWLIST = Object.freeze({
  "secret-tool":    true,
  "powershell.exe": true,
  "pwsh.exe":       true,
});

function _resolveOnPath(binName) {
  if (typeof binName !== "string" || _PATH_RESOLVE_ALLOWLIST[binName] !== true) {
    return null;
  }
  // Reject any bin name with a path separator — defense in depth on top
  // of the allowlist; a future contributor adding to the allowlist
  // can't accidentally land a value with a "/" or "\" in it.
  if (binName.indexOf("/") !== -1 || binName.indexOf("\\") !== -1) return null;
  // Windows env vars are case-insensitive; Node populates both PATH and Path.
  // safeEnv.readVar gates each by name with the standard size cap.
  var pathEnv = safeEnv.readVar("PATH",  { default: "" }) ||
                safeEnv.readVar("Path",  { default: "" }) ||
                "";
  var sep = process.platform === "win32" ? ";" : ":";
  var parts = pathEnv.split(sep);
  for (var i = 0; i < parts.length; i += 1) {
    var dir = parts[i];
    if (typeof dir !== "string" || dir.length === 0) continue;
    var candidate = nodePath.join(dir, binName);
    if (_existsExecutable(candidate)) return candidate;
  }
  return null;
}

// ---- Opts validation -------------------------------------------------------

function _validateCommonOpts(opts, primitive) {
  if (opts == null || typeof opts !== "object") {
    throw new KeychainError("keychain/bad-opts",
      primitive + ": opts must be an object");
  }
  validateOpts(opts, [
    "service", "account", "password", "fallbackFile", "passphrase",
    "preferFile", "audit",
  ], primitive);
  validateOpts.requireNonEmptyString(opts.service, "service",
    KeychainError, "keychain/bad-service");
  validateOpts.requireNonEmptyString(opts.account, "account",
    KeychainError, "keychain/bad-account");
  // Service / account names cross argv on every native backend. Refuse
  // newline / null bytes universally — they enable command injection on
  // secret-tool's attribute-list parser and embed-an-extra-key on
  // PowerShell's -Target string.
  // eslint-disable-next-line no-control-regex
  if (/[\u0000\r\n]/.test(opts.service) || /[\u0000\r\n]/.test(opts.account)) {
    throw new KeychainError("keychain/bad-identifier",
      primitive + ": service/account must not contain null or newline bytes");
  }
}

function _validateFallbackFile(filepath, primitive) {
  validateOpts.requireNonEmptyString(filepath, "fallbackFile",
    KeychainError, "keychain/bad-fallback-file");
  if (!nodePath.isAbsolute(filepath)) {
    throw new KeychainError("keychain/relative-fallback-file",
      primitive + ": fallbackFile must be an absolute path; got " + filepath);
  }
}

// ---- File-fallback I/O -----------------------------------------------------
//
// File format: vault.wrap-sealed buffer whose plaintext is a canonical
// JSON document of the shape
//
//   { version: 1, entries: { "<service>\u0000<account>": "<password>" } }
//
// One file holds every binding for the operator's process. Atomic
// rename on every write (atomicFile.write) so a crash never leaves a
// half-written ciphertext at `fallbackFile`.

var FILE_FORMAT_VERSION = 1;
var FILE_KEY_SEPARATOR = "\u0000";

function _bindingKey(service, account) {
  return service + FILE_KEY_SEPARATOR + account;
}

async function _readFile(fallbackFile, passphrase) {
  if (!atomicFile.exists(fallbackFile)) {
    return { version: FILE_FORMAT_VERSION, entries: {} };
  }
  validateOpts.requireNonEmptyString(passphrase, "passphrase",
    KeychainError, "keychain/file-passphrase-required");
  var sealed = await atomicFile.read(fallbackFile, {
    maxBytes: C.BYTES.mib(4),
  });
  if (!Buffer.isBuffer(sealed)) sealed = Buffer.from(sealed);
  var pwBuf = Buffer.from(String(passphrase), "utf8");
  var plaintext;
  try {
    plaintext = await vaultWrap.unwrap(sealed, pwBuf);
  } catch (_e) {
    throw new KeychainError("keychain/file-unseal-failed",
      "fallback file passphrase rejected or file corrupted");
  } finally {
    safeBuffer.secureZero(pwBuf);
  }
  var doc;
  try {
    doc = safeJson.parse(plaintext.toString("utf8"));
  } catch (_e) {
    safeBuffer.secureZero(plaintext);
    throw new KeychainError("keychain/file-bad-shape",
      "fallback file payload is not valid JSON");
  }
  safeBuffer.secureZero(plaintext);
  if (!doc || typeof doc !== "object" || doc.version !== FILE_FORMAT_VERSION ||
      !doc.entries || typeof doc.entries !== "object") {
    throw new KeychainError("keychain/file-bad-shape",
      "fallback file is not a keychain document");
  }
  return doc;
}

async function _writeFile(fallbackFile, doc, passphrase) {
  validateOpts.requireNonEmptyString(passphrase, "passphrase",
    KeychainError, "keychain/file-passphrase-required");
  var serialized = Buffer.from(safeJson.canonical(doc), "utf8");
  var pwBuf = Buffer.from(String(passphrase), "utf8");
  var sealed;
  try {
    sealed = await vaultWrap.wrap(serialized, pwBuf);
  } finally {
    safeBuffer.secureZero(pwBuf);
    safeBuffer.secureZero(serialized);
  }
  // atomicFile.write enforces 0o600 by default and writes via
  // temp + fsync + rename so a crash never leaves a partial file.
  await atomicFile.write(fallbackFile, sealed, { fileMode: 0o600 });
}

// ---- Native-backend invocations -------------------------------------------

// Drain a stream into a Buffer, honoring an upper byte cap so a
// runaway tool can't OOM the framework.
function _drain(stream, capBytes) {
  if (!stream) return Promise.resolve(Buffer.alloc(0));
  return safeBuffer.collectStream(stream, {
    maxBytes:    capBytes,
    errorClass:  KeychainError,
    sizeCode:    "keychain/native-output-too-large",
    sizeMessage: "native tool output exceeded " + capBytes + " bytes",
  });
}

function _runNative(command, args, opts) {
  opts = opts || {};
  var stdinBuf = opts.stdin == null ? null
                 : (Buffer.isBuffer(opts.stdin) ? opts.stdin : Buffer.from(String(opts.stdin), "utf8"));
  return new Promise(function (resolve, reject) {
    var child;
    try {
      child = processSpawn.spawn(command, args || [], {
        stdio: ["pipe", "pipe", "pipe"],
      });
    } catch (e) { reject(e); return; }

    var stdoutCap = opts.maxStdoutBytes || C.BYTES.mib(1);
    var stderrCap = opts.maxStderrBytes || C.BYTES.kib(64);
    var settled   = false;
    var outP = _drain(child.stdout, stdoutCap);
    var errP = _drain(child.stderr, stderrCap);

    child.on("error", function (e) {
      if (settled) return;
      settled = true;
      if (stdinBuf) safeBuffer.secureZero(stdinBuf);
      reject(e);
    });

    child.on("close", function (code, signal) {
      Promise.all([outP, errP]).then(function (bufs) {
        if (settled) return;
        settled = true;
        if (stdinBuf) safeBuffer.secureZero(stdinBuf);
        resolve({
          code:   typeof code === "number" ? code : -1,
          signal: signal || null,
          stdout: bufs[0],
          stderr: bufs[1],
        });
      }, function (e) {
        if (settled) return;
        settled = true;
        if (stdinBuf) safeBuffer.secureZero(stdinBuf);
        reject(e);
      });
    });

    if (stdinBuf && child.stdin) {
      try {
        child.stdin.on("error", function (_e) { /* broken pipe is fine */ });
        child.stdin.end(stdinBuf);
      } catch (_e) { /* tool may have closed stdin already */ }
    } else if (child.stdin) {
      try { child.stdin.end(); } catch (_e) { /* close best-effort */ }
    }
  });
}

// ---- macOS: /usr/bin/security ---------------------------------------------
//
// add-generic-password supports `-w -` to read the password from stdin
// (man security(1) — "If pre-existing or read with -w -, the password
// is read from stdin"). The single dash is the documented sentinel.

async function _macStore(service, account, password) {
  var r = await _runNative("/usr/bin/security", [
    "add-generic-password",
    "-s", service,
    "-a", account,
    "-w", "-",   // read password from stdin
    "-U",        // update if exists
  ], { stdin: password });
  if (r.code !== 0) {
    throw new KeychainError("keychain/macos-store-failed",
      "security add-generic-password exited " + r.code + ": " +
      r.stderr.toString("utf8").trim());
  }
}

async function _macRetrieve(service, account) {
  var r = await _runNative("/usr/bin/security", [
    "find-generic-password",
    "-s", service,
    "-a", account,
    "-w",        // print password on stdout
  ]);
  if (r.code === 44) {        // SecKeychainSearchCopyNext: not found
    return null;
  }
  if (r.code !== 0) {
    throw new KeychainError("keychain/macos-retrieve-failed",
      "security find-generic-password exited " + r.code + ": " +
      r.stderr.toString("utf8").trim());
  }
  // `security -w` prints the password followed by a newline.
  var raw = r.stdout.toString("utf8");
  if (raw.length > 0 && raw[raw.length - 1] === "\n") raw = raw.slice(0, -1);
  return raw;
}

async function _macRemove(service, account) {
  var r = await _runNative("/usr/bin/security", [
    "delete-generic-password",
    "-s", service,
    "-a", account,
  ]);
  if (r.code === 44) return false;
  if (r.code !== 0) {
    throw new KeychainError("keychain/macos-remove-failed",
      "security delete-generic-password exited " + r.code + ": " +
      r.stderr.toString("utf8").trim());
  }
  return true;
}

// ---- Linux: secret-tool ----------------------------------------------------
//
// `secret-tool store` reads the password from stdin only — there is no
// CLI flag for the value (man secret-tool — "Will prompt for the secret
// or read it from standard input if it isn't a TTY"). Stdin path is
// process-list-safe by construction.

async function _linuxStore(service, account, password) {
  var r = await _runNative("secret-tool", [
    "store",
    "--label", service,
    "service", service,
    "account", account,
  ], { stdin: password });
  if (r.code !== 0) {
    throw new KeychainError("keychain/linux-store-failed",
      "secret-tool store exited " + r.code + ": " +
      r.stderr.toString("utf8").trim());
  }
}

async function _linuxRetrieve(service, account) {
  var r = await _runNative("secret-tool", [
    "lookup",
    "service", service,
    "account", account,
  ]);
  if (r.code !== 0) {
    // secret-tool exits 1 when the attribute set has no match. Surface
    // null instead of throwing — operators expect "not found" to return
    // null rather than an error.
    if (r.stderr.toString("utf8").indexOf("No matching") !== -1 || r.stdout.length === 0) {
      return null;
    }
    throw new KeychainError("keychain/linux-retrieve-failed",
      "secret-tool lookup exited " + r.code + ": " +
      r.stderr.toString("utf8").trim());
  }
  var raw = r.stdout.toString("utf8");
  // secret-tool does NOT append a newline (man secret-tool); guard
  // anyway in case a future libsecret release changes that.
  if (raw.length > 0 && raw[raw.length - 1] === "\n") raw = raw.slice(0, -1);
  if (raw.length === 0) return null;
  return raw;
}

async function _linuxRemove(service, account) {
  var r = await _runNative("secret-tool", [
    "clear",
    "service", service,
    "account", account,
  ]);
  if (r.code !== 0) {
    throw new KeychainError("keychain/linux-remove-failed",
      "secret-tool clear exited " + r.code + ": " +
      r.stderr.toString("utf8").trim());
  }
  return true;
}

// ---- Windows: PowerShell + CredentialManager module -----------------------
//
// CredentialManager (PSGallery) exposes Get-/New-/Remove-StoredCredential.
// We pipe the password to PowerShell on stdin via $cred = [Console]::In.
// ReadLine() so the plaintext never hits argv. When CredentialManager is
// not installed (`Get-Module -ListAvailable CredentialManager` empty),
// the calling host gets a not-supported error and the keychain falls
// through to the file fallback.
//
// The script reads: command (one of "store" / "retrieve" / "remove"),
// service, account from argv; password (store only) from stdin.

var _PS_SCRIPT_HEAD = "" +
  "$ErrorActionPreference = 'Stop';" +
  "if (-not (Get-Module -ListAvailable -Name CredentialManager)) {" +
    "Write-Error 'CredentialManager module not installed';" +
    "exit 2;" +
  "}" +
  "Import-Module CredentialManager;";

function _psQuote(value) {
  // PowerShell single-quoted strings escape ' as ''.
  return "'" + String(value).replace(/'/g, "''") + "'";
}

function _psStoreScript(service, account) {
  var target = service + ":" + account;
  return _PS_SCRIPT_HEAD +
    "$pw = [Console]::In.ReadToEnd();" +
    "if ($pw.EndsWith([char]10)) { $pw = $pw.Substring(0, $pw.Length - 1); }" +
    "if ($pw.EndsWith([char]13)) { $pw = $pw.Substring(0, $pw.Length - 1); }" +
    "$secure = ConvertTo-SecureString -String $pw -AsPlainText -Force;" +
    "New-StoredCredential -Target " + _psQuote(target) +
      " -UserName " + _psQuote(account) +
      " -SecurePassword $secure -Persist LocalMachine | Out-Null;" +
    "Write-Output 'OK';";
}

function _psRetrieveScript(service, account) {
  var target = service + ":" + account;
  return _PS_SCRIPT_HEAD +
    "$cred = Get-StoredCredential -Target " + _psQuote(target) + ";" +
    "if ($null -eq $cred) { exit 44; }" +
    "$ptr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($cred.Password);" +
    "try {" +
      "$plain = [Runtime.InteropServices.Marshal]::PtrToStringAuto($ptr);" +
      "[Console]::Out.Write($plain);" +
    "} finally {" +
      "[Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr);" +
    "}";
}

function _psRemoveScript(service, account) {
  var target = service + ":" + account;
  return _PS_SCRIPT_HEAD +
    "try {" +
      "Remove-StoredCredential -Target " + _psQuote(target) + ";" +
      "Write-Output 'OK';" +
    "} catch {" +
      "if ($_.Exception.Message -match 'not be found') { exit 44; } else { throw; }" +
    "}";
}

function _psResolve() {
  var p = _resolveOnPath("pwsh.exe") || _resolveOnPath("powershell.exe");
  if (!p) {
    throw new KeychainError("keychain/windows-no-powershell",
      "PowerShell executable not found on PATH");
  }
  return p;
}

async function _windowsStore(service, account, password) {
  var r = await _runNative(_psResolve(), [
    "-NoProfile", "-NonInteractive", "-Command", _psStoreScript(service, account),
  ], { stdin: password });
  if (r.code === 2) {
    var e = new KeychainError("keychain/windows-not-supported",
      "CredentialManager PowerShell module not installed");
    e.fallback = true;
    throw e;
  }
  if (r.code !== 0) {
    throw new KeychainError("keychain/windows-store-failed",
      "PowerShell New-StoredCredential exited " + r.code + ": " +
      r.stderr.toString("utf8").trim());
  }
}

async function _windowsRetrieve(service, account) {
  var r = await _runNative(_psResolve(), [
    "-NoProfile", "-NonInteractive", "-Command", _psRetrieveScript(service, account),
  ]);
  if (r.code === 2) {
    var e = new KeychainError("keychain/windows-not-supported",
      "CredentialManager PowerShell module not installed");
    e.fallback = true;
    throw e;
  }
  if (r.code === 44) return null;
  if (r.code !== 0) {
    throw new KeychainError("keychain/windows-retrieve-failed",
      "PowerShell Get-StoredCredential exited " + r.code + ": " +
      r.stderr.toString("utf8").trim());
  }
  return r.stdout.toString("utf8");
}

async function _windowsRemove(service, account) {
  var r = await _runNative(_psResolve(), [
    "-NoProfile", "-NonInteractive", "-Command", _psRemoveScript(service, account),
  ]);
  if (r.code === 2) {
    var e = new KeychainError("keychain/windows-not-supported",
      "CredentialManager PowerShell module not installed");
    e.fallback = true;
    throw e;
  }
  if (r.code === 44) return false;
  if (r.code !== 0) {
    throw new KeychainError("keychain/windows-remove-failed",
      "PowerShell Remove-StoredCredential exited " + r.code + ": " +
      r.stderr.toString("utf8").trim());
  }
  return true;
}

// ---- Audit emit ------------------------------------------------------------
// drop-silent — by design (audit is best-effort observability).

function _emit(action, outcome, metadata, auditOn) {
  if (auditOn === false) return;
  try {
    audit().safeEmit({
      action:   action,
      outcome: outcome,
      metadata: metadata || {},
    });
  } catch (_e) { /* audit best-effort */ }
}

// ---- Backend selection -----------------------------------------------------

function _selectBackend(opts) {
  if (opts && opts.preferFile === true) return "file";
  return _detectBackend() || "file";
}

function _isFallbackError(e) {
  // A KeychainError flagged with .fallback === true means the native
  // tool reported "not installed / unavailable" rather than an
  // operational failure. Promote to file fallback transparently.
  return e instanceof FrameworkError && e.fallback === true;
}

// ---- Public surface --------------------------------------------------------

/**
 * @primitive b.keychain.store
 * @signature b.keychain.store(opts)
 * @since     0.7.0
 * @related   b.keychain.retrieve, b.keychain.remove
 *
 * Persist a `(service, account) -> password` binding to the
 * platform's native credential store, falling back to an encrypted
 * file when no native backend is reachable. The password crosses to
 * the native tool on stdin so it never appears in `/proc/<pid>/cmdline`
 * or `ps`. Resolves to `{ stored: true, backend }` on success.
 * Bad opts throw `KeychainError` synchronously.
 *
 * Set `preferFile: true` to skip native backend probing entirely (for
 * deterministic CI / disposable container deployments).
 *
 * @opts
 *   {
 *     service:       string,        // required, no NUL/CR/LF bytes
 *     account:       string,        // required, no NUL/CR/LF bytes
 *     password:      string,        // required, non-empty
 *     fallbackFile?: string,        // absolute path; required if file fallback may engage
 *     passphrase?:   string,        // required when fallbackFile engages (Argon2id-derived KEK)
 *     preferFile?:   boolean,       // default: false
 *     audit?:        boolean,       // default: true (emits keychain.stored)
 *   }
 *
 * @example
 *   await b.keychain.store({
 *     service:      "blamejs/db",
 *     account:      "primary",
 *     password:     "s3cr3t",
 *     fallbackFile: "/var/lib/blamejs/keychain.enc",
 *     passphrase:   process.env.BLAMEJS_KEYCHAIN_PASSPHRASE,
 *   });
 *   // → { stored: true, backend: "macos-security" }
 */
async function store(opts) {
  _validateCommonOpts(opts, "keychain.store");
  validateOpts.requireNonEmptyString(opts.password, "password",
    KeychainError, "keychain/bad-password");

  var backend = _selectBackend(opts);
  var auditOn = opts.audit !== false;

  if (backend !== "file") {
    try {
      if (backend === "macos-security")    await _macStore(opts.service, opts.account, opts.password);
      else if (backend === "linux-secret-tool") await _linuxStore(opts.service, opts.account, opts.password);
      else if (backend === "windows-credential") await _windowsStore(opts.service, opts.account, opts.password);
      _emit("keychain.stored", "success", {
        service: opts.service, account: opts.account, backend: backend,
      }, auditOn);
      return { stored: true, backend: backend };
    } catch (e) {
      if (!_isFallbackError(e)) {
        _emit("keychain.stored", "failure", {
          service: opts.service, account: opts.account, backend: backend,
          code: e && e.code, message: e && e.message,
        }, auditOn);
        throw e;
      }
      // fallthrough to file fallback
    }
  }

  _validateFallbackFile(opts.fallbackFile, "keychain.store");
  // The lock sentinel lives beside fallbackFile, so its parent directory must
  // exist before the FIRST writer can lock — otherwise the lock (added to
  // serialize the RMW below) fails where the pre-lock atomicFile.write used to
  // create the directory lazily on first store.
  atomicFile.ensureDir(nodePath.dirname(opts.fallbackFile), 0o700);
  // Serialize the read-modify-write so concurrent stores to the same
  // fallbackFile can't each read the pre-update document and clobber one
  // another's binding on write. atomicFile.lock is a cross-process file
  // mutex; _removeFromFile serializes its RMW through the same lock.
  await atomicFile.lock(opts.fallbackFile, async function () {
    var doc = await _readFile(opts.fallbackFile, opts.passphrase);
    doc.entries[_bindingKey(opts.service, opts.account)] = String(opts.password);
    await _writeFile(opts.fallbackFile, doc, opts.passphrase);
  });
  _emit("keychain.stored", "success", {
    service: opts.service, account: opts.account, backend: "file",
  }, auditOn);
  return { stored: true, backend: "file" };
}

/**
 * @primitive b.keychain.retrieve
 * @signature b.keychain.retrieve(opts)
 * @since     0.7.0
 * @related   b.keychain.store, b.keychain.remove
 *
 * Look up the password for `(service, account)` from the native
 * credential store, falling back to the encrypted file when the
 * native store has no entry or no native backend is reachable.
 * Resolves to `{ password, backend }` on a hit, `null` on a clean
 * miss. Native-tool failures surface as `KeychainError` with the
 * tool's stderr included.
 *
 * @opts
 *   {
 *     service:       string,        // required
 *     account:       string,        // required
 *     fallbackFile?: string,        // absolute path; required for file-backend lookup
 *     passphrase?:   string,        // required when fallbackFile engages
 *     preferFile?:   boolean,       // default: false
 *     audit?:        boolean,       // default: true (emits keychain.retrieved)
 *   }
 *
 * @example
 *   var got = await b.keychain.retrieve({
 *     service:      "blamejs/db",
 *     account:      "primary",
 *     fallbackFile: "/var/lib/blamejs/keychain.enc",
 *     passphrase:   process.env.BLAMEJS_KEYCHAIN_PASSPHRASE,
 *   });
 *   // → { password: "s3cr3t", backend: "macos-security" }  // or null on miss
 */
async function retrieve(opts) {
  _validateCommonOpts(opts, "keychain.retrieve");

  var backend = _selectBackend(opts);
  var auditOn = opts.audit !== false;

  if (backend !== "file") {
    try {
      var pw = null;
      if (backend === "macos-security")    pw = await _macRetrieve(opts.service, opts.account);
      else if (backend === "linux-secret-tool") pw = await _linuxRetrieve(opts.service, opts.account);
      else if (backend === "windows-credential") pw = await _windowsRetrieve(opts.service, opts.account);
      if (pw === null || pw === undefined) {
        // Fall through to file fallback when the OS keychain has no
        // entry — operators may have stored under file mode and later
        // booted on a host with a native keychain.
      } else {
        _emit("keychain.retrieved", "success", {
          service: opts.service, account: opts.account, backend: backend,
        }, auditOn);
        return { password: pw, backend: backend };
      }
    } catch (e) {
      if (!_isFallbackError(e)) {
        _emit("keychain.retrieved", "failure", {
          service: opts.service, account: opts.account, backend: backend,
          code: e && e.code, message: e && e.message,
        }, auditOn);
        throw e;
      }
    }
  }

  if (!opts.fallbackFile) {
    _emit("keychain.retrieved", "success", {
      service: opts.service, account: opts.account, backend: "none",
      found: false,
    }, auditOn);
    return null;
  }
  _validateFallbackFile(opts.fallbackFile, "keychain.retrieve");
  if (!atomicFile.exists(opts.fallbackFile)) {
    _emit("keychain.retrieved", "success", {
      service: opts.service, account: opts.account, backend: "file",
      found: false,
    }, auditOn);
    return null;
  }
  var doc = await _readFile(opts.fallbackFile, opts.passphrase);
  var bindingKey = _bindingKey(opts.service, opts.account);
  var found = Object.prototype.hasOwnProperty.call(doc.entries, bindingKey);
  if (!found) {
    _emit("keychain.retrieved", "success", {
      service: opts.service, account: opts.account, backend: "file",
      found: false,
    }, auditOn);
    return null;
  }
  _emit("keychain.retrieved", "success", {
    service: opts.service, account: opts.account, backend: "file",
  }, auditOn);
  return { password: doc.entries[bindingKey], backend: "file" };
}

/**
 * @primitive b.keychain.remove
 * @signature b.keychain.remove(opts)
 * @since     0.7.0
 * @related   b.keychain.store, b.keychain.retrieve
 *
 * Delete the `(service, account)` binding from both the native
 * credential store (when reachable) and the encrypted file fallback
 * (when `fallbackFile` is supplied). Resolves to `true` when at least
 * one backend held the binding, `false` on a no-op. The double-sweep
 * matters because a binding may have been stored on a prior boot
 * under a different backend than the current host advertises.
 *
 * @opts
 *   {
 *     service:       string,        // required
 *     account:       string,        // required
 *     fallbackFile?: string,        // absolute path; required for file-backend cleanup
 *     passphrase?:   string,        // required when fallbackFile engages
 *     preferFile?:   boolean,       // default: false
 *     audit?:        boolean,       // default: true (emits keychain.removed)
 *   }
 *
 * @example
 *   var existed = await b.keychain.remove({
 *     service:      "blamejs/db",
 *     account:      "primary",
 *     fallbackFile: "/var/lib/blamejs/keychain.enc",
 *     passphrase:   process.env.BLAMEJS_KEYCHAIN_PASSPHRASE,
 *   });
 *   // → true
 */
async function remove(opts) {
  _validateCommonOpts(opts, "keychain.remove");

  var backend = _selectBackend(opts);
  var auditOn = opts.audit !== false;

  if (backend !== "file") {
    try {
      var ok = false;
      if (backend === "macos-security")    ok = await _macRemove(opts.service, opts.account);
      else if (backend === "linux-secret-tool") ok = await _linuxRemove(opts.service, opts.account);
      else if (backend === "windows-credential") ok = await _windowsRemove(opts.service, opts.account);
      _emit("keychain.removed", ok ? "success" : "no-op", {
        service: opts.service, account: opts.account, backend: backend,
      }, auditOn);
      // Also sweep file fallback if both could carry the binding.
      if (opts.fallbackFile && atomicFile.exists(opts.fallbackFile)) {
        try { await _removeFromFile(opts.fallbackFile, opts.service, opts.account, opts.passphrase); }
        catch (_e) { /* file remove best-effort when native succeeded */ }
      }
      return ok;
    } catch (e) {
      if (!_isFallbackError(e)) {
        _emit("keychain.removed", "failure", {
          service: opts.service, account: opts.account, backend: backend,
          code: e && e.code, message: e && e.message,
        }, auditOn);
        throw e;
      }
    }
  }

  // Validate a supplied fallbackFile (reject a relative path) BEFORE the
  // exists check, so a relative path throws keychain/relative-fallback-file
  // consistently with store/retrieve instead of silently no-op'ing.
  if (opts.fallbackFile) {
    _validateFallbackFile(opts.fallbackFile, "keychain.remove");
  }
  if (!opts.fallbackFile || !atomicFile.exists(opts.fallbackFile)) {
    _emit("keychain.removed", "no-op", {
      service: opts.service, account: opts.account, backend: "file",
    }, auditOn);
    return false;
  }
  var existed = await _removeFromFile(opts.fallbackFile, opts.service, opts.account, opts.passphrase);
  _emit("keychain.removed", existed ? "success" : "no-op", {
    service: opts.service, account: opts.account, backend: "file",
  }, auditOn);
  return existed;
}

async function _removeFromFile(fallbackFile, service, account, passphrase) {
  // Same serialized read-modify-write as store: hold the file mutex across
  // read -> delete -> write so a concurrent store/remove can't lose the edit.
  return await atomicFile.lock(fallbackFile, async function () {
    var doc = await _readFile(fallbackFile, passphrase);
    var bindingKey = _bindingKey(service, account);
    if (!Object.prototype.hasOwnProperty.call(doc.entries, bindingKey)) return false;
    delete doc.entries[bindingKey];
    await _writeFile(fallbackFile, doc, passphrase);
    return true;
  });
}

// ---- Test seam -------------------------------------------------------------
// Reset the cached backend probe so a test can flip platform / PATH and
// re-run detection. NOT operator-facing.
function _clearBackendCacheForTest() { _cachedBackend = null; }

module.exports = {
  store:                    store,
  retrieve:                 retrieve,
  remove:                   remove,
  KeychainError:            KeychainError,
  _clearBackendCacheForTest: _clearBackendCacheForTest,
};
